// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 VMware Inc.  All rights reserved.

#include "net-tracking.h"
#include "net-helper.h"
#include "hash-table-generic.h"
#include "cb-spinlock.h"

#include <linux/inet.h>

#include <linux/workqueue.h>
#include <linux/jiffies.h>

typedef struct table_key {
    uint32_t        pid;
    uint16_t        proto;
    uint16_t        conn_dir;
    CB_SOCK_ADDR    laddr;
    CB_SOCK_ADDR    raddr;
} NET_TBL_KEY;

typedef struct table_value {
    struct timespec  last_seen;
    uint64_t         count;
} NET_TBL_VALUE;

typedef struct table_node {
    HashTableNode     link;
    NET_TBL_KEY       key;
    NET_TBL_VALUE     value;
    struct list_head  ageList;
} NET_TBL_NODE;

void __ec_net_tracking_print_message(const char *message, NET_TBL_KEY *key);
void __ec_net_tracking_task(struct work_struct *work);
void __ec_net_tracking_set_key(NET_TBL_KEY    *key,
                      pid_t           pid,
                      CB_SOCK_ADDR   *localAddr,
                      CB_SOCK_ADDR   *remoteAddr,
                      uint16_t        proto,
                      CONN_DIRECTION  conn_dir);

static HashTbl            *s_net_hash_table;
static struct delayed_work s_net_track_work;
static uint32_t            s_ntt_delay;
static uint64_t            s_net_age_lock;
static LIST_HEAD(s_net_age_list);


#define NET_TBL_SIZE     262000
#define NET_TBL_PURGE    200000


bool ec_net_tracking_initialize(ProcessContext *context)
{
    // Initialize the delayed work timeout value.  This will check for timed out network
    //  connections every 15 minutes.
    s_ntt_delay = msecs_to_jiffies(15 * 60 * 1000);
    s_net_hash_table = ec_hashtbl_init_generic(context,
                                               NET_TBL_SIZE,
                                               sizeof(NET_TBL_NODE),
                                               0,
                                               "network_tracking_table",
                                               sizeof(NET_TBL_KEY),
                                               offsetof(NET_TBL_NODE, key),
                                               offsetof(NET_TBL_NODE, link),
                                               HASHTBL_DISABLE_REF_COUNT,
                                               NULL,
                                               NULL);
    TRY(s_net_hash_table);

    ec_spinlock_init(&s_net_age_lock, context);

    // Initialize a workque struct to police the hashtable
    INIT_DELAYED_WORK(&s_net_track_work, __ec_net_tracking_task);
    schedule_delayed_work(&s_net_track_work, s_ntt_delay);

CATCH_DEFAULT:
    return s_net_hash_table != NULL;
}

void ec_net_tracking_shutdown(ProcessContext *context)
{
    /*
     * Calling the sync flavor gives the guarantee that on the return of the
     * routine, work is not pending and not executing on any CPU.
     *
     * Its supposed to work even if the work schedules itself.
     */

    cancel_delayed_work_sync(&s_net_track_work);
    ec_hashtbl_shutdown_generic(s_net_hash_table, context);
    ec_spinlock_destroy(&s_net_age_lock, context);
    INIT_LIST_HEAD(&s_net_age_list);
}

// Track this connection in the local table
//  If it is a new connection, add an entry and send an event (return value of true)
//  If it is a tracked connection, update the time and skip sending an event (return value of false)
bool ec_net_tracking_check_cache(
    ProcessContext *context,
    pid_t           pid,
    CB_SOCK_ADDR   *localAddr,
    CB_SOCK_ADDR   *remoteAddr,
    uint16_t        proto,
    CONN_DIRECTION  conn_dir)
{
    bool xcode = false;
    NET_TBL_KEY key;
    NET_TBL_NODE *node;

    // Build the key
    __ec_net_tracking_set_key(&key, pid, localAddr, remoteAddr, proto, conn_dir);

    // CB-10650
    // We found a rare race condition where we find a node to be updated, and then wait on
    //  the spinlock.  The node is then deleted from the cleanup code.  We attempt to add it
    //  back to the list and crash with a double delete.
    ec_write_lock(&s_net_age_lock, context);

    // Check to see if this item is already tracked
    node = ec_hashtbl_get_generic(s_net_hash_table, &key, context);

    if (!node)
    {
        xcode = true;
        node = (NET_TBL_NODE *) ec_hashtbl_alloc_generic(s_net_hash_table, context);
        TRY_MSG(node, DL_ERROR, "Failed to allocate a network tracking node, event will be sent!");

        memcpy(&node->key, &key, sizeof(NET_TBL_KEY));
        node->value.count = 0;
        // Initialize ageList so it is safe to call delete on it.
        INIT_LIST_HEAD(&(node->ageList));

        __ec_net_tracking_print_message("ADD", &key);

        TRY_DO_MSG(!ec_hashtbl_add_generic(s_net_hash_table, node, context),
                   { ec_hashtbl_free_generic(s_net_hash_table, node, context); },
                   DL_ERROR, "Failed to add a network tracking node, event will be sent!");
    }

    // Update the last seen time and count
    getnstimeofday(&node->value.last_seen);
    ++node->value.count;

    // In case this connection is already tracked remove it from it's current location in
    //  the list so we can add it to the end.  This is a safe operation for a new entry
    //  because we initialize ageList above.
    list_del(&(node->ageList));
    list_add(&(node->ageList), &s_net_age_list);

CATCH_DEFAULT:

    ec_write_unlock(&s_net_age_lock, context);

    // If we have an excessive amount of netconns force it to clean up now.
    if (atomic64_read(&(s_net_hash_table->tableInstance)) >= NET_TBL_SIZE)
    {
        // Cancel the currently scheduled work, and and schedule it for immediate execution
        cancel_delayed_work(&s_net_track_work);
        schedule_work(&s_net_track_work.work);
    }

    return xcode;
}

struct priv_data {
    struct timespec time;
    uint32_t        count;
};

void __ec_net_tracking_print_message(const char *message, NET_TBL_KEY *key)
{
    uint16_t  rport                         = 0;
    uint16_t  lport                         = 0;
    char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
    char      laddr_str[INET6_ADDRSTRLEN*2] = {0};

    ec_ntop(&key->raddr.sa_addr, raddr_str, sizeof(raddr_str), &rport);
    ec_ntop(&key->laddr.sa_addr, laddr_str, sizeof(laddr_str), &lport);
    TRACE(DL_NET_TRACKING, "NET-TRACK <%s> %u %s-%s laddr=%s:%u raddr=%s:%u",
          message,
          key->pid,
          PROTOCOL_STR(key->proto),
          (key->conn_dir == CONN_IN ? "in" : (key->conn_dir == CONN_OUT ? "out" : "??")),
          laddr_str, ntohs(lport), raddr_str, ntohs(rport));
}

void __ec_net_hash_table_cleanup(ProcessContext *context, struct priv_data *data)
{
    NET_TBL_NODE *datap = NULL;
    NET_TBL_NODE *tmp = NULL;
    uint64_t      purgeCount = 0;

    if (!data)
    {
        TRACE(DL_ERROR, "%s: Bad PARAM", __func__);
        return;
    }

    purgeCount = (data->count >= NET_TBL_SIZE ? NET_TBL_PURGE : 0);

    data->count = 0;

    ec_write_lock(&s_net_age_lock, context);
    list_for_each_entry_safe_reverse(datap, tmp, &s_net_age_list, ageList)
    {
        if (!purgeCount)
        {
            if (data->time.tv_sec < datap->value.last_seen.tv_sec)
            {
                break;
            }
        } else
        {
            --purgeCount;
        }

        __ec_net_tracking_print_message("AGE OUT", &datap->key);

        ++data->count;

        list_del(&(datap->ageList));
        ec_hashtbl_del_generic(s_net_hash_table, datap, context);
        ec_hashtbl_free_generic(s_net_hash_table, datap, context);
    }
    ec_write_unlock(&s_net_age_lock, context);
}

void ec_net_tracking_clean(ProcessContext *context, int sec)
{
    struct priv_data data;
    uint64_t         total = atomic64_read(&(s_net_hash_table->tableInstance));

    data.count = 0;
    getnstimeofday(&data.time);

    data.time.tv_sec -= sec;
    data.count        = total;

    __ec_net_hash_table_cleanup(context, &data);

    TRACE(DL_NET_TRACKING, "%s: Removed %d of %llu cached connections\n", __func__, data.count, total);
}

void __ec_net_tracking_task(struct work_struct *work)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // Set the last seen time that we want to age out
    //  This is set to 3600 to match the default tcp session timeout
    ec_net_tracking_clean(&context, 3600);
    schedule_delayed_work(&s_net_track_work, s_ntt_delay);
}

// Completely purge the network tracking table
ssize_t ec_net_track_purge_all(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    ec_write_lock(&s_net_age_lock, &context);
    ec_hashtbl_clear_generic(s_net_hash_table, &context);
    INIT_LIST_HEAD(&s_net_age_list);
    ec_write_unlock(&s_net_age_lock, &context);

    return size;
}

// Read in the age to purge from the user
ssize_t ec_net_track_purge_age(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    long seconds = 0;
    int  ret     = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    ret = kstrtol(buf, 10, &seconds);
    if (!ret)
    {
        ec_net_tracking_clean(&context, seconds);
    } else
    {
        TRACE(DL_ERROR, "%s: Error reading data: %s (%d)", __func__, buf, -ret);
    }

    return size;
}

// Display the 50 oldest netconns
int ec_net_track_show_old(struct seq_file *m, void *v)
{
    NET_TBL_NODE *datap = 0;
    int           i     = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    ec_write_lock(&s_net_age_lock, &context);
    list_for_each_entry_reverse(datap, &s_net_age_list, ageList)
    {
        uint16_t  rport                         = 0;
        uint16_t  lport                         = 0;
        char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
        char      laddr_str[INET6_ADDRSTRLEN*2] = {0};

        ec_ntop(&datap->key.raddr.sa_addr, raddr_str, sizeof(raddr_str), &rport);
        ec_ntop(&datap->key.laddr.sa_addr, laddr_str, sizeof(laddr_str), &lport);
        seq_printf(m, "NET-TRACK %d %s-%s %s:%u -> %s:%u (%d)\n",
                   datap->key.pid,
                   PROTOCOL_STR(datap->key.proto),
                   (datap->key.conn_dir == CONN_IN ? "in" : (datap->key.conn_dir == CONN_OUT ? "out" : "??")),
                   laddr_str, ntohs(lport), raddr_str, ntohs(rport),
                   (int)datap->value.last_seen.tv_sec);
        if (++i == 50) break;
    }
    ec_write_unlock(&s_net_age_lock, &context);

    return 0;
}

// Display the 50 newest netconns
int ec_net_track_show_new(struct seq_file *m, void *v)
{
    NET_TBL_NODE *datap = 0;
    int           i     = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    ec_write_lock(&s_net_age_lock, &context);
    list_for_each_entry(datap, &s_net_age_list, ageList)
    {
        uint16_t  rport                         = 0;
        uint16_t  lport                         = 0;
        char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
        char      laddr_str[INET6_ADDRSTRLEN*2] = {0};

        ec_ntop(&datap->key.raddr.sa_addr, raddr_str, sizeof(raddr_str), &rport);
        ec_ntop(&datap->key.laddr.sa_addr, laddr_str, sizeof(laddr_str), &lport);
        seq_printf(m, "NET-TRACK %d %s-%s %s:%u -> %s:%u (%d)\n",
                   datap->key.pid,
                   PROTOCOL_STR(datap->key.proto),
                   (datap->key.conn_dir == CONN_IN ? "in" : (datap->key.conn_dir == CONN_OUT ? "out" : "??")),
                   laddr_str, ntohs(lport), raddr_str, ntohs(rport),
                   (int)datap->value.last_seen.tv_sec);
        if (++i == 50) break;
    }
    ec_write_unlock(&s_net_age_lock, &context);

    return 0;
}

void __ec_net_tracking_set_key(NET_TBL_KEY    *key,
                      pid_t           pid,
                      CB_SOCK_ADDR   *localAddr,
                      CB_SOCK_ADDR   *remoteAddr,
                      uint16_t        proto,
                      CONN_DIRECTION  conn_dir)
{
    memset(key, 0, sizeof(NET_TBL_KEY));

    ec_copy_sockaddr(&key->laddr, localAddr);
    ec_copy_sockaddr(&key->raddr, remoteAddr);

    // Network applications tend to randomize the source port, so in order to
    //  reduce the number of reported network connections we ignore the source port.
    //  (Which one that is depends on the direction.)
    if (conn_dir == CONN_IN)
    {
        ec_set_sockaddr_port(&key->raddr, 0);
    } else if (conn_dir == CONN_OUT)
    {
        ec_set_sockaddr_port(&key->laddr, 0);
    } else
    {
        TRACE(DL_WARNING, "Unexpected netconn direction: %d", conn_dir);
    }

    key->pid      = pid;
    key->proto    = proto;
    key->conn_dir = conn_dir;
}
