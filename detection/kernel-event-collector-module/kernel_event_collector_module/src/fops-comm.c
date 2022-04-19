// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/ioctl.h>

#include "priv.h"
#include "cb-banning.h"
#include "cb-isolation.h"
#include "hash-table-generic.h"
#include "process-tracking.h"
#include "mem-cache.h"
#include "cb-spinlock.h"

#include "InodeState.h"

const char DRIVER_NAME[] = CB_APP_MODULE_NAME;
#define MINOR_COUNT 1
ssize_t KF_LEN = sizeof(struct CB_EVENT_UM); // This needs to be sizeof(whatever we store in queue)

int ec_device_open(struct inode *inode, struct file *filep);
int ec_device_release(struct inode *inode, struct file *filep);
ssize_t ec_device_read(struct file *f, char __user *buf, size_t count, loff_t *offset);
unsigned int ec_device_poll(struct file *filep, struct poll_table_struct *poll);
long ec_device_unlocked_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
int __ec_DoAction(ProcessContext *context, uint32_t action);
void ec_user_comm_clear_queues(ProcessContext *context);
void __ec_user_comm_clear_queues_locked(ProcessContext *context);
bool __ec_try_to_gain_capacity(struct list_head *tx_queue);
void __ec_get_tx_queue_to_serve(struct list_head **tx_queue, atomic64_t **tx_ready);
void __ec_decrease_holdoff_counter(atomic64_t *tx_ready);
bool __ec_is_action_allowed(ModuleState moduleState, CB_EVENT_ACTION_TYPE action);
bool __ec_is_ioctl_allowed(ModuleState module_state, unsigned int cmd);
size_t __ec_get_memory_usage(ProcessContext *context);
void __ec_apply_legacy_driver_config(uint32_t eventFilter);
void __ec_apply_driver_config(CB_DRIVER_CONFIG *config);
char *__ec_driver_config_option_to_string(CB_CONFIG_OPTION config_option);
void __ec_print_driver_config(char *msg, CB_DRIVER_CONFIG *config);
int __ec_copy_cbevent_to_user(char __user *ubuf, size_t count, ProcessContext *context);
int __ec_precompute_payload(struct CB_EVENT *cb_event);

// checkpatch-ignore: CONST_STRUCT
struct file_operations driver_fops = {
    .owner          = THIS_MODULE,
    .read           = ec_device_read,
    .poll           = ec_device_poll,
    .open           = ec_device_open,
    .release        = ec_device_release,
    .unlocked_ioctl = ec_device_unlocked_ioctl,
};
// checkpatch-no-ignore: CONST_STRUCT

// Our device special major number
static dev_t g_maj_t;
struct cdev ec_cdev;

static LIST_HEAD(msg_queue_pri0);
static LIST_HEAD(msg_queue_pri1);
static LIST_HEAD(msg_queue_pri2);

#define  MAX_VALID_INTERVALS     60
#define  MAX_INTERVALS           62
#define  NUM_STATS               18
#define  EVENT_STATS             13
#define  MEM_START               EVENT_STATS
#define  MEM_STATS               (EVENT_STATS + 4)



typedef struct CB_EVENT_STATS {
    // This is a circular array of elements were each element is an increasing sum from the
    //  previous element. You can always get the sum of any two elements, and divide by the
    //  number of elements between them to yield the average.
    //  tx_queued_pri0;
    //  tx_queued_pri1;
    //  tx_queued_pri2;
    //  tx_dropped;
    //  tx_total;
    //  tx_other
    //  tx_process
    //  tx_modload
    //  tx_file
    //  tx_net
    //  tx_dns
    //  tx_proxy
    //  tx_block
    atomic64_t      stats[MAX_INTERVALS][NUM_STATS];
    struct timespec time[MAX_INTERVALS];

    // These are live counters that rise and fall as events are generated.  This variable
    //  will be added to the stats end the end of each interval.
    atomic64_t      tx_ready_pri0;
    atomic64_t      tx_ready_pri1;
    atomic64_t      tx_ready_pri1_holdoff;
    atomic64_t      tx_ready_pri2;
    atomic64_t      tx_ready_prev0;
    atomic64_t      tx_ready_prev1;
    atomic64_t      tx_ready_prev2;

    // The current index into the list
    atomic_t        curr;

    // The number of times the list has carried over. (This helps us calculate the average
    //  later by knowing how many are valid.)
    atomic_t        validStats;
} CB_EVENT_STATS, *PCB_EVENT_STATS;

const struct {
    const char *name;
    const char *str_format;
    const char *num_format;
} STAT_STRINGS[] = {
    { "Total Queued",   " %12s ||", " %12d ||" },
    { "Queued in P0",   " %12s |", " %12d |" },
    { "Queued in P1",   " %12s |", " %12d |" },
    { "Queued in P2",   " %12s |", " %12d |" },
    { "Dropped",        " %7s |", " %7d |" },
    { "All",            " %7s |", " %7d |" },
    { "Process",        " %7s |", " %7d |" },
    { "Modload",        " %7s |", " %7d |" },
    { "File",           " %7s |", " %7d |" },
    { "Net",            " %7s |", " %7d |" },
    { "DNS",            " %7s |", " %7d |" },
    { "Proxy",          " %7s |", " %7d |" },
    { "Blocked",        " %7s |", " %7d |" },
    { "Other",          " %7s |", " %7d |" },
    { "User",           " %10s |", " %10d |" },
    { "User Peak",      " %10s |", " %10d |" },
    { "Kernel",         " %7s |", " %7d |" },
    { "Kernel Peak",    " %12s |", " %12d |" }
};

static CB_EVENT_STATS s_event_stats;


#define current_stat        (s_event_stats.curr)
#define valid_stats         (s_event_stats.validStats)
#define tx_ready_pri0       (s_event_stats.tx_ready_pri0)
#define tx_ready_pri1       (s_event_stats.tx_ready_pri1)
#define tx_ready_pri1_holdoff (s_event_stats.tx_ready_pri1_holdoff)
#define tx_ready_pri2       (s_event_stats.tx_ready_pri2)
#define tx_ready_prev0      (s_event_stats.tx_ready_prev0)
#define tx_ready_prev1      (s_event_stats.tx_ready_prev1)
#define tx_ready_prev2      (s_event_stats.tx_ready_prev2)
#define tx_queued_t         (s_event_stats.stats[atomic_read(&current_stat)][0])
#define tx_queued_pri0      (s_event_stats.stats[atomic_read(&current_stat)][1])
#define tx_queued_pri1      (s_event_stats.stats[atomic_read(&current_stat)][2])
#define tx_queued_pri2      (s_event_stats.stats[atomic_read(&current_stat)][3])
#define tx_dropped          (s_event_stats.stats[atomic_read(&current_stat)][4])
#define tx_total            (s_event_stats.stats[atomic_read(&current_stat)][5])
#define tx_process          (s_event_stats.stats[atomic_read(&current_stat)][6])
#define tx_modload          (s_event_stats.stats[atomic_read(&current_stat)][7])
#define tx_file             (s_event_stats.stats[atomic_read(&current_stat)][8])
#define tx_net              (s_event_stats.stats[atomic_read(&current_stat)][9])
#define tx_dns              (s_event_stats.stats[atomic_read(&current_stat)][10])
#define tx_proxy            (s_event_stats.stats[atomic_read(&current_stat)][11])
#define tx_block            (s_event_stats.stats[atomic_read(&current_stat)][12])
#define tx_other            (s_event_stats.stats[atomic_read(&current_stat)][13])


#define mem_user            (s_event_stats.stats[atomic_read(&current_stat)][14])
#define mem_user_peak       (s_event_stats.stats[atomic_read(&current_stat)][15])
#define mem_kernel          (s_event_stats.stats[atomic_read(&current_stat)][16])
#define mem_kernel_peak     (s_event_stats.stats[atomic_read(&current_stat)][17])

atomic_t reader_pid;

bool event_queue_enabled;
uint64_t dev_spinlock;

DECLARE_WAIT_QUEUE_HEAD(wq);

#define STAT_INTERVAL    15
static struct delayed_work stats_work;
void ec_stats_work_task(struct work_struct *work);
static uint32_t g_stats_work_delay;

void ec_reader_init(void)
{
    atomic_set(&reader_pid, 0);
}

bool ec_is_reader_connected(void)
{
    return (0 != atomic_cmpxchg(&reader_pid, 0, 0));
}

bool __ec_connect_reader(ProcessContext *context)
{
    return (0 == atomic_cmpxchg(&reader_pid, 0, context->pid));
}

bool ec_disconnect_reader(pid_t pid)
{
    return (pid == atomic_cmpxchg(&reader_pid, pid, 0));
}

bool __ec_is_process_connected_reader(pid_t pid)
{
    return (pid == atomic_cmpxchg(&reader_pid, pid, pid));
}

bool ec_user_comm_initialize(ProcessContext *context)
{
    int i;
    size_t kernel_mem;

    ec_spinlock_init(&dev_spinlock, context);

    atomic_set(&current_stat,          0);
    atomic_set(&valid_stats,           0);
    atomic64_set(&tx_ready_pri0,         0);
    atomic64_set(&tx_ready_pri1,         0);
    atomic64_set(&tx_ready_pri1_holdoff, 0);
    atomic64_set(&tx_ready_pri2,         0);

    for (i = 0; i < NUM_STATS; ++i)
    {
        // We make sure the first and last interval are 0 for the average calculations
        atomic64_set(&s_event_stats.stats[0][i],                0);
        atomic64_set(&s_event_stats.stats[MAX_INTERVALS - 1][i], 0);
    }
    getnstimeofday(&s_event_stats.time[0]);
    kernel_mem = __ec_get_memory_usage(context);
    atomic64_set(&mem_kernel,      kernel_mem);
    atomic64_set(&mem_kernel_peak, kernel_mem);

    // Initialize a workque struct to police the hashtable
    g_stats_work_delay = msecs_to_jiffies(STAT_INTERVAL * 1000);
    INIT_DELAYED_WORK(&stats_work, ec_stats_work_task);
    schedule_delayed_work(&stats_work, g_stats_work_delay);

    event_queue_enabled  = true;
    return true;
}

bool ec_user_devnode_init(ProcessContext *context)
{
    const unsigned int MINOR_FIRST = 0;
    int maj_no;

    // Allocate Major / Minor number of device special file
    TRY_STEP_DO(DEVNUM_ALLOC, alloc_chrdev_region(&g_maj_t, MINOR_FIRST, MINOR_COUNT, DRIVER_NAME) >= 0,

                TRACE(DL_ERROR, "Failed allocating character device region."););

    maj_no = MAJOR(g_maj_t);
    cdev_init(&ec_cdev, &driver_fops);
    TRY_STEP_DO(CHRDEV_ALLOC, cdev_add(&ec_cdev, g_maj_t, 1) >= 0, TRACE(DL_ERROR, "cdev_add failed"););

    event_queue_enabled  = true;
    return true;

CATCH_CHRDEV_ALLOC:
        unregister_chrdev_region(g_maj_t, MINOR_COUNT);
        cdev_del(&ec_cdev);

CATCH_DEVNUM_ALLOC:
    return false;
}

void ec_user_devnode_close(ProcessContext *context)
{
    cdev_del(&ec_cdev);
    unregister_chrdev_region(g_maj_t, MINOR_COUNT);
}

void ec_user_comm_shutdown(ProcessContext *context)
{
    /**
     * Calling the sync flavor gives the guarantee that on the return of the
     * routine, work is not pending and not executing on any CPU.
     *
     * Its supposed to work even if the work schedules itself.
     */
    cancel_delayed_work_sync(&stats_work);

    ec_write_lock(&dev_spinlock, context);
    __ec_user_comm_clear_queues_locked(context);
    event_queue_enabled  = false;
    ec_write_unlock(&dev_spinlock, context);
    ec_spinlock_destroy(&dev_spinlock, context);
}

void ec_user_comm_clear_queues(ProcessContext *context)
{
    ec_write_lock(&dev_spinlock, context);
    __ec_user_comm_clear_queues_locked(context);
    ec_write_unlock(&dev_spinlock, context);
}

void __ec_clear_tx_queue(struct list_head *tx_queue, atomic64_t *tx_ready, ProcessContext *context)
{
    struct list_head *eventNode;
    struct list_head *safeNode;

    list_for_each_safe(eventNode, safeNode, tx_queue)
    {
        list_del(eventNode);
        ec_free_event(&(container_of(eventNode, CB_EVENT_NODE, listEntry)->data), context);
        atomic64_dec(tx_ready);
    }
}

void __ec_user_comm_clear_queues_locked(ProcessContext *context)
{
    TRACE(DL_INFO, "%s: clear queues", __func__);

    // Clearing the queues can trigger sending an exit event which will hang when ec_send_event
    // locks this same lock. Since we're clearing the queues we don't need to send exit events.
    DISABLE_SEND_EVENTS(context);
     __ec_clear_tx_queue(&msg_queue_pri0, &tx_ready_pri0, context);
     __ec_clear_tx_queue(&msg_queue_pri1, &tx_ready_pri1, context);
     __ec_clear_tx_queue(&msg_queue_pri2, &tx_ready_pri2, context);
    ENABLE_SEND_EVENTS(context);
}

int ec_send_event(struct CB_EVENT *msg, ProcessContext *context)
{
    int               result     = -1;
    uint64_t          readyCount = 0;
    struct list_head *tx_queue   = NULL;
    atomic64_t       *tx_ready   = NULL;
    uint64_t          max_queue_size = 0;
    int               payload;
    CB_EVENT_NODE    *eventNode;

    TRY(ALLOW_SEND_EVENTS(context));

    TRY(msg && ec_is_reader_connected());

    eventNode = container_of(msg, CB_EVENT_NODE, data);
    payload = __ec_precompute_payload(msg);

    // Should not happen but it can
    TRY(payload >= sizeof(struct CB_EVENT_UM));

    eventNode->payload = (uint16_t)payload;

    switch (msg->eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START:
    case CB_EVENT_TYPE_PROCESS_EXIT:
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
    case CB_EVENT_TYPE_PROCESS_BLOCKED:
    case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
        tx_queue       = &msg_queue_pri0;
        tx_ready       = &tx_ready_pri0;
        max_queue_size = g_max_queue_size_pri0;
        break;
    case CB_EVENT_TYPE_MODULE_LOAD:
        tx_queue       = &msg_queue_pri2;
        tx_ready       = &tx_ready_pri2;
        max_queue_size = g_max_queue_size_pri2;
        break;
    default:
        tx_queue       = &msg_queue_pri1;
        tx_ready       = &tx_ready_pri1;
        max_queue_size = g_max_queue_size_pri1;
        break;
    }

    ec_write_lock(&dev_spinlock, context);
    readyCount = atomic64_read(tx_ready);
    if (event_queue_enabled &&
        (readyCount < max_queue_size ||
         __ec_try_to_gain_capacity(tx_queue)))
    {
        list_add_tail(&(eventNode->listEntry), tx_queue);
        atomic64_inc(tx_ready);
        TRACE(DL_VERBOSE, "send_event_atomic %p %llu", msg, readyCount);
        msg = NULL;
    }
    ec_write_unlock(&dev_spinlock, context);

    // This should be NULL by now.
    TRY(!msg);

    // If we did enqueue the event, wake up the reader task if we are allowed to
    if (ALLOW_WAKE_UP(context))
    {
        // NOTE: This call must happen outside the dev_spinlock or it may cause a
        //       deadlock woking up the task
        ec_fops_comm_wake_up_reader(context);
    }
    result = 0;

CATCH_DEFAULT:
    if (msg)
    {
        // If we still have an event at this point free it now
        atomic64_inc(&tx_dropped);
        TRACE(DL_INFO, "Failed event insertion");
        ec_free_event(msg, context);
    }

    return result;
}

void ec_fops_comm_wake_up_reader(ProcessContext *context)
{
    // Wake up the reader task if we are allowed to
    if (ALLOW_WAKE_UP(context))
    {
        wake_up(&wq);
    }
}

bool __ec_try_to_gain_capacity(struct list_head *tx_queue)
{
    bool              tx_queue_is_pri1 = tx_queue == &msg_queue_pri1;
    uint64_t          qlen_pri0        = atomic64_read(&tx_ready_pri0);
    uint64_t          qlen_pri1        = atomic64_read(&tx_ready_pri1);
    uint64_t          pri1_holdoff     = atomic64_read(&tx_ready_pri1_holdoff);

    //Calculate the percentage of used capacity
    uint64_t          qlen_pri1_pct = (qlen_pri1*100) / g_max_queue_size_pri1;

    // If P1 reaches 90% of its capacity we attempt to move some of its items to P0
    //  before dropping events.  This allows us to always service P0 in priority order.
    //  This will also guarantee that we will still service any process start event
    //  before other events for the same process. (Any events currently in P1 must
    //  already have an associated process start in P0.)
    //
    // We don't however want to do this if P0 also has a significant number of events
    //  queued.  We use the simple criteria that the current number of events in P0 must
    //  be less than what is in P1.
    //
    // We never want to drop any events if it can be avoided.  The events in P0 are
    //  only more important than P1 because our tracking logic depends on it.  In
    //  reality the events in P1 are more important to the customer, because these
    //  represent the "interesting" events.  The events in P2 are really just informational,
    //  so we do not take special care to preserved.hem.
    //
    // The legacy logic for CbR requires the Fork events to be at the P0 priority
    //  for its tracking purpose.  In reality these events are not very interesting,
    //  and could be placed in the P2 queue.
    if (tx_queue_is_pri1 &&
        pri1_holdoff == 0 &&
        qlen_pri1_pct >= 90 &&
        qlen_pri0 < qlen_pri1)
    {
        LIST_HEAD(tempList);
        struct list_head *eventNode;
        uint64_t           events_to_move = qlen_pri1 / 2;
        const unsigned int overrun_log_frequency = 1000;
        static unsigned int overrun_count;

        // Update the counters to reflect that we moved some events
        //  We set the holdoff to three times what we moved
        pri1_holdoff = events_to_move * 3;
        atomic64_set(&tx_ready_pri1_holdoff, pri1_holdoff);
        atomic64_add(events_to_move, &tx_ready_pri0);
        atomic64_sub(events_to_move, &tx_ready_pri1);

        if (overrun_count++ % overrun_log_frequency == 0) {
            TRACE(DL_WARNING,
                  "P1 queue full, moving %llu events to P0.  Will holdoff for at least %llu events (count=%u).",
                  events_to_move, pri1_holdoff, overrun_count);
        }

        // We need to iterate over the P1 queue from the beginning to find the point
        //  where we want to split the queue.
        list_for_each(eventNode, &msg_queue_pri1)
        {
            if (--events_to_move == 0)
            {
                break;
            }
        }

        // Use the split point to move a bunch of events to a temporary list, and leave
        //  rest at the head of the P1 queue.  The tepmorary list can then be added
        //  to the end of the P0 queue.
        list_cut_position(&tempList, &msg_queue_pri1, eventNode);
        list_splice_tail(&tempList, &msg_queue_pri0);
        return true;
    }
    return false;
}

ssize_t ec_device_read(struct file *f,  char __user *ubuf, size_t count, loff_t *offset)
{
    ssize_t xcode = -ENOMEM;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    TRACE(DL_COMMS, "%s: start read", __func__);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // When userspace is ready to handle multiple events throw this into a loop
    xcode = __ec_copy_cbevent_to_user(ubuf, count, &context);

CATCH_DEFAULT:
    FINISH_MODULE_DISABLE_CHECK(&context);

    return xcode;
}

int ec_obtain_next_cbevent(struct CB_EVENT **cb_event, size_t count, ProcessContext *context)
{
    uint64_t qlen_pri0;
    uint64_t qlen_pri1;
    uint64_t qlen_pri2;
    struct list_head  *tx_queue = NULL;
    atomic64_t        *tx_ready = NULL;
    CB_EVENT_NODE     *eventNode = NULL;
    int xcode = -ENOMEM;

    if (count < sizeof(struct CB_EVENT_UM))
    {
        return -ENOMEM;
    }

    qlen_pri0 = atomic64_read(&tx_ready_pri0);
    qlen_pri1 = atomic64_read(&tx_ready_pri1);
    qlen_pri2 = atomic64_read(&tx_ready_pri2);

    TRY_DO_MSG((qlen_pri0 > 0 || qlen_pri1 > 0 || qlen_pri2 > 0),
                { xcode = -ENOMEM; },
                DL_COMMS,
                "%s: empty queue", __func__);

    ec_write_lock(&dev_spinlock, context);
    // select the queue - taken from __ec_get_tx_queue_to_serve
    if (qlen_pri0 != 0)
    {
        tx_queue = &msg_queue_pri0;
        tx_ready = &tx_ready_pri0;
    } else if (qlen_pri1 != 0)
    {
        tx_queue = &msg_queue_pri1;
        tx_ready = &tx_ready_pri1;
    } else
    {
        tx_queue = &msg_queue_pri2;
        tx_ready = &tx_ready_pri2;
    }

    eventNode = list_first_entry_or_null(tx_queue, CB_EVENT_NODE, listEntry);
    if (eventNode && count >= eventNode->payload &&
        eventNode->payload >= sizeof(struct CB_EVENT_UM))
    {
        // when we know for sure we can send this event
        __ec_decrease_holdoff_counter(tx_ready);
        list_del_init(&eventNode->listEntry);
        atomic64_dec(tx_ready);
        *cb_event = &eventNode->data;
        xcode = eventNode->payload;
    }
    ec_write_unlock(&dev_spinlock, context);

CATCH_DEFAULT:

    return xcode;
}

int __ec_copy_cbevent_to_user(char __user *ubuf, size_t count, ProcessContext *context)
{
    char __user *p;
    int rc;
    uint16_t payload;
    int xcode = -ENOMEM;
    struct CB_EVENT *msg = NULL;
    struct CB_EVENT_UM __user *msg_user = (struct CB_EVENT_UM __user *)ubuf;

    // You *must* ask for at least 1 packet

    rc = ec_obtain_next_cbevent(&msg, count, context);
    if (rc < 0)
    {
        xcode = rc;
        goto CATCH_DEFAULT;
    }

    payload = (uint16_t)rc;
    p = ubuf + sizeof(struct CB_EVENT_UM);

    // Payload hdr
    rc = put_user(payload, &msg_user->payload);
    TRY_STEP(COPY_FAIL, !rc);

    // Write the main event to user
    rc = copy_to_user(&msg_user->event, msg, sizeof(*msg));
    TRY_STEP(COPY_FAIL, !rc);

    // Proc Path
    if (msg->procInfo.path && msg->procInfo.path_size)
    {
        rc = copy_to_user(p, msg->procInfo.path, msg->procInfo.path_size);
        TRY_STEP(COPY_FAIL, !rc);
        p += msg->procInfo.path_size;
    }
    // Always zero it out kaddrs
    rc = put_user(0, &msg_user->event.procInfo.path);
    TRY_STEP(COPY_FAIL, !rc);

    // Use switch for now to allow us to extend in the future
    switch (msg->eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START:
        if (msg->processStart.path && msg->processStart.path_size)
        {
            rc = copy_to_user(p, msg->processStart.path, msg->processStart.path_size);
            TRY_STEP(COPY_FAIL, !rc);
            p += msg->processStart.path_size;
        }
        rc = put_user(0, &msg_user->event.processStart.path);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        if (msg->moduleLoad.path && msg->moduleLoad.path_size)
        {
            rc = copy_to_user(p, msg->moduleLoad.path, msg->moduleLoad.path_size);
            TRY_STEP(COPY_FAIL, !rc);

            p += msg->moduleLoad.path_size;
        }
        rc = put_user(0, &msg_user->event.moduleLoad.path);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_OPEN:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
        if (msg->fileGeneric.path && msg->fileGeneric.path_size)
        {
            rc = copy_to_user(p, msg->fileGeneric.path, msg->fileGeneric.path_size);
            TRY_STEP(COPY_FAIL, !rc);
            p += msg->fileGeneric.path_size;
        }
        rc = put_user(0, &msg_user->event.fileGeneric.path);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        if (msg->dnsResponse.records && msg->dnsResponse.record_count)
        {
            rc = copy_to_user(p, msg->dnsResponse.records,
                              msg->dnsResponse.record_count * sizeof(CB_DNS_RECORD));
            TRY_STEP(COPY_FAIL, !rc);
            p += msg->dnsResponse.record_count * sizeof(CB_DNS_RECORD);
        }
        rc = put_user(0, &msg_user->event.dnsResponse.records);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
    case CB_EVENT_TYPE_WEB_PROXY:
        if (msg->netConnect.actual_server && msg->netConnect.server_size)
        {
            rc = copy_to_user(p, msg->netConnect.actual_server,
                              msg->netConnect.server_size);
            TRY_STEP(COPY_FAIL, !rc);

            p += msg->netConnect.server_size;
        }
        rc = put_user(0, &msg_user->event.netConnect.actual_server);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
        if (msg->blockResponse.path && msg->blockResponse.path_size)
        {
            rc = copy_to_user(p, msg->blockResponse.path, msg->blockResponse.path_size);
            TRY_STEP(COPY_FAIL, !rc);

            p += msg->blockResponse.path_size;
        }
        rc = put_user(0, &msg_user->event.blockResponse.path);
        TRY_STEP(COPY_FAIL, !rc);
        break;

    default:
        break;
    }

    if (p - ubuf != payload)
    {
        TRACE(DL_ERROR, "%s: Offset:%u Payload:%u", __func__,
              (unsigned int)(p - ubuf), payload);
        xcode = -ENXIO;
        goto CATCH_DEFAULT;
    }

    xcode = payload;

    atomic64_inc(&tx_total);

    switch (msg->eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START:
    case CB_EVENT_TYPE_PROCESS_EXIT:
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
        atomic64_inc(&tx_process);
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        atomic64_inc(&tx_modload);
        break;

    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
    case CB_EVENT_TYPE_FILE_OPEN:
        atomic64_inc(&tx_file);
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
        atomic64_inc(&tx_net);
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        atomic64_inc(&tx_dns);
        break;

    case CB_EVENT_TYPE_WEB_PROXY:
        atomic64_inc(&tx_proxy);
        break;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
    case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
        atomic64_inc(&tx_block);
        break;

    case CB_EVENT_TYPE_PROC_ANALYZE:
    case CB_EVENT_TYPE_HEARTBEAT:
    case CB_EVENT_TYPE_MAX:
    case CB_EVENT_TYPE_UNKNOWN:
    default:
        atomic64_inc(&tx_other);
        break;
    }

CATCH_COPY_FAIL:
    // Check the result
    if (rc)
    {
        TRACE(DL_ERROR, "%s: copy to user failed rc=%d", __func__, rc);
        xcode = -ENXIO;
    }

    // When we start pausing tasks we will want to handle waking
    // them when we have an issue with userspace.

CATCH_DEFAULT:
    ec_free_event(msg, context);

    return xcode;
}

// Note, this is expected to be called with the lock held
void __ec_get_tx_queue_to_serve(struct list_head **tx_queue, atomic64_t **tx_ready)
{
    uint64_t          qlen_pri0    = atomic64_read(&tx_ready_pri0);
    uint64_t          qlen_pri1    = atomic64_read(&tx_ready_pri1);

    if (qlen_pri0 != 0)
    {
        *tx_queue = &msg_queue_pri0;
        *tx_ready = &tx_ready_pri0;
    } else if (qlen_pri1 != 0)
    {
        *tx_queue = &msg_queue_pri1;
        *tx_ready = &tx_ready_pri1;
    } else
    {
        *tx_queue = &msg_queue_pri2;
        *tx_ready = &tx_ready_pri2;
    }

    __ec_decrease_holdoff_counter(*tx_ready);
}

void __ec_decrease_holdoff_counter(atomic64_t *tx_ready)
{
    uint64_t pri1_holdoff = atomic64_read(&tx_ready_pri1_holdoff);

    // The holdoff counter helps us to ensure that we do not allow the P0 queue
    //  to get backed up.  If we moved events from P1 to P0 then we want to decrese
    //  the holdoff counter.  Only worry about counting this down if we are actually
    //  servicing events from the P0 queue.  If we are able to service events from
    //  another queue, just reset the counter.  This is because moveing events from
    //  P1 again would not be introducing a backup in P0.
    if (pri1_holdoff != 0)
    {
        if (tx_ready == &tx_ready_pri0)
        {
            atomic64_dec(&tx_ready_pri1_holdoff);
        } else
        {
            atomic64_set(&tx_ready_pri1_holdoff, 0);
        }
    }
}

int ec_device_open(struct inode *inode, struct file *filp)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    TRACE(DL_INFO, "%s: attempting to connect to device from pid[%d]", __func__, context.pid);

    if (!__ec_connect_reader(&context))
    {
        // The ec_device_release call is called asynchronously from the reader closing
        //  the device.  The test-app rapidly closes and reopens the device.
        //  Occasionally the reopen occurs before the cleanup, and it fails (4%).
        // This brief sleep allows us to recheck in this case, and possibly still
        //  connect.
        usleep_range(10000, 11000);
        if (!__ec_connect_reader(&context))
        {
            TRACE(DL_WARNING, "%s: refusing connection to device from pid[%d]; only one connection is allowed", __func__, context.pid);
            return -ECONNREFUSED;
        }
    }

    TRACE(DL_INFO, "%s: connected to device from pid[%d]", __func__, context.pid);

    return nonseekable_open(inode, filp);
}

int ec_device_release(struct inode *inode, struct file *filp)
{
    TRACE(DL_INFO, "%s: releasing device from pid[%d]; reader_pid[%d]", __func__, ec_getpid(current), atomic_read(&reader_pid));

    if (!ec_disconnect_reader(ec_getpid(current)))
    {
        return -ECONNREFUSED;
    }

    return 0;
}

unsigned int ec_device_poll(struct file *filp, struct poll_table_struct *pts)
{
    uint64_t qlen;

    // Check if data is available and lets go
    qlen = atomic64_read(&tx_ready_pri0) + atomic64_read(&tx_ready_pri1) + atomic64_read(&tx_ready_pri2);

    if (qlen != 0)
    {
        TRACE(DL_COMMS, "%s: msg available qlen=%llu", __func__, qlen);
        goto data_avail;
    }

    // We should call poll_wait here if we want the kernel to actually
    // sleep when waiting for us.
    TRACE(DL_COMMS, "%s: waiting for data", __func__);
    poll_wait(filp, &wq, pts);

    qlen = atomic64_read(&tx_ready_pri0) + atomic64_read(&tx_ready_pri1) + atomic64_read(&tx_ready_pri2);

    if (qlen != 0)
    {
        TRACE(DL_COMMS, "%s: msg available qlen=%llu", __func__, qlen);
        goto data_avail;
    }

    TRACE(DL_COMMS, "%s: msg queued qlen=%llu", __func__, qlen);

data_avail:

    // We should also return POLLHUP if we ever desire to shutdown
    return (qlen != 0 ? (POLLIN | POLLRDNORM) : 0);
}


long ec_device_unlocked_ioctl(struct file *filep, unsigned int cmd_in, unsigned long arg)
{
    unsigned int cmd  = _IOC_NR(cmd_in);
    size_t       size = _IOC_SIZE(cmd_in);
    void *page = 0;
    union {
        uint32_t         value;
        CB_EVENT_DYNAMIC dynControl;
        CB_DRIVER_CONFIG config;
        unsigned char    raw[0];
    } data;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    /**
     * If the module is disabled cannot process any commands.
     * The only allowed command is enable.
     */

    ModuleState moduleState = ec_get_module_state(&context);

    TRACE(DL_INFO, "%s: ioctl from pid[%d]", __func__, context.pid);

    // Only the connected process can send ioctls to this kernel module.
    if (!__ec_is_process_connected_reader(context.pid))
    {
        TRACE(DL_ERROR, "%s: Cannot process cmd=%d, process not authorized; pid[%d], reader-pid[%d]", __func__, cmd, context.pid, atomic_read(&reader_pid));
        return -EPERM;
    }

    if (!arg)
    {
        TRACE(DL_ERROR, "%s: arg null", __func__);
        return -ENOMEM;
    }

    if (!__ec_is_ioctl_allowed(moduleState, cmd))
    {
        TRACE(DL_ERROR, "%s: Cannot process cmd=%d, module is not enabled", __func__, cmd);
        return -EPERM;
    }

    if ((cmd == CB_DRIVER_REQUEST_SET_BANNED_INODE) ||
        (cmd == CB_DRIVER_REQUEST_SET_BANNED_INODE_WITHOUT_KILL) ||
        (cmd == CB_DRIVER_REQUEST_CLR_BANNED_INODE) ||
        (cmd == CB_DRIVER_REQUEST_SET_TRUSTED_PATH))
    {
        page = (void *)__get_free_page(GFP_MODE(&context));
        if (!page)
        {
            TRACE(DL_ERROR, "%s: alloc failed cmd=%d", __func__, cmd);
            return -ENOMEM;
        }
    } else
    {
        if (copy_from_user((void *)data.raw, (void *)arg, min(sizeof(data), size)))
        {
            TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
            return -ENOMEM;
        }
    }

    switch (cmd)
    {
    case CB_DRIVER_REQUEST_APPLY_FILTER:
        {
            __ec_apply_legacy_driver_config(data.value);
        }
        break;

    case CB_DRIVER_REQUEST_CONFIG:
        {
            __ec_apply_driver_config(&data.config);
        }
        break;

    case CB_DRIVER_REQUEST_IGNORE_UID:
        {
            uid_t uid = (uid_t)data.value;

            TRACE(DL_INFO, "Received uid=%u", uid);
            ec_banning_SetIgnoredUid(&context, uid);
        }
        break;

    case CB_DRIVER_REQUEST_IGNORE_SERVER:
        {
            uid_t uid = (uid_t)data.value;

            TRACE(DL_INFO, "Recevied server uid curr=%u new%u", uid,  g_edr_server_uid);
            if (uid != g_edr_server_uid)
            {
                TRACE(DL_WARNING, "+Setting CB server UID=%u", uid);
                g_edr_server_uid  = uid;
            }
        }
        break;

    case CB_DRIVER_REQUEST_IGNORE_PID:
        {
            pid_t pid = (pid_t)data.value;

            TRACE(DL_INFO, "Recevied trusted pid=%u", pid);
            ec_banning_SetIgnoredProcess(&context, pid);
        }
        break;

    case CB_DRIVER_REQUEST_ISOLATION_MODE_CONTROL:
        {
            ec_ProcessIsolationIoctl(&context, IOCTL_SET_ISOLATION_MODE, (void *)data.dynControl.data, data.dynControl.size);
        }
        break;

    case CB_DRIVER_REQUEST_HEARTBEAT:
        {
            PCB_EVENT event = NULL;

            CB_EVENT_HEARTBEAT heartbeat;

            if (copy_from_user(&heartbeat, (void *)arg, sizeof(heartbeat)))
            {
                TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
                return -ENOMEM;
            }

            TRACE(DL_INFO, "Got a heartbeat request.");
            event = ec_alloc_event(INTENT_REPORT, CB_EVENT_TYPE_HEARTBEAT, &context);
            if (event == NULL)
            {
                TRACE(DL_ERROR, "Unable to alloc CB_EVENT_TYPE_HEARTBEAT.");
            } else
            {
                atomic64_set(&mem_user,      heartbeat.user_memory);
                atomic64_set(&mem_user_peak, heartbeat.user_memory_peak);
                event->heartbeat.user_memory        = heartbeat.user_memory;
                event->heartbeat.user_memory_peak   = heartbeat.user_memory_peak;
                event->heartbeat.kernel_memory      = atomic64_read(&mem_kernel);
                event->heartbeat.kernel_memory_peak = atomic64_read(&mem_kernel_peak);
                ec_send_event(event, &context);
            }
        }
        break;

    case CB_DRIVER_REQUEST_SET_BANNED_INODE:
        {
            PCB_PROTECTION_CONTROL protectionData = (PCB_PROTECTION_CONTROL)page;
            int i;

            if (copy_from_user(page, (void *)arg, sizeof(CB_PROTECTION_CONTROL)))
            {
                TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
                free_page((unsigned long)page);
                return -ENOMEM;
            }

            for (i = 0; i < protectionData->count; ++i)
            {
                if (protectionData->data[i].action == InodeBanned)
                {
                    ec_banning_SetBannedProcessInode(&context, protectionData->data[i].device, protectionData->data[i].inode);
                    TRACE(DL_INFO, "%s: banned inode: [%llu:%llu]", __func__, protectionData->data[i].device, protectionData->data[i].inode);
                }
            }
            free_page((unsigned long)page);
        }
        break;

    case CB_DRIVER_REQUEST_SET_BANNED_INODE_WITHOUT_KILL:
        {
            PCB_PROTECTION_CONTROL protectionData = (PCB_PROTECTION_CONTROL)page;
            int i;

            if (copy_from_user(page, (void *)arg, sizeof(CB_PROTECTION_CONTROL)))
            {
                TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
                free_page((unsigned long)page);
                return -ENOMEM;
            }

            for (i = 0; i < protectionData->count; i++)
            {
                if (protectionData->data[i].action == InodeBanned)
                {
                    ec_banning_SetBannedProcessInodeWithoutKillingProcs(&context, protectionData->data[i].device, protectionData->data[i].inode);
                    TRACE(DL_INFO, "%s: banned inode (w/o proc kill): [%llu:%llu]",
                          __func__, protectionData->data[i].device, protectionData->data[i].inode);
                }
            }
            free_page((unsigned long)page);
        }
        break;

    case CB_DRIVER_REQUEST_PROTECTION_ENABLED:
        {
            ec_banning_SetProtectionState(&context, (uint32_t)data.value);
        }

    case CB_DRIVER_REQUEST_CLR_BANNED_INODE:
        {
            ec_banning_ClearAllBans(&context);
            free_page((unsigned long)page);
        }
        break;

    case CB_DRIVER_REQUEST_SET_TRUSTED_PATH:
        {
            PCB_TRUSTED_PATH pathData = (PCB_TRUSTED_PATH)page;

            if (copy_from_user(page, (void *)arg, size))
            {
                TRACE(DL_ERROR, "%s: failed to copy arg", __func__);
                free_page((unsigned long)page);
                return -ENOMEM;
            }

            TRACE(DL_INFO, "pathData=%p path=%s", pathData, pathData->path);
            free_page((unsigned long)page);
        }
        break;

    case CB_DRIVER_REQUEST_SET_LOG_LEVEL:
        {
            g_traceLevel = data.value;
            TRACE(DL_INFO, "Set trace level=%x", g_traceLevel);
        }
        break;

    case CB_DRIVER_REQUEST_ACTION:
        {
            int result = 0;
            CB_EVENT_ACTION_TYPE action = (CB_EVENT_ACTION_TYPE) data.value;

            if (!__ec_is_action_allowed(moduleState, action))
            {
                TRACE(DL_ERROR, "%s: Module state is %d, cmd %d, action %d is illegal", __func__, moduleState, cmd, action);
                return -EPERM;
            }

            result = __ec_DoAction(&context, action);
            return result;
        }
        break;

    default:
        TRACE(DL_INFO, "Unknown request type %d", cmd);
        break;
    }

    return 0l;
}


bool __ec_is_ioctl_allowed(ModuleState module_state, unsigned int cmd)
{
    return (module_state == ModuleStateEnabled || cmd == CB_DRIVER_REQUEST_ACTION);
}

/**
 * Check if module is not enabled, the only allowed action is one that changes states,
 * fail any other actions.
 */
bool __ec_is_action_allowed(ModuleState moduleState, CB_EVENT_ACTION_TYPE action)
{
    return ((moduleState == ModuleStateEnabled) ||
            (action == CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR ||
             action == CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR));
}

int __ec_DoAction(ProcessContext *context, CB_EVENT_ACTION_TYPE action)
{
    int result = 0;

    TRACE(DL_INFO, "Recevied action=%u", action);
    switch (action)
    {
    case CB_EVENT_ACTION_CLEAR_EVENT_QUEUE:
        ec_user_comm_clear_queues(context);
        break;

    case CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR:
        result = ec_enable_module(context);
        break;

    case CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR:
        result = ec_disable_module(context);
        break;

    case CB_EVENT_ACTION_REQUEST_PROCESS_DISCOVERY:
        ec_process_tracking_send_process_discovery(context);
        break;

    default:
        break;
    }

    return result;
}

void __ec_apply_legacy_driver_config(uint32_t eventFilter)
{
    g_driver_config.processes = (eventFilter & CB_EVENT_FILTER_PROCESSES ? ALL_FORKS_AND_EXITS : DISABLE);
    g_driver_config.module_loads = (eventFilter & CB_EVENT_FILTER_MODULE_LOADS ? ENABLE : DISABLE);
    g_driver_config.file_mods = (eventFilter & CB_EVENT_FILTER_FILEMODS ? ENABLE : DISABLE);
    g_driver_config.net_conns = (eventFilter & CB_EVENT_FILTER_NETCONNS ? ENABLE : DISABLE);
    g_driver_config.report_process_user = (eventFilter & CB_EVENT_FILTER_PROCESSUSER ? ENABLE : DISABLE);

    __ec_print_driver_config("New Module Config", &g_driver_config);
}

void __ec_apply_driver_config(CB_DRIVER_CONFIG *config)
{
    if (config)
    {
        g_driver_config.processes = (config->processes != NO_CHANGE ? config->processes : g_driver_config.processes);
        g_driver_config.module_loads = (config->module_loads != NO_CHANGE ? config->module_loads : g_driver_config.module_loads);
        g_driver_config.file_mods = (config->file_mods != NO_CHANGE ? config->file_mods : g_driver_config.file_mods);
        g_driver_config.net_conns = (config->net_conns != NO_CHANGE ? config->net_conns : g_driver_config.net_conns);
        g_driver_config.report_process_user = (config->report_process_user != NO_CHANGE ? config->report_process_user : g_driver_config.report_process_user);
        g_driver_config.report_file_intent = (config->report_file_intent != NO_CHANGE ? config->report_file_intent : g_driver_config.report_file_intent);

        __ec_print_driver_config("New Module Config", &g_driver_config);
    }
}

#define STR(A) #A

char *__ec_driver_config_option_to_string(CB_CONFIG_OPTION config_option)
{
    char *str =  "<unknown>";

    switch (config_option)
    {
    case NO_CHANGE: str = STR(NO_CHANGE); break;
    case DISABLE: str = STR(DISABLE); break;
    case ENABLE: str = STR(ENABLE); break;
    case ALL_FORKS_AND_EXITS: str = STR(ALL_FORKS_AND_EXITS); break;
    case EXECS_ONLY: str = STR(EXECS_ONLY); break;
    case COLLAPSED_EXITS_ALL_FORKS: str = STR(COLLAPSED_EXITS_ALL_FORKS); break;
    case COLLAPSED_EXITS_NO_FORKS: str = STR(COLLAPSED_EXITS_NO_FORKS); break;
    }
    return str;
}

void __ec_print_driver_config(char *msg, CB_DRIVER_CONFIG *config)
{
    if (config)
    {
        TRACE(DL_INFO, "%s: %s, %s, %s, %s, %s, %s",
            msg,
            __ec_driver_config_option_to_string(config->processes),
            __ec_driver_config_option_to_string(config->module_loads),
            __ec_driver_config_option_to_string(config->file_mods),
            __ec_driver_config_option_to_string(config->net_conns),
            __ec_driver_config_option_to_string(config->report_process_user),
            __ec_driver_config_option_to_string(config->report_file_intent));
    }
}

void ec_stats_work_task(struct work_struct *work)
{
    uint32_t         curr   = atomic_read(&s_event_stats.curr);
    uint32_t         next   = (curr + 1) % MAX_INTERVALS;
    uint64_t         ready0 = atomic64_read(&tx_ready_pri0);
    uint64_t         ready1 = atomic64_read(&tx_ready_pri1);
    uint64_t         ready2 = atomic64_read(&tx_ready_pri2);
    uint64_t         prev0  = atomic64_read(&tx_ready_prev0);
    uint64_t         prev1  = atomic64_read(&tx_ready_prev1);
    uint64_t         prev2  = atomic64_read(&tx_ready_prev2);
    int              i;
    size_t           kernel_mem;
    size_t           kernel_mem_peak;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // I am not strictly speaking doing this operation atomicly.  This means there is a
    //  chance that a counter will be missed.  I am willing to allow that for the sake of
    //  performance.

    // tx_ready_X are live counters that rise and fall as events are generated. Add whatever
    //  is new in this variable to the current stat.
    if (ready0 > prev0)
    {
        atomic64_add(ready0 - prev0, &tx_queued_pri0);
    }
    if (ready1 > prev1)
    {
        atomic64_add(ready1 - prev1, &tx_queued_pri1);
    }
    if (ready2 > prev2)
    {
        atomic64_add(ready2 - prev2, &tx_queued_pri2);
    }

    // Save the current totals for nex time
    atomic64_set(&tx_ready_prev0, ready0);
    atomic64_set(&tx_ready_prev1, ready1);
    atomic64_add(ready0 + ready1, &tx_queued_t);

    // Copy over the current total to the next interval
    for (i = 0; i < NUM_STATS; ++i)
    {
        atomic64_set(&s_event_stats.stats[next][i], atomic64_read(&s_event_stats.stats[curr][i]));
    }
    atomic_set(&current_stat, next);
    atomic_inc(&valid_stats);
    getnstimeofday(&s_event_stats.time[next]);
    kernel_mem      = __ec_get_memory_usage(&context);
    kernel_mem_peak = atomic64_read(&mem_kernel_peak);
    atomic64_set(&mem_kernel,      kernel_mem);
    atomic64_set(&mem_kernel_peak, (kernel_mem > kernel_mem_peak ? kernel_mem : kernel_mem_peak));

    schedule_delayed_work(&stats_work, g_stats_work_delay);
}

// Print event stats
int ec_proc_show_events_avg(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = atomic_read(&s_event_stats.curr) + MAX_INTERVALS;
    uint32_t    valid   = atomic_read(&s_event_stats.validStats);
    int32_t     avg1_c  = (valid >  4 ?  4 : valid);
    int32_t     avg2_c  = (valid > 20 ? 20 : valid);
    int32_t     avg3_c  = (valid > 60 ? 60 : valid);
    int32_t     avg1    = (curr - avg1_c) % MAX_INTERVALS;
    int32_t     avg2    = (curr - avg2_c) % MAX_INTERVALS;
    int32_t     avg3    = (curr - avg3_c) % MAX_INTERVALS;

    int         i;

    if (valid == 0)
    {
        seq_puts(m, "No Data\n");
        return 0;
    }

    // I only want to include valid intervals, so back the current pointer to the last valid
    curr = (curr - 1) % MAX_INTERVALS;

    seq_printf(m, " %15s | %9s | %9s | %9s | %10s |\n", "Stat", "Total",  "1 min avg", "5 min avg", "15 min avg");

    // Uncomment this to debug the averaging
    //seq_printf(m, " %15s | %9d | %9d | %9d | %10d\n", "Avgs", curr, avg1, avg2, avg3 );
    for (i = 1; i < EVENT_STATS; ++i)
    {
        // This is a circular array of elements were each element is an increasing sum from the
        //  previous element. You can always get the sum of any two elements, and divide by the
        //  number of elements between them to yield the average.
        uint64_t currentStat = atomic64_read(&s_event_stats.stats[curr][i]);

        seq_printf(m, " %15s | %9lld | %9lld | %9lld | %10lld |\n", STAT_STRINGS[i].name, currentStat,
                   (currentStat - atomic64_read(&s_event_stats.stats[avg1][i])) / avg1_c / STAT_INTERVAL,
                   (currentStat - atomic64_read(&s_event_stats.stats[avg2][i])) / avg2_c / STAT_INTERVAL,
                   (currentStat - atomic64_read(&s_event_stats.stats[avg3][i])) / avg3_c / STAT_INTERVAL);
    }

    seq_puts(m, "\n");

    return 0;
}

int ec_proc_show_events_det(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = atomic_read(&s_event_stats.curr);
    uint32_t    valid   = min(atomic_read(&s_event_stats.validStats), MAX_VALID_INTERVALS);
    uint32_t    start   = (MAX_INTERVALS + curr - valid) % MAX_INTERVALS + MAX_INTERVALS;
    int         i;
    int         j;

    if (valid == 0)
    {
        seq_puts(m, "No Data\n");
        return 0;
    }
    //seq_printf(m, "Curr = %d, valid = %d, start = %d\n", curr, valid, start - MAX_INTERVALS );

    seq_printf(m, " %19s |", "Timestamp");
    for (j = 0; j < EVENT_STATS; ++j)
    {
        seq_printf(m, STAT_STRINGS[j].str_format, STAT_STRINGS[j].name);
    }
    seq_puts(m, "\n");

    for (i = 0; i < valid; ++i)
    {
        uint64_t left  = (start + i - 1) % MAX_INTERVALS;
        uint64_t right = (start + i) % MAX_INTERVALS;

        seq_printf(m, " %19lld |", ec_to_windows_timestamp(&s_event_stats.time[right]));
        for (j = 0; j < EVENT_STATS; ++j)
        {
            seq_printf(m, STAT_STRINGS[j].num_format, atomic64_read(&s_event_stats.stats[right][j]) - atomic64_read(&s_event_stats.stats[left][j]));
        }
        seq_puts(m, "\n");
    }

    return 0;
}

ssize_t ec_proc_show_events_rst(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    int i;

    // Cancel the currently scheduled job
    cancel_delayed_work(&stats_work);

    // I do not need to zero out everything, just the new active interval
    atomic_set(&current_stat,  0);
    atomic_set(&valid_stats,   0);
    for (i = 0; i < NUM_STATS; ++i)
    {
        // We make sure the first and last interval are 0 for the average calculations
        atomic64_set(&s_event_stats.stats[0][i],                0);
        atomic64_set(&s_event_stats.stats[MAX_INTERVALS - 1][i], 0);
    }
    getnstimeofday(&s_event_stats.time[0]);

    // Resatrt the job from now
    schedule_delayed_work(&stats_work, g_stats_work_delay);
    return size;
}

int ec_proc_current_memory_avg(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = atomic_read(&s_event_stats.curr);

    int         i;

    for (i = MEM_START; i < MEM_STATS; ++i)
    {
        // This is a circular array of elements were each element is an increasing sum from the
        //  previous element. You can always get the sum of any two elements, and divide by the
        //  number of elements between them to yield the average.
        uint64_t currentStat = atomic64_read(&s_event_stats.stats[curr][i]);

        seq_printf(m, "%9lld ", currentStat);
    }

    seq_puts(m, "\n");

    return 0;
}

int ec_proc_current_memory_det(struct seq_file *m, void *v)
{
    // I add MAX_INTERVALS to some of the items below so that when I subtract 1 it will
    //  still be a positive number.  The modulus math will clean it up later.
    uint32_t    curr    = atomic_read(&s_event_stats.curr);
    uint32_t    valid   = min(atomic_read(&s_event_stats.validStats), MAX_VALID_INTERVALS);
    uint32_t    start   = (MAX_INTERVALS + curr - valid) % MAX_INTERVALS + MAX_INTERVALS;
    int         i;
    int         j;

    if (valid == 0)
    {
        seq_puts(m, "No Data\n");
        return 0;
    }
    //seq_printf(m, "Curr = %d, valid = %d, start = %d\n", curr, valid, start - MAX_INTERVALS );

    seq_printf(m, " %19s |", "Timestamp");
    for (j = MEM_START; j < MEM_STATS; ++j)
    {
        seq_printf(m, STAT_STRINGS[j].str_format, STAT_STRINGS[j].name);
    }
    seq_puts(m, "\n");

    for (i = 0; i < valid; ++i)
    {
        uint64_t right = (start + i) % MAX_INTERVALS;

        seq_printf(m, " %19lld |", ec_to_windows_timestamp(&s_event_stats.time[right]));
        for (j = MEM_START; j < MEM_STATS; ++j)
        {
            seq_printf(m, STAT_STRINGS[j].num_format, atomic64_read(&s_event_stats.stats[right][j]));
        }
        //seq_printf(m, " %9lld | %9lld |", left, right );
        seq_puts(m, "\n");
    }

    return 0;
}

size_t __ec_get_memory_usage(ProcessContext *context)
{
    return ec_mem_cache_get_memory_usage(context) +
           ec_hashtbl_get_memory(context);
}

// Eventually do this just before attempting to enqueue the event.
int __ec_precompute_payload(struct CB_EVENT *cb_event)
{
    int payload = 0;

    if (!cb_event)
    {
        return -EINVAL;
    }

    payload += sizeof(struct CB_EVENT_UM);

    if (cb_event->procInfo.path && cb_event->procInfo.path_size)
    {
        cb_event->procInfo.path_offset = payload;
        payload += cb_event->procInfo.path_size;
    }

    switch (cb_event->eventType)
    {
    case CB_EVENT_TYPE_PROCESS_START:
        if (cb_event->processStart.path && cb_event->processStart.path_size)
        {
            cb_event->processStart.path_offset = payload;
            payload += cb_event->processStart.path_size;
        }
        break;

    case CB_EVENT_TYPE_PROCESS_EXIT:
    case CB_EVENT_TYPE_PROCESS_LAST_EXIT:
        break;

    case CB_EVENT_TYPE_MODULE_LOAD:
        if (cb_event->moduleLoad.path && cb_event->moduleLoad.path_size)
        {
            cb_event->moduleLoad.path_offset = payload;
            payload += cb_event->moduleLoad.path_size;
        }
        break;

    case CB_EVENT_TYPE_FILE_CREATE:
    case CB_EVENT_TYPE_FILE_DELETE:
    case CB_EVENT_TYPE_FILE_OPEN:
    case CB_EVENT_TYPE_FILE_WRITE:
    case CB_EVENT_TYPE_FILE_CLOSE:
        if (cb_event->fileGeneric.path && cb_event->fileGeneric.path_size)
        {
            cb_event->fileGeneric.path_offset = payload;
            payload += cb_event->fileGeneric.path_size;
        }
        break;

    case CB_EVENT_TYPE_NET_CONNECT_PRE:
    case CB_EVENT_TYPE_NET_CONNECT_POST:
    case CB_EVENT_TYPE_NET_ACCEPT:
    case CB_EVENT_TYPE_WEB_PROXY:
        if (cb_event->netConnect.actual_server && cb_event->netConnect.server_size)
        {
            cb_event->netConnect.server_offset = payload;
            payload += cb_event->netConnect.server_size;
        }
        break;

    case CB_EVENT_TYPE_DNS_RESPONSE:
        if (cb_event->dnsResponse.records && cb_event->dnsResponse.record_count)
        {
            cb_event->dnsResponse.record_offset = payload;
            payload += cb_event->dnsResponse.record_count * sizeof(CB_DNS_RECORD);
        }

        break;

    case CB_EVENT_TYPE_PROCESS_BLOCKED:
        if (cb_event->blockResponse.path && cb_event->blockResponse.path_size)
        {
            cb_event->blockResponse.path_offset = payload;
            payload += cb_event->blockResponse.path_size;
        }
        break;

    case CB_EVENT_TYPE_HEARTBEAT:
        break;

    // Internal To The Kernel
    case CB_EVENT_TYPE_PROCESS_START_FORK:
    case CB_EVENT_TYPE_PROCESS_START_EXEC:
        return -EINVAL;

    // Unused
    case CB_EVENT_TYPE_UNKNOWN:
    case CB_EVENT_TYPE_PROC_ANALYZE:
    case CB_EVENT_TYPE_PROCESS_NOT_BLOCKED:
        break;

    default:
        if (cb_event->eventType < CB_EVENT_TYPE_UNKNOWN || cb_event->eventType >= CB_EVENT_TYPE_MAX)
        {
            return -EINVAL;
        }
        break;
    }

    return payload;
}
