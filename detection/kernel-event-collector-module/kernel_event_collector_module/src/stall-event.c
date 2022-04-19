// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include "priv.h"
#include "mem-cache.h"
#include "hash-table-generic.h"

struct stall_event_key {
    uint64_t perm_id;
    pid_t tid;
    CB_EVENT_TYPE eventType;
};

struct stall_event {
    HashTableNode link;
    struct stall_event_key key;

#define EC_STALL_MODE_STALL   0x0
#define EC_STALL_MODE_WAKEUP  0x1

// Combine following with EC_STALL_MODE_WAKEUP
#define EC_STALL_MODE_FLUSH   0x2   // use when we drain pipes
#define EC_STALL_MODE_ABORT   0x4   // use during critical error
    u8 mode;
    int response;
    wait_queue_head_t waitq;
};

// Data from struct stall_event that we care about
// to release stall_event sooner than later.
struct stall_data {
    u8 mode;
    int response;
};


static bool enabled;
static atomic64_t perm_id = ATOMIC64_INIT(0);
static HashTbl *stall_tbl;

bool ec_current_task_may_stall(void)
{
// defined in linux/preempt.h
#ifdef in_task
    return in_task();
#else
    return (!(in_interrupt() || in_irq() || in_softirq() || in_nmi()));
#endif
}

void ec_stall_tbl_delete_callback(void *data, ProcessContext *context)
{
    TRACE(DL_INFO, "%s %#lx", __func__, (unsigned long)data);
}

bool ec_stall_events_initialize(ProcessContext *context)
{
    TRACE(DL_INFO, "Initializing Authorizations");

    stall_tbl = ec_hashtbl_init_generic(context, BIT(14),
                                        sizeof(struct stall_event),
                                        sizeof(struct stall_event),
                                        "stall_tbl",
                                        sizeof(struct stall_event_key),
                                        offsetof(struct stall_event, key),
                                        offsetof(struct stall_event, link),
                                        HASHTBL_DISABLE_REF_COUNT,
                                        ec_stall_tbl_delete_callback,
                                        NULL);
    enabled = false;

    return (stall_tbl != NULL);
}

void ec_wake_stalled_task(struct stall_event *stall_event)
{
    if (stall_event)
    {
        wake_up(&stall_event->waitq);
    }
}

// Flush is used instead of clear as terminology since we are letting the tasks remove it's entry
int __ec_flush_callback(HashTbl *stall_tbl, HashTableNode *nodep, void *priv, ProcessContext *context)
{
    struct stall_event *stall_event = (struct stall_event *)nodep;

    if (stall_event)
    {
        if (stall_event->mode == EC_STALL_MODE_STALL)
        {
            stall_event->mode = EC_STALL_MODE_WAKEUP|EC_STALL_MODE_FLUSH;
            ec_wake_stalled_task(stall_event);
        }
    }

    return ACTION_CONTINUE;
}

void __ec_stall_events_flush(ProcessContext *context)
{
    if (stall_tbl)
    {
        // Requests to wake up all the tasks a couple times if scheduling is large
        ec_hashtbl_write_for_each_generic(stall_tbl, __ec_flush_callback, NULL, context);
    }
}

void ec_stall_events_flush(ProcessContext *context)
{
    if (enabled)
    {
        __ec_stall_events_flush(context);
    }
}

void ec_enable_stall_events(void)
{
    if (!enabled && stall_tbl)
    {
        enabled = true;
    }
}

void ec_disable_stall_events(ProcessContext *context)
{
    if (enabled)
    {
        enabled = false;
        __ec_stall_events_flush(context);
    }
}

void ec_stall_events_shutdown(ProcessContext *context)
{
    ec_disable_stall_events(context);

    ec_hashtbl_shutdown_generic(stall_tbl, context);
    stall_tbl = NULL;
}

uint64_t ec_next_perm_id(void)
{
    if (enabled)
    {
        return atomic64_inc_return(&perm_id);
    }
    return 0;
}

bool ec_stall_events_enabled(void)
{
    return enabled && stall_tbl;
}

void ec_free_stall_event(struct stall_event *stall_event, ProcessContext *context)
{
    if (stall_event)
    {
        ec_hashtbl_free_generic(stall_tbl, stall_event, context);
    }
}

int ec_stall_event_abort(uint64_t perm_id, pid_t tid, CB_EVENT_TYPE eventType, ProcessContext *context)
{
    int ret = -ENOENT;
    int response = 0;
    struct stall_event *stall_event = NULL;
    struct stall_event_key key = {};
    HashTableBkt *bkt = NULL;
    bool found;

    if (!ec_stall_events_enabled())
    {
        return -EINVAL;
    }

    key.perm_id = perm_id;
    key.tid = tid;
    key.eventType = eventType;

    // Update entry data - so use write lock
    found = ec_hashtbl_write_bkt_lock(stall_tbl, &key, (void **)&stall_event, &bkt, context);
    if (found)
    {
        if (stall_event->mode == EC_STALL_MODE_STALL)
        {
            stall_event->response = response;
            stall_event->mode = EC_STALL_MODE_WAKEUP|EC_STALL_MODE_ABORT;
            ec_wake_stalled_task(stall_event);
        }
        ec_hashtbl_write_bkt_unlock(bkt, context);
        ret = 0;
    }
    return ret;
}

int ec_stall_event_resume(struct CB_PERM_RESPONSE *perm_response, ProcessContext *context)
{
    struct stall_event *stall_event = NULL;
    struct stall_event_key key = {};
    int ret = -ENOENT;
    int response = -EPERM;
    HashTableBkt *bkt = NULL;
    bool found;

    if (!ec_stall_events_enabled())
    {
        return -EINVAL;
    }

    if (!perm_response)
    {
        return -EINVAL;
    }

    // map to errno values
    switch (perm_response->response)
    {
    case CB_PERM_RESPONSE_TYPE_ALLOW:
        response = 0;
        break;

    case CB_PERM_RESPONSE_TYPE_EACCES:
        response = -EACCES;
        break;

    case CB_PERM_RESPONSE_TYPE_EPERM:
        response = -EPERM;
        break;

    case CB_PERM_RESPONSE_TYPE_ENOENT:
        response = -ENOENT;
        break;

    default:
        return -EINVAL;
    }

    key.perm_id = perm_response->perm_id;
    key.tid = perm_response->tid;
    key.eventType = perm_response->eventType;

    // Update entry data - so use write lock
    found = ec_hashtbl_write_bkt_lock(stall_tbl, &key, (void **)&stall_event, &bkt, context);
    if (found)
    {
        if (stall_event->mode == EC_STALL_MODE_STALL)
        {
            stall_event->response = response;
            stall_event->mode = EC_STALL_MODE_WAKEUP;
            ec_wake_stalled_task(stall_event);
        }
        ec_hashtbl_write_bkt_unlock(bkt, context);
        ret = 0;
    }

    return ret;
}

struct stall_event *ec_alloc_stall_event(uint64_t perm_id, pid_t tid, CB_EVENT_TYPE eventType,
                                         ProcessContext *context)
{
    struct stall_event *stall_event = NULL;

    if (!ec_stall_events_enabled())
    {
        return NULL;
    }

    stall_event = ec_hashtbl_alloc_generic(stall_tbl, context);
    if (stall_event)
    {
        init_waitqueue_head(&stall_event->waitq);
        stall_event->key.perm_id = perm_id;
        stall_event->key.tid = tid;
        stall_event->key.eventType = eventType;
        stall_event->mode = EC_STALL_MODE_STALL;
        stall_event->response = 0;
    }

    return stall_event;
}

int ec_stall_event_enqueue(struct stall_event *stall_event, ProcessContext *context)
{
    int ret = -EINVAL;

    if (!stall_event)
    {
        return -EINVAL;
    }

    // Set timestamp here to track duration of stalls

    ret = ec_hashtbl_add_generic_safe(stall_tbl, stall_event, context);
    if (ret < 0)
    {
        TRACE(DL_WARNING, "Unable to queue stall event:%d tid:%d eventType:%d", ret,
              stall_event->key.tid, stall_event->key.eventType);
    }
    return ret;
}

// Helps remove any direct exposure to stall_event instances
bool __ec_get_stall_data_and_release(uint64_t perm_id, pid_t tid, CB_EVENT_TYPE eventType, struct stall_data *stall_data,
                                     ProcessContext *context)
{
    bool found = false;
    HashTableBkt *bkt = NULL;
    struct stall_event *stall_event = NULL;
    struct stall_event_key key = {
        .perm_id = perm_id,
        .tid = tid,
        .eventType = eventType,
    };

    // Read the data we need and might as well remove from bucket - Write Lock
    found = ec_hashtbl_write_bkt_lock(stall_tbl, &key, (void **)&stall_event, &bkt, context);
    if (found)
    {
        if (stall_data)
        {
            stall_data->mode = stall_event->mode;
            stall_data->response = stall_event->response;
        }

        // Do not call this unless you know what you are doing
        ec_hashtbl_del_generic_lockheld(stall_tbl, stall_event, context);
        ec_hashtbl_write_bkt_unlock(bkt, context);

        TRACE(DL_INFO, "%s: FOUND - tid:%d eventType:%d response:%d mode:%x", __func__,
              tid, eventType, stall_data->response, stall_data->mode);

        // Free the stall event
        ec_free_stall_event(stall_event, context);
    } else
    {
        TRACE(DL_INFO, "%s: Does Not Exist - tid:%d eventType:%d", __func__,
              tid, eventType);
    }

    return found;
}

int ec_wait_stall_event_killable(uint64_t perm_id, pid_t tid, CB_EVENT_TYPE eventType, ProcessContext *context)
{
    int ret;
    int response = 0;
    struct stall_event *stall_event = NULL;
    bool found;
    struct stall_data stall_data = {};

    if (!context)
    {
        return -EINVAL;
    }

    stall_event = ec_alloc_stall_event(perm_id, tid, eventType, context);

    ret = ec_stall_event_enqueue(stall_event, context);
    if (ret)
    {
        ec_free_stall_event(stall_event, context);
        return -EINVAL;
    }

    ret = wait_event_killable(stall_event->waitq, stall_event->mode != EC_STALL_MODE_STALL);
    stall_event = NULL; // just for extra measure
    found = __ec_get_stall_data_and_release(perm_id, tid, eventType, &stall_data, context);
    if (!found)
    {
        return response;
    }

    // wait_event_killable returns 0 when condition evaluates to true
    if (ret == 0)
    {
        response = stall_data.response;
    } else // signal interrupted
    {
        TRACE(DL_INFO, "%s: Signaled:%d - tid:%d eventType:%d mode:%#x", __func__, ret,
              tid, eventType, stall_data.mode);
    }

    return response;
}

int ec_wait_stall_event_timeout(uint64_t perm_id, pid_t tid, CB_EVENT_TYPE eventType, unsigned int ms,
                                ProcessContext *context)
{
    int ret;
    int response = 0;
    struct stall_event *stall_event = NULL;
    bool found;
    struct stall_data stall_data = {};

    if (!context)
    {
        return -EINVAL;
    }

    stall_event = ec_alloc_stall_event(perm_id, tid, eventType, context);

    ret = ec_stall_event_enqueue(stall_event, context);
    if (ret)
    {
        ec_free_stall_event(stall_event, context);
        return -EINVAL;
    }

    ret = wait_event_timeout(stall_event->waitq, stall_event->mode != EC_STALL_MODE_STALL,
                             msecs_to_jiffies(ms));
    stall_event = NULL; // just for extra measure
    found = __ec_get_stall_data_and_release(perm_id, tid, eventType, &stall_data, context);
    if (!found)
    {
        return response;
    }

    if (ret >= 1)
    {
        response = stall_data.response;
    } else
    {
        TRACE(DL_INFO, "%s: Timedout:%d - tid:%d eventType:%d mode:%#x", __func__, ret,
              tid, eventType, stall_data.mode);
    }

    return response;
}

int ec_wait_stall_event_killable_timeout(uint64_t perm_id, pid_t tid, CB_EVENT_TYPE eventType, unsigned int ms,
                                         ProcessContext *context)
{
// defined in linux/wait.h
#ifdef wait_event_killable_timeout
    int ret;
    int response = 0;
    struct stall_event *stall_event = NULL;
    bool found;
    struct stall_data stall_data = {};

    if (!context)
    {
        return -EINVAL;
    }

    stall_event = ec_alloc_stall_event(perm_id, tid, eventType, context);

    ret = ec_stall_event_enqueue(stall_event, context);
    if (ret)
    {
        ec_free_stall_event(stall_event, context);
        return -EINVAL;
    }

    ret = wait_event_killable_timeout(stall_event->waitq, stall_event->mode != EC_STALL_MODE_STALL,
                                      msecs_to_jiffies(ms));
    stall_event = NULL; // just for extra measure
    found = __ec_get_stall_data_and_release(perm_id, tid, eventType, &stall_data, context);
    if (!found)
    {
        return response;
    }

    if (ret >= 1)
    {
        response = stall_data.response;
    } else // signal interrupted (-ERESTARTSYS) or timed out (0)
    {
        TRACE(DL_INFO, "%s: Signaled or Timedout:%d - tid:%d eventType:%d mode:%#x", __func__, ret,
              tid, eventType, stall_data.mode);
    }

    return response;
#else
    return ec_wait_stall_event_timeout(perm_id, tid, eventType, ms, context);
#endif  /* ! wait_event_killable_timeout */
}
