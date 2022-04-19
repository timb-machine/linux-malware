// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include "priv.h"
#include "run-tests.h"
#include "stall-event.h"

#include <linux/kthread.h>

bool __init test__stall_enable(ProcessContext *context)
{
    bool passed = false;
    ec_enable_stall_events();

    if (ec_stall_events_enabled() == true)
    {
        passed = true;
    }

    TRACE(DL_ERROR, "ec_enable_stall_events: %d", ec_stall_events_enabled());

    ec_disable_stall_events(context);

    return passed;
}

static unsigned long long now_milli(void)
{
    struct timespec now;
    getrawmonotonic(&now);
    return (now.tv_sec * MSEC_PER_SEC) + (now.tv_nsec / NSEC_PER_MSEC);
}

// Stall current task for 500 milliseconds
bool __init test__stall_timedout(ProcessContext *context)
{
    bool passed = false;
    int ret;
    unsigned long long start;
    unsigned long long diff;
    unsigned int ms_wait = 1000;

    ec_enable_stall_events();

    start = now_milli();
    ret = ec_wait_stall_event_timeout(0, 0, CB_EVENT_TYPE_MODULE_LOAD, ms_wait, context);
    diff = now_milli() - start;
    TRACE(DL_INFO, "diff:%llu  max wait time:%u ms", diff, ms_wait);
    ASSERT_TRY((unsigned int)diff >= ms_wait -1); // diff might be truncated a bit
    TRY_MSG(!ret, DL_ERROR, "ec_wait_stall_event_timeout failed ret: %d", ret);
    passed = true;

CATCH_DEFAULT:
    ec_disable_stall_events(context);

    return passed;
}


bool __init test__perm_id(ProcessContext *context)
{
    bool passed = false;
    uint64_t perm_id;

    ec_enable_stall_events();
    perm_id = ec_next_perm_id();
    ASSERT_TRY(perm_id > 0);
    ASSERT_TRY(ec_next_perm_id() > perm_id);
    passed = true;

CATCH_DEFAULT:
    ec_disable_stall_events(context);
    return passed;
}

bool __init test__perm_id_disabled(ProcessContext *context)
{
    bool passed = false;
    uint64_t perm_id;

    ec_disable_stall_events(context);
    perm_id = ec_next_perm_id();
    ASSERT_TRY(perm_id == 0);
    ASSERT_TRY(0 == ec_next_perm_id());
    passed = true;

CATCH_DEFAULT:
    ec_disable_stall_events(context);
    return passed;
}

// Call ec_stall_event_resume on a delay to act like a response
// from userspace.
int defer_stall_event_resume(void *data)
{
    int ret;
    struct CB_PERM_RESPONSE *cb_perm_response = (struct CB_PERM_RESPONSE *)data;
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    if (!data)
    {
        return -1;
    }

    msleep(100);

    // This would really called from char device's write file ops hook
    ret = ec_stall_event_resume(cb_perm_response, &context);

    return 0;
}

static struct CB_PERM_RESPONSE cb_perm_eperm;

// Wait for a response instead of a timeout
bool __init test__stall_event_EPERM(ProcessContext *context)
{
    uint64_t perm_id;
    pid_t tid;
    bool passed = false;
    int ret;
    struct task_struct *task = NULL;
    unsigned long long start;
    unsigned long long diff;
    unsigned int ms_wait = 1000;


    ec_enable_stall_events();

    // Setup Helper task that will act as a response from userspace
    task = kthread_create(&defer_stall_event_resume, &cb_perm_eperm, "defer_EPERM");
    ASSERT_TRY(!IS_ERR(task));
    tid = task->pid;

    memset(&cb_perm_eperm, 0, sizeof(cb_perm_eperm));

    cb_perm_eperm.tid = tid;
    cb_perm_eperm.eventType = CB_EVENT_TYPE_MODULE_LOAD;
    cb_perm_eperm.response = CB_PERM_RESPONSE_TYPE_EPERM;
    perm_id = cb_perm_eperm.perm_id = ec_next_perm_id();

    start = now_milli();
    wake_up_process(task);

    ret = ec_wait_stall_event_timeout(perm_id, tid, CB_EVENT_TYPE_MODULE_LOAD, ms_wait, context);
    diff = now_milli() - start;
    TRACE(DL_INFO, "diff:%llu  max wait time:%u ms", diff, ms_wait);
    ASSERT_TRY(ret == -EPERM);
    ASSERT_TRY((unsigned int)diff < ms_wait);

    passed = true;
CATCH_DEFAULT:
    ec_disable_stall_events(context);

    return passed;
}


static int defer_stall_disable(void *data)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    msleep(100);
    ec_disable_stall_events(&context);
    return 0;
}

bool __init test__stall_one_during_disable(ProcessContext *context)
{
    struct task_struct *task;
    bool passed = false;
    int ret;
    unsigned long long start;
    unsigned long long diff;
    unsigned int ms_wait = 1000;

    ec_enable_stall_events();

    start = now_milli();
    task = kthread_run(&defer_stall_disable, NULL, "defer_disable");
    ASSERT_TRY(!IS_ERR(task));
    ret = ec_wait_stall_event_timeout(0, 0, CB_EVENT_TYPE_MODULE_LOAD, ms_wait, context);
    diff = now_milli() - start;
    TRACE(DL_INFO, "diff:%llu  max wait time:%u ms", diff, ms_wait);
    ASSERT_TRY(0 == ret);
    ASSERT_TRY((unsigned int) diff < ms_wait);
    passed = true;

CATCH_DEFAULT:
    ec_disable_stall_events(context);
    return passed;
}


static int kthread_may_stall(void *data)
{
    bool *may_stall = (bool *)data;

    if (!data)
    {
        return -1;
    }

    *may_stall = ec_current_task_may_stall();

    return 0;
}

bool __init test__kthread_may_stall(void)
{
    struct task_struct *task;
    bool passed = false;
    bool may_stall = false;

    task = kthread_run(&kthread_may_stall, &may_stall, "may_stall");
    ASSERT_TRY(!IS_ERR(task));
    msleep(1);
    ASSERT_TRY(true == may_stall);
    passed = true;

CATCH_DEFAULT:
    return passed;
}

bool __init test__insmod_may_stall(void)
{
    bool passed = false;

    passed = ec_current_task_may_stall();
    ASSERT_TRY(true == passed);

CATCH_DEFAULT:
    return passed;
}

struct abort_args {
    uint64_t perm_id;
    pid_t tid;
    CB_EVENT_TYPE eventType;
    unsigned int sleep_ms;
    int result;
    int exp_result;
};

static struct abort_args abort_args;

// Try to simulate when a CB_EVENT pipeline failure.
// Update this to use a CB_EVENT when there exists an event with these attrs.
static int defer_stall_abort(void *data)
{
    struct abort_args *args = (struct abort_args *)data;
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    if (!data)
    {
        return -1;
    }

    msleep(args->sleep_ms);

    args->result = ec_stall_event_abort(args->perm_id, args->tid, args->eventType,
                                        &context);
    return 0;
}

bool __init test__stall_event_abort(ProcessContext *context)
{
    struct task_struct *task;
    bool passed = false;
    unsigned long long start;
    unsigned long long diff;
    unsigned int ms_wait = 1000;
    int exp_response = 0;
    int response;

    ec_enable_stall_events();
    memset(&abort_args, 0xAC, sizeof(abort_args));


    // This data will really eventully be derived from a CB_EVENT
    task = kthread_create(&defer_stall_abort, &abort_args,
                          "defer_abort-%d", (int)abort_args.perm_id);
    ASSERT_TRY(!IS_ERR(task));

    abort_args.tid = task->pid;
    abort_args.eventType = CB_EVENT_TYPE_MODULE_LOAD;
    abort_args.perm_id = ec_next_perm_id();
    abort_args.sleep_ms = 200;
    abort_args.exp_result = 0; // -ENOENT , -EINVAL I think are the error cases?
    abort_args.result = 0xBEEF;

    start = now_milli();
    wake_up_process(task);

    response = ec_wait_stall_event_timeout(abort_args.perm_id, abort_args.tid, abort_args.eventType,
                                           ms_wait, context);
    diff = now_milli() - start;
    TRACE(DL_INFO, "diff:%llu  max wait time:%u ms", diff, ms_wait);

    ASSERT_TRY(exp_response == response); // 0 is access control returned when we abort mid-flight
    ASSERT_TRY(abort_args.exp_result == abort_args.result); // ec_stall_event_abort should have been successful
    ASSERT_TRY((unsigned int)diff < ms_wait);

    passed = true;

CATCH_DEFAULT:
    ec_disable_stall_events(context);
    return passed;
}
