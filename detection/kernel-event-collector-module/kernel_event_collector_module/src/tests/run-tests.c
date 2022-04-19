// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "run-tests.h"

#define RUN_TEST(test_stmt) do {\
    TRACE(DL_INFO, "%s START", #test_stmt); \
    if (test_stmt) { \
        TRACE(DL_INFO, "%s PASSED", #test_stmt); \
    } else { \
        TRACE(DL_INFO, "%s FAILED", #test_stmt); \
        all_passed = false; \
    } \
} while (0);


bool __init run_tests(ProcessContext *context)
{
    bool all_passed = true;

    uint32_t origTraceLevel = g_traceLevel;
    g_traceLevel |= (uint32_t)DL_INFO;

    pr_alert("Running self-tests\n");

    RUN_TEST(test__hash_table(context));
    RUN_TEST(test__hashtbl_double_del(context));
    RUN_TEST(test__hashtbl_refcount_double_del(context));
    RUN_TEST(test__hashtbl_refcount(context));
    RUN_TEST(test__hashtbl_add_duplicate(context));

    RUN_TEST(test__proc_track_report_double_exit(context));

    RUN_TEST(test__begin_finish_macros(context));
    RUN_TEST(test__hook_tracking_add_del(context));

    RUN_TEST(test__stall_enable(context));
    RUN_TEST(test__perm_id(context));
    RUN_TEST(test__perm_id_disabled(context));
    RUN_TEST(test__stall_timedout(context));
    RUN_TEST(test__stall_event_EPERM(context));
    RUN_TEST(test__stall_one_during_disable(context));
    RUN_TEST(test__kthread_may_stall());
    RUN_TEST(test__insmod_may_stall());
    RUN_TEST(test__stall_event_abort(context));

    g_traceLevel = origTraceLevel;
    return all_passed;
}
