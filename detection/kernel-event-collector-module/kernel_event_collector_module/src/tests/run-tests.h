/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#pragma once

#include <linux/init.h>

#include "process-context.h"
#include "priv.h"

//
// run_tests provides a way to write consumption tests that exercise and verify
// components of the kernel module. These tests may crash the kernel and should
// not be run in production environments.
//
// To run self-tests include the g_run_self_tests arg when loading the module:
//   insmod event_collector_2_0_999999.ko.3.10.0-957 g_run_self_tests
//
// Test functions and global data must use the __init decorator. This allows
// the kernel to unload these functions and data after initialization.
//

bool run_tests(ProcessContext *context) __init;

bool test__hash_table(ProcessContext *context) __init;
bool test__hashtbl_double_del(ProcessContext *context) __init;
bool test__hashtbl_refcount_double_del(ProcessContext *context) __init;
bool test__hashtbl_refcount(ProcessContext *context) __init;
bool test__hashtbl_add_duplicate(ProcessContext *context) __init;

bool test__proc_track_report_double_exit(ProcessContext *context) __init;

bool test__begin_finish_macros(ProcessContext *context) __init;
bool test__hook_tracking_add_del(ProcessContext *context) __init;

bool test__stall_enable(ProcessContext *context) __init;

bool test__perm_id(ProcessContext *context) __init;
bool test__perm_id_disabled(ProcessContext *context) __init;
bool test__stall_timedout(ProcessContext *context) __init;
bool test__stall_event_EPERM(ProcessContext *context) __init;
bool test__stall_one_during_disable(ProcessContext *context) __init;
bool test__kthread_may_stall(void) __init;
bool test__insmod_may_stall(void) __init;
bool test__stall_event_abort(ProcessContext *context) __init;

#define ASSERT_TRY(stmt) TRY_MSG(stmt, DL_ERROR, "ASSERT FAILED %s:%d -- %s", __FILE__, __LINE__, #stmt)
