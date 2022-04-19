/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "cb-spinlock.h"
#include "run-tests.h"

// This verifies multiple BEGIN/FINISH disable check macros in the same
// hook function. See ec_sys_rename for an example.
bool __init test__begin_finish_macros(ProcessContext *context)
{
    bool passed = false;
    unsigned int cpu;

    // Initially we're enabled...
    g_module_state_info.module_state = ModuleStateEnabled;

    // so we enter the enabled-only section
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DISABLED);

    // Module enabled section //

    FINISH_MODULE_DISABLE_CHECK(context);

    // The module disables while we're outside the enabled-only section
    g_module_state_info.module_state = ModuleStateDisabling;

    // Now we try to enter an enabled-only section
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DISABLED);

    // Module enabled section //

    // We should never get here because the module is disabled
    ASSERT_TRY(false);

CATCH_DISABLED:
    // This will warn if the active call count is wrong
    FINISH_MODULE_DISABLE_CHECK(context);

    for_each_possible_cpu(cpu)
    {
        ASSERT_TRY(atomic64_read(&per_cpu(module_active_inuse, cpu)) == 0);
    }
    passed = true;

CATCH_DEFAULT:
    // Make sure the state is set back to disabled
    g_module_state_info.module_state = ModuleStateDisabled;

    return passed;
}

bool __init test__hook_tracking_add_del(ProcessContext *context)
{
    bool passed = false;
    pid_t current_pid = ec_getpid(current);
    // ignore the passed in context for this test
    DECLARE_NON_ATOMIC_CONTEXT(test_context, current_pid);

    ASSERT_TRY(atomic64_read(&test_context.percpu_hook_tracking->count) == 0);

    ec_hook_tracking_add_entry(&test_context, __func__);

    ASSERT_TRY(atomic64_read(&test_context.percpu_hook_tracking->count) == 1);
    ASSERT_TRY(atomic64_read(&test_context.percpu_hook_tracking->last_pid) == current_pid);

    // This is here to exercise this code since there's no easy way to force it to run.
    ec_hook_tracking_print_active(&test_context);

    ec_hook_tracking_del_entry(&test_context);

    ASSERT_TRY(atomic64_read(&test_context.percpu_hook_tracking->count) == 0);

    passed = true;

CATCH_DEFAULT:
    return passed;
}
