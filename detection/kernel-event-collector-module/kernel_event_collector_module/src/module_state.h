/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2021 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "process-context.h"
#include "hook-tracking.h"

typedef enum {
    ModuleStateEnabled = 1,
    ModuleStateDisabling = 2,
    ModuleStateDisabled = 3,
    ModuleStateEnabling = 4
} ModuleState;

typedef struct _ModuleStateInfo {
    uint64_t     module_state_lock;
    ModuleState  module_state;
} ModuleStateInfo;

//------------------------------------------------
// Macros that track entry and exit for each of the hook routines.
// - Implement the checks for module-state and bypass the routines if the module is disabled.
// - Keep track of a counter use_count, to allow for safe rmmod.

extern ModuleStateInfo g_module_state_info;

//-------------------------------------------------
// Module usage protection
//  NOTE: Be very careful when adding new exit points to the hooks that the PUT is properly called.
// 'module_used' tracks usage of our hook functions and blocks module unload but not disable.
// 'g_module_state_info.module_active_call_count' tracks usage of code that requires
// the module to be in an enabled state and blocks disable but not unload.
#define MODULE_GET(context)  atomic64_inc((context)->percpu_module_inuse)

#define MODULE_PUT(context)  ATOMIC64_DEC__CHECK_NEG((context)->percpu_module_inuse)

// Everything between this macro and FINISH_MODULE_DISABLE_CHECK is tracked
// and can potentially block the module from disabling. We should avoid calling
// the original syscall between these two macros.
// checkpatch-ignore: SUSPECT_CODE_INDENT,MACRO_WITH_FLOW_CONTROL
#define BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(CONTEXT, pass_through_label)    \
do {                                                                                \
    ec_read_lock(&g_module_state_info.module_state_lock, (CONTEXT));                \
                                                                                    \
    if (g_module_state_info.module_state != ModuleStateEnabled)                     \
    {                                                                               \
        ec_read_unlock(&g_module_state_info.module_state_lock, (CONTEXT));          \
        (CONTEXT)->decr_active_call_count_on_exit = false;                          \
        goto pass_through_label;                                                    \
    }                                                                               \
    else                                                                            \
    {                                                                               \
        (CONTEXT)->decr_active_call_count_on_exit = true;                           \
        atomic64_inc((CONTEXT)->percpu_module_active_inuse);                        \
    }                                                                               \
                                                                                    \
    ec_read_unlock(&g_module_state_info.module_state_lock, (CONTEXT));              \
    ec_hook_tracking_add_entry((CONTEXT), __func__);                                \
} while (false)

#define IF_MODULE_DISABLED_GOTO(CONTEXT, pass_through_label)                        \
do {                                                                                \
    ec_read_lock(&g_module_state_info.module_state_lock, (CONTEXT));                \
                                                                                    \
    if (g_module_state_info.module_state != ModuleStateEnabled)                     \
    {                                                                               \
        ec_read_unlock(&g_module_state_info.module_state_lock, (CONTEXT));          \
        goto pass_through_label;                                                    \
    }                                                                               \
                                                                                    \
    ec_read_unlock(&g_module_state_info.module_state_lock, (CONTEXT));              \
} while (false)

#define MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(CONTEXT, pass_through_label)  \
do {                                                                                             \
   MODULE_GET(CONTEXT);                                                                          \
   BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO((CONTEXT), pass_through_label);                   \
}                                                                                                \
while (false)

#define MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(CONTEXT, pass_through_label)         \
do {                                                                                \
   MODULE_GET(CONTEXT);                                                             \
   IF_MODULE_DISABLED_GOTO((CONTEXT), pass_through_label);                          \
}                                                                                   \
while (false)

#define FINISH_MODULE_DISABLE_CHECK(CONTEXT)                                   \
do {                                                                           \
   if ((CONTEXT)->decr_active_call_count_on_exit)                              \
   {                                                                           \
       ec_hook_tracking_del_entry((CONTEXT));                                  \
       ATOMIC64_DEC__CHECK_NEG((CONTEXT)->percpu_module_active_inuse);         \
   }                                                                           \
}                                                                              \
while (false)

#define MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(CONTEXT)               \
do {                                                                      \
  FINISH_MODULE_DISABLE_CHECK(CONTEXT);                                   \
  MODULE_PUT(CONTEXT);                                                    \
}                                                                         \
while (false)

// checkpatch-no-ignore: SUSPECT_CODE_INDENT,MACRO_WITH_FLOW_CONTROL
