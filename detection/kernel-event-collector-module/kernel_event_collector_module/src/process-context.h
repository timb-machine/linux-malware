/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

// checkpatch-ignore: COMPLEX_MACRO

#include <linux/types.h>
#include <linux/time.h>
#include <linux/gfp.h>
#include "dbg.h"
#include <linux/llist.h>

extern struct timespec ec_get_current_timespec(void);

#define MAX_GFP_STACK    10

// Counters that track usage of hook functions are implemented as per-cpu variables. This reduces contention between
// CPUs. Each CPU has its own set of counters and when we enter a hook we pick up the counters for the CPU we are
// currently running on. We then use that set of counters until we leave the hook. This prevents the counters from
// being a bottleneck, in the case where multiple CPUs need to access the same counter simultaneously.

// Counter for hooks in use by the module
DECLARE_PER_CPU(atomic64_t, module_inuse);

// Counter for hooks in use by the enabled module
DECLARE_PER_CPU(atomic64_t, module_active_inuse);

// Get the per-cpu pointer. Disabling preemption while getting the percpu pointer ensures we stay on the same CPU
// while getting the pointer. Seems safer but might not be necessary since all we really need is the CPU ID.
static inline void *_safe_percpu_ptr(void *pointer)
{
    void *percpu;

    preempt_disable();
    percpu = this_cpu_ptr(pointer);
    preempt_enable();

    return percpu;
}

typedef struct hook_tracking {
    const char      *hook_name;
    atomic64_t       count;
    atomic64_t       last_enter_time;
    atomic64_t       last_pid;
    struct list_head list;
} HookTracking;

typedef struct process_context {
    gfp_t            gfp_mode[MAX_GFP_STACK];
    int              stack_index;
    pid_t            pid;
    bool             allow_wake_up;
    bool             allow_send_events;
    struct list_head list;
    bool             decr_active_call_count_on_exit;
    atomic64_t       *percpu_module_inuse;
    atomic64_t       *percpu_module_active_inuse;
    HookTracking     *percpu_hook_tracking;
} ProcessContext;

#define __CONTEXT_INITIALIZER(NAME, MODE, PID) {                               \
    .gfp_mode              = { (MODE), },                                      \
    .stack_index           = 0,                                                \
    .pid                   = (PID),                                            \
    .allow_wake_up         = true,                                             \
    .allow_send_events     = true,                                             \
    .decr_active_call_count_on_exit = false,                                   \
    .percpu_module_inuse = _safe_percpu_ptr(&module_inuse),                    \
    .percpu_module_active_inuse = _safe_percpu_ptr(&module_active_inuse),      \
    .percpu_hook_tracking = _safe_percpu_ptr(&hook_tracking)                   \
}

#define CB_ATOMIC        (GFP_ATOMIC | GFP_NOWAIT)

#define DECLARE_CONTEXT(name, mode, pid)                               \
    static DEFINE_PER_CPU(HookTracking, hook_tracking);                \
    ProcessContext name = __CONTEXT_INITIALIZER(name, mode, pid)

#define DECLARE_ATOMIC_CONTEXT(name, pid) DECLARE_CONTEXT(name, CB_ATOMIC, pid)

#define DECLARE_NON_ATOMIC_CONTEXT(name, pid) DECLARE_CONTEXT(name, GFP_KERNEL, pid)

#define DISABLE_WAKE_UP(context)                                               \
    (context)->allow_wake_up = false

#define ENABLE_WAKE_UP(context)                                                \
    (context)->allow_wake_up = true

#define DISABLE_SEND_EVENTS(context)                                               \
    (context)->allow_send_events = false

#define ENABLE_SEND_EVENTS(context)                                                \
    (context)->allow_send_events = true

#define GFP_MODE(context)            (context)->gfp_mode[(context)->stack_index]
#define IS_ATOMIC(context)           (GFP_MODE(context) & GFP_ATOMIC)
#define IS_NON_ATOMIC(context)       (GFP_MODE(context) & GFP_KERNEL)
#define ALLOW_WAKE_UP(context)       (context)->allow_wake_up
#define ALLOW_SEND_EVENTS(context)   (context)->allow_send_events

// checkpatch-ignore: SUSPECT_CODE_INDENT
#define PUSH_GFP_MODE(context, MODE) \
    do {\
        if ((context)->stack_index < MAX_GFP_STACK) {\
            (context)->stack_index++;\
            (context)->gfp_mode[(context)->stack_index] = (MODE);\
        } else {\
            TRACE(DL_ERROR, "%s: GFP_MODE overflow", __func__);\
        } \
    } while (0)

#define POP_GFP_MODE(context) \
    do {\
        if ((context)->stack_index > 0) {\
            (context)->stack_index--;\
        } else {\
            TRACE(DL_ERROR, "%s: GFP_MODE underflow", __func__);\
        } \
    } while (0)
// checkpatch-ignore: SUSPECT_CODE_INDENT

