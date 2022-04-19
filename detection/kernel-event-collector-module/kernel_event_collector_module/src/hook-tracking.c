// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "hook-tracking.h"
#include "cb-spinlock.h"
#include "process-context.h"
#include "priv.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{
#define CURRENT_TIME_SEC ((struct timespec) { get_seconds(), 0 })
#endif  //}

static struct ec_hook_tracking_node
{
    uint64_t          lock;
    struct list_head  hook_list;
} s_hook_tracking;

bool ec_hook_tracking_initialize(ProcessContext *context)
{
    INIT_LIST_HEAD(&(s_hook_tracking.hook_list));
    ec_spinlock_init(&s_hook_tracking.lock, context);
    return true;
}

void ec_hook_tracking_shutdown(ProcessContext *context)
{
    ec_spinlock_destroy(&s_hook_tracking.lock, context);
}

void ec_hook_tracking_add_entry(ProcessContext *context, const char *hook_name)
{
    CANCEL_VOID(context);
    CANCEL_VOID(context->percpu_hook_tracking);

    if (!context->percpu_hook_tracking->hook_name)
    {
        ec_write_lock(&s_hook_tracking.lock, context);
        // Now that we're inside the lock check this hook still has not been initialized
        if (!context->percpu_hook_tracking->hook_name)
        {
            TRACE(DL_VERBOSE, "%s %d %p", hook_name, smp_processor_id(), context->percpu_hook_tracking);

            context->percpu_hook_tracking->hook_name = hook_name;
            INIT_LIST_HEAD(&context->percpu_hook_tracking->list);
            list_add(&context->percpu_hook_tracking->list, &s_hook_tracking.hook_list);
        }
        ec_write_unlock(&s_hook_tracking.lock, context);
    }

    atomic64_inc(&context->percpu_hook_tracking->count);
    atomic64_set(&context->percpu_hook_tracking->last_enter_time, CURRENT_TIME_SEC.tv_sec);
    atomic64_set(&context->percpu_hook_tracking->last_pid, context->pid);
}

void ec_hook_tracking_del_entry(ProcessContext *context)
{
    CANCEL_VOID(context);
    CANCEL_VOID(context->percpu_hook_tracking);

    ATOMIC64_DEC__CHECK_NEG(&context->percpu_hook_tracking->count);
    atomic64_set(&context->percpu_hook_tracking->last_enter_time, 0);
    atomic64_set(&context->percpu_hook_tracking->last_pid, 0);
}

// This will be called in the module disable logic when we need to wait for hooks
//  to exit befor the module is disabled
int ec_hook_tracking_print_active(ProcessContext *context)
{
    HookTracking *list_entry;

    ec_read_lock(&s_hook_tracking.lock, context);
    list_for_each_entry(list_entry, &s_hook_tracking.hook_list, list)
    {
        if (atomic64_read(&list_entry->count) > 0)
        {
            pr_info("Hook %s has %u active users, last pid %d, last entry %lus ago\n",
                    list_entry->hook_name,
                    (unsigned int)atomic64_read(&list_entry->count),
                    (pid_t)atomic64_read(&list_entry->last_pid),
                    (unsigned long)(CURRENT_TIME_SEC.tv_sec - atomic64_read(&list_entry->last_enter_time))
            );
        }
    }
    ec_read_unlock(&s_hook_tracking.lock, context);

    return 0;
}

// This is called when reading the proc file
int ec_show_active_hooks(struct seq_file *seq_file, void *v)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    HookTracking *list_entry;
    unsigned long total_active = 0;

    seq_printf(seq_file, "%25s | %6s | %6s | %6s\n",
                "HOOK", "USERS", "LAST PID", "TIME");

    ec_read_lock(&s_hook_tracking.lock, &context);
    list_for_each_entry(list_entry, &s_hook_tracking.hook_list, list)
    {
        total_active += atomic64_read(&list_entry->count);

        seq_printf(seq_file, "%25s | %6u | %6u | %6lu |\n",
                      list_entry->hook_name,
                      (unsigned int)atomic64_read(&list_entry->count),
                      (pid_t)atomic64_read(&list_entry->last_pid),
                      (unsigned long)(CURRENT_TIME_SEC.tv_sec - atomic64_read(&list_entry->last_enter_time))
                      );
    }
    seq_printf(seq_file, "Total Active %lu\n", total_active);
    ec_read_unlock(&s_hook_tracking.lock, &context);

    return 0;
}
