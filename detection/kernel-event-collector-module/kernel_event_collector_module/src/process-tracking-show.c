// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "cb-test.h"
#include "task-helper.h"

void __ec_show_process_tracking_table(void *data, void *priv, ProcessContext *context);

int ec_proc_track_show_table(struct seq_file *m, void *v)
{

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    seq_printf(m, "%20s | %6s | %12s | %6s | %6s | %6s | %10s | %10s | %5s |\n",
                "Name", "RPID", "RPPID", "PID", "PPID", "TID", "Inode", "Exec Count", "Alive");

    ec_sorted_tracking_table_for_each(__ec_show_process_tracking_table, m, &context);

    return 0;
}

const char *ec_process_tracking_get_proc_name(const char *path)
{
    const char *proc_name = "<unknown>";

    if (path)
    {
        proc_name = strrchr(path, '/');
        if (proc_name)
        {
            proc_name++;
        } else
        {
            proc_name = path;
        }
    }
    return proc_name;
}

void __ec_show_process_tracking_table(void *data, void *priv, ProcessContext *context)
{
    struct seq_file     *seq_file     = (struct seq_file *)priv;
    ProcessHandle       *process_handle = ec_sorted_tracking_table_get_handle(data, context);
    const char          *proc_name    = NULL;
    struct task_struct  const *task   = NULL;
    uint64_t             shared_count = 0;

    TRY(process_handle && seq_file);

    task = ec_find_task(ec_process_posix_identity(process_handle)->posix_details.pid);

    proc_name = ec_process_tracking_get_proc_name(ec_process_path(process_handle));

    shared_count = atomic64_read(&ec_process_exec_identity(process_handle)->reference_count);

    seq_printf(seq_file, "%20s | %6llu | %12llu | %6llu | %6llu | %6llu | %10llu | %10llu | %5s |\n",
                  proc_name,
                  (uint64_t)ec_process_exec_identity(process_handle)->exec_details.pid,
                  (uint64_t)ec_process_exec_identity(process_handle)->exec_parent_details.pid,
                  (uint64_t)ec_process_posix_identity(process_handle)->posix_details.pid,
                  (uint64_t)ec_process_posix_identity(process_handle)->posix_parent_details.pid,
                  (uint64_t)ec_process_posix_identity(process_handle)->tid,
                  ec_process_posix_identity(process_handle)->posix_details.inode,
                  shared_count,
                  (ec_is_task_alive(task) ? "yes" : "no"));

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, context);
    return;
}

int ec_proc_track_show_stats(struct seq_file *m, void *v)
{
    seq_printf(m, "%22s | %6llu |\n", "Total Changes",   g_process_tracking_data.op_cnt);
    seq_printf(m, "%22s | %6llu |\n", "Process Creates", g_process_tracking_data.create);
    seq_printf(m, "%22s | %6llu |\n", "Process Forks",   g_process_tracking_data.create_by_fork);
    seq_printf(m, "%22s | %6llu |\n", "Process Execs",   g_process_tracking_data.create_by_exec);
    seq_printf(m, "%22s | %6llu |\n", "Process Exits",   g_process_tracking_data.exit);

    return 0;
}
