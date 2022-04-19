// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/binfmts.h>
#include <linux/cred.h>
#endif
#include <linux/proc_fs.h>
#include <linux/mm.h>
#include <trace/events/sched.h>

#include "process-tracking.h"
#include "cb-banning.h"
#include "event-factory.h"
#include "path-buffers.h"
#include "cb-spinlock.h"
#include "task-helper.h"

void ec_exit_hook(struct task_struct *task, ProcessContext *context);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void ec_sched_process_fork_probe(void *data, struct task_struct *parent, struct task_struct *child);
void ec_sched_process_exit_probe(void *data, struct task_struct *task);
#else
void ec_sched_process_fork_probe(struct task_struct *parent, struct task_struct *child);
void ec_sched_process_exit_probe(struct task_struct *task);
#endif


bool ec_task_initialize(ProcessContext *context)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    register_trace_sched_process_fork(ec_sched_process_fork_probe, NULL);
    register_trace_sched_process_exit(ec_sched_process_exit_probe, NULL);
#else
    register_trace_sched_process_fork(ec_sched_process_fork_probe);
    register_trace_sched_process_exit(ec_sched_process_exit_probe);
#endif

    return true;
}

void ec_task_shutdown(ProcessContext *context)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    unregister_trace_sched_process_fork(ec_sched_process_fork_probe, NULL);
    unregister_trace_sched_process_exit(ec_sched_process_exit_probe, NULL);
#else
    unregister_trace_sched_process_fork(ec_sched_process_fork_probe);
    unregister_trace_sched_process_exit(ec_sched_process_exit_probe);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void ec_sched_process_exit_probe(void *data, struct task_struct *task)
#else
void ec_sched_process_exit_probe(struct task_struct *task)
#endif
{
    // This is in the kernel exit code, I don't know if it is safe to be NON_ATOMIC
    DECLARE_ATOMIC_CONTEXT(context, task ? ec_getpid(task) : 0);

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);
    TRY(task);

    ec_exit_hook(task, &context);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
}

void ec_exit_hook(struct task_struct *task, ProcessContext *context)
{
    pid_t pid = ec_getpid(task);

    // If the `pid` and `tid` are the same than this is a fork.  If they are different this is a
    //  thread.  We need to ignore threads.
    // In theory we should see `CLONE_THREAD` in flags, but I have often found this to be garbage data.
    CANCEL_VOID(ec_gettid(task) == pid);

    // ec_disconnect_reader will do nothing if the pid isn't the reader process.
    // Otherwise, it will disconnect the reader which we need if it exits without
    // releasing the devnode.
    if (ec_disconnect_reader(pid))
    {
        TRACE(DL_INFO, "reader process has exited, and has been disconnected; pid=%d", pid);
    }

    CANCEL_VOID(!ec_banning_IgnoreProcess(context, pid));

    CANCEL_VOID_MSG(ec_process_tracking_report_exit(pid, context),
        DL_PROC_TRACKING, "remove process failed to find pid=%d\n", pid);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void ec_sched_process_fork_probe(void *data, struct task_struct *parent, struct task_struct *child)
#else
void ec_sched_process_fork_probe(struct task_struct *parent, struct task_struct *child)
#endif
{
    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // ignore kernel tasks (swapper, migrate, etc)
    // this is critial because path lookups for these functions will schedule
    // and deadlock the system
    TRY(child->mm != NULL);

    // only hook for tasks which are new and have not yet run
    TRY(child->se.sum_exec_runtime == 0);

    // Do not allow any calls to schedule tasks
    DISABLE_WAKE_UP(&context);

    ec_sys_clone(&context, child);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
}

void ec_sys_clone(ProcessContext *context, struct task_struct *task)
{
    // this function is called after the task is created but before it has been
    // allowed to run.
    // also the disable logic is owned by the wapper in cfs.c

    pid_t tid = ec_gettid(task);
    pid_t pid = ec_getpid(task);
    pid_t ppid = ec_getppid(task);
    uid_t uid = TASK_UID(task);
    uid_t euid = TASK_EUID(task);
    struct timespec start_time = {0};
    ProcessHandle *process_handle = NULL;

    getnstimeofday(&start_time);

    // If the `pid` and `tid` are the same than this is a fork.  If they are different this is a
    //  thread.  We need to ignore threads.
    // In theory we should see `CLONE_THREAD` in flags, but I have often found this to be garbage data.
    if (ec_gettid(task) != ec_getpid(task))
    {
        return;
    }

    // It is not safe to allow scheduling in this hook
    if (ec_is_process_tracked(pid, context))
    {
        TRACE(DL_PROC_TRACKING, "fork hook called on already tracked pid=%d", pid);
        return;
    }

    if (!ec_is_process_tracked(ppid, context))
    {
        // in some rare cases during startup we can still get into a position where
        // the parent is not in the tracking table. if this is the case we insert it and
        // send a fake process-start

        TRACE(DL_PROC_TRACKING, "fork ppid=%d not tracked", ppid);
        ec_create_process_start_by_exec_event(task->real_parent, context);
    }

    process_handle = ec_process_tracking_create_process(
        pid,
        ppid,
        tid,
        uid,
        euid,
        ec_to_windows_timestamp(&start_time),
        CB_PROCESS_START_BY_FORK,
        task,
        REAL_START,
        context);

    // Send the event
    ec_event_send_start(process_handle,
                    ec_process_tracking_should_track_user() ? uid : (uid_t)-1,
                    CB_PROCESS_START_BY_FORK,
                    context);

    ec_process_tracking_put_handle(process_handle, context);
}

// This hook happens before the exec.  It will process_handle both the banning case and the start case
//  Note: We used to process_handle the start in a post hook.  We are using the pre hook for two reasons.
//        1. We had problems with page faults in the post hook
//        2. We need the process tracking entry to be updated for the baned event anyway
int ec_lsm_bprm_check_security(struct linux_binprm *bprm)
{
    struct task_struct *task = current;
    pid_t pid = ec_getpid(task);
    pid_t tid = ec_gettid(task);
    uid_t uid = GET_UID();
    uid_t euid = GET_EUID();
    struct timespec start_time = {0, 0};
    ProcessHandle *process_handle = NULL;
    uint64_t device = 0;
    uint64_t inode = 0;
    char *path_buffer = NULL;
    char *path = NULL;
    bool path_found = false;
    int stat = 0;
    bool killit = false;
    int ret = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, pid);

    MODULE_GET(&context);

    // get time as early in the function as possible
    getnstimeofday(&start_time);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    // Call any other hooks in the chain, and bail if they want to bail
    ret = g_original_ops_ptr->bprm_check_security(bprm);
    TRY(ret == 0);
#endif  //}

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(!ec_banning_IgnoreProcess(&context, pid));

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    // Check the current creds, this may tell us we are supposed to bail
    stat = g_original_ops_ptr->bprm_set_creds(bprm);
#endif  //}

    ec_get_devinfo_from_file(bprm->file, &device, &inode);

    if (tid != INITTASK)
    {
        killit = ec_banning_KillBannedProcessByInode(&context, device, inode);
    }

    // get a temporary path buffer before going into an unschedulable state
    // It is safe to schedule in this hook
    path_buffer = ec_get_path_buffer(&context);
    if (path_buffer)
    {
        // ec_file_get_path() uses dpath which builds the path efficently
        //  by walking back to the root. It starts with a string terminator
        //  in the last byte of the target buffer.
        //
        // The `path` variable will point to the start of the string, so we will
        //  use that directly later to copy into the tracking entry and event.
        path_found = ec_file_get_path(bprm->file, path_buffer, PATH_MAX, &path);
        path_buffer[PATH_MAX] = 0;

        if (!path_found)
        {
            TRACE(DL_INFO, "Failed to retrieve path for pid: %d", pid);
        }
    }

    // this function can be called recursively by the kernel, for an interpreter
    // and a script/binary it is interpreting.
    if (bprm->recursion_depth == 0)
    {
        // Update the existing process on exec
        process_handle = ec_process_tracking_update_process(
                    pid,
                    tid,
                    uid,
                    euid,
                    device,
                    inode,
                    path,
                    path_found,
                    ec_to_windows_timestamp(&start_time),
                    CB_PROCESS_START_BY_EXEC,
                    task,
                    CB_EVENT_TYPE_PROCESS_START_EXEC,
                    REAL_START,
                    &context);
    } else
    {
        // This hook is called for the script first, with bprm->recursion_depth 0. If exec was called on a #! script
        // during the first call the path was the script, then on the next call, the interpreter is set as the path.
        // The interpreter can itself be a script so this hook can be called be called multiple times with
        // bprm->recursion_depth incremented on each call.

        if (path_found)
        {
            process_handle = ec_process_tracking_get_handle(pid, &context);

            if (process_handle)
            {
                // The previously set path is actually the script_path.
                // The script will report as an open event when the interpreter opens it.
                // The path from this call is the path of the interpreter.
                char *_path = ec_mem_cache_strdup(path, &context);

                ec_process_exec_identity(process_handle)->is_interpreter = true;
                ec_process_tracking_set_path(process_handle, _path, &context);
                ec_mem_cache_put_generic(_path);

                // also need to update the file information
                ec_process_exec_identity(process_handle)->exec_details.inode = inode;
                ec_process_exec_identity(process_handle)->exec_details.device = device;

                ec_process_posix_identity(process_handle)->posix_details.inode = inode;
                ec_process_posix_identity(process_handle)->posix_details.device = device;
            }
        }
    }

    // Check to see if this should be banned or not.
    //   If it is banned, send the banned event and return an error
    //   If it is not banned, send a start event
    if (stat || killit)
    {
        if (killit)
        {
            ec_process_tracking_mark_as_blocked(process_handle);
            ec_event_send_block(process_handle,
                             BlockDuringProcessStartup,
                             TerminateFailureReasonNone,
                             0, // details
                             ec_process_tracking_should_track_user() ? uid : (uid_t)-1,
                             path_buffer,
                             &context);
        }
        ret = -EPERM;
    }

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, &context);
    ec_put_path_buffer(path_buffer);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

//
// Process start hook.  Callout called late in the exec process
//
void ec_lsm_bprm_committed_creds(struct linux_binprm *bprm)
{
    pid_t            pid     = ec_getpid(current);
    uid_t            uid     = GET_UID();
    ProcessHandle *process_handle   = NULL;
    char *cmdline = NULL;

    DECLARE_ATOMIC_CONTEXT(context, pid);

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // If this process is not tracked, do not send an event
    // We have had issues scheduling from this hook.  (Though it should really be OK)
    process_handle = ec_process_tracking_get_handle(pid, &context);
    if (process_handle && !ec_process_tracking_is_blocked(process_handle))
    {
        cmdline = ec_get_path_buffer(&context);
        if (cmdline)
        {
            ec_get_cmdline_from_binprm(bprm, cmdline, PATH_MAX);
        }

        ec_process_tracking_set_proc_cmdline(process_handle, cmdline, &context);

        ec_event_send_start(process_handle,
                         ec_process_tracking_should_track_user() ? uid : (uid_t)-1,
                         CB_PROCESS_START_BY_EXEC,
                         &context);
    }

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, &context);
    ec_put_path_buffer(cmdline);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    g_original_ops_ptr->bprm_committed_creds(bprm);
#endif  //}
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
}
