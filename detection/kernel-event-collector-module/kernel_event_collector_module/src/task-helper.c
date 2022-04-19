// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "task-helper.h"
#include "priv.h"
#include "process-tracking.h"
#include "path-buffers.h"

#include <linux/binfmts.h>

struct file *__ec_get_file_from_mm(struct mm_struct *mm);

pid_t ec_gettid(struct task_struct const *task)
{
    return task->pid; // this is the thread id
}

pid_t ec_getpid(struct task_struct const *task)
{
    return task->tgid; // task_tgid_vnr(task);
}

pid_t ec_getcurrentpid(void)
{
    return ec_getpid(current);
}

pid_t ec_getppid(struct task_struct const *task)
{
    if (task->real_parent) // @@review: use parent?
    {
        return ec_getpid(task->real_parent);
    }
    pr_err("no  parent for task %d", ec_getpid(task));
    return -1;
}

bool ec_is_task_valid(struct task_struct const *task)
{
    // This tells us if the task_struct data is safe to access
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    return (task && pid_alive(task));
#else  //}{ missing 'const' in include/linux/sched.h
    return (task && pid_alive((struct task_struct *)task));
#endif  //}
}

bool ec_is_task_alive(struct task_struct const *task)
{
    // This tells us if the process is actually alive
    return (ec_is_task_valid(task) &&
          !(task->state == TASK_DEAD || task->exit_state == EXIT_DEAD));
}

struct task_struct const *ec_find_task(pid_t pid)
{
    struct task_struct const *task  = NULL;

    rcu_read_lock();
    task = CB_RESOLVED(find_task_by_vpid)(pid);
    rcu_read_unlock();

    return task;
}

void ec_get_starttime(struct timespec *start_time)
{
    // to interpret see http://www.fieldses.org/~bfields/kernel/time.txt
    //struct timespec boottime
    //struct timespec tmptime;
    struct timespec current_time;

    getnstimeofday(&current_time);

    //getboottime( &boottime );

    //tmptime.tv_sec = current_time.tv_sec;
    // CEL tmptime.tv_sec = boottime.tv_sec + task->real_start_time.tv_sec;
    // CEL tmptime.tv_nsec= boottime.tv_nsec + task->real_start_time.tv_nsec;
    // Round down to the nearest second (fake process creations can only get second resolution)
    //tmptime.tv_nsec= 0;

    set_normalized_timespec(start_time, current_time.tv_sec, current_time.tv_nsec);
}

bool ec_task_get_path(struct task_struct const *task, char *buffer, unsigned int buflen, char **pathname)
{
    bool ret = true;

    CANCEL(task, false);
    CANCEL(buffer, false);
    CANCEL(pathname, false);

    ret = ec_file_get_path(__ec_get_file_from_mm(task->mm), buffer, buflen, pathname);

    if (!ret)
    {
        buffer[0] = 0;
        strncat(buffer, task->comm, buflen-1);
        (*pathname) = buffer;
    }

    return ret;
}

void ec_get_devinfo_from_task(struct task_struct const *task, uint64_t *device, uint64_t *inode)
{
    CANCEL_VOID(task);
    ec_get_devinfo_from_file(__ec_get_file_from_mm(task->mm), device, inode);
}

struct inode const *ec_get_inode_from_task(struct task_struct const *task)
{
    struct inode const *pInode = NULL;

    if (task)
    {
        // TODO: We should be locking the task here, but I do not want to add it right now.
        //task_lock(task);
        pInode = ec_get_inode_from_file(__ec_get_file_from_mm(task->mm));
        //task_unlock(task);
    }

    return pInode;
}

bool __ec_get_cmdline(struct task_struct const *task,
                         unsigned long       start_addr,
                         unsigned long       end_addr,
                         int                 args,
                         char *cmdLine,
                         size_t              cmdLineSize);

bool __ec_get_cmdline_from_task(struct task_struct const *task, char *cmdLine, size_t cmdLineSize)
{
    CANCEL(task && task->mm, false);

    // This will be bound only by the size of the target buffer and memory range
    //  defined in the mm struct.
    // Note that `arg_end` is not valid during exec hooks
    return __ec_get_cmdline(task, task->mm->arg_start, task->mm->arg_end, 0xFFFF, cmdLine, cmdLineSize);
}

bool ec_get_cmdline_from_binprm(struct linux_binprm const *bprm, char *cmdLine, size_t cmdLineSize)
{
    CANCEL(bprm && current->mm, false);

    // This will be bound by the size of the target buffer, memory range in mm,
    //  and the arg count provided in the bprm.
    // Note that the memory range will include the arg list and the env.  Unfortunately
    //  the `arg_end` varaible is not set yet.  We are relying on the arc in this
    //  case to keep us from including anything from the env.
    return __ec_get_cmdline(current, bprm->p, bprm->exec, bprm->argc - 1, cmdLine, cmdLineSize);
    // the way we get the command line has always been a little bit hacky.
    // we have to go into the process virtual memory and extract it,
    // but at the time of doing so the mm struct dosent have all the values set
    // that we would like (arg_start and arg_end). previously, we were using the
    // 'exec' pointer which points to the start of the executable code, which we
    // knew was directly after the arguments and environment.
    // we would then subtract arg_start from that to tell us how much virtual
    // memory we would need to load. we would then work backwards from exec to
    // find the command line. in 7.8 they changed the order things were initialized
    // in, and we can no longer use mm->arg_start to tell us the beginning of the
    // arguments, because it is not ready yet when we are called. we can however,
    // use the bprm->p pointer. this gives us the current stack top of the new
    // processes memory. at the time we are being called, this points to directly
    // before the the argument list. so basically at the time we are called,
    // it has the same value as mm->arg_start even in the 3.10.0-1127 kernel.

}

bool __ec_get_cmdline(struct task_struct const *task,
                         unsigned long       start_addr,
                         unsigned long       end_addr,
                         int                 args,
                         char *cmdLine,
                         size_t              cmdLineSize)
{
    unsigned int      cmdLinePos  = 0;
    int               i;
    size_t            len         = 0;

    CANCEL(task, false);
    CANCEL_CB_RESOLVED(access_process_vm, false);

    // Verify the buffer exists
    if (cmdLine == NULL)
    {
        TRACE(DL_WARNING, "couldn't allocate cmdline buffer pid:%d", ec_getpid(task));
        return false;
    }
    cmdLine[0] = 0;

    // We can not trust the `arg_end` variable since it is not set correctly
    //  We instead make some assumptions based on the behavior of `do_execve_common`
    //  Specically we know that it writes the argv, env, and exec name consecutively
    //  in memory.  We trust that `mm->arg_start` is the beginning of the argv list, and
    //  that `mm->exec` is the beginning of the exec name. So we know it is safe to
    //  read in the data between those two addresses.  (This will also read in the env,
    //  which we do not need.)
    len = min(cmdLineSize, (size_t) (end_addr - start_addr));

    // Copy the argument string.
    //  NOTE: A simple memcopy does not work because this technically runs in a different
    //        process context than what is about to exec.  So we need to page in the memory.
    CB_RESOLVED(access_process_vm)(task, start_addr, &cmdLine[0], len, 0);

    // The args we just read from "mm" are delimited by '\0', so we walk through the
    //  buffer and replace them with ' '.
    for (i = 0; i < args; ++i)
    {
        // Find the end of the string and replace it with ' '.  We will start here on the next pass.
        cmdLinePos += strnlen(&cmdLine[cmdLinePos], MAX_ARG_STRLEN) + 1;
        if (cmdLinePos >= len)
        break;
        cmdLine[cmdLinePos-1] = ' ';
    }
    cmdLine[len] = 0;

    return true;
}

struct file *__ec_get_file_from_mm(struct mm_struct *mm)
{
    struct vm_area_struct *vma;
    struct file *filep = NULL;

    if (!mm)
    {
        goto dentry_mm_exit;
    }

    // Under some situations, the mmap_sem will be locked for write above us in
    // the stack. Eventually, we should fix that. Since this can be called from
    // inside an interrupt we should to avoid a call to sleep so we'll try once and
    // fail if the lock is held.
    if (down_read_trylock(&mm->mmap_sem) == 0)
    {
        TRACE(DL_INFO, "%s: unable to down semaphore\n", __func__);
        goto dentry_mm_exit;
    }

    vma = mm->mmap;

    while (vma)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        if ((vma->vm_flags & VM_EXEC) && vma->vm_file)
#else
        if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
#endif
        {
            // If the vma's space contains the code seciton of the actual process, we have the correct one
            if (vma->vm_start <= mm->start_code && vma->vm_end >= mm->end_code)
            {
                break;
            }
            // Otherwise, we're likely looking at a module with executable flags set
            else
            {
                TRACE(DL_VERBOSE, "==========EXECUTABLE MODULE LOADED=========");
                TRACE(DL_VERBOSE, "pid:%u (%s)", current->pid, current->comm);
                TRACE(DL_VERBOSE, "    vma count:    %d", mm->map_count);
                TRACE(DL_VERBOSE, "    code section: 0x%lx -> 0x%lx", mm->start_code, mm->end_code);
                TRACE(DL_VERBOSE, "    vma(exeflag): 0x%lx -> 0x%lx", vma->vm_start, vma->vm_end);
                TRACE(DL_VERBOSE, "    Invalid dentry reference as this executable section is not part of process code.");
                TRACE(DL_VERBOSE, "    Continuing to search vma list...");
                TRACE(DL_VERBOSE, "===========================================");
            }
        }
        vma = vma->vm_next;
    }

    if (vma && vma->vm_file)
    {
        filep = vma->vm_file;
    }

    up_read(&mm->mmap_sem);

dentry_mm_exit:
    return filep;
}

#define MAX_TASK_STACK    40
struct task_stack {
    struct task_struct *task;
    struct task_struct *child;
};

// These helper macros are derived from `list_for_each_entry_rcu`.  We use them to traverse the private stack.
// The children and sibling pointers are not RCU protected and they can change while in rcu_read_lock()
// but the task_structs should not be freed until after rcu_read_unlock(). See release_task() in exit.c
#define FIRST_TASK(stack)      list_entry_rcu(rcu_dereference((stack)->task)->children.next, struct task_struct, sibling)
#define NEXT_TASK(stack)       list_entry_rcu(rcu_dereference((stack)->child)->sibling.next, struct task_struct, sibling)

// FIRST_TASK and NEXT_TASK provide local dereferenced pointers so we don't need to dereference here
#define HAS_MORE_TASKS(stack)  (!list_empty((stack)->child->sibling.next) && (&(stack)->child->sibling != &(stack)->task->children))

bool __ec_add_tracking_for_child_and_update_stack(
    struct task_stack *top,
    struct task_stack *next,
    char              *path_buffer,
    time_t             start_time,
    ProcessContext *context);
void __ec_add_tracking_for_task(
    struct task_struct *task,
    time_t              start_time,
    char               *path_buffer,
    ProcessContext *context);

// Assuming no system will have > 10000 processes, break out of the loop if we exceed this.
#define MAX_ENUMERATE_LOOPS 10000

void ec_enumerate_and_track_all_tasks(ProcessContext *context)
{
    struct task_stack *stack = NULL;
    char *path_buffer = NULL;
    time_t             start_time = 0;
    int                index = 0;
    int num_loops = 0;

    // Allocate stack space for walking the process tree
    //  We allocate one more than we need, so that the logic never accesses invalid memory
    stack       = ec_mem_cache_alloc_generic((MAX_TASK_STACK + 1) * sizeof(struct task_stack), context);
    path_buffer = ec_get_path_buffer(context);
    start_time  = ec_get_current_time() - TO_WIN_SEC(2);

    // I would prefer to hold the tasklist_lock here, but it causes a softlok
    rcu_read_lock();

    // This will walk all the children from init without recursion
    //  We use a private stack for this loop, where each layer in the stack is a
    //  possible list of sibling tasks.  After recording a task, we push its children
    //  onto the stack.  (This causes the inner loop to start looping over the children.)
    // Once the children are exhausted, it will exit the inner loop.  The outer loop will
    //  pop a layer off the stack and resume enumerating the previous list of children.
    TRY(path_buffer && stack);

    stack[0].task  = &init_task;
    stack[0].child = FIRST_TASK(&stack[0]);

    do
    {
        // NEXT_TASK grabs the rcu lock on the actual task struct, while
        // HAS_MORE_TASKS locks the list entries. we need both locks
        // to make sure nothing gets freed from under us
        // TODO: the infinite looping problem should be fixed, it we don't see it any more remove MAX_ENUMERATE_LOOPS.
        while (num_loops < MAX_ENUMERATE_LOOPS && NEXT_TASK(&stack[index]) && HAS_MORE_TASKS(&stack[index]))
        {
            if (__ec_add_tracking_for_child_and_update_stack(&stack[index],
                                                        &stack[index + 1],
                                                        path_buffer,
                                                        start_time++,
                                                        context))
            {
                // If the process tree goes too deep, we print a warning and continue
                //  enumerating.
                index++;
                if (unlikely(index >= MAX_TASK_STACK))
                {
                    index--;
                    TRACE(DL_WARNING, "Max depth (%d) reached for process tree.", MAX_TASK_STACK);
                }
            }

            ++num_loops;
        }

        if (num_loops >= MAX_ENUMERATE_LOOPS)
        {
            struct task_struct *pos;

            TRACE(DL_ERROR, "Too many enumeration cycles: %d, %d", num_loops, index);
            TRACE(DL_ERROR, "child->sibling %p, task->children %p", &stack[index].child->sibling, &stack[index].task->children);
            TRACE(DL_ERROR, "first child->sibling.next %p", &stack[index].child->sibling.next);

            list_for_each_entry_rcu(pos, stack[index].child->sibling.next, sibling)
            {
                TRACE(DL_ERROR, "child->sibling %p", pos);
            }
        }
    }
    // If index is 0 when we get here, it means that we are at the init task, so
    //  end the loop.  Otherwise we pop off the stack.
    while (index > 0 && index--);

CATCH_DEFAULT:
    rcu_read_unlock();
    ec_put_path_buffer(path_buffer);
    ec_mem_cache_free_generic(stack);
}

bool __ec_add_tracking_for_child_and_update_stack(
    struct task_stack *top,
    struct task_stack *next,
    char              *path_buffer,
    time_t             start_time,
    ProcessContext *context)
{
    bool found_child = false;

    if (top && top->child && next && path_buffer)
    {
        if (top->child->mm != NULL &&
            top->child->state != TASK_DEAD &&
            top->child->exit_state == 0 &&
            ec_getpid(top->child) == ec_gettid(top->child))
        {
            __ec_add_tracking_for_task(top->child, start_time, path_buffer, context);

            // initialize the next stack entry so we can enumerate the children
            // of this task
            next->task  = top->child;
            next->child = FIRST_TASK(next);
            found_child = true;
        }

        // Move the top stack entry to the next child
        top->child = NEXT_TASK(top);
    }

    return found_child;
}

void __ec_add_tracking_for_task(
    struct task_struct *task,
    time_t              start_time,
    char               *path_buffer,
    ProcessContext     *context)
{
    ProcessHandle *handle;
    char *path = NULL;
    bool             path_found = false;

    if (path_buffer)
    {
        // ec_task_get_path() uses dpath which builds the path efficently
        //  by walking back to the root. It starts with a string terminator
        //  in the last byte of the target buffer.
        //
        // The `path` variable will point to the start of the string, so we will
        //  use that directly later to copy into the tracking entry and event.
        path_found = ec_task_get_path(task, path_buffer, PATH_MAX, &path);
        path_buffer[PATH_MAX] = 0;
    }

    // If the current task reports that it actually exec'ed or
    //  this task has reparented to init we want to record it as an exec
    // The second case may result in some tasks being reported as an exec
    //  where if we had observed the starts we would have used its parent
    //  for the exec information.
    // Ie....
    //   PID 100 execs and forks 101, then 100 exits.  The exec pid should
    //     be 100, but use the forks pid as the exec pid.
    //   PID 100 execs and forks 101 and 102, then 100 exits.  The exec pid should
    //     be 100, but each fork uses its own pid as the exec pid.  This is not
    //     ideal since it causes two reported processes when there should
    //     only be one.
    if (!(task->flags & PF_FORKNOEXEC) || ec_getppid(task) == 1)
    {
        uint64_t device;
        uint64_t inode;

        ec_get_devinfo_from_task(task, &device, &inode);
        handle = ec_process_tracking_update_process(
                ec_getpid(task),
                ec_gettid(task),
                TASK_UID(task),
                TASK_EUID(task),
                device,
                inode,
                path,
                path_found,
                start_time,
                CB_PROCESS_START_BY_EXEC,
                task,
                CB_EVENT_TYPE_PROCESS_START_EXEC,
                FAKE_START,
                context);

        if (handle && path_buffer)
        {
            if (__ec_get_cmdline_from_task(task, path_buffer, PATH_MAX))
            {
                ec_process_tracking_set_proc_cmdline(handle, path_buffer, context);
            }
        }
    } else
    {
        handle = ec_process_tracking_create_process(
                ec_getpid(task),
                ec_getppid(task),
                ec_gettid(task),
                TASK_UID(task),
                TASK_EUID(task),
                start_time,
                CB_PROCESS_START_BY_FORK,
                task,
                FAKE_START,
                context);
    }

    ec_process_tracking_put_handle(handle, context);
}
