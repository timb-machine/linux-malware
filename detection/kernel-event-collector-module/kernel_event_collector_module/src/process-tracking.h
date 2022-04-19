/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/sched.h>
#include "hash-table-generic.h"
#include "rbtree-helper.h"
#include "raw_event.h"

typedef struct pt_table_key {
    pid_t    pid;
} PT_TBL_KEY;

#define FAKE_START false
#define REAL_START true

// List struct for use by RUNNING_BANNED_INODE_S
typedef struct processes_to_ban {
    void *process_handle; // Pointer for the process tracking element to ban
    struct list_head list;
} RUNNING_PROCESSES_TO_BAN;

typedef struct running_banned_inode_info_s {
    uint64_t count;
    uint64_t device;
    uint64_t inode;
    RUNNING_PROCESSES_TO_BAN BanList;
} RUNNING_BANNED_INODE_S;

typedef struct exec_identity {
    ProcessDetails    exec_details;
    ProcessDetails    exec_parent_details;
    ProcessDetails    exec_grandparent_details;


    uint64_t          string_lock;
    char             *path;
    char             *cmdline;
    bool              path_found;

    // Processes with this set report file open events
    bool              is_interpreter;
    uint64_t          exec_count;

    // This list contains all the open files tracked by the kernel for this process.
    //  Manipulation of this list is only done in file-process-tracking, and is protected
    //  by a mutex
    void            *tracked_files;

    // This tracks the owners of this struct (can be more than the number of active processes)
    atomic64_t        reference_count;

    // This tracks the number of active processes so that we can identify the last running process for an exec identity
    //  when sending an exit event.
    atomic64_t        active_process_count;

    // This holds a PCB_EVENT for the exit event for this process; which will only be enqueued
    // when the final process exits AND all outstanding events for the process have been read by the agent.
    // It is stored as an atomic so we can replace the pointer atomically
    atomic64_t        exit_event;
} ExecIdentity;

// This handle holds reference counts to the exec_identity and some internal pointers
typedef struct ExecIdentity_handle {
    ExecIdentity *identity;
    char         *path;
    char         *cmdline;
} ExecHandle;

typedef struct posix_identity {
    HashTableNode     pt_link;
    PT_TBL_KEY        pt_key;

    // This tracks the owners of this struct (can be more than the number of active processes)
    atomic64_t        reference_count;

    ProcessDetails    posix_details;
    ProcessDetails    posix_parent_details;
    ProcessDetails    posix_grandparent_details;

    pid_t       tid;
    uid_t       uid;
    uid_t       euid;
    int         action;   // How did we start

    bool        exec_blocked;
    bool        is_real_start;
    uint64_t    op_cnt;

    uint64_t    net_op_cnt;
    uint64_t    net_connect;
    uint64_t    net_accept;
    uint64_t    net_dns;

    uint64_t    file_op_cnt;
    uint64_t    file_create;
    uint64_t    file_delete;
    uint64_t    file_open;      // First write equals open
    uint64_t    file_write;
    uint64_t    file_close;
    uint64_t    file_map_write;
    uint64_t    file_map_exec;

    uint64_t    process_op_cnt;
    uint64_t    process_create;
    uint64_t    process_exit;
    uint64_t    process_create_by_fork;
    uint64_t    process_create_by_exec;

    uint64_t    childproc_cnt;

    ExecIdentity   *exec_identity;

    // This holds a temporary handle to the exec_identity that will be referenced by the next event created for
    // this proc. This is only used when creating events as a result of process execs.
    ExecHandle      temp_exec_handle;

} PosixIdentity;

// This handle holds reference counts to the posix_identity
typedef struct process_handle {
    PosixIdentity  *posix_identity;
    ExecHandle      exec_handle;
} ProcessHandle;

bool ec_process_tracking_initialize(ProcessContext *context);
void ec_process_tracking_shutdown(ProcessContext *context);

ProcessHandle *ec_process_tracking_create_process(
        pid_t               pid,
        pid_t               parent,
        pid_t               tid,
        uid_t               uid,
        uid_t               euid,
        time_t              start_time,
        int                 action,
        struct task_struct *taskp,
        bool                is_real_start,
        ProcessContext *context);
ProcessHandle *ec_process_tracking_update_process(
        pid_t               pid,
        pid_t               tid,
        uid_t               uid,
        uid_t               euid,
        uint64_t            device,
        uint64_t            inode,
        char               *path,
        bool                path_found,
        time_t              start_time,
        int                 action,
        struct task_struct *taskp,
        CB_EVENT_TYPE       event_type,
        bool                is_real_start,
        ProcessContext     *context);

ProcessHandle *ec_process_tracking_get_handle(pid_t pid, ProcessContext *context);
void ec_process_tracking_put_handle(ProcessHandle *process_handle, ProcessContext *context);
void ec_process_tracking_remove_process(ProcessHandle *process_handle, ProcessContext *context);
bool ec_is_process_tracked(pid_t pid, ProcessContext *context);
void ec_is_process_tracked_get_state_by_inode(RUNNING_BANNED_INODE_S *psRunningInodesToBan, ProcessContext *context);
bool ec_process_tracking_report_exit(pid_t pid, ProcessContext *context);
char *ec_process_tracking_get_path(ExecIdentity *exec_identity, ProcessContext *context);
void ec_process_tracking_set_path(ProcessHandle *process_handle, char *path, ProcessContext *context);
char *ec_process_tracking_get_cmdline(ExecIdentity *exec_identity, ProcessContext *context);
void ec_process_tracking_set_cmdline(ExecHandle *exec_handle, char *cmdline, ProcessContext *context);
void ec_process_tracking_set_proc_cmdline(ProcessHandle *process_handle, char *cmdline, ProcessContext *context);

// Discovery
void ec_process_tracking_send_process_discovery(ProcessContext *context);

// Hook Helpers
void ec_process_tracking_mark_as_blocked(ProcessHandle *process_handle);
bool ec_process_tracking_is_blocked(ProcessHandle *process_handle);
pid_t ec_process_tracking_exec_pid(ProcessHandle *process_handle, ProcessContext *context);
ProcessHandle *ec_create_process_start_by_exec_event(struct task_struct *task, ProcessContext *context);
ProcessHandle *ec_get_procinfo_and_create_process_start_if_needed(pid_t pid, const char *msg, ProcessContext *context);
ExecIdentity *ec_process_tracking_get_exec_identity(PosixIdentity *posix_identity, ProcessContext *context);
ExecIdentity *ec_process_tracking_get_exec_identity_ref(ExecIdentity *exec_identity, ProcessContext *context);
void ec_process_tracking_put_exec_identity(ExecIdentity *exec_identity, ProcessContext *context);
void ec_process_tracking_put_exec_handle(ExecHandle *exec_handle, ProcessContext *context);
void ec_process_exec_handle_clone(ExecHandle *from, ExecHandle *to, ProcessContext *context);

// Event Helper
void ec_process_tracking_set_event_info(ProcessHandle *process_handle, CB_INTENT_TYPE intentType, CB_EVENT_TYPE eventType, PCB_EVENT event, ProcessContext *context);
void ec_process_tracking_store_exit_event(PosixIdentity *posix_identity, PCB_EVENT event, ProcessContext *context);
bool ec_process_tracking_should_track_user(void);
bool ec_process_tracking_has_active_process(PosixIdentity *posix_identity, ProcessContext *context);

// File helpers
typedef void (*process_tracking_for_each_tree_callback)(void *tree, void *priv, ProcessContext *context);
void ec_process_tracking_for_each_file_tree(process_tracking_for_each_tree_callback callback, void *priv, ProcessContext *context);

PosixIdentity *ec_process_posix_identity(ProcessHandle *process_handle);
ExecIdentity *ec_process_exec_identity(ProcessHandle *process_handle);
ExecHandle *ec_process_exec_handle(ProcessHandle *process_handle);
char *ec_process_path(ProcessHandle *process_handle);
char *ec_process_cmdline(ProcessHandle *process_handle);
ExecIdentity *ec_exec_identity(ExecHandle *exec_handle);
char *ec_exec_path(ExecHandle *exec_handle);

// List of interpreters. The ExecIdentity::is_interpreter flag
// is set for any process whose path contains a name in this list.
extern char **g_interpreter_names;
extern int    g_interpreter_names_count;
