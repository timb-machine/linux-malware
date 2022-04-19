/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

// Defining __KERNEL__ and MODULE allows us to access kernel-level code not usually available to userspace programs.
#undef __KERNEL__
#define __KERNEL__

#undef MODULE
#define MODULE

// Linux Kernel/LKM headers: module.h is needed by all modules and kernel.h is needed for KERN_INFO.
#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>        // included for __init and __exit macros

#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <net/ipv6.h>
//#include <linux/sunrpc/clnt.h>
#include <linux/mman.h>
#include <linux/connector.h>
#include <linux/version.h>

#include "process-context.h"
#include "dbg.h"
#include "raw_event.h"
#include "cb-test.h"
#include "version.h"
#include "task-helper.h"
#include "module_state.h"

extern const char DRIVER_NAME[];

#define INITTASK 1    // used by protection software to prevent catastrophic issues

#define CB_SENSOR_MAX_PIDS  5
#define CB_SENSOR_MAX_UIDS  5

#define ROUND_TO_BASE(x, base) ((((size_t)(x)) + base-1) & (~(base-1)))
#define ROUND_TO_NEXT_CACHE_LINE(x) (ROUND_TO_BASE(x, 64))
#define ROUND_TO_NEXT_PAGE(x) (ROUND_TO_BASE(x, PAGE_SIZE))

extern CB_DRIVER_CONFIG g_driver_config;
extern uid_t    g_edr_server_uid;
extern int64_t  g_cb_ignored_pid_count;
extern int64_t  g_cb_ignored_uid_count;
extern pid_t    g_cb_ignored_pids[CB_SENSOR_MAX_PIDS];
extern uid_t    g_cb_ignored_uids[CB_SENSOR_MAX_UIDS];
extern bool     g_exiting;
extern uint32_t g_max_queue_size_pri0;
extern uint32_t g_max_queue_size_pri1;
extern uint32_t g_max_queue_size_pri2;

#define MSG_QUEUE_SIZE  8192
#define DEFAULT_P0_QUEUE_SIZE  (MSG_QUEUE_SIZE * 3)
#define DEFAULT_P1_QUEUE_SIZE  MSG_QUEUE_SIZE
#define DEFAULT_P2_QUEUE_SIZE  MSG_QUEUE_SIZE



//-------------------------------------------------

#define CB__NR_clone                      0x0000000000000001
#define CB__NR_fork                       0x0000000000000002
#define CB__NR_vfork                      0x0000000000000004
#define CB__NR_recvfrom                   0x0000000000000008
#define CB__NR_recvmsg                    0x0000000000000010
#define CB__NR_recvmmsg                   0x0000000000000020
#define CB__NR_delete_module              0x0000000000000080
#define CB__NR_creat                      0x0000000000000200
#define CB__NR_open                       0x0000000000000400
#define CB__NR_openat                     0x0000000000000800
#define CB__NR_unlink                     0x0000000000001000
#define CB__NR_unlinkat                   0x0000000000002000
#define CB__NR_rename                     0x0000000000004000
#define CB__NR_renameat                   0x0000000000008000
#define CB__NR_renameat2                  0x0000000000010000

#define SYSCALL_HOOK_MASK                 0x00000000FFFFFFFF

#define CB__NF_local_out                  0x0000000100000000

#define CB__LSM_bprm_check_security       0x0000100000000000
#define CB__LSM_bprm_committed_creds      0x0000200000000000

#define CB__LSM_mmap_file                 0x0000800000000000
#define CB__LSM_file_mmap                 0x0000800000000000
#define CB__LSM_file_permission           0x0001000000000000
#define CB__LSM_socket_connect            0x0002000000000000
#define CB__LSM_inet_conn_request         0x0004000000000000
#define CB__LSM_socket_sock_rcv_skb       0x0008000000000000
#define CB__LSM_socket_post_create        0x0010000000000000
#define CB__LSM_socket_sendmsg            0x0020000000000000
#define CB__LSM_socket_recvmsg            0x0040000000000000
#define CB__LSM_file_free_security        0x0080000000000000

#define SAFE_STRING(PATH) (PATH) ? (PATH) : "<unknown>"

// ------------------------------------------------
// Module Helpers
//
void ec_shutdown(ProcessContext *context);
int ec_enable_module(ProcessContext *context);
int ec_disable_module(ProcessContext *context);
ModuleState ec_get_module_state(ProcessContext *context);
bool ec_is_reader_connected(void);
bool ec_disconnect_reader(pid_t pid);
void ec_reader_init(void);

// ------------------------------------------------
// Linux Security Module Helpers
//
extern bool ec_do_lsm_initialize(ProcessContext *context, uint64_t enableHooks);
extern void ec_do_lsm_shutdown(ProcessContext *context);
extern bool ec_do_lsm_hooks_changed(ProcessContext *context, uint64_t enableHooks);

// ------------------------------------------------
// Linux Syscall Hook Helpers
//
#define GPF_DISABLE write_cr0(read_cr0() & (~0x10000))
#define GPF_ENABLE  write_cr0(read_cr0() | 0x10000)

extern bool ec_do_sys_initialize(ProcessContext *context, uint64_t enableHooks);
extern void ec_do_sys_shutdown(ProcessContext *context, uint64_t enableHooks);
extern bool ec_do_sys_hooks_changed(ProcessContext *context, uint64_t enableHooks);
extern void ec_sys_clone(ProcessContext *context, struct task_struct *task);

extern struct security_operations *g_original_ops_ptr;

// ------------------------------------------------
// Netfilter Module Helpers
//
extern bool ec_netfilter_initialize(ProcessContext *context, uint64_t enableHooks);
extern void ec_netfilter_cleanup(ProcessContext *context, uint64_t enableHooks);

// ------------------------------------------------
// Stats Proc Helper
bool ec_stats_proc_initialize(ProcessContext *context);
void ec_stats_proc_shutdown(ProcessContext *context);
int ec_proc_track_show_table(struct seq_file *m, void *v);
int ec_proc_track_show_stats(struct seq_file *m, void *v);
int ec_file_track_show_table(struct seq_file *m, void *v);

int ec_proc_current_memory_avg(struct seq_file *m, void *v);
int ec_proc_current_memory_det(struct seq_file *m, void *v);
int ec_show_active_hooks(struct seq_file *m, void *v);

// ------------------------------------------------
// Logging
//
extern bool ec_logger_initialize(ProcessContext *context);
extern void ec_logger_shutdown(ProcessContext *context);

extern PCB_EVENT ec_alloc_event(CB_INTENT_TYPE intentType, CB_EVENT_TYPE eventType, ProcessContext *context);
extern void ec_free_event(PCB_EVENT event, ProcessContext *context);
extern void ec_free_event_on_error(PCB_EVENT event, ProcessContext *context);
extern void ec_event_set_process_data(PCB_EVENT event, void *process_data, ProcessContext *context);

extern bool ec_logger_should_log(CB_INTENT_TYPE intentType, CB_EVENT_TYPE eventType);

extern int ec_send_event(struct CB_EVENT *msg, ProcessContext *context);
extern void ec_fops_comm_wake_up_reader(ProcessContext *context);
extern bool ec_user_comm_initialize(ProcessContext *context);
extern void ec_user_comm_shutdown(ProcessContext *context);

// ------------------------------------------------
// File Operations
//
extern bool ec_user_devnode_init(ProcessContext *context);
extern void ec_user_devnode_close(ProcessContext *context);
extern char *ec_event_type_to_str(CB_EVENT_TYPE event_type);

// ------------------------------------------------
// Symbol Helpers
//
extern void *ec_get_ksym(char *sym_name);

// ------------------------------------------------
// General Helpers
//
#define ATOMIC_INCREMENT(v)   __sync_fetch_and_add((v), 1)
uint64_t ec_to_windows_timestamp(const struct timespec *tv);
time_t ec_get_current_time(void);
time_t ec_get_null_time(void);

#define TO_WIN_SEC(SEC) ((uint64_t)(SEC) * (uint64_t)10000000)
#define TO_WIN_TIME(SEC, NSEC) (TO_WIN_SEC(SEC) + (uint64_t)116444736000000000 + ((NSEC) / 100))

// ------------------------------------------------

extern int     ec_proc_show_events_avg(struct seq_file *m, void *v);
extern int     ec_proc_show_events_det(struct seq_file *m, void *v);
extern ssize_t ec_proc_show_events_rst(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern ssize_t ec_net_track_purge_age(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern ssize_t ec_net_track_purge_all(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern int     ec_net_track_show_new(struct seq_file *m, void *v);
extern int     ec_net_track_show_old(struct seq_file *m, void *v);

extern int ec_get_syscall_clone(struct seq_file *m, void *v);
extern ssize_t ec_set_syscall_clone(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern int ec_get_syscall_fork(struct seq_file *m, void *v);
extern ssize_t ec_set_syscall_fork(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern int ec_get_syscall_vfork(struct seq_file *m, void *v);
extern ssize_t ec_set_syscall_vfork(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern int ec_get_syscall_recvfrom(struct seq_file *m, void *v);
extern ssize_t ec_set_syscall_recvfrom(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern int ec_get_syscall_recvmsg(struct seq_file *m, void *v);
extern ssize_t ec_set_syscall_recvmsg(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern int ec_get_syscall_recvmmsg(struct seq_file *m, void *v);
extern ssize_t ec_set_syscall_recvmmsg(struct file *file, const char *buf, size_t size, loff_t *ppos);
extern int ec_get_syscall_write(struct seq_file *m, void *v);
extern ssize_t ec_set_syscall_write(struct file *file, const char *buf, size_t size, loff_t *ppos);

extern int ec_get_netfilter_local_out(struct seq_file *m, void *v);
extern ssize_t ec_set_netfilter_local_out(struct file *file, const char *buf, size_t size, loff_t *ppos);

int ec_get_lsm_bprm_check_security(struct seq_file *m, void *v);
int ec_get_lsm_inode_create(struct seq_file *m, void *v);
int ec_get_lsm_inode_rename(struct seq_file *m, void *v);
int ec_get_lsm_inode_unlink(struct seq_file *m, void *v);
int ec_get_lsm_file_permission(struct seq_file *m, void *v);
int ec_get_lsm_file_free_security(struct seq_file *m, void *v);
int ec_get_lsm_socket_connect(struct seq_file *m, void *v);
int ec_get_lsm_inet_conn_request(struct seq_file *m, void *v);
int ec_get_lsm_socket_sock_rcv_skb(struct seq_file *m, void *v);
int ec_get_lsm_socket_post_create(struct seq_file *m, void *v);
int ec_get_lsm_socket_sendmsg(struct seq_file *m, void *v);
int ec_get_lsm_socket_recvmsg(struct seq_file *m, void *v);

ssize_t ec_set_lsm_bprm_check_security(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_inode_create(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_inode_rename(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_inode_unlink(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_file_permission(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_file_free_security(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_socket_connect(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_inet_conn_request(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_socket_sock_rcv_skb(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_socket_post_create(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_socket_sendmsg(struct file *file, const char *buf, size_t size, loff_t *ppos);
ssize_t ec_set_lsm_socket_recvmsg(struct file *file, const char *buf, size_t size, loff_t *ppos);

#if KERNEL_VERSION(3, 10, 0) < LINUX_VERSION_CODE
int     ec_get_lsm_mmap_file(struct seq_file *m, void *v);
ssize_t ec_set_lsm_mmap_file(struct file *file, const char *buf, size_t size, loff_t *ppos);
#else
int     ec_get_lsm_file_mmap(struct seq_file *m, void *v);
ssize_t ec_set_lsm_file_mmap(struct file *file, const char *buf, size_t size, loff_t *ppos);
#endif

bool ec_disable_if_not_connected(ProcessContext *context, char *src_module_name, char **failure_reason);

// ------------------------------------------------
// File Helpers
//
extern bool ec_file_helper_init(ProcessContext *context);
extern bool ec_file_get_path(struct file const *file, char *buffer, unsigned int buflen, char **pathname);
extern bool ec_path_get_path(struct path const *path, char *buffer, unsigned int buflen, char **pathname);
extern bool ec_dentry_get_path(struct dentry const *dentry, char *buffer, unsigned int buflen, char **pathname);
extern char *ec_dentry_to_path(struct dentry const *dentry, char *buf, int buflen);
extern char *ec_lsm_dentry_path(struct dentry const *dentry, char *path, int len);
extern struct inode const *ec_get_inode_from_file(struct file const *file);
extern void ec_get_devinfo_from_file(struct file const *file, uint64_t *device, uint64_t *inode);
extern void ec_get_devinfo_from_path(struct path const *path, uint64_t *device, uint64_t *inode);
extern struct inode const *ec_get_inode_from_dentry(struct dentry const *dentry);
umode_t ec_get_mode_from_file(struct file const *file);
extern struct super_block const *ec_get_sb_from_file(struct file const *file);
extern bool ec_is_interesting_file(struct file *file);
extern int ec_is_special_file(char *pathname, int len);
extern bool ec_may_skip_unsafe_vfs_calls(struct file const *file);

// schedulers
extern const struct sched_class idle_sched_class;
extern const struct sched_class fair_sched_class;
extern const struct sched_class rt_sched_class;

typedef enum {
    HASH_STATE_NEVER_HASHED     = 0,        // File has never been seen/hashed
    HASH_STATE_HASH_IN_PROGRESS = 1,        // Hash scan request is queued or in progress
    HASH_STATE_HASH_VALID       = 2,        // Hash is valid, no need to rescan
}
HASH_STATE;

#define INODE_CTX_MAGIC     ('xtCI')

typedef struct _inode_ctx {
    uint32_t        magic;      // INODE_CTX_MAGIC
    dev_t           devno;      // device number
    u64             ino;        // inode number
    bool            isImage;    // is executable image
    HASH_STATE      hashState;  // validity in hash cache
}
inode_ctx, *pinode_ctx;

#define FILE_CTX_MAGIC      ('xtCF')

typedef struct _file_ctx {
    u32             magic;      // FILE_CTX_MAGIC
    pinode_ctx      inodeCtx;
    char            filePath[0];
}
file_ctx, *pfile_ctx;

//------------------------------------
// Symbol lookup
//
#define CB_KALLSYMS_BUFFER   2048

// checkpatch-ignore: SPACING,COMPLEX_MACRO
#define _C ,
// checkpatch-no-ignore: SPACING,COMPLEX_MACRO

// Global pointer resolution
//  This section defines global symbols (variables or functions) that are not exported to modules.
//  These symbols will be discovered at runtime and can be used in code with the CB_RESOLVED( S_NAME )
//  macro.


// This macro can be used in code to access a symbol we looked up at runtime.  It is important to verify
//  symbol is not NULL before use.  (It will be NULL if the symbol was not found.)
#define CB_RESOLVED(S_NAME)             g_resolvedSymbols.S_NAME
#define CB_CHECK_RESOLVED(S_NAME)     (g_resolvedSymbols.S_NAME != NULL)
#define TRY_CB_RESOLVED(S_NAME)         TRY_MSG(CB_CHECK_RESOLVED(S_NAME), DL_ERROR, "%s: Function pointer \"%s\" is NULL.", __func__, #S_NAME)
#define CANCEL_CB_RESOLVED(S_NAME, VAL) CANCEL_MSG(CB_CHECK_RESOLVED(S_NAME), VAL, DL_ERROR, "%s: Function pointer \"%s\" is NULL.", __func__, #S_NAME)
// Define a list of symbols using the CB_RESOLV_VARIABLE(V_TYPE, V_NAME) and CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL)
//  macros.  Note, these macros are special.  They are defined just before CB_RESOLV_SYMBOLS is expanded.
//  This allows us to list a symbol name only once, and it will be used correctly in several places.
// CB_RESOLV_FUNCTION_310 will only resolve the function when built for kernel >= 3.10
// checkpatch-ignore: COMPLEX_MACRO,MULTISTATEMENT_MACRO_USE_DO_WHILE,TRAILING_SEMICOLON
#define CB_RESOLV_SYMBOLS \
CB_RESOLV_FUNCTION(int, access_process_vm, struct task_struct const *tsk _C unsigned long addr _C void *buf _C int len _C int write) \
CB_RESOLV_FUNCTION(char *, dentry_path, struct dentry *dentry _C char *buf _C int buflen) \
CB_RESOLV_FUNCTION_310(bool, current_chrooted, void) \
CB_RESOLV_FUNCTION(pte_t *, lookup_address, unsigned long address _C unsigned int *level) \
CB_RESOLV_VARIABLE(rwlock_t, tasklist_lock) \
CB_RESOLV_VARIABLE(void*, sys_call_table) \
CB_RESOLV_VARIABLE(void*, ia32_sys_call_table) \
CB_RESOLV_VARIABLE_LT4(struct security_operations*, security_ops) \
CB_RESOLV_VARIABLE_GE4(struct security_hook_heads, security_hook_heads) \
CB_RESOLV_VARIABLE(const struct sched_class, idle_sched_class) \
CB_RESOLV_VARIABLE(const struct sched_class, fair_sched_class) \
CB_RESOLV_VARIABLE(const struct sched_class, rt_sched_class) \
CB_RESOLV_FUNCTION(u64, nsec_to_clock_t, u64 x) \
CB_RESOLV_FUNCTION(struct task_struct *, find_task_by_vpid, pid_t) \
CB_RESOLV_FUNCTION(struct filename *, getname, const char __user *) \
CB_RESOLV_FUNCTION(void, putname, struct filename *) \

// Here we declare the typedefs for the symbol pointer we will eventually look up.  "p_" will be prepended to the
//  symbol name.
#undef  CB_RESOLV_FUNCTION
#define CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL) typedef F_TYPE(*p_ ## F_NAME)(ARGS_DECL);

#undef  CB_RESOLV_FUNCTION_310
#define CB_RESOLV_FUNCTION_310(F_TYPE, F_NAME, ARGS_DECL) CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL);

#undef  CB_RESOLV_VARIABLE
#define CB_RESOLV_VARIABLE(V_TYPE, V_NAME)            typedef V_TYPE * p_ ## V_NAME;

#undef  CB_RESOLV_VARIABLE_LT4
#if LINUX_VERSION_CODE <  KERNEL_VERSION(4, 0, 0)  //{
#define CB_RESOLV_VARIABLE_LT4(V_TYPE, V_NAME) CB_RESOLV_VARIABLE(V_TYPE, V_NAME)
#else  //}{
#define CB_RESOLV_VARIABLE_LT4(V_TYPE, V_NAME)
#endif  //}

#undef  CB_RESOLV_VARIABLE_GE4
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{
#define CB_RESOLV_VARIABLE_GE4(V_TYPE, V_NAME) CB_RESOLV_VARIABLE(V_TYPE, V_NAME)
#else  //}{
#define CB_RESOLV_VARIABLE_GE4(V_TYPE, V_NAME)
#endif  //}
CB_RESOLV_SYMBOLS

// Here we declare CB_RESOLVED_SYMS struct that holds all the symbols we will eventually look up.
typedef struct _CB_RESOLVED_SYMS {
    #undef  CB_RESOLV_FUNCTION
    #define CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL) CB_RESOLV_VARIABLE(F_TYPE, F_NAME);

    #undef  CB_RESOLV_FUNCTION_310
    #define CB_RESOLV_FUNCTION_310(F_TYPE, F_NAME, ARGS_DECL) CB_RESOLV_FUNCTION(F_TYPE, F_NAME, ARGS_DECL);

    #undef  CB_RESOLV_VARIABLE
    #define CB_RESOLV_VARIABLE(V_TYPE, V_NAME)            p_ ## V_NAME V_NAME;

    #undef  CB_RESOLV_VARIABLE_LT4
    #if LINUX_VERSION_CODE <  KERNEL_VERSION(4, 0, 0)  //{
    #define CB_RESOLV_VARIABLE_LT4(V_TYPE, V_NAME) CB_RESOLV_VARIABLE(V_TYPE, V_NAME)
    #else  //}{
    #define CB_RESOLV_VARIABLE_LT4(V_TYPE, V_NAME)
    #endif  //}

    #undef  CB_RESOLV_VARIABLE_GE4
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{
    #define CB_RESOLV_VARIABLE_GE4(V_TYPE, V_NAME) CB_RESOLV_VARIABLE(V_TYPE, V_NAME)
    #else  //}{
    #define CB_RESOLV_VARIABLE_GE4(V_TYPE, V_NAME)
    #endif  //}

    CB_RESOLV_SYMBOLS
} CB_RESOLVED_SYMS;
// checkpatch-no-ignore: COMPLEX_MACRO,MULTISTATEMENT_MACRO_USE_DO_WHILE,TRAILING_SEMICOLON

// Create a node to hold the event
typedef struct _CB_EVENT_NODE {
    struct list_head   listEntry;
    struct CB_EVENT    data;
    uint16_t           payload; // precomputed size of event data to be sent to userspace
    void              *process_data;
} CB_EVENT_NODE;

// Define the actual storage varaible
extern CB_RESOLVED_SYMS g_resolvedSymbols;
#define INIT_CB_RESOLVED_SYMS()   CB_RESOLVED_SYMS g_resolvedSymbols = {0}

// Helpers

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define PDE_DATA(a) container_of((a), struct proc_inode, vfs_inode)->pde->data
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#   define GET_UID()  current_cred()->uid.val
#   define GET_EUID() current_cred()->euid.val
#   define TASK_UID(task)  __task_cred(task)->uid.val
#   define TASK_EUID(task)  __task_cred(task)->euid.val
#else
#   define GET_UID()  current_cred()->uid
#   define GET_EUID() current_cred()->euid
#   define TASK_UID(task)  __task_cred(task)->uid
#   define TASK_EUID(task)  __task_cred(task)->euid
#   define PDE_DATA(a) container_of((a), struct proc_inode, vfs_inode)->pde->data
#endif

extern struct proc_dir_entry *g_cb_proc_dir;
extern ModuleStateInfo g_module_state_info;
extern uint64_t g_enableHooks;

/* See <linux>/Documentation/core-api/printk-formats.rst
 * Leading '%' omitted to allow infix of width, precision, etc.
 * such as:   "%16.16" PRFx64  ==>  "%16.16llx"
 */
#define PRFs64 "lld"  /*   signed 64-bit decimal */
#define PRFu64 "llu"  /* unsigned 64-bit decimal */
#define PRFx64 "llx"  /* unsigned 64-bit hex     */

#undef _C
