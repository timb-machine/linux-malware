// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{
#include <linux/lsm_hooks.h>  // security_hook_heads
#endif  //}

#include <linux/rculist.h>  // hlist_add_tail_rcu
// checkpatch-ignore: AVOID_EXTERNS
#define DEBUGGING_SANITY 0
#if DEBUGGING_SANITY  //{ WARNING from checkpatch
#define PR_p "%px"
#else  //}{ checkpatch no WARNING
#define PR_p "%p"
#endif  //}

static bool g_lsmRegistered;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{ not RHEL8
struct        security_operations  *g_original_ops_ptr;   // Any LSM which we are layered on top of
static struct security_operations   g_combined_ops;       // Original LSM plus our hooks combined
#endif //}

extern int  ec_lsm_bprm_check_security(struct linux_binprm *bprm);
extern void ec_lsm_bprm_committed_creds(struct linux_binprm *bprm);
extern int  ec_lsm_task_create(unsigned long clone_flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern int ec_lsm_mmap_file(struct file *file,
                         unsigned long reqprot, unsigned long prot,
                         unsigned long flags);
#else
extern int ec_lsm_file_mmap(struct file *file,
                         unsigned long reqprot, unsigned long prot,
                         unsigned long flags, unsigned long addr,
                         unsigned long addr_only);
#endif

extern void ec_lsm_inet_conn_established(struct sock *sk, struct sk_buff *skb);
extern int ec_lsm_socket_connect(struct socket *sock, struct sockaddr *addr, int addrlen);
extern int ec_lsm_inet_conn_request(struct sock *sk, struct sk_buff *skb, struct request_sock *req);
extern int ec_lsm_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size);
extern int ec_lsm_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags);
extern int ec_lsm_socket_post_create(struct socket *sock, int family, int type, int protocol, int kern);
extern int ec_lsm_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);
extern void ec_lsm_file_free_security(struct file *file);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{
static unsigned int cblsm_hooks_count;
static struct security_hook_list cblsm_hooks[64];  // [0..39] not needed?
#endif  //}

bool ec_do_lsm_initialize(ProcessContext *context, uint64_t enableHooks)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    TRY_CB_RESOLVED(security_ops);

    //
    // Save off the old LSM pointers
    //
    g_original_ops_ptr = *CB_RESOLVED(security_ops);
    if (g_original_ops_ptr != NULL)
    {
        g_combined_ops     = *g_original_ops_ptr;
    }
    TRACE(DL_INFO, "Other LSM named %s", g_original_ops_ptr->name);

    #define CB_LSM_SETUP_HOOK(NAME) do { \
        if (enableHooks & CB__LSM_##NAME) \
            g_combined_ops.NAME = ec_lsm_##NAME; \
    } while (0)

#else  // }{ LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    TRY_CB_RESOLVED(security_hook_heads);
    cblsm_hooks_count = 0;
    memset(cblsm_hooks, 0, sizeof(cblsm_hooks));

    #define CB_LSM_SETUP_HOOK(NAME) do { \
        if (enableHooks & CB__LSM_##NAME) { \
            pr_info("Hooking %u@" PR_p " %s\n", cblsm_hooks_count, &security_hook_heads.NAME, #NAME); \
            cblsm_hooks[cblsm_hooks_count].head = &security_hook_heads.NAME; \
            cblsm_hooks[cblsm_hooks_count].hook.NAME = ec_lsm_##NAME; \
            cblsm_hooks[cblsm_hooks_count].lsm = "eclsm"; \
            cblsm_hooks_count++; \
        } \
    } while (0)
#endif  // }

    //
    // Now add our hooks
    //
    // 2020-12-15 FIXME: Why is the list a proper subset?
    CB_LSM_SETUP_HOOK(bprm_check_security);   // process banning  (exec)
    CB_LSM_SETUP_HOOK(bprm_committed_creds);  // process launched (exec)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)  //{
    CB_LSM_SETUP_HOOK(mmap_file);  // shared library load
#else  //}{
    CB_LSM_SETUP_HOOK(file_mmap);  // shared library load
#endif  //}
    CB_LSM_SETUP_HOOK(socket_connect);  // outgoing connects (pre)
    CB_LSM_SETUP_HOOK(inet_conn_request);  // incoming accept (pre)
    CB_LSM_SETUP_HOOK(socket_post_create);
    CB_LSM_SETUP_HOOK(socket_sendmsg);
    CB_LSM_SETUP_HOOK(socket_recvmsg);  // incoming UDP/DNS - where we get the process context
    CB_LSM_SETUP_HOOK(file_free_security);
#undef CB_LSM_SETUP_HOOK

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    *CB_RESOLVED(security_ops) = &g_combined_ops;
#else  //}{
    {
        unsigned int j;

        for (j = 0; j < cblsm_hooks_count; ++j) {
            cblsm_hooks[j].lsm = "eclsm";
            hlist_add_tail_rcu(&cblsm_hooks[j].list, cblsm_hooks[j].head);
        }
    }
#endif  //}

    g_lsmRegistered = true;
    return true;

CATCH_DEFAULT:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    TRACE(DL_ERROR, "LSM: Failed to find security_ops\n");
#else  //}{
    TRACE(DL_ERROR, "LSM: Failed to find security_hook_heads\n");
#endif  //}
    return false;
}

// KERNEL_VERSION(4,0,0) and above say this is none of our business
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
bool ec_do_lsm_hooks_changed(ProcessContext *context, uint64_t enableHooks)
{
    bool changed = false;
    struct security_operations *secops = *CB_RESOLVED(security_ops);

    if (enableHooks & CB__LSM_bprm_check_security) changed |= secops->bprm_check_security  != ec_lsm_bprm_check_security;
    if (enableHooks & CB__LSM_bprm_committed_creds) changed |= secops->bprm_committed_creds != ec_lsm_bprm_committed_creds;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    if (enableHooks & CB__LSM_mmap_file) changed |= secops->mmap_file != ec_lsm_mmap_file;
#else
    if (enableHooks & CB__LSM_file_mmap) changed |= secops->file_mmap != ec_lsm_file_mmap;
#endif
    if (enableHooks & CB__LSM_socket_connect) changed |= secops->socket_connect != ec_lsm_socket_connect;
    if (enableHooks & CB__LSM_inet_conn_request) changed |= secops->inet_conn_request != ec_lsm_inet_conn_request;
    if (enableHooks & CB__LSM_socket_post_create) changed |= secops->socket_post_create != ec_lsm_socket_post_create;
    if (enableHooks & CB__LSM_socket_sendmsg) changed |= secops->socket_sendmsg != ec_lsm_socket_sendmsg;
    if (enableHooks & CB__LSM_socket_recvmsg) changed |= secops->socket_recvmsg != ec_lsm_socket_recvmsg;
    if (enableHooks & CB__LSM_file_free_security) changed |= secops->file_free_security != ec_lsm_file_free_security;

    return changed;
}
#endif  //}

void ec_do_lsm_shutdown(ProcessContext *context)
{
    if (g_lsmRegistered
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    &&      CB_CHECK_RESOLVED(security_ops)
#endif  //}
    )
    {
        TRACE(DL_SHUTDOWN, "Unregistering ec_LSM...");
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
        *CB_RESOLVED(security_ops) = g_original_ops_ptr;
#else  // }{ >= KERNEL_VERSION(4,0,0)
        security_delete_hooks(cblsm_hooks, cblsm_hooks_count);
#endif  //}
    } else
    {
        TRACE(DL_WARNING, "ec_LSM not registered so not unregistering");
    }
}

#ifdef HOOK_SELECTOR
void __ec_setHook(const char *buf, const char *name, uint32_t call, void **addr, void *ec_hook, void *kern_hook)
{
    if ('1' == buf[0])
    {
        pr_info("Adding %s: 0x" PR_p "\n", name, addr);
        g_enableHooks |= call;
        *addr = ec_hook;
    } else if ('0' == buf[0])
    {
        pr_info("Removing %s\n", name);
        g_enableHooks &= ~call;
        *addr = kern_hook;
    } else
    {
        pr_err("Error adding %s to %s\n", buf, name);
        return;
    }
}

int __ec_getHook(uint32_t hook, struct seq_file *m)
{
    seq_printf(m, (g_enableHooks & hook ? "1\n" : "0\n"));
    return 0;
}

int ec_get_lsm_bprm_check_security(struct seq_file *m, void *v)  { return __ec_getHook(CB__LSM_bprm_check_security, m); }
int ec_get_lsm_bprm_committed_creds(struct seq_file *m, void *v) { return __ec_getHook(CB__LSM_bprm_committed_creds, m); }
int ec_get_lsm_file_permission(struct seq_file *m, void *v)      { return __ec_getHook(CB__LSM_file_permission, m); }
int ec_get_lsm_socket_connect(struct seq_file *m, void *v)       { return __ec_getHook(CB__LSM_socket_connect, m); }
int ec_get_lsm_inet_conn_request(struct seq_file *m, void *v)    { return __ec_getHook(CB__LSM_inet_conn_request, m); }
int ec_get_lsm_socket_post_create(struct seq_file *m, void *v)   { return __ec_getHook(CB__LSM_socket_post_create, m); }
int ec_get_lsm_socket_sendmsg(struct seq_file *m, void *v)       { return __ec_getHook(CB__LSM_socket_sendmsg, m); }
int ec_get_lsm_socket_recvmsg(struct seq_file *m, void *v)       { return __ec_getHook(CB__LSM_socket_recvmsg, m); }
int ec_get_lsm_file_free_security(struct seq_file *m, void *v)   { return __ec_getHook(CB__LSM_file_free_security, m); }


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int ec_get_lsm_mmap_file(struct seq_file *m, void *v) { return __ec_getHook(CB__LSM_mmap_file, m); }
#else
int ec_get_lsm_file_mmap(struct seq_file *m, void *v) { return __ec_getHook(CB__LSM_file_mmap, m); }
#endif

#define LSM_HOOK(HOOK, NAME, FUNC) \
ssize_t ec_lsm_##HOOK##_set(struct file *file, const char *buf, size_t size, loff_t *ppos) \
{ \
    TRY_CB_RESOLVED(security_ops); \
    __ec_setHook(buf, NAME, CB__LSM_##HOOK, (void **)&(*CB_RESOLVED(security_ops))->HOOK, FUNC, g_original_ops_ptr->HOOK); \
CATCH_DEFAULT: \
    return size; \
}

LSM_HOOK(bprm_check_security, "bprm_check_security",  ec_lsm_bprm_check_security)
LSM_HOOK(bprm_committed_creds, "bprm_committed_creds", ec_lsm_bprm_committed_creds)
LSM_HOOK(socket_connect, "socket_connect",       ec_lsm_socket_connect)
LSM_HOOK(inet_conn_request, "inet_conn_request",    ec_lsm_inet_conn_request)
LSM_HOOK(socket_post_create, "socket_post_create",   ec_lsm_socket_post_create)
LSM_HOOK(socket_sendmsg, "socket_sendmsg",       ec_lsm_socket_sendmsg)
LSM_HOOK(socket_recvmsg, "socket_recvmsg",       ec_lsm_socket_recvmsg)
LSM_HOOK(file_free_security, "file_free_security", ec_lsm_file_free_security)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
LSM_HOOK(mmap_file, "mmap_file",            ec_lsm_mmap_file)
#else
LSM_HOOK(file_mmap, "file_mmap",            ec_lsm_file_mmap)
#endif

#endif
