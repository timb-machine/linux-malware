// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "priv.h"
#include "mem-cache.h"

typedef int     (*fp_readCallback)  (struct seq_file *m, void *v);
typedef ssize_t (*fp_writeCallback) (struct file *, const char __user *, size_t, loff_t *);

// Common
struct _ec_procs {
    const char        *name;
    fp_readCallback    r_callback;
    fp_writeCallback   w_callback;
};

static const struct _ec_procs proc_callbacks[] = {
    { "cache",                    ec_mem_cache_show,                NULL                            },
    { "events-avg",               ec_proc_show_events_avg,          NULL                            },
    { "events-detail",            ec_proc_show_events_det,          NULL                            },
    { "events-reset",             NULL,                             ec_proc_show_events_rst         },
    { "net-track-old",            ec_net_track_show_old,            NULL                            },
    { "net-track-new",            ec_net_track_show_new,            NULL                            },
    { "net-track-purge-age",      NULL,                             ec_net_track_purge_age          },
    { "net-track-purge-all",      NULL,                             ec_net_track_purge_all          },
    { "proc-track-table",         ec_proc_track_show_table,         NULL                            },
    { "proc-track-stats",         ec_proc_track_show_stats,         NULL                            },
    { "file-track-table",         ec_file_track_show_table,         NULL                            },
    { "mem",                      ec_proc_current_memory_avg,       NULL                            },
    { "mem-detail",               ec_proc_current_memory_det,       NULL                            },
    { "active-hooks",             ec_show_active_hooks,             NULL                            },

#ifdef HOOK_SELECTOR
    { "syscall-clone",            ec_get_syscall_clone,             ec_set_syscall_clone            },
    { "syscall-fork",             ec_get_syscall_fork,              ec_set_syscall_fork             },
    { "syscall-vfork",            ec_get_syscall_vfork,             ec_set_syscall_vfork            },
    { "syscall-recvfrom",         ec_get_syscall_recvfrom,          ec_set_syscall_recvfrom         },
    { "syscall-recvmsg",          ec_get_syscall_recvmsg,           ec_set_syscall_recvmsg          },
    { "syscall-recvmmsg",         ec_get_syscall_recvmmsg,          ec_set_syscall_recvmmsg         },
    { "syscall-write",            ec_get_syscall_write,             ec_set_syscall_write            },
    { "syscall-delete-module",    ec_get_syscall_delete_module,     ec_set_syscall_delete_module    },
    { "netfilter-out",            ec_get_netfilter_local_out,       ec_set_netfilter_local_out      },
    { "lsm-bprm_check_security",  ec_get_lsm_bprm_check_security,   ec_set_lsm_bprm_check_security  },
    { "lsm-bprm_committed_creds", ec_get_lsm_bprm_committed_creds,  ec_set_lsm_bprm_committed_creds },
    { "lsm-inode_create",         ec_get_lsm_inode_create,          ec_set_lsm_inode_create         },
    { "lsm-inode_rename",         ec_get_lsm_inode_rename,          ec_set_lsm_inode_rename         },
    { "lsm-inode_unlink",         ec_get_lsm_inode_unlink,          ec_set_lsm_inode_unlink         },
    { "lsm-file_permission",      ec_get_lsm_file_permission,       ec_set_lsm_file_permission      },
    { "lsm-file_free_security",   ec_get_lsm_file_free_security,    ec_set_lsm_file_free_security   },
    { "lsm-socket_connect",       ec_get_lsm_socket_connect,        ec_set_lsm_socket_connect       },
    { "lsm-inet_conn_request",    ec_get_lsm_inet_conn_request,     ec_set_lsm_inet_conn_request    },
    { "lsm-socket_sock_rcv_skb",  ec_get_lsm_socket_sock_rcv_skb,   ec_set_lsm_socket_sock_rcv_skb  },
    { "lsm-socket_post_create",   ec_get_lsm_socket_post_create,    ec_set_lsm_socket_post_create   },
    { "lsm-socket_sendmsg",       ec_get_lsm_socket_sendmsg,        ec_set_lsm_socket_sendmsg       },
    { "lsm-socket_recvmsg",       ec_get_lsm_socket_recvmsg,        ec_set_lsm_socket_recvmsg       },

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    { "lsm-mmap_file",            ec_get_lsm_mmap_file,             ec_set_lsm_mmap_file            },
#else
    { "lsm-file_mmap",            ec_get_lsm_file_mmap,             ec_set_lsm_file_mmap            },
#endif
#endif
    { 0 }
};

int ec_dummy_show(struct seq_file *m, void *v)
{
    return 0;
}

int ec_proc_open(struct inode *inode, struct file *file)
{
    uint64_t          procId   = (uint64_t)PDE_DATA(inode);
    fp_readCallback   callback = proc_callbacks[procId].r_callback;

    if (procId >= (sizeof(proc_callbacks) / sizeof(struct _ec_procs)))
        return -EINVAL;

    return single_open(file, (callback ? callback : ec_dummy_show), PDE_DATA(inode));
}

ssize_t ec_proc_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
    uint64_t procId = (uint64_t)((struct seq_file *)file->private_data)->private;
    ssize_t  len    = 0;
    char buffer[20] = { 0 };

    size = (size < 20 ? size : 19);
    if (copy_from_user(buffer, buf, size))
        size = 0;
    buffer[size] = 0;

    if (proc_callbacks[procId].w_callback)
    {
        len = proc_callbacks[procId].w_callback(file, buffer, size, ppos);
    }

    return len;
}

const struct file_operations ec_fops = {
    .owner      = THIS_MODULE,
    .open       = ec_proc_open,
    .read       = seq_read,
    .write      = ec_proc_write,
    .release    = single_release,
};

bool ec_stats_proc_initialize(ProcessContext *context)
{
    uint64_t i;

    for (i = 0; proc_callbacks[i].name != NULL; ++i)
    {
        int mode = (proc_callbacks[i].r_callback ? 0400 : 0) | (proc_callbacks[i].w_callback ? 0200 : 0);

        if (!proc_create_data(proc_callbacks[i].name, mode, g_cb_proc_dir, &ec_fops, (void *)i))
        {
            TRACE(DL_ERROR, "Failed to create proc directory entry %s", proc_callbacks[i].name);
        }
    }

    return true;
}

void ec_stats_proc_shutdown(ProcessContext *context)
{
    int i;

    for (i = 0; proc_callbacks[i].name != NULL; ++i)
    {
        remove_proc_entry(proc_callbacks[i].name, g_cb_proc_dir);
    }

}
