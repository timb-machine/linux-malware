// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "process-tracking.h"
#include "cb-spinlock.h"
#include "cb-banning.h"
#include "path-buffers.h"
#include "event-factory.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define MMAP_ADDRESS() 0
int ec_lsm_mmap_file(struct file *file,
                  unsigned long reqprot, unsigned long prot,
                  unsigned long flags)
#else
#define MMAP_ADDRESS() addr
int ec_lsm_file_mmap(struct file *file,
                  unsigned long reqprot, unsigned long prot,
                  unsigned long flags, unsigned long addr,
                  unsigned long addr_only)
#endif
{
    int xcode;
    char *string_buffer    = NULL;
    char *pathname         = NULL;
    uint64_t device           = 0;
    uint64_t inode            = 0;
    ProcessHandle *process_handle = NULL;
    pid_t pid              = ec_getpid(current);

    DECLARE_ATOMIC_CONTEXT(context, pid);

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY((prot & PROT_EXEC) && !(prot & PROT_WRITE));

    TRY(file);

    // Skip if deleted
    TRY(!d_unlinked(file->f_path.dentry));

    TRY(!ec_banning_IgnoreProcess(&context, pid));

    // Skip if not interesting
    TRY(ec_is_interesting_file(file));

    // Skip if excluded
    // TODO: add device to test
    ec_get_devinfo_from_file(file, &device, &inode);

    // TODO: Add logic here to kill a process based on banned inode.
    //       There was logic here that made the check, but did not actually kill
    //       anything.

    //
    // This is a valid file, allocate an event
    //
    string_buffer = ec_get_path_buffer(&context);
    if (string_buffer)
    {
        // ec_file_get_path() uses dpath which builds the path efficently
        //  by walking back to the root. It starts with a string terminator
        //  in the last byte of the target buffer and needs to be copied
        //  with memmove to adjust
        // Note for CB-6707: The 3.10 kernel occasionally crashed in d_path when the file was closed.
        //  The workaround used dentry->d_iname instead. But this only provided the short name and
        //  not the whole path.  The daemon could no longer match the lastWrite to the firstWrite.
        //  I am now only calling this with an open file now so we should be fine.
        ec_file_get_path(file, string_buffer, PATH_MAX, &pathname);
    }

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(pid, "MODLOAD", &context);
    ec_event_send_modload(
        process_handle,
        CB_EVENT_TYPE_MODULE_LOAD,
        device,
        inode,
        MMAP_ADDRESS(),
        pathname,
        &context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, &context);
    ec_put_path_buffer(string_buffer);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    xcode = 0;  // original_ops are none of our business
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    xcode = g_original_ops_ptr->mmap_file(file, reqprot, prot, flags);
#else
    xcode = g_original_ops_ptr->file_mmap(file, reqprot, prot, flags, addr, addr_only);
#endif

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}
