// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "linux/cred.h"

inline bool is_root_uid(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
#include "linux/uidgid.h"
    // current_uid() returns struct in newer kernels
    return uid_eq(current_uid(), GLOBAL_ROOT_UID);
#else
    return 0 == current_uid();
#endif
}

long (*ec_orig_sys_delete_module)(const char __user *name_user,
                                  unsigned int flags) = NULL;

asmlinkage long ec_sys_delete_module(const char __user *name_user,
                                     unsigned int flags)
{
    const size_t slen = strlen(DRIVER_NAME);
    char name_kernel[slen];
    int rval;

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    /* strncpy_from_user() does an access_ok check to see if this is user memory. If it
     * is not user memory, it returns -EFAULT. In that case we'll assume that it is
     * already kernel memory.
     */
    rval = strncpy_from_user(name_kernel, name_user, slen);
    if (rval < 0) {
        if (-EFAULT == rval) {
            // Already kernel memory, so copy the string over.
            (void)strncpy(name_kernel, name_user, slen);
        } else {
            // Something else went wrong
            return rval;
        }
    }

    // If the unload request is not for our module, pass it through.
    if (strncmp(name_kernel, DRIVER_NAME, slen))
        return ec_orig_sys_delete_module(name_user, flags);

    // Don't let non-root users call
    CANCEL(is_root_uid(), -EPERM);

    /* If the syscall or lsm function hooks have changed since we set them,
     * then another module has probably loaded and may be calling our hooks.
     * In that case, if we unload, the system could crash when they try to
     * call our (non-existant) hooks. For that reason, we say we are busy
     * and refuse to unload. We also remove our device node in case Cb
     * Response with an incompatible version of the daemon.
     * TODO: Add a version compatability check between the daemon and the
     * module to handle this situation more gracefully.
     */
    ec_user_devnode_close(&context);

    // Remove hooks
    ec_shutdown(&context);

    // Hooks may not yet be unloaded so return EBUSY.
    return -EBUSY;
}
