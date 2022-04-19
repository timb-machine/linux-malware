// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "cb-banning.h"
#include <linux/magic.h>

bool ec_file_helper_init(ProcessContext *context)
{
    return true;
}

bool ec_path_get_path(struct path const *path, char *buffer, unsigned int buflen, char **pathname)
{
    bool         xcode = true;

    CANCEL(pathname, false);
    CANCEL(buffer, false);
    CANCEL(path && path->mnt && path->dentry, false);
    (*pathname) = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)  //{
    path_get(path);
#else  //}{ v2.6.32 forgot 'const'
    path_get((struct path *)path);
#endif  //}

    // Problem here is that dentry_path, which solves pathing issues in chroot/namespace cases is not adequate
    // for the normal use case that d_path satisfies. These two function differ in the way in which they determine
    // the root dentry (d_path by get_fs_root and dentry_path by explicitly walking the dentry table). In the
    // dentry_path case, we consistently miss the root node. So each solution is the right solution for that
    // specific case, we just need to know when to use each.


    // If we failed to resolve the symbol, i.e. we're on a 2.6.32 kernel or it just doesn't resolve,
    // default to the d_path option
    if (current->nsproxy && CB_CHECK_RESOLVED(current_chrooted) && CB_RESOLVED(current_chrooted)())
    {
        (*pathname) = ec_dentry_to_path(path->dentry, buffer, buflen);
    } else
    {
        (*pathname) = d_path(path, buffer, buflen);
    }

    if (IS_ERR_OR_NULL((*pathname)))
    {
        (*pathname) = buffer;
        xcode   = false;

        buffer[0] = 0;
        strncat(buffer, path->dentry->d_name.name, buflen-1);

        TRACE(DL_WARNING, "Path lookup failed, using |%s| as file name", buffer);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)  //{
    path_put(path);
#else  //}{ v2.6.32 forgot 'const'
    path_put((struct path *)path);
#endif  //}

    return xcode;
}

bool ec_file_get_path(struct file const *file, char *buffer, unsigned int buflen, char **pathname)
{
    CANCEL(file, false);
    return ec_path_get_path(&file->f_path, buffer, buflen, pathname);
}

char *ec_dentry_to_path(struct dentry const *dentry, char *buf, int buflen)
{
    CANCEL_CB_RESOLVED(dentry_path, NULL);
    return CB_RESOLVED(dentry_path)((struct dentry *)dentry, buf, buflen);
}

bool ec_dentry_get_path(struct dentry const *dentry, char *buffer, unsigned int buflen, char **pathname)
{
    bool xcode = true;

    CANCEL(dentry, false);
    CANCEL(buffer, false);
    CANCEL(pathname, false);

    (*pathname) = ec_dentry_to_path(dentry, buffer, buflen);

    if (IS_ERR_OR_NULL((*pathname)))
    {
        (*pathname) = buffer;
        xcode   = false;

        buffer[0] = 0;
        strncat(buffer, dentry->d_name.name, buflen-1);

        TRACE(DL_WARNING, "Path lookup failed, using |%s| as file name", buffer);
    }

    return xcode;
}

struct inode const *ec_get_inode_from_dentry(struct dentry const *dentry)
{
    // Skip if dentry is null
    if (!dentry) return NULL;
    if (!dentry->d_inode) return NULL;

    // dig out inode
    return dentry->d_inode;
}

struct inode const *ec_get_inode_from_file(struct file const *file)
{
    if (!file) return NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)  //{
    // The cached inode may be NULL, but the calling code will handle that
    return file->f_inode;
#else  //}{
    return ec_get_inode_from_dentry(file->f_path.dentry);
#endif  //}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    #define VFS_GETATTR(PATH, KS)   vfs_getattr_nosec((PATH), (KS), STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT)
#else
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        #define _VFS_GETATTR(PATH, KS)   vfs_getattr((PATH), (KS))
    #else
        #define _VFS_GETATTR(PATH, KS)   vfs_getattr((PATH)->mnt, (PATH)->dentry, (KS))

        // This "simulates" the behavior of vfs_getattr_nosec found in later kernels
        //  by adding S_PRIVATE to the inode flags.  With this flag set, the kernel
        //  will not call check the security on getattr.
        // The nosec version is needed because SELinux was rejecting our access to some files.
        //  (You would see messages like this in the log.)
        //  SELinux is preventing /usr/bin/dbus-daemon from getattr access on the fifo_file /run/systemd/sessions/1.ref.
        int ec_getattr(struct path const *path, struct kstat *stat)
        {
            int ret = 0;
            bool should_remove_private = false;

            if (!IS_PRIVATE(path->dentry->d_inode))
            {
                should_remove_private = true;
                path->dentry->d_inode->i_flags = path->dentry->d_inode->i_flags | S_PRIVATE;
            }

            ret = _VFS_GETATTR(path, stat);

            if (should_remove_private)
            {
                path->dentry->d_inode->i_flags = path->dentry->d_inode->i_flags & ~S_PRIVATE;
            }
            return ret;
        }
        #define VFS_GETATTR(PATH, KS)   ec_getattr((PATH), (KS))
    #endif
#endif

struct super_block const *ec_get_sb_from_dentry(struct dentry const *dentry);  // forward

void ec_get_devinfo_from_path(struct path const *path, uint64_t *device, uint64_t *inode)
{
    *device = new_encode_dev(ec_get_sb_from_dentry(path->dentry)->s_dev);
    *inode  =                path->dentry->d_inode->i_ino;
}

void ec_get_devinfo_from_file(struct file const *file, uint64_t *device, uint64_t *inode)
{
    struct super_block const *sb = NULL;

    CANCEL_VOID(file && device && inode);

    *device = 0;
    *inode  = 0;

    if (file->f_inode)
    {
        *inode = file->f_inode->i_ino;
    }

    sb = ec_get_sb_from_file(file);
    if (sb)
    {
        *device = new_encode_dev(sb->s_dev);
    }
}

umode_t ec_get_mode_from_file(struct file const *file)
{
    umode_t mode = 0;

    if (file)
    {
        struct inode const *inode = ec_get_inode_from_file(file);

        if (inode)
        {
            mode = inode->i_mode;
        }
    }

    return mode;
}

struct super_block const *ec_get_sb_from_dentry(struct dentry const *dentry)
{
    struct super_block const *sb = NULL;

    if (dentry)
    {
        // Get super_block from inode first
        struct inode const *inode = ec_get_inode_from_dentry(dentry);

        if (inode)
        {
            sb = inode->i_sb;
        }

        // Get super_block from dentry last.
        if (!sb)
        {
            sb = dentry->d_sb;
        }
    }
    return sb;
}

struct super_block const *ec_get_sb_from_file(struct file const *file)
{
    struct super_block const *sb = NULL;

    if (file)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        struct inode const *inode = ec_get_inode_from_file(file);

        if (inode)
        {
            sb = inode->i_sb;
        }
#endif
        if (!sb)
        {
            sb = ec_get_sb_from_dentry(file->f_path.dentry);
        }
    }
    return sb;
}

bool ec_is_network_filesystem(struct super_block const *sb)
{
    if (!sb)
    {
        return false;
    }

    // Check magic numbers
    switch (sb->s_magic)
    {
    case NFS_SUPER_MAGIC:
        return true;

    case SMB_SUPER_MAGIC:
        return true;

    default:
        return false;
    }

    return false;
}

bool ec_may_skip_unsafe_vfs_calls(struct file const *file)
{
    struct super_block const *sb = ec_get_sb_from_file(file);

    // Since we still don't know the file system type
    // it's safer to not perform any VFS ops on the file.
    if (!sb)
    {
        return true;
    }

    // We may want to check if a file's inode lock is held
    // before trying to do a vfs operation.

    // Eventually expand to stacked file systems
    return ec_is_network_filesystem(sb);
}
