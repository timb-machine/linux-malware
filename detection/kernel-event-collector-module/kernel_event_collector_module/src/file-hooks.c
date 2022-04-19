// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "process-tracking.h"
#include "file-process-tracking.h"
#include "cb-spinlock.h"
#include "path-buffers.h"
#include "cb-banning.h"
#include "event-factory.h"

#include <linux/file.h>
#include <linux/namei.h>

bool ec_file_exists(int dfd, const char __user *filename);

#define N_ELEM(x) (sizeof(x) / sizeof(*x))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define DENTRY(a)    (a)
#else
// checkpatch-ignore: COMPLEX_MACRO
#define DENTRY(a)    (a)->dentry, (a)->mnt
// checkpatch-no-ignore: COMPLEX_MACRO
#endif

typedef struct special_file_t_ {
    char *name;
    int   len;
    int   enabled;

} special_file_t;

// We collect data about a file in some of the syscall hooks.  We use this struct
//  so that we can collect data before modifying the file, but not actually use
//  it to send an event until the operation completes successfully
typedef struct file_data_t_ {
    struct filename *file_s;
    uint64_t         device;
    uint64_t         inode;
    const char      *name;
    char            *generic_path_buffer; // on the GENERIC cache
} file_data_t;

file_data_t *__ec_get_file_data_from_name(ProcessContext *context, const char __user *filename);  // forward
file_data_t *__ec_get_file_data_from_name_at(ProcessContext *context, int dfd, const char __user *filename);
file_data_t *__ec_get_file_data_from_fd(ProcessContext *context, const char __user *filename, unsigned int fd);
void __ec_put_file_data(ProcessContext *context, file_data_t *file_data);

#define ENABLE_SPECIAL_FILE_SETUP(x)   {x, sizeof(x)-1, 1}
#define DISABLE_SPECIAL_FILE_SETUP(x)  {x, sizeof(x)-1, 0}


//
// be sure to keep this value set to the smallest 'len' value in the
// special_files[] array below
//
#define MIN_SPECIAL_FILE_LEN 5
static const special_file_t special_files[] = {

    ENABLE_SPECIAL_FILE_SETUP("/var/log/messages"),
    ENABLE_SPECIAL_FILE_SETUP("/var/lib/cb"),
    ENABLE_SPECIAL_FILE_SETUP("/var/log"),
    ENABLE_SPECIAL_FILE_SETUP("/srv/bit9/data"),
    ENABLE_SPECIAL_FILE_SETUP("/sys"),
    ENABLE_SPECIAL_FILE_SETUP("/proc"),
    ENABLE_SPECIAL_FILE_SETUP("/var/opt/carbonblack"),
    DISABLE_SPECIAL_FILE_SETUP(""),
    DISABLE_SPECIAL_FILE_SETUP(""),
    DISABLE_SPECIAL_FILE_SETUP(""),
    DISABLE_SPECIAL_FILE_SETUP(""),
};

//
// FUNCTION:
//   ec_is_special_file()
//
// DESCRIPTION:
//   we'll skip any file that lives below any of the directories listed in
//   in the special_files[] array.
//
// PARAMS:
//   char *pathname - full path + filename to test
//   int len - length of the full path and filename
//
// RETURNS:
//   0 == no match
//
//
int ec_is_special_file(char *pathname, int len)
{
    int i;

    //
    // bail out if we've got no chance of a match
    //
    if (len < MIN_SPECIAL_FILE_LEN)
    {
        return 0;
    }

    for (i = 0; i < N_ELEM(special_files); i++)
    {
        //
        // Skip disabled elements
        //
        if (!special_files[i].enabled)
        {
            continue;
        }

        //
        // if the length of the path we're testing is shorter than this special
        // file, it can't possibly be a match
        //
        if (special_files[i].len > len)
        {
            continue;
        }

        //
        // still here, do the compare. We know that the path passed in is >=
        // this special_file[].len so we'll just compare up the length of the
        // special file itself. If we match up to that point, the path being
        // tested is or is below this special_file[].name
        //
        if (strncmp(pathname, special_files[i].name, special_files[i].len) == 0)
        {
            return -1;
        }
    }

    return 0;
}

bool ec_is_interesting_file(struct file *file)
{
    umode_t mode = ec_get_mode_from_file(file);

    return (S_ISREG(mode) && (!S_ISDIR(mode)) && (!S_ISLNK(mode)));
}

char *ec_event_type_to_str(CB_EVENT_TYPE event_type)
{
    char *str = "UNKNOWN";

    switch (event_type)
    {
    case CB_EVENT_TYPE_FILE_CREATE:
        str = "FILE-CREATE";
        break;
    case CB_EVENT_TYPE_FILE_DELETE:
        str = "FILE-DELETE";
        break;
    case CB_EVENT_TYPE_FILE_WRITE:
        str = "FILE-WRITE";
        break;
    case CB_EVENT_TYPE_FILE_CLOSE:
        str = "FILE-CLOSE";
        break;
    default:
        break;
    }

    return str;
}

//
// IMPORTANT: get_file_data_*/__ec_put_file_data MUST work regardless of whether the module is enabled
// or disabled. We call these functions from outside the active call hook tracking that prevents
// the module from disabling.
//

// Allocates a file_data_t and sets file_data->file_s to a kernelspace filename string
file_data_t *__ec_file_data_alloc(ProcessContext *context, const char __user *filename)
{
    file_data_t *file_data           = NULL;

    TRY(filename);

    file_data = ec_mem_cache_alloc_generic(sizeof(file_data_t), context);
    TRY(file_data);

    file_data->generic_path_buffer = NULL;
    file_data->name                = NULL;
    file_data->device = 0;
    file_data->inode = 0;

    file_data->file_s = CB_RESOLVED(getname)(filename);
    TRY(!IS_ERR_OR_NULL(file_data->file_s));

    // If the path begins with a / we know it is already absolute so we dont need to do a lookup.
    // Otherwise: prepare to do a lookup by allocating a buffer
    if (file_data->file_s->name[0] != '/')
    {
        // need to use the generic cache because the module could disable before we are able to free
        file_data->generic_path_buffer = ec_mem_cache_alloc_generic(PATH_MAX, context);
    }
    return file_data;

CATCH_DEFAULT:
    __ec_put_file_data(context, file_data);
    return NULL;
}

// Initializes file_data members from a file struct
void __ec_file_data_init(ProcessContext *context, file_data_t *file_data, struct file const *file)
{
    char *pathname            = NULL;

    if (file_data->generic_path_buffer)  // relative path; find absolute path
    {
        ec_file_get_path(file, file_data->generic_path_buffer, PATH_MAX, &pathname);
        file_data->name = pathname;
    } else
    {
        // if no path buffer that means we already have an absolute path because
        // it starts with a / or maybe the kmalloc failed. in either case just use the
        // file_s->name because it is either already absolute or if the buffer failed to
        // allocate, then we cant do the lookup anyways, so we just report the relative path
        // as a best effort.
        file_data->name = file_data->file_s->name;
    }

    ec_get_devinfo_from_file(file, &file_data->device, &file_data->inode);
}

void __ec_file_data_init_from_path(ProcessContext *context, file_data_t *file_data, struct path const *path); // forward

file_data_t *__ec_get_file_data_from_name_at(ProcessContext *context, int dfd, const char __user *filename)
{
    file_data_t *file_data = __ec_file_data_alloc(context, filename);

    TRY(file_data);
    {
        char *pathname = NULL;
        struct path path = {};
        int error = user_path_at(dfd, filename, LOOKUP_FOLLOW, &path);

        TRY(!error);
        __ec_file_data_init_from_path(context, file_data, &path);
        if (file_data->generic_path_buffer) { // filename not absolute
            // Get pathname as absolute path, ending at hi end of generic_path_buffer
            ec_path_get_path(&path, file_data->generic_path_buffer, PATH_MAX, &pathname);
        }
        path_put(&path);
        file_data->name = (pathname ? pathname : file_data->file_s->name);
    }
    return file_data;

CATCH_DEFAULT:
    __ec_put_file_data(context, file_data);  // de-allocate file_data
    return NULL;
}
file_data_t *__ec_get_file_data_from_name(ProcessContext *context, const char __user *filename)
{
    return __ec_get_file_data_from_name_at(context, AT_FDCWD, filename);
}

void __ec_file_data_init_from_path(ProcessContext *context, file_data_t *file_data, struct path const *path)
{
    char *pathname            = NULL;

    if (file_data->generic_path_buffer)  // is relative; need absolute
    {
        ec_path_get_path(path, file_data->generic_path_buffer, PATH_MAX, &pathname);
        file_data->name = pathname;
    } else
    {
        // if no path buffer that means we already have an absolute path because
        // it starts with a / or maybe the kmalloc failed. in either case just use the
        // file_s->name because it is either already absolute or if the buffer failed to
        // allocate, then we cant do the lookup anyways, so we just report the relative path
        // as a best effort.
        file_data->name = file_data->file_s->name;
    }

    ec_get_devinfo_from_path(path, &file_data->device, &file_data->inode);
}

file_data_t *__ec_get_file_data_from_fd(ProcessContext *context, const char __user *filename, unsigned int fd)
{
    struct file *file      = NULL;
    file_data_t *file_data = __ec_file_data_alloc(context, filename);

    TRY(file_data);

    file = fget(fd);
    TRY(!IS_ERR_OR_NULL(file));

    __ec_file_data_init(context, file_data, file);

    fput(file);

    return file_data;

CATCH_DEFAULT:
    __ec_put_file_data(context, file_data);
    return NULL;
}

//
// **NOTE: __ec_put_file_data is not protected by active call hook disable tracking.
//
void __ec_put_file_data(ProcessContext *context, file_data_t *file_data)
{
    CANCEL_VOID(file_data);

    if (!IS_ERR_OR_NULL(file_data->file_s))
    {
        CB_RESOLVED(putname)(file_data->file_s);
    }
    if (file_data->generic_path_buffer)
    {
        ec_mem_cache_free_generic(file_data->generic_path_buffer);
    }
    ec_mem_cache_free_generic(file_data);
}

void __ec_do_generic_file_event(ProcessContext *context,
                                file_data_t *file_data,
                                enum CB_INTENT_TYPE intent,
                                CB_EVENT_TYPE   eventType)
{
    pid_t pid = ec_getpid(current);
    ProcessHandle *process_handle = NULL;

    TRY(file_data);

    TRY(!ec_banning_IgnoreProcess(context, pid));

    TRY(ec_logger_should_log(intent, eventType));

    if (eventType == CB_EVENT_TYPE_FILE_DELETE && intent == INTENT_REPORT)
    {
        TRACE(DL_VERBOSE, "Checking if deleted inode [%llu:%llu] was banned.", file_data->device, file_data->inode);
        if (ec_banning_ClearBannedProcessInode(context, file_data->device, file_data->inode))
        {
            TRACE(DL_FILE, "[%llu:%llu] was removed from banned inode table.", file_data->device, file_data->inode);
        }
    }

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(pid, "Fileop", context);

    TRY(eventType != CB_EVENT_TYPE_FILE_OPEN ||
        (process_handle &&
         ec_process_exec_identity(process_handle)->is_interpreter));

    ec_event_send_file(
        process_handle,
        eventType,
        intent,
        file_data->device,
        file_data->inode,
        file_data->name,
        context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, context);
}

#define SANE_PATH(PATH) PATH ? PATH : "<unknown>"

void __ec_do_file_event(ProcessContext *context, struct file *file, CB_EVENT_TYPE eventType)
{
    FILE_PROCESS_VALUE *fileProcess    = NULL;
    pid_t               pid            = ec_getpid(current);
    bool                doClose        = false;

    CANCEL_VOID(file);
    CANCEL_VOID(!ec_banning_IgnoreProcess(context, pid));

    CANCEL_VOID(ec_logger_should_log(INTENT_REPORT, eventType));

    // Skip if not interesting
    CANCEL_VOID(ec_is_interesting_file(file));

    fileProcess = ec_file_process_get(file, context);

    if (fileProcess)
    {
        TRY_MSG(eventType != CB_EVENT_TYPE_FILE_WRITE,
                DL_FILE, "%s [%llu:%llu] process:%u written before", SANE_PATH(fileProcess->path), fileProcess->device, fileProcess->inode, pid);

        if (eventType == CB_EVENT_TYPE_FILE_CLOSE || eventType == CB_EVENT_TYPE_FILE_DELETE)
        {
            TRACE(DL_FILE, "%s [%llu:%llu] process:%u closed or deleted", SANE_PATH(fileProcess->path), fileProcess->device, fileProcess->inode, pid);
            // I still need to use the path buffer from fileProcess, so don't call
            //  ec_file_process_status_close until later.
            doClose = true;
        }
    } else //status == CLOSED
    {
        char *path          = NULL;
        char *string_buffer = NULL;

        TRY(eventType == CB_EVENT_TYPE_FILE_WRITE || eventType == CB_EVENT_TYPE_FILE_CREATE);

        // If this file is deleted already, then just skip it
        TRY(!d_unlinked(file->f_path.dentry));

        string_buffer = ec_get_path_buffer(context);
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
            ec_file_get_path(file, string_buffer, PATH_MAX, &path);
        }

        fileProcess = ec_file_process_status_open(
            file,
            pid,
            path,
            context);
        ec_put_path_buffer(string_buffer);

        if (fileProcess)
        {
            path = SANE_PATH(fileProcess->path);
            TRACE(DL_FILE, "%s [%llu:%llu:%p] process:%u first write", path, fileProcess->device, fileProcess->inode, file, pid);

            // If this file has been written to AND that files inode is in the banned list
            // we need to remove it on the assumption that the md5 will have changed. It is
            // entirely possible that the exact bits are written back, but in that case we
            // will catch it in user space, by md5, and notify kernel to kill and ban if necessary.
            //
            // This should be a fairly lightweight call as it is inlined and the hashtable is usually
            // empty and if not is VERY small.
            if (ec_banning_ClearBannedProcessInode(context, fileProcess->device, fileProcess->inode))
            {
                TRACE(DL_FILE, "%s [%llu:%llu] was removed from banned inode table.", path, fileProcess->device,
                      fileProcess->inode);
            }
        }
    }

    TRY(fileProcess);
    if (fileProcess->path)
    {
        // Check to see if the process is tracked already
        ProcessHandle *process_handle = ec_process_tracking_get_handle(pid, context);

        TRY(process_handle);

        if (fileProcess->path[0] == '/')
        {
            //
            // Log it
            //
            if (!fileProcess->isSpecialFile)
            {
                ec_event_send_file(
                    process_handle,
                    eventType,
                    INTENT_REPORT,
                    fileProcess->device,
                    fileProcess->inode,
                    fileProcess->path,
                    context);
            }
        } else if (fileProcess->path[0] == '[' && eventType == CB_EVENT_TYPE_FILE_WRITE)
        {
            // CEL This is a noop as we can see [eventfd] on a write and we don't care about it
        } else if (eventType == CB_EVENT_TYPE_FILE_CLOSE)
        {
            ec_event_send_file(
                process_handle,
                eventType,
                INTENT_REPORT,
                fileProcess->device,
                fileProcess->inode,
                fileProcess->path,
                context);
        } else
        {
            TRACE(DL_FILE, "invalid full path %s event %d", fileProcess->path, eventType);
        }
        ec_process_tracking_put_handle(process_handle, context);
    }

CATCH_DEFAULT:
    ec_file_process_put_ref(fileProcess, context);
    if (doClose)
    {
        ec_file_process_status_close(file, context);
    }

    return;
}

long (*ec_orig_sys_write)(unsigned int fd, const char __user *buf, size_t count);
long (*ec_orig_sys_close)(unsigned int fd);

long (*ec_orig_sys_open)(const char __user *filename, int flags, umode_t mode);
long (*ec_orig_sys_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
long (*ec_orig_sys_creat)(const char __user *filename, umode_t mode);
long (*ec_orig_sys_unlink)(const char __user *filename);
long (*ec_orig_sys_unlinkat)(int dfd, const char __user *pathname, int flag);
long (*ec_orig_sys_rename)(const char __user *oldname, const char __user *newname);
long (*ec_orig_sys_renameat)(int old_dfd, const char __user *oldname, int new_dfd, const char __user *newname);
long (*ec_orig_sys_renameat2)(int old_dfd, const char __user *oldname, int new_dfd, const char __user *newname, unsigned int flags);

asmlinkage void ec_lsm_file_free_security(struct file *file)
{
    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    __ec_do_file_event(&context, file, CB_EVENT_TYPE_FILE_CLOSE);

CATCH_DEFAULT:

    g_original_ops_ptr->file_free_security(file);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
}

asmlinkage long ec_sys_open(const char __user *filename, int flags, umode_t mode)
{
    long                fd;
    CB_EVENT_TYPE       eventType = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    if ((flags & O_CREAT) && !ec_file_exists(AT_FDCWD, filename))
    {
        // If this is opened with create mode AND it does not already exist we will report a create event
        eventType = CB_EVENT_TYPE_FILE_CREATE;
    } else if (flags & (O_RDWR | O_WRONLY))
    {
        eventType = CB_EVENT_TYPE_FILE_WRITE;
    } else if (!(flags & (O_RDWR | O_WRONLY)))
    {
        // If the file is opened with read-only mode we will report an open event
        eventType = CB_EVENT_TYPE_FILE_OPEN;
    }

CATCH_DISABLED:
    fd = ec_orig_sys_open(filename, flags, mode);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    if (!IS_ERR_VALUE(fd) && eventType)
    {
        struct file *file = fget(fd);

        TRY(!IS_ERR_OR_NULL(file));
        __ec_do_file_event(&context, file, eventType);
        fput(file);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return fd;
}

asmlinkage long ec_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    long                fd;
    CB_EVENT_TYPE       eventType = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    if ((flags & O_CREAT) && !ec_file_exists(dfd, filename))
    {
        // If this is opened with create mode AND it does not already exist we will report a create event
        eventType = CB_EVENT_TYPE_FILE_CREATE;
    } else if (flags & (O_RDWR | O_WRONLY))
    {
        eventType = CB_EVENT_TYPE_FILE_WRITE;
    } else if (!(flags & (O_RDWR | O_WRONLY)))
    {
        // If the file is opened with read-only mode we will report an open event
        eventType = CB_EVENT_TYPE_FILE_OPEN;
    }

CATCH_DISABLED:
    fd = ec_orig_sys_openat(dfd, filename, flags, mode);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    if (!IS_ERR_VALUE(fd) && eventType)
    {
        struct file *file = fget(fd);

        TRY(!IS_ERR_OR_NULL(file));
        __ec_do_file_event(&context, file, eventType);
        fput(file);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return fd;
}

asmlinkage long ec_sys_creat(const char __user *filename, umode_t mode)
{
    long fd;
    CB_EVENT_TYPE       eventType = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // If this is opened with create mode AND it does not already exist we
    //  will report an event
    if (!ec_file_exists(AT_FDCWD, filename))
    {
        eventType = CB_EVENT_TYPE_FILE_CREATE;
    } else
    {
        eventType = CB_EVENT_TYPE_FILE_WRITE;
    }

CATCH_DISABLED:
    fd = ec_orig_sys_creat(filename, mode);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    if (!IS_ERR_VALUE(fd) && eventType)
    {
        struct file *file = fget(fd);

        TRY(!IS_ERR_OR_NULL(file));
        __ec_do_file_event(&context, file, eventType);
        fput(file);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return fd;
}

asmlinkage long ec_sys_unlink(const char __user *filename)
{
    long         ret;
    file_data_t *file_data = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // __ec_get_file_data_from_name can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, to avoid blocking module disable
    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    //  after a successful operation
    file_data = __ec_get_file_data_from_name(&context, filename);
    if (file_data)
    {
        __ec_do_generic_file_event(&context, file_data, INTENT_PREACTION,
                                   CB_EVENT_TYPE_FILE_DELETE);
    }

CATCH_DISABLED:
    ret = ec_orig_sys_unlink(filename);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && file_data)
    {
        __ec_do_generic_file_event(&context, file_data, INTENT_REPORT, CB_EVENT_TYPE_FILE_DELETE);
    }

CATCH_DEFAULT:
    // Note: file_data is destroyed by __ec_do_generic_file_event
    __ec_put_file_data(&context, file_data);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_unlinkat(int dfd, const char __user *filename, int flag)
{
    long         ret;
    file_data_t *file_data = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // __ec_get_file_data_from_name can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, since that can block module disable
    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    //  after a successful operation
    file_data = __ec_get_file_data_from_name_at(&context, dfd, filename);
    if (file_data)
    {
        __ec_do_generic_file_event(&context, file_data, INTENT_PREACTION,
                                   CB_EVENT_TYPE_FILE_DELETE);
    }

CATCH_DISABLED:
    ret = ec_orig_sys_unlinkat(dfd, filename, flag);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && file_data)
    {
        __ec_do_generic_file_event(&context, file_data, INTENT_REPORT, CB_EVENT_TYPE_FILE_DELETE);
    }

CATCH_DEFAULT:
    // Note: file_data is destroyed by __ec_do_generic_file_event
    __ec_put_file_data(&context, file_data);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_renameat(int olddirfd, char __user const *oldname, int newdirfd, char __user const *newname)
{
    long         ret;
    file_data_t *old_file_data = NULL;
    file_data_t *new_file_data_pre_rename = NULL;
    file_data_t *new_file_data_post_rename = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // __ec_get_file_data_from_name can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, since that can block module disable
    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    //  after a successful operation
    old_file_data = __ec_get_file_data_from_name_at(&context, olddirfd, oldname);

    // Only lookup new path when old path was found
    if (old_file_data)
    {
        new_file_data_pre_rename = __ec_get_file_data_from_name_at(&context, newdirfd, newname);
    }
    // Old path must exist but still execute syscall

CATCH_DISABLED:
    ret = ec_orig_sys_renameat(olddirfd, oldname, newdirfd, newname);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && old_file_data)
    {
        __ec_do_generic_file_event(&context, old_file_data, INTENT_REPORT, CB_EVENT_TYPE_FILE_DELETE);

        // Send a delete for the destination if the renameat will overwrite an existing file
        if (new_file_data_pre_rename)
        {
            __ec_do_generic_file_event(&context, new_file_data_pre_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_DELETE);
        }

        FINISH_MODULE_DISABLE_CHECK(&context);

        // This could block so call it outside the disable tracking
        new_file_data_post_rename = __ec_get_file_data_from_name_at(&context, newdirfd, newname);

        BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

        __ec_do_generic_file_event(&context, new_file_data_post_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_CREATE);
        __ec_do_generic_file_event(&context, new_file_data_post_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_CLOSE);
    }

CATCH_DEFAULT:
    __ec_put_file_data(&context, old_file_data);
    __ec_put_file_data(&context, new_file_data_pre_rename);
    __ec_put_file_data(&context, new_file_data_post_rename);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_renameat2(int olddirfd, char __user const *oldname, int newdirfd, char __user const *newname, unsigned int flags)
{
    long         ret;
    file_data_t *old_file_data = NULL;
    file_data_t *new_file_data_pre_rename = NULL;
    file_data_t *new_file_data_post_rename = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // __ec_get_file_data_from_name can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, since that can block module disable
    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    //  after a successful operation
    old_file_data = __ec_get_file_data_from_name_at(&context, olddirfd, oldname);

    // Only lookup new path when old path was found
    if (old_file_data)
    {
        new_file_data_pre_rename = __ec_get_file_data_from_name_at(&context, newdirfd, newname);
    }
    // Old path must exist but still execute syscall

CATCH_DISABLED:
    ret = ec_orig_sys_renameat2(olddirfd, oldname, newdirfd, newname, flags);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && old_file_data)
    {
        __ec_do_generic_file_event(&context, old_file_data, INTENT_REPORT, CB_EVENT_TYPE_FILE_DELETE);

        // Send a delete for the destination if the renameat will overwrite an existing file
        if (new_file_data_pre_rename)
        {
            __ec_do_generic_file_event(&context, new_file_data_pre_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_DELETE);
        }

        FINISH_MODULE_DISABLE_CHECK(&context);

        // This could block so call it outside the disable tracking
        new_file_data_post_rename = __ec_get_file_data_from_name_at(&context, newdirfd, newname);

        BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

        __ec_do_generic_file_event(&context, new_file_data_post_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_CREATE);
        __ec_do_generic_file_event(&context, new_file_data_post_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_CLOSE);
    }

CATCH_DEFAULT:
    __ec_put_file_data(&context, old_file_data);
    __ec_put_file_data(&context, new_file_data_pre_rename);
    __ec_put_file_data(&context, new_file_data_post_rename);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_rename(const char __user *oldname, const char __user *newname)
{
    long         ret;
    file_data_t *old_file_data = NULL;
    file_data_t *new_file_data_pre_rename = NULL;
    file_data_t *new_file_data_post_rename = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    // __ec_get_file_data_from_name can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, since that can block module disable
    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    //  after a successful operation
    old_file_data = __ec_get_file_data_from_name(&context, oldname);

    // Only lookup new path when old path was found
    if (old_file_data)
    {
        new_file_data_pre_rename = __ec_get_file_data_from_name(&context, newname);
    }
    // Old path must exist but still execute syscall

CATCH_DISABLED:
    ret = ec_orig_sys_rename(oldname, newname);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && old_file_data)
    {
        __ec_do_generic_file_event(&context, old_file_data, INTENT_REPORT, CB_EVENT_TYPE_FILE_DELETE);

        // Send a delete for the destination if the rename will overwrite an existing file
        if (new_file_data_pre_rename)
        {
            __ec_do_generic_file_event(&context, new_file_data_pre_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_DELETE);
        }

        FINISH_MODULE_DISABLE_CHECK(&context);

        // This could block so call it outside the disable tracking
        new_file_data_post_rename = __ec_get_file_data_from_name(&context, newname);

        BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

        __ec_do_generic_file_event(&context, new_file_data_post_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_CREATE);
        __ec_do_generic_file_event(&context, new_file_data_post_rename, INTENT_REPORT, CB_EVENT_TYPE_FILE_CLOSE);
    }

CATCH_DEFAULT:
    __ec_put_file_data(&context, old_file_data);
    __ec_put_file_data(&context, new_file_data_pre_rename);
    __ec_put_file_data(&context, new_file_data_post_rename);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

bool ec_file_exists(int dfd, const char __user *filename)
{
    bool         exists     = false;
    struct path path;

    TRY(filename);

    exists = user_path_at(dfd, filename, LOOKUP_FOLLOW, &path) == 0;

CATCH_DEFAULT:
    if (exists)
    {
        path_put(&path);
    }

    return exists;
}
