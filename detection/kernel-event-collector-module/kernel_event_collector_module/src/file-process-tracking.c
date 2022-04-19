// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "file-process-tracking.h"
#include "process-tracking.h"
#include "process-tracking-private.h"
#include "hash-table-generic.h"
#include "priv.h"

void __ec_file_tracking_delete_callback(void *posix_identity, ProcessContext *context);
int __ec_file_tracking_show(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context);

static HashTbl      *s_file_hash_table;

bool ec_file_tracking_init(ProcessContext *context)
{
    s_file_hash_table = ec_hashtbl_init_generic(
        context,
        8192,
        sizeof(FILE_PROCESS_VALUE),
        0,
        "file_tracking_table",
        sizeof(FILE_PROCESS_KEY),
        offsetof(FILE_PROCESS_VALUE, key),
        offsetof(FILE_PROCESS_VALUE, node),
        offsetof(FILE_PROCESS_VALUE, reference_count),
        __ec_file_tracking_delete_callback,
        NULL);

    return s_file_hash_table != NULL;
}

void ec_file_tracking_shutdown(ProcessContext *context)
{
    ec_hashtbl_shutdown_generic(s_file_hash_table, context);
}

void __ec_file_tracking_delete_callback(void *data, ProcessContext *context)
{
    if (data)
    {
        FILE_PROCESS_VALUE *value = (FILE_PROCESS_VALUE *)data;

        ec_mem_cache_put_generic(value->path);
        value->path = NULL;
    }
}


FILE_PROCESS_VALUE *ec_file_process_status_open(
    struct file    *file,
    uint32_t        pid,
    char           *path,
    ProcessContext *context)
{
    FILE_PROCESS_VALUE *value = ec_file_process_get(file, context);

    if (!value)
    {
        value = ec_hashtbl_alloc_generic(s_file_hash_table, context);
        TRY(value);

        // Initialize the reference count
        atomic64_set(&value->reference_count, 1);

        value->key.file      = (uint64_t)file;
        value->pid           = pid;
        value->path          = ec_mem_cache_strdup(path, context);
        value->isSpecialFile = ec_is_special_file(value->path, ec_mem_cache_get_size_generic(value->path));

        ec_get_devinfo_from_file(file, &value->device, &value->inode);

        if (ec_hashtbl_add_generic(s_file_hash_table, value, context) < 0)
        {
            if (MAY_TRACE_LEVEL(DL_FILE))
            {
                // We are racing against other threads or processes
                // to insert a similar entry on the same rb_tree.
                TRACE(DL_FILE, "File entry already exists: [%llu:%llu] %s pid:%u",
                      value->device, value->inode, path ? path : "<unknown>", pid);
            }

            // If the insert failed we free the local reference and clear
            //  value
            ec_hashtbl_free_generic(s_file_hash_table, value, context);
            value = NULL;
        }
    }

CATCH_DEFAULT:
    // Return holding a reference
    return value;
}

FILE_PROCESS_VALUE *ec_file_process_get(
    struct file    *file,
    ProcessContext *context)
{
    FILE_PROCESS_KEY key = { (uint64_t)file };

    return ec_hashtbl_get_generic(s_file_hash_table, &key, context);
}

void ec_file_process_status_close(
    struct file    *file,
    ProcessContext *context)
{
    FILE_PROCESS_KEY key = {(uint64_t)file};
    FILE_PROCESS_VALUE *value = NULL;

    value = ec_hashtbl_del_by_key_generic(s_file_hash_table, &key, context);

    // We still need to release it
    ec_hashtbl_put_generic(s_file_hash_table, value, context);
}

void ec_file_process_put_ref(FILE_PROCESS_VALUE *value, ProcessContext *context)
{
    ec_hashtbl_put_generic(s_file_hash_table, value, context);
}

int ec_file_track_show_table(struct seq_file *m, void *v)
{

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    seq_printf(m, "%50s | %10s | %10s | %6s | %10s | %10s |\n",
                   "Path", "Device", "Inode", "PID", "Is Special", "File Pointer");

    ec_hashtbl_read_for_each_generic(
        s_file_hash_table,
        __ec_file_tracking_show,
        m,
        &context);

    return 0;
}

int __ec_file_tracking_show(HashTbl *hashTblp, HashTableNode *data, void *m, ProcessContext *context)
{
    if (data && m)
    {
        FILE_PROCESS_VALUE *value = (FILE_PROCESS_VALUE *)data;

        seq_printf(m, "%50s | %10llu | %10llu | %6d | %10s | %10llx |\n",
                      value->path,
                      value->device,
                      value->inode,
                      value->pid,
                      (value->isSpecialFile ? "YES" : "NO"),
                      value->key.file);
    }

    return ACTION_CONTINUE;
}
