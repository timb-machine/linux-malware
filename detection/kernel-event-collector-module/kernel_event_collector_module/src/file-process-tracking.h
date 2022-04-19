/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/types.h>
#include "priv.h"
#include "hash-table-generic.h"

typedef struct FILE_PROCESS_KEY {
    uint64_t            file;
} FILE_PROCESS_KEY;

typedef struct FILE_PROCESS_VALUE {
    HashTableNode       node;
    FILE_PROCESS_KEY    key;
    uint32_t            pid;
    uint64_t            device;
    uint64_t            inode;
    bool                isSpecialFile;
    char               *path;
    atomic64_t          reference_count;
} FILE_PROCESS_VALUE;

void ec_file_process_put_ref(FILE_PROCESS_VALUE *value, ProcessContext *context);

bool ec_file_tracking_init(ProcessContext *context);
void ec_file_tracking_shutdown(ProcessContext *context);
FILE_PROCESS_VALUE *ec_file_process_get(
    struct file    *file,
    ProcessContext *context);
FILE_PROCESS_VALUE *ec_file_process_status_open(
    struct file    *file,
    uint32_t        pid,
    char           *path,
    ProcessContext *context);
void ec_file_process_status_close(
    struct file    *file,
    ProcessContext *context);
