/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "process-tracking.h"

typedef struct posix_identity_data {
    uint64_t      op_cnt;
    uint64_t      create;
    uint64_t      exit;
    uint64_t      create_by_fork;
    uint64_t      create_by_exec;

    HashTbl      *table;
    CB_MEM_CACHE  exec_identity_cache;
} process_tracking_data;

extern process_tracking_data g_process_tracking_data;

void ec_process_tracking_update_op_cnts(PosixIdentity *posix_identity, CB_EVENT_TYPE event_type, int action);
void ec_sorted_tracking_table_for_each(for_rbtree_node callback, void *priv, ProcessContext *context);
ProcessHandle *ec_sorted_tracking_table_get_handle(void *data, ProcessContext *context);
const char *ec_process_tracking_get_proc_name(const char *path);

ExecHandle *ec_process_tracking_get_temp_exec_handle(ProcessHandle *process_handle, ProcessContext *context);
void ec_process_posix_identity_set_exec_identity(PosixIdentity *posix_identity, ExecIdentity *exec_identity, ProcessContext *context);
void ec_process_tracking_set_temp_exec_handle(ProcessHandle *process_handle, ExecHandle *exec_handle, ProcessContext *context);
void ec_process_tracking_set_exec_identity(ProcessHandle *process_handle, ExecIdentity *exec_identity, ProcessContext *context);
ProcessHandle *ec_process_handle_alloc(PosixIdentity *posix_identity, ProcessContext *context);
void ec_process_exec_handle_set_exec_identity(ExecHandle *exec_handle, ExecIdentity *exec_identity, ProcessContext *context);
void ec_process_tracking_put_path(char *path, ProcessContext *context);

#ifdef _REF_DEBUGGING
    #define TRACE_IF_REF_DEBUGGING(...)  TRACE(__VA_ARGS__)
#else
    #define TRACE_IF_REF_DEBUGGING(...)
#endif
