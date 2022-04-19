/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/version.h>
#include <linux/time.h>
#include <linux/binfmts.h>

#include "process-context.h"

// ------------------------------------------------
//
// Task helpers
//
extern bool ec_task_initialize(ProcessContext *context);
extern void ec_task_shutdown(ProcessContext *context);

extern pid_t ec_getcurrentpid(void);
extern pid_t ec_getpid(struct task_struct const *task);
extern pid_t ec_gettid(struct task_struct const *task);
extern pid_t ec_getppid(struct task_struct const *task);
extern void ec_get_task_struct(struct task_struct *task);
extern void ec_put_task_struct(struct task_struct *task);
extern void ec_get_starttime(struct timespec *start_time);
extern uint64_t ec_get_path_buffer_memory_usage(void);
bool ec_task_get_path(struct task_struct const *task, char *buffer, unsigned int buflen, char **pathname);
extern bool ec_is_task_valid(struct task_struct const *task);
extern bool ec_is_task_alive(struct task_struct const *task);
struct task_struct const *ec_find_task(pid_t pid);
void ec_get_devinfo_from_task(struct task_struct const *task, uint64_t *device, uint64_t *ino);
struct inode const *ec_get_inode_from_task(struct task_struct const *task);
bool ec_get_cmdline_from_binprm(struct linux_binprm const *bprm, char *cmdLine, size_t cmdLineSize);
void ec_enumerate_and_track_all_tasks(ProcessContext *context);

#define IS_CURRENT_TASK(a)   (strcmp(current->comm, (a)) == 0)
