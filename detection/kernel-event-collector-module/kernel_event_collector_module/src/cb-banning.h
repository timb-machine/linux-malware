/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

extern bool ec_banning_initialize(ProcessContext *context);
extern void ec_banning_shutdown(ProcessContext *context);
extern void ec_banning_SetProtectionState(ProcessContext *context, uint32_t new_mode);
extern bool ec_banning_SetBannedProcessInode(ProcessContext *context, uint64_t device, uint64_t ino);
extern bool ec_banning_SetBannedProcessInodeWithoutKillingProcs(ProcessContext *context, uint64_t device, uint64_t ino);
extern inline bool ec_banning_ClearBannedProcessInode(ProcessContext *context, uint64_t device, uint64_t ino);
extern bool ec_banning_KillBannedProcessByInode(ProcessContext *context, uint64_t device, uint64_t ino);
extern bool ec_banning_IgnoreProcess(ProcessContext *context, pid_t pid);
extern void ec_banning_SetIgnoredProcess(ProcessContext *context, pid_t pid);
extern bool ec_banning_IgnoreUid(ProcessContext *context, pid_t uid);
extern void ec_banning_SetIgnoredUid(ProcessContext *context, uid_t uid);
extern void ec_banning_ClearAllBans(ProcessContext *context);
extern bool ec_banning_KillBannedProcessByPid(ProcessContext *context, pid_t pid);
