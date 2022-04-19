/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#define  DL_INIT           0x00000001
#define  DL_SHUTDOWN       0x00000002
#define  DL_WARNING        0x00000004
#define  DL_ERROR          0x00000008
#define  DL_INFO           0x00000010
#define  DL_REQUEST        0x00000100
#define  DL_NET            0x00000200
#define  DL_NET_TRACKING   0x00000400
#define  DL_FILE           0x00000800
#define  DL_MODLOAD        0x00001000
#define  DL_HOOK           0x00200000
#define  DL_PROCESS        0x00400000
#define  DL_PROC_TRACKING  0x00800000
#define  DL_VERBOSE        0x08000000
#define  DL_ENTRY          0x10000000
#define  DL_EXIT           0x20000000
#define  DL_COMMS          0x40000000
#define  DL_TRACE          0x08000000

// Check to see if we are compiled in the kernel
#ifndef __cplusplus
#include "version.h"
extern uint32_t g_traceLevel;

#define MAY_TRACE_LEVEL(level) ((g_traceLevel & (level)))
#define TRACE(level, fmt, ...)    do { if (MAY_TRACE_LEVEL(level)) pr_info(CB_APP_MODULE_NAME ": " fmt "\n", ##__VA_ARGS__); } while (0)
#endif // LINUX_VERSION_CODE
