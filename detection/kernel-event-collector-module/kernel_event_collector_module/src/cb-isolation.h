/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

typedef uint32_t DWORD;
typedef uint32_t ULONG;
typedef uint64_t ULONGLONG;
typedef unsigned char *PBYTE;
typedef uint16_t USHORT;
typedef int NTSTATUS;
typedef enum { FALSE = 0, TRUE = 1} BOOLEAN;
typedef void VOID;
typedef VOID * PVOID;
typedef ULONG * ULONG_PTR;
typedef uint32_t UINT32;
typedef uint16_t UINT16;


#define IOCTL_RESPONSE            0
#define IOCTL_ENABLE_INTERCEPTS   1
#define IOCTL_DISABLE_INTERCEPTS  2
#define IOCTL_GET_VERSION         3
#define IOCTL_GET_KERNEL_STATS    4
#define IOCTL_SET_ISOLATION_MODE 10


#define IP_PROTO_UDP 17

#ifndef htonl
#define htonl(x) (((((ULONG)(x))&0xffL)<<24) | \
    ((((ULONG)(x))&0xff00L)<<8) | \
    ((((ULONG)(x))&0xff0000L)>>8) | \
    ((((ULONG)(x))&0xff000000L)>>24))
#endif

#ifndef htons
#define htons(x) (((((USHORT)(x))&0x00ff)<<8) | \
    ((((USHORT)(x))&0xff00)>>8))
#endif

#define DHCP_CLIENT_PORT_V6 (htons((USHORT) 546))
#define DHCP_SERVER_PORT_V6 (htons((USHORT) 547))

#define DHCP_CLIENT_PORT_V4 (htons((USHORT) 67))
#define DHCP_SERVER_PORT_V4 (htons((USHORT) 68))
#define DNS_SERVER_PORT  (htons((USHORT) 53))  // DNS over IPV4 or IPV6 will use port 53


#define STATUS_SUCCESS                0
#define STATUS_INVALID_PARAMETER_4    1
#define STATUS_INSUFFICIENT_RESOURCES 2

typedef enum _CB_ISOLATION_ACTION {
    IsolationActionDisabled     = 0,
    IsolationActionAllow        = 1,
    IsolationActionBlock        = 2
} CB_ISOLATION_ACTION, *PCB_ISOLATION_ACTION;

typedef struct _CB_ISOLATION_INTERCEPT_RESULT {
    CB_ISOLATION_ACTION     isolationAction;

} CB_ISOLATION_INTERCEPT_RESULT, *PCB_ISOLATION_INTERCEPT_RESULT;

#define CB_ISOLATION_MODE_CONTROL_SIZE(x)   (ULONG)(sizeof(CB_ISOLATION_MODE_CONTROL) + ((sizeof(ULONG) * x) - 1))

typedef struct _CB_ISOLATION_STATS {
    BOOLEAN     isolationEnabled;
    ULONGLONG   isolationBlockedInboundIp4Packets;
    ULONGLONG   isolationBlockedInboundIp6Packets;
    ULONGLONG   isolationBlockedOutboundIp4Packets;
    ULONGLONG   isolationBlockedOutboundIp6Packets;
    ULONGLONG   isolationAllowedInboundIp4Packets;
    ULONGLONG   isolationAllowedInboundIp6Packets;
    ULONGLONG   isolationAllowedOutboundIp4Packets;
    ULONGLONG   isolationAllowedOutboundIp6Packets;
} CB_ISOLATION_STATS, *PCB_ISOLATION_STATS;

NTSTATUS ec_InitializeNetworkIsolation(ProcessContext *context);

VOID ec_DestroyNetworkIsolation(ProcessContext *context);

VOID ec_SetNetworkIsolationMode(CB_ISOLATION_MODE isolationMode);

VOID ec_DisableNetworkIsolation(ProcessContext *context);

CB_ISOLATION_MODE ec_GetCurrentIsolationMode(ProcessContext *context);

VOID ec_IsolationIntercept(ProcessContext *context,
                          ULONG  remoteIpAddress,
                          CB_ISOLATION_INTERCEPT_RESULT *isolationResult);


NTSTATUS ec_ProcessIsolationIoctl(
    ProcessContext *context,
    ULONG           IoControlCode,
    PVOID           pBuf,
    DWORD           InputBufLen);

//	DWORD       OutputBufLen,
//ULONG_PTR*  bytesXfered);

VOID ec_IsolationInterceptByAddrProtoPort(
    ProcessContext *context,
    ULONG                                   remoteIpAddress,
    bool                                    isIpV4,
    UINT32                                  protocol,
    UINT16                                  port,
    CB_ISOLATION_INTERCEPT_RESULT *isolationResult);

extern CB_ISOLATION_STATS g_cbIsolationStats;
