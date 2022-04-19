// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/hash.h>
#include <linux/list.h>
#include <linux/inet.h>
#include "priv.h"
#include "mem-cache.h"
#include "cb-spinlock.h"

#include "cb-isolation.h"

CB_ISOLATION_STATS  g_cbIsolationStats;

static CB_ISOLATION_MODE             CBIsolationMode = IsolationModeOff;
static PCB_ISOLATION_MODE_CONTROL   _pCurrentCbIsolationModeControl;
uint64_t                            _pControlLock;
static BOOLEAN                      _isInitialized = FALSE;

BOOLEAN ACQUIRE_RESOURCE(ProcessContext *context)
{
    if (_isInitialized == FALSE)
    {
        return FALSE;
    }

    ec_write_lock(&_pControlLock, context);
    return TRUE;
}

VOID RELEASE_RESOURCE(ProcessContext *context)
{
    ec_write_unlock(&_pControlLock, context);
}

NTSTATUS ec_InitializeNetworkIsolation(ProcessContext *context)
{
    ec_spinlock_init(&_pControlLock, context);
    atomic_set((atomic_t *)&CBIsolationMode, IsolationModeOff);
    atomic_set((atomic_t *)&_isInitialized, TRUE);
    return STATUS_SUCCESS;
}

VOID ec_DestroyNetworkIsolation(ProcessContext *context)
{
    atomic_set((atomic_t *)&_isInitialized, FALSE);
    atomic_set((atomic_t *)&CBIsolationMode, IsolationModeOff);

    if (ACQUIRE_RESOURCE(context))
    {
        if (_pCurrentCbIsolationModeControl)
        {
            ec_mem_cache_free_generic(_pCurrentCbIsolationModeControl);
            _pCurrentCbIsolationModeControl = NULL;
        }

        RELEASE_RESOURCE(context);
    }

    ec_spinlock_destroy(&_pControlLock, context);
}

VOID ec_SetNetworkIsolationMode(CB_ISOLATION_MODE isolationMode)
{
    atomic_set((atomic_t *)&CBIsolationMode, isolationMode);
    g_cbIsolationStats.isolationEnabled = isolationMode == IsolationModeOn;
    TRACE(DL_INFO, "CB ISOLATION MODE: %s", isolationMode == IsolationModeOff ? "DISABLED" : "ENABLED");
}

VOID ec_DisableNetworkIsolation(ProcessContext *context)
{
    atomic_set((atomic_t *)&CBIsolationMode, IsolationModeOff);
    g_cbIsolationStats.isolationEnabled = FALSE;
    TRACE(DL_INFO, "CB ISOLATION MODE: DISABLED");
}

NTSTATUS ec_ProcessIsolationIoctl(
    ProcessContext *context,
    ULONG IoControlCode,
    PVOID pBuf,
    DWORD InputBufLen)
{
    NTSTATUS                   xcode                   = STATUS_SUCCESS;
    PCB_ISOLATION_MODE_CONTROL tmpIsolationModeControl = NULL;
    DWORD                      ExpectedBufLen;

    TRY_SET_MSG(IoControlCode == IOCTL_SET_ISOLATION_MODE, STATUS_INVALID_PARAMETER_4,
                 DL_WARNING, "CB_ISOLATION_MODE_CONTROL size is invalid");

    tmpIsolationModeControl = (PCB_ISOLATION_MODE_CONTROL)ec_mem_cache_alloc_generic(InputBufLen, context);

    TRY_SET_MSG(tmpIsolationModeControl, STATUS_INSUFFICIENT_RESOURCES,
                 DL_ERROR, "%s: failed to allocate memory for network isolation control\n", __func__);

    TRY_STEP_SET_MSG(RESOURCE, !copy_from_user(tmpIsolationModeControl, pBuf, InputBufLen),
                      STATUS_INSUFFICIENT_RESOURCES,
                      DL_ERROR, "%s: failed to copy arg\n", __func__);

    // Calculate the size of the buffer we should have hold the number of addresses that user space claims is
    //  present.  This prevents us from reading past the buffer later. (CB-8236)
    ExpectedBufLen = sizeof(CB_ISOLATION_MODE_CONTROL) + (sizeof(DWORD) * (tmpIsolationModeControl->numberOfAllowedIpAddresses - 1));
    TRY_SET_MSG(ExpectedBufLen <= InputBufLen, STATUS_INVALID_PARAMETER_4,
                 DL_ERROR, "%s: the expected buffer is larger than what we received. (%d > %d)\n", __func__, ExpectedBufLen, InputBufLen);

    TRY_SET_MSG(ACQUIRE_RESOURCE(context), STATUS_INSUFFICIENT_RESOURCES,
                 DL_WARNING, "Network Isolation can't process IOCTL in uninitialized state.");

    if (_pCurrentCbIsolationModeControl)
    {
        ec_mem_cache_free_generic(_pCurrentCbIsolationModeControl);
    }

    _pCurrentCbIsolationModeControl = tmpIsolationModeControl;
    tmpIsolationModeControl         = NULL;
    ec_SetNetworkIsolationMode(_pCurrentCbIsolationModeControl->isolationMode);

    if (_pCurrentCbIsolationModeControl->isolationMode == IsolationModeOff)
    {
        TRACE(DL_INFO, "%s: isolation OFF\n", __func__);
    } else
    {
        char           str[INET_ADDRSTRLEN];
        unsigned char *addr, i;

        for (i = 0; i < _pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses; ++i)
        {
            addr = (unsigned char *)&_pCurrentCbIsolationModeControl->allowedIpAddresses[i];
            snprintf(str, INET_ADDRSTRLEN, "%d.%d.%d.%d", addr[3], addr[2], addr[1], addr[0]);
            TRACE(DL_INFO, "%s: isolation ON IP: %s\n", __func__, str);
        }
    }

CATCH_RESOURCE:
    RELEASE_RESOURCE(context);

CATCH_DEFAULT:
    ec_mem_cache_free_generic(tmpIsolationModeControl);
    return xcode;
}

CB_ISOLATION_MODE ec_GetCurrentIsolationMode(ProcessContext *context)
{
    return atomic_read((atomic_t *)&CBIsolationMode);
}

VOID ec_IsolationIntercept(ProcessContext *context,
                          ULONG remoteIpAddress,
                          CB_ISOLATION_INTERCEPT_RESULT *isolationResult)
{

    // immediate allow if isolation mode is not on
    if (atomic_read((atomic_t *)&CBIsolationMode) == IsolationModeOff)
    {
        isolationResult->isolationAction = IsolationActionDisabled;
        return;
    }

    // acquire shared resource
    if (ACQUIRE_RESOURCE(context))
    {
        ULONG i;

        for (i = 0; i < _pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses; i++)
        {
            ULONG allowedIpAddress = _pCurrentCbIsolationModeControl->allowedIpAddresses[i];

            if (allowedIpAddress && remoteIpAddress == allowedIpAddress)
            {
                TRACE(DL_INFO, "ISOLATION ALLOWED: ADDR: 0x%08x", remoteIpAddress);
                isolationResult->isolationAction = IsolationActionAllow;
                RELEASE_RESOURCE(context);
                return;
            }
        }
        RELEASE_RESOURCE(context);
    }

    TRACE(DL_INFO, "ISOLATION BLOCKED: ADDR: 0x%08x", remoteIpAddress);
    isolationResult->isolationAction = IsolationActionBlock;
}

VOID ec_IsolationInterceptByAddrProtoPort(
    ProcessContext *context,
    ULONG                                   remoteIpAddress,
    bool                                    isIpV4,
    UINT32                                  protocol,
    UINT16                                  port,
    CB_ISOLATION_INTERCEPT_RESULT *isolationResult)
{
    // immediate allow if isolation mode is not on
    if (atomic_read((atomic_t *)&CBIsolationMode) == IsolationModeOff)
    {
        isolationResult->isolationAction = IsolationActionDisabled;
        return;
    }

    if (protocol == IPPROTO_UDP && (((isIpV4 == true) && (port == DHCP_CLIENT_PORT_V4 || port == DHCP_SERVER_PORT_V4)) ||
        ((isIpV4 == false) && (port == DHCP_CLIENT_PORT_V6 || port == DHCP_SERVER_PORT_V6)) ||
        port == DNS_SERVER_PORT))
    {
        TRACE(DL_INFO, "ISOLATION ALLOWED:: %s ADDR: 0x%08x PROTO: %s PORT: %u",
            (isIpV4?"IPv4":"IPv6"),
            remoteIpAddress, (protocol == IPPROTO_UDP?"UDP":"TCP"), ntohs(port));
        isolationResult->isolationAction = IsolationActionAllow;
        return;
    }

    // Our list of allowed addresses is IPv4, so just block IPv6 addresses
    // acquire shared resource
    if (isIpV4 && ACQUIRE_RESOURCE(context))
    {
        ULONG i;

        for (i = 0; i < _pCurrentCbIsolationModeControl->numberOfAllowedIpAddresses; i++)
        {
            ULONG allowedIpAddress = _pCurrentCbIsolationModeControl->allowedIpAddresses[i];

            if (allowedIpAddress && remoteIpAddress == allowedIpAddress)
            {
                TRACE(DL_INFO, "ISOLATION ALLOWED: By %s ADDR: 0x%08x PROTO: %s PORT: %u",
                    (isIpV4?"IPv4":"IPv6"),
                    remoteIpAddress, (protocol == IPPROTO_UDP?"UDP":"TCP"), ntohs(port));
                isolationResult->isolationAction = IsolationActionAllow;
                RELEASE_RESOURCE(context);
                return;
            }
            //			TRACE(DL_INFO, "ISOLATION NO Match: ADDR: 0x%08x RADDR: 0x%08x PROTO: %u PORT: %u",
            //				  ntohl(allowedIpAddress), ntohl(remoteIpAddress), protocol, ntohs(port));

        }
        RELEASE_RESOURCE(context);
    }

    TRACE(DL_INFO, "ISOLATION BLOCKED: %s ADDR: 0x%08x PROTO: %s PORT: %u",
        (isIpV4?"IPv4":"IPv6"),
        remoteIpAddress, (protocol == IPPROTO_UDP?"UDP":"TCP"), ntohs(port));
    isolationResult->isolationAction = IsolationActionBlock;
}
