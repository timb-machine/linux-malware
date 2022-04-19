/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum {
        InodeUnknown = 0,
        InodeAllowed = 1,
        InodeBanned  = 2
    } InodeState;

#ifdef __cplusplus
}
#endif
