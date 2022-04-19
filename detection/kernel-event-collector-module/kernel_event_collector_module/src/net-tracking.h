/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once


#include "priv.h"

typedef enum _conn_direction {
    CONN_IN  = 1,
    CONN_OUT = 2
} CONN_DIRECTION;

bool ec_net_tracking_initialize(ProcessContext *context);
void ec_net_tracking_shutdown(ProcessContext *context);
bool ec_net_tracking_check_cache(
    ProcessContext *context,
    pid_t           pid,
    CB_SOCK_ADDR   *localAddr,
    CB_SOCK_ADDR   *remoteAddr,
    uint16_t        proto,
    CONN_DIRECTION  conn_dir);
