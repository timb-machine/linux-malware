/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "process-tracking.h"

void ec_event_send_start(ProcessHandle  * process_handle,
                         uid_t            uid,
                         int              start_action,
                         ProcessContext  *context);

void ec_event_send_last_exit(PCB_EVENT        event,
                             ProcessContext  *context);

void ec_event_send_exit(ProcessHandle  *process_handle,
                        bool             was_last_active_process,
                        ProcessContext  *context);

void ec_event_send_block(ProcessHandle  *process_handle,
                         uint32_t          type,
                         uint32_t          reason,
                         uint32_t          details,
                         uid_t             uid,
                         char             *cmdline,
                         ProcessContext *context);

void ec_event_send_file(ProcessHandle  *process_handle,
                        CB_EVENT_TYPE    event_type,
                        CB_INTENT_TYPE   intent,
                        uint64_t         device,
                        uint64_t         inode,
                        const char *path,
                        ProcessContext *context);

void ec_event_send_modload(ProcessHandle  *process_handle,
                           CB_EVENT_TYPE    event_type,
                           uint64_t         device,
                           uint64_t         inode,
                           int64_t          base_address,
                           char *path,
                           ProcessContext *context);
#
void ec_event_send_net(ProcessHandle  *process_handle,
                       char            *msg,
                       CB_EVENT_TYPE    net_event_type,
                       CB_SOCK_ADDR * localAddr,
                       CB_SOCK_ADDR * remoteAddr,
                       int               protocol,
                       void             *sk,
                       ProcessContext   *context);

void ec_event_send_net_proxy(ProcessHandle  *process_handle,
                             char            *msg,
                             CB_EVENT_TYPE    net_event_type,
                             CB_SOCK_ADDR     *localAddr,
                             CB_SOCK_ADDR     *remoteAddr,
                             int               protocol,
                             char             *actual_server,
                             uint16_t          actual_port,
                             void             *sk,
                             ProcessContext   *context);

void ec_event_send_dns(CB_EVENT_TYPE          net_event_type,
                       CB_EVENT_DNS_RESPONSE *response,
                       ProcessContext        *context);
