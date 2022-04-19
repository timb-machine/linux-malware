/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "process-context.h"
#include "raw_event.h"

int ec_dns_parse_data(
    char                  *dns_data,
    int                    dns_data_len,
    CB_EVENT_DNS_RESPONSE *response,
    ProcessContext        *context);
