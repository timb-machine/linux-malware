/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "priv.h"
#include <linux/unistd.h>

pte_t *ec_lookup_pte(p_sys_call_table address);
bool ec_set_page_state_rw(p_sys_call_table address, unsigned long *old_page_rw);
void ec_restore_page_state(p_sys_call_table address, unsigned long page_rw);
