/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "process-context.h"

// These helper routines are used to keep track of the actual active hooks for
//  diagnostic purposes.  This will add the context into a list that can be walked
//  at module disable or on demand.
//
// Ideally this should add a context to the list when the context is created,
//  but we do not currently have a context "destroy" action.  Instead I am adding
//  a context to the list from the module entry check routines.
// This makes the assumption that these macros are not used recursively.
bool ec_hook_tracking_initialize(ProcessContext *context);
void ec_hook_tracking_shutdown(ProcessContext *context);
void ec_hook_tracking_add_entry(ProcessContext *context, const char *hook_name);
void ec_hook_tracking_del_entry(ProcessContext *context);
int ec_hook_tracking_print_active(ProcessContext *context);
