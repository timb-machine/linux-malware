/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

struct symbols_s {
    unsigned char name[50];  // BEWARE maximum length, including '\0'
    unsigned char len;  // strlen(name)
    unsigned long *addr;
};
int  ec_findsyms_init(ProcessContext *context, struct symbols_s *p_symbols);
void ec_lookup_symbols(ProcessContext *context, struct symbols_s *p_symbols);
int  ec_verify_symbols(ProcessContext *context, struct symbols_s *p_symbols);

#define MAX_MODULE_NAME (200)

#define disable_suffix "_disable"

typedef bool (*disable_fn_type)(char *src_module_name, char **failure_reason);

typedef struct PEER_MODULE {
    char                               module_name[MAX_MODULE_NAME + 1];
    /** List of functions that module exports */
    char                               disable_fn_name[sizeof(disable_suffix) + MAX_MODULE_NAME + 1];
    disable_fn_type                    disable_fn;
    struct list_head   list;
} PEER_MODULE;

bool ec_lookup_peer_module_symbols(ProcessContext *context, struct list_head *peer_modules);
void ec_free_peer_module_symbols(struct list_head *peer_modules);

#define CBP_KSYM_lookup_address      0
#define CBP_KSYM_sys_call_table      1
#define CBP_KSYM_ia32_sys_call_table 2
#define CBP_KSYM_security_ops        3
