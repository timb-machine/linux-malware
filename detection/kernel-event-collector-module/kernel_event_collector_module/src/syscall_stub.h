/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#define CBSYSSTUB_NAME(c_name)      ec_stub_sys_##c_name
#define ORIG_SYSCALL_PTR(c_name)    ec_orig_syscall_##c_name##_ptr
