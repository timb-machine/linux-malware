// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "version.h"

#define PPCAT_NX(A, B) A ## B
#define MAKE_FN(PREFIX, SUFFIX)  PPCAT_NX(PREFIX, SUFFIX)
#define DISABLE_FN  MAKE_FN(MODULE_NAME, _disable)

bool DISABLE_FN(char *src_module_name, char **failure_reason)
{
    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    return ec_disable_if_not_connected(&context, src_module_name, failure_reason);
}
EXPORT_SYMBOL(DISABLE_FN);
