// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"

typedef struct _on_symbol_context {
    char *function_name;
    void *function;
}
on_symbol_context;

int __ec_onsym(void *data, const char *name, struct module *module_name,
          unsigned long addr)
{
    if (!data)
    {
        return 1;
    }

    if (name)
    {
        on_symbol_context *ctx = (on_symbol_context *)data;

        if (!strcmp(name, ctx->function_name))
        {
            ctx->function = (void *)addr;
            return 1;
        } else
        {
            //pr_info("%s at 0x%lx\n", name, addr);
        }
    }
    return 0;
}

void *ec_get_ksym(char *sym_name)
{
    on_symbol_context ctx;

    ctx.function_name = sym_name;
    ctx.function = 0;

    kallsyms_on_each_symbol(__ec_onsym, &ctx);
    pr_info("%s found at 0x%p\n", ctx.function_name, ctx.function);

    return ctx.function;
}
