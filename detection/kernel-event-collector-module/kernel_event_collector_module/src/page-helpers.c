// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "page-helpers.h"

pte_t *ec_lookup_pte(p_sys_call_table address)
{
    unsigned int level;

    TRY_CB_RESOLVED(lookup_address);
    return CB_RESOLVED(lookup_address)((unsigned long)address, &level);

CATCH_DEFAULT:
    return NULL;
}

bool ec_set_page_state_rw(p_sys_call_table address, unsigned long *old_page_rw)
{
    unsigned long irq_flags;
    pte_t *pte = NULL;

    local_irq_save(irq_flags);
    local_irq_disable();

    pte = ec_lookup_pte(address);
    if (!pte)
    {
        local_irq_restore(irq_flags);
        return false;
    }

    *old_page_rw = pte->pte & _PAGE_RW;
    pte->pte |= _PAGE_RW;

    local_irq_restore(irq_flags);
    return true;
}


void ec_restore_page_state(p_sys_call_table address, unsigned long page_rw)
{
    unsigned long irq_flags;
    pte_t *pte = NULL;

    local_irq_save(irq_flags);
    local_irq_disable();

    pte = ec_lookup_pte(address);
    if (!pte)
    {
        TRACE(DL_ERROR, "Unable to restore page state\n");
        local_irq_restore(irq_flags);
        return;
    }

    // If the page state was originally RO, restore it to RO.
    // We don't just assign the original value back here in case some other bits were changed.
    if (!page_rw) pte->pte &= ~_PAGE_RW;
    local_irq_restore(irq_flags);
}

