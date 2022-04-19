// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include "priv.h"
#include "findsyms.h"
#include "mem-cache.h"

#define CB_APP_NAME CB_APP_PROC_DIR

// kptr_restrict contains 0, 1 or 2
#define KPTR_RESTRICT_LEN 1
#define KPTR_RESTRICT_PATH "/proc/sys/kernel/kptr_restrict"

bool __ec_parse_module_name(char *line, char **module_name);
bool __ec_lookup_peer_modules(ProcessContext *context, struct list_head *output_modules);
int __ec_get_kptr_restrict(void);
void __ec_set_kptr_restrict(int new_kptr_restrict);


int ec_set_symbol_address_if_matches(void *data, const char *namebuf, struct module *module, unsigned long address)
{
    struct symbols_s *p_symbols = (struct symbols_s *) data;
    struct symbols_s *curr_symbol;
    int symbol_name_len = strlen(namebuf);

    for (curr_symbol = p_symbols; curr_symbol->name[0]; ++curr_symbol) {
        if (!*curr_symbol->addr &&  // not yet found
            symbol_name_len == curr_symbol->len && // length matches
            0 == strcmp(namebuf, curr_symbol->name))  // not yet found
        {
            TRACE(DL_INFO, "Discovered address of %s (0x%lx)", namebuf, address);
            *curr_symbol->addr = address;
            break;
        }
    }

    return 0;
}

/*
 * NOTE: This will not currently work on RHEL 8, vfs_read()/vfs_write()
 * are visible in linux 2.x and 3.x (RHEL 6 and 7) but after
 * linux 4.14 vfs_read()/vfs_write() are no longer exported.
 * However they are replaced with kernel_read()/kernel_write() and we
 * can use those instead if we ever want to build for those kernels.
 */

/*
 * ec_lookup_symbols
 * @struct symbols_s* p_symbols - a list of the functions to search for
 * Provides access to global symbols listed by the kernel via /proc/kallsyms by name.
 */
void ec_lookup_symbols(ProcessContext *context, struct symbols_s *p_symbols)
{
    struct symbols_s *curr_symbol;
    unsigned int n_unk = 0;  // number of unknown symbols
    int current_kptr_restrict = __ec_get_kptr_restrict();

    TRY(p_symbols && p_symbols->name[0]);

    /*
     * Documentation/sysctl/kernel.txt:
     *  When kptr_restrict is set to (0), there are no restrictions.  When
     *  kptr_restrict is set to (1), the default, kernel pointers
     *  printed using the %pK format specifier will be replaced with 0's
     *  unless the user has CAP_SYSLOG.  When kptr_restrict is set to
     *  (2), kernel pointers printed using %pK will be replaced with 0's
     *  regardless of privileges.
     */
    if (current_kptr_restrict > 0)
    {
        __ec_set_kptr_restrict(0);
    }

    // Initialize all the addresses to 0 in case it is not found
    for (curr_symbol = p_symbols; curr_symbol->name[0]; ++curr_symbol) {
        *curr_symbol->addr = 0;
        ++n_unk;
    }
    TRACE(DL_INFO, "Searching for %d symbols...", n_unk);

    kallsyms_on_each_symbol(ec_set_symbol_address_if_matches, (void *)p_symbols);

    for (curr_symbol = p_symbols; curr_symbol->name[0]; ++curr_symbol) {
        if (curr_symbol->addr)
            --n_unk;
    }
    if (n_unk != 0)
        TRACE(DL_INFO, "Unable to find %d symbols", n_unk);

CATCH_DEFAULT:
    if (current_kptr_restrict > 0)
    {
        __ec_set_kptr_restrict(current_kptr_restrict);
    }
}

/**
 * Looks up other event_collectors loaded in the kernel.
 * For each event_collector found, the routine will
 * - Construct a PEER_MODULE struct and add it the output list.
 * - Also the routine will attempt to lookup the functions the peer exports
 *   to manage the state of the peer module and sets these up in PEER_MODULE struct also.
 *
 * For backwards compatibility the routine does not fail if it cannot resolve an expected function,
 * in this case it will just set the corresponding field in PEER_MODULE to null.
 *
 *
 * @param peer_modules
 * @return
 */
bool ec_lookup_peer_module_symbols(ProcessContext *context, struct list_head *peer_modules)
{
    bool result = true;
    PEER_MODULE *elem = NULL;
    int peer_module_count = 0;
    int i = 0;
    struct symbols_s *symbols = NULL;

    if (!__ec_lookup_peer_modules(context, peer_modules))
    {
        TRACE(DL_ERROR, "Failed to lookup peer modules");
        result = false;
        goto Exit;
    }

    /**
     * Populate the names for the functions for each peer module.
     *
     * Each module will export a unique name for the functions.
     * e.g. The module with name event_collector_12349 will export a name.
     * event_collector_12349_disable_if_not_connected
     *
     */
    list_for_each_entry(elem, peer_modules, list)
    {
        int remaining_char_count = sizeof(elem->disable_fn_name) - 1;

        elem->disable_fn_name[0] = 0;

        strncat(elem->disable_fn_name, elem->module_name, remaining_char_count);
        remaining_char_count -= strnlen(elem->module_name, remaining_char_count);

        strncat(elem->disable_fn_name, disable_suffix, remaining_char_count);
        remaining_char_count -= sizeof(disable_suffix);

        peer_module_count += 1;
    }

    PUSH_GFP_MODE(context, GFP_MODE(context) | __GFP_ZERO);
    symbols = ec_mem_cache_alloc_generic(sizeof(struct symbols_s) * (peer_module_count + 1), context);
    POP_GFP_MODE(context);

    i = 0;
    list_for_each_entry(elem, peer_modules, list)
    {
        strncat(symbols[i].name, elem->disable_fn_name, sizeof(symbols[i].name) - 1);
        symbols[i].len = (char) strlen(symbols[i].name);
        symbols[i].addr = (unsigned long *) &elem->disable_fn;
        i++;
    }

    ec_lookup_symbols(context, symbols);

    if (ec_verify_symbols(context, symbols) < 0)
    {
        TRACE(DL_ERROR, "%s Failed to lookup symbols for some peer modules", __func__);
    }

Exit:
    if (symbols != NULL)
    {
        ec_mem_cache_free_generic(symbols);
    }

    return result;
}

bool __ec_lookup_peer_modules(ProcessContext *context, struct list_head *output_modules)
{
    struct file *pFile  = NULL;
    bool           result = true;
    loff_t         offset = 0;
    int            ret    = 0;
    int            l_pfx  = 0;
    char          *buffer = NULL;

    INIT_LIST_HEAD(output_modules);

    set_fs(get_ds());
    pFile = filp_open("/proc/modules", O_RDONLY, 0);
    if (IS_ERR(pFile))
    {
        TRACE(DL_ERROR, "%s /proc/modules open failed", __func__);
        result = false;
        goto Exit;
    }

    PUSH_GFP_MODE(context, GFP_MODE(context) | __GFP_ZERO);
    buffer = (char *)ec_mem_cache_alloc_generic(CB_KALLSYMS_BUFFER*sizeof(unsigned char), context);
    POP_GFP_MODE(context);
    if (buffer == NULL)
    {
        TRACE(DL_ERROR, "%s Out of memory", __func__);
        result = false;
        goto Exit;
    }

    while (true)
    {
        char *line_start = buffer;

        ret = vfs_read(pFile, &buffer[l_pfx], CB_KALLSYMS_BUFFER - 1 - l_pfx, &offset);

        if (ret <= 0)
        {
            goto Exit;
        }

        // Read ret bytes, total string to process is left over prefix + number of bytes read.
        line_start[l_pfx + ret] = 0;

        while (line_start != NULL)
        {
            char *line = strsep(&line_start, "\n");

            if (line_start == NULL)
            {
                /**
                 * Did not find line ending.
                 * Store the read bytes so the subsequent read can append the read result
                 * to the bytes read.
                 */
                l_pfx = strlen(line);
                memmove(&buffer[0], line, l_pfx);
                break;
            } else
            {
                char *module_name = NULL;
                /**
                 * Found a line ending.
                 * Now process the line.
                 */
                __ec_parse_module_name(line, &module_name);

                if (strstr(module_name, CB_APP_NAME) && strcmp(module_name, CB_APP_MODULE_NAME) != 0)
                {
                    /**
                     *  Found another module add it to the output list.
                     *  The strcmp in the if condition will make sure
                     *  that this module does not add an entry for itself.
                     */
                    PEER_MODULE *temp = (PEER_MODULE *) ec_mem_cache_alloc_generic(sizeof(PEER_MODULE), context);

                    temp->module_name[0] = 0;
                    strncat(temp->module_name, module_name, sizeof(temp->module_name) - 1);

                    list_add(&(temp->list), output_modules);
                }
            }
        }
    }

Exit:
    if (buffer != NULL)
    {
        ec_mem_cache_free_generic(buffer);
        buffer = NULL;
    }
    if (pFile != NULL)
    {
        filp_close(pFile, NULL);
        pFile = NULL;
    }
    if (result != true)
    {
        ec_free_peer_module_symbols(output_modules);

        INIT_LIST_HEAD(output_modules);
    }

    return result;
}

void ec_free_peer_module_symbols(struct list_head *peer_modules)
{
    struct PEER_MODULE *elem, *next;

    list_for_each_entry_safe(elem, next, peer_modules, list)
    {
        list_del_init(&elem->list);
        ec_mem_cache_free_generic(elem);
        elem = NULL;
    }
}

/**
 * Gets the module name from the line.
 * e.g.
 * Input: ablk_helper 13597 1 aesni_intel, Live 0xffffffffa0233000
 * Output: ablk_helper
 *
 * @param line
 * @param module_name
 * @return
 */
bool __ec_parse_module_name(char *line, char **module_name)
{
    *module_name = strsep(&line, " ");
    return true;
}

int ec_verify_symbols(ProcessContext *context, struct symbols_s *p_symbols)
{
    struct symbols_s *curr_symbol;
    int ret = 0;

    for (curr_symbol = p_symbols; curr_symbol->name[0]; ++curr_symbol)
    {
            if (!(*curr_symbol->addr))
            {
                TRACE(DL_INIT, "ec_findsyms_init: no address for %s", curr_symbol->name);

                ret = -1;
            }
    }

    return ret;
}

/**
 * Gets the kptr_restrict setting.
 *
 * @return kptr_restrict setting or -1 if unable to retrieve
 */
int __ec_get_kptr_restrict(void)
{
    struct file *pFile = NULL;
    ssize_t      ret;
    char         buffer[KPTR_RESTRICT_LEN + 1];
    int          current_kptr_restrict = -1;
    loff_t       offset                = 0;
    mm_segment_t oldfs                 = get_fs();

    set_fs(get_ds());
    pFile = filp_open(KPTR_RESTRICT_PATH, O_RDONLY, 0);
    TRY(!IS_ERR(pFile));

    ret = vfs_read(pFile, buffer, KPTR_RESTRICT_LEN, &offset);
    if (ret != KPTR_RESTRICT_LEN)
    {
        TRACE(DL_ERROR, "kptr_restrict: read failed, %zd", ret);
        goto CATCH_DEFAULT;
    }

    buffer[KPTR_RESTRICT_LEN] = 0;
    if (0 != kstrtoint(buffer, 0, &current_kptr_restrict))
    {
        TRACE(DL_ERROR, "kptr_restrict: failed to convert to int %s", buffer);
        goto CATCH_DEFAULT;
    }

CATCH_DEFAULT:
    if (pFile != NULL) {
        filp_close(pFile, NULL);
        pFile = NULL;
    }
    set_fs(oldfs);
    return current_kptr_restrict;
}

/**
 * Sets the kptr_restrict setting.
 *
 * @param new_kptr_restrict
 */
void __ec_set_kptr_restrict(int new_kptr_restrict)
{
    struct file *pFile = NULL;
    char         buffer[KPTR_RESTRICT_LEN + 1];
    ssize_t      ret;
    loff_t       offset = 0;
    mm_segment_t oldfs  = get_fs();

    set_fs(get_ds());
    pFile = filp_open(KPTR_RESTRICT_PATH, O_WRONLY, 0);
    TRY(!IS_ERR(pFile));

    if (KPTR_RESTRICT_LEN != snprintf(buffer, sizeof(buffer), "%d", new_kptr_restrict))
    {
        TRACE(DL_ERROR, "kptr_restrict: failed to convert to string %d", new_kptr_restrict);
        goto CATCH_DEFAULT;
    }

    ret = vfs_write(pFile, buffer, KPTR_RESTRICT_LEN, &offset);
    if (ret != KPTR_RESTRICT_LEN)
    {
        TRACE(DL_ERROR, "kptr_restrict: write failed %zd", ret);
        goto CATCH_DEFAULT;
    }

CATCH_DEFAULT:
    if (pFile != NULL) {
        filp_close(pFile, NULL);
        pFile = NULL;
    }
    set_fs(oldfs);
}

int ec_findsyms_init(ProcessContext *context, struct symbols_s *p_symbols)
{
        ec_lookup_symbols(context, p_symbols);
        if (ec_verify_symbols(context, p_symbols) < 0) {
                TRACE(DL_INIT, "%s failed", __func__);
                return -ENOTSUPP;
        }
        return 0;
}
