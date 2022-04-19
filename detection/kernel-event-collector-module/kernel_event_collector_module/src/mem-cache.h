/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/list.h>
#include <linux/seq_file.h>

#include "process-context.h"

#define CB_MEM_CACHE_NAME_LEN    43

typedef struct CB_MEM_CACHE {
    struct list_head   node;
    struct list_head   allocation_list;
    uint64_t           lock;
    atomic64_t         allocated_count;
    struct kmem_cache *kmem_cache;
    uint32_t           object_size;
    uint8_t            name[CB_MEM_CACHE_NAME_LEN + 1];
} CB_MEM_CACHE;

typedef void (*memcache_printval_cb)(void *value, ProcessContext *context);


void ec_mem_cache_init(ProcessContext *context);
void ec_mem_cache_shutdown(ProcessContext *context);
size_t ec_mem_cache_get_memory_usage(ProcessContext *context);
int ec_mem_cache_show(struct seq_file *m, void *v);

bool ec_mem_cache_create(CB_MEM_CACHE *cache, const char *name, size_t size, ProcessContext *context);
void ec_mem_cache_destroy(CB_MEM_CACHE *cache, ProcessContext *context, memcache_printval_cb printval_callback);

void *ec_mem_cache_alloc(CB_MEM_CACHE *cache, ProcessContext *context);
void ec_mem_cache_free(CB_MEM_CACHE *cache, void *value, ProcessContext *context);

/* private */
void *__ec_mem_cache_alloc_generic(const size_t size, ProcessContext *context, bool doVirtualAlloc, const char *fn, uint32_t line);
void __ec_mem_cache_free_generic(void *value, const char *fn, uint32_t line);
/* end private */


// Define this to enable memory leak debugging
//  This will track all memory allocations in a list with record of the source function
//  NOTE: This list is not protectd by a lock, so it is absolutely for debug only.
//        a. Our locks allocate memory
//        b. The free function does not currently accept a `context`, and always using GFP_ATOMIC causes issues
#ifdef MEM_DEBUG
#  define ec_mem_cache_alloc_generic(SIZE, CONTEXT) __ec_mem_cache_alloc_generic(SIZE, CONTEXT, false, __func__, __LINE__)
#  define ec_mem_cache_valloc_generic(SIZE, CONTEXT) __ec_mem_cache_alloc_generic(SIZE, CONTEXT, true, __func__, __LINE__)
#  define ec_mem_cache_free_generic(VALUE) __ec_mem_cache_free_generic(VALUE, __func__, __LINE__)
#  define ec_mem_cache_put_generic(VALUE) __ec_mem_cache_free_generic(VALUE, __func__, __LINE__)
#else
#  define ec_mem_cache_alloc_generic(SIZE, CONTEXT) __ec_mem_cache_alloc_generic(SIZE, CONTEXT, false, NULL, __LINE__)
#  define ec_mem_cache_valloc_generic(SIZE, CONTEXT) __ec_mem_cache_alloc_generic(SIZE, CONTEXT, true, NULL, __LINE__)
#  define ec_mem_cache_free_generic(VALUE) __ec_mem_cache_free_generic(VALUE, NULL, __LINE__)
#  define ec_mem_cache_put_generic(VALUE) __ec_mem_cache_free_generic(VALUE, NULL, __LINE__)
#endif

void *ec_mem_cache_get_generic(void *value, ProcessContext *context);
size_t ec_mem_cache_get_size_generic(const void *value);
char *ec_mem_cache_strdup(const char *src, ProcessContext *context);
char *ec_mem_cache_strdup_x(const char *src, size_t *len, ProcessContext *context);
