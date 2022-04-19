// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"

#include "mem-cache.h"

#include "cb-spinlock.h"


static struct
{
    uint64_t          lock;
    struct list_head  list;
    atomic64_t        generic_buffer_count;
    atomic64_t        generic_buffer_size;
} s_mem_cache;

typedef struct cache_buffer {
    uint32_t  magic;
    struct list_head  list;
} cache_buffer_t;

#define CACHE_BUFFER_MAGIC   0xDEADBEEF
static const size_t CACHE_BUFFER_SZ = sizeof(cache_buffer_t);

#ifdef MEM_DEBUG
    struct list_head mem_debug_list = LIST_HEAD_INIT(mem_debug_list);

    void __ec_mem_cache_generic_report_leaks(void);
#endif

// Get the size of this string, and subtract the `\0`
#define MEM_CACHE_PREFIX_LEN   (sizeof(MEM_CACHE_PREFIX) - 1)

void ec_mem_cache_init(ProcessContext *context)
{
    atomic64_set(&s_mem_cache.generic_buffer_count, 0);
    atomic64_set(&s_mem_cache.generic_buffer_size, 0);
    INIT_LIST_HEAD(&s_mem_cache.list);

    // ec_spinlock_init calls ec_mem_cache_alloc_generic, all initialization needs to happen before this call
    ec_spinlock_init(&s_mem_cache.lock, context);
}

void ec_mem_cache_shutdown(ProcessContext *context)
{
    int64_t generic_buffer_count;

    // cp_spinlock_destroy calls ec_mem_cache_free_generic, this must be called before other shutdown
    ec_spinlock_destroy(&s_mem_cache.lock, context);

    generic_buffer_count = atomic64_read(&s_mem_cache.generic_buffer_count);

    if (generic_buffer_count != 0)
    {
        TRACE(DL_ERROR, "Exiting with %" PRFs64 " allocated objects (total size: %" PRFs64 ")",
            (long long)generic_buffer_count, (long long)atomic64_read(&s_mem_cache.generic_buffer_size));
    }

    // TODO: Check cache list

    #ifdef MEM_DEBUG
        __ec_mem_cache_generic_report_leaks();
    #endif
}

bool ec_mem_cache_create(CB_MEM_CACHE *cache, const char *name, size_t size, ProcessContext *context)
{
    if (cache)
    {
        cache->object_size = size;
        // prefix the cache name with a unique prefix to avoid conflicts with cbr
        cache->name[0] = 0;
        strncat(cache->name, MEM_CACHE_PREFIX, CB_MEM_CACHE_NAME_LEN);
        strncat(cache->name, name, CB_MEM_CACHE_NAME_LEN - MEM_CACHE_PREFIX_LEN);
        INIT_LIST_HEAD(&cache->allocation_list);

        cache->kmem_cache = kmem_cache_create(
            cache->name,
            size + CACHE_BUFFER_SZ,
            0,
            SLAB_HWCACHE_ALIGN,
            NULL);
        atomic64_set(&cache->allocated_count, 0);
        cache->object_size = size;

        if (cache->kmem_cache)
        {
            ec_spinlock_init(&cache->lock, context);
            ec_write_lock(&s_mem_cache.lock, context);
            list_add(&cache->node, &s_mem_cache.list);
            ec_write_unlock(&s_mem_cache.lock, context);

            return true;
        }
    }
    return false;
}

void ec_mem_cache_destroy(CB_MEM_CACHE *cache, ProcessContext *context, memcache_printval_cb printval_callback)
{
    void *value = NULL;
    struct cache_buffer *cb = NULL;

    if (cache && cache->kmem_cache)
    {
        uint64_t allocated_count = atomic64_read(&cache->allocated_count);

        // cache->node only needs to be deleted from the list if cache->kmem_cache was allocated
        // otherwise it was never added to s_mem_cache.list and may have invalid next and prev pointers
        ec_write_lock(&s_mem_cache.lock, context);
        list_del_init(&cache->node);
        ec_write_unlock(&s_mem_cache.lock, context);

        if (allocated_count > 0)
        {
            TRACE(DL_ERROR, "Destroying Memory Cache (%s) with %" PRFu64 " allocated items.",
                   cache->name, (unsigned long long)allocated_count);

            if (printval_callback)
            {
                ec_write_lock(&cache->lock, context);
                list_for_each_entry(cb, &cache->allocation_list, list)
                {
                    if (cb)
                    {
                        value = (char *)cb + CACHE_BUFFER_SZ;
                        printval_callback(value, context);
                    }
                }
                ec_write_unlock(&cache->lock, context);

            }
        }

        ec_spinlock_destroy(&cache->lock, context);

        kmem_cache_destroy(cache->kmem_cache);
        cache->kmem_cache = NULL;
    }
}

#if LINUX_VERSION_CODE == KERNEL_VERSION(3, 10, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7, 3)
    // CB-10446
    // We observed a kernel panic in kmem_cache_alloc affecting only Centos/RHEL 7. This was
    //  found to be a documented "use after free" issue in the 3.10 kernel which is fixed in
    //  3.10.0-327.22.2.el7 (Late 7.2).  It appears that using GFP_ATOMIC for ALL kmem_cache_alloc calls
    //  seems to workaround the problem. Unfortunately there is no test for the specific version.
    //
    // http://lkml.iu.edu/hypermail/linux/kernel/1403.1/04340.html
    // https://patchwork.ozlabs.org/patch/303498/
    #define CHECK_GFP(CONTEXT)  CB_ATOMIC
#else
    #define CHECK_GFP(CONTEXT)  GFP_MODE(CONTEXT)
#endif

void *ec_mem_cache_alloc(CB_MEM_CACHE *cache, ProcessContext *context)
{
    void *value = NULL;

    if (cache && cache->kmem_cache)
    {
        value = kmem_cache_alloc(cache->kmem_cache, CHECK_GFP(context));
        if (value)
        {
            cache_buffer_t *cache_buffer = (cache_buffer_t *)value;

            cache_buffer->magic = CACHE_BUFFER_MAGIC;

            ec_write_lock(&cache->lock, context);
            list_add(&cache_buffer->list, &cache->allocation_list);
            ec_write_unlock(&cache->lock, context);

            atomic64_inc(&cache->allocated_count);

            value = (char *)cache_buffer + CACHE_BUFFER_SZ;
        }
    }

    return value;
}

void ec_mem_cache_free(CB_MEM_CACHE *cache, void *value, ProcessContext *context)
{
    if (value && cache->kmem_cache)
    {
        cache_buffer_t *cache_buffer = (cache_buffer_t *)((char *)value - CACHE_BUFFER_SZ);

        if (cache_buffer->magic == CACHE_BUFFER_MAGIC)
        {
            ec_write_lock(&cache->lock, context);
            list_del(&cache_buffer->list);
            ec_write_unlock(&cache->lock, context);

            kmem_cache_free(cache->kmem_cache, (void *)cache_buffer);
            ATOMIC64_DEC__CHECK_NEG(&cache->allocated_count);
        } else
        {
            TRACE(DL_ERROR, "Cache entry magic does not match for %s.  Failed to free memory: %p", cache->name, value);
            dump_stack();
        }
    }
}

size_t ec_mem_cache_get_memory_usage(ProcessContext *context)
{
    CB_MEM_CACHE *cache;
    size_t        size = atomic64_read(&s_mem_cache.generic_buffer_size);

    ec_write_lock(&s_mem_cache.lock, context);
    list_for_each_entry(cache, &s_mem_cache.list, node) {
            size += cache->object_size * atomic64_read(&(cache->allocated_count));
    }
    ec_write_unlock(&s_mem_cache.lock, context);

    return size;
}

#define SUFFIX_LIST_SIZE  4
void __ec_simplify_size(size_t *size, const char **suffix)
{
    int s_index = 0;
    static const char * const suffix_list[SUFFIX_LIST_SIZE] = { "bytes", "Kb", "Mb", "Gb" };

    CANCEL_VOID(size && suffix);

    while (*size > 1024 && s_index < (SUFFIX_LIST_SIZE - 1))
    {
        *size /= 1024;
        s_index++;
    }

    *suffix = suffix_list[s_index];
}

int ec_mem_cache_show(struct seq_file *m, void *v)
{
    CB_MEM_CACHE *cache;
    size_t size = 0;
    const char *suffix;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    seq_printf(m, "%40s | %6s | %40s | %9s |\n",
                  "Name", "Alloc", "Cache Name", "Obj. Size");

    ec_write_lock(&s_mem_cache.lock, &context);
    list_for_each_entry(cache, &s_mem_cache.list, node) {
            const char *cache_name = cache->name;
            int         cache_size = cache->object_size;
            long        count      = atomic64_read(&(cache->allocated_count));

            seq_printf(m, "%40s | %6ld | %40s | %9d |\n",
                       cache->name,
                       count,
                       cache_name,
                       cache_size);
            size += count * cache_size;
    }
    ec_write_unlock(&s_mem_cache.lock, &context);

    __ec_simplify_size(&size, &suffix);

    seq_puts(m, "\n");
    seq_printf(m, "Allocated Cache Memory         : %ld %s\n", size, suffix);

    size = atomic64_read(&s_mem_cache.generic_buffer_size);
    __ec_simplify_size(&size, &suffix);

    seq_printf(m, "Allocated Generic Memory       : %ld %s\n", size, suffix);
    seq_printf(m, "Allocated Generic Memory Count : %" PRFs64 "\n", (long long)atomic64_read(&s_mem_cache.generic_buffer_count));

    return 0;
}

// Generic Memory Allocations
//  This is a wrapper aroud kmalloc and vmalloc that keeps track of the number and
//   size of allocations.
//
//  This logic will add overhead of a single `generic_buffer_t` instance to every
//   memory allocation to help decrement the allocation counter on free.
//
// We include the total allocation in the used memory reporte to user space.  We
//  also report the total `leaked` memory when the module is disabled.
typedef struct generic_buffer {
    uint32_t          magic;
    size_t            size;
    bool              isVirtual;
    atomic64_t        ref_count;
    #ifdef MEM_DEBUG
    #define ALLOC_SOURCE_LEN 50
    char              alloc_source[ALLOC_SOURCE_LEN+1];
    struct list_head  list;
    #endif
} generic_buffer_t;

#ifdef MEM_DEBUG

    #define MEM_DEBUG_ADD_ENTRY(BUFFER, CONTEXT, FN, LINE) \
        do {\
            snprintf((BUFFER)->alloc_source, ALLOC_SOURCE_LEN, "%s:%d", (FN), (LINE));\
            (BUFFER)->alloc_source[ALLOC_SOURCE_LEN] = 0;\
            list_add(&(BUFFER)->list, &mem_debug_list);\
        } while (0)


    #define MEM_DEBUG_DEL_ENTRY(BUFFER, FN, LINE) \
        do {\
            BUFFER->magic = 0;\
            list_del(&(BUFFER)->list);\
        } while (0)

#else

    #define MEM_DEBUG_ADD_ENTRY(BUFFER, CONTEXT, FN, LINE)
    #define MEM_DEBUG_DEL_ENTRY(BUFFER, FN, LINE)

#endif

#define GENERIC_BUFFER_MAGIC   0xDEADBEEF
static const size_t GENERIC_BUFFER_SZ = sizeof(generic_buffer_t);

void *__ec_mem_cache_alloc_generic(const size_t size, ProcessContext *context, bool doVirtualAlloc, const char *fn, uint32_t line)
{
    void    *new_allocation = NULL;
    size_t   real_size      = size + GENERIC_BUFFER_SZ;

    // Ensure that we are passed valid size (greater than 0 and does not overflow)
    if (size > 0 && size < real_size)
    {
        if (!doVirtualAlloc)
        {
            new_allocation = kmalloc(real_size, GFP_MODE(context));
        } else if (doVirtualAlloc && IS_NON_ATOMIC(context))
        {
            new_allocation = vmalloc(real_size);
        } else
        {
            TRACE(DL_ERROR, "Generic MEM alloc failed: ATOMIC not allowed for vmalloc");
            return NULL;
        }

        if (new_allocation)
        {
            generic_buffer_t *generic_buffer = (generic_buffer_t *)new_allocation;

            generic_buffer->magic     = GENERIC_BUFFER_MAGIC;
            generic_buffer->size      = real_size;
            generic_buffer->isVirtual = doVirtualAlloc;
            atomic64_inc(&s_mem_cache.generic_buffer_count);
            atomic64_add(real_size, &s_mem_cache.generic_buffer_size);

            // Init reference count
            atomic64_set(&generic_buffer->ref_count, 1);

            new_allocation = (char *)generic_buffer + sizeof(generic_buffer_t);

            MEM_DEBUG_ADD_ENTRY(generic_buffer, context, fn, line);
        }
    }

    return new_allocation;
}

void __ec_mem_cache_free_generic(void *value, const char *fn, uint32_t line)
{
    if (value)
    {
        generic_buffer_t *generic_buffer = (generic_buffer_t *)((char *)value - sizeof(generic_buffer_t));

        if (generic_buffer->magic == GENERIC_BUFFER_MAGIC)
        {
            IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(&generic_buffer->ref_count,
            {
                ATOMIC64_DEC__CHECK_NEG(&s_mem_cache.generic_buffer_count);
                atomic64_sub(generic_buffer->size, &s_mem_cache.generic_buffer_size);
                MEM_DEBUG_DEL_ENTRY(generic_buffer, fn, line);
                if (!generic_buffer->isVirtual)
                {
                    kfree(generic_buffer);
                } else
                {
                    vfree(generic_buffer);
                }
            });
        } else
        {
            TRACE(DL_ERROR, "Generic MEM cache magic does not match.  Failed to free memory: %p", value);
            dump_stack();
        }
    }
}

void *ec_mem_cache_get_generic(void *value, ProcessContext *context)
{
    if (value)
    {
        generic_buffer_t *generic_buffer = (generic_buffer_t *)((char *)value - sizeof(generic_buffer_t));

        if (generic_buffer->magic == GENERIC_BUFFER_MAGIC)
        {
            atomic64_inc(&generic_buffer->ref_count);
        } else
        {
            value = 0;
            TRACE(DL_ERROR, "Generic MEM cache magic does not match.  Failed to free memory: %p", value);
            dump_stack();
        }
    }
    return value;
}

size_t ec_mem_cache_get_size_generic(const void *value)
{
    size_t size = 0;

    if (value)
    {
        generic_buffer_t *generic_buffer = (generic_buffer_t *)((char *)value - sizeof(generic_buffer_t));

        if (generic_buffer->magic == GENERIC_BUFFER_MAGIC)
        {
            size = generic_buffer->size - GENERIC_BUFFER_SZ;
        } else
        {
            TRACE(DL_ERROR, "Generic MEM cache magic does not match.  Failed to free memory: %p", value);
            dump_stack();
        }
    }
    return size;
}

char *ec_mem_cache_strdup(const char *src, ProcessContext *context)
{
    return ec_mem_cache_strdup_x(src, NULL, context);
}

char *ec_mem_cache_strdup_x(const char *src, size_t *size, ProcessContext *context)
{
    char *dest = NULL;

    if (src)
    {
        size_t len = strlen(src);

        dest = ec_mem_cache_alloc_generic(len + 1, context);
        if (dest)
        {
            dest[0] = 0;
            strncat(dest, src, len);

            if (size)
            {
                *size = len + 1;
            }
        }
    }
    return dest;
}

#ifdef MEM_DEBUG
void __ec_mem_cache_generic_report_leaks(void)
{
    generic_buffer_t *generic_buffer;

    // We can't lock here because it has been destroyed
    // ec_write_lock(&s_mem_cache.lock, &context);
    list_for_each_entry(generic_buffer, &mem_debug_list, list)
    {
        TRACE(DL_ERROR, "## Buffer size=%ld, from %s", generic_buffer->size, generic_buffer->alloc_source);
    }
    // ec_write_unlock(&s_mem_cache.lock, &context);
}
#endif
