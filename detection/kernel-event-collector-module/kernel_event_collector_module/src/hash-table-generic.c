// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "hash-table-generic.h"
#include "cb-spinlock.h"

static inline atomic64_t *__ec_get_refcountp(const HashTbl *hashTblp, void *datap)
{
    return (atomic64_t *)(datap + hashTblp->refcount_offset);
}
static inline void *__ec_get_datap(const HashTbl *hashTblp, HashTableNode *nodep)
{
    return (void *)(nodep - hashTblp->node_offset);
}
inline HashTableNode *__ec_get_nodep(const HashTbl *hashTblp, void *datap)
{
    return (HashTableNode *)(datap + hashTblp->node_offset);
}

static int debug;

static uint64_t s_hashtbl_generic_lock;
static LIST_HEAD(s_hashtbl_generic);

#define HASHTBL_PRINT(fmt, ...)    do { if (debug) pr_err("hash-tbl: " fmt, ##__VA_ARGS__); } while (0)

int ec_hashtbl_del_generic_lockheld(HashTbl *hashTblp, void *datap, ProcessContext *context);

void ec_hashtable_debug_on(void)
{
    debug = 1;
}

void ec_hashtable_debug_off(void)
{
    debug = 0;
}

char *__ec_key_in_hex(ProcessContext *context, unsigned char *key, int key_len)
{
    int i;
    char *str = (char *) ec_mem_cache_alloc_generic(key_len * 3, context);

    for (i = 0; i < key_len; i++)
    {
        sprintf(str + i*3, "%02x ", key[i]);
    }
    str[key_len * 3 - 1] = '\0';
    return str;
}

inline void *__ec_get_key_ptr(HashTbl *hashTblp, void *datap)
{
    return (void *) datap + hashTblp->key_offset;
}

void ec_hashtbl_generic_init(ProcessContext *context)
{
    ec_spinlock_init(&s_hashtbl_generic_lock, context);
}

void ec_hashtbl_generic_destoy(ProcessContext *context)
{
    ec_spinlock_destroy(&s_hashtbl_generic_lock, context);
}

static inline u32 ec_hashtbl_hash_key(HashTbl *hashTblp,
                   unsigned char *key)
{
    return jhash(key, hashTblp->key_len, hashTblp->secret);
}
static inline int ec_hashtbl_bkt_index(HashTbl *hashTblp, u32 hash)
{
    return hash & (hashTblp->numberOfBuckets - 1);
}

static void ec_hashtbl_bkt_read_lock(HashTableBkt *bkt, ProcessContext *context)
{
    ec_read_lock(&bkt->lock, context);
}
static void ec_hashtbl_bkt_read_unlock(HashTableBkt *bkt, ProcessContext *context)
{
    ec_read_unlock(&bkt->lock, context);
}

static void ec_hashtbl_bkt_write_lock(HashTableBkt *bkt, ProcessContext *context)
{
    ec_write_lock(&bkt->lock, context);
}
static void ec_hashtbl_bkt_write_unlock(HashTableBkt *bkt, ProcessContext *context)
{
    ec_write_unlock(&bkt->lock, context);
}


HashTbl *ec_hashtbl_init_generic(ProcessContext *context,
                              uint64_t numberOfBuckets,
                              uint64_t datasize,
                              uint64_t sizehint,
                              const char *hashtble_name,
                              int key_len,
                              int key_offset,
                              int node_offset,
                              int refcount_offset,
                              hashtbl_delete_cb delete_callback,
                              hashtbl_handle_cb handle_callback)
{
    unsigned int i;
    HashTbl *hashTblp = NULL;
    size_t tableSize;
    unsigned char *tbl_storage_p  = NULL;
    uint64_t cache_elem_size;

    if (!is_power_of_2(numberOfBuckets))
    {
        numberOfBuckets = roundup_pow_of_two(numberOfBuckets);
    }
    tableSize = ((numberOfBuckets * sizeof(HashTableBkt)) + sizeof(HashTbl));

    //Since we're not in an atomic context this is an acceptable alternative to
    //kmalloc however, it should be noted that this is a little less efficient. The reason for this is
    //fragmentation that can occur on systems. We noticed this happening in the field, and if highly
    //fragmented, our driver will fail to load with a normal kmalloc
    tbl_storage_p  = ec_mem_cache_valloc_generic(tableSize, context);


    if (tbl_storage_p  == NULL)
    {
        HASHTBL_PRINT("Failed to allocate %luB at %s:%d.", tableSize,
                                                            __func__,
                                                            __LINE__);
        return NULL;
    }

    //With kzalloc we get zeroing for free, with vmalloc we need to do it ourself
    memset(tbl_storage_p, 0, tableSize);

    if (sizehint > datasize)
    {
        cache_elem_size = sizehint;
    } else
    {
        cache_elem_size = datasize;
    }

    HASHTBL_PRINT("Cache=%s elemsize=%llu hint=%llu\n", hashtble_name, cache_elem_size, sizehint);

    hashTblp = (HashTbl *)tbl_storage_p;
    hashTblp->tablePtr = (HashTableBkt *)(tbl_storage_p + sizeof(HashTbl));
    hashTblp->numberOfBuckets = numberOfBuckets;
    hashTblp->key_len     = key_len;
    hashTblp->key_offset  = key_offset;
    hashTblp->node_offset = node_offset;
    hashTblp->refcount_offset = refcount_offset;
    hashTblp->base_size   = tableSize + sizeof(HashTbl);
    hashTblp->delete_callback = delete_callback;
    hashTblp->handle_callback = handle_callback;

    if (cache_elem_size)
    {
        if (!ec_mem_cache_create(&hashTblp->hash_cache, hashtble_name, cache_elem_size, context))
        {
            ec_mem_cache_free_generic(hashTblp);
            return 0;
        }
    }

    // Make hash more random
    get_random_bytes(&hashTblp->secret, sizeof(hashTblp->secret));

    for (i = 0; i < hashTblp->numberOfBuckets; i++)
    {
        ec_spinlock_init(&hashTblp->tablePtr[i].lock, context);
        INIT_HLIST_HEAD(&hashTblp->tablePtr[i].head);
    }

    ec_write_lock(&s_hashtbl_generic_lock, context);
    list_add(&(hashTblp->genTables), &s_hashtbl_generic);
    ec_write_unlock(&s_hashtbl_generic_lock, context);

    HASHTBL_PRINT("Size=%lu NumberOfBuckets=%llu\n", tableSize, numberOfBuckets);
    HASHTBL_PRINT("ADDR=%p TADDR=%p OFFSET=%lu\n", hashTblp, hashTblp->tablePtr, sizeof(HashTbl));
    return hashTblp;
}

int __ec_hashtbl_delete_callback(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context)
{
    return ACTION_DELETE;
}

void __ec_hashtbl_for_each_generic(HashTbl *hashTblp, hashtbl_for_each_generic_cb callback, void *priv, bool haveWriteLock, ProcessContext *context);

void ec_hashtbl_shutdown_generic(HashTbl *hashTblp, ProcessContext *context)
{
    unsigned int i;

    CANCEL_VOID(hashTblp != NULL);
    atomic64_set(&(hashTblp->tableShutdown), 1);

    ec_write_lock(&s_hashtbl_generic_lock, context);
    list_del(&(hashTblp->genTables));
    ec_write_unlock(&s_hashtbl_generic_lock, context);

    __ec_hashtbl_for_each_generic(hashTblp, __ec_hashtbl_delete_callback, NULL, true, context);

    HASHTBL_PRINT("hash shutdown inst=%" PRFs64 " alloc=%" PRFs64 "\n",
        (long long)atomic64_read(&(hashTblp->tableInstance)),
        (long long)atomic64_read(&(hashTblp->hash_cache.allocated_count)));

    for (i = 0; i < hashTblp->numberOfBuckets; i++)
    {
        ec_spinlock_destroy(&hashTblp->tablePtr[i].lock, context);
    }

    ec_mem_cache_destroy(&hashTblp->hash_cache, context, NULL);
    ec_mem_cache_free_generic(hashTblp);
}

void ec_hashtbl_clear_generic(HashTbl *hashTblp, ProcessContext *context)
{
    HASHTBL_PRINT("ADDR=%p TADDR=%p OFFSET=%lu\n", hashTblp, hashTblp->tablePtr, sizeof(HashTbl));

    ec_hashtbl_write_for_each_generic(hashTblp, __ec_hashtbl_delete_callback, NULL, context);
}

void ec_hashtbl_write_for_each_generic(HashTbl *hashTblp, hashtbl_for_each_generic_cb callback, void *priv, ProcessContext *context)
{
    if (!hashTblp)
    {
        return;
    }
    if (atomic64_read(&(hashTblp->tableShutdown)) == 1)
    {
        return;
    }

    __ec_hashtbl_for_each_generic(hashTblp, callback, priv, true, context);
}

void ec_hashtbl_read_for_each_generic(HashTbl *hashTblp, hashtbl_for_each_generic_cb callback, void *priv, ProcessContext *context)
{
    if (!hashTblp)
    {
        return;
    }
    if (atomic64_read(&(hashTblp->tableShutdown)) == 1)
    {
        return;
    }

    __ec_hashtbl_for_each_generic(hashTblp, callback, priv, false, context);
}

void __ec_hashtbl_for_each_generic(HashTbl *hashTblp, hashtbl_for_each_generic_cb callback, void *priv, bool haveWriteLock, ProcessContext *context)
{
    unsigned int i;
    uint64_t numberOfBuckets;
    HashTableBkt *ec_hashtbl_tbl  = NULL;

    if (!hashTblp) return;

    ec_hashtbl_tbl = hashTblp->tablePtr;
    numberOfBuckets  = hashTblp->numberOfBuckets;

    // May need to walk the lists too
    for (i = 0; i < numberOfBuckets; ++i)
    {
        HashTableBkt *bucketp = &ec_hashtbl_tbl[i];
        HashTableNode *nodep = 0;
        struct hlist_node *tmp;

        if (haveWriteLock)
        {
            ec_hashtbl_bkt_write_lock(bucketp, context);
        } else
        {
            ec_hashtbl_bkt_read_lock(bucketp, context);
        }

        if (!hlist_empty(&bucketp->head))
        {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
            hlist_for_each_entry_safe(nodep, tmp, &bucketp->head, link)
#else
            struct hlist_node *_nodep;

            hlist_for_each_entry_safe(nodep, _nodep, tmp, &bucketp->head, link)
#endif
            {

                switch ((*callback)(hashTblp, __ec_get_datap(hashTblp, nodep), priv, context))
                {
                case ACTION_DELETE:
                    // This should never be called with only a read lock
                    BUG_ON(!haveWriteLock);
                    hlist_del(&nodep->link);
                    atomic64_dec(&(hashTblp->tableInstance));
                    ec_hashtbl_free_generic(hashTblp, nodep, context);
                    break;
                case ACTION_STOP:
                    if (haveWriteLock)
                    {
                        ec_hashtbl_bkt_write_unlock(bucketp, context);
                    } else
                    {
                        ec_hashtbl_bkt_read_unlock(bucketp, context);
                    }
                    goto Exit;
                    break;
                case ACTION_CONTINUE:
                default:
                    break;
                }
            }
        }

        if (haveWriteLock)
        {
            ec_hashtbl_bkt_write_unlock(bucketp, context);
        } else
        {
            ec_hashtbl_bkt_read_unlock(bucketp, context);
        }
    }

Exit:
    // Signal the callback we are done.  It may need to clean up something in the context
    (*callback)(hashTblp, NULL, priv, context);
    return;
}


HashTableNode *__ec_hashtbl_lookup(HashTbl *hashTblp, struct hlist_head *head, u32 hash, const void *key)
{
    HashTableNode *tableNode = NULL;
    struct hlist_node *hlistTmp = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    struct hlist_node *hlistNode = NULL;

    hlist_for_each_entry_safe(tableNode, hlistNode, hlistTmp, head, link)
#else
    hlist_for_each_entry_safe(tableNode, hlistTmp, head, link)
#endif
    {
        if (hash == tableNode->hash &&
            memcmp(key, __ec_get_key_ptr(hashTblp, __ec_get_datap(hashTblp, tableNode)), hashTblp->key_len) == 0)
        {
            return tableNode;
        }
    }

    return NULL;
}

int ec_hashtbl_add_generic(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    u32 hash;
    uint64_t bucket_indx;
    HashTableBkt *bucketp = NULL;
    HashTableNode *nodep;
    char *key_str;

    if (!hashTblp || !datap)
    {
        return -EINVAL;
    }

    if (atomic64_read(&(hashTblp->tableShutdown)) == 1)
    {
        return -1;
    }

    hash = ec_hashtbl_hash_key(hashTblp, __ec_get_key_ptr(hashTblp, datap));
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    nodep = __ec_get_nodep(hashTblp, datap);
    nodep->hash = hash;

    if (debug)
    {
        key_str = __ec_key_in_hex(context, __ec_get_key_ptr(hashTblp, datap), hashTblp->key_len);
        HASHTBL_PRINT("%s: bucket=%llu key=%s\n", __func__, bucket_indx, key_str);
        ec_mem_cache_free_generic(key_str);
    }

    ec_hashtbl_bkt_write_lock(bucketp, context);
    hlist_add_head(&nodep->link, &bucketp->head);
    if (hashTblp->refcount_offset != HASHTBL_DISABLE_REF_COUNT)
    {
        atomic64_inc(__ec_get_refcountp(hashTblp, datap));
    }
    atomic64_inc(&(hashTblp->tableInstance));
    ec_hashtbl_bkt_write_unlock(bucketp, context);

    return 0;
}

int ec_hashtbl_add_generic_safe(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    u32 hash;
    uint64_t bucket_indx;
    HashTableBkt *bucketp = NULL;
    HashTableNode *nodep = NULL;
    HashTableNode *old_node;
    char *key_str;
    void *key;
    int ret;

    if (!hashTblp || !datap)
    {
        return -EINVAL;
    }

    if (atomic64_read(&(hashTblp->tableShutdown)) == 1)
    {
        return -1;
    }

    key = __ec_get_key_ptr(hashTblp, datap);
    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    nodep = __ec_get_nodep(hashTblp, datap);
    nodep->hash = hash;

    if (debug)
    {
        key_str = __ec_key_in_hex(context, key, hashTblp->key_len);
        HASHTBL_PRINT("%s: bucket=%llu key=%s\n", __func__, bucket_indx, key_str);
        ec_mem_cache_free_generic(key_str);
    }

    ret = -EEXIST;

    ec_hashtbl_bkt_write_lock(bucketp, context);
    old_node = __ec_hashtbl_lookup(hashTblp, &bucketp->head, hash, key);
    if (!old_node)
    {
        ret = 0;
        hlist_add_head(&nodep->link, &bucketp->head);
        if (hashTblp->refcount_offset != HASHTBL_DISABLE_REF_COUNT)
        {
            atomic64_inc(__ec_get_refcountp(hashTblp, datap));
        }
        atomic64_inc(&(hashTblp->tableInstance));
    }
    ec_hashtbl_bkt_write_unlock(bucketp, context);

    return ret;
}

void *ec_hashtbl_get_generic(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    u32 hash;
    uint64_t bucket_indx;
    HashTableBkt *bucketp;
    HashTableNode *nodep = NULL;
    char *key_str;
    void *datap = NULL;

    if (!hashTblp || !key)
    {
        return NULL;
    }

    if (atomic64_read(&(hashTblp->tableShutdown)) == 1)
    {
        return NULL;
    }

    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    if (debug)
    {
        key_str = __ec_key_in_hex(context, key, hashTblp->key_len);
        HASHTBL_PRINT("%s: bucket=%llu key=%s\n", __func__, bucket_indx, key_str);
        ec_mem_cache_free_generic(key_str);
    }

    ec_hashtbl_bkt_read_lock(bucketp, context);
    nodep = __ec_hashtbl_lookup(hashTblp, &bucketp->head, hash, key);
    if (nodep)
    {
        datap = ec_hashtbl_get_generic_ref(
            hashTblp,
            __ec_get_datap(hashTblp, nodep),
            context);
    }
    ec_hashtbl_bkt_read_unlock(bucketp, context);

    return datap;
}

void *ec_hashtbl_get_generic_ref(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    if (hashTblp->refcount_offset != HASHTBL_DISABLE_REF_COUNT)
    {
        atomic64_inc(__ec_get_refcountp(hashTblp, datap));
    }
    if (hashTblp->handle_callback)
    {
        void *handle = hashTblp->handle_callback(datap, context);

        if (!handle)
        {
            // If we failed to get a handle, we want to release the reference and return NULL
            ec_hashtbl_put_generic(hashTblp, datap, context);
        }

        // We want to return the handle
        datap = handle;
    }

    return datap;
}

int ec_hashtbl_del_generic_lockheld(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    HashTableNode *nodep = __ec_get_nodep(hashTblp, datap);

    // This protects against ec_hashtbl_del_generic being called twice for the same datap
    if ((&nodep->link)->pprev != NULL)
    {
        hlist_del_init(&nodep->link);

        if (atomic64_read(&(hashTblp->tableInstance)) == 0)
        {
            HASHTBL_PRINT("ec_hashtbl_del: underflow!!\n");
        } else
        {
            atomic64_dec(&(hashTblp->tableInstance));
        }

        // The only reason this should happen is if ec_hashtbl_del_generic and
        // ec_hashtbl_put_generic are called out of order,
        // e.g. ec_hashtbl_put_generic -> ec_hashtbl_del_generic
        if (hashTblp->refcount_offset != HASHTBL_DISABLE_REF_COUNT)
        {
            WARN(atomic64_read(__ec_get_refcountp(hashTblp, datap)) == 1, "hashtbl will free while lock held");
        }

        ec_hashtbl_put_generic(hashTblp, datap, context);

        return 0;
    } else
    {
        pr_err("Attempt to delete a NULL object from the hash table");
    }

    return -1;
}

void *ec_hashtbl_del_by_key_generic(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    u32 hash;
    uint64_t bucket_indx;
    HashTableBkt *bucketp;
    HashTableNode *nodep = NULL;
    void *datap = NULL;

    if (!hashTblp || !key)
    {
        return NULL;
    }

    if (atomic64_read(&(hashTblp->tableShutdown)) == 1)
    {
        return NULL;
    }

    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    ec_hashtbl_bkt_write_lock(bucketp, context);
    nodep = __ec_hashtbl_lookup(hashTblp, &bucketp->head, hash, key);
    if (nodep)
    {
        datap = __ec_get_datap(hashTblp, nodep);

        // Will be needed as long ec_hashtbl_del_generic_lockheld is used
        if (hashTblp->refcount_offset != HASHTBL_DISABLE_REF_COUNT)
        {
            atomic64_inc(__ec_get_refcountp(hashTblp, datap));
        }

        ec_hashtbl_del_generic_lockheld(hashTblp, datap, context);
    }
    ec_hashtbl_bkt_write_unlock(bucketp, context);

    // caller must put or free (if no reference count)
    return datap;
}

void ec_hashtbl_del_generic(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    uint64_t bucket_indx;
    HashTableBkt *bucketp;
    HashTableNode *nodep;

    CANCEL_VOID(hashTblp != NULL);
    CANCEL_VOID(datap != NULL);
    CANCEL_VOID(atomic64_read(&(hashTblp->tableShutdown)) != 1);

    nodep = __ec_get_nodep(hashTblp, datap);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, nodep->hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    ec_hashtbl_bkt_write_lock(bucketp, context);
    ec_hashtbl_del_generic_lockheld(hashTblp, datap, context);
    ec_hashtbl_bkt_write_unlock(bucketp, context);
}

void *ec_hashtbl_alloc_generic(HashTbl *hashTblp, ProcessContext *context)
{
    void *datap;

    CANCEL(hashTblp != NULL, NULL);
    CANCEL(atomic64_read(&(hashTblp->tableShutdown)) != 1, NULL);

    datap = ec_mem_cache_alloc(&hashTblp->hash_cache, context);
    CANCEL(datap, NULL);

    INIT_HLIST_NODE(&__ec_get_nodep(hashTblp, datap)->link);
    return datap;
}

void ec_hashtbl_put_generic(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    CANCEL_VOID(hashTblp != NULL);
    CANCEL_VOID(datap != NULL);

    if (hashTblp->refcount_offset != HASHTBL_DISABLE_REF_COUNT)
    {
         IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(__ec_get_refcountp(hashTblp, datap), {
            ec_hashtbl_free_generic(hashTblp, datap, context);
        });
    }
}

void ec_hashtbl_free_generic(HashTbl *hashTblp, void *datap, ProcessContext *context)
{
    CANCEL_VOID(hashTblp != NULL);

    if (datap)
    {
        if (hashTblp->delete_callback)
        {
            hashTblp->delete_callback(__ec_get_datap(hashTblp, datap), context);
        }
        ec_mem_cache_free(&hashTblp->hash_cache, datap, context);
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define CACHE_SIZE(a)      a->object_size
#else
#define CACHE_SIZE(a)      a->buffer_size
#endif

// Loop over each hash table and calculate the memory used
size_t ec_hashtbl_get_memory(ProcessContext *context)
{
    HashTbl *hashTblp;
    size_t   size = 0;

    ec_read_lock(&s_hashtbl_generic_lock, context);
    list_for_each_entry(hashTblp, &s_hashtbl_generic, genTables) {
            size += hashTblp->base_size;
    }
    ec_read_unlock(&s_hashtbl_generic_lock, context);

    return size;
}

bool __ec_hashtbl_bkt_lock(bool haveWriteLock, HashTbl *hashTblp, void *key, void **datap, HashTableBkt **bkt, ProcessContext *context)
{
    u32 hash;
    uint64_t bucket_indx;
    HashTableBkt *bucketp;
    HashTableNode *nodep;

    if (!hashTblp || !key || !datap || !bkt)
    {
        return false;
    }

    if (atomic64_read(&(hashTblp->tableShutdown)) == 1)
    {
        return false;
    }

    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);
    bucketp = &(hashTblp->tablePtr[bucket_indx]);

    if (haveWriteLock)
    {
        ec_hashtbl_bkt_write_lock(bucketp, context);
    } else
    {
        ec_hashtbl_bkt_read_lock(bucketp, context);
    }

    nodep = __ec_hashtbl_lookup(hashTblp, &bucketp->head, hash, key);
    if (!nodep)
    {
        if (haveWriteLock)
        {
            ec_hashtbl_bkt_write_unlock(bucketp, context);
        } else
        {
            ec_hashtbl_bkt_read_unlock(bucketp, context);
        }
        return false;
    }

    *datap = __ec_get_datap(hashTblp, nodep);
    *bkt = bucketp;
    return true;
}

bool ec_hashtbl_read_bkt_lock(HashTbl *hashTblp, void *key, void **datap, HashTableBkt **bkt, ProcessContext *context)
{
    return __ec_hashtbl_bkt_lock(false, hashTblp, key, datap, bkt, context);
}

void ec_hashtbl_read_bkt_unlock(HashTableBkt *bkt, ProcessContext *context)
{
    if (bkt)
    {
        ec_hashtbl_bkt_read_unlock(bkt, context);
    }
}

bool ec_hashtbl_write_bkt_lock(HashTbl *hashTblp, void *key, void **datap, HashTableBkt **bkt, ProcessContext *context)
{
    return __ec_hashtbl_bkt_lock(true, hashTblp, key, datap, bkt, context);
}

void ec_hashtbl_write_bkt_unlock(HashTableBkt *bkt, ProcessContext *context)
{
    if (bkt)
    {
        ec_hashtbl_bkt_write_unlock(bkt, context);
    }
}

HashTableBkt *__ec_hashtbl_find_bucket(HashTbl *hashTblp, void *key)
{
    u32 hash;
    uint64_t bucket_indx;

    if (!hashTblp || !key)
    {
        return NULL;
    }

    if (atomic64_read(&(hashTblp->tableShutdown)) == 1)
    {
        return NULL;
    }

    hash = ec_hashtbl_hash_key(hashTblp, key);
    bucket_indx = ec_hashtbl_bkt_index(hashTblp, hash);

    return &(hashTblp->tablePtr[bucket_indx]);
}

void ec_hashtbl_read_lock(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    HashTableBkt *bucketp = __ec_hashtbl_find_bucket(hashTblp, key);

    if (bucketp)
    {
        ec_hashtbl_bkt_read_lock(bucketp, context);
    }
}

void ec_hashtbl_read_unlock(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    HashTableBkt *bucketp = __ec_hashtbl_find_bucket(hashTblp, key);

    if (bucketp)
    {
        ec_hashtbl_bkt_read_unlock(bucketp, context);
    }
}

void ec_hashtbl_write_lock(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    HashTableBkt *bucketp = __ec_hashtbl_find_bucket(hashTblp, key);

    if (bucketp)
    {
        ec_hashtbl_bkt_write_lock(bucketp, context);
    }
}

void ec_hashtbl_write_unlock(HashTbl *hashTblp, void *key, ProcessContext *context)
{
    HashTableBkt *bucketp = __ec_hashtbl_find_bucket(hashTblp, key);

    if (bucketp)
    {
        ec_hashtbl_bkt_write_unlock(bucketp, context);
    }
}

