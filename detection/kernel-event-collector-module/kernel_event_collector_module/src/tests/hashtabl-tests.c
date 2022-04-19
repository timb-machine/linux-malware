/* Copyright 2020 VMWare, Inc.  All rights reserved. */

#include "hash-table-generic.h"
#include "run-tests.h"

typedef struct table_key {
    int id;
} TableKey;

typedef struct table_value {
    char a[16];
} TableValue;

typedef struct entry {
    HashTableNode      link;
    struct table_key   key;
    atomic64_t         reference_count;
    struct table_value value;
} Entry;

HashTbl * init_hashtbl(ProcessContext *context, int refcount_offset, hashtbl_delete_cb delete_callback)
{
    return ec_hashtbl_init_generic(context,
                              1024,
                              sizeof(Entry),
                              sizeof(Entry),
                              "hash_table_testing",
                              sizeof(TableKey),
                              offsetof(Entry, key),
                              offsetof(Entry, link),
                              refcount_offset,
                              delete_callback,
                              NULL);
}

bool __init test__hash_table(ProcessContext *context)
{
    bool passed = false;
    HashTbl *table = init_hashtbl(context, HASHTBL_DISABLE_REF_COUNT, NULL);

    int size = 102400;
    int i, result;
    struct table_key *keys = (struct table_key *)ec_mem_cache_alloc_generic(sizeof(struct table_key) * size, context);
    struct table_value *values = (struct table_value *)ec_mem_cache_alloc_generic(sizeof(struct table_value) * size, context);
    struct entry *entry_ptr;

    //Test ec_hashtbl_alloc and ec_hashtbl_add
    for (i = 0; i < size; i++)
    {
        keys[i].id = i;

        get_random_bytes(&values[i], sizeof(struct table_value));
        entry_ptr = (struct entry *)ec_hashtbl_alloc_generic(table, context);
        if(entry_ptr == NULL)
        {
            pr_alert("Failt to alloc %d\n", i);
            goto test_exit;
        }

        entry_ptr->key.id = i;
        memcpy(&entry_ptr->value, &values[i], sizeof(struct table_value));
        result = ec_hashtbl_add_generic(table, entry_ptr, context);
        if(result != 0)
        {
            ec_hashtbl_free_generic(table, entry_ptr, context);
            pr_alert("Add fails %d\n", i);
            goto test_exit;
        }
    }

    //Test ec_hashtbl_get
    for (i = 0; i < size; i++)
    {
        entry_ptr = ec_hashtbl_get_generic(table, &keys[i], context);

        if (!entry_ptr)
        {
            pr_alert("ec_hashtbl_get_generic failed %d %d\n", i, keys[i].id);
        }

        if (memcmp(&entry_ptr->value, &values[i], sizeof(struct table_key)) != 0)
        {
            pr_alert("Get value does not match %d %d\n", i, keys[i].id);
            goto test_exit;
        }
    }

    //Test hastbl_del and ec_hashtbl_free
    for (i = 0; i < size; i++)
    {
        entry_ptr = ec_hashtbl_del_by_key_generic(table, &keys[i], context);
        if (entry_ptr == NULL)
        {
            pr_alert("Fail to find the element to be deleted\n");
            goto test_exit;
        }

        ec_hashtbl_free_generic(table, entry_ptr, context);

        entry_ptr = ec_hashtbl_get_generic(table, &keys[i], context);
        if (entry_ptr != NULL)
        {
            pr_alert("Delete fails %d\n", i);
            goto test_exit;
        }
    }

    pr_alert("Hash table tests all passed.\n");
    passed = true;
test_exit:
    ec_mem_cache_free_generic(keys);
    ec_mem_cache_free_generic(values);
    ec_hashtbl_shutdown_generic(table, context);

    return passed;
}

bool __init test__hashtbl_double_del(ProcessContext *context)
{
    bool passed = false;
    HashTbl *table = init_hashtbl(context, HASHTBL_DISABLE_REF_COUNT, NULL);
    Entry *tdata   = NULL;

    ASSERT_TRY(table);

    tdata = (Entry *)ec_hashtbl_alloc_generic(table, context);
    TRY_MSG(tdata, DL_ERROR, "ec_hashtbl_alloc_generic failed");

    ASSERT_TRY(ec_hashtbl_add_generic(table, tdata, context) == 0);

    // delete tdata so it gets deleted again below
    ec_hashtbl_del_generic(table, tdata, context);

    passed = true;
CATCH_DEFAULT:
    if (table)
    {
        if(tdata)
        {
            ec_hashtbl_del_generic(table, tdata, context);
            ec_hashtbl_free_generic(table, tdata, context);
        }
        ec_hashtbl_shutdown_generic(table, context);
    }

    return passed;
}

bool __init test__hashtbl_refcount_double_del(ProcessContext *context)
{
    bool passed = false;
    HashTbl *table  = init_hashtbl(context, offsetof(Entry, reference_count), NULL);
    Entry *tdata = NULL;

    ASSERT_TRY(table);

    tdata = (Entry *)ec_hashtbl_alloc_generic(table, context);
    TRY_MSG(tdata, DL_ERROR, "ec_hashtbl_alloc_generic failed");

    atomic64_set(&tdata->reference_count, 1);

    TRY_MSG(ec_hashtbl_add_generic(table, tdata, context) == 0, DL_ERROR, "ec_hashtbl_add_generic failed");

    // delete tdata so it gets deleted again below
    ec_hashtbl_del_generic(table, tdata, context);

    passed = true;
CATCH_DEFAULT:
    if (tdata)
    {
        ec_hashtbl_del_generic(table, tdata, context);
        ec_hashtbl_put_generic(table, tdata, context);
    }
    ec_hashtbl_shutdown_generic(table, context);

    return passed;
}

static bool _delete_callback_called __initdata;

void __init __ec_test_hashtbl_delete_callback(void *data, ProcessContext *context)
{
    _delete_callback_called = true;
}

bool __init test__hashtbl_refcount(ProcessContext *context)
{
    bool passed = false;
    HashTbl *table = init_hashtbl(context, offsetof(Entry, reference_count), __ec_test_hashtbl_delete_callback);
    Entry *tdata   = NULL;
    TableKey key;

    ASSERT_TRY(table);

    tdata = (Entry *)ec_hashtbl_alloc_generic(table, context);
    ASSERT_TRY(tdata);

    tdata->key.id = 1;
    atomic64_set(&tdata->reference_count, 1);

    ASSERT_TRY(ec_hashtbl_add_generic(table, tdata, context) == 0);
    // refcount 2

    key.id = 1;
    ASSERT_TRY(ec_hashtbl_get_generic(table, &key, context) == tdata);
    // refcount 3

    _delete_callback_called = false;
    ec_hashtbl_put_generic(table, tdata, context);
    // refcount 2
    ASSERT_TRY(!_delete_callback_called);

    // calls put
    ec_hashtbl_del_generic(table, tdata, context);
    // refcount 1
    ASSERT_TRY(!_delete_callback_called);

    // The reference count should be 1 now and this put should result in a free
    ec_hashtbl_put_generic(table, tdata, context);
    // refcount 0 should have been freed
    ASSERT_TRY(_delete_callback_called);
    tdata = NULL;
    passed = true;

CATCH_DEFAULT:
    if (table)
    {
        if(tdata)
        {
            ec_hashtbl_del_generic(table, tdata, context);
            ec_hashtbl_put_generic(table, tdata, context);
        }
        ec_hashtbl_shutdown_generic(table, context);
    }

    return passed;
}

// Attempt to add two entries and verify -EEXIST is returned
bool __init test__hashtbl_add_duplicate(ProcessContext *context)
{
    bool passed = false;
    Entry *tdata   = NULL;
    Entry *tdata2  = NULL;
    HashTbl *table = init_hashtbl(context, HASHTBL_DISABLE_REF_COUNT, NULL);

    ASSERT_TRY(table);

    tdata = (Entry *)ec_hashtbl_alloc_generic(table, context);
    tdata2 = (Entry *)ec_hashtbl_alloc_generic(table, context);
    ASSERT_TRY(tdata);
    ASSERT_TRY(tdata2);

    tdata->key.id = 1;
    tdata2->key.id = 1;

    ASSERT_TRY(ec_hashtbl_add_generic(table, tdata, context) == 0);
    ASSERT_TRY(ec_hashtbl_add_generic_safe(table, tdata2, context) == -EEXIST);
    passed = true;

CATCH_DEFAULT:
    if (table)
    {
        if(tdata)
        {
            ec_hashtbl_del_generic(table, tdata, context);
            ec_hashtbl_free_generic(table, tdata, context);
        }
        if(tdata2)
        {
            ec_hashtbl_del_by_key_generic(table, &tdata2->key, context);
            ec_hashtbl_free_generic(table, tdata2, context);
        }
        ec_hashtbl_shutdown_generic(table, context);
    }
    return passed;
}
