// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "process-tracking-private.h"
#include "priv.h"
#include "cb-spinlock.h"

// Helper logic to sort the tracking table
typedef struct SORTED_PROCESS_TREE {
    CB_RBTREE           tree;
    for_rbtree_node     rb_callback;
    void *priv;
} SORTED_PROCESS_TREE;

typedef struct SORTED_PROCESS {
    struct rb_node     node;
    time_t             start_time;
    pid_t              pid;
} SORTED_PROCESS;

int __ec_rbtree_compare_process_start_time(void *left, void *right);
void __ec_rbtree_get_ref(void *data, ProcessContext *context);
void __ec_rbtree_put_ref(void *data, ProcessContext *context);
int __ec_sort_process_tracking_table(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context);

void ec_sorted_tracking_table_for_each(for_rbtree_node callback, void *priv, ProcessContext *context)
{
    SORTED_PROCESS_TREE data;

    data.rb_callback = callback;
    data.priv        = priv;

    ec_rbtree_init(&data.tree,
                   offsetof(SORTED_PROCESS, start_time),
                   offsetof(SORTED_PROCESS, node),
                   __ec_rbtree_compare_process_start_time,
                   __ec_rbtree_get_ref,
                   __ec_rbtree_put_ref,
                   context);

    ec_hashtbl_read_for_each_generic(g_process_tracking_data.table, __ec_sort_process_tracking_table, &data, context);

    ec_rbtree_destroy(&data.tree, context);
}

ProcessHandle *ec_sorted_tracking_table_get_handle(void *data, ProcessContext *context)
{
    if (data)
    {
        return ec_process_tracking_get_handle(((SORTED_PROCESS *)data)->pid, context);
    }
    return NULL;
}

int __ec_sort_process_tracking_table(HashTbl *hashTblp, HashTableNode *nodep, void *priv, ProcessContext *context)
{
    PosixIdentity *posix_identity = (PosixIdentity *)nodep;
    SORTED_PROCESS_TREE *data  = (SORTED_PROCESS_TREE *)priv;

    IF_MODULE_DISABLED_GOTO(context, CATCH_DISABLED);

    // posix_identity will be non-null while looping the entries, and null for the last call
    //  after iterating
    if (posix_identity)
    {
        // Insert each process entry into a rb_tree sorted by the start time
        SORTED_PROCESS *value = ec_mem_cache_alloc_generic(sizeof(SORTED_PROCESS), context);

        if (value)
        {
            RB_CLEAR_NODE(&value->node);
            value->start_time = posix_identity->posix_details.start_time;
            value->pid        = posix_identity->pt_key.pid;
            if (!ec_rbtree_insert(&data->tree, value, context))
            {
                ec_mem_cache_free_generic(value);
            }
        }
    } else
    {
        // Walk the rb_tree.
        ec_rbtree_read_for_each(&data->tree, data->rb_callback, data->priv, context);
    }

    return ACTION_CONTINUE;

CATCH_DISABLED:
    return ACTION_STOP;
}

// Compare function for the rb_tree
int __ec_rbtree_compare_process_start_time(void *left, void *right)
{
    time_t *left_key  = (time_t *)left;
    time_t *right_key = (time_t *)right;

    if (left_key && right_key)
    {
        if (*left_key < *right_key)
        {
            return -1;
        } else if (*left_key > *right_key)
        {
            return 1;
        } else if (*left_key == *right_key)
        {
            return 0;
        }
    }
    return -2;
}

void __ec_rbtree_get_ref(void *data, ProcessContext *context)
{
}

void __ec_rbtree_put_ref(void *data, ProcessContext *context)
{
    ec_mem_cache_free_generic(data);
}
