/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/rbtree.h>
#include "process-context.h"

typedef int (*compare_callback)(void *left, void *right);
typedef void (*ref_callback)(void *data, ProcessContext *context);
typedef void (*for_rbtree_node)(void *data, void *priv, ProcessContext *context);

typedef struct ec_tree {
    struct rb_root       root;
    bool                 valid;
    uint64_t             lock;
    atomic64_t           count;
    int                  key_offset;
    int                  node_offset;
    compare_callback     compare;
    ref_callback         get_ref;
    ref_callback         put_ref;
} CB_RBTREE;

bool ec_rbtree_init(CB_RBTREE *tree,
                    int                  key_offset,
                    int                  node_offset,
                    compare_callback  compare_cb,
                    ref_callback      get_ref,
                    ref_callback      put_ref,
                    ProcessContext *context);
void ec_rbtree_destroy(CB_RBTREE *tree, ProcessContext *context);

void *ec_rbtree_search(CB_RBTREE *tree, void *key, ProcessContext *context);
bool ec_rbtree_insert(CB_RBTREE *tree, void *data, ProcessContext *context);
bool ec_rbtree_delete_by_key(CB_RBTREE *tree, void *key, ProcessContext *context);
bool ec_rbtree_delete(CB_RBTREE *tree, void *data, ProcessContext *context);
void ec_rbtree_clear(CB_RBTREE *tree, ProcessContext *context);
void ec_rbtree_read_for_each(CB_RBTREE *tree, for_rbtree_node callback, void *priv, ProcessContext *context);
void ec_rbtree_write_for_each(CB_RBTREE *tree, for_rbtree_node callback, void *priv, ProcessContext *context);
