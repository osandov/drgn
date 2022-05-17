// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

// Linux kernel module for testing drgn helpers and kernel support. For now,
// this is all in one file for simplicity and to keep the compilation fast
// (since this is compiled for every kernel version in CI).
//
// This is intended to be used with drgn's vmtest framework, but in theory it
// can be used with any kernel that has debug info enabled (at your own risk).

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/rbtree_augmented.h>
#include <linux/slab.h>

// list

LIST_HEAD(drgn_test_empty_list);
LIST_HEAD(drgn_test_full_list);
LIST_HEAD(drgn_test_singular_list);
LIST_HEAD(drgn_test_corrupted_list);

struct drgn_test_list_entry {
	struct list_head node;
	int value;
};

struct drgn_test_list_entry drgn_test_list_entries[3];
struct drgn_test_list_entry drgn_test_singular_list_entry;
struct drgn_test_list_entry drgn_test_corrupted_list_entries[2];

HLIST_HEAD(drgn_test_empty_hlist);
HLIST_HEAD(drgn_test_full_hlist);

struct drgn_test_hlist_entry {
	struct hlist_node node;
	int value;
};

struct drgn_test_hlist_entry drgn_test_hlist_entries[3];

// Emulate a race condition between two threads calling list_add() at the same
// time.
static void init_corrupted_list(void)
{
	struct list_head *prev = &drgn_test_corrupted_list;
	struct list_head *next = drgn_test_corrupted_list.next;
	struct list_head *new1 = &drgn_test_corrupted_list_entries[0].node;
	struct list_head *new2 = &drgn_test_corrupted_list_entries[1].node;

	// Thread 1 starts list_add().
	next->prev = new1;

	// Thread 2 races in and does its own list_add().
	next->prev = new2;
	new2->next = next;
	new2->prev = prev;
	WRITE_ONCE(prev->next, new2);

	// Thread 1 finishes list_add().
	new1->next = next;
	new1->prev = prev;
	WRITE_ONCE(prev->next, new1);
}

static void drgn_test_list_init(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_list_entries); i++) {
		list_add_tail(&drgn_test_list_entries[i].node,
			      &drgn_test_full_list);
	}
	list_add(&drgn_test_singular_list_entry.node, &drgn_test_singular_list);

	for (i = ARRAY_SIZE(drgn_test_hlist_entries); i-- > 0;) {
		hlist_add_head(&drgn_test_hlist_entries[i].node,
			       &drgn_test_full_hlist);
	}

	init_corrupted_list();
}

// rbtree

struct rb_root drgn_test_empty_rb_root = RB_ROOT;
struct rb_root drgn_test_rb_root = RB_ROOT;

struct drgn_test_rb_entry {
	struct rb_node node;
	int value;
};

struct drgn_test_rb_entry drgn_test_rb_entries[4];

struct rb_node drgn_test_empty_rb_node;

struct rb_root drgn_test_rbtree_with_equal = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_equal[4];

struct rb_root drgn_test_rbtree_out_of_order = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_out_of_order[4];

struct rb_root drgn_test_rbtree_with_bad_root_parent = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entry_bad_root_parent;

struct rb_root drgn_test_rbtree_with_red_root = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entry_red_root;

struct rb_root drgn_test_rbtree_with_inconsistent_parents = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_inconsistent_parents[2];

struct rb_root drgn_test_rbtree_with_red_violation = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_red_violation[3];

struct rb_root drgn_test_rbtree_with_black_violation = RB_ROOT;
struct drgn_test_rb_entry drgn_test_rb_entries_with_black_violation[2];

static void drgn_test_rbtree_insert(struct rb_root *root,
				    struct drgn_test_rb_entry *entry)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;

	while (*new) {
		struct drgn_test_rb_entry *this =
			container_of(*new, struct drgn_test_rb_entry, node);

		parent = *new;
		if (entry->value <= this->value)
			new = &(*new)->rb_left;
		else
			new = &(*new)->rb_right;
	}

	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, root);
}

static void drgn_test_rbtree_init(void)
{
	struct rb_node *node;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries); i++) {
		drgn_test_rb_entries[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rb_root,
					&drgn_test_rb_entries[i]);
	}
	RB_CLEAR_NODE(&drgn_test_empty_rb_node);

	// Red-black tree with entries that compare equal to each other.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_equal); i++) {
		drgn_test_rb_entries_with_equal[i].value = i / 2;
		drgn_test_rbtree_insert(&drgn_test_rbtree_with_equal,
					&drgn_test_rb_entries_with_equal[i]);
	}

	// Bad red-black tree whose entries are out of order.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_out_of_order); i++) {
		drgn_test_rb_entries_out_of_order[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rbtree_out_of_order,
					&drgn_test_rb_entries_out_of_order[i]);
	}
	drgn_test_rb_entries_out_of_order[0].value = 99;

	// Bad red-black tree with a root node that has a non-NULL parent.
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_bad_root_parent,
				&drgn_test_rb_entry_bad_root_parent);
	rb_set_parent(&drgn_test_rb_entry_bad_root_parent.node,
		      &drgn_test_empty_rb_node);

	// Bad red-black tree with a red root node.
	rb_link_node(&drgn_test_rb_entry_red_root.node, NULL,
		     &drgn_test_rbtree_with_red_root.rb_node);

	// Bad red-black tree with inconsistent rb_parent.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_inconsistent_parents); i++) {
		drgn_test_rb_entries_with_inconsistent_parents[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rbtree_with_inconsistent_parents,
					&drgn_test_rb_entries_with_inconsistent_parents[i]);
	}
	node = drgn_test_rbtree_with_inconsistent_parents.rb_node;
	rb_set_parent(node->rb_left ? node->rb_left : node->rb_right,
		      &drgn_test_empty_rb_node);

	// Bad red-black tree with red node with red child.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_red_violation); i++)
		drgn_test_rb_entries_with_red_violation[i].value = i;
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_red_violation,
				&drgn_test_rb_entries_with_red_violation[0]);
	rb_link_node(&drgn_test_rb_entries_with_red_violation[1].node,
		     &drgn_test_rb_entries_with_red_violation[0].node,
		     &drgn_test_rb_entries_with_red_violation[0].node.rb_right);
	rb_link_node(&drgn_test_rb_entries_with_red_violation[2].node,
		     &drgn_test_rb_entries_with_red_violation[1].node,
		     &drgn_test_rb_entries_with_red_violation[1].node.rb_right);

	// Bad red-black tree with unequal number of black nodes in paths from
	// root to leaves.
	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries_with_black_violation); i++)
		drgn_test_rb_entries_with_black_violation[i].value = i;
	drgn_test_rbtree_insert(&drgn_test_rbtree_with_black_violation,
				&drgn_test_rb_entries_with_black_violation[0]);
	rb_link_node(&drgn_test_rb_entries_with_black_violation[1].node,
		     &drgn_test_rb_entries_with_black_violation[0].node,
		     &drgn_test_rb_entries_with_black_violation[0].node.rb_right);
	drgn_test_rb_entries_with_black_violation[1].node.__rb_parent_color |= RB_BLACK;
}

// slab

const int drgn_test_slob = IS_ENABLED(CONFIG_SLOB);
struct kmem_cache *drgn_test_kmem_cache;

struct drgn_test_slab_object {
	int padding[11];
	int value;
};

struct drgn_test_slab_object *drgn_test_slab_objects[5];

static void drgn_test_slab_exit(void)
{
	size_t i;

	if (!drgn_test_kmem_cache)
		return;

	for (i = 0; i < ARRAY_SIZE(drgn_test_slab_objects); i++) {
		if (drgn_test_slab_objects[i]) {
			kmem_cache_free(drgn_test_kmem_cache,
					drgn_test_slab_objects[i]);
		}
	}
	kmem_cache_destroy(drgn_test_kmem_cache);
}

// Dummy constructor so test slab cache won't get merged.
static void drgn_test_slab_ctor(void *arg)
{
}

static int drgn_test_slab_init(void)
{
	size_t i;

	drgn_test_kmem_cache =
		kmem_cache_create("drgn_test",
				  sizeof(struct drgn_test_slab_object),
				  __alignof__(struct drgn_test_slab_object), 0,
				  drgn_test_slab_ctor);
	if (!drgn_test_kmem_cache)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(drgn_test_slab_objects); i++) {
		drgn_test_slab_objects[i] =
			kmem_cache_alloc(drgn_test_kmem_cache, GFP_KERNEL);
		if (!drgn_test_slab_objects[i])
			return -ENOMEM;
		drgn_test_slab_objects[i]->value = i;
	}
	return 0;
}

static void __exit drgn_test_exit(void)
{
	drgn_test_slab_exit();
}

static int __init drgn_test_init(void)
{
	int ret;

	drgn_test_list_init();
	drgn_test_rbtree_init();
	ret = drgn_test_slab_init();
	if (ret)
		drgn_test_exit();
	return ret;
}

module_init(drgn_test_init);
module_exit(drgn_test_exit);

MODULE_LICENSE("GPL");
