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

// list

LIST_HEAD(drgn_test_empty_list);
LIST_HEAD(drgn_test_full_list);
LIST_HEAD(drgn_test_singular_list);

struct drgn_test_list_entry {
	struct list_head node;
	int value;
};

struct drgn_test_list_entry drgn_test_list_entries[3];
struct drgn_test_list_entry drgn_test_singular_list_entry;

HLIST_HEAD(drgn_test_empty_hlist);
HLIST_HEAD(drgn_test_full_hlist);

struct drgn_test_hlist_entry {
	struct hlist_node node;
	int value;
};

struct drgn_test_hlist_entry drgn_test_hlist_entries[3];

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
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_rb_entries); i++) {
		drgn_test_rb_entries[i].value = i;
		drgn_test_rbtree_insert(&drgn_test_rb_root,
					&drgn_test_rb_entries[i]);
	}
	RB_CLEAR_NODE(&drgn_test_empty_rb_node);
}

static int __init drgn_test_init(void)
{
	drgn_test_list_init();
	drgn_test_rbtree_init();
	return 0;
}

static void __exit drgn_test_exit(void)
{
}

module_init(drgn_test_init);
module_exit(drgn_test_exit);

MODULE_LICENSE("GPL");
