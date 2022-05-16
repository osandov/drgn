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

LIST_HEAD(drgn_test_empty_list);
LIST_HEAD(drgn_test_full_list);
LIST_HEAD(drgn_test_singular_list);

struct drgn_test_list_entry {
	struct list_head node;
	int value;
};

struct drgn_test_list_entry drgn_test_list_entries[3];
struct drgn_test_list_entry drgn_test_singular_list_entry;

static void drgn_test_list_init(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(drgn_test_list_entries); i++) {
		list_add_tail(&drgn_test_list_entries[i].node,
			      &drgn_test_full_list);
	}
	list_add(&drgn_test_singular_list_entry.node, &drgn_test_singular_list);
}

static int __init drgn_test_init(void)
{
	drgn_test_list_init();
	return 0;
}

static void __exit drgn_test_exit(void)
{
}

module_init(drgn_test_init);
module_exit(drgn_test_exit);

MODULE_LICENSE("GPL");
