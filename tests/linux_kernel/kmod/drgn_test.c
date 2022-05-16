// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

// Linux kernel module for testing drgn helpers and kernel support. For now,
// this is all in one file for simplicity and to keep the compilation fast
// (since this is compiled for every kernel version in CI).
//
// This is intended to be used with drgn's vmtest framework, but in theory it
// can be used with any kernel that has debug info enabled (at your own risk).

#include <linux/module.h>

static int __init drgn_test_init(void)
{
	return 0;
}

static void __exit drgn_test_exit(void)
{
}

module_init(drgn_test_init);
module_exit(drgn_test_exit);

MODULE_LICENSE("GPL");
