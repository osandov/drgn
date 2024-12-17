// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "crashme.h"

__attribute__((__visibility__("hidden")))
int *crashme_ptr(void)
{
	return (int *)0xabc;
}
