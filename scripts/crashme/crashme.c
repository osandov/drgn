// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "crashme.h"

__attribute__((__noipa__)) static int c(struct crashme *cm)
{
	*cm->ptr = 0xdeadbeef;
	return 3;
}

__attribute__((__noipa__)) static int b(struct crashme *cm)
{
	return c(cm) - 1;
}

__attribute__((__noipa__)) static int a(struct crashme *cm)
{
	return b(cm) - 1;
}

int crashme(struct crashme *cm)
{
	return cm->ptr == crashme_ptr() ? a(cm) - 1 : 1;
}
