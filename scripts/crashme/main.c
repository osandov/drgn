// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "crashme.h"

int main(void)
{
	struct crashme cm = { crashme_ptr() };
	return !!crashme(&cm);
}
