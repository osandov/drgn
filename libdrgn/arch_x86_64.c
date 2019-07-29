// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "platform.h"

const struct drgn_architecture_info arch_info_x86_64 = {
	.name = "x86-64",
	.arch = DRGN_ARCH_X86_64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
};
