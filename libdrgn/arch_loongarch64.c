// Copyright (c) KylinSoft Corporation.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "platform.h" // IWYU pragma: associated

const struct drgn_architecture_info arch_info_loongarch64 = {
	.name = "LoongArch64",
	.arch = DRGN_ARCH_LOONGARCH64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	.scalar_alignment = { 1, 2, 4, 8, 16 },
	.register_by_name = drgn_register_by_name_unknown,
};
