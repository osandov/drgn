// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "platform.h" // IWYU pragma: associated

// Include the defs first so register macros are available to arch_riscv.h
#include "arch_riscv64_defs.inc"
#include "arch_riscv.h"

const struct drgn_architecture_info arch_info_riscv64 = {
	.name = "RISC-V 64",
	.arch = DRGN_ARCH_RISCV64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	.scalar_alignment = { 1, 2, 4, 8, 16 },
	DRGN_ARCHITECTURE_REGISTERS,
};
