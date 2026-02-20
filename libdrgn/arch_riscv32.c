// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "platform.h" // IWYU pragma: associated

// Include the defs first so register macros are available to arch_riscv.h
#include "arch_riscv32_defs.inc"
#include "arch_riscv.h"

const struct drgn_architecture_info arch_info_riscv32 = {
	.name = "RISC-V 32",
	.arch = DRGN_ARCH_RISCV32,
	.default_flags = DRGN_PLATFORM_IS_LITTLE_ENDIAN,
	.scalar_alignment = { 1, 2, 4, 8, 16 },
	DRGN_ARCHITECTURE_REGISTERS,
	.apply_elf_reloc = apply_elf_reloc_riscv,
	.default_dwarf_cfi_row = &default_dwarf_cfi_row_riscv,
	.fallback_unwind = fallback_unwind_riscv,
	.bad_call_unwind = bad_call_unwind_riscv,
	.pt_regs_get_initial_registers = pt_regs_get_initial_registers_riscv,
	.prstatus_get_initial_registers = prstatus_get_initial_registers_riscv,
	.linux_kernel_get_initial_registers = linux_kernel_get_initial_registers_riscv,
};
