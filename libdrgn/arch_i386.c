// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "platform.h" // IWYU pragma: associated

static struct drgn_error *
apply_elf_reloc_i386(const struct drgn_relocating_section *relocating,
		     uint64_t r_offset, uint32_t r_type,
		     const int64_t *r_addend, uint64_t sym_value)
{
	switch (r_type) {
	case R_386_NONE:
		return NULL;
	case R_386_32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	case R_386_PC32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	default:
		return DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
	}
}

const struct drgn_architecture_info arch_info_i386 = {
	.name = "i386",
	.arch = DRGN_ARCH_I386,
	.default_flags = DRGN_PLATFORM_IS_LITTLE_ENDIAN,
	.register_by_name = drgn_register_by_name_unknown,
	.apply_elf_reloc = apply_elf_reloc_i386,
};
