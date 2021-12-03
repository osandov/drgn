// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "platform.h" // IWYU pragma: associated

static struct drgn_error *
apply_elf_reloc_s390(const struct drgn_relocating_section *relocating,
		     uint64_t r_offset, uint32_t r_type,
		     const int64_t *r_addend, uint64_t sym_value)
{
	switch (r_type) {
	case R_390_NONE:
		return NULL;
	case R_390_8:
		return drgn_reloc_add8(relocating, r_offset, r_addend,
				       sym_value);
	case R_390_16:
		return drgn_reloc_add16(relocating, r_offset, r_addend,
					sym_value);
	case R_390_32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	case R_390_PC32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	case R_390_PC16:
		return drgn_reloc_add16(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	case R_390_64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value);
	case R_390_PC64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	default:
		return DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
	}
}

const struct drgn_architecture_info arch_info_s390x = {
	.name = "s390x",
	.arch = DRGN_ARCH_S390X,
	.default_flags = DRGN_PLATFORM_IS_64_BIT,
	.register_by_name = drgn_register_by_name_unknown,
	.apply_elf_reloc = apply_elf_reloc_s390,
};

const struct drgn_architecture_info arch_info_s390 = {
	.name = "s390",
	.arch = DRGN_ARCH_S390,
	.default_flags = 0,
	.register_by_name = drgn_register_by_name_unknown,
	.apply_elf_reloc = apply_elf_reloc_s390,
};
