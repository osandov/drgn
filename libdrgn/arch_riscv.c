// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <byteswap.h>

#include "platform.h" // IWYU pragma: associated

/*
 * The ABI specification can be found at:
 * https://github.com/riscv-non-isa/riscv-elf-psabi-doc
 */

static struct drgn_error drgn_invalid_rel = {
	.code = DRGN_ERROR_OTHER,
	.message = "invalid relocation type for SHT_REL",
};

static struct drgn_error *
apply_elf_reloc_riscv(const struct drgn_relocating_section *relocating,
		      uint64_t r_offset, uint32_t r_type, const int64_t *r_addend,
		      uint64_t sym_value)
{
	switch (r_type) {
	case R_RISCV_NONE:
		return NULL;
	case R_RISCV_32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	case R_RISCV_64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value);
#define CASE_R_RISCV_ADD_SUB(bits)						\
	case R_RISCV_ADD##bits: {						\
		if (!r_addend)							\
			return &drgn_invalid_rel;				\
		uint##bits##_t value;						\
		if (r_offset > relocating->buf_size ||				\
		    relocating->buf_size - r_offset < sizeof(value))		\
			return &drgn_invalid_relocation_offset;			\
		memcpy(&value, relocating->buf + r_offset, sizeof(value));	\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
		value += sym_value + *r_addend;					\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
		memcpy(relocating->buf + r_offset, &value, sizeof(value));	\
		return NULL;							\
	}									\
	case R_RISCV_SUB##bits: {						\
		if (!r_addend)							\
			return &drgn_invalid_rel;				\
		uint##bits##_t value;						\
		if (r_offset > relocating->buf_size ||				\
		    relocating->buf_size - r_offset < sizeof(value))		\
			return &drgn_invalid_relocation_offset;			\
		memcpy(&value, relocating->buf + r_offset, sizeof(value));	\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
		value -= sym_value + *r_addend;					\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
		memcpy(relocating->buf + r_offset, &value, sizeof(value));	\
		return NULL;							\
	}
#define bswap_8(x) (x)
	CASE_R_RISCV_ADD_SUB(8)
#undef bswap_8
	CASE_R_RISCV_ADD_SUB(16)
	CASE_R_RISCV_ADD_SUB(32)
	CASE_R_RISCV_ADD_SUB(64)
#undef CASE_R_RISCV_ADD_SUB
	case R_RISCV_SUB6: {
		if (!r_addend)
			return &drgn_invalid_rel;
		uint8_t value;
		if (r_offset > relocating->buf_size ||
		    relocating->buf_size - r_offset < sizeof(value))
			return &drgn_invalid_relocation_offset;
		memcpy(&value, relocating->buf + r_offset, sizeof(value));
		value = ((value & 0xc0) |
			 (((value & 0x3f) - (sym_value + *r_addend)) & 0x3f));
		memcpy(relocating->buf + r_offset, &value, sizeof(value));
		return NULL;
	}
	case R_RISCV_SET6: {
		if (!r_addend)
			return &drgn_invalid_rel;
		uint8_t value;
		if (r_offset > relocating->buf_size ||
		    relocating->buf_size - r_offset < sizeof(value))
			return &drgn_invalid_relocation_offset;
		memcpy(&value, relocating->buf + r_offset, sizeof(value));
		value = (value & 0xc0) | ((sym_value + *r_addend) & 0x3f);
		memcpy(relocating->buf + r_offset, &value, sizeof(value));
		return NULL;
	}
	case R_RISCV_SET8:
		return drgn_reloc_add8(relocating, r_offset, r_addend,
				       sym_value);
	case R_RISCV_SET16:
		return drgn_reloc_add16(relocating, r_offset, r_addend,
					sym_value);
	case R_RISCV_SET32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	default:
		return DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
	}
}

const struct drgn_architecture_info arch_info_riscv64 = {
	.name = "RISC-V 64",
	.arch = DRGN_ARCH_RISCV64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	.register_by_name = drgn_register_by_name_unknown,
	.apply_elf_reloc = apply_elf_reloc_riscv,
};

const struct drgn_architecture_info arch_info_riscv32 = {
	.name = "RISC-V 32",
	.arch = DRGN_ARCH_RISCV32,
	.default_flags = DRGN_PLATFORM_IS_LITTLE_ENDIAN,
	.register_by_name = drgn_register_by_name_unknown,
	.apply_elf_reloc = apply_elf_reloc_riscv,
};
