// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <byteswap.h>
#include <elf.h>
#include <stdlib.h>

#include "platform.h"
#include "util.h"

const struct drgn_register *drgn_register_by_name_unknown(const char *name)
{
	return NULL;
}

const struct drgn_architecture_info arch_info_unknown = {
	.name = "unknown",
	.arch = DRGN_ARCH_UNKNOWN,
	.register_by_name = drgn_register_by_name_unknown,
};

LIBDRGN_PUBLIC const struct drgn_platform drgn_host_platform = {
#if __x86_64__
	.arch = &arch_info_x86_64,
#elif __i386__
	.arch = &arch_info_i386,
#elif __aarch64__
	.arch = &arch_info_aarch64,
#elif __arm__
	.arch = &arch_info_arm,
#elif __powerpc64__
	.arch = &arch_info_ppc64,
#elif __riscv
#if __riscv_xlen == 64
	.arch = &arch_info_riscv64,
#elif __riscv_xlen == 32
	.arch = &arch_info_riscv32,
#else
#error "unknown __riscv_xlen"
#endif
#else
	.arch = &arch_info_unknown,
#endif
	.flags = ((sizeof(void *) == 8 ? DRGN_PLATFORM_IS_64_BIT : 0) |
		  (HOST_LITTLE_ENDIAN ? DRGN_PLATFORM_IS_LITTLE_ENDIAN : 0)),
};

LIBDRGN_PUBLIC struct drgn_error *
drgn_platform_create(enum drgn_architecture arch,
		     enum drgn_platform_flags flags, struct drgn_platform **ret)
{
	const struct drgn_architecture_info *arch_info;
	struct drgn_platform *platform;

	SWITCH_ENUM_DEFAULT(arch,
	case DRGN_ARCH_UNKNOWN:
		arch_info = &arch_info_unknown;
		break;
	case DRGN_ARCH_X86_64:
		arch_info = &arch_info_x86_64;
		break;
	case DRGN_ARCH_I386:
		arch_info = &arch_info_i386;
		break;
	case DRGN_ARCH_AARCH64:
		arch_info = &arch_info_aarch64;
		break;
	case DRGN_ARCH_ARM:
		arch_info = &arch_info_arm;
		break;
	case DRGN_ARCH_PPC64:
		arch_info = &arch_info_ppc64;
		break;
	case DRGN_ARCH_RISCV64:
		arch_info = &arch_info_riscv64;
		break;
	case DRGN_ARCH_RISCV32:
		arch_info = &arch_info_riscv32;
		break;
	default:
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid architecture");
	)
	if (flags == DRGN_PLATFORM_DEFAULT_FLAGS) {
		if (arch == DRGN_ARCH_UNKNOWN) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "cannot get default platform flags of unknown architecture");
		}
		flags = arch_info->default_flags;
	} else if (flags & ~DRGN_ALL_PLATFORM_FLAGS) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid platform flags");
	}
	platform = malloc(sizeof(*platform));
	if (!platform)
		return &drgn_enomem;
	platform->arch = arch_info;
	platform->flags = flags;
	*ret = platform;
	return NULL;
}

LIBDRGN_PUBLIC void drgn_platform_destroy(struct drgn_platform *platform)
{
	free(platform);
}

LIBDRGN_PUBLIC enum drgn_architecture
drgn_platform_arch(const struct drgn_platform *platform)
{
	return platform->arch->arch;
}

LIBDRGN_PUBLIC enum drgn_platform_flags
drgn_platform_flags(const struct drgn_platform *platform)
{
	return platform->flags;
}

LIBDRGN_PUBLIC bool drgn_platform_eq(struct drgn_platform *a,
				     struct drgn_platform *b)
{
	return a->arch == b->arch && a->flags == b->flags;
}

void drgn_platform_from_arch(const struct drgn_architecture_info *arch,
			     bool is_64_bit, bool is_little_endian,
			     struct drgn_platform *ret)
{
	ret->arch = arch;
	ret->flags = (arch->default_flags &
		      ~(DRGN_PLATFORM_IS_64_BIT | DRGN_PLATFORM_IS_LITTLE_ENDIAN));
	if (is_64_bit)
		ret->flags |= DRGN_PLATFORM_IS_64_BIT;
	if (is_little_endian)
		ret->flags |= DRGN_PLATFORM_IS_LITTLE_ENDIAN;
}

void drgn_platform_from_elf(GElf_Ehdr *ehdr, struct drgn_platform *ret)
{
	const struct drgn_architecture_info *arch;

	switch (ehdr->e_machine) {
	case EM_X86_64:
		arch = &arch_info_x86_64;
		break;
	case EM_386:
		arch = &arch_info_i386;
		break;
	case EM_AARCH64:
		arch = &arch_info_aarch64;
		break;
	case EM_ARM:
		arch = &arch_info_arm;
		break;
	case EM_PPC64:
		arch = &arch_info_ppc64;
		break;
	case EM_RISCV:
		if (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
			arch = &arch_info_riscv64;
		else
			arch = &arch_info_riscv32;
		break;
	default:
		arch = &arch_info_unknown;
		break;
	}
	drgn_platform_from_arch(arch, ehdr->e_ident[EI_CLASS] == ELFCLASS64,
				ehdr->e_ident[EI_DATA] == ELFDATA2LSB, ret);
}

LIBDRGN_PUBLIC size_t
drgn_platform_num_registers(const struct drgn_platform *platform)
{
	return platform->arch->num_registers;
}

LIBDRGN_PUBLIC const struct drgn_register *
drgn_platform_register(const struct drgn_platform *platform, size_t n)
{
	return &platform->arch->registers[n];
}

LIBDRGN_PUBLIC const struct drgn_register *
drgn_platform_register_by_name(const struct drgn_platform *platform,
			       const char *name)
{
	return platform->arch->register_by_name(name);
}

LIBDRGN_PUBLIC const char * const *
drgn_register_names(const struct drgn_register *reg, size_t *num_names_ret)
{
	*num_names_ret = reg->num_names;
	return reg->names;
}

struct drgn_error drgn_invalid_relocation_offset = {
	.code = DRGN_ERROR_OTHER,
	.message = "invalid relocation offset",
};

#define DEFINE_DRGN_RELOC_ADD(bits)						\
struct drgn_error *								\
drgn_reloc_add##bits(const struct drgn_relocating_section *relocating,		\
		     uint64_t r_offset, const int64_t *r_addend,		\
		     uint##bits##_t addend)					\
{										\
	uint##bits##_t value;							\
	if (r_offset > relocating->buf_size ||					\
	    relocating->buf_size - r_offset < sizeof(value))			\
		return &drgn_invalid_relocation_offset;				\
	if (r_addend) {								\
		value = *r_addend;						\
	} else {								\
		memcpy(&value, relocating->buf + r_offset, sizeof(value));	\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
	}									\
	value += addend;							\
	if (relocating->bswap)							\
		value = bswap_##bits(value);					\
	memcpy(relocating->buf + r_offset, &value, sizeof(value));		\
	return NULL;								\
}
DEFINE_DRGN_RELOC_ADD(64)
DEFINE_DRGN_RELOC_ADD(32)
DEFINE_DRGN_RELOC_ADD(16)
#define bswap_8(x) (x)
DEFINE_DRGN_RELOC_ADD(8)
#undef bswap_8
#undef DEFINE_DRGN_RELOC_ADD
