// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <elf.h>
#include <stdlib.h>

#include "platform.h"
#include "util.h"

static const struct drgn_register *register_by_name_unknown(const char *name)
{
	return NULL;
}

const struct drgn_architecture_info arch_info_unknown = {
	.name = "unknown",
	.arch = DRGN_ARCH_UNKNOWN,
	.register_by_name = register_by_name_unknown,
};

LIBDRGN_PUBLIC const struct drgn_platform drgn_host_platform = {
#ifdef __x86_64__
	.arch = &arch_info_x86_64,
#elif __powerpc64__
	.arch = &arch_info_ppc64,
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
	case DRGN_ARCH_PPC64:
		arch_info = &arch_info_ppc64;
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
	case EM_PPC64:
		arch = &arch_info_ppc64;
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
