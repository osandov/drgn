// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_PLATFORM_H
#define DRGN_PLATFORM_H

#include <gelf.h>

#include "drgn.h"

struct drgn_architecture_info {
	const char *name;
	enum drgn_architecture arch;
	enum drgn_platform_flags default_flags;
};

extern const struct drgn_architecture_info arch_info_unknown;
extern const struct drgn_architecture_info arch_info_x86_64;

struct drgn_platform {
	const struct drgn_architecture_info *arch;
	enum drgn_platform_flags flags;
};

/**
 * Initialize a @ref drgn_platform from an architecture, word size, and
 * endianness.
 *
 * The default flags for the architecture are used other than the word size and
 * endianness.
 */
void drgn_platform_from_arch(const struct drgn_architecture_info *arch,
			     bool is_64_bit, bool is_little_endian,
			     struct drgn_platform *ret);

/** Initialize a @ref drgn_platform from an ELF header. */
void drgn_platform_from_elf(GElf_Ehdr *ehdr, struct drgn_platform *ret);

#endif /* DRGN_PLATFORM_H */
