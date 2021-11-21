// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DRGN_SYMBOL_H
#define DRGN_SYMBOL_H

#include <gelf.h>

#include "drgn.h"

struct drgn_symbol {
	const char *name;
	uint64_t address;
	uint64_t size;
	enum drgn_symbol_binding binding;
	enum drgn_symbol_kind kind;
};

/** Initialize a @ref drgn_symbol from an ELF symbol. */
void drgn_symbol_from_elf(const char *name, uint64_t address,
			  const GElf_Sym *elf_sym, struct drgn_symbol *ret);

#endif /* DRGN_SYMBOL_H */
