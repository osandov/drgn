// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

// DOCTODO

#ifndef DRGN_ELF_SYMBOL_H
#define DRGN_ELF_SYMBOL_H

#include "drgn_internal.h"

struct drgn_elf_file;

struct drgn_elf_symbol_table {
	struct drgn_elf_file *file;
	uint64_t bias;
	const char *data;
	size_t num_symbols;
	size_t num_local_symbols;
	Elf_Data *strtab;
	Elf_Data *shndx;
};

struct drgn_error *
drgn_module_elf_symbols_search(struct drgn_module *module, const char *name,
			       uint64_t addr, enum drgn_find_symbol_flags flags,
			       struct drgn_symbol_result_builder *builder);

#endif /* DRGN_ELF_SYMBOL_H */
