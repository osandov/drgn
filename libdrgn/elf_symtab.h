// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * ELF symbol tables.
 *
 * See @ref ElfSymtab.
 */

#ifndef DRGN_ELF_SYMBOL_H
#define DRGN_ELF_SYMBOL_H

#include "drgn_internal.h"

struct drgn_elf_file;

/**
 * @ingroup Internals
 *
 * @defgroup ElfSymtab ELF symbol tables
 *
 * ELF symbol table lookups.
 *
 * @{
 */

/** Symbol table from an ELF file. */
struct drgn_elf_symbol_table {
	/** File containing symbol table. @c NULL if not found yet. */
	struct drgn_elf_file *file;
	/** Bias to apply to addresses from the file. */
	uint64_t bias;
	/** Symbol table section data. */
	const char *data;
	/** Number of symbols in table. */
	size_t num_symbols;
	/** Number of local symbols in table. */
	size_t num_local_symbols;
	/** String table section used by symbol table. */
	Elf_Data *strtab;
	/** Optional `SHT_SYMTAB_SHNDX` section used by symbol table. */
	Elf_Data *shndx;
};

/** Find matching ELF symbols in a specific module. */
struct drgn_error *
drgn_module_elf_symbols_search(struct drgn_module *module, const char *name,
			       uint64_t addr, enum drgn_find_symbol_flags flags,
			       struct drgn_symbol_result_builder *builder);

/** @} */

#endif /* DRGN_ELF_SYMBOL_H */
