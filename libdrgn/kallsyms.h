// Copyright (c) 2023 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Kallsyms data handling
 *
 * See @ref Kallsyms
 */

#ifndef DRGN_KALLSYMS_H
#define DRGN_KALLSYMS_H

#include <stdint.h>
#include <sys/types.h>

#include "hash_table.h"

struct drgn_program;
struct drgn_module;
struct vmcoreinfo;
enum drgn_find_symbol_flags;
struct drgn_symbol_result_builder;

struct kallsyms_locations {
	uint64_t kallsyms_names;
	uint64_t kallsyms_token_table;
	uint64_t kallsyms_token_index;
	uint64_t kallsyms_num_syms;
	uint64_t kallsyms_offsets;
	uint64_t kallsyms_relative_base;
	uint64_t kallsyms_addresses;
	uint64_t _stext;
};

/**
 * @ingroup KernelInfo
 *
 * @defgroup Kallsyms Kallsyms symbol table
 *
 * Using the kallsyms data from within the program as a symbol table.
 *
 * @{
 */

struct symbol_entry {
	uint32_t start;
	uint32_t end;
};

DEFINE_HASH_MAP(drgn_kallsyms_names, char *, struct symbol_entry,
		c_string_key_hash_pair, c_string_key_eq);

/**
 * Holds kallsyms data copied from the kernel
 *
 * Kallsyms data are in increasing sorted order by address. Each symbol is
 * identified by its index, which we can assume fits in a uint32_t. The
 * essential data is stored in arrays of length "num_syms": the memory address,
 * the symbol type, and the index into the string table.
 *
 * Strings are stored in a single buffer, all concatenated together and
 * separated by nul bytes.
 */
struct kallsyms_finder {
	/** Program owning this registry */
	struct drgn_program *prog;

	/** Number of symbols */
	uint32_t num_syms;
	/** Array of symbol addresses */
	uint64_t *addresses;
	/** Array of one-character type codes*/
	char *types;
	/** Array of symbol names */
	uint32_t *names;

	/** Buffer backing the symbols array, all point into here */
	char *strings;
	/** Bytes used of symbol buffer array */
	uint32_t strings_len;

	/** Array of symbol indices, sorted by name. Used by the htab. */
	uint32_t *sorted;
	/** Map of symbol names to index */
	struct drgn_kallsyms_names htab;
};


/**
 * Initialize kallsyms data
 *
 * Search for a kallsyms symbol table, and if found, attempt to load it. On
 * success, a kallsyms registry is returned in @a ret. If the kallsyms data is
 * not found (a common failure mode), NULL will be returned to indicate no
 * error, but @a ret will not be set. This indicates that initialization should
 * continue. If an error occurs parsing the kallsyms data once it is found, the
 * error will be returned.
 *
 * @param prog Program to search
 * @param vi vmcoreinfo from the crash dump
 * @param[out] ret Created registry
 * @returns NULL on success, or when kallsyms data is not found
 */
struct drgn_error *drgn_kallsyms_init(struct kallsyms_finder *reg,
				      struct drgn_program *prog,
				      struct kallsyms_locations *locations);

/**
 * Find a symbol using the symbol finder object
 *
 * This object may be passed to drgn_program_add_symbol_finder, along with a
 * pointer to the struct kallsyms_finder, in order to find symbols in the
 * vmlinux kallsyms.
 */
struct drgn_error *
drgn_kallsyms_symbol_finder(const char *name, uint64_t address,
			    enum drgn_find_symbol_flags flags, void *arg,
			    struct drgn_symbol_result_builder *builder);

/**
 * Destroy kallsyms data
 *
 * Frees all resources held by the kallsyms finder. Please note that if the
 * finder has been added to the program, then this *will* cause errors.
 *
 * @param kr Finder to destroy
 */
void drgn_kallsyms_destroy(struct kallsyms_finder *kr);

/** @} */

#endif // DRGN_KALLSYMS_H
