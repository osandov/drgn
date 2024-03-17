// Copyright (c) 2024 Oracle and/or its affiliates
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
#include "symbol.h"

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
 * Initialize a symbol index containing symbols from /proc/kallsyms
 */
struct drgn_error *drgn_load_proc_kallsyms(const char *filename, bool modules,
					   struct drgn_symbol_index *ret);

/**
 * Initialize a symbol index containing symbols from built-in kallsyms tables
 */
struct drgn_error *
drgn_load_builtin_kallsyms(struct drgn_program *prog,
			   struct kallsyms_locations *loc,
			   struct drgn_symbol_index *ret);

#endif // DRGN_KALLSYMS_H
