// Copyright (c) 2022 Oracle and/or its affiliates
// SPDX-License-Identifier: GPL-3.0-or-later

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

struct drgn_program;
struct vmcoreinfo;

/**
 * @ingroup KernelInfo
 *
 * @defgroup Kallsyms Kallsyms symbol table
 *
 * Using the kallsyms data from within the program as a symbol table.
 *
 * @{
 */

/** Holds kallsyms data copied from the kernel */
struct kallsyms_registry {
	/** Program owning this registry */
	struct drgn_program *prog;
	/** Number of symbols contained */
	uint32_t num_syms;
	/** Array of symbol names */
	char **symbols;
	/** Buffer backing the symbols array, all point into here */
	char *symbol_buffer;
	/** Array of symbol addresses */
	uint64_t *addresses;
	/** Array of one-character type codes*/
	char *types;
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
struct drgn_error *drgn_kallsyms_create(struct drgn_program *prog,
				        struct vmcoreinfo *vi,
					struct kallsyms_registry **kr_out);

/** @} */

#endif // DRGN_KALLSYMS_H
