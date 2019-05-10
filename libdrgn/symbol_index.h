// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Symbol lookup.
 *
 * See @ref SymbolIndex.
 */

#ifndef DRGN_SYMBOL_INDEX_H
#define DRGN_SYMBOL_INDEX_H

#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup SymbolIndex Symbol index
 *
 * Symbol lookup.
 *
 * @ref drgn_symbol_index provides a common interface for finding symbols (e.g.,
 * variables, constants, and functions) in a program.
 *
 * @{
 */

/** Registered callback in a @ref drgn_symbol_index. */
struct drgn_symbol_finder {
	/** The callback. */
	drgn_symbol_find_fn fn;
	/** Argument to pass to @ref drgn_symbol_finder::fn. */
	void *arg;
	/** Next callback to try. */
	struct drgn_symbol_finder *next;
};

/**
 * Symbol index.
 *
 * A symbol index is used to find symbols (variables, constants, and functions)
 * by name. The types are found using callbacks which are registered with @ref
 * drgn_symbol_index_add_finder(). @ref drgn_symbol_index_find() searches for an
 * symbol.
 */
struct drgn_symbol_index {
	/** Callbacks for finding symbols. */
	struct drgn_symbol_finder *finders;
};

/** Initialize a @ref drgn_symbol_index. */
void drgn_symbol_index_init(struct drgn_symbol_index *sindex);

/** Deinitialize a @ref drgn_symbol_index. */
void drgn_symbol_index_deinit(struct drgn_symbol_index *sindex);

/** @sa drgn_program_add_symbol_finder() */
struct drgn_error *
drgn_symbol_index_add_finder(struct drgn_symbol_index *sindex,
			     drgn_symbol_find_fn fn, void *arg);

/**
 * Find a symbol in a @ref drgn_symbol_index.
 *
 * @param[in] sindex Symbol index.
 * @param[in] name Name of the symbol.
 * @param[in] filename Exact filename containing the symbol definition, or @c
 * NULL for any definition.
 * @param[in] flags Bitmask of @ref drgn_find_object_flags.
 * @param[out] ret Returned symbol.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_symbol_index_find(struct drgn_symbol_index *sindex,
					  const char *name,
					  const char *filename,
					  enum drgn_find_object_flags flags,
					  struct drgn_symbol *ret);

/** @} */

#endif /* DRGN_SYMBOL_INDEX_H */
