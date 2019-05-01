// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Debugging information cache.
 *
 * See @ref DWARFInfoCache.
 */

#ifndef DRGN_DWARF_INFO_CACHE_H
#define DRGN_DWARF_INFO_CACHE_H

#include "drgn.h"
#include "hash_table.h"

/**
 * @ingroup Internals
 *
 * @defgroup DWARFInfoCache Debugging information cache
 *
 * Caching of DWARF debugging information.
 *
 * @ref drgn_dwarf_info_cache bridges the raw DWARF information indexed by @ref
 * drgn_dwarf_index to the higher-level @ref drgn_type_index and @ref
 * drgn_symbol_index.
 *
 * @{
 */

/** Cached type in a @ref drgn_dwarf_info_cache. */
struct drgn_dwarf_type {
	struct drgn_type *type;
	enum drgn_qualifiers qualifiers;
	/**
	 * Whether this is an incomplete array type or a typedef of one.
	 *
	 * This is used to work around a GCC bug; see @ref
	 * drgn_type_from_dwarf_internal().
	 */
	bool is_incomplete_array;
	/** Whether we need to free @c type. */
	bool should_free;
};

DEFINE_HASH_MAP_TYPES(dwarf_type_map, const void *, struct drgn_dwarf_type);

struct drgn_dwarf_index;
struct drgn_program;
struct drgn_symbol;

/**
 * Cache of types and symbols from DWARF debugging information.
 *
 * This is the argument for @ref drgn_dwarf_type_find() and @ref
 * drgn_dwarf_symbol_find().
 */
struct drgn_dwarf_info_cache {
	/** Index of DWARF debugging information. */
	struct drgn_dwarf_index dindex;
	/**
	 * Cache of parsed types.
	 *
	 * The key is the address of the DIE (@c Dwarf_Die::addr). The value is
	 * a @ref drgn_dwarf_type.
	 */
	struct dwarf_type_map map;
	/**
	 * Cache of parsed types which appear to be incomplete array types but
	 * can't be.
	 *
	 * See @ref drgn_type_from_dwarf_internal().
	 */
	struct dwarf_type_map cant_be_incomplete_array_map;
	/** Current parsing recursion depth. */
	int depth;
	/** Type index. */
	struct drgn_type_index *tindex;
	/** Program to pass to @c relocation_hook(). */
	struct drgn_program *prog;
	/**
	 * Relocation callback.
	 *
	 * Objects in an ELF file are often relocated when they are loaded into
	 * a program (e.g., shared libraries or position-independent
	 * executables). This callback can be used to adjust the address which
	 * was found in the DWARF debugging information entry for the symbol.
	 *
	 * On entry, @p sym is fully initialized and not a constant. This
	 * should look at @c sym->address and modify it as appropriate.
	 *
	 * @param[in] prog @ref drgn_dwarf_symbol_index::prog.
	 * @param[in] name Name of the symbol.
	 * @param[in] die DWARF DIE of the symbol.
	 * @param[in,out] sym Symbol to relocate.
	 * @return @c NULL on success, non-@c NULL on error.
	 */
	struct drgn_error *(*relocation_hook)(struct drgn_program *prog,
					      const char *name, Dwarf_Die *die,
					      struct drgn_symbol *sym);
};

/** Create a @ref drgn_dwarf_info_cache. */
struct drgn_error *
drgn_dwarf_info_cache_create(struct drgn_type_index *tindex,
			     struct drgn_dwarf_info_cache **ret);

/** Destroy a @ref drgn_dwarf_info_cache. */
void drgn_dwarf_info_cache_destroy(struct drgn_dwarf_info_cache *dicache);

/** @ref drgn_type_find_fn() that uses DWARF debugging information. */
struct drgn_error *drgn_dwarf_type_find(enum drgn_type_kind kind,
					const char *name, size_t name_len,
					const char *filename, void *arg,
					struct drgn_qualified_type *ret);

/** @ref drgn_symbol_find_fn() that uses DWARF debugging information. */
struct drgn_error *
drgn_dwarf_symbol_find(const char *name, size_t name_len, const char *filename,
		       enum drgn_find_object_flags flags, void *arg,
		       struct drgn_symbol *ret);

/** @} */

#endif /* DRGN_DWARF_INFO_CACHE_H */
