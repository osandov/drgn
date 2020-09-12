// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Debugging information handling.
 *
 * See @ref DebugInfo.
 */

#ifndef DRGN_DEBUG_INFO_H
#define DRGN_DEBUG_INFO_H

#include "drgn.h"
#include "dwarf_index.h"
#include "hash_table.h"

/**
 * @ingroup Internals
 *
 * @defgroup DebugInfo Debugging information cache
 *
 * Caching of debugging information.
 *
 * @ref drgn_debug_info caches debugging information (currently only DWARF). It
 * translates the debugging information to types and objects.
 *
 * @{
 */

/** Cached type in a @ref drgn_debug_info. */
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
};

DEFINE_HASH_MAP_TYPE(drgn_dwarf_type_map, const void *, struct drgn_dwarf_type);

/** Cache of debugging information. */
struct drgn_debug_info {
	/** Index of DWARF debugging information. */
	struct drgn_dwarf_index dindex;
	/**
	 * Cache of parsed types.
	 *
	 * The key is the address of the DIE (@c Dwarf_Die::addr). The value is
	 * a @ref drgn_dwarf_type.
	 */
	struct drgn_dwarf_type_map types;
	/**
	 * Cache of parsed types which appear to be incomplete array types but
	 * can't be.
	 *
	 * See @ref drgn_type_from_dwarf_internal().
	 */
	struct drgn_dwarf_type_map cant_be_incomplete_array_types;
	/** Current parsing recursion depth. */
	int depth;
	/** Program owning this cache. */
	struct drgn_program *prog;
};

/** Create a @ref drgn_debug_info. */
struct drgn_error *drgn_debug_info_create(struct drgn_program *prog,
					  const Dwfl_Callbacks *dwfl_callbacks,
					  struct drgn_debug_info **ret);

/** Destroy a @ref drgn_debug_info. */
void drgn_debug_info_destroy(struct drgn_debug_info *dbinfo);

/** @ref drgn_type_find_fn() that uses debugging information. */
struct drgn_error *drgn_debug_info_find_type(enum drgn_type_kind kind,
					     const char *name, size_t name_len,
					     const char *filename, void *arg,
					     struct drgn_qualified_type *ret);

/** @ref drgn_object_find_fn() that uses debugging information. */
struct drgn_error *
drgn_debug_info_find_object(const char *name, size_t name_len,
			    const char *filename,
			    enum drgn_find_object_flags flags, void *arg,
			    struct drgn_object *ret);

/** @} */

#endif /* DRGN_DEBUG_INFO_H */
