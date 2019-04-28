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

/**
 * Cache of types and symbols from DWARF debugging information.
 *
 * This is the argument for @ref drgn_dwarf_type_find() and @ref
 * drgn_dwarf_symbol_find().
 */
struct drgn_dwarf_info_cache {
	/** Type index. */
	struct drgn_type_index *tindex;
	/** Index of DWARF debugging information. */
	struct drgn_dwarf_index *dindex;
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
};

/** Create a @ref drgn_dwarf_info_cache. */
struct drgn_error *
drgn_dwarf_info_cache_create(struct drgn_type_index *tindex,
			     struct drgn_dwarf_index *dindex,
			     struct drgn_dwarf_info_cache **ret);

/** Destroy a @ref drgn_dwarf_info_cache. */
void drgn_dwarf_info_cache_destroy(struct drgn_dwarf_info_cache *dicache);

/** @ref drgn_type_find_fn() that uses DWARF debugging information. */
struct drgn_error *drgn_dwarf_type_find(enum drgn_type_kind kind,
					const char *name, size_t name_len,
					const char *filename, void *arg,
					struct drgn_qualified_type *ret);

/**
 * Parse a type from a DWARF debugging information entry.
 *
 * This is the same as @ref drgn_type_from_dwarf() except that it can be used to
 * work around a bug in GCC < 9.0 that zero length array types are encoded the
 * same as incomplete array types. There are a few places where GCC allows
 * zero-length arrays but not incomplete arrays:
 *
 * - As the type of a member of a structure with only one member.
 * - As the type of a structure member other than the last member.
 * - As the type of a union member.
 * - As the element type of an array.
 *
 * In these cases, we know that what appears to be an incomplete array type must
 * actually have a length of zero. In other cases, a subrange DIE without
 * DW_AT_count or DW_AT_upper_bound is ambiguous; we return an incomplete array
 * type.
 *
 * @param[in] dicache Debugging information cache.
 * @param[in] die DIE to parse.
 * @param[in] can_be_incomplete_array Whether the type can be an incomplete
 * array type. If this is @c false and the type appears to be an incomplete
 * array type, its length is set to zero instead.
 * @param[out] is_incomplete_array_ret Whether the encoded type is an incomplete
 * array type or a typedef of an incomplete array type (regardless of @p
 * can_be_incomplete_array).
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_from_dwarf_internal(struct drgn_dwarf_info_cache *dicache,
			      Dwarf_Die *die, bool can_be_incomplete_array,
			      bool *is_incomplete_array_ret,
			      struct drgn_qualified_type *ret);

/**
 * Parse a type from a DWARF debugging information entry.
 *
 * @param[in] dicache Debugging information cache.
 * @param[in] die DIE to parse.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_type_from_dwarf(struct drgn_dwarf_info_cache *dicache, Dwarf_Die *die,
		     struct drgn_qualified_type *ret)
{
	return drgn_type_from_dwarf_internal(dicache, die, true, NULL, ret);
}

/**
 * Parse a type from the @c DW_AT_type attribute of a DWARF debugging
 * information entry.
 *
 * See @ref drgn_type_from_dwarf_child() and @ref
 * drgn_type_from_dwarf_internal().
 */
struct drgn_error *
drgn_type_from_dwarf_child_internal(struct drgn_dwarf_info_cache *dicache,
				    Dwarf_Die *parent_die, const char *tag_name,
				    bool can_be_void,
				    bool can_be_incomplete_array,
				    bool *is_incomplete_array_ret,
				    struct drgn_qualified_type *ret);

/**
 * Parse a type from the @c DW_AT_type attribute of a DWARF debugging
 * information entry.
 *
 * @param[in] dicache Debugging information cache.
 * @param[in] parent_die Parent DIE.
 * @param[in] can_be_void Whether the @c DW_AT_type attribute may be missing,
 * which is interpreted as a void type. If this is false and the @c DW_AT_type
 * attribute is missing, an error is returned.
 * @param[in] tag_name Spelling of the DWARF tag of @p parent_die. Used for
 * error messages.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_type_from_dwarf_child(struct drgn_dwarf_info_cache *dicache,
			   Dwarf_Die *parent_die, const char *tag_name,
			   bool can_be_void, struct drgn_qualified_type *ret)
{
	return drgn_type_from_dwarf_child_internal(dicache, parent_die,
						   tag_name, can_be_void, true,
						   NULL, ret);
}

/** @} */

#endif /* DRGN_DWARF_INFO_CACHE_H */
