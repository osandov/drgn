// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Type lookup and caching.
 *
 * See @ref TypeIndex.
 */

#ifndef DRGN_TYPE_INDEX_H
#define DRGN_TYPE_INDEX_H

#include <elfutils/libdw.h>

#include "drgn.h"
#include "hash_table.h"
#include "language.h"
#include "type.h"

/**
 * @ingroup Internals
 *
 * @defgroup TypeIndex Type index
 *
 * Type lookup and caching.
 *
 * @ref drgn_type_index provides a common interface for finding types in a
 * program.
 *
 * @{
 */

struct drgn_language;
struct drgn_type_index;

/** Type index operations. */
struct drgn_type_index_ops {
	/** Implements @ref drgn_type_index_destroy(). */
	void (*destroy)(struct drgn_type_index *tindex);
	/** Implements @ref drgn_type_index_find_internal(). */
	struct drgn_error *(*find)(struct drgn_type_index *tindex,
				   enum drgn_type_kind kind,
				   const char *name, size_t name_len,
				   const char *filename,
				   struct drgn_qualified_type *ret);
};

DEFINE_HASH_SET_TYPES(drgn_pointer_type_set, struct drgn_type *)
DEFINE_HASH_SET_TYPES(drgn_array_type_set, struct drgn_type *)

/**
 * Abstract type index.
 *
 * A type index is used to find types by name and cache the results. It is
 * usually backed by debugging information (@ref drgn_dwarf_type_index). It can
 * also be backed by manually-created types for testing (@ref
 * drgn_mock_type_index).
 *
 * @ref drgn_type_index_find() searches for a type. @ref
 * drgn_type_index_pointer_type(), @ref drgn_type_index_array_type(), and @ref
 * drgn_type_index_incomplete_array_type() create derived types. Any type
 * returned by these is valid until the type index is destroyed with @ref
 * drgn_type_index_destroy().
 */
struct drgn_type_index {
	/** Operation dispatch table. */
	const struct drgn_type_index_ops *ops;
	/** Cached primitive types. */
	struct drgn_type *primitive_types[DRGN_PRIMITIVE_TYPE_NUM];
	/** Cache of created pointer types. */
	struct drgn_pointer_type_set pointer_types;
	/** Cache of created array types. */
	struct drgn_array_type_set array_types;
	/** Default size of a pointer in bytes. */
	uint8_t word_size;
	/** Default endianness of types. */
	bool little_endian;
};

/**
 * Initialize the common part of a @ref drgn_type_index.
 *
 * This should only be called by type index implementations. It initializes @ref
 * drgn_type_index::primitive_types to a default set of types based on @p
 * word_size. The implementation should override the C types with the
 * definitions that it finds.
 *
 * @param[in] tindex Type index to initialize.
 * @param[in] ops Operation dispatch table.
 * @param[in] word_size Default size of a pointer in bytes.
 * @param[in] little_endian Default endianness of types.
 */
void drgn_type_index_init(struct drgn_type_index *tindex,
			  const struct drgn_type_index_ops *ops,
			  uint8_t word_size, bool little_endian);

/**
 * Free the common part of a @ref drgn_type_index.
 *
 * This should only be called by implementations of @ref
 * drgn_type_index_ops::destroy().
 *
 * @param[in] tindex Type index to deinitialize.
 */
void drgn_type_index_deinit(struct drgn_type_index *tindex);

/**
 * Free a @ref drgn_type_index.
 *
 * @param[in] tindex Type index to destroy.
 */
static inline void drgn_type_index_destroy(struct drgn_type_index *tindex)
{
	if (tindex)
		tindex->ops->destroy(tindex);
}

/**
 * Find a type in a @ref drgn_type_index.
 *
 * The returned type is valid for the lifetime of the @ref drgn_type_index.
 *
 * @param[in] tindex Type index.
 * @param[in] name Name of the type.
 * @param[in] filename Exact filename containing the type definition, or @c NULL
 * for any definition.
 * @param[in] lang Language to use to parse @p name.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_type_index_find(struct drgn_type_index *tindex, const char *name,
		     const char *filename, const struct drgn_language *lang,
		     struct drgn_qualified_type *ret)
{
	return lang->find_type(tindex, name, filename, ret);
}

/**
 * Create a pointer type.
 *
 * The created type is cached for the lifetime of the @ref drgn_type_index. If
 * the same @p size and @p referenced_type are passed, the same type will be
 * returned.
 *
 * If this succeeds, @p referenced_type must remain valid until @p tindex is
 * destroyed.
 *
 * @param[in] tindex Type index.
 * @param[in] size Size of the type in bytes.
 * @param[in] referenced_type Type referenced by the pointer type.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_index_pointer_type(struct drgn_type_index *tindex, uint64_t size,
			     struct drgn_qualified_type referenced_type,
			     struct drgn_type **ret);

/**
 * Create an array type.
 *
 * The created type is cached for the lifetime of the @ref drgn_type_index. If
 * the same @p length and @p element_type are passed, the same type will be
 * returned.
 *
 * If this succeeds, @p element_type must remain valid until @p tindex is
 * destroyed.
 *
 * @param[in] tindex Type index.
 * @param[in] length Number of elements in the array type.
 * @param[in] element_type Type of an element in the array type.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_index_array_type(struct drgn_type_index *tindex, uint64_t length,
			   struct drgn_qualified_type element_type,
			   struct drgn_type **ret);

/**
 * Create an incomplete array type.
 *
 * The created type is cached for the lifetime of the @ref drgn_type_index. If
 * the same @p element_type is passed, the same type will be returned.
 *
 * If this succeeds, @p element_type must remain valid until @p tindex is
 * destroyed.
 *
 * @param[in] tindex Type index.
 * @param[in] element_type Type of an element in the array type.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_index_incomplete_array_type(struct drgn_type_index *tindex,
				      struct drgn_qualified_type element_type,
				      struct drgn_type **ret);

/**
 * Find a parsed type in a @ref drgn_type_index.
 *
 * This should only be called by implementations of @ref
 * drgn_language::find_type().
 *
 * @param[in] kind Kind of type to find. Must be @ref DRGN_TYPE_STRUCT, @ref
 * DRGN_TYPE_UNION, @ref DRGN_TYPE_ENUM, or @ref DRGN_TYPE_TYPEDEF.
 * @param[in] name Name of the type.
 * @param[in] name_len Length of @p name in bytes.
 * @param[in] filename See @ref drgn_type_index_find().
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_type_index_find_internal(struct drgn_type_index *tindex,
			      enum drgn_type_kind kind, const char *name,
			      size_t name_len, const char *filename,
			      struct drgn_qualified_type *ret)
{
	return tindex->ops->find(tindex, kind, name, name_len, filename, ret);
}

/**
 * Create a @ref drgn_error for a type which could not be found in a @ref
 * drgn_type_index.
 *
 * This is a helper for implementations of @ref drgn_type_index_ops::find().
 *
 * @param[in] kind Kind of type which could not be found. Must be @ref
 * DRGN_TYPE_STRUCT, @ref DRGN_TYPE_UNION, @ref DRGN_TYPE_ENUM, or @ref
 * DRGN_TYPE_TYPEDEF.
 * @param[in] name Name of the type.
 * @param[in] name_len Length of @p name in bytes.
 * @param[in] filename Filename that was searched in or @c NULL.
 */
struct drgn_error *
drgn_type_index_not_found_error(enum drgn_type_kind kind, const char *name,
				size_t name_len, const char *filename)
	__attribute__((returns_nonnull));

/** Type indexed by a @ref drgn_mock_type_index. */
struct drgn_mock_type {
	/** Type. */
	struct drgn_type *type;
	/**
	 * Name of the file that the type is defined in.
	 *
	 * This may be @c NULL, in which case no filename will match it.
	 */
	const char *filename;
};

/**
 * Type index backed by manually-defined types.
 *
 * This is mostly useful for testing. It is created with @ref
 * drgn_mock_type_index_create().
 */
struct drgn_mock_type_index {
	/** Abstract type index. */
	struct drgn_type_index tindex;
	/** Indexed types. */
	struct drgn_mock_type *types;
	/** Number of types. */
	size_t num_types;
};

/**
 * Create a @ref drgn_mock_type_index_create.
 *
 * @param[in] word_size See @ref drgn_type_index_init().
 * @param[in] little_endian See @ref drgn_type_index_init().
 * @param[in] types Types to index. This will not be freed when the type index
 * is destroyed.
 * @param[in] num_types Number of types.
 * @param[out] ret Returned type index.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_mock_type_index_create(uint8_t word_size, bool little_endian,
			    struct drgn_mock_type *types, size_t num_types,
			    struct drgn_mock_type_index **ret);

/** Cached type in a @ref drgn_dwarf_type_index. */
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

/** Type index backed by DWARF debugging information. */
struct drgn_dwarf_type_index {
	/** Abstract type index. */
	struct drgn_type_index tindex;
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

/**
 * Create a @ref drgn_dwarf_type_index.
 *
 * @param[in] dindex Index of DWARF debugging information.
 * @param[out] ret Returned type index.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_dwarf_type_index_create(struct drgn_dwarf_index *dindex,
			     struct drgn_dwarf_type_index **ret);

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
 * @param[in] dtindex DWARF type index.
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
drgn_type_from_dwarf_internal(struct drgn_dwarf_type_index *dtindex,
			      Dwarf_Die *die, bool can_be_incomplete_array,
			      bool *is_incomplete_array_ret,
			      struct drgn_qualified_type *ret);

/**
 * Parse a type from a DWARF debugging information entry.
 *
 * @param[in] dtindex DWARF type index.
 * @param[in] die DIE to parse.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_type_from_dwarf(struct drgn_dwarf_type_index *dtindex, Dwarf_Die *die,
		     struct drgn_qualified_type *ret)
{
	return drgn_type_from_dwarf_internal(dtindex, die, true, NULL, ret);
}

/**
 * Parse a type from the @c DW_AT_type attribute of a DWARF debugging
 * information entry.
 *
 * See @ref drgn_type_from_dwarf_child() and @ref
 * drgn_type_from_dwarf_internal().
 */
struct drgn_error *
drgn_type_from_dwarf_child_internal(struct drgn_dwarf_type_index *dtindex,
				    Dwarf_Die *parent_die, const char *tag_name,
				    bool can_be_void,
				    bool can_be_incomplete_array,
				    bool *is_incomplete_array_ret,
				    struct drgn_qualified_type *ret);

/**
 * Parse a type from the @c DW_AT_type attribute of a DWARF debugging
 * information entry.
 *
 * @param[in] dtindex DWARF type index.
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
drgn_type_from_dwarf_child(struct drgn_dwarf_type_index *dtindex,
			   Dwarf_Die *parent_die, const char *tag_name,
			   bool can_be_void, struct drgn_qualified_type *ret)
{
	return drgn_type_from_dwarf_child_internal(dtindex, parent_die,
						   tag_name, can_be_void, true,
						   NULL, ret);
}

/** @} */

#endif /* DRGN_TYPE_INDEX_H */
