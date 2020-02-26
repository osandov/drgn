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

struct drgn_pointer_type_key {
	struct drgn_type *type;
	enum drgn_qualifiers qualifiers;
	const struct drgn_language *lang;
};

static struct drgn_pointer_type_key
drgn_pointer_type_entry_to_key(struct drgn_type * const *entry)
{
	struct drgn_qualified_type referenced_type = drgn_type_type(*entry);

	return (struct drgn_pointer_type_key){
		.type = referenced_type.type,
		.qualifiers = referenced_type.qualifiers,
		.lang = drgn_type_language(*entry),
	};
}

struct drgn_array_type_key {
	struct drgn_type *type;
	enum drgn_qualifiers qualifiers;
	bool is_complete;
	uint64_t length;
	const struct drgn_language *lang;
};

static struct drgn_array_type_key
drgn_array_type_entry_to_key(struct drgn_type * const *entry)
{
	struct drgn_qualified_type element_type = drgn_type_type(*entry);

	return (struct drgn_array_type_key){
		.type = element_type.type,
		.qualifiers = element_type.qualifiers,
		.is_complete = drgn_type_is_complete(*entry),
		.length = drgn_type_length(*entry),
		.lang = drgn_type_language(*entry),
	};
}

DEFINE_HASH_TABLE_TYPE(drgn_pointer_type_table, struct drgn_type *,
		       drgn_pointer_type_entry_to_key)
DEFINE_HASH_TABLE_TYPE(drgn_array_type_table, struct drgn_type *,
		       drgn_array_type_entry_to_key)

/** <tt>(type, member name)</tt> pair. */
struct drgn_member_key {
	struct drgn_type *type;
	const char *name;
	size_t name_len;
};

/** Type, offset, and bit field size of a type member. */
struct drgn_member_value {
	struct drgn_lazy_type *type;
	uint64_t bit_offset, bit_field_size;
};

#ifdef DOXYGEN
/**
 * @struct drgn_member_map
 *
 * Map of compound type members.
 *
 * The key is a @ref drgn_member_key, and the value is a @ref drgn_member_value.
 *
 * @struct drgn_type_set
 *
 * Set of types compared by address.
 */
#else
DEFINE_HASH_MAP_TYPE(drgn_member_map, struct drgn_member_key,
		      struct drgn_member_value)
DEFINE_HASH_SET_TYPE(drgn_type_set, struct drgn_type *)
#endif

/** Registered callback in a @ref drgn_type_index. */
struct drgn_type_finder {
	/** The callback. */
	drgn_type_find_fn fn;
	/** Argument to pass to @ref drgn_type_finder::fn. */
	void *arg;
	/** Next callback to try. */
	struct drgn_type_finder *next;
};

/**
 * Type index.
 *
 * A type index is used to find types by name and cache the results. The types
 * are found using callbacks which are registered with @ref
 * drgn_type_index_add_finder().
 *
 * @ref drgn_type_index_find() searches for a type. @ref
 * drgn_type_index_pointer_type(), @ref drgn_type_index_array_type(), and @ref
 * drgn_type_index_incomplete_array_type() create derived types. Any type
 * returned by these is valid until the type index is destroyed with @ref
 * drgn_type_index_destroy().
 */
struct drgn_type_index {
	/** Callbacks for finding types. */
	struct drgn_type_finder *finders;
	/** Cache of primitive types. */
	struct drgn_type *primitive_types[DRGN_PRIMITIVE_TYPE_NUM];
	struct drgn_type default_size_t;
	struct drgn_type default_ptrdiff_t;
	/** Cache of created pointer types. */
	struct drgn_pointer_type_table pointer_types;
	/** Cache of created array types. */
	struct drgn_array_type_table array_types;
	/** Cache for @ref drgn_type_index_find_member(). */
	struct drgn_member_map members;
	/**
	 * Set of types which have been already cached in @ref
	 * drgn_type_index::members.
	 */
	struct drgn_type_set members_cached;
	/**
	 * Size of a pointer in bytes.
	 *
	 * This is zero if it has not been set yet.
	 */
	uint8_t word_size;
};

/**
 * Initialize a @ref drgn_type_index.
 *
 * @param[in] tindex Type index to initialize.
 */
void drgn_type_index_init(struct drgn_type_index *tindex);

/** Deinitialize a @ref drgn_type_index. */
void drgn_type_index_deinit(struct drgn_type_index *tindex);

/** @sa drgn_program_add_type_finder() */
struct drgn_error *drgn_type_index_add_finder(struct drgn_type_index *tindex,
					      drgn_type_find_fn fn, void *arg);

/**
 * Remove the most recently added type finding callback.
 *
 * This must only be called if the type index hasn't been used since the finder
 * was added.
 */
void drgn_type_index_remove_finder(struct drgn_type_index *tindex);

/** Find a primitive type in a @ref drgn_type_index. */
struct drgn_error *
drgn_type_index_find_primitive(struct drgn_type_index *tindex,
			       enum drgn_primitive_type type,
			       struct drgn_type **ret);

/**
 * Find a parsed type in a @ref drgn_type_index.
 *
 * This should only be called by implementations of @ref
 * drgn_language::find_type().
 *
 * @param[in] kind Kind of type to find. Must be @ref DRGN_TYPE_STRUCT, @ref
 * DRGN_TYPE_UNION, @ref DRGN_TYPE_CLASS, @ref DRGN_TYPE_ENUM, or @ref
 * DRGN_TYPE_TYPEDEF.
 * @param[in] name Name of the type.
 * @param[in] name_len Length of @p name in bytes.
 * @param[in] filename See @ref drgn_type_index_find().
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_index_find_parsed(struct drgn_type_index *tindex,
			    enum drgn_type_kind kind, const char *name,
			    size_t name_len, const char *filename,
			    struct drgn_qualified_type *ret);

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
 * the same @p referenced_type and @p lang are passed, the same type will be
 * returned.
 *
 * If this succeeds, @p referenced_type must remain valid until @p tindex is
 * destroyed.
 *
 * @param[in] tindex Type index.
 * @param[in] referenced_type Type referenced by the pointer type.
 * @param[in] lang Language of the pointer type. If @c NULL, the language of @p
 * referenced_type is used.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_index_pointer_type(struct drgn_type_index *tindex,
			     struct drgn_qualified_type referenced_type,
			     const struct drgn_language *lang,
			     struct drgn_type **ret);

/**
 * Create an array type.
 *
 * The created type is cached for the lifetime of the @ref drgn_type_index. If
 * the same @p length, @p element_type, and @p lang are passed, the same type
 * will be returned.
 *
 * If this succeeds, @p element_type must remain valid until @p tindex is
 * destroyed.
 *
 * @param[in] tindex Type index.
 * @param[in] length Number of elements in the array type.
 * @param[in] element_type Type of an element in the array type.
 * @param[in] lang Language of the array type. If @c NULL, the language of @p
 * element_type is used.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_index_array_type(struct drgn_type_index *tindex, uint64_t length,
			   struct drgn_qualified_type element_type,
			   const struct drgn_language *lang,
			   struct drgn_type **ret);

/**
 * Create an incomplete array type.
 *
 * The created type is cached for the lifetime of the @ref drgn_type_index. If
 * the same @p element_type and @p lang are passed, the same type will be
 * returned.
 *
 * If this succeeds, @p element_type must remain valid until @p tindex is
 * destroyed.
 *
 * @param[in] tindex Type index.
 * @param[in] element_type Type of an element in the array type.
 * @param[in] lang Language of the array type. If @c NULL, the language of @p
 * element_type is used.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_index_incomplete_array_type(struct drgn_type_index *tindex,
				      struct drgn_qualified_type element_type,
				      const struct drgn_language *lang,
				      struct drgn_type **ret);

/**
 * Find the type, offset, and bit field size of a type member.
 *
 * This matches the members of the type itself as well as the members of any
 * unnamed members of the type.
 *
 * This caches all members of @p type for subsequent calls.
 *
 * @param[in] tindex Type index.
 * @param[in] type Compound type to search in.
 * @param[in] member_name Name of member.
 * @param[in] member_name_len Length of @p member_name
 * @param[out] ret Returned member information.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_type_index_find_member(struct drgn_type_index *tindex,
					       struct drgn_type *type,
					       const char *member_name,
					       size_t member_name_len,
					       struct drgn_member_value **ret);

/** @} */

#endif /* DRGN_TYPE_INDEX_H */
