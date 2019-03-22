// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Object lookup.
 *
 * See @ref ObjectIndex.
 */

#ifndef DRGN_OBJECT_INDEX_H
#define DRGN_OBJECT_INDEX_H

#include <elfutils/libdw.h>

#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup ObjectIndex Object index
 *
 * Object lookup.
 *
 * @ref drgn_object_index provides a common interface for finding objects (e.g.,
 * variables, constants, and functions) in a program.
 *
 * @{
 */

struct drgn_object_index;

/**
 * An indexed object in a program.
 *
 * This is the result of a lookup in a @ref drgn_object_index. It is typically
 * converted to a @ref drgn_object.
 */
struct drgn_partial_object {
	/** The type of the object. */
	struct drgn_qualified_type qualified_type;
	/**
	 * Whether the object is an enumerator.
	 *
	 * If this is @c true, then @ref drgn_partial_object::qualified_type
	 * must be an enumerated type, and either @ref
	 * drgn_partial_object::svalue or @ref drgn_partial_object::uvalue is
	 * set (based on the signedness of @ref
	 * drgn_partial_object::qualified_type). Otherwise, @ref
	 * drgn_partial_object::address is set.
	 */
	bool is_enumerator;
	/** Whether the object is little-endian. */
	bool little_endian;
	union {
		/** If not an enumerator, the address of the object. */
		uint64_t address;
		/** If a signed enumerator, the value. */
		int64_t svalue;
		/** If an unsigned enumerator, the value. */
		uint64_t uvalue;
	};
};

/** Object index operations. */
struct drgn_object_index_ops {
	/** Implements @ref drgn_object_index_destroy(). */
	void (*destroy)(struct drgn_object_index *oindex);
	/** Implements @ref drgn_object_index_find(). */
	struct drgn_error *(*find)(struct drgn_object_index *oindex,
				   const char *name, const char *filename,
				   enum drgn_find_object_flags flags,
				   struct drgn_partial_object *ret);
};

/**
 * Abstract object index.
 *
 * A object index is used to find objects (objects and constants) by name. It is
 * usually backed by debugging information (@ref drgn_dwarf_object_index). It
 * can also be backed by manually-created objects for testing (@ref
 * drgn_mock_object_index). It is destroyed with @ref
 * drgn_object_index_destroy().
 *
 * @ref drgn_object_index_find() searches for an object.
 */
struct drgn_object_index {
	/** Operation dispatch table. */
	const struct drgn_object_index_ops *ops;
};

/**
 * Free a @ref drgn_object_index.
 *
 * @param[in] oindex Object index to destroy.
 */
static inline void
drgn_object_index_destroy(struct drgn_object_index *oindex)
{
	if (oindex)
		oindex->ops->destroy(oindex);
}

/**
 * Find an object in a @ref drgn_object_index.
 *
 * @param[in] oindex Object index.
 * @param[in] name Name of the object.
 * @param[in] filename Exact filename containing the object definition, or @c
 * NULL for any definition.
 * @param[in] flags Bitmask of @ref drgn_find_object_flags.
 * @param[out] ret Returned object.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_object_index_find(struct drgn_object_index *oindex, const char *name,
		       const char *filename, enum drgn_find_object_flags flags,
		       struct drgn_partial_object *ret)
{
	if ((flags & ~DRGN_FIND_OBJECT_ANY) || !flags) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid find object flags");
	}

	return oindex->ops->find(oindex, name, filename, flags, ret);
}

/**
 * Initialize a @ref drgn_object with an enumerated type.
 *
 * This is a helper for implementations of @ref drgn_object_index_ops::find().
 *
 * @c pobj->qualified_type should already be initialized. This will initialize
 * @c pobj->svalue or @c pobj->uvalue to the value of the enumerator with the
 * given name in that type.
 *
 * @param[in,out] pobj Object to initialize.
 * @param[in] name Name of enumerator to find.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_partial_object_from_enumerator(struct drgn_partial_object *pobj,
				    const char *name);

/**
 * Create a @ref drgn_error for an object which could not be found in a @ref
 * drgn_object_index.
 *
 * This is a helper for implementations of @ref drgn_object_index_ops::find().
 *
 * @param[in] name Name of the object.
 * @param[in] filename Filename that was searched in or @c NULL.
 * @param[in] flags Flags that were passed to @ref
 * drgn_object_index_ops::find().
 */
struct drgn_error *
drgn_object_index_not_found_error(const char *name, const char *filename,
				  enum drgn_find_object_flags flags)
	__attribute__((returns_nonnull));

/** Object indexed in a @ref drgn_mock_object_index. */
struct drgn_mock_object {
	/** Name of the object. */
	const char *name;
	/**
	 * Name of the file that the object is defined in.
	 *
	 * This may be @c NULL, in which case no filename will match it.
	 */
	const char *filename;
	/** See @ref drgn_partial_object::qualified_type. */
	struct drgn_qualified_type qualified_type;
	/** See @ref drgn_partial_object::is_enumerator. */
	bool is_enumerator;
	/** See @ref drgn_partial_object::little_endian. */
	bool little_endian;
	/** See @ref drgn_partial_object::address. */
	uint64_t address;
};

/**
 * Object index backed by manually-defined objects.
 *
 * This is mostly useful for testing. It is created with @ref
 * drgn_mock_object_index_create().
 */
struct drgn_mock_object_index {
	/** Abstract object index. */
	struct drgn_object_index oindex;
	/** Indexed objects. */
	struct drgn_mock_object *objects;
	/** Number of objects. */
	size_t num_objects;
};

/**
 * Create a @ref drgn_mock_object_index.
 *
 * @param[in] objects Objects to index. This will not be freed when the
 * object index is destroyed.
 * @param[in] num_objects Number of objects to index.
 * @param[out] ret Returned object index.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_mock_object_index_create(struct drgn_mock_object *objects,
			      size_t num_objects,
			      struct drgn_mock_object_index **ret);

struct drgn_program;
struct drgn_dwarf_type_index;

/** Object index backed by DWARF debugging information. */
struct drgn_dwarf_object_index {
	/** Abstract object index. */
	struct drgn_object_index oindex;
	/**
	 * DWARF type index.
	 *
	 * Used to lookup types and DWARF information through @ref
	 * drgn_dwarf_type_index::dindex.
	 */
	struct drgn_dwarf_type_index *dtindex;
	/** Program to pass to @c relocation_hook(). */
	struct drgn_program *prog;
	/**
	 * Relocation callback.
	 *
	 * Objects in an ELF file are often relocated when they are loaded into
	 * a program (e.g., shared libraries or position-independent
	 * executables). This callback can be used to adjust the address which
	 * was found in the DWARF debugging information entry for the object.
	 *
	 * On entry, @p pobj is fully initialized and not a constant. This
	 * should look at @c pobj->address and modify it as appropriate.
	 *
	 * @param[in] prog @ref drgn_dwarf_object_index::prog.
	 * @param[in] name Name of the object.
	 * @param[in] die DWARF DIE of the object.
	 * @param[in,out] pobj Object to relocate.
	 * @return @c NULL on success, non-@c NULL on error.
	 */
	struct drgn_error *(*relocation_hook)(struct drgn_program *prog,
					      const char *name, Dwarf_Die *die,
					      struct drgn_partial_object *pobj);
};

/**
 * Create a @ref drgn_dwarf_object_index.
 *
 * @param[in] dtindex DWARF type index.
 * @param[out] ret Returned object index.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_dwarf_object_index_create(struct drgn_dwarf_type_index *dtindex,
			       struct drgn_dwarf_object_index **ret);

/** @} */

#endif /* DRGN_OBJECT_INDEX_H */
