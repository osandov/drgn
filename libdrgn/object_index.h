// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Object lookup.
 *
 * See @ref ObjectIndex.
 */

#ifndef DRGN_OBJECT_INDEX_H
#define DRGN_OBJECT_INDEX_H

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

/** Registered callback in a @ref drgn_object_index. */
struct drgn_object_finder {
	/** The callback. */
	drgn_object_find_fn fn;
	/** Argument to pass to @ref drgn_object_finder::fn. */
	void *arg;
	/** Next callback to try. */
	struct drgn_object_finder *next;
	/** Whether this structure needs to be freed. */
	bool free;
};

/**
 * Object index.
 *
 * A object index is used to find objects (variables, constants, and functions)
 * by name. The objects are found using callbacks which are registered with @ref
 * drgn_object_index_add_finder(). @ref drgn_object_index_find() searches for an
 * object.
 */
struct drgn_object_index {
	/** Callbacks for finding objects. */
	struct drgn_object_finder *finders;
};

/** Initialize a @ref drgn_object_index. */
void drgn_object_index_init(struct drgn_object_index *oindex);

/** Deinitialize a @ref drgn_object_index. */
void drgn_object_index_deinit(struct drgn_object_index *oindex);

struct drgn_error *
drgn_object_index_add_finder(struct drgn_object_index *oindex,
			     struct drgn_object_finder *finder,
			     drgn_object_find_fn fn, void *arg);

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
struct drgn_error *drgn_object_index_find(struct drgn_object_index *oindex,
					  const char *name,
					  const char *filename,
					  enum drgn_find_object_flags flags,
					  struct drgn_object *ret);

/** @} */

#endif /* DRGN_OBJECT_INDEX_H */
