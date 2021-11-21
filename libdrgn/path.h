// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Paths.
 *
 * See @ref Paths.
 */

#ifndef DRGN_PATH_H
#define DRGN_PATH_H

#include <elfutils/libdw.h>
#include <stdbool.h>
#include <stddef.h>

#include "nstring.h" // IWYU pragma: export

/**
 * @ingroup Internals
 *
 * @defgroup Paths Paths
 *
 * Utilities for working with paths.
 *
 * @{
 */

/**
 * Path component iterator.
 *
 * This iterates over the components of a file path, joining multiple components
 * and normalizing the result. Normalization:
 *
 * - Collapses redundant "/" separators.
 * - Removes "." components.
 * - Removes ".." components when possible.
 *
 * Components are emitted in @b reverse. So, "a/b/c" is emitted in the order
 * "c", "b", "a" (this allows the implementation to operate in O(n) time and
 * O(1) space).
 *
 * Absolute paths have an implicit empty component, so "/a/b" is emitted as "b",
 * "a", "".
 *
 * Relative paths are emitted relative to a hypothetical current directory. A
 * path referring to the current directory (e.g., "." or "a/..") does not emit
 * any components.
 *
 * ".." components above the current directory are included, so "a/b/../../../c"
 * is emitted as "c", "..". However, ".." components above an absolute path are
 * not meaningful, so "/a/b/../../../c" is emitted as "c", "".
 *
 * A empty path does not emit any components.
 */
struct path_iterator {
	/**
	 * Array of input components.
	 *
	 * The input components are treated as if they were joined with a "/".
	 * @ref nstring::str and @ref nstring::len should be initialized for
	 * each component. The latter will be modified as the path is iterated.
	 */
	struct nstring *components;
	/** Number of components in @ref path_iterator::components. */
	size_t num_components;
	/**
	 * Current number of ".." components.
	 *
	 * Initialize this to 0.
	 */
	size_t dot_dot;
};

/**
 * Get the next component from a @ref path_iterator.
 *
 * Components are emitted in reverse. This will never emit a "." component. It
 * will emit an empty ("") component only for an absolute path. It may emit ".."
 * components if there are any that go above the current directory.
 *
 * @param[in] it Iterator.
 * @param[out] component_ret Returned component.
 * @param[out] component_len_ret Length of @c component.
 * @return @c true if we returned a componenent, @c false if there were no more
 * components.
 */
bool path_iterator_next(struct path_iterator *it, const char **component_ret,
			size_t *component_len_ret);

/**
 * Return whether the path @p haystack ends with the path @p needle once both
 * are normalized.
 *
 * The unit of comparison is a path component, not a character. Thus, "ab/cd/ef"
 * ends with "cd/ef", but not "d/ef".
 *
 * @sa path_iterator
 */
bool path_ends_with(struct path_iterator *haystack,
		    struct path_iterator *needle);

bool die_matches_filename(Dwarf_Die *die, const char *filename);

/** @} */

#endif /* DRGN_PATH_H */
