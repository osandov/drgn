// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Miscellanous internal drgn helpers.
 */

#ifndef DRGN_INTERNAL_H
#define DRGN_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <elfutils/libdw.h>
#include <elfutils/version.h>

#include "drgn.h"
#include "error.h"
#include "util.h"

/**
 *
 * @defgroup Internals Internals
 *
 * Internal implementation.
 *
 * @{
 */

#ifndef LIBDRGN_PUBLIC
#define LIBDRGN_PUBLIC __attribute__((visibility("default")))
#endif

struct drgn_error *open_elf_file(const char *path, int *fd_ret, Elf **elf_ret);

struct drgn_error *find_elf_file(char **path_ret, int *fd_ret, Elf **elf_ret,
				 const char * const *path_formats, ...);

struct drgn_error *read_elf_section(Elf_Scn *scn, Elf_Data **ret);

struct drgn_error *elf_address_range(Elf *elf, uint64_t bias,
				     uint64_t *start_ret, uint64_t *end_ret);

bool die_matches_filename(Dwarf_Die *die, const char *filename);

/** Path iterator input component. */
struct path_iterator_component {
	/**
	 * Path component.
	 *
	 * This can contain "/".
	 */
	const char *path;
	/** Length of @ref path_iterator_component::path. */
	size_t len;
};

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
	 * @ref path_iterator_component::path and @ref
	 * path_iterator_component::len should be initialized for each
	 * component. The latter will be modified as the path is iterated.
	 */
	struct path_iterator_component *components;
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
 * @param[out] component Returned component.
 * @param[out] component_len Length of @c component.
 * @return @c true if we returned a componenent, @c false if there were no more
 * components.
 */
bool path_iterator_next(struct path_iterator *it, const char **component,
			size_t *component_len);

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

/** @} */

struct drgn_lexer;
struct drgn_token;
struct drgn_error *drgn_lexer_c(struct drgn_lexer *lexer,
				struct drgn_token *token);

#endif /* DRGN_INTERNAL_H */
