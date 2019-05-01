// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * DWARF debugging information index.
 *
 * See @ref DwarfIndex.
 */

#ifndef DRGN_DWARF_INDEX_H
#define DRGN_DWARF_INDEX_H

#include <elfutils/libdw.h>
#include <libelf.h>
#include <stddef.h>
#include <stdint.h>

#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup DwarfIndex DWARF index
 *
 * DWARF debugging information index.
 *
 * A core part of debugger functionality is looking up types, variables, etc. by
 * name. A @ref drgn_dwarf_index combines debugging information from all object
 * files and indexes it by name.
 *
 * Because this indexing step happens as part of startup, it is parallelized and
 * highly optimized. This is implemented as a homegrown DWARF parser specialized
 * for the task of scanning over DIEs quickly.
 *
 * Although the DWARF standard defines ".debug_pubnames" and ".debug_names"
 * sections, GCC and Clang currently don't emit them by default, so we don't use
 * them.
 *
 * @{
 */

/**
 * @struct drgn_dwarf_index
 *
 * Fast index of DWARF debugging information.
 *
 * This interface indexes DWARF debugging information by name and tag,
 * deduplicating information which exists in multiple compilation units or
 * files. It is much faster for this task than other generic DWARF parsing
 * libraries.
 *
 * A new DWARF index is created by @ref drgn_dwarf_index_create(). It is freed
 * by @ref drgn_dwarf_index_destroy().
 *
 * Indexing happens in two steps: the files to index are opened using @ref
 * drgn_dwarf_index_open(), then they all are parsed and indexed by @ref
 * drgn_dwarf_index_update(). The update step is parallelized across CPUs, so it
 * is most efficient to open as many files as possible before indexing them all
 * at once in parallel.
 *
 * Searches in the index are done with a @ref drgn_dwarf_index_iterator.
 */
struct drgn_dwarf_index;

enum {
	/**
	 * Index global type information. This excludes incomplete types (i.e.,
	 * types with @c DW_AT_declaration).
	 */
	DRGN_DWARF_INDEX_TYPES = (1 << 0),
	/** Index global variables. */
	DRGN_DWARF_INDEX_VARIABLES = (1 << 1),
	/**
	 * Index global enumeration constants. Note that the returned DIE will
	 * refer to the parent @c DW_TAG_enumeration_type.
	 */
	DRGN_DWARF_INDEX_ENUMERATORS = (1 << 2),
	/** Index global functions. */
	DRGN_DWARF_INDEX_FUNCTIONS = (1 << 3),
	/** Index all of the above. */
	DRGN_DWARF_INDEX_ALL = (1 << 4) - 1,
};

/**
 * Allocate a new, empty DWARF index.
 *
 * @param[in] flags Bitmask of <tt>DRGN_DWARF_INDEX_*</tt> flags indicating what
 * to index.
 * @param[out] ret Returned index.
 * @return @c NULL on success or non-@c NULL on error, in which case the
 * contents of @c dindex are undefined.
 */
struct drgn_error *drgn_dwarf_index_create(int flags,
					   struct drgn_dwarf_index **ret);

/**
 * Free all of the resources used by a DWARF index.
 *
 * After this is called, anything belonging to the index should no longer be
 * accessed.
 *
 * @param[in] dindex Index to free.
 */
void drgn_dwarf_index_destroy(struct drgn_dwarf_index *dindex);

/**
 * Open a file and add it to a DWARF index.
 *
 * This function does the first part of indexing a file: it opens the file,
 * reads or maps it, and checks that it contains the required debugging
 * information. However, it does not actually parse the debugging information.
 * To do so, call drgn_dwarf_index_update() once all of the files to index have
 * been opened.
 *
 * If this fails, the file is not opened, but previously opened files are not
 * affected.
 *
 * @param[in] dindex DWARF index.
 * @param[in] path Path to open.
 * @param[out] elf If not @c NULL, the opened ELF file. It is valid until @ref
 * drgn_dwarf_index_destroy() is called.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_dwarf_index_open(struct drgn_dwarf_index *dindex,
					 const char *path, Elf **elf);

/**
 * Add a previously opened ELF file to a DWARF index.
 *
 * This is equivalent to @ref drgn_dwarf_index_open() except that the ELF file
 * was previously opened. The DWARF index does not take ownership of @c elf
 * (i.e., it will not call @c elf_end()). The contents of @c elf will be
 * modified in memory; therefore, it should be opened with @c
 * ELF_C_READ_MMAP_PRIVATE.
 *
 * @param[in] dindex DWARF index.
 * @param[in] elf ELF file.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_dwarf_index_open_elf(struct drgn_dwarf_index *dindex,
					     Elf *elf);

/**
 * Index newly opened files.
 *
 * This function does the second part of indexing a file: it applies ELF
 * relocations, then parses and indexes the debugging information in all of the
 * files opened by @ref drgn_dwarf_index_open() since the last call to @ref
 * drgn_dwarf_index_update() or @ref drgn_dwarf_index_create().
 *
 * If this fails, no new debugging information is indexed and all opened files
 * which were not already indexed are closed.
 *
 * @param[in] dindex DWARF index.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_dwarf_index_update(struct drgn_dwarf_index *dindex);

/**
 * Iterator over DWARF debugging information.
 *
 * An iterator is initialized with @ref drgn_dwarf_index_iterator_init(). It is
 * advanced with @ref drgn_dwarf_index_iterator_next().
 */
struct drgn_dwarf_index_iterator {
	/** @privatesection */
	struct drgn_dwarf_index *dindex;
	const uint64_t *tags;
	size_t num_tags;
	size_t shard;
	size_t index;
	bool any_name;
};

/**
 * Create an iterator over DIEs in a DWARF index.
 *
 * @param[out] it DWARF index iterator to initialize.
 * @param[in] dindex DWARF index.
 * @param[in] name Name of DIE to search for, or @c NULL for any name.
 * @param[in] name_len Length of @c name.
 * @param[in] tags List of DIE tags to search for.
 * @param[in] num_tags Number of tags in @p tags, or zero to search for any tag.
 */
void drgn_dwarf_index_iterator_init(struct drgn_dwarf_index_iterator *it,
				    struct drgn_dwarf_index *dindex,
				    const char *name, size_t name_len,
				    const uint64_t *tags, size_t num_tags);

/**
 * Get the next matching DIE from a DWARF index iterator.
 *
 * If matching any name, this is O(n), where n is the number of indexed DIEs. If
 * matching by name, this is O(1) on average and O(n) worst case.
 *
 * @param[in] it DWARF index iterator.
 * @param[out] die Returned DIE.
 * @return @c NULL on success, non-@c NULL on error. In particular, when there
 * are no more matching DIEs, @p die is not modified and an error with code @ref
 * DRGN_ERROR_STOP is returned; this @ref DRGN_ERROR_STOP error does not have to
 * be passed to @ref drgn_error_destroy().
 */
struct drgn_error *
drgn_dwarf_index_iterator_next(struct drgn_dwarf_index_iterator *it,
			       Dwarf_Die *die);

/** @} */

#endif /* DRGN_DWARF_INDEX_H */
