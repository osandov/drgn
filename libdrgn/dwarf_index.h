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
#include <omp.h>
#include <stddef.h>
#include <stdint.h>

#include "drgn.h"
#include "hash_table.h"

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

enum {
	SECTION_SYMTAB,
	SECTION_DEBUG_ABBREV,
	SECTION_DEBUG_INFO,
	SECTION_DEBUG_LINE,
	SECTION_DEBUG_STR,
	DRGN_DWARF_INDEX_NUM_SECTIONS,
};

struct drgn_dwarf_index_file {
	Elf_Data *sections[DRGN_DWARF_INDEX_NUM_SECTIONS];
	/* Other byte order. */
	bool bswap;
	bool failed;
	int fd;
	/*
	 * If this is NULL, then we didn't open the file and don't own the Elf
	 * handle.
	 */
	const char *path;
	Elf *elf;
	Dwarf *dwarf;
	Elf_Data *rela_sections[DRGN_DWARF_INDEX_NUM_SECTIONS];
	struct drgn_dwarf_index_file *next;
};

static inline const char *
drgn_dwarf_index_file_to_key(struct drgn_dwarf_index_file * const *entry)
{
	return (*entry)->path;
}
DEFINE_HASH_TABLE_TYPE(drgn_dwarf_index_file_table,
		       struct drgn_dwarf_index_file *,
		       drgn_dwarf_index_file_to_key)

struct drgn_dwarf_index_die;
DEFINE_HASH_MAP_TYPE(drgn_dwarf_index_die_map, struct string, size_t)

struct drgn_dwarf_index_shard {
	/** @privatesection */
	omp_lock_t lock;
	struct drgn_dwarf_index_die_map map;
	/*
	 * We store all entries in a shard as a single array, which is more
	 * cache friendly.
	 */
	struct drgn_dwarf_index_die *dies;
	size_t num_entries, entries_capacity;
};

#define DRGN_DWARF_INDEX_SHARD_BITS 8

/**
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
struct drgn_dwarf_index {
	/** @privatesection */
	struct drgn_dwarf_index_file_table files;
	struct drgn_dwarf_index_file *opened_first, *opened_last;
	struct drgn_dwarf_index_file *indexed_first, *indexed_last;
	/* The index is sharded to reduce lock contention. */
	struct drgn_dwarf_index_shard shards[1 << DRGN_DWARF_INDEX_SHARD_BITS];
};

/**
 * Initialize a @ref drgn_dwarf_index.
 *
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_dwarf_index_init(struct drgn_dwarf_index *dindex);

/**
 * Deinitialize a @ref drgn_dwarf_index.
 *
 * After this is called, anything belonging to the index should no longer be
 * accessed.
 */
void drgn_dwarf_index_deinit(struct drgn_dwarf_index *dindex);

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

/** Close any files which haven't been indexed yet. */
void drgn_dwarf_index_close_unindexed(struct drgn_dwarf_index *dindex);

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
 * Note that this returns the parent @c DW_TAG_enumeration_type for indexed @c
 * DW_TAG_enumerator DIEs.
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
