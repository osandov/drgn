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

#include <elfutils/libdwfl.h>
#include <libelf.h>
#include <omp.h>
#include <stddef.h>
#include <stdint.h>

#include "drgn.h"
#include "hash_table.h"
#include "string_builder.h"
#include "vector.h"

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
 * drgn-specific data for the @c Dwfl_Module userdata pointer.
 *
 * For a newly created userdata, @c indexed is @c false and @c err is @c NULL.
 * They are updated by @ref drgn_dwarf_index_update(). @c err may be set with
 * @ref drgn_dwfl_module_userdata_set_error() before @ref
 * drgn_dwarf_index_update() is called to skip indexing for that module; the
 * error message will be added to the @ref DRGN_ERROR_MISSING_DEBUG_INFO error.
 *
 * @sa drgn_dwfl_find_elf(), drgn_dwfl_section_address()
 */
struct drgn_dwfl_module_userdata {
	/** Whether the module is indexed in a @ref drgn_dwarf_index. */
	bool indexed;
	/** File descriptor of @ref drgn_dwfl_module_userdata::elf. */
	int fd;
	/** Error encountered while indexing. */
	struct drgn_error *err;
	/** Path of @ref drgn_dwfl_module_userdata::elf. */
	char *path;
	/** ELF handle to use. */
	Elf *elf;
};

struct drgn_dwfl_module_userdata *drgn_dwfl_module_userdata_create(void);

void
drgn_dwfl_module_userdata_destroy(struct drgn_dwfl_module_userdata *userdata);

/* This takes ownership of err. */
void
drgn_dwfl_module_userdata_set_error(struct drgn_dwfl_module_userdata *userdata,
				    const char *message,
				    struct drgn_error *err);

extern const Dwfl_Callbacks drgn_dwfl_callbacks;

/** Get the @ref drgn_dwfl_module_userdata for a @c Dwfl_Module. */
static inline struct drgn_dwfl_module_userdata *
drgn_dwfl_module_userdata(Dwfl_Module *module)
{
	void **userdatap;

	dwfl_module_info(module, &userdatap, NULL, NULL, NULL, NULL, NULL,
			 NULL);
	return *userdatap;
}

struct drgn_dwarf_index_die;
DEFINE_HASH_MAP_TYPE(drgn_dwarf_index_die_map, struct string, size_t)
DEFINE_VECTOR_TYPE(drgn_dwarf_index_die_vector, struct drgn_dwarf_index_die)

struct drgn_dwarf_index_shard {
	/** @privatesection */
	omp_lock_t lock;
	struct drgn_dwarf_index_die_map map;
	/*
	 * We store all entries in a shard as a single array, which is more
	 * cache friendly.
	 */
	struct drgn_dwarf_index_die_vector dies;
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
 * Searches in the index are done with a @ref drgn_dwarf_index_iterator.
 */
struct drgn_dwarf_index {
	/**
	 * Index shards.
	 *
	 * This is sharded to reduce lock contention.
	 */
	struct drgn_dwarf_index_shard shards[1 << DRGN_DWARF_INDEX_SHARD_BITS];
};

/** Initialize a @ref drgn_dwarf_index. */
void drgn_dwarf_index_init(struct drgn_dwarf_index *dindex);

/**
 * Deinitialize a @ref drgn_dwarf_index.
 *
 * After this is called, anything belonging to the index should no longer be
 * accessed.
 */
void drgn_dwarf_index_deinit(struct drgn_dwarf_index *dindex);

/**
 * Index new DWARF information.
 *
 * This parses and indexes the debugging information for all modules in @p dwfl
 * that have not yet been indexed.
 *
 * On success, @ref drgn_dwfl_module_userdata::indexed is set to @c true for all
 * modules that we were able to index, and @ref drgn_dwfl_module_userdata::err
 * is set to non-@c NULL for all other modules.
 *
 * If debug information was not available for one or more modules, a @ref
 * DRGN_ERROR_MISSING_DEBUG_INFO error is returned.
 *
 * On any other error, no new debugging information is indexed.
 *
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_dwarf_index_update(struct drgn_dwarf_index *dindex,
					   Dwfl *dwfl);

/**
 * Remove all @c Dwfl_Modules that aren't indexed (see @ref
 * drgn_dwfl_module_userdata::indexed) from @p dwfl.
 *
 * This should be called if @ref drgn_dwarf_index_update() returned an error or
 * if modules were reported and @ref drgn_dwarf_index_update() was not called.
 */
void drgn_remove_unindexed_dwfl_modules(Dwfl *dwfl);

/** Remove all @Dwfl_Modules from @p dwfl. */
void drgn_remove_all_dwfl_modules(Dwfl *dwfl);

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
 * @param[out] die_ret Returned DIE.
 * @param[out] bias_ret Returned difference between addresses in the loaded
 * module and addresses in the debugging information. This may be @c NULL if it
 * is not needed.
 * @return @c NULL on success, non-@c NULL on error. In particular, when there
 * are no more matching DIEs, @p die_ret is not modified and an error with code
 * @ref DRGN_ERROR_STOP is returned; this @ref DRGN_ERROR_STOP error does not
 * have to be passed to @ref drgn_error_destroy().
 */
struct drgn_error *
drgn_dwarf_index_iterator_next(struct drgn_dwarf_index_iterator *it,
			       Dwarf_Die *die_ret, uint64_t *bias_ret);

/** @} */

#endif /* DRGN_DWARF_INDEX_H */
