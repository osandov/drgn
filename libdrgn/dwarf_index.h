// Copyright (c) Facebook, Inc. and its affiliates.
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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#else
typedef struct {} omp_lock_t;
#define omp_init_lock(lock) do {} while (0)
#define omp_destroy_lock(lock) do {} while (0)
#define omp_set_lock(lock) do {} while (0)
#define omp_unset_lock(lock) do {} while (0)
#endif

#include "hash_table.h"
#include "vector.h"

struct drgn_debug_info_module;
struct drgn_error;

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

/*
 * An indexed DIE.
 *
 * DIEs with the same name but different tags or files are considered distinct.
 * We only compare the hash of the file name, not the string value, because a
 * 64-bit collision is unlikely enough, especially when also considering the
 * name and tag.
 */
struct drgn_dwarf_index_die {
	/*
	 * The next DIE with the same name (as an index into
	 * drgn_dwarf_index_shard::dies), or UINT32_MAX if this is the last DIE.
	 */
	uint32_t next;
	uint8_t tag;
	union {
		/*
		 * If tag != DW_TAG_namespace (namespaces are merged, so they
		 * don't need this).
		 */
		uint64_t file_name_hash;
		/* If tag == DW_TAG_namespace. */
		struct drgn_dwarf_index_namespace *namespace;
	};
	struct drgn_debug_info_module *module;
	uintptr_t addr;
};

DEFINE_HASH_MAP_TYPE(drgn_dwarf_index_die_map, struct string, uint32_t)
DEFINE_VECTOR_TYPE(drgn_dwarf_index_die_vector, struct drgn_dwarf_index_die)

struct drgn_dwarf_index_shard {
	/** @privatesection */
	omp_lock_t lock;
	/*
	 * Map from name to list of DIEs with that name (as the index in
	 * drgn_dwarf_index_shard::dies of the first DIE with that name).
	 */
	struct drgn_dwarf_index_die_map map;
	/*
	 * We store all entries in a shard as a single array, which is more
	 * cache friendly.
	 */
	struct drgn_dwarf_index_die_vector dies;
};

#define DRGN_DWARF_INDEX_SHARD_BITS 8

/* A DIE with a DW_AT_specification attribute. */
struct drgn_dwarf_index_specification {
	/*
	 * Address of non-defining declaration DIE referenced by
	 * DW_AT_specification.
	 */
	uintptr_t declaration;
	/* Module and address of DIE. */
	struct drgn_debug_info_module *module;
	uintptr_t addr;
};

static inline uintptr_t
drgn_dwarf_index_specification_to_key(const struct drgn_dwarf_index_specification *entry)
{
	return entry->declaration;
}

DEFINE_HASH_TABLE_TYPE(drgn_dwarf_index_specification_map,
		       struct drgn_dwarf_index_specification,
		       drgn_dwarf_index_specification_to_key)

DEFINE_VECTOR_TYPE(drgn_dwarf_index_cu_vector, struct drgn_dwarf_index_cu)

DEFINE_VECTOR_TYPE(drgn_dwarf_index_pending_die_vector,
		   struct drgn_dwarf_index_pending_die)

/** Mapping from names/tags to DIEs/nested namespaces. */
struct drgn_dwarf_index_namespace {
	/**
	 * Index shards.
	 *
	 * This is sharded to reduce lock contention.
	 */
	struct drgn_dwarf_index_shard shards[1 << DRGN_DWARF_INDEX_SHARD_BITS];
	/** Parent DWARF index. */
	struct drgn_dwarf_index *dindex;
	/** DIEs we have not indexed yet. */
	struct drgn_dwarf_index_pending_die_vector pending_dies;
	/** Saved error from a previous index. */
	struct drgn_error *saved_err;
};

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
	/** Global namespace. */
	struct drgn_dwarf_index_namespace global;
	/**
	 * Map from address of DIE referenced by DW_AT_specification to DIE that
	 * references it. This is used to resolve DIEs with DW_AT_declaration to
	 * their definition.
	 *
	 * This is not sharded because there typically aren't enough of these in
	 * a program to cause contention.
	 */
	struct drgn_dwarf_index_specification_map specifications;
	/** Indexed compilation units. */
	struct drgn_dwarf_index_cu_vector cus;
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

/** State tracked while updating a @ref drgn_dwarf_index. */
struct drgn_dwarf_index_update_state {
	struct drgn_dwarf_index *dindex;
	size_t old_cus_size;
	struct drgn_error *err;
};

/**
 * Prepare to update a @ref drgn_dwarf_index.
 *
 * @param[out] state Initialized update state. Must be passed to @ref
 * drgn_dwarf_index_update_end().
 */
void drgn_dwarf_index_update_begin(struct drgn_dwarf_index_update_state *state,
				   struct drgn_dwarf_index *dindex);

/**
 * Finish updating a @ref drgn_dwarf_index.
 *
 * This should be called once all of the tasks created by @ref
 * drgn_dwarf_index_read_module() have completed (even if the update was
 * cancelled).
 *
 * If the update was not cancelled, this finishes indexing all modules reported
 * by @ref drgn_dwarf_index_read_module(). If it was cancelled or there is an
 * error while indexing, this rolls back the index and removes the newly
 * reported modules.
 *
 * @return @c NULL on success, non-@c NULL if the update was cancelled or there
 * was another error.
 */
struct drgn_error *
drgn_dwarf_index_update_end(struct drgn_dwarf_index_update_state *state);

/**
 * Cancel an update of a @ref drgn_dwarf_index.
 *
 * This should be called if there is a fatal error and the update must be
 * aborted.
 *
 * @param[in] err Error to report. This will be returned from @ref
 * drgn_dwarf_index_update_end(). If an error has already been reported, this
 * error is destroyed.
 */
void drgn_dwarf_index_update_cancel(struct drgn_dwarf_index_update_state *state,
				    struct drgn_error *err);

/**
 * Return whether an update of a @ref drgn_dwarf_index has been cancelled by
 * @ref drgn_dwarf_index_update_cancel().
 *
 * Because updating is parallelized, this allows tasks other than the one that
 * encountered the error to "fail fast".
 */
static inline bool
drgn_dwarf_index_update_cancelled(struct drgn_dwarf_index_update_state *state)
{
	/*
	 * No need for omp critical/omp atomic since this is a best-effort
	 * optimization.
	 */
	return state->err != NULL;
}

/**
 * Read a module for updating a @ref drgn_dwarf_index.
 *
 * This creates OpenMP tasks to begin indexing the module. It may cancel the
 * update.
 */
void drgn_dwarf_index_read_module(struct drgn_dwarf_index_update_state *state,
				  struct drgn_debug_info_module *module);

/**
 * Iterator over DWARF debugging information.
 *
 * An iterator is initialized with @ref drgn_dwarf_index_iterator_init(). It is
 * advanced with @ref drgn_dwarf_index_iterator_next().
 */
struct drgn_dwarf_index_iterator {
	/** @privatesection */
	struct drgn_dwarf_index_namespace *ns;
	const uint64_t *tags;
	size_t num_tags;
	size_t shard;
	uint32_t index;
	bool any_name;
};

/**
 * Create an iterator over DIEs in a DWARF index namespace.
 *
 * @param[out] it DWARF index iterator to initialize.
 * @param[in] ns DWARF index namespace.
 * @param[in] name Name of DIE to search for, or @c NULL for any name.
 * @param[in] name_len Length of @c name.
 * @param[in] tags List of DIE tags to search for.
 * @param[in] num_tags Number of tags in @p tags, or zero to search for any tag.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_dwarf_index_iterator_init(struct drgn_dwarf_index_iterator *it,
			       struct drgn_dwarf_index_namespace *ns,
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
 * @return Next DIE, or @c NULL if there are no more matching DIEs.
 */
struct drgn_dwarf_index_die *
drgn_dwarf_index_iterator_next(struct drgn_dwarf_index_iterator *it);

/**
 * Get a @c Dwarf_Die from a @ref drgn_dwarf_index_die.
 *
 * @param[in] die Indexed DIE.
 * @param[out] die_ret Returned DIE.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_dwarf_index_get_die(struct drgn_dwarf_index_die *die,
					    Dwarf_Die *die_ret);


/**
 * Find a definition corresponding to a declaration DIE.
 *
 * This finds the address of a DIE with a @c DW_AT_specification attribute that
 * refers to the given address.
 *
 * @param[in] die_addr The address of the declaration DIE.
 * @param[out] module_ret Returned module containing the definition DIE.
 * @param[out] addr_ret Returned address of the definition DIE.
 * @return @c true if a definition DIE was found, @c false if not (in which case
 * *@p module_ret and *@p addr_ret are not modified).
 */
bool
drgn_dwarf_index_find_definition(struct drgn_dwarf_index *dindex,
				 uintptr_t die_addr,
				 struct drgn_debug_info_module **module_ret,
				 uintptr_t *addr_ret);

/** @} */

#endif /* DRGN_DWARF_INDEX_H */
