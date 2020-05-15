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

#include <elfutils/libdwfl.h>
#include <libelf.h>
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

extern const Dwfl_Callbacks drgn_dwfl_callbacks;
extern const Dwfl_Callbacks drgn_linux_proc_dwfl_callbacks;
extern const Dwfl_Callbacks drgn_userspace_core_dump_dwfl_callbacks;

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

/** State of a @ref drgn_dwarf_module or a @c Dwfl_Module. */
enum drgn_dwarf_module_state {
	/** Reported but not indexed. */
	DRGN_DWARF_MODULE_NEW,
	/** Reported and will be indexed on success. */
	DRGN_DWARF_MODULE_INDEXING,
	/** Indexed. Must not be freed until @ref drgn_dwarf_index_deinit(). */
	DRGN_DWARF_MODULE_INDEXED,
};

DEFINE_VECTOR_TYPE(dwfl_module_vector, Dwfl_Module *)

/**
 * A module reported to a @ref drgn_dwarf_index.
 *
 * Conceptually, a module is an ELF file loaded at a specific address range (or
 * not loaded).
 *
 * Each (file, address range) referenced by a @ref drgn_dwarf_index is uniquely
 * represented by one @c Dwfl_Module. Files are identified by canonical path.
 *
 * Each (binary, address range) is uniquely represented by a @ref
 * drgn_dwarf_module. Binaries are identified by build ID; note that a single
 * binary may be represented by multiple files (e.g., a stripped binary and its
 * corresponding separate debug info file). If a file does not have a build ID,
 * it is considered a different binary from other files with different canonical
 * paths.
 */
struct drgn_dwarf_module {
	/** Allocated with @c malloc() if @c build_id_len is non-zero. */
	void *build_id;
	/** Zero if the module does not have a build ID. */
	size_t build_id_len;
	/** Load address range, or both 0 if not loaded. */
	uint64_t start, end;
	/** Optional module name allocated with @c malloc(). */
	char *name;
	enum drgn_dwarf_module_state state;
	/**
	 * Candidate <tt>Dwfl_Module</tt>s which were reported for this module.
	 *
	 * One of these will be indexed. Once the module is indexed, this is
	 * always empty.
	 */
	struct dwfl_module_vector dwfl_modules;
};

/**
 * State tracked for each @c Dwfl_Module.
 *
 * @c path, @c elf, and @c fd are used when an ELF file was reported to a @ref
 * drgn_dwarf_index so that we can report the ELF file to libdwfl later.
 */
struct drgn_dwfl_module_userdata {
	char *path;
	Elf *elf;
	int fd;
	enum drgn_dwarf_module_state state;
};

DEFINE_VECTOR_TYPE(drgn_dwarf_module_vector, struct drgn_dwarf_module *)

struct drgn_dwarf_module_key {
	const void *build_id;
	size_t build_id_len;
	uint64_t start, end;
};

static inline struct drgn_dwarf_module_key
drgn_dwarf_module_key(struct drgn_dwarf_module * const *entry)
{
	return (struct drgn_dwarf_module_key){
		.build_id = (*entry)->build_id,
		.build_id_len = (*entry)->build_id_len,
		.start = (*entry)->start,
		.end = (*entry)->end,
	};
}
DEFINE_HASH_TABLE_TYPE(drgn_dwarf_module_table, struct drgn_dwarf_module *,
		       drgn_dwarf_module_key)

DEFINE_HASH_SET_TYPE(c_string_set, const char *)

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
	Dwfl *dwfl;
	/**
	 * Formatted errors reported by @ref drgn_dwarf_index_report_error().
	 */
	struct string_builder errors;
	/**
	 * Number of errors reported by @ref drgn_dwarf_index_report_error().
	 */
	unsigned int num_errors;
	/** Maximum number of errors to report before truncating. */
	unsigned int max_errors;
	/**
	 * Modules keyed by build ID and address range.
	 *
	 * Every reported module is either here or in @ref no_build_id. While
	 * reporting modules, these include indexed and unindexed modules.
	 */
	struct drgn_dwarf_module_table module_table;
	/** Modules that don't have a build ID. */
	struct drgn_dwarf_module_vector no_build_id;
	/**
	 * Names of indexed modules.
	 *
	 * The entries in this set are @ref drgn_dwarf_module::name, so they
	 * should not be freed.
	 */
	struct c_string_set names;
};

/**
 * Initialize a @ref drgn_dwarf_index.
 *
 * @param[in] callbacks One of @ref drgn_dwfl_callbacks, @ref
 * drgn_linux_proc_dwfl_callbacks, or @ref
 * drgn_userspace_core_dump_dwfl_callbacks.
 */
struct drgn_error *drgn_dwarf_index_init(struct drgn_dwarf_index *dindex,
					 const Dwfl_Callbacks *callbacks);

/**
 * Deinitialize a @ref drgn_dwarf_index.
 *
 * After this is called, anything belonging to the index should no longer be
 * accessed.
 */
void drgn_dwarf_index_deinit(struct drgn_dwarf_index *dindex);

/**
 * Start reporting modules to a @ref drgn_dwarf_index.
 *
 * This must be paired with a call to either @ref drgn_dwarf_index_report_end()
 * or @ref drgn_dwarf_index_report_abort().
 */
void drgn_dwarf_index_report_begin(struct drgn_dwarf_index *dindex);

/**
 * Report a non-fatal error to a @ref drgn_dwarf_index.
 *
 * These errors are reported by @ref drgn_dwarf_index_report_end() in the @ref
 * DRGN_ERROR_MISSING_DEBUG_INFO error.
 *
 * @param[name] name An optional module name to prefix to the error message.
 * @param[message] message An optional message with additional context to prefix
 * to the error message.
 * @param[err] err The error to report. This may be @c NULL if @p name and @p
 * message provide sufficient information.
 * @return @c NULL on success, @ref drgn_enomem if the error could not be
 * reported.
 */
struct drgn_error *
drgn_dwarf_index_report_error(struct drgn_dwarf_index *dindex, const char *name,
			      const char *message, struct drgn_error *err);

/**
 * Report a module to a @ref drgn_dwarf_index from an ELF file.
 *
 * This takes ownership of @p fd and @p elf on either success or failure. They
 * should not be used (including closed or freed) after this returns.
 *
 * If this fails, @ref drgn_dwarf_index_report_abort() must be called.
 *
 * @param[in] path The path to the file.
 * @param[in] fd A file descriptor referring to the file.
 * @param[in] elf The Elf handle of the file.
 * @param[in] start The (inclusive) start address of the loaded file, or 0 if
 * the file is not loaded.
 * @param[in] end The (exclusive) end address of the loaded file, or 0 if the
 * file is not loaded.
 * @param[in] name An optional name for the module. This is only used for @ref
 * drgn_dwarf_index_is_indexed().
 * @param[out] new_ret Whether the module was newly created and reported. This
 * is @c false if a module with the same build ID and address range was already
 * indexed or a file with the same path and address range was already reported.
 */
struct drgn_error *drgn_dwarf_index_report_elf(struct drgn_dwarf_index *dindex,
					       const char *path, int fd,
					       Elf *elf, uint64_t start,
					       uint64_t end, const char *name,
					       bool *new_ret);

/**
 * Stop reporting modules to a @ref drgn_dwarf_index and index new DWARF
 * information.
 *
 * This parses and indexes the debugging information for all modules that have
 * not yet been indexed.
 *
 * If debug information was not available for one or more modules, a @ref
 * DRGN_ERROR_MISSING_DEBUG_INFO error is returned, those modules are freed, and
 * all other modules are added to the index.
 *
 * On any other error, no new debugging information is indexed and all unindexed
 * modules are freed.
 *
 * @param[in] report_from_dwfl Whether any <tt>Dwfl_Module</tt>s were reported
 * to @ref drgn_dwarf_index::dwfl directly via libdwfl. In that case, we need to
 * report those to the DWARF index, as well.
 */
struct drgn_error *drgn_dwarf_index_report_end(struct drgn_dwarf_index *dindex,
					       bool report_from_dwfl);

/**
 * Index new DWARF information and continue reporting.
 *
 * This is similar to @ref drgn_dwarf_index_report_end() except that it does not
 * finish reporting or return a @ref DRGN_ERROR_MISSING_DEBUG_INFO error. @ref
 * After this is called, more modules may be reported. @ref
 * drgn_dwarf_index_report_end() or @ref drgn_dwarf_index_report_abort() must
 * still be called.
 */
struct drgn_error *drgn_dwarf_index_flush(struct drgn_dwarf_index *dindex,
					  bool report_from_dwfl);

/**
 * Stop reporting modules to a @ref drgn_dwarf_index and free all unindexed
 * modules.
 *
 * This also clears all errors reported by @ref drgn_dwarf_index_report_error().
 *
 * This should be called instead of @ref drgn_dwarf_index_report_end() if a
 * fatal error is encountered while reporting modules.
 */
void drgn_dwarf_index_report_abort(struct drgn_dwarf_index *dindex);

/**
 * Return whether a @ref drgn_dwarf_index has indexed a module with the given
 * name.
 */
bool drgn_dwarf_index_is_indexed(struct drgn_dwarf_index *dindex,
				 const char *name);

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
