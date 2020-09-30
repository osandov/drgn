// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Debugging information handling.
 *
 * See @ref DebugInfo.
 */

#ifndef DRGN_DEBUG_INFO_H
#define DRGN_DEBUG_INFO_H

#include <elfutils/libdwfl.h>
#include <libelf.h>

#include "drgn.h"
#include "dwarf_index.h"
#include "hash_table.h"
#include "string_builder.h"
#include "vector.h"

/**
 * @ingroup Internals
 *
 * @defgroup DebugInfo Debugging information
 *
 * Caching of debugging information.
 *
 * @ref drgn_debug_info caches debugging information (currently only DWARF). It
 * translates the debugging information to types and objects.
 *
 * @{
 */

/** State of a @ref drgn_debug_info_module. */
enum drgn_debug_info_module_state {
	/** Reported but not indexed. */
	DRGN_DEBUG_INFO_MODULE_NEW,
	/** Reported and will be indexed on success. */
	DRGN_DEBUG_INFO_MODULE_INDEXING,
	/** Indexed. Must not be freed until @ref drgn_debug_info_destroy(). */
	DRGN_DEBUG_INFO_MODULE_INDEXED,
} __attribute__((packed));

/**
 * A module reported to a @ref drgn_debug_info.
 *
 * Conceptually, a module is an ELF file loaded at a specific address range (or
 * not loaded).
 *
 * Files are identified by canonical path and, if present, build ID. Each (path,
 * address range) is uniquely represented by a @ref drgn_debug_info_module.
 */
struct drgn_debug_info_module {
	/** @c NULL if the module does not have a build ID. */
	const void *build_id;
	/** Zero if the module does not have a build ID. */
	size_t build_id_len;
	/** Load address range, or both 0 if not loaded. */
	uint64_t start, end;
	/** Optional module name allocated with @c malloc(). */
	char *name;

	Dwfl_Module *dwfl_module;
	Elf_Data *debug_info;
	Elf_Data *debug_abbrev;
	Elf_Data *debug_str;
	Elf_Data *debug_line;

	/*
	 * path, elf, and fd are used when an ELF file was reported with
	 * drgn_debug_info_report_elf() so we can report the file to libdwfl
	 * later. They are not valid after loading.
	 */
	char *path;
	Elf *elf;
	int fd;
	enum drgn_debug_info_module_state state;
	bool bswap;
	/** Error while loading. */
	struct drgn_error *err;
	/**
	 * Next module with same build ID and address range.
	 *
	 * There may be multiple files with the same build ID (e.g., a stripped
	 * binary and its corresponding separate debug info file). While
	 * loading, all files with the same build ID and address range are
	 * linked in a list. Only one is indexed; the rest are destroyed.
	 */
	struct drgn_debug_info_module *next;
};

struct drgn_debug_info_module_key {
	const void *build_id;
	size_t build_id_len;
	uint64_t start, end;
};

static inline struct drgn_debug_info_module_key
drgn_debug_info_module_key(struct drgn_debug_info_module * const *entry)
{
	return (struct drgn_debug_info_module_key){
		.build_id = (*entry)->build_id,
		.build_id_len = (*entry)->build_id_len,
		.start = (*entry)->start,
		.end = (*entry)->end,
	};
}
DEFINE_HASH_TABLE_TYPE(drgn_debug_info_module_table,
		       struct drgn_debug_info_module *,
		       drgn_debug_info_module_key)

DEFINE_HASH_SET_TYPE(c_string_set, const char *)

/** Cached type in a @ref drgn_debug_info. */
struct drgn_dwarf_type {
	struct drgn_type *type;
	enum drgn_qualifiers qualifiers;
	/**
	 * Whether this is an incomplete array type or a typedef of one.
	 *
	 * This is used to work around a GCC bug; see @ref
	 * drgn_type_from_dwarf_internal().
	 */
	bool is_incomplete_array;
};

DEFINE_HASH_MAP_TYPE(drgn_dwarf_type_map, const void *, struct drgn_dwarf_type);

/** Cache of debugging information. */
struct drgn_debug_info {
	/** Program owning this cache. */
	struct drgn_program *prog;

	/** DWARF frontend library handle. */
	Dwfl *dwfl;
	/** Modules keyed by build ID and address range. */
	struct drgn_debug_info_module_table modules;
	/**
	 * Names of indexed modules.
	 *
	 * The entries in this set are @ref drgn_debug_info_module::name, so
	 * they should not be freed.
	 */
	struct c_string_set module_names;
	/** Index of DWARF debugging information. */
	struct drgn_dwarf_index dindex;

	/**
	 * Cache of parsed types.
	 *
	 * The key is the address of the DIE (@c Dwarf_Die::addr). The value is
	 * a @ref drgn_dwarf_type.
	 */
	struct drgn_dwarf_type_map types;
	/**
	 * Cache of parsed types which appear to be incomplete array types but
	 * can't be.
	 *
	 * See @ref drgn_type_from_dwarf_internal().
	 */
	struct drgn_dwarf_type_map cant_be_incomplete_array_types;
	/** Current parsing recursion depth. */
	int depth;
};

/** Create a @ref drgn_debug_info. */
struct drgn_error *drgn_debug_info_create(struct drgn_program *prog,
					  struct drgn_debug_info **ret);

/** Destroy a @ref drgn_debug_info. */
void drgn_debug_info_destroy(struct drgn_debug_info *dbinfo);

DEFINE_VECTOR_TYPE(drgn_debug_info_module_vector,
		   struct drgn_debug_info_module *)

/** State tracked while loading debugging information. */
struct drgn_debug_info_load_state {
	struct drgn_debug_info * const dbinfo;
	const char ** const paths;
	const size_t num_paths;
	const bool load_default;
	const bool load_main;
	/** Newly added modules to be indexed. */
	struct drgn_debug_info_module_vector new_modules;
	/** Formatted errors reported by @ref drgn_debug_info_report_error(). */
	struct string_builder errors;
	/** Number of errors reported by @ref drgn_debug_info_report_error(). */
	unsigned int num_errors;
	/** Maximum number of errors to report before truncating. */
	unsigned int max_errors;
};

/**
 * Report a non-fatal error while loading debugging information.
 *
 * The error will be included in a @ref DRGN_ERROR_MISSING_DEBUG_INFO error
 * returned by @ref drgn_debug_info_load().
 *
 * @param[name] name An optional module name to prefix to the error message.
 * @param[message] message An optional message with additional context to prefix
 * to the error message.
 * @param[err] err The error to report. This may be @c NULL if @p name and @p
 * message provide sufficient information. This is destroyed on either success
 * or failure.
 * @return @c NULL on success, @ref drgn_enomem if the error could not be
 * reported.
 */
struct drgn_error *
drgn_debug_info_report_error(struct drgn_debug_info_load_state *load,
			     const char *name, const char *message,
			     struct drgn_error *err);

/**
 * Report a module to a @ref drgn_debug_info from an ELF file.
 *
 * This takes ownership of @p fd and @p elf on either success or failure. They
 * should not be used (including closed or freed) after this returns.
 *
 * @param[in] path The path to the file.
 * @param[in] fd A file descriptor referring to the file.
 * @param[in] elf The Elf handle of the file.
 * @param[in] start The (inclusive) start address of the loaded file, or 0 if
 * the file is not loaded.
 * @param[in] end The (exclusive) end address of the loaded file, or 0 if the
 * file is not loaded.
 * @param[in] name An optional name for the module. This is only used for @ref
 * drgn_debug_info_is_indexed().
 * @param[out] new_ret Whether the module was newly created and reported. This
 * is @c false if a module with the same build ID and address range was already
 * loaded or a file with the same path and address range was already reported.
 */
struct drgn_error *
drgn_debug_info_report_elf(struct drgn_debug_info_load_state *load,
			   const char *path, int fd, Elf *elf, uint64_t start,
			   uint64_t end, const char *name, bool *new_ret);

/** Index new debugging information and continue reporting. */
struct drgn_error *
drgn_debug_info_report_flush(struct drgn_debug_info_load_state *load);

/**
 * Load debugging information.
 *
 * @sa drgn_program_load_debug_info
 */
struct drgn_error *drgn_debug_info_load(struct drgn_debug_info *dbinfo,
					const char **paths, size_t n,
					bool load_default, bool load_main);

/**
 * Return whether a @ref drgn_debug_info has indexed a module with the given
 * name.
 */
bool drgn_debug_info_is_indexed(struct drgn_debug_info *dbinfo,
				const char *name);

/** @ref drgn_type_find_fn() that uses debugging information. */
struct drgn_error *drgn_debug_info_find_type(enum drgn_type_kind kind,
					     const char *name, size_t name_len,
					     const char *filename, void *arg,
					     struct drgn_qualified_type *ret);

/** @ref drgn_object_find_fn() that uses debugging information. */
struct drgn_error *
drgn_debug_info_find_object(const char *name, size_t name_len,
			    const char *filename,
			    enum drgn_find_object_flags flags, void *arg,
			    struct drgn_object *ret);

struct drgn_error *open_elf_file(const char *path, int *fd_ret, Elf **elf_ret);

struct drgn_error *find_elf_file(char **path_ret, int *fd_ret, Elf **elf_ret,
				 const char * const *path_formats, ...);

struct drgn_error *read_elf_section(Elf_Scn *scn, Elf_Data **ret);

struct drgn_error *elf_address_range(Elf *elf, uint64_t bias,
				     uint64_t *start_ret, uint64_t *end_ret);

/** @} */

#endif /* DRGN_DEBUG_INFO_H */
