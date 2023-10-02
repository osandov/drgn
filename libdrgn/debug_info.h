// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

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
#include <elfutils/version.h>
#include <libelf.h>

#include "cfi.h"
#include "drgn.h"
#include "dwarf_info.h"
#include "hash_table.h"
#include "object_index.h"
#include "orc_info.h"
#include "string_builder.h"
#include "type.h"
#include "vector.h"

struct drgn_elf_file;

/**
 * @ingroup Internals
 *
 * @defgroup DebugInfo Debugging information
 *
 * Caching of debugging information.
 *
 * @ref drgn_debug_info caches debugging information (currently DWARF and ORC).
 * It translates the debugging information to types and objects.
 *
 * @{
 */

/** State of a @ref drgn_module. */
enum drgn_module_state {
	/** Reported but not indexed. */
	DRGN_DEBUG_INFO_MODULE_NEW,
	/** Reported and will be indexed on success. */
	DRGN_DEBUG_INFO_MODULE_INDEXING,
	/** Indexed. Must not be freed until @ref drgn_debug_info_destroy(). */
	DRGN_DEBUG_INFO_MODULE_INDEXED,
} __attribute__((__packed__));

DEFINE_HASH_TABLE_TYPE(drgn_elf_file_dwarf_table, struct drgn_elf_file *);

/**
 * A module reported to a @ref drgn_debug_info.
 *
 * Conceptually, a module is an ELF file loaded at a specific address range (or
 * not loaded).
 *
 * Files are identified by canonical path and, if present, build ID. Each (path,
 * address range) is uniquely represented by a @ref drgn_module.
 */
struct drgn_module {
	struct drgn_program *prog;

	/** @c NULL if the module does not have a build ID. */
	const void *build_id;
	/** Zero if the module does not have a build ID. */
	size_t build_id_len;
	/** Load address range, or both 0 if not loaded. */
	uint64_t start, end;
	/** Optional module name allocated with @c malloc(). */
	char *name;

	Dwfl_Module *dwfl_module;
	/** File that is loaded into the program. */
	struct drgn_elf_file *loaded_file;
	/** File containing debugging information. */
	struct drgn_elf_file *debug_file;
	/**
	 * Difference between addresses in program and addresses in @ref
	 * drgn_module::loaded_file.
	 */
	uint64_t loaded_file_bias;
	/**
	 * Difference between addresses in program and addresses in @ref
	 * drgn_module::debug_file.
	 */
	uint64_t debug_file_bias;

	struct drgn_elf_file_dwarf_table split_dwarf_files;

	/** DWARF debugging information. */
	struct drgn_module_dwarf_info dwarf;
	/** ORC unwinder information. */
	struct drgn_module_orc_info orc;

	/** Whether DWARF CFI from .debug_frame has been parsed. */
	bool parsed_debug_frame;
	/** Whether EH CFI from .eh_frame has been parsed. */
	bool parsed_eh_frame;
	/** Whether ORC unwinder data has been parsed. */
	bool parsed_orc;

	/*
	 * path, elf, and fd are used when an ELF file was reported with
	 * drgn_debug_info_report_elf() so we can report the file to libdwfl
	 * later. They are not valid after loading.
	 */
	char *path;
	Elf *elf;
	int fd;
	enum drgn_module_state state;
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
	struct drgn_module *next;
};

DEFINE_HASH_TABLE_TYPE(drgn_module_table, struct drgn_module *);

DEFINE_HASH_SET_TYPE(c_string_set, const char *);

/** Cache of debugging information. */
struct drgn_debug_info {
	/** Program owning this cache. */
	struct drgn_program *prog;

	struct drgn_type_finder type_finder;
	struct drgn_object_finder object_finder;

	/** DWARF frontend library handle. */
	Dwfl *dwfl;
	/** Modules keyed by build ID and address range. */
	struct drgn_module_table modules;
	/**
	 * Names of indexed modules.
	 *
	 * The entries in this set are @ref drgn_module::name, so they should
	 * not be freed.
	 */
	struct c_string_set module_names;
	/** DWARF debugging information. */
	struct drgn_dwarf_info dwarf;
};

/** Initialize a @ref drgn_debug_info. */
void drgn_debug_info_init(struct drgn_debug_info *dbinfo,
			  struct drgn_program *prog);

/** Deinitialize a @ref drgn_debug_info. */
void drgn_debug_info_deinit(struct drgn_debug_info *dbinfo);

DEFINE_VECTOR_TYPE(drgn_module_vector, struct drgn_module *);

/** State tracked while loading debugging information. */
struct drgn_debug_info_load_state {
	struct drgn_debug_info * const dbinfo;
	const char ** const paths;
	const size_t num_paths;
	const bool load_default;
	const bool load_main;
	/** Newly added modules to be indexed. */
	struct drgn_module_vector new_modules;
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

/**
 * Get the language of the program's `main` function or `NULL` if it could not
 * be found.
 */
struct drgn_error *
drgn_debug_info_main_language(struct drgn_debug_info *dbinfo,
			      const struct drgn_language **ret);

/** @ref drgn_type_find_fn() that uses debugging information. */
struct drgn_error *drgn_debug_info_find_type(uint64_t kinds, const char *name,
					     size_t name_len,
					     const char *filename, void *arg,
					     struct drgn_qualified_type *ret);

/** @ref drgn_object_find_fn() that uses debugging information. */
struct drgn_error *
drgn_debug_info_find_object(const char *name, size_t name_len,
			    const char *filename,
			    enum drgn_find_object_flags flags, void *arg,
			    struct drgn_object *ret);

struct drgn_elf_file *drgn_module_find_dwarf_file(struct drgn_module *module,
						  Dwarf *dwarf);

struct drgn_error *
drgn_module_create_split_dwarf_file(struct drgn_module *module,
				    const char *name, Dwarf *dwarf,
				    struct drgn_elf_file **ret);

/**
 * Get the Call Frame Information in a @ref drgn_module at a given program
 * counter.
 *
 * @param[in] module Module containing @p pc.
 * @param[in] pc Program counter.
 * @param[out] file_ret Returned file containing CFI.
 * @param[in,out] row_ret Returned CFI row.
 * @param[out] interrupted_ret Whether the found frame interrupted its caller.
 * @param[out] ret_addr_regno_ret Returned return address register number.
 * @return @c NULL on success, non-@c NULL on error. In particular, &@ref
 * drgn_not_found if CFI wasn't found.
 */
struct drgn_error *
drgn_module_find_cfi(struct drgn_program *prog, struct drgn_module *module,
		     uint64_t pc, struct drgn_elf_file **file_ret,
		     struct drgn_cfi_row **row_ret, bool *interrupted_ret,
		     drgn_register_number *ret_addr_regno_ret);

struct drgn_error *open_elf_file(const char *path, int *fd_ret, Elf **elf_ret);

struct drgn_error *find_elf_file(char **path_ret, int *fd_ret, Elf **elf_ret,
				 const char * const *path_formats, ...);

struct drgn_error *elf_address_range(Elf *elf, uint64_t bias,
				     uint64_t *start_ret, uint64_t *end_ret);

static inline Elf_Type note_header_type(uint64_t p_align)
{
#if _ELFUTILS_PREREQ(0, 175)
	if (p_align == 8)
		return ELF_T_NHDR8;
#endif
	return ELF_T_NHDR;
}

/** @} */

#endif /* DRGN_DEBUG_INFO_H */
