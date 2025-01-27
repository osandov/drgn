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

#if WITH_DEBUGINFOD
#include <elfutils/debuginfod.h>
#endif
#include <elfutils/libdw.h>
#include <libelf.h>

#include "binary_search_tree.h"
#include "cfi.h"
#include "debug_info_options.h"
#include "drgn_internal.h"
#include "dwarf_info.h"
#include "elf_symtab.h"
#include "hash_table.h"
#include "object.h"
#include "orc_info.h"
#include "string_builder.h"
#include "symbol.h"
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

DEFINE_HASH_TABLE_TYPE(drgn_elf_file_dwarf_table, struct drgn_elf_file *);
DEFINE_HASH_TABLE_TYPE(drgn_module_table, struct drgn_module *);
DEFINE_BINARY_SEARCH_TREE_TYPE(drgn_module_address_tree, struct drgn_module);

struct drgn_debug_info_finder {
	struct drgn_handler handler;
	struct drgn_debug_info_finder_ops ops;
	void *arg;
};

/** Cache of debugging information. */
struct drgn_debug_info {
	/** Program owning this cache. */
	struct drgn_program *prog;

	struct drgn_type_finder type_finder;
	struct drgn_object_finder object_finder;
	struct drgn_symbol_finder symbol_finder;

	/** Main module. @c NULL if not created yet. */
	struct drgn_module *main_module;
	/** Table of non-main modules indexed on @ref drgn_module_key. */
	struct drgn_module_table modules;
	/**
	 * Counter used to detect when @ref modules is modified during iteration
	 * of a @ref drgn_created_module_iterator.
	 */
	uint64_t modules_generation;
	/** Tree of modules sorted by start address. */
	struct drgn_module_address_tree modules_by_address;
	/**
	 * Singly-linked list of modules that need to have their DWARF
	 * information indexed.
	 */
	struct drgn_module *modules_pending_indexing;
	/** DWARF debugging information. */
	struct drgn_dwarf_info dwarf;

	struct drgn_handler_list debug_info_finders;
	struct drgn_debug_info_finder standard_debug_info_finder;
	struct drgn_debug_info_options options;
	/**
	 * Counter used to detect when loading debugging information is
	 * attempted.
	 *
	 * @sa drgn_module::load_debug_info_generation
	 */
	uint64_t load_debug_info_generation;
	/**
	 * Counter used to detect when the wanted supplementary file for a
	 * module has changed.
	 *
	 * @sa drgn_module_wanted_supplementary_file::generation
	 */
	uint64_t supplementary_file_generation;

#if WITH_DEBUGINFOD
	struct drgn_debug_info_finder debuginfod_debug_info_finder;
	/** debuginfod-client session. */
	debuginfod_client *debuginfod_client;
	const char *debuginfod_current_name;
	const char *debuginfod_current_type;
	unsigned int debuginfod_spinner_position;
	bool debuginfod_have_url;
	bool logged_debuginfod_progress;
#endif
	bool logged_no_debuginfod;

	/**
	 * Cache of entries in /proc/$pid/map_files used for finding loaded
	 * files. Populated the first time we need it or opportunistically when
	 * we parse /proc/$pid/maps. Rebuilt whenever we try to open an entry
	 * that no longer exists.
	 */
	struct drgn_map_files_segment *map_files_segments;
	/** Number of segments in @ref map_files_segments. */
	size_t num_map_files_segments;
};

/** Initialize a @ref drgn_debug_info. */
void drgn_debug_info_init(struct drgn_debug_info *dbinfo,
			  struct drgn_program *prog);

/** Deinitialize a @ref drgn_debug_info. */
void drgn_debug_info_deinit(struct drgn_debug_info *dbinfo);

typedef void drgn_module_iterator_destroy_fn(struct drgn_module_iterator *);
typedef struct drgn_error *
drgn_module_iterator_next_fn(struct drgn_module_iterator *,
			     struct drgn_module **, bool *);

struct drgn_module_iterator {
	struct drgn_program *prog;
	drgn_module_iterator_destroy_fn *destroy;
	drgn_module_iterator_next_fn *next;
};

static inline void
drgn_module_iterator_init(struct drgn_module_iterator *it,
			  struct drgn_program *prog,
			  drgn_module_iterator_destroy_fn *destroy,
			  drgn_module_iterator_next_fn *next)
{
	it->prog = prog;
	it->destroy = destroy;
	it->next = next;
}

/** Bitmask of files in a @ref drgn_module. */
enum drgn_module_file_mask {
	DRGN_MODULE_FILE_MASK_LOADED = 1 << 0,
	DRGN_MODULE_FILE_MASK_DEBUG = 1 << 1,
} __attribute__((__packed__));

DEFINE_HASH_MAP_TYPE(drgn_module_section_address_map, char *, uint64_t);

struct drgn_module {
	struct drgn_program *prog;
	enum drgn_module_kind kind;

	/** Module name. */
	char *name;
	/** Kind-specific information. */
	union {
		struct {
			uint64_t dynamic_address;
		} shared_library;
		struct {
			uint64_t dynamic_address;
		} vdso;
		struct {
			uint64_t address;
		} relocatable;
		struct {
			uint64_t id;
		} extra;
	};
	/**
	 * Raw binary build ID. @c NULL if the module does not have a build ID.
	 */
	void *build_id;
	/**
	 * Length of @ref drgn_module::build_id in bytes. Zero if the module
	 * does not have a build ID.
	 */
	size_t build_id_len;
	/**
	 * Build ID as a null-terminated hexadecimal string. @c NULL if the
	 * module does not have a build ID.
	 *
	 * Used for logging and finding debugging information.
	 *
	 * This is allocated together with @ref drgn_module::build_id.
	 */
	char *build_id_str;
	/** Node in @ref drgn_debug_info::modules_by_address. */
	struct binary_tree_node node;
	/**
	 * Load address range. Both 0 if not loaded. Both @c UINT64_MAX if not
	 * known yet.
	 */
	uint64_t start, end;

	struct drgn_elf_file *loaded_file;
	struct drgn_elf_file *debug_file;
	struct drgn_elf_file *supplementary_debug_file;
	/** Table mapping libdw handle to corresponding @ref drgn_elf_file. */
	struct drgn_elf_file_dwarf_table split_dwarf_files;
	uint64_t loaded_file_bias;
	uint64_t debug_file_bias;
	enum drgn_module_file_status loaded_file_status;
	enum drgn_module_file_status debug_file_status;
	enum drgn_supplementary_file_kind supplementary_debug_file_kind;

	/** DWARF debugging information. */
	struct drgn_module_dwarf_info dwarf;
	/** ORC unwinder information. */
	struct drgn_module_orc_info orc;
	/** ELF symbol table. */
	struct drgn_elf_symbol_table elf_symtab;

	/** Whether .debug_frame has been parsed. */
	bool parsed_debug_frame;
	/** Whether .eh_frame has been parsed. */
	bool parsed_eh_frame;
	/** Whether ORC unwinder data has been parsed. */
	bool parsed_orc;
	/** Which files need to be checked for an ELF symbol table. */
	enum drgn_module_file_mask elf_symtab_pending_files;
	/**
	 * Whether a full symbol table has been found (as opposed to a dynamic
	 * symbol table, which only contains a subset of symbols).
	 */
	bool have_full_symtab;

	/** Mapping from section name to address. */
	struct drgn_module_section_address_map section_addresses;
	/**
	 * Counter used to detect when @ref section_addresses is modified during
	 * iteration of a @ref drgn_module_section_address_iterator.
	 */
	uint64_t section_addresses_generation;

	/**
	 * Counter used to detect when loading debugging information is
	 * attempted.
	 *
	 * @sa drgn_debug_info::load_debug_info_generation
	 */
	uint64_t load_debug_info_generation;
	struct drgn_module_wanted_supplementary_file *wanted_supplementary_debug_file;
	/** Node in @ref drgn_debug_info::modules_pending_indexing. */
	struct drgn_module *pending_indexing_next;
};

struct drgn_error *drgn_module_find_or_create(struct drgn_program *prog,
					      const struct drgn_module_key *key,
					      const char *name,
					      struct drgn_module **ret,
					      bool *new_ret);

/**
 * Delete a partially-initialized module. This can only be called before the
 * module is returned from public API.
 */
void drgn_module_delete(struct drgn_module *module);

static inline void drgn_module_deletep(struct drgn_module **modulep)
{
	if (*modulep)
		drgn_module_delete(*modulep);
}

// Binary index file generated by depmod(8).
struct depmod_index {
	char *path;
	void *addr;
	size_t len;
};

// State kept by standard debug info finder for all modules it's working on.
// Currently it's only used to cache locations of Linux kernel loadable modules.
struct drgn_standard_debug_info_find_state {
	struct depmod_index modules_dep;
};

void
drgn_standard_debug_info_find_state_deinit(struct drgn_standard_debug_info_find_state *state);

// Always takes ownership of fd. Attempts to resolve the real path of path.
struct drgn_error *
drgn_module_try_standard_file(struct drgn_module *module,
			      const struct drgn_debug_info_options *options,
			      const char *path, int fd, bool check_build_id,
			      const uint32_t *expected_crc);

static inline bool drgn_module_wants_file(struct drgn_module *module)
{
	return drgn_module_wants_loaded_file(module)
	       || drgn_module_wants_debug_file(module);
}

/**
 * Get the language of the program's `main` function or `NULL` if it could not
 * be found.
 */
const struct drgn_language *
drgn_debug_info_main_language(struct drgn_debug_info *dbinfo);

/** @ref drgn_type_finder_ops::find() that uses debugging information. */
struct drgn_error *drgn_debug_info_find_type(uint64_t kinds, const char *name,
					     size_t name_len,
					     const char *filename, void *arg,
					     struct drgn_qualified_type *ret);

/** @ref drgn_object_finder_ops::find() that uses debugging information. */
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

/** @} */

#endif /* DRGN_DEBUG_INFO_H */
