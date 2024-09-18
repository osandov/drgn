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
#include <elfutils/version.h>
#include <libelf.h>

#include "binary_search_tree.h"
#include "cfi.h"
#include "drgn_internal.h"
#include "dwarf_info.h"
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

// TODO: document
struct drgn_module_file_finder {
	struct drgn_handler handler;
	struct drgn_module_file_finder_ops ops;
	void *arg;
};

/** Cache of debugging information. */
struct drgn_debug_info {
	/** Program owning this cache. */
	struct drgn_program *prog;

	struct drgn_type_finder type_finder;
	struct drgn_object_finder object_finder;
	struct drgn_symbol_finder symbol_finder;

	struct drgn_module *main_module; // TODO: document
	struct drgn_module_table modules; // TODO: document
	/**
	 * Counter used to detect when @ref modules is modified during iteration
	 * of a @ref drgn_created_module_iterator.
	 */
	size_t modules_generation;
	struct drgn_module_address_tree modules_by_address; // TODO: document
	struct drgn_module *modules_pending_indexing;
	/** DWARF debugging information. */
	struct drgn_dwarf_info dwarf;

	struct drgn_handler_list module_file_finders;
	struct drgn_module_file_finder standard_module_file_finder;
	const char *debug_info_path;
	// TODO: explain. Specifically, this is the last generation number given
	// out, not the next to give out.
	uint64_t supplementary_file_generation;

#if WITH_DEBUGINFOD
	struct drgn_module_file_finder debuginfod_module_file_finder;
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
			     struct drgn_module **);

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

// TODO: where should this go?
static inline bool drgn_error_should_log(struct drgn_error *err)
{
	return err != &drgn_enomem;
}

DEFINE_HASH_MAP_TYPE(drgn_module_section_address_map, char *, uint64_t);

// TODO: document
// TODO: think about order
struct drgn_module {
	struct drgn_program *prog;
	enum drgn_module_kind kind;

	/** Module name. */
	char *name;
	// TODO
	union {
		struct {
			uint64_t dynamic_address;
		} shared_library;
		struct {
			uint64_t dynamic_address;
		} vdso;
		struct {
			uint64_t base_address;
		} linux_kernel_loadable;
		struct {
			uint64_t id;
		} extra;
	};
	/**
	 * TODO: use more generic naming
	 * Raw binary GNU build ID. @c NULL if the module does not have a GNU
	 * build ID.
	 */
	void *build_id;
	/**
	 * Length of @ref drgn_module::build_id in bytes. Zero if the module
	 * does not have a GNU build ID.
	 */
	size_t build_id_len;
	/**
	 * GNU build ID as a null-terminated hexadecimal string. @c NULL if the
	 * module does not have a GNU build ID.
	 *
	 * Used for logging and finding debugging information.
	 *
	 * This is allocated together with @ref drgn_module::build_id.
	 */
	char *build_id_str;
	// TODO
	struct binary_tree_node node;
	/**
	 * Load address range. Both 0 if not loaded. Both @c UINT64_MAX if not
	 * known yet.
	 */
	uint64_t start, end;

	struct drgn_elf_file *loaded_file;
	struct drgn_elf_file *debug_file;
	struct drgn_elf_file *supplementary_debug_file;
	struct drgn_elf_file_dwarf_table split_dwarf_files;
	// TODO: or just store in file? Is that too much memory for dwo?
	uint64_t loaded_file_bias;
	uint64_t debug_file_bias;
	enum drgn_module_file_status loaded_file_status;
	enum drgn_module_file_status debug_file_status;
	enum drgn_supplementary_file_kind supplementary_debug_file_kind;

	/** DWARF debugging information. */
	struct drgn_module_dwarf_info dwarf;
	/** ORC unwinder information. */
	struct drgn_module_orc_info orc;

	// TODO: better wording for this documentation?
	/** Whether .debug_frame has been parsed. */
	bool parsed_debug_frame;
	/** Whether .eh_frame has been parsed. */
	bool parsed_eh_frame;
	/** Whether ORC unwinder data has been parsed. */
	bool parsed_orc;

	struct drgn_module_section_address_map section_addresses;

	struct drgn_module_wanted_supplementary_file *wanted_supplementary_debug_file;
	struct drgn_module *pending_indexing_next;
};

struct drgn_error *drgn_module_find_or_create(struct drgn_program *prog,
					      const struct drgn_module_key *key,
					      const char *name,
					      struct drgn_module **ret,
					      bool *new_ret);

// Delete a partially-initialized module. This can only be called before the
// module is returned from public API.
void drgn_module_delete(struct drgn_module *module);

struct depmod_index {
	char *path;
	void *addr;
	size_t len;
};

struct drgn_module_standard_files_state {
	struct depmod_index modules_dep;
};

// Takes ownership of fd.
// TODO: explain path resolution
struct drgn_error *
drgn_module_try_file_internal(struct drgn_module *module, const char *path,
			      int fd, bool check_build_id,
			      const uint32_t *expected_crc);

// TODO: make it public?
bool drgn_module_set_section_address(struct drgn_module *module,
				     const char *name, uint64_t address);

// TODO: naming. Take prog instead of dbinfo?
struct drgn_module *drgn_module_by_address(struct drgn_debug_info *dbinfo,
					   uint64_t address);

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

static inline Elf_Type note_header_type(uint64_t p_align)
{
#if _ELFUTILS_PREREQ(0, 175)
	if (p_align == 8)
		return ELF_T_NHDR8;
#endif
	return ELF_T_NHDR;
}

size_t parse_gnu_build_id_from_note(const void *note, size_t note_size,
				    unsigned int align, bool bswap,
				    const void **ret);

struct drgn_error *find_elf_note(Elf *elf, const char *name, uint32_t type,
				 const void **ret, size_t *size_ret);

/** @} */

#endif /* DRGN_DEBUG_INFO_H */
