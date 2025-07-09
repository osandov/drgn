// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <byteswap.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwelf.h>
#include <elfutils/version.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <wchar.h>

#include "array.h"
#include "binary_buffer.h"
#include "binary_search.h"
#include "cleanup.h"
#include "crc32.h"
#include "debug_info.h"
#include "elf_file.h"
#include "elf_notes.h"
#include "error.h"
#include "hexlify.h"
#include "io.h"
#include "linux_kernel.h"
#include "log.h"
#include "openmp.h"
#include "platform.h"
#include "pp.h"
#include "program.h"
#include "serialize.h"
#include "util.h"

#define _cleanup_elf_end_ _cleanup_(elf_endp)
static inline void elf_endp(Elf **elfp)
{
	elf_end(*elfp);
}

#if !_ELFUTILS_PREREQ(0, 175)
// If we don't have dwelf_elf_begin(), this is equivalent except that it doesn't
// handle compressed files.
static inline Elf *dwelf_elf_begin(int fd)
{
	return elf_begin(fd, ELF_C_READ_MMAP_PRIVATE, NULL);
}
#endif

DEFINE_HASH_MAP_FUNCTIONS(drgn_module_section_address_map,
			  c_string_key_hash_pair, c_string_key_eq);

// This is currently always DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK.
struct drgn_module_wanted_supplementary_file {
	struct drgn_elf_file *file;
	// supplementary_path and checksum are owned by file.
	const char *supplementary_path;
	const void *checksum;
	size_t checksum_len;
	// checksum_str is a separate allocation.
	char *checksum_str;
	// Used to detect when the wanted supplementary file has changed in
	// order to avoid redundant attempts.
	uint64_t generation;
};

#if WITH_DEBUGINFOD
#if _ELFUTILS_PREREQ(0, 179)
#define DRGN_DEBUGINFOD_0_179_FUNCTIONS	\
	X(debuginfod_set_user_data)	\
	X(debuginfod_get_user_data)	\
	X(debuginfod_get_url)
#else
#define DRGN_DEBUGINFOD_0_179_FUNCTIONS
#endif

#define DRGN_DEBUGINFOD_FUNCTIONS	\
	X(debuginfod_begin)		\
	X(debuginfod_end)		\
	X(debuginfod_find_debuginfo)	\
	X(debuginfod_find_executable)	\
	X(debuginfod_set_progressfn)	\
	DRGN_DEBUGINFOD_0_179_FUNCTIONS

#if ENABLE_DLOPEN_DEBUGINFOD
#include <dlfcn.h>

#define X(name) static typeof(&name) drgn_##name;
DRGN_DEBUGINFOD_FUNCTIONS
#undef X

__attribute__((__constructor__))
static void drgn_dlopen_debuginfod(void)
{
	void *handle = dlopen(DEBUGINFOD_SONAME, RTLD_LAZY);
	if (handle) {
		#define X(name) drgn_##name = dlsym(handle, #name);
		DRGN_DEBUGINFOD_FUNCTIONS
		#undef X

		#define X(name) || !drgn_##name
		if (0 DRGN_DEBUGINFOD_FUNCTIONS) {
		#undef X
			#define X(name) drgn_##name = NULL;
			DRGN_DEBUGINFOD_FUNCTIONS
			#undef X
			dlclose(handle);
		}
	}
}

bool drgn_have_debuginfod(void)
{
	return drgn_debuginfod_begin != NULL;
}
#else
// GCC and Clang optimize out the function pointer.
#define X(name) static const typeof(&name) drgn_##name = name;
DRGN_DEBUGINFOD_FUNCTIONS
#undef X
#endif

#undef DRGN_DEBUGINFOD_FUNCTIONS
#undef DRGN_DEBUGINFOD_0_179_FUNCTIONS
#endif

static inline Dwarf *drgn_elf_file_dwarf_key(struct drgn_elf_file * const *entry)
{
	return (*entry)->_dwarf;
}
DEFINE_HASH_TABLE_FUNCTIONS(drgn_elf_file_dwarf_table, drgn_elf_file_dwarf_key,
			    ptr_key_hash_pair, scalar_key_eq);
DEFINE_VECTOR(drgn_module_vector, struct drgn_module *);

static inline const char *drgn_module_entry_name(struct drgn_module * const *entry)
{
	return (*entry)->name;
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_module_table, drgn_module_entry_name,
			    c_string_key_hash_pair, c_string_key_eq);

static inline uint64_t
drgn_module_address_range_key(const struct drgn_module_address_range *entry)
{
	return entry->start;
}

DEFINE_BINARY_SEARCH_TREE_FUNCTIONS(drgn_module_address_tree, node,
				    drgn_module_address_range_key,
				    binary_search_tree_scalar_cmp, splay);

static void drgn_module_free_section_addresses(struct drgn_module *module)
{
	hash_table_for_each(drgn_module_section_address_map, it,
			    &module->section_addresses)
		free(it.entry->key);
}

LIBDRGN_PUBLIC
struct drgn_module *drgn_module_find_by_name(struct drgn_program *prog,
					     const char *name)
{
	struct drgn_module_table_iterator it =
		drgn_module_table_search(&prog->dbinfo.modules, &name);
	return it.entry ? *it.entry : NULL;
}

LIBDRGN_PUBLIC
struct drgn_module *drgn_module_find_by_address(struct drgn_program *prog,
						uint64_t address)
{
	struct drgn_module_address_tree_iterator it =
		drgn_module_address_tree_search_le(&prog->dbinfo.modules_by_address,
						   &address);
	if (!it.entry || address >= it.entry->end)
		return NULL;
	return it.entry->module;
}

static struct drgn_module *drgn_module_find(struct drgn_program *prog,
					    enum drgn_module_kind kind,
					    const char *name, uint64_t info)
{
	struct drgn_module_table_iterator it =
		drgn_module_table_search(&prog->dbinfo.modules, &name);
	if (!it.entry)
		return NULL;
	struct drgn_module *module = *it.entry;
	while (module->kind != kind || module->info != info) {
		module = module->next_same_name;
		if (!module)
			break;
	}
	return module;
}

static struct drgn_error *
drgn_module_find_or_create(struct drgn_program *prog,
			   enum drgn_module_kind kind, const char *name,
			   uint64_t info, struct drgn_module **ret,
			   bool *new_ret)
{
	struct drgn_error *err;

	struct hash_pair hp;
	struct drgn_module_table_iterator it;
	if (kind == DRGN_MODULE_MAIN) {
		if (prog->dbinfo.main_module) {
			if (strcmp(prog->dbinfo.main_module->name, name) != 0) {
				return drgn_error_create(DRGN_ERROR_LOOKUP,
							 "main module already exists with different name");
			}
			*ret = prog->dbinfo.main_module;
			if (new_ret)
				*new_ret = false;
			return NULL;
		}
		hp = drgn_module_table_hash(&name);
		it.entry = NULL;
	} else {
		hp = drgn_module_table_hash(&name);
		it = drgn_module_table_search_hashed(&prog->dbinfo.modules,
						     &name, hp);
		if (it.entry) {
			struct drgn_module *module = *it.entry;
			do {
				if (module->kind == kind && module->info == info) {
					*ret = module;
					if (new_ret)
						*new_ret = false;
					return NULL;
				}
				module = module->next_same_name;
			} while (module);
		}
	}

	struct drgn_module *module = calloc(1, sizeof(*module));
	if (!module)
		return &drgn_enomem;

	module->prog = prog;
	module->kind = kind;
	module->info = info;
	drgn_object_init(&module->object, prog);
	// Linux userspace core dumps usually filter out file-backed mappings
	// (see coredump_filter in core(5)), so we need the loaded file to read
	// the text. Additionally, .eh_frame is in the loaded file and not the
	// debug file.
	//
	// Linux kernel core dumps preserve the main kernel and kernel module
	// text, and the kernel doesn't use .eh_frame, so we don't need the
	// loaded file for the kernel.
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL
	    && (kind == DRGN_MODULE_MAIN || kind == DRGN_MODULE_RELOCATABLE))
		module->loaded_file_status = DRGN_MODULE_FILE_DONT_NEED;
	else
		module->loaded_file_status = DRGN_MODULE_FILE_WANT;
	module->debug_file_status = DRGN_MODULE_FILE_WANT;

	module->name = strdup(name);
	if (!module->name) {
		err = &drgn_enomem;
		goto err_module;
	}

	if (it.entry) {
		module->next_same_name = *it.entry;
		*it.entry = module;
	} else if (drgn_module_table_insert_searched(&prog->dbinfo.modules,
						     &module, hp, NULL) < 0) {
		err = &drgn_enomem;
		goto err_name;
	}
	if (kind == DRGN_MODULE_MAIN)
		prog->dbinfo.main_module = module;
	prog->dbinfo.modules_generation++;

	drgn_elf_file_dwarf_table_init(&module->split_dwarf_files);
	drgn_module_section_address_map_init(&module->section_addresses);

	SWITCH_ENUM(module->kind) {
	case DRGN_MODULE_MAIN:
		drgn_log_debug(prog, "created main module %s", module->name);
		break;
	case DRGN_MODULE_SHARED_LIBRARY:
		drgn_log_debug(prog,
			       "created shared library module %s@0x%" PRIx64,
			       module->name, module->info);
		break;
	case DRGN_MODULE_VDSO:
		drgn_log_debug(prog, "created vDSO module %s@0x%" PRIx64,
			       module->name, module->info);
		break;
	case DRGN_MODULE_RELOCATABLE:
		drgn_log_debug(prog, "created relocatable module %s@0x%" PRIx64,
			       module->name, module->info);
		break;
	case DRGN_MODULE_EXTRA:
		drgn_log_debug(prog, "created extra module %s 0x%" PRIx64,
			       module->name, module->info);
		break;
	default:
		UNREACHABLE();
	}

	*ret = module;
	if (new_ret)
		*new_ret = true;
	return NULL;

err_name:
	free(module->name);
err_module:
	drgn_object_deinit(&module->object);
	free(module);
	return err;
}

LIBDRGN_PUBLIC
struct drgn_module *drgn_module_find_main(struct drgn_program *prog,
					  const char *name)
{
	if (name && prog->dbinfo.main_module
	    && strcmp(prog->dbinfo.main_module->name, name) != 0)
		return NULL;
	return prog->dbinfo.main_module;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_find_or_create_main(struct drgn_program *prog,
						   const char *name,
						   struct drgn_module **ret,
						   bool *new_ret)
{
	return drgn_module_find_or_create(prog, DRGN_MODULE_MAIN, name, 0, ret,
					  new_ret);
}

LIBDRGN_PUBLIC
struct drgn_module *drgn_module_find_shared_library(struct drgn_program *prog,
						    const char *name,
						    uint64_t dynamic_address)
{
	return drgn_module_find(prog, DRGN_MODULE_SHARED_LIBRARY, name,
				dynamic_address);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_find_or_create_shared_library(struct drgn_program *prog,
					  const char *name,
					  uint64_t dynamic_address,
					  struct drgn_module **ret,
					  bool *new_ret)
{
	return drgn_module_find_or_create(prog, DRGN_MODULE_SHARED_LIBRARY,
					  name, dynamic_address, ret, new_ret);
}

LIBDRGN_PUBLIC
struct drgn_module *drgn_module_find_vdso(struct drgn_program *prog,
					  const char *name,
					  uint64_t dynamic_address)
{
	return drgn_module_find(prog, DRGN_MODULE_VDSO, name, dynamic_address);
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_find_or_create_vdso(struct drgn_program *prog,
						   const char *name,
						   uint64_t dynamic_address,
						   struct drgn_module **ret,
						   bool *new_ret)
{
	return drgn_module_find_or_create(prog, DRGN_MODULE_VDSO, name,
					  dynamic_address, ret, new_ret);
}

LIBDRGN_PUBLIC
struct drgn_module *drgn_module_find_relocatable(struct drgn_program *prog,
						 const char *name,
						 uint64_t address)
{
	return drgn_module_find(prog, DRGN_MODULE_RELOCATABLE, name, address);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_find_or_create_relocatable(struct drgn_program *prog,
				       const char *name, uint64_t address,
				       struct drgn_module **ret, bool *new_ret)
{
	return drgn_module_find_or_create(prog, DRGN_MODULE_RELOCATABLE, name,
					  address, ret, new_ret);
}

LIBDRGN_PUBLIC
struct drgn_module *drgn_module_find_extra(struct drgn_program *prog,
					   const char *name, uint64_t id)
{
	return drgn_module_find(prog, DRGN_MODULE_EXTRA, name, id);
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_find_or_create_extra(struct drgn_program *prog,
						    const char *name,
						    uint64_t id,
						    struct drgn_module **ret,
						    bool *new_ret)
{
	return drgn_module_find_or_create(prog, DRGN_MODULE_EXTRA, name, id,
					  ret, new_ret);
}

static void
drgn_module_clear_wanted_supplementary_debug_file(struct drgn_module *module)
{
	struct drgn_module_wanted_supplementary_file *wanted =
		module->wanted_supplementary_debug_file;
	if (wanted) {
		free(wanted->checksum_str);
		if (wanted->file != module->loaded_file
		    && wanted->file != module->debug_file)
			drgn_elf_file_destroy(wanted->file);
		free(wanted);
		module->wanted_supplementary_debug_file = NULL;
	}
}

// Note: this doesn't remove the module from the module tables.
static void drgn_module_destroy(struct drgn_module *module)
{
	drgn_module_free_section_addresses(module);
	drgn_module_section_address_map_deinit(&module->section_addresses);
	drgn_module_orc_info_deinit(module);
	drgn_module_dwarf_info_deinit(module);
	drgn_module_clear_wanted_supplementary_debug_file(module);
	drgn_elf_file_destroy(module->gnu_debugdata_file);
	drgn_elf_file_destroy(module->supplementary_debug_file);
	if (module->debug_file != module->loaded_file)
		drgn_elf_file_destroy(module->debug_file);
	drgn_elf_file_destroy(module->loaded_file);
	if (module->address_ranges != &module->single_address_range)
		free(module->address_ranges);
	free(module->build_id);
	free(module->name);
	drgn_object_deinit(&module->object);
	free(module);
}

static void drgn_module_delete_address_ranges(struct drgn_module *module)
{
	for (size_t i = 0; i < module->num_address_ranges; i++) {
		drgn_module_address_tree_delete_entry(&module->prog->dbinfo.modules_by_address,
						      &module->address_ranges[i]);
	}
	if (module->address_ranges != &module->single_address_range)
		free(module->address_ranges);
}

void drgn_module_delete(struct drgn_module *module)
{
	assert(!module->loaded_file);
	assert(!module->debug_file);
	drgn_module_delete_address_ranges(module);
	// So drgn_module_destroy() doesn't free it again.
	module->address_ranges = NULL;

	const char *name = module->name;
	struct drgn_module_table_iterator it =
		drgn_module_table_search(&module->prog->dbinfo.modules, &name);
	if (*it.entry == module && !module->next_same_name) {
		drgn_module_table_delete_iterator(&module->prog->dbinfo.modules,
						  it);
	} else {
		struct drgn_module **modulep = it.entry;
		while (*modulep != module)
			modulep = &(*modulep)->next_same_name;
		*modulep = module->next_same_name;
	}
	if (module->kind == DRGN_MODULE_MAIN)
		module->prog->dbinfo.main_module = NULL;
	module->prog->dbinfo.modules_generation++;

	drgn_module_destroy(module);
}

LIBDRGN_PUBLIC
struct drgn_program *drgn_module_program(const struct drgn_module *module)
{
	return module->prog;
}

LIBDRGN_PUBLIC
enum drgn_module_kind drgn_module_kind(const struct drgn_module *module)
{
	return module->kind;
}

LIBDRGN_PUBLIC const char *drgn_module_name(const struct drgn_module *module)
{
	return module->name;
}

LIBDRGN_PUBLIC uint64_t drgn_module_info(const struct drgn_module *module)
{
	return module->info;
}

LIBDRGN_PUBLIC
bool drgn_module_num_address_ranges(const struct drgn_module *module,
				    size_t *ret)
{
	*ret = module->num_address_ranges;
	return module->address_ranges != NULL;
}

LIBDRGN_PUBLIC bool drgn_module_address_range(const struct drgn_module *module,
					      size_t i, uint64_t *start_ret,
					      uint64_t *end_ret)
{
	if (i >= module->num_address_ranges)
		return false;
	*start_ret = module->address_ranges[i].start;
	*end_ret = module->address_ranges[i].end;
	return true;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_set_address_range(struct drgn_module *module,
						 uint64_t start, uint64_t end)
{
	// This is a special case instead of a wrapper around
	// drgn_module_set_address_ranges() so we can avoid allocating memory.
	// Since the old address range might be module->single_address_range,
	// this has to do things in a different order.

	if (start >= end) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid module address range");
	}

	drgn_module_delete_address_ranges(module);

	module->single_address_range.start = start;
	module->single_address_range.end = end;
	module->single_address_range.module = module;

	// We don't bother checking for overlapping address ranges, which
	// shouldn't happen with well-formed programs and at worst causes
	// spurious failed lookups. We may need to revisit this if it's a
	// problem in practice.
	drgn_module_address_tree_insert(&module->prog->dbinfo.modules_by_address,
					&module->single_address_range, NULL);

	module->address_ranges = &module->single_address_range;
	module->num_address_ranges = 1;
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_set_address_ranges(struct drgn_module *module,
						  uint64_t ranges[][2],
						  size_t num_ranges)
{
	if (num_ranges == 1) {
		return drgn_module_set_address_range(module, ranges[0][0],
						     ranges[0][1]);
	}

	_cleanup_free_ struct drgn_module_address_range *address_ranges = NULL;
	if (num_ranges) {
		address_ranges =
			malloc_array(num_ranges, sizeof(*address_ranges));
		if (!address_ranges)
			return &drgn_enomem;
		for (size_t i = 0; i < num_ranges; i++) {
			if (ranges[i][0] >= ranges[i][1]) {
				return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
							 "invalid module address range");
			}
			address_ranges[i].start = ranges[i][0];
			address_ranges[i].end = ranges[i][1];
			address_ranges[i].module = module;
		}
	}

	drgn_module_delete_address_ranges(module);

	for (size_t i = 0; i < num_ranges; i++) {
		// We don't bother checking for overlapping address ranges; see
		// drgn_module_set_address_range().
		drgn_module_address_tree_insert(&module->prog->dbinfo.modules_by_address,
						&address_ranges[i], NULL);
	}

	if (num_ranges) {
		module->address_ranges = no_cleanup_ptr(address_ranges);
	} else {
		// We need a non-NULL pointer to distinguish this from the unset
		// case.
		module->address_ranges = &module->single_address_range;
	}
	module->num_address_ranges = num_ranges;
	return NULL;
}

LIBDRGN_PUBLIC void drgn_module_unset_address_ranges(struct drgn_module *module)
{
	drgn_module_delete_address_ranges(module);
	module->address_ranges = NULL;
	module->num_address_ranges = 0;
}

LIBDRGN_PUBLIC
bool drgn_module_contains_address(const struct drgn_module *module,
				  uint64_t address)
{
	for (size_t i = 0; i < module->num_address_ranges; i++) {
		if (module->address_ranges[i].start <= address
		    && address < module->address_ranges[i].end)
			return true;
	}
	return false;
}

LIBDRGN_PUBLIC
const char *drgn_module_build_id(const struct drgn_module *module,
				 const void **raw_ret, size_t *raw_len_ret)
{
	if (raw_ret)
		*raw_ret = module->build_id;
	if (raw_len_ret)
		*raw_len_ret = module->build_id_len;
	return module->build_id_str;
}

static void *drgn_module_alloc_build_id(size_t build_id_len)
{
	size_t alloc_size;
	if (__builtin_mul_overflow(build_id_len, 3U, &alloc_size) ||
	    __builtin_add_overflow(alloc_size, 1U, &alloc_size))
		return NULL;
	return malloc(alloc_size);
}

static void drgn_module_set_build_id_impl(struct drgn_module *module,
					  const void *build_id,
					  size_t build_id_len,
					  void *build_id_buf)
{
	module->build_id = build_id_buf;
	memcpy(module->build_id, build_id, build_id_len);

	module->build_id_len = build_id_len;

	module->build_id_str = (char *)build_id_buf + build_id_len;
	hexlify(build_id, build_id_len, module->build_id_str);
	module->build_id_str[2 * build_id_len] = '\0';
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_set_build_id(struct drgn_module *module,
					    const void *build_id,
					    size_t build_id_len)
{
	if (build_id_len == 0) {
		free(module->build_id);
		module->build_id = NULL;
		module->build_id_len = 0;
		module->build_id_str = NULL;
		return NULL;
	}

	char *build_id_buf = drgn_module_alloc_build_id(build_id_len);
	if (!build_id_buf)
		return &drgn_enomem;
	free(module->build_id);
	drgn_module_set_build_id_impl(module, build_id, build_id_len,
				      build_id_buf);
	return NULL;
}

static struct drgn_error *
drgn_module_section_addresses_allowed(struct drgn_module *module, bool modify)
{
	if (module->kind != DRGN_MODULE_RELOCATABLE) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "section addresses are only supported for relocatable modules");
	}
	if (modify && (module->loaded_file || module->debug_file)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "section addresses cannot be modified after file is set");
	}
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_get_section_address(struct drgn_module *module,
						   const char *name,
						   uint64_t *ret)
{
	struct drgn_error *err =
		drgn_module_section_addresses_allowed(module, false);
	if (err)
		return err;
	struct drgn_module_section_address_map_iterator it =
		drgn_module_section_address_map_search(&module->section_addresses,
						       (char **)&name);
	if (!it.entry)
		return &drgn_not_found;
	*ret = it.entry->value;
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_set_section_address(struct drgn_module *module,
						   const char *name,
						   uint64_t address)
{
	struct drgn_error *err =
		drgn_module_section_addresses_allowed(module, true);
	if (err)
		return err;

	struct hash_pair hp =
		drgn_module_section_address_map_hash((char **)&name);
	struct drgn_module_section_address_map_iterator it =
		drgn_module_section_address_map_search_hashed(&module->section_addresses,
							      (char **)&name,
							      hp);
	if (it.entry) {
		it.entry->value = address;
		return NULL;
	}
	struct drgn_module_section_address_map_entry entry = {
		.key = strdup(name),
		.value = address,
	};
	if (!entry.key)
		return &drgn_enomem;
	if (drgn_module_section_address_map_insert_searched(&module->section_addresses,
							    &entry, hp,
							    NULL) < 0) {
		free(entry.key);
		return &drgn_enomem;
	}
	module->section_addresses_generation++;
	return NULL;
}

struct drgn_error *drgn_module_delete_section_address(struct drgn_module *module,
						      const char *name)
{
	struct drgn_error *err =
		drgn_module_section_addresses_allowed(module, true);
	if (err)
		return err;

	struct hash_pair hp =
		drgn_module_section_address_map_hash((char **)&name);
	struct drgn_module_section_address_map_iterator it =
		drgn_module_section_address_map_search_hashed(&module->section_addresses,
							      (char **)&name,
							      hp);
	if (!it.entry)
		return &drgn_not_found;

	_cleanup_free_ _unused_ char *key_to_free = it.entry->key;
	drgn_module_section_address_map_delete_iterator_hashed(&module->section_addresses,
							       it, hp);
	module->section_addresses_generation++;
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_num_section_addresses(struct drgn_module *module,
						     size_t *ret)
{
	struct drgn_error *err =
		drgn_module_section_addresses_allowed(module, false);
	if (err)
		return err;
	*ret = drgn_module_section_address_map_size(&module->section_addresses);
	return NULL;
}

struct drgn_module_section_address_iterator {
	struct drgn_module *module;
	struct drgn_module_section_address_map_iterator map_it;
	uint64_t generation;
};

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_section_address_iterator_create(struct drgn_module *module,
					    struct drgn_module_section_address_iterator **ret)
{
	struct drgn_error *err =
		drgn_module_section_addresses_allowed(module, false);
	if (err)
		return err;

	struct drgn_module_section_address_iterator *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;
	it->module = module;
	it->map_it = drgn_module_section_address_map_first(&module->section_addresses);
	it->generation = module->section_addresses_generation;
	*ret = it;
	return NULL;
}

LIBDRGN_PUBLIC void
drgn_module_section_address_iterator_destroy(struct drgn_module_section_address_iterator *it)
{
	free(it);
}

LIBDRGN_PUBLIC struct drgn_module *
drgn_module_section_address_iterator_module(struct drgn_module_section_address_iterator *it)
{
	return it->module;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_section_address_iterator_next(struct drgn_module_section_address_iterator *it,
					  const char **name_ret,
					  uint64_t *address_ret)
{
	if (it->map_it.entry) {
		if (it->generation != it->module->section_addresses_generation) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "section addresses changed during iteration");
		}
		*name_ret = it->map_it.entry->key;
		if (address_ret)
			*address_ret = it->map_it.entry->value;
		it->map_it = drgn_module_section_address_map_next(it->map_it);
	} else {
		*name_ret = NULL;
	}
	return NULL;
}

LIBDRGN_PUBLIC enum drgn_module_file_status
drgn_module_loaded_file_status(const struct drgn_module *module)
{
	return module->loaded_file_status;
}

static bool
drgn_can_change_module_file_status(enum drgn_module_file_status old_status,
				   enum drgn_module_file_status new_status)
{
	SWITCH_ENUM(old_status) {
	case DRGN_MODULE_FILE_WANT:
	case DRGN_MODULE_FILE_DONT_WANT:
	case DRGN_MODULE_FILE_DONT_NEED:
		SWITCH_ENUM(new_status) {
		case DRGN_MODULE_FILE_WANT:
		case DRGN_MODULE_FILE_DONT_WANT:
		case DRGN_MODULE_FILE_DONT_NEED:
			return true;
		case DRGN_MODULE_FILE_HAVE:
		case DRGN_MODULE_FILE_WANT_SUPPLEMENTARY:
		default:
			return false;
		}
	case DRGN_MODULE_FILE_HAVE:
		return new_status == DRGN_MODULE_FILE_HAVE;
	case DRGN_MODULE_FILE_WANT_SUPPLEMENTARY:
		SWITCH_ENUM(new_status) {
		case DRGN_MODULE_FILE_WANT:
		case DRGN_MODULE_FILE_DONT_WANT:
		case DRGN_MODULE_FILE_DONT_NEED:
		case DRGN_MODULE_FILE_WANT_SUPPLEMENTARY:
			return true;
		case DRGN_MODULE_FILE_HAVE:
		default:
			return false;
		}
	default:
		UNREACHABLE();
	}
}

LIBDRGN_PUBLIC
bool drgn_module_set_loaded_file_status(struct drgn_module *module,
					enum drgn_module_file_status status)
{
	if (!drgn_can_change_module_file_status(module->loaded_file_status,
						status))
		return false;
	module->loaded_file_status = status;
	return true;
}

LIBDRGN_PUBLIC
bool drgn_module_wants_loaded_file(const struct drgn_module *module)
{
	SWITCH_ENUM(module->loaded_file_status) {
	case DRGN_MODULE_FILE_WANT:
		return true;
	case DRGN_MODULE_FILE_HAVE:
	case DRGN_MODULE_FILE_DONT_WANT:
	case DRGN_MODULE_FILE_DONT_NEED:
		return false;
	case DRGN_MODULE_FILE_WANT_SUPPLEMENTARY:
	default:
		UNREACHABLE();
	}
}

LIBDRGN_PUBLIC enum drgn_module_file_status
drgn_module_debug_file_status(const struct drgn_module *module)
{
	return module->debug_file_status;
}

LIBDRGN_PUBLIC
bool drgn_module_set_debug_file_status(struct drgn_module *module,
				       enum drgn_module_file_status status)
{
	if (!drgn_can_change_module_file_status(module->debug_file_status,
						status))
		return false;
	if (module->debug_file_status == DRGN_MODULE_FILE_WANT_SUPPLEMENTARY
	    && status != DRGN_MODULE_FILE_WANT_SUPPLEMENTARY)
		drgn_module_clear_wanted_supplementary_debug_file(module);
	module->debug_file_status = status;
	return true;
}

LIBDRGN_PUBLIC
bool drgn_module_wants_debug_file(const struct drgn_module *module)
{
	SWITCH_ENUM(module->debug_file_status) {
	case DRGN_MODULE_FILE_WANT:
	case DRGN_MODULE_FILE_WANT_SUPPLEMENTARY:
		return true;
	case DRGN_MODULE_FILE_HAVE:
	case DRGN_MODULE_FILE_DONT_WANT:
	case DRGN_MODULE_FILE_DONT_NEED:
		return false;
	default:
		UNREACHABLE();
	}
}

LIBDRGN_PUBLIC
const char *drgn_module_loaded_file_path(const struct drgn_module *module)
{
	return module->loaded_file ? module->loaded_file->path : NULL;
}

LIBDRGN_PUBLIC
uint64_t drgn_module_loaded_file_bias(const struct drgn_module *module)
{
	return module->loaded_file_bias;
}

LIBDRGN_PUBLIC
const char *drgn_module_debug_file_path(const struct drgn_module *module)
{
	return module->debug_file ? module->debug_file->path : NULL;
}

LIBDRGN_PUBLIC
uint64_t drgn_module_debug_file_bias(const struct drgn_module *module)
{
	return module->debug_file_bias;
}

LIBDRGN_PUBLIC enum drgn_supplementary_file_kind
drgn_module_supplementary_debug_file_kind(const struct drgn_module *module)
{
	return module->supplementary_debug_file
	       ? DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK
	       : DRGN_SUPPLEMENTARY_FILE_NONE;
}

LIBDRGN_PUBLIC const char *
drgn_module_supplementary_debug_file_path(const struct drgn_module *module)
{
	return module->supplementary_debug_file
	       ? module->supplementary_debug_file->path : NULL;
}

LIBDRGN_PUBLIC enum drgn_supplementary_file_kind
drgn_module_wanted_supplementary_debug_file(struct drgn_module *module,
					    const char **debug_file_path_ret,
					    const char **supplementary_path_ret,
					    const void **checksum_ret,
					    size_t *checksum_len_ret)
{
	struct drgn_module_wanted_supplementary_file *wanted =
		module->wanted_supplementary_debug_file;
	if (debug_file_path_ret)
		*debug_file_path_ret = wanted ? wanted->file->path : NULL;
	if (supplementary_path_ret)
		*supplementary_path_ret = wanted ? wanted->supplementary_path : NULL;
	if (checksum_ret)
		*checksum_ret = wanted ? wanted->checksum : NULL;
	if (checksum_len_ret)
		*checksum_len_ret = wanted ? wanted->checksum_len : 0;
	return wanted
	       ? DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK
	       : DRGN_SUPPLEMENTARY_FILE_NONE;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_object(const struct drgn_module *module, struct drgn_object *ret)
{
	return drgn_object_copy(ret, &module->object);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_set_object(struct drgn_module *module, const struct drgn_object *obj)
{
	return drgn_object_copy(&module->object, obj);
}

static struct drgn_error *
drgn_program_register_debug_info_finder_impl(struct drgn_program *prog,
					     struct drgn_debug_info_finder *finder,
					     const char *name,
					     const struct drgn_debug_info_finder_ops *ops,
					     void *arg, size_t enable_index)
{
	struct drgn_error *err;
	bool should_free = !finder;
	if (finder) {
		finder->handler.name = name;
	} else {
		finder = malloc(sizeof(*finder));
		if (!finder)
			return &drgn_enomem;
		finder->handler.name = strdup(name);
		if (!finder->handler.name) {
			free(finder);
			return &drgn_enomem;
		}
	}
	finder->handler.free = should_free;
	finder->ops = *ops;
	finder->arg = arg;
	err = drgn_handler_list_register(&prog->dbinfo.debug_info_finders,
					 &finder->handler, enable_index,
					 "module debug info finder");
	if (err && should_free) {
		free((char *)finder->handler.name);
		free(finder);
	}
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_register_debug_info_finder(struct drgn_program *prog,
					const char *name,
					const struct drgn_debug_info_finder_ops *ops,
					void *arg, size_t enable_index)
{
	return drgn_program_register_debug_info_finder_impl(prog, NULL, name,
							    ops, arg,
							    enable_index);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_registered_debug_info_finders(struct drgn_program *prog,
					   const char ***names_ret,
					   size_t *count_ret)
{
	return drgn_handler_list_registered(&prog->dbinfo.debug_info_finders,
					    names_ret, count_ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_enabled_debug_info_finders(struct drgn_program *prog,
					    const char * const *names,
					    size_t count)
{
	return drgn_handler_list_set_enabled(&prog->dbinfo.debug_info_finders,
					     names, count,
					     "module debug info finder");
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_enabled_debug_info_finders(struct drgn_program *prog,
					const char ***names_ret,
					size_t *count_ret)
{
	return drgn_handler_list_enabled(&prog->dbinfo.debug_info_finders,
					 names_ret, count_ret);
}

LIBDRGN_PUBLIC struct drgn_debug_info_options *
drgn_program_debug_info_options(struct drgn_program *prog)
{
	return &prog->dbinfo.options;
}

static struct drgn_error *
drgn_module_set_wanted_gnu_debugaltlink(struct drgn_module *module,
					struct drgn_elf_file *file)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	// We don't cache .gnu_debugaltlink, and it doesn't need relocation, so
	// don't use drgn_elf_file_read_section().
	Elf_Data *data;
	err = read_elf_section(file->scns[DRGN_SCN_GNU_DEBUGALTLINK], &data);
	if (err) {
		if (!drgn_error_is_fatal(err)) {
			drgn_error_log_debug(prog, err,
					     "%s: couldn't read .gnu_debugaltlink; ignoring debug info: ",
					     file->path);
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}

	const char *debugaltlink = data->d_buf;
	const char *nul = memchr(debugaltlink, 0, data->d_size);
	if (!nul || nul + 1 == debugaltlink + data->d_size) {
		drgn_log_debug(prog,
			       "%s: couldn't parse .gnu_debugaltlink; ignoring debug info",
			       file->path);
		return NULL;
	}
	const void *build_id = nul + 1;
	size_t build_id_len = debugaltlink + data->d_size - (nul + 1);
	_cleanup_free_ char *build_id_str = ahexlify(build_id, build_id_len);
	if (!build_id_str)
		return &drgn_enomem;
	drgn_log_debug(prog, "%s has gnu_debugaltlink %s build ID %s",
		       file->path, debugaltlink, build_id_str);

	struct drgn_module_wanted_supplementary_file *wanted =
		malloc(sizeof(*wanted));
	if (!wanted)
		return &drgn_enomem;
	*wanted = (struct drgn_module_wanted_supplementary_file){
		.file = file,
		.supplementary_path = debugaltlink,
		.checksum = build_id,
		.checksum_len = build_id_len,
		.checksum_str = no_cleanup_ptr(build_id_str),
		.generation = ++prog->dbinfo.supplementary_file_generation,
	};
	drgn_module_clear_wanted_supplementary_debug_file(module);
	module->wanted_supplementary_debug_file = wanted;
	module->debug_file_status = DRGN_MODULE_FILE_WANT_SUPPLEMENTARY;
	return NULL;
}

static bool
drgn_module_copy_section_addresses(struct drgn_module *module, Elf *elf)
{
	if (drgn_module_section_address_map_empty(&module->section_addresses))
		return true;

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return false;

	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr *shdr, shdr_mem;
		shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return false;

		char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname)
			return false;

		struct drgn_module_section_address_map_iterator it =
			drgn_module_section_address_map_search(&module->section_addresses,
							       &scnname);
		if (!it.entry)
			continue;

		shdr->sh_addr = it.entry->value;
		if (!gelf_update_shdr(scn, shdr))
			return false;
	}
	return true;
}

static bool elf_main_bias(struct drgn_program *prog, Elf *elf, uint64_t *ret)
{
	GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr) {
		drgn_log_debug(prog, "gelf_getehdr: %s", elf_errmsg(-1));
		return false;
	}

	size_t phnum;
	if (elf_getphdrnum(elf, &phnum) != 0) {
		drgn_log_debug(prog, "elf_getphdrnum: %s", elf_errmsg(-1));
		return false;
	}

	uint64_t phdr_vaddr;
	bool have_phdr_vaddr = false;
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr) {
			drgn_log_debug(prog, "gelf_getphdr: %s",
				       elf_errmsg(-1));
			return false;
		}
		if (phdr->p_type == PT_LOAD &&
		    phdr->p_offset <= ehdr->e_phoff &&
		    ehdr->e_phoff < phdr->p_offset + phdr->p_filesz) {
			phdr_vaddr = ehdr->e_phoff - phdr->p_offset + phdr->p_vaddr;
			have_phdr_vaddr = true;
		}
	}
	if (!have_phdr_vaddr) {
		drgn_log_debug(prog,
			       "file does not have loadable segment containing e_phoff");
		return false;
	}
	*ret = prog->auxv.at_phdr - phdr_vaddr;
	return true;
}

static bool elf_dso_bias(struct drgn_program *prog, Elf *elf,
			 uint64_t dynamic_address, uint64_t *ret)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum) != 0) {
		drgn_log_debug(prog, "elf_getphdrnum: %s", elf_errmsg(-1));
		return false;
	}

	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr) {
			drgn_log_debug(prog, "gelf_getphdr: %s",
				       elf_errmsg(-1));
			return false;
		}
		if (phdr->p_type == PT_DYNAMIC) {
			*ret = dynamic_address - phdr->p_vaddr;
			drgn_log_debug(prog,
				       "got bias 0x%" PRIx64 " from PT_DYNAMIC program header",
				       *ret);
			return true;
		}
	}
	drgn_log_debug(prog, "file does not have PT_DYNAMIC program header");
	return false;
}

static bool drgn_module_elf_file_bias(struct drgn_module *module,
				      struct drgn_elf_file *file, uint64_t *ret)
{
	struct drgn_program *prog = module->prog;
	SWITCH_ENUM(module->kind) {
	case DRGN_MODULE_MAIN:
		if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
			*ret = prog->vmcoreinfo.kaslr_offset;
			drgn_log_debug(prog,
				       "got bias 0x%" PRIx64 " from VMCOREINFO",
				       *ret);
			return true;
		} else {
			return elf_main_bias(prog, file->elf, ret);
		}
	case DRGN_MODULE_SHARED_LIBRARY:
	case DRGN_MODULE_VDSO:
		return elf_dso_bias(prog, file->elf, module->info, ret);
	case DRGN_MODULE_EXTRA: {
		size_t num_address_ranges;
		if (drgn_module_num_address_ranges(module, &num_address_ranges)
		    && num_address_ranges == 1) {
			uint64_t start, end;
			drgn_module_address_range(module, 0, &start, &end);
			uint64_t elf_start, elf_end;
			if (!drgn_elf_file_address_range(file, &elf_start,
							 &elf_end))
				return false;
			if (elf_start < elf_end) {
				*ret = start - elf_start;
				drgn_log_debug(prog,
					       "got bias 0x%" PRIx64 " from ELF start address",
					       *ret);
				return true;
			}
		}
		fallthrough;
	}
	case DRGN_MODULE_RELOCATABLE:
	default:
		*ret = 0;
		return true;
	}
}

static bool
drgn_module_should_set_address_range_from_elf_file(struct drgn_module *module)
{
	if (module->address_ranges)
		return false;

	SWITCH_ENUM(module->kind) {
	case DRGN_MODULE_MAIN:
	case DRGN_MODULE_SHARED_LIBRARY:
	case DRGN_MODULE_VDSO:
		return true;
	case DRGN_MODULE_RELOCATABLE:
	case DRGN_MODULE_EXTRA:
	default:
		return false;
	}
}

// Takes ownership of file unless it is already owned by module.
static struct drgn_error *
drgn_module_maybe_use_elf_file(struct drgn_module *module,
			       struct drgn_elf_file *file,
			       bool is_gnu_debugaltlink_file)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;
	struct drgn_elf_file *gnu_debugaltlink_file = NULL;

	bool use_loaded, has_dwarf, use_debug;
	if (is_gnu_debugaltlink_file) {
		assert(module->debug_file_status
		       == DRGN_MODULE_FILE_WANT_SUPPLEMENTARY);
		gnu_debugaltlink_file = file;
		file = module->wanted_supplementary_debug_file->file;
		use_loaded = false;
		has_dwarf = use_debug = true;
	} else {
		// We should only be here if we want a file.
		assert(drgn_module_wants_file(module));
		use_loaded = module->loaded_file_status == DRGN_MODULE_FILE_WANT
			     && file->is_loadable;
		has_dwarf = drgn_elf_file_has_dwarf(file);
		use_debug = drgn_module_wants_debug_file(module) && has_dwarf;
	}

	_cleanup_free_ void *build_id_buf = NULL;

	if (!is_gnu_debugaltlink_file
	    && use_debug && file->scns[DRGN_SCN_GNU_DEBUGALTLINK]) {
		// If we're trying to reuse a debug file that wants a
		// supplementary file, then don't reset it, otherwise we'll free
		// the file that we're trying to reuse.
		if (!module->wanted_supplementary_debug_file
		    || module->wanted_supplementary_debug_file->file != file) {
			err = drgn_module_set_wanted_gnu_debugaltlink(module, file);
			if (err)
				goto unused;
		}
		if (!use_loaded && module->wanted_supplementary_debug_file
		    && module->wanted_supplementary_debug_file->file == file)
			return NULL;
		use_debug = false;
	}

	if (!use_loaded && !use_debug) {
		if (file->is_loadable) {
			drgn_log_debug(prog,
				       "%s is loadable, but don't want loaded file; ignoring",
				       file->path);
		} else if (has_dwarf) {
			drgn_log_debug(prog,
				       "%s has debug info, but don't want debug info; ignoring",
				       file->path);
		} else {
			drgn_log_debug(prog,
				       "%s is not loadable and no debug info; ignoring",
				       file->path);
		}
		err = NULL;
		goto unused;
	}

	// Get everything that might fail before we commit to using the file.
	const void *elf_build_id;
	ssize_t elf_build_id_len = 0;
	if (module->build_id_len == 0) {
		elf_build_id_len = drgn_elf_gnu_build_id(file->elf,
							 &elf_build_id);
		if (elf_build_id_len < 0) {
			drgn_log_debug(prog, "%s: %s", file->path,
				       elf_errmsg(-1));
			err = NULL;
			goto unused;
		}
		if (elf_build_id_len > 0) {
			build_id_buf =
				drgn_module_alloc_build_id(elf_build_id_len);
			if (!build_id_buf) {
				err = &drgn_enomem;
				goto unused;
			}
		}
	}

	if (file != module->loaded_file && file != module->debug_file
	    && !drgn_module_copy_section_addresses(module, file->elf)) {
		drgn_log_debug(prog, "%s: %s", file->path, elf_errmsg(-1));
		err = NULL;
		goto unused;
	}

	uint64_t bias;
	if (!drgn_module_elf_file_bias(module, file, &bias)) {
		err = NULL;
		goto unused;
	}
	uint64_t elf_start = 0, elf_end = 0;
	if (drgn_module_should_set_address_range_from_elf_file(module)) {
		if (!drgn_elf_file_address_range(file, &elf_start, &elf_end)) {
			drgn_log_debug(prog, "%s: %s", file->path,
				       elf_errmsg(-1));
			err = NULL;
			goto unused;
		}
		elf_start += bias;
		elf_end += bias;
		if (elf_start >= elf_end) {
			drgn_log_debug(prog, "%s: address range is invalid",
				       file->path);
		}
	}

	// At this point, we've committed to using the file. Nothing after this
	// is allowed to fail.

	if (use_loaded && use_debug) {
		drgn_log_info(prog,
			      "%s: using loadable file with debug info %s",
			      module->name, file->path);
	} else if (use_loaded) {
		drgn_log_info(prog, "%s: using loadable file %s", module->name,
			      file->path);
	} else if (is_gnu_debugaltlink_file) {
		drgn_log_info(prog,
			      "%s: using debug info file %s with supplementary file %s",
			      module->name, file->path, gnu_debugaltlink_file->path);
	} else {
		drgn_log_info(prog, "%s: using debug info file %s",
			      module->name, file->path);
	}

	// If we got a build ID or address range earlier, install them.
	if (elf_build_id_len > 0) {
		drgn_module_set_build_id_impl(module, elf_build_id,
					      elf_build_id_len,
					      no_cleanup_ptr(build_id_buf));
		drgn_log_debug(prog, "%s: set build ID %s from file",
			       module->name, module->build_id_str);
	}
	if (elf_start < elf_end) {
		drgn_log_debug(prog,
			       "%s: set address range 0x%" PRIx64
			       "-0x%" PRIx64 " from file", module->name,
			       elf_start, elf_end);
		err = drgn_module_set_address_range(module, elf_start, elf_end);
		// This can only fail if the address range is invalid, which we
		// just checked for.
		assert(!err);
	}

	if (use_loaded) {
		module->loaded_file = file;
		module->loaded_file_bias = bias;
		module->loaded_file_status = DRGN_MODULE_FILE_HAVE;
		module->elf_symtab_pending_files |=
			DRGN_MODULE_FILE_MASK_LOADED;
	}
	if (use_debug) {
		module->debug_file = file;
		module->debug_file_bias = bias;
		module->supplementary_debug_file = gnu_debugaltlink_file;
		drgn_module_clear_wanted_supplementary_debug_file(module);
		module->debug_file_status = DRGN_MODULE_FILE_HAVE;
		module->pending_indexing_next =
			prog->dbinfo.modules_pending_indexing;
		prog->dbinfo.modules_pending_indexing = module;
		prog->tried_main_language = false;
		module->elf_symtab_pending_files |=
			DRGN_MODULE_FILE_MASK_DEBUG;
	}
	if (!prog->has_platform) {
		drgn_log_debug(prog, "setting program platform from %s",
			       file->path);
		drgn_program_set_platform(prog, &file->platform);
	}
	return NULL;

unused:
	drgn_elf_file_destroy(gnu_debugaltlink_file);
	if (module->wanted_supplementary_debug_file
	    && file == module->wanted_supplementary_debug_file->file) {
		module->wanted_supplementary_debug_file->file = NULL;
		drgn_module_clear_wanted_supplementary_debug_file(module);
		module->debug_file_status = DRGN_MODULE_FILE_WANT;
	}
	if (file != module->loaded_file && file != module->debug_file)
		drgn_elf_file_destroy(file);
	return err;
}

// Always takes ownership of fd_. Attempts to resolve the real path of path.
static struct drgn_error *
drgn_module_try_file_internal(struct drgn_module *module, const char *path,
			      int fd_, bool check_build_id,
			      const uint32_t *expected_crc)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	_cleanup_close_ int fd = fd_;
	if (fd >= 0) {
		if (path) {
			drgn_log_debug(prog, "%s: trying %s with fd %d",
				       module->name, path, fd);
		} else {
			drgn_log_debug(prog, "%s: trying fd %d", module->name,
				       fd);
		}
	} else {
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			drgn_log_debug(prog, "%s: %m", path);
			return NULL;
		}
		drgn_log_debug(prog, "%s: trying %s", module->name, path);
	}

	_cleanup_free_ char *canonical_path = fd_canonical_path(fd, path);
	if (!canonical_path)
		return &drgn_enomem;
	if (drgn_log_is_enabled(prog, DRGN_LOG_DEBUG)
	    && (!path || strcmp(path, canonical_path) != 0))
		drgn_log_debug(prog, "canonical path is %s", canonical_path);
	path = canonical_path;

	_cleanup_elf_end_ Elf *elf = dwelf_elf_begin(fd);
	if (!elf) {
		drgn_log_debug(prog, "%s: %s", path, elf_errmsg(-1));
		return NULL;
	}
	if (elf_kind(elf) != ELF_K_ELF) {
		drgn_log_debug(prog, "%s: not an ELF file", path);
		return NULL;
	}

	// This code assumes that DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK is
	// the only kind of supplementary file, which is currently true.
	bool log_build_id = check_build_id
			    || drgn_log_is_enabled(prog, DRGN_LOG_DEBUG);
	const void *elf_build_id;
	ssize_t elf_build_id_len;
	if (module->debug_file_status == DRGN_MODULE_FILE_WANT_SUPPLEMENTARY
	    || (log_build_id && module->build_id_len > 0)) {
		elf_build_id_len = drgn_elf_gnu_build_id(elf, &elf_build_id);
		if (elf_build_id_len < 0) {
			drgn_log_debug(prog, "%s: %s%s", path, elf_errmsg(-1),
				       check_build_id ? "" : "; ignoring build ID");
		}
	}

	bool is_gnu_debugaltlink_file = false;
	if (module->debug_file_status == DRGN_MODULE_FILE_WANT_SUPPLEMENTARY
	    && elf_build_id_len >= 0
	    && elf_build_id_len
	       == module->wanted_supplementary_debug_file->checksum_len
	    && memcmp(elf_build_id,
		      module->wanted_supplementary_debug_file->checksum,
		      elf_build_id_len) == 0) {
		drgn_log_debug(prog, "%s: %s build ID matches gnu_debugaltlink",
			       module->name, path);
		is_gnu_debugaltlink_file = true;
	} else if (log_build_id && module->build_id_len > 0) {
		if (elf_build_id_len < 0) {
			if (check_build_id)
				return NULL;
		} else if (elf_build_id_len == module->build_id_len
			   && memcmp(elf_build_id, module->build_id,
				     elf_build_id_len) == 0) {
			drgn_log_debug(prog, "%s: %s build ID matches",
				       module->name, path);
		} else {
			if (elf_build_id_len == 0) {
				drgn_log_debug(prog,
					       "%s: %s is missing build ID%s",
					       module->name, path,
					       check_build_id ? "" : "; forcing");
			} else {
				drgn_log_debug(prog,
					       "%s: %s build ID does not match%s",
					       module->name, path,
					       check_build_id ? "" : "; forcing");
			}
			if (check_build_id)
				return NULL;
		}
	}
	if (expected_crc) {
		size_t size;
		const void *rawfile = elf_rawfile(elf, &size);
		if (!rawfile) {
			drgn_log_debug(prog, "%s: %s", path, elf_errmsg(-1));
			return NULL;
		}
		uint32_t crc = ~crc32_update(-1, rawfile, size);
		if (crc != *expected_crc) {
			drgn_log_debug(prog,
				       "%s: %s CRC 0x%08" PRIx32 " does not match",
				       module->name, path, crc);
			return NULL;
		}
		drgn_log_debug(prog, "%s: %s CRC matches", module->name, path);
	}

	struct drgn_elf_file *file;
	err = drgn_elf_file_create(module, path, fd, NULL, elf, &file);
	if (err) {
		if (!drgn_error_is_fatal(err)) {
			drgn_error_log_debug(prog, err, "");
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}
	// fd and elf are owned by the drgn_elf_file now.
	fd = -1;
	elf = NULL;
	return drgn_module_maybe_use_elf_file(module, file,
					      is_gnu_debugaltlink_file);
}

// Arbitrary limit on the number of bytes we'll allocate and read from the
// program's memory at once when finding modules/debug info.
static const uint64_t MAX_MEMORY_READ_FOR_DEBUG_INFO = UINT64_C(1048576);

#define drgn_module_try_files_log(module, how_format, ...)			\
({										\
	struct drgn_module *_module = (module);					\
	bool _want_loaded = _module->loaded_file_status == DRGN_MODULE_FILE_WANT;\
	bool _want_debug = _module->debug_file_status == DRGN_MODULE_FILE_WANT;	\
	bool _want_supplementary_debug = _module->debug_file_status		\
					 == DRGN_MODULE_FILE_WANT_SUPPLEMENTARY;\
	drgn_log_debug(_module->prog,						\
		       "%s (%s%s): " how_format " %s%s%s file%s", _module->name,\
		       _module->build_id_str ? "build ID " : "no build ID",	\
		       _module->build_id_str ?: "",				\
		       ## __VA_ARGS__,						\
		       _want_loaded ? "loaded" : "",				\
		       _want_loaded && (_want_debug || _want_supplementary_debug)\
		       ? " and " : "",						\
		       _want_debug ? "debug"					\
		       : _want_supplementary_debug ? "supplementary debug" : "",\
		       _want_loaded && (_want_debug || _want_supplementary_debug)\
		       ? "s" : "");						\
})

static struct drgn_error *
drgn_module_try_vdso_in_core(struct drgn_module *module,
			     const struct drgn_debug_info_options *options)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	if (!options->try_embedded_vdso)
		return NULL;

	// The Linux kernel has included the entire vDSO in core dumps since
	// Linux kernel commit f47aef55d9a1 ("[PATCH] i386 vDSO: use
	// VM_ALWAYSDUMP") (in v2.6.20). Try to read it from program memory.

	// The vDSO in memory is always stripped.
	if (module->loaded_file_status != DRGN_MODULE_FILE_WANT)
		return NULL;

	size_t num_address_ranges;
	if (!drgn_module_num_address_ranges(module, &num_address_ranges)) {
		drgn_log_debug(prog,
			       "vDSO address range is not known; "
			       "can't read from program");
		return NULL;
	}
	if (num_address_ranges != 1) {
		drgn_log_debug(prog, "vDSO has %s; can't read from program",
			       num_address_ranges
			       ? "multiple address ranges"
			       : "empty address range");
		return NULL;
	}
	uint64_t start, end;
	drgn_module_address_range(module, 0, &start, &end);
	uint64_t size = end - start;
	if (size > MAX_MEMORY_READ_FOR_DEBUG_INFO) {
		drgn_log_debug(prog,
			       "vDSO is unreasonably large (%" PRIu64 " bytes); "
			       "not reading from program",
			       size);
		return NULL;
	}

	_cleanup_free_ char *image = malloc(size);
	if (!image)
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, image, start, size, false);
	if (err) {
		if (!drgn_error_is_fatal(err)) {
			drgn_error_log_debug(prog, err, "couldn't read vDSO: ");
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}

	_cleanup_elf_end_ Elf *elf = elf_memory(image, size);
	if (!elf) {
		drgn_log_debug(prog, "couldn't read vDSO: %s", elf_errmsg(-1));
		return NULL;
	}
	struct drgn_elf_file *file;
	err = drgn_elf_file_create(module, "[vdso]", -1, image, elf, &file);
	if (err) {
		if (!drgn_error_is_fatal(err)) {
			drgn_error_log_debug(prog, err, "");
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}
	// image and elf are owned by the drgn_elf_file now.
	image = NULL;
	elf = NULL;

	drgn_log_debug(prog, "trying vDSO in %s",
		       (module->prog->flags & DRGN_PROGRAM_IS_LIVE)
		       ? "memory" : "core");
	return drgn_module_maybe_use_elf_file(module, file, false);
}

static void
drgn_module_try_supplementary_debug_file_log(struct drgn_module *module,
					     const char *how)
{
	const char *debug_file_path;
	const char *debugaltlink_path;
	if (drgn_module_wanted_supplementary_debug_file(module,
							&debug_file_path,
							&debugaltlink_path,
							NULL, NULL)
	    != DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK)
		return;
	const char *debugaltlink_build_id_str =
		module->wanted_supplementary_debug_file->checksum_str;
	drgn_log_debug(module->prog,
		       "%s: %s gnu_debugaltlink %s build ID %s in file %s",
		       module->name, how, debugaltlink_path,
		       debugaltlink_build_id_str, debug_file_path);
}

static struct drgn_error *
drgn_module_try_standard_supplementary_files(struct drgn_module *module,
					     const struct drgn_debug_info_options *options)
{
	struct drgn_error *err;

	if (!options->try_supplementary)
		return NULL;

	const char *debug_file_path;
	const char *debugaltlink_path;
	if (drgn_module_wanted_supplementary_debug_file(module,
							&debug_file_path,
							&debugaltlink_path,
							NULL, NULL)
	    != DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK)
		return NULL;

	drgn_module_try_supplementary_debug_file_log(module,
						     "trying standard paths for");

	STRING_BUILDER(sb);
	const char *slash;
	if (debugaltlink_path[0] == '/'
	    || !(slash = strrchr(debug_file_path, '/'))) {
		// debugaltlink is absolute, or the debug file doesn't have a
		// directory component and is therefore in the current working
		// directory. Try debugaltlink directly.
		err = drgn_module_try_file_internal(module, debugaltlink_path,
						    -1, true, NULL);
	} else {
		// Try $(dirname $path)/$debugaltlink.
		if (!string_builder_appendn(&sb, debug_file_path,
					    slash + 1 - debug_file_path)
		    || !string_builder_append(&sb, debugaltlink_path)
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		err = drgn_module_try_file_internal(module, sb.str, -1, true,
						    NULL);
	}
	if (err
	    || module->debug_file_status != DRGN_MODULE_FILE_WANT_SUPPLEMENTARY)
		return err;

	// All of the Linux distributions that use gnu_debugaltlink that I'm
	// aware of (Debian, Fedora, SUSE, and their derivatives) put
	// gnu_debugaltlink files in a ".dwz" subdirectory under the debug
	// directory (e.g., "/usr/lib/debug/.dwz"). Try the path starting with
	// the ".dwz" directory under all of the configured debug directories.
	// This can help in a couple of cases:
	//
	// 1. When the gnu_debugaltlink path is absolute (which is the case on
	//    Debian and its derivatives as of Debian 12/Ubuntu 23.10) and the
	//    debug directory has been copied to a different path. See
	//    https://bugs.launchpad.net/ubuntu/+source/gdb/+bug/1818918.
	// 2. When the gnu_debugaltlink path is relative (which is the case on
	//    Fedora, SUSE, and their derivatives) and the debug file was found
	//    outside of the debug directory.
	const char *dwz = strstr(debugaltlink_path, "/.dwz/");
	if (dwz) {
		for (size_t i = 0; options->directories[i]; i++) {
			const char *debug_dir = options->directories[i];

			sb.len = 0;
			if (!string_builder_append(&sb, debug_dir)
			    || !string_builder_append(&sb, dwz)
			    || !string_builder_null_terminate(&sb))
				return &drgn_enomem;

			// Don't bother trying debugaltlink directly again.
			if (strcmp(sb.str, debugaltlink_path) == 0)
				continue;

			err = drgn_module_try_file_internal(module, sb.str, -1,
							    true, NULL);
			if (err
			    || module->debug_file_status
			       != DRGN_MODULE_FILE_WANT_SUPPLEMENTARY)
				return err;
		}
	}
	return NULL;
}

static bool
drgn_module_wanted_supplementary_debug_file_is_new(struct drgn_module *module,
						   uint64_t orig_supplementary_file_generation)
{
	return module->wanted_supplementary_debug_file
	       && module->wanted_supplementary_debug_file->generation
		  > orig_supplementary_file_generation;
}

struct drgn_error *
drgn_module_try_standard_file(struct drgn_module *module,
			      const struct drgn_debug_info_options *options,
			      const char *path, int fd, bool check_build_id,
			      const uint32_t *expected_crc)
{
	struct drgn_error *err;
	uint64_t orig_supplementary_file_generation =
		module->prog->dbinfo.supplementary_file_generation;
	err = drgn_module_try_file_internal(module, path, fd, check_build_id,
					    expected_crc);
	if (err)
		return err;
	// If the wanted supplementary debug file changed, try finding it again.
	if (drgn_module_wanted_supplementary_debug_file_is_new(module,
					orig_supplementary_file_generation)) {
		err = drgn_module_try_standard_supplementary_files(module,
								   options);
		if (err)
			return err;
	}
	return NULL;
}

// An entry in /proc/$pid/map_files.
struct drgn_map_files_segment {
	uint64_t start;
	uint64_t end;
};

DEFINE_VECTOR(drgn_map_files_segment_vector, struct drgn_map_files_segment);

static inline int drgn_map_files_segment_compare(const void *_a, const void *_b)
{
	const struct drgn_map_files_segment *a = _a;
	const struct drgn_map_files_segment *b = _b;
	return (a->start > b->start) - (a->start < b->start);
}

static void
drgn_debug_info_set_map_files_segments(struct drgn_debug_info *dbinfo,
				       struct drgn_map_files_segment_vector *segments,
				       bool sorted)
{
	free(dbinfo->map_files_segments);
	drgn_map_files_segment_vector_shrink_to_fit(segments);
	drgn_map_files_segment_vector_steal(segments,
					    &dbinfo->map_files_segments,
					    &dbinfo->num_map_files_segments);
	// The Linux kernel always returns these entries in order, but sort it
	// just in case.
	if (!sorted) {
		qsort(dbinfo->map_files_segments,
		      dbinfo->num_map_files_segments,
		      sizeof(dbinfo->map_files_segments[0]),
		      drgn_map_files_segment_compare);
	}
}

static struct drgn_error *
drgn_module_try_proc_files_for_shared_library(struct drgn_module *module,
					      const struct drgn_debug_info_options *options,
					      bool *tried)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;
	const uint64_t address = module->info;

#define DIR_FORMAT "/proc/%ld/map_files"
#define ENTRY_FORMAT "/%" PRIx64 "-%" PRIx64
	char path[sizeof(DIR_FORMAT ENTRY_FORMAT)
		  - (sizeof("%ld") - 1)
		  + max_decimal_length(long)
		  - 2 * (sizeof("%" PRIx64) - 1)
		  + 2 * 16];
	int dir_len = sprintf(path, DIR_FORMAT, (long)prog->pid);

	// Check the cache first.
	#define less_than_start(a, b) (*(a) < (b)->start)
	size_t cache_index = binary_search_gt(prog->dbinfo.map_files_segments,
					      prog->dbinfo.num_map_files_segments,
					      &address, less_than_start);
	#undef less_than_start
	if (cache_index > 0
	    && address < prog->dbinfo.map_files_segments[cache_index - 1].end) {
		struct drgn_map_files_segment *cache =
			&prog->dbinfo.map_files_segments[cache_index - 1];
		sprintf(path + dir_len, ENTRY_FORMAT, cache->start, cache->end);
		drgn_log_debug(prog,
			       "found %s containing dynamic section 0x%" PRIx64 " in map_files cache",
			       path, address);
		int fd = open(path, O_RDONLY);
		if (fd >= 0) {
			*tried = true;
			return drgn_module_try_standard_file(module, options,
							     path, fd, false,
							     NULL);
		} else {
			// We found a match in the cache, but we couldn't open
			// it. If it doesn't exist anymore, then we need to
			// rebuild the cache. If it failed for any other reason,
			// ignore it like we do in the cache miss case.
			bool rebuild_cache = errno == ENOENT;
			drgn_log_debug(prog, "%s: %m", path);
			if (!rebuild_cache)
				return NULL;
		}
		drgn_log_debug(prog, "rebuilding map_files cache");
		path[dir_len] = '\0';
	}
#undef ENTRY_FORMAT
#undef DIR_FORMAT

	// Walk /proc/$pid/map_files, caching it while looking for a match.
	_cleanup_closedir_ DIR *dir = opendir(path);
	if (!dir) {
		if (errno != ENOENT)
			return drgn_error_create_os("opendir", errno, path);
		drgn_log_debug(prog, "%s: %m", path);
		return NULL;
	}
	VECTOR(drgn_map_files_segment_vector, segments);
	bool sorted = true;
	bool found = false;
	struct dirent *ent;
	while ((errno = 0, ent = readdir(dir))) {
		struct drgn_map_files_segment segment;
		if (sscanf(ent->d_name, "%" SCNx64 "-%" SCNx64, &segment.start,
			   &segment.end) != 2)
			continue;

		if (!drgn_map_files_segment_vector_empty(&segments)
		    && segment.start
		       < drgn_map_files_segment_vector_last(&segments)->start)
			sorted = false;
		if (!drgn_map_files_segment_vector_append(&segments, &segment))
			return &drgn_enomem;

		if (segment.start <= address && address < segment.end
		    && !found
		    && strlen(ent->d_name) + 1 < sizeof(path) - dir_len) {
			found = true;
			path[dir_len] = '/';
			memcpy(path + dir_len + 1, ent->d_name,
			       strlen(ent->d_name) + 1);
			drgn_log_debug(prog,
				       "found %s containing dynamic section 0x%" PRIx64,
				       path, address);
			int fd = openat(dirfd(dir), ent->d_name, O_RDONLY);
			if (fd >= 0) {
				*tried = true;
				err = drgn_module_try_standard_file(module,
								    options,
								    path, fd,
								    false,
								    NULL);
				if (err)
					return err;
			} else {
				drgn_log_debug(prog, "%s: %m", path);
			}
			path[dir_len] = '\0';
		}
	}
	if (errno)
		return drgn_error_create_os("readdir", errno, path);

	drgn_debug_info_set_map_files_segments(&prog->dbinfo, &segments,
					       sorted);

	if (!found) {
		drgn_log_debug(prog,
			       "didn't find entry in %s containing dynamic section 0x%" PRIx64,
			       path, address);
	}
	return NULL;
}

static struct drgn_error *drgn_module_try_proc_files(struct drgn_module *module,
						     const struct drgn_debug_info_options *options,
						     bool *tried)
{
	struct drgn_program *prog = module->prog;

	if (!options->try_procfs)
		return NULL;

	*tried = false;
	if (module->kind == DRGN_MODULE_MAIN) {
#define FORMAT "/proc/%ld/exe"
		char path[sizeof(FORMAT)
			  - (sizeof("%ld") - 1)
			  + max_decimal_length(long)];
		snprintf(path, sizeof(path), FORMAT, (long)prog->pid);
#undef FORMAT
		int fd = open(path, O_RDONLY);
		if (fd < 0) {
			drgn_log_debug(prog, "%s: %m", path);
			return NULL;
		}
		*tried = true;
		return drgn_module_try_standard_file(module, options, path, fd,
						     false, NULL);
	} else if (module->kind == DRGN_MODULE_SHARED_LIBRARY) {
		return drgn_module_try_proc_files_for_shared_library(module,
								     options,
								     tried);
	} else {
		return NULL;
	}
}

static struct drgn_error *
drgn_module_try_files_by_build_id(struct drgn_module *module,
				  const struct drgn_debug_info_options *options)
{
	struct drgn_error *err;

	if (!options->try_build_id)
		return NULL;

	size_t build_id_len;
	const char *build_id_str =
		drgn_module_build_id(module, NULL, &build_id_len);
	// We need at least 2 bytes (4 hex characters) to build the paths.
	if (build_id_len < 2)
		return NULL;

	STRING_BUILDER(sb);
	for (size_t i = 0; options->directories[i]; i++) {
		const char *debug_dir = options->directories[i];
		if (!string_builder_append(&sb, debug_dir)
		    || !string_builder_appendf(&sb, "/.build-id/%c%c/%s.debug",
					       build_id_str[0], build_id_str[1],
					       &build_id_str[2])
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		// We trust the build ID encoded in the path and don't check it
		// again.
		if (module->debug_file_status == DRGN_MODULE_FILE_WANT) {
			err = drgn_module_try_standard_file(module, options,
							    sb.str, -1, false,
							    NULL);
			if (err || !drgn_module_wants_file(module))
				return err;
		}
		if (module->loaded_file_status == DRGN_MODULE_FILE_WANT) {
			// Remove the ".debug" extension.
			sb.str[sb.len - sizeof(".debug") + 1] = '\0';
			err = drgn_module_try_standard_file(module, options,
							    sb.str, -1, false,
							    NULL);
			if (err || !drgn_module_wants_file(module))
				return err;
		}
		sb.len = 0;
	}
	return NULL;
}

// Return the first occurrence of either $ORIGIN followed by a word boundary or
// ${ORIGIN}, and set *end_ret to the character after that occurrence. Return
// NULL if not found (and *end_ret is not modified).
static const char *find_dollar_origin(const char *s, const char **end_ret)
{
	const char *dollar;
	while ((dollar = strchr(s, '$'))) {
		if (strstartswith(dollar + 1, "ORIGIN")) {
			s = dollar + (sizeof("$ORIGIN") - 1);
			// Skip it if it doesn't end at a word boundary.
			if (*s == '_' || isalnum(*s))
				continue;
			*end_ret = s;
			break;
		} else if (strstartswith(dollar + 1, "{ORIGIN}")) {
			*end_ret = dollar + (sizeof("${ORIGIN}") - 1);
			break;
		} else {
			s = dollar + 1;
		}
	}
	return dollar;
}

static struct drgn_error *
drgn_module_try_files_by_gnu_debuglink(struct drgn_module *module,
				       const struct drgn_debug_info_options *options)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	if (!options->try_debug_link)
		return NULL;

	struct drgn_elf_file *file = module->loaded_file;
	if (!file || !file->scns[DRGN_SCN_GNU_DEBUGLINK])
		return NULL;
	// We don't cache .gnu_debuglink, and it doesn't need relocation, so
	// don't use drgn_elf_file_read_section().
	Elf_Data *data;
	err = read_elf_section(file->scns[DRGN_SCN_GNU_DEBUGLINK], &data);
	if (err) {
		if (!drgn_error_is_fatal(err)) {
			drgn_error_log_debug(prog, err,
					     "%s: couldn't read .gnu_debuglink: ",
					     file->path);
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}

	struct drgn_elf_file_section_buffer buffer;
	drgn_elf_file_section_buffer_init(&buffer, file,
					  file->scns[DRGN_SCN_GNU_DEBUGLINK],
					  data);
	const char *debuglink;
	size_t debuglink_len;
	uint32_t crc;
	if ((err = binary_buffer_next_string(&buffer.bb, &debuglink,
					     &debuglink_len))
	    // Align up to 4-byte boundary.
	    || (err = binary_buffer_skip(&buffer.bb, -(debuglink_len + 1) & 3))
	    || (err = binary_buffer_next_u32(&buffer.bb, &crc))) {
		if (!drgn_error_is_fatal(err)) {
			drgn_error_log_debug(prog, err, "");
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}
	drgn_log_debug(prog, "%s has debuglink %s CRC 0x%08" PRIx32, file->path,
		       debuglink, crc);

	STRING_BUILDER(sb);
	if (debuglink[0] == '/') {
		// debuglink is absolute. Try it directly.
		return drgn_module_try_standard_file(module, options, debuglink,
						     -1, false, &crc);
	}

	if (!debuglink[0] || file->path[0] != '/') {
		// debuglink is empty or file path is not absolute. Ignore it.
		return NULL;
	}

	// debuglink is relative. Try it in the debug link directories.
	const char *slash = strrchr(file->path, '/');
	// We just checked that the file path is absolute, so there must be a
	// slash. Also trim extra slashes just in case.
	while (slash != file->path && slash[-1] == '/')
		slash--;
	size_t dir_len = slash - file->path;
	const char * const *next_debug_link_dir =
		options->debug_link_directories;
	const char * const *next_debug_dir = NULL;
	for (;;) {
		if (next_debug_dir) {
			const char *debug_dir = *next_debug_dir++;
			if (!debug_dir) {
				next_debug_dir = NULL;
				continue;
			}
			if (!string_builder_append(&sb, debug_dir)
			    || !string_builder_appendn(&sb, file->path, dir_len))
				return &drgn_enomem;
		} else {
			const char *debug_link_dir = *next_debug_link_dir++;
			if (!debug_link_dir)
				return NULL;
			if (!debug_link_dir[0]) {
				// Empty path. Try under the debug directories.
				next_debug_dir = options->directories;
				continue;
			}
			const char *s = debug_link_dir;
			const char *dollar, *end;
			while ((dollar = find_dollar_origin(s, &end))) {
				if (!string_builder_appendn(&sb, s, dollar - s)
				    || !string_builder_appendn(&sb, file->path,
							       dir_len))
					return &drgn_enomem;
				s = end;
			}
			if (!string_builder_append(&sb, s))
				return &drgn_enomem;
		}
		if (!string_builder_appendc(&sb, '/')
		    || !string_builder_appendn(&sb, debuglink, debuglink_len)
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		err = drgn_module_try_standard_file(module, options, sb.str, -1,
						    false, &crc);
		if (err || !drgn_module_wants_file(module))
			return err;
		sb.len = 0;
	}
}

static struct drgn_error *
drgn_module_try_standard_files(struct drgn_module *module,
			       const struct drgn_debug_info_options *options,
			       struct drgn_standard_debug_info_find_state *state)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	// This can't happen when called from the standard debug info finder,
	// but it can from drgn_find_standard_debug_info().
	if (!drgn_module_wants_file(module))
		return NULL;

	drgn_module_try_files_log(module, "trying standard paths for");

	// If we need a supplementary file, try that first.
	err = drgn_module_try_standard_supplementary_files(module, options);
	if (err || !drgn_module_wants_file(module))
		return err;

	// If a previous attempt used a loadable file with debug info but didn't
	// want both, we might be able to reuse it.
	if (options->try_reuse
	    && module->loaded_file_status == DRGN_MODULE_FILE_WANT) {
		struct drgn_elf_file *reuse_file = NULL;
		if (module->debug_file && module->debug_file->is_loadable)
			reuse_file = module->debug_file;
		else if (module->wanted_supplementary_debug_file
			 && module->wanted_supplementary_debug_file->file->is_loadable)
			reuse_file = module->wanted_supplementary_debug_file->file;
		if (reuse_file) {
			drgn_log_debug(prog,
				       "reusing loadable debug file %s as loaded file",
				       reuse_file->path);
			err = drgn_module_maybe_use_elf_file(module, reuse_file,
							     false);
			if (err || !drgn_module_wants_file(module))
				return err;
		}
	}
	if (options->try_reuse
	    && module->debug_file_status == DRGN_MODULE_FILE_WANT
	    && module->loaded_file
	    && drgn_elf_file_has_dwarf(module->loaded_file)) {
		drgn_log_debug(prog,
			       "reusing loaded file with debug info %s as debug file",
			       module->loaded_file->path);
		err = drgn_module_maybe_use_elf_file(module,
						     module->loaded_file,
						     false);
		if (err || !drgn_module_wants_file(module))
			return err;
	}

	// First, try methods that are guaranteed to find the right file:
	// reading a vDSO from the core dump and opening a file via a magic
	// symlink in /proc.
	bool tried_proc_symlink = false;
	if (module->kind == DRGN_MODULE_VDSO) {
		err = drgn_module_try_vdso_in_core(module, options);
		if (err || !drgn_module_wants_file(module))
			return err;
	} else if (drgn_program_is_userspace_process(prog)) {
		err = drgn_module_try_proc_files(module, options,
						 &tried_proc_symlink);
		if (err || !drgn_module_wants_file(module))
			return err;
	}

	// If we already have the build ID, try it now before wasting time with
	// the expected paths. If this is a Linux kernel loadable module, this
	// can save us from needing the depmod index. If not, it can still save
	// us from trying a file with the wrong build ID.
	const bool had_build_id = module->build_id_len > 0;
	if (had_build_id) {
		err = drgn_module_try_files_by_build_id(module, options);
		if (err || !drgn_module_wants_file(module))
			return err;
	}

	// Next, try opening things at their expected paths. If this is the
	// Linux kernel or a Linux kernel loadable module, try some well-known
	// paths.
	if (module->kind == DRGN_MODULE_MAIN
	    && (module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		err = drgn_module_try_vmlinux_files(module, options);
		if (err || !drgn_module_wants_file(module))
			return err;
	} else if (module->kind == DRGN_MODULE_RELOCATABLE
		   && (module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		err = drgn_module_try_linux_kmod_files(module, options, state);
		if (err || !drgn_module_wants_file(module))
			return err;
	// Otherwise, if the module name looks like a path (i.e., it contains a
	// slash), try it. The vDSO is embedded in the kernel and isn't on disk,
	// so there's no point in trying it. Additionally, if we already tried a
	// /proc symlink, then we already tried the file that the path is
	// supposed to refer to, so don't try again.
	} else if (module->kind != DRGN_MODULE_VDSO
		   && options->try_module_name
		   && !tried_proc_symlink
		   && strchr(module->name, '/')) {
		err = drgn_module_try_standard_file(module, options,
						    module->name, -1, true,
						    NULL);
		if (err || !drgn_module_wants_file(module))
			return err;
	}

	// If we didn't have the build ID before, we might have found the loaded
	// file and gotten a build ID from it. Try to find the debug file by
	// build ID now.
	if (!had_build_id) {
		err = drgn_module_try_files_by_build_id(module, options);
		if (err || !drgn_module_wants_file(module))
			return err;
	}

	// We might have a loaded file with a .gnu_debuglink. Try to find the
	// corresponding debug file.
	return drgn_module_try_files_by_gnu_debuglink(module, options);
}

static struct drgn_error *
drgn_standard_debug_info_find(struct drgn_module * const *modules,
			      size_t num_modules, void *arg)
{
	struct drgn_error *err;
	struct drgn_debug_info_options *options = arg;

	if (drgn_log_is_enabled(modules[0]->prog, DRGN_LOG_DEBUG)) {
		_cleanup_free_ char *options_str =
			drgn_format_debug_info_options(options);
		if (!options_str)
			return &drgn_enomem;
		drgn_log_debug(modules[0]->prog,
			       "trying standard debug info finder with %s%s",
			       options == &modules[0]->prog->dbinfo.options
			       ? "" : "given ",
			       options_str);
	}

	_cleanup_(drgn_standard_debug_info_find_state_deinit)
		struct drgn_standard_debug_info_find_state state = {
			.modules = modules,
			.num_modules = num_modules,
			.kmod_walk = {
				.modules = HASH_TABLE_INIT,
				.stack = VECTOR_INIT,
				.path = STRING_BUILDER_INIT,
				.visited_dirs = HASH_TABLE_INIT,
				.next_kernel_dir = options->kernel_directories,
			},
		};
	for (size_t i = 0; i < num_modules; i++) {
		err = drgn_module_try_standard_files(modules[i], options,
						     &state);
		if (err)
			return err;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_find_standard_debug_info(struct drgn_module * const *modules,
			      size_t num_modules,
			      struct drgn_debug_info_options *options)
{
	if (num_modules == 0)
		return NULL;

	struct drgn_program *prog = modules[0]->prog;
	for (size_t i = 0; i < num_modules; i++) {
		if (modules[i]->prog != prog) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "modules are from different programs");
		}
	}

	if (!options)
		options = &modules[0]->prog->dbinfo.options;
	return drgn_standard_debug_info_find(modules, num_modules, options);
}

#if WITH_DEBUGINFOD
static int count_columns(const char *s, size_t n)
{
	int columns = 0;
	while (n > 0) {
		mbstate_t ps;
		memset(&ps, 0, sizeof(ps));
		do {
			wchar_t wc;
			size_t r = mbrtowc(&wc, s, n, &ps);
			if (r == (size_t)-1) // Invalid multibyte sequence.
				return -1;
			if (r == (size_t)-2) // Incomplete multibyte character.
				return -2;
			if (r == 0) // Null wide character.
				r = 1;

			int w = wcwidth(wc);
			if (w < 0) // Nonprintable wide character.
				return -3;
			s += r;
			n -= r;
			columns += w;
		} while (!mbsinit(&ps));
	}
	return columns;
}

static int truncate_columns(struct string_builder *sb, size_t start, size_t end,
			    int max_columns)
{
	int columns = 0;

	size_t truncate_len = start;
	int truncate_column = 0;
	mbstate_t truncate_ps;
	memset(&truncate_ps, 0, sizeof(truncate_ps));

	while (start < end) {
		mbstate_t ps;
		memset(&ps, 0, sizeof(ps));
		do {
			wchar_t wc;
			size_t r = mbrtowc(&wc, &sb->str[start], end - start,
					   &ps);
			if (r == (size_t)-1) // Invalid multibyte sequence.
				return -1;
			if (r == (size_t)-2) // Incomplete multibyte character.
				return -2;
			if (r == 0) // Null wide character.
				r = 1;

			int w = wcwidth(wc);
			if (w < 0) // Nonprintable wide character.
				return -3;

			if (w > max_columns - columns) {
				int dots = min(max_columns, 3);
				char reset[MB_LEN_MAX];
				size_t reset_len = 0;
				if (!mbsinit(&truncate_ps)) {
					reset_len = wcrtomb(reset, L'\0',
							    &truncate_ps) - 1;
				}
				size_t new_len = (truncate_len
						  + reset_len
						  + dots
						  + (sb->len - end));
				if (!string_builder_reserve(sb, new_len))
					return INT_MIN;
				memmove(&sb->str[truncate_len + reset_len + dots],
					&sb->str[end], sb->len - end);
				memset(&sb->str[truncate_len + reset_len], '.',
				       dots);
				memcpy(&sb->str[truncate_len], reset,
				       reset_len);
				sb->len = new_len;
				return truncate_column + dots;
			}

			start += r;
			columns += w;
			if (columns <= max_columns - 3) {
				truncate_len = start;
				truncate_column = columns;
				memcpy(&truncate_ps, &ps, sizeof(ps));
			}
		} while (!mbsinit(&ps));
	}
	return columns;
}

static void reset_shift_state(struct string_builder *sb, mbstate_t *ps)
{
	if (!mbsinit(ps))
		sb->len += wcrtomb(&sb->str[sb->len], L'\0', ps) - 1;
}

static bool write_unicode_progress_bar(struct string_builder *sb, int columns,
				       double ratio)
{
	size_t orig_len = sb->len;

	mbstate_t ps;
	memset(&ps, 0, sizeof(ps));

	// "Right one eighth block" character.
	size_t r = wcrtomb(&sb->str[sb->len], L'\u2595', &ps);
	if (r == (size_t)-1)
		return false;
	sb->len += r;

	// + 0.25 so that we round up if the piece would be at least 75% full.
	int eighths = columns * ratio * 8.0 + 0.25;
	int blocks = eighths / 8;
	int i;
	for (i = 0; i < blocks; i++) {
		// "Full block" character.
		r = wcrtomb(&sb->str[sb->len], L'\u2588', &ps);
		if (r == (size_t)-1)
			goto undo;
		sb->len += r;
	}
	// "Left one eighth block" through "left seven eighths block"
	// characters.
	static const wchar_t eighths_blocks[7] =
		L"\u258f\u258e\u258d\u258c\u258b\u258a\u2589";
	if (eighths % 8 != 0) {
		r = wcrtomb(&sb->str[sb->len], eighths_blocks[eighths % 8 - 1],
			    &ps);
		if (r == (size_t)-1)
			goto undo;
		sb->len += r;
		i++;
	}

	for (; i < columns; i++) {
		r = wcrtomb(&sb->str[sb->len], L' ', &ps);
		if (r == (size_t)-1)
			goto undo;
		sb->len += r;
	}

	// "Left one eighth block" character.
	r = wcrtomb(&sb->str[sb->len], L'\u258f', &ps);
	if (r == (size_t)-1)
		goto undo;
	sb->len += r;

	reset_shift_state(sb, &ps);
	return true;

undo:
	sb->len = orig_len;
	return false;
}

static void write_ascii_progress_bar(struct string_builder *sb, int columns,
				     double ratio)
{
	sb->str[sb->len++] = '[';
	// + 0.25 so that we round up if the block would be at least 75% full.
	int blocks = columns * ratio + 0.25;
	memset(&sb->str[sb->len], '#', blocks);
	sb->len += blocks;
	memset(&sb->str[sb->len], ' ', columns - blocks);
	sb->len += columns - blocks;
	sb->str[sb->len++] = ']';
}

static bool write_unicode_spinner(struct string_builder *sb, int pos)
{
	static const wchar_t spinner[] = {
		L'\u2596', // Quadrant lower left
		L'\u2598', // Quadrant upper left
		L'\u259d', // Quadrant upper right
		L'\u2597', // Quadrant lower right
	};
	mbstate_t ps;
	memset(&ps, 0, sizeof(ps));
	size_t r = wcrtomb(&sb->str[sb->len],
			   spinner[pos % array_size(spinner)], &ps);
	if (r == (size_t)-1)
		return false;
	sb->len += r;
	reset_shift_state(sb, &ps);
	return true;
}

static void write_ascii_spinner(struct string_builder *sb, int pos)
{
	static const char spinner[] = { '|', '/', '-', '\\' };
	sb->str[sb->len++] = spinner[pos % array_size(spinner)];
}

// debuginfod_set_user_data() and debuginfod_get_user_data() were added in
// elfutils 0.179. Before that, we emulate them with a thread-local variable.
#if !_ELFUTILS_PREREQ(0, 179)
static _Thread_local void *drgn_debuginfod_user_data;
#endif

// This is called with:
// - a >= 0 && b == 0 while cleaning the debuginfod cache, where a is the number
//   of files in the cache that have been checked.
// - a >= 0 && b == 0 while waiting to read the first chunk of data from a
//   debuginfod server, where a is an increasing counter. Note that this cannot
//   be distinguished from the previous case.
// - a >= 0 && b > 0 while downloading, where a is the number of bytes
//   downloaded and b is the total size to download in bytes.
// - a >= 0 && b <= 0 while downloading, where a is the number of bytes
//   downloaded and the total size is not known. This can be distinguished from
//   the first two cases because debuginfod_get_url() will return non-NULL.
// - a < 0 && b >= 0 when the download has finished successfully. b is the
//   downloaded file descriptor.
// - a < 0 && b < 0 when the download failed. b is a negative errno.
static void drgn_log_debuginfod_progress(debuginfod_client *client, long a,
					 long b)
{
#if _ELFUTILS_PREREQ(0, 179)
	struct drgn_program *prog = drgn_debuginfod_get_user_data(client);
#else
	struct drgn_program *prog = drgn_debuginfod_user_data;
#endif

	const bool done = a < 0;

	// If we already started logging progress for this download when it
	// failed, we log the error like progress below. Otherwise, the download
	// failed very early, so we only log a debug message.
	if (done && b < 0 && !prog->dbinfo.logged_debuginfod_progress) {
		if (b != -ENOSYS) {
			errno = -b;
			drgn_log_debug(prog,
				       "%s: couldn't download%s from debuginfod: %m",
				       prog->dbinfo.debuginfod_current_name,
				       prog->dbinfo.debuginfod_current_type);
		} else if (!prog->dbinfo.logged_no_debuginfod) {
			drgn_log_debug(prog,
				       "no debuginfod servers configured; "
				       "try setting the DEBUGINFOD_URLS environment variable");
			prog->dbinfo.logged_no_debuginfod = true;
		}
		return;
	}
	prog->dbinfo.logged_debuginfod_progress = true;

	int columns;
	FILE *file = drgn_program_get_progress_file(prog, &columns);

	// ANSI escape sequence to clear the current line and return the cursor
	// to the beginning of the line.
	static const char ansi_erase_line[] = "\33[2K\r";

	// Once we know what URL we are downloading from, log it.
	if (!prog->dbinfo.debuginfod_have_url) {
		// debuginfod_get_url() was added in elfutils 0.179. Before
		// that, we have to assume that we have a URL.
#if _ELFUTILS_PREREQ(0, 179)
		const char *url = drgn_debuginfod_get_url(client);
		if (url) {
			prog->dbinfo.debuginfod_have_url = true;
			// Erase the current line since we may have logged
			// progress.
			if (columns >= 0) {
				fwrite(ansi_erase_line, 1,
				       sizeof(ansi_erase_line) - 1, file);
				fflush(file);
			}
			drgn_log_debug(prog, "downloading from debuginfod at %s", url);
		}
#else
		prog->dbinfo.debuginfod_have_url = true;
#endif
	}

	// If we succeeded without ever getting a URL, it must have been cached.
	if (done && b >= 0 && !prog->dbinfo.debuginfod_have_url) {
		// We may have logged download progress when we were actually
		// cleaning the cache. Clear it to avoid confusion.
		if (columns >= 0) {
			fwrite(ansi_erase_line, 1, sizeof(ansi_erase_line) - 1,
			       file);
			fflush(file);
		}
		drgn_log_debug(prog, "%s: found%s in debuginfod cache",
			       prog->dbinfo.debuginfod_current_name,
			       prog->dbinfo.debuginfod_current_type);
		return;
	}

	if (!file)
		return;

	// We only do the progress animation if we would have at least one
	// column for a progress bar. Using the calculation for bar_columns
	// below:
	//
	//    columns - (floor(columns / 2) - 10) - 2 - 4 >= 1
	// => columns - floor(columns / 2) >= 17
	// => ceil(columns / 2) >= 17
	// => columns >= 33
	bool animate = columns >= 33;
	const bool orig_animate = animate;

	STRING_BUILDER(sb);

	if (animate && !string_builder_appendc(&sb, '\r'))
		return;

	int fill_columns = 0;
	int bar_columns = 0;
	if (animate) {
		if (done) {
			// We need to erase anything left in the line with
			// spaces.
			fill_columns = columns;
		} else if (b > 0) {
			// Use half of the line plus a bit for the name and
			// download size so that it doesn't get too short in
			// small terminals.
			fill_columns = columns / 2 + 10;
			// Use the rest for the progress bar.
			bar_columns = (columns - fill_columns
				       - 2 // Ends of progress bar
				       - 4 // " XX%"
				      );
		} else {
			// Use the whole line, minus the spinner, for the name
			// and download size
			fill_columns = columns - 1;
		}
	}

	if (!string_builder_append(&sb,
				   done && b >= 0
				   ? "Downloaded " : "Downloading ")
	    || !string_builder_append(&sb,
				      prog->dbinfo.debuginfod_current_name)
	    || !string_builder_append(&sb,
				      prog->dbinfo.debuginfod_current_type))
		return;

	size_t download_size_start = sb.len;
	if (done && b < 0) {
		errno = -b;
		if (!string_builder_appendf(&sb, " failed: %m"))
			return;
	} else if (prog->dbinfo.debuginfod_have_url) {
		intmax_t download_size;
		if (done) {
			struct stat st;
			if (fstat(b, &st) < 0) {
				drgn_log_warning(prog, "fstat: %m");
				return;
			}
			download_size = st.st_size;
		} else {
			download_size = a;
		}
		if (download_size < 2048) {
			if (!string_builder_appendf(&sb, " (%" PRIdMAX " B)",
						    download_size))
				return;
		} else {
			static const char prefixes[] = "KMGTPEZY";
			int i = 1;
			while (i < sizeof(prefixes) - 1
			       && (download_size >> (10 * i)) >= 2048)
				i++;
			double unit = INTMAX_C(1) << (10 * i);
			if (!string_builder_appendf(&sb, " (%.1f %ciB)",
						    download_size / unit,
						    prefixes[i - 1]))
				return;
		}
	}

	if (animate) {
		int current_column;
		if (done) {
			// Start at byte 1 to skip the "\r".
			current_column = count_columns(&sb.str[1], sb.len - 1);
		} else {
			int download_size_len = sb.len - download_size_start;
			// Leave room for the download size and an extra space.
			int max_columns =
				max(fill_columns - download_size_len - 1, 0);
			// Start at byte 1 to skip the "\r".
			current_column = truncate_columns(&sb, 1,
							  download_size_start,
							  max_columns);
			if (current_column == INT_MIN)
				return; // Memory allocation failed.
			if (current_column >= 0)
				current_column += download_size_len;
		}
		if (current_column < 0) {
			// We either couldn't decode the string or the string
			// contained a nonprintable character. Give up on the
			// animation.
			animate = false;
		} else if (current_column < fill_columns) {
			if (!string_builder_reserve_for_append(&sb,
							       fill_columns
							       - current_column))
				return;
			memset(&sb.str[sb.len], ' ',
			       fill_columns - current_column);
			sb.len += fill_columns - current_column;
		}
	}

	// If we can't encode any of the following Unicode characters in the
	// current locale, we fall back to ASCII.
	if (!done && b > 0) {
		// Clamp the ratio in case we get bogus sizes.
		double ratio = a < b ? (double)a / (double)b : 1.0;
		if (animate) {
			// One multibyte character for each bar column, one for
			// each end, and one to reset the shift state.
			if (!string_builder_reserve_for_append(&sb,
							       (bar_columns + 3)
							       * MB_CUR_MAX))
				return;
			if (!write_unicode_progress_bar(&sb, bar_columns,
							ratio)) {
				write_ascii_progress_bar(&sb, bar_columns,
							 ratio);
			}
		}
		unsigned int percent = 100.0 * ratio;
		// We're not 100% done until we're called with done = true.
		if (percent > 99)
			percent = 99;
		if (!string_builder_appendf(&sb, " %*u%%", animate ? 2 : 0,
					    percent))
			return;
	} else if (!done && animate) {
		// One multibyte character for the spinner, one to reset the
		// shift state.
		if (!string_builder_reserve_for_append(&sb, 2 * MB_CUR_MAX))
			return;
		unsigned int pos = prog->dbinfo.debuginfod_spinner_position++;
		if (!write_unicode_spinner(&sb, pos))
			write_ascii_spinner(&sb, pos);
	}

	if ((done || !animate) && !string_builder_appendc(&sb, '\n'))
		return;

	// If we were originally animating but gave up, we need to skip the
	// "\r".
	fwrite(sb.str + (orig_animate && !animate ? 1 : 0), 1,
	       sb.len - (orig_animate && !animate ? 1 : 0), file);
}

static struct sigaction drgn_cancel_debuginfod_oldact;
static volatile sig_atomic_t drgn_cancel_debuginfod;
static void drgn_cancel_debuginfod_handler(int sig)
{
	drgn_cancel_debuginfod = 1;
	drgn_cancel_debuginfod_oldact.sa_handler(sig);
}
static void drgn_cancel_debuginfod_sigaction(int sig, siginfo_t *info,
					     void *ucontext)
{
	drgn_cancel_debuginfod = 1;
	drgn_cancel_debuginfod_oldact.sa_sigaction(sig, info, ucontext);
}
static bool drgn_prepare_debuginfod_find(struct drgn_program *prog)
{
#if !_ELFUTILS_PREREQ(0, 179)
	drgn_debuginfod_user_data = prog;
#endif
	// If the application has a signal handler for SIGINT, temporarily wrap
	// it with our own signal handler that sets a flag for the debuginfod
	// progressfn. This allows Ctrl+C to interrupt a download in
	// applications that handle SIGINT (like the Python interpreter).
	drgn_cancel_debuginfod = 0;
	if (sigaction(SIGINT, NULL, &drgn_cancel_debuginfod_oldact) != 0)
		return false;
	struct sigaction act = drgn_cancel_debuginfod_oldact;
	if ((act.sa_flags & SA_SIGINFO)
	    // SIG_DFL and SIG_IGN are meant to be assigned to sa_handler, but
	    // the Linux kernel treats them the same for sa_sigaction.
	    && act.sa_sigaction != (void *)SIG_DFL
	    && act.sa_sigaction != (void *)SIG_IGN)
		act.sa_sigaction = drgn_cancel_debuginfod_sigaction;
	else if (!(act.sa_flags & SA_SIGINFO)
		 && act.sa_handler != SIG_DFL && act.sa_handler != SIG_IGN)
		act.sa_handler = drgn_cancel_debuginfod_handler;
	else
		return false;
	return sigaction(SIGINT, &act, NULL) == 0;
}
static void drgn_finish_debuginfod_find(bool restore_sigaction)
{
	if (restore_sigaction)
		sigaction(SIGINT, &drgn_cancel_debuginfod_oldact, NULL);
}

static int drgn_debuginfod_progressfn(debuginfod_client *client, long a, long b)
{
	if (drgn_cancel_debuginfod)
		return 1;
	if (a >= 0)
		drgn_log_debuginfod_progress(client, a, b);
	return 0;
}

static struct drgn_error *
drgn_module_try_file_from_debuginfod(struct drgn_module *module,
				     const char *build_id_str,
				     bool debug, bool supplementary,
				     struct string_builder *cache_sb)
{
	struct drgn_program *prog = module->prog;

	if (!string_builder_appendf(cache_sb, "/%s/%s", build_id_str,
				    debug ? "debuginfo" : "executable")
	    || !string_builder_null_terminate(cache_sb))
		return &drgn_enomem;

	prog->dbinfo.debuginfod_current_name = module->name;
	if (supplementary)
		prog->dbinfo.debuginfod_current_type = " supplementary debug info";
	else if (debug)
		prog->dbinfo.debuginfod_current_type = " debug info";
	else
		prog->dbinfo.debuginfod_current_type = "";
	prog->dbinfo.debuginfod_have_url = false;
	prog->dbinfo.logged_debuginfod_progress = false;
	bool restore_sigaction = drgn_prepare_debuginfod_find(prog);
	char *path;
	auto find = debug
		    ? drgn_debuginfod_find_debuginfo
		    : drgn_debuginfod_find_executable;
	int fd = find(prog->dbinfo.debuginfod_client,
		      (const unsigned char *)build_id_str, 0, &path);
	drgn_finish_debuginfod_find(restore_sigaction);
	if (fd == -ENOENT && drgn_cancel_debuginfod) {
		// Before elfutils commit 5527216460c6 ("debuginfod-client.c:
		// Skip empty file creation for cancelled queries") (in elfutils
		// 0.190), libdebuginfod has a nasty bug that causes it to cache
		// a cancelled download as a negative hit. Work around it by
		// deleting the cache file.
		unlink(cache_sb->str);
		return drgn_error_create_os("download cancelled", EINTR, NULL);
	}
	drgn_log_debuginfod_progress(prog->dbinfo.debuginfod_client, -1, fd);
	if (fd >= 0) {
		struct drgn_error *err =
			drgn_module_try_file(module, path, fd, true);
		free(path);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_module_try_supplementary_file_from_debuginfod(struct drgn_module *module,
						   struct string_builder *cache_sb)
{
	if (drgn_module_wanted_supplementary_debug_file(module, NULL, NULL,
							NULL, NULL)
	    != DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK)
		return NULL;
	const char *gnu_debugaltlink_build_id_str =
		module->wanted_supplementary_debug_file->checksum_str;
	return drgn_module_try_file_from_debuginfod(module,
						    gnu_debugaltlink_build_id_str,
						    true, true, cache_sb);
}

static struct drgn_error *
drgn_debuginfod_find(struct drgn_module * const *modules, size_t num_modules,
		     void *arg)
{
	struct drgn_error *err;
	struct drgn_program *prog = arg;

	if (!prog->dbinfo.debuginfod_client) {
		prog->dbinfo.debuginfod_client = drgn_debuginfod_begin();
		if (!prog->dbinfo.debuginfod_client) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "couldn't create debuginfod client session");
		}
		drgn_debuginfod_set_progressfn(prog->dbinfo.debuginfod_client,
					       drgn_debuginfod_progressfn);
#if _ELFUTILS_PREREQ(0, 179)
		drgn_debuginfod_set_user_data(prog->dbinfo.debuginfod_client,
					      prog);
#endif
	}

	STRING_BUILDER(sb);
	const char *env;
	if ((env = getenv("DEBUGINFOD_CACHE_PATH"))) {
		if (!string_builder_append(&sb, env))
			return &drgn_enomem;
	} else {
		env = getenv("HOME") ?: "/";
		if (!string_builder_append(&sb, env)
		    || !string_builder_append(&sb, "/.debuginfod_client_cache")
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		struct stat st;
		if (stat(sb.str, &st) < 0) {
			sb.len = 0;
			if ((env = getenv("XDG_CACHE_HOME"))) {
				if (!string_builder_append(&sb, env)
				    || !string_builder_append(&sb,
							      "/debuginfod_client"))
					return &drgn_enomem;
			} else if (!string_builder_append(&sb,
							  getenv("HOME") ?: "/")
				   || !string_builder_append(&sb,
							     "/.cache/debuginfod_client")) {
					return &drgn_enomem;
			}
		}
	}

	size_t cache_dir_len = sb.len;
	for (size_t i = 0; i < num_modules; i++) {
		struct drgn_module *module = modules[i];
		const char *build_id_str =
			drgn_module_build_id(module, NULL, NULL);
		if (!build_id_str) {
			drgn_module_try_files_log(module, "can't query debuginfod for");
			continue;
		}

		drgn_module_try_files_log(module, "querying debuginfod for");

		// If we need a supplementary file, try that first.
		err = drgn_module_try_supplementary_file_from_debuginfod(module,
									 &sb);
		if (err)
			return err;
		sb.len = cache_dir_len;

		// If we need the debug file (including if we needed a
		// gnu_debugaltlink file and didn't find it), try that next.
		if (drgn_module_wants_debug_file(module)) {
			uint64_t orig_supplementary_file_generation =
				prog->dbinfo.supplementary_file_generation;
			err = drgn_module_try_file_from_debuginfod(module,
								   build_id_str,
								   true, false,
								   &sb);
			if (err)
				return err;
			sb.len = cache_dir_len;
			// If the wanted supplementary debug file changed, try
			// finding it again.
			if (drgn_module_wanted_supplementary_debug_file_is_new(module,
						orig_supplementary_file_generation)) {
				err = drgn_module_try_supplementary_file_from_debuginfod(module,
											 &sb);
				if (err)
					return err;
				sb.len = cache_dir_len;
			}
		}

		if (drgn_module_wants_loaded_file(module)) {
			err = drgn_module_try_file_from_debuginfod(module,
								   build_id_str,
								   false, false,
								   &sb);
			if (err)
				return err;
			sb.len = cache_dir_len;
		}
	}
	return NULL;
}
#endif // WITH_DEBUGINFOD

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_try_file(struct drgn_module *module,
					const char *path, int fd, bool force)
{
	if (!drgn_module_wants_file(module)) {
		drgn_log_debug(module->prog, "%s: ignoring unwanted file %s",
			       module->name, path);
		if (fd >= 0)
			close(fd);
		return NULL;
	}
	drgn_module_try_files_log(module, "trying provided file as");
	return drgn_module_try_file_internal(module, path, fd, !force, NULL);
}

LIBDRGN_PUBLIC
void drgn_module_iterator_destroy(struct drgn_module_iterator *it)
{
	if (it) {
		if (it->destroy)
			it->destroy(it);
		else
			free(it);
	}
}

LIBDRGN_PUBLIC struct drgn_program *
drgn_module_iterator_program(const struct drgn_module_iterator *it)
{
	return it->prog;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_iterator_next(struct drgn_module_iterator *it,
					     struct drgn_module **ret,
					     bool *new_ret)
{
	if (!it->next) {
		*ret = NULL;
		return NULL;
	}
	struct drgn_error *err = it->next(it, ret, new_ret);
	if (err || !*ret)
		it->next = NULL;
	return err;
}

struct drgn_created_module_iterator {
	struct drgn_module_iterator it;
	struct drgn_module_table_iterator table_it;
	struct drgn_module *next_module;
	uint64_t generation;
	bool yielded_main;
};

static struct drgn_error *
drgn_created_module_iterator_next(struct drgn_module_iterator *_it,
				  struct drgn_module **ret,
				  bool *new_ret)
{
	struct drgn_created_module_iterator *it =
		container_of(_it, struct drgn_created_module_iterator, it);
	struct drgn_debug_info *dbinfo = &it->it.prog->dbinfo;

	if (!it->yielded_main) {
		it->yielded_main = true;
		it->table_it = drgn_module_table_first(&dbinfo->modules);
		it->generation = dbinfo->modules_generation;
		if (dbinfo->main_module) {
			*ret = dbinfo->main_module;
			if (new_ret)
				*new_ret = false;
			return NULL;
		}
	}

	if (it->generation != dbinfo->modules_generation) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "modules changed during iteration");
	}

	for (;;) {
		if (!it->next_module) {
			if (it->table_it.entry) {
				it->next_module = *it->table_it.entry;
				it->table_it = drgn_module_table_next(it->table_it);
			} else {
				*ret = NULL;
				return NULL;
			}
		}
		if (it->next_module == dbinfo->main_module) {
			it->next_module = it->next_module->next_same_name;
		} else {
			*ret = it->next_module;
			if (new_ret)
				*new_ret = false;
			it->next_module = it->next_module->next_same_name;
			return NULL;
		}
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_created_module_iterator_create(struct drgn_program *prog,
				    struct drgn_module_iterator **ret)
{
	struct drgn_created_module_iterator *it = calloc(1, sizeof(*it));
	if (!it)
		return &drgn_enomem;
	drgn_module_iterator_init(&it->it, prog, NULL,
				  drgn_created_module_iterator_next);
	*ret = &it->it;
	return NULL;
}

struct drgn_mapped_file {
	const char *path;
	// Mapped address range containing file offset 0. This is used to find
	// the file header.
	uint64_t offset0_vaddr, offset0_size;
};

static struct drgn_mapped_file *drgn_mapped_file_create(const char *path)
{
	struct drgn_mapped_file *file = calloc(1, sizeof(*file));
	if (file)
		file->path = path;
	return file;
}

static void drgn_mapped_file_destroy(struct drgn_mapped_file *file)
{
	free(file);
}

struct drgn_mapped_file_segment {
	uint64_t start;
	uint64_t end;
	uint64_t file_offset;
	struct drgn_mapped_file *file;
};

DEFINE_VECTOR(drgn_mapped_file_segment_vector, struct drgn_mapped_file_segment);

struct drgn_mapped_file_segments {
	struct drgn_mapped_file_segment_vector vector;
	// Whether the segments are already sorted by start address. This should
	// always be true for both /proc/$pid/maps and NT_FILE, but we check and
	// sort afterwards if not just in case.
	bool sorted;
};

#define DRGN_MAPPED_FILE_SEGMENTS_INIT { VECTOR_INIT, true }

static void drgn_mapped_file_segments_abort(struct drgn_mapped_file_segments *segments)
{
	drgn_mapped_file_segment_vector_deinit(&segments->vector);
}

static struct drgn_error *
drgn_add_mapped_file_segment(struct drgn_mapped_file_segments *segments,
			     uint64_t start, uint64_t end, uint64_t file_offset,
			     struct drgn_mapped_file *file)
{
	assert(start < end);
	if (file_offset == 0 && file->offset0_size == 0) {
		file->offset0_vaddr = start;
		file->offset0_size = end - start;
	}
	if (!drgn_mapped_file_segment_vector_empty(&segments->vector)) {
		struct drgn_mapped_file_segment *last =
			drgn_mapped_file_segment_vector_last(&segments->vector);
		// If the last segment is from the same file and contiguous with
		// this one, merge into that one.
		if (file == last->file && start == last->end
		    && file_offset == last->file_offset + (last->end - last->start)) {
			last->end = end;
			return NULL;
		}
		if (start < last->start)
			segments->sorted = false;
	}
	struct drgn_mapped_file_segment *entry =
		drgn_mapped_file_segment_vector_append_entry(&segments->vector);
	if (!entry)
		return &drgn_enomem;
	entry->start = start;
	entry->end = end;
	entry->file_offset = file_offset;
	entry->file = file;
	return NULL;
}

enum {
	// Yield main module next.
	USERSPACE_LOADED_MODULE_ITERATOR_STATE_MAIN,
	// Yield vDSO module next.
	USERSPACE_LOADED_MODULE_ITERATOR_STATE_VDSO,
	// Get first link_map from r_debug next.
	USERSPACE_LOADED_MODULE_ITERATOR_STATE_R_DEBUG,
	// Yield module from link_map list next.
	USERSPACE_LOADED_MODULE_ITERATOR_STATE_LINK_MAP,
	// States after this are the same as
	// USERSPACE_LOADED_MODULE_ITERATOR_STATE_LINK_MAP but also count how
	// many link_map entries we've iterated.
};

// Arbitrary limit on the number iterations to make through the link_map list in
// order to avoid getting stuck in a cycle.
static const int MAX_LINK_MAP_LIST_ITERATIONS = 10000;

struct userspace_loaded_module_iterator {
	struct drgn_module_iterator it;
	int state;
	bool read_main_phdrs;
	bool have_main_dyn;
	bool have_vdso_dyn;

	struct drgn_mapped_file_segment *file_segments;
	size_t num_file_segments;

	uint64_t main_phoff;
	uint64_t main_bias;
	uint64_t main_dyn_vaddr;
	uint64_t main_dyn_memsz;
	uint64_t vdso_dyn_vaddr;
	uint64_t link_map;

	// Temporary buffer for reading program headers.
	void *phdrs_buf;
	size_t phdrs_buf_capacity;

	// Temporary buffer for reading segment contents.
	void *segment_buf;
	size_t segment_buf_capacity;
};

static void
userspace_loaded_module_iterator_deinit(struct userspace_loaded_module_iterator *it)
{
	free(it->segment_buf);
	free(it->phdrs_buf);
	free(it->file_segments);
}

static inline int drgn_mapped_file_segment_compare(const void *_a,
						   const void *_b)
{
	const struct drgn_mapped_file_segment *a = _a;
	const struct drgn_mapped_file_segment *b = _b;
	return (a->start > b->start) - (a->start < b->start);
}

static void
userspace_loaded_module_iterator_set_file_segments(struct userspace_loaded_module_iterator *it,
						   struct drgn_mapped_file_segments *segments)
{
	// Don't bother shrinking to fit since this is short-lived.
	drgn_mapped_file_segment_vector_steal(&segments->vector,
					      &it->file_segments,
					      &it->num_file_segments);
	if (!segments->sorted) {
		qsort(it->file_segments, it->num_file_segments,
		      sizeof(it->file_segments[0]),
		      drgn_mapped_file_segment_compare);
	}
}

static struct drgn_mapped_file_segment *
find_mapped_file_segment(struct userspace_loaded_module_iterator *it,
			 uint64_t address)
{
	#define less_than_start(a, b) (*(a) < (b)->start)
	size_t i = binary_search_gt(it->file_segments, it->num_file_segments,
				    &address, less_than_start);
	#undef less_than_start
	if (i == 0 || address >= it->file_segments[i - 1].end)
		return NULL;
	return &it->file_segments[i - 1];
}

static struct drgn_error *
userspace_loaded_module_iterator_read_ehdr(struct userspace_loaded_module_iterator *it,
					   uint64_t address, GElf_Ehdr *ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	err = drgn_program_read_memory(prog, ret, address, sizeof(*ret), false);
	if (err && err->code == DRGN_ERROR_FAULT) {
		drgn_log_debug(prog,
			       "couldn't read ELF header at 0x%" PRIx64 ": %s",
			       err->address, err->message);
		drgn_error_destroy(err);
		return &drgn_not_found;
	} else if (err) {
		return err;
	}
	if (memcmp(ret->e_ident, ELFMAG, SELFMAG) != 0) {
		drgn_log_debug(prog, "invalid ELF header magic");
		return &drgn_not_found;
	}
	if (ret->e_ident[EI_CLASS] !=
	    (drgn_platform_is_64_bit(&prog->platform)
	     ? ELFCLASS64 : ELFCLASS32)) {
		drgn_log_debug(prog,
			       "ELF header class (%u) does not match program",
			       ret->e_ident[EI_CLASS]);
		return &drgn_not_found;
	}
	if (ret->e_ident[EI_DATA] !=
	    (drgn_platform_is_little_endian(&prog->platform)
	     ? ELFDATA2LSB : ELFDATA2MSB)) {
		drgn_log_debug(prog,
			       "ELF header data encoding (%u) does not match program",
			       ret->e_ident[EI_DATA]);
		return &drgn_not_found;
	}
#define visit_elf_ehdr_members(visit_scalar_member, visit_raw_member) do {	\
	visit_raw_member(e_ident);						\
	visit_scalar_member(e_type);						\
	visit_scalar_member(e_machine);						\
	visit_scalar_member(e_version);						\
	visit_scalar_member(e_entry);						\
	visit_scalar_member(e_phoff);						\
	visit_scalar_member(e_shoff);						\
	visit_scalar_member(e_flags);						\
	visit_scalar_member(e_ehsize);						\
	visit_scalar_member(e_phentsize);					\
	visit_scalar_member(e_phnum);						\
	visit_scalar_member(e_shentsize);					\
	visit_scalar_member(e_shnum);						\
	visit_scalar_member(e_shstrndx);					\
} while (0)
	deserialize_struct64_inplace(ret, Elf32_Ehdr, visit_elf_ehdr_members,
				     drgn_platform_is_64_bit(&prog->platform),
				     drgn_platform_bswap(&prog->platform));
#undef visit_elf_ehdr_members
	if (ret->e_phentsize !=
	    (drgn_platform_is_64_bit(&prog->platform)
	     ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr))) {
		drgn_log_debug(prog,
			       "ELF program header entry size (%u) does not match class",
			       ret->e_phentsize);
		return &drgn_not_found;
	}
	return NULL;
}

static struct drgn_error *
userspace_loaded_module_iterator_read_phdrs(struct userspace_loaded_module_iterator *it,
					    uint64_t address, uint16_t phnum)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;
	uint32_t phentsize =
		(drgn_platform_is_64_bit(&prog->platform)
		 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr));
	uint32_t phdrs_size = (uint32_t)phnum * phentsize;
	if (phdrs_size > MAX_MEMORY_READ_FOR_DEBUG_INFO) {
		drgn_log_debug(prog,
			       "program header table is unreasonably large (%" PRIu32 " bytes); ignoring",
			       phdrs_size);
		return &drgn_not_found;
	}
	if (!alloc_or_reuse(&it->phdrs_buf, &it->phdrs_buf_capacity,
			    phdrs_size))
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, it->phdrs_buf, address, phdrs_size,
				       false);
	if (err && err->code == DRGN_ERROR_FAULT) {
		drgn_log_debug(prog,
			       "couldn't read program header table at 0x%" PRIx64 ": %s",
			       err->address, err->message);
		drgn_error_destroy(err);
		return &drgn_not_found;
	}
	return err;
}

static void
userspace_loaded_module_iterator_phdr(struct userspace_loaded_module_iterator *it,
				      size_t i, GElf_Phdr *ret)
{
	struct drgn_program *prog = it->it.prog;
	size_t phentsize =
		(drgn_platform_is_64_bit(&prog->platform)
		 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr));
#define visit_phdr_members(visit_scalar_member, visit_raw_member) do {	\
	visit_scalar_member(p_type);					\
	visit_scalar_member(p_flags);					\
	visit_scalar_member(p_offset);					\
	visit_scalar_member(p_vaddr);					\
	visit_scalar_member(p_paddr);					\
	visit_scalar_member(p_filesz);					\
	visit_scalar_member(p_memsz);					\
	visit_scalar_member(p_align);					\
} while (0)
	deserialize_struct64(ret, Elf32_Phdr, visit_phdr_members,
			     (char *)it->phdrs_buf + i * phentsize,
			     drgn_platform_is_64_bit(&prog->platform),
			     drgn_platform_bswap(&prog->platform));
#undef visit_phdr_members
}

static struct drgn_error *
userspace_loaded_module_iterator_read_dynamic(struct userspace_loaded_module_iterator *it,
					      uint64_t address, uint64_t size,
					      size_t *num_dyn_ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	if (size > MAX_MEMORY_READ_FOR_DEBUG_INFO) {
		drgn_log_debug(prog,
			       "dynamic section is unreasonably large (%" PRIu64 " bytes); ignoring",
			       size);
		return &drgn_not_found;
	}
	size_t dyn_size =
		(drgn_platform_is_64_bit(&prog->platform)
		 ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn));
	uint64_t num_dyn = size / dyn_size;
	*num_dyn_ret = num_dyn;
	if (num_dyn == 0)
		return NULL;

	if (!alloc_or_reuse(&it->segment_buf, &it->segment_buf_capacity,
			    num_dyn * dyn_size))
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, it->segment_buf, address,
				       num_dyn * dyn_size, false);
	if (err && err->code == DRGN_ERROR_FAULT) {
		drgn_log_debug(prog,
			       "couldn't read dynamic section at 0x%" PRIx64 ": %s",
			       err->address, err->message);
		drgn_error_destroy(err);
		return &drgn_not_found;
	}
	return err;
}

static void
userspace_loaded_module_iterator_dyn(struct userspace_loaded_module_iterator *it,
				     size_t i, GElf_Dyn *ret)
{
	struct drgn_program *prog = it->it.prog;
	size_t dyn_size =
		(drgn_platform_is_64_bit(&prog->platform)
		 ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn));
#define visit_elf_dyn_members(visit_scalar_member, visit_raw_member) do {	\
	visit_scalar_member(d_tag);						\
	visit_scalar_member(d_un.d_val);					\
} while (0)
	deserialize_struct64(ret, Elf32_Dyn, visit_elf_dyn_members,
			     (char *)it->segment_buf + i * dyn_size,
			     drgn_platform_is_64_bit(&prog->platform),
			     drgn_platform_bswap(&prog->platform));
#undef visit_elf_dyn_members
}

static struct drgn_error *
userspace_loaded_module_iterator_read_main_phdrs(struct userspace_loaded_module_iterator *it)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	// The main bias is the difference between AT_PHDR and the virtual
	// address of the program headers in the ELF file. We determine the
	// latter by finding the PT_LOAD segment containing e_phoff. We would
	// use PT_PHDR instead, but static binaries usually don't have it, and
	// we can't assume a bias of 0 for static PIE binaries.
	//
	// If we couldn't find the file offset of the program headers, we can't
	// find anything else.
	if (it->main_phoff == 0)
		return NULL;

	drgn_log_debug(prog, "reading program header table from AT_PHDR");

	err = userspace_loaded_module_iterator_read_phdrs(it,
							  prog->auxv.at_phdr,
							  prog->auxv.at_phnum);
	if (err == &drgn_not_found)
		return NULL;
	else if (err)
		return err;

	// Silence -Wmaybe-uninitialized false positives on dyn_vaddr and
	// dyn_memsz last seen with GCC 9.
	uint64_t phdr_vaddr, dyn_vaddr = 0, dyn_memsz = 0;
	bool have_phdr_vaddr = false, have_dyn = false;
	for (uint16_t i = 0; i < prog->auxv.at_phnum; i++) {
		GElf_Phdr phdr;
		userspace_loaded_module_iterator_phdr(it, i, &phdr);
		if (phdr.p_type == PT_LOAD && phdr.p_offset <= it->main_phoff
		    && it->main_phoff < phdr.p_offset + phdr.p_filesz) {
			drgn_log_debug(prog,
				       "found PT_LOAD containing program headers with p_vaddr 0x%" PRIx64
				       " and p_offset 0x%" PRIx64,
				       phdr.p_vaddr, phdr.p_offset);
			phdr_vaddr = it->main_phoff - phdr.p_offset + phdr.p_vaddr;
			have_phdr_vaddr = true;
		} else if (phdr.p_type == PT_DYNAMIC) {
			drgn_log_debug(prog,
				       "found PT_DYNAMIC with p_vaddr 0x%" PRIx64
				       " and p_memsz 0x%" PRIx64,
				       phdr.p_vaddr, phdr.p_memsz);
			have_dyn = true;
			dyn_vaddr = phdr.p_vaddr;
			dyn_memsz = phdr.p_memsz;
		}
	}
	if (have_phdr_vaddr) {
		it->main_bias = prog->auxv.at_phdr - phdr_vaddr;
		drgn_log_debug(prog, "main bias is 0x%" PRIx64, it->main_bias);
	} else {
		drgn_log_debug(prog,
			       "didn't find PT_LOAD containing program headers");
		return NULL;
	}
	if (have_dyn) {
		it->have_main_dyn = true;
		it->main_dyn_vaddr = dyn_vaddr + it->main_bias;
		it->main_dyn_memsz = dyn_memsz;
		drgn_log_debug(prog, "main dynamic section is at 0x%" PRIx64,
			       it->main_dyn_vaddr);
	} else {
		drgn_log_debug(prog,
			       "didn't find PT_DYNAMIC program header; probably statically linked");
	}
	it->read_main_phdrs = true;
	return NULL;
}

static struct drgn_error *
identify_module_from_phdrs(struct userspace_loaded_module_iterator *it,
			   struct drgn_module *module, size_t phnum,
			   uint64_t bias)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	uint64_t start = UINT64_MAX, end = 0;
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr;
		userspace_loaded_module_iterator_phdr(it, i, &phdr);
		if (phdr.p_type == PT_LOAD) {
			// Like elf_address_range_from_min_and_max_phdr().
			start = min(start, phdr.p_vaddr + bias);
			end = max(end, phdr.p_vaddr + phdr.p_memsz + bias);
		} else if (phdr.p_type == PT_NOTE
			   && module->build_id_len == 0) {
			uint64_t note_size = min(phdr.p_filesz, phdr.p_memsz);
			if (!note_size)
				continue;
			if (note_size > MAX_MEMORY_READ_FOR_DEBUG_INFO) {
				drgn_log_debug(prog,
					       "note is unreasonably large (%" PRIu64 " bytes); ignoring",
					       note_size);
				continue;
			}
			if (!alloc_or_reuse(&it->segment_buf,
					    &it->segment_buf_capacity,
					    note_size))
				return &drgn_enomem;
			err = drgn_program_read_memory(prog, it->segment_buf,
						       phdr.p_vaddr + bias,
						       note_size, false);
			if (err && err->code == DRGN_ERROR_FAULT) {
				drgn_log_debug(prog,
					       "couldn't read note at 0x%" PRIx64 ": %s"
					       "; ignoring",
					       err->address, err->message);
				drgn_error_destroy(err);
				continue;
			} else if (err) {
				return err;
			}
			const void *build_id;
			size_t build_id_len =
				parse_gnu_build_id_from_notes(it->segment_buf,
							      note_size,
							      phdr.p_align == 8 ?
							      8 : 4,
							      drgn_platform_bswap(&prog->platform),
							      &build_id);
			if (build_id_len > 0) {
				err = drgn_module_set_build_id(module, build_id,
							       build_id_len);
				if (err)
					return err;
				drgn_log_debug(prog,
					       "found build ID %s in note at 0x%" PRIx64,
					       module->build_id_str,
					       phdr.p_vaddr + bias
					       + ((char *)build_id
						  - (char *)it->segment_buf));
			}
		}
	}
	if (module->build_id_len == 0) {
		drgn_log_debug(prog,
			       "couldn't find build ID from mapped program headers");
	}
	if (start < end) {
		err = drgn_module_set_address_range(module, start, end);
		if (err)
			return err;
		drgn_log_debug(prog,
			       "got address range 0x%" PRIx64 "-0x%" PRIx64 " from mapped program headers",
			       start, end);
	} else {
		drgn_log_debug(prog,
			       "couldn't find address range from mapped program headers");
	}
	return NULL;
}

static struct drgn_error *
userspace_loaded_module_iterator_yield_main(struct userspace_loaded_module_iterator *it,
					    struct drgn_module **ret,
					    bool *new_ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	struct drgn_mapped_file_segment *segment =
		find_mapped_file_segment(it, prog->auxv.at_phdr);
	if (segment) {
		// We don't need to read the file header to get e_phoff. Instead,
		// determine it from the file mapping.
		it->main_phoff =
			segment->file_offset + (prog->auxv.at_phdr - segment->start);
		drgn_log_debug(prog,
			       "AT_PHDR is mapped from file %s at offset 0x%" PRIx64,
			       segment->file->path, it->main_phoff);
	} else {
		drgn_log_debug(prog,
			       "couldn't find mapped file segment containing AT_PHDR");
	}

	_cleanup_(drgn_module_deletep) struct drgn_module *module = NULL;
	bool new;
	err = drgn_module_find_or_create_main(prog,
					      segment ? segment->file->path : "",
					      &module, &new);
	if (err)
		return err;
	if (!new) {
		*ret = no_cleanup_ptr(module);
		if (new_ret)
			*new_ret = new;
		return NULL;
	}
	err = userspace_loaded_module_iterator_read_main_phdrs(it);
	if (err)
		return err;
	if (it->read_main_phdrs) {
		err = identify_module_from_phdrs(it, module,
						 prog->auxv.at_phnum,
						 it->main_bias);
		if (err)
			return err;
	}
	*ret = no_cleanup_ptr(module);
	if (new_ret)
		*new_ret = new;
	return NULL;
}

static struct drgn_error *
userspace_loaded_module_iterator_yield_vdso(struct userspace_loaded_module_iterator *it,
					    struct drgn_module **ret,
					    bool *new_ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	if (!prog->auxv.at_sysinfo_ehdr) {
		drgn_log_debug(prog, "no vDSO");
no_vdso:
		*ret = NULL;
		return NULL;
	}

	drgn_log_debug(prog, "reading vDSO ELF header from AT_SYSINFO_EHDR");
	GElf_Ehdr ehdr;
	err = userspace_loaded_module_iterator_read_ehdr(it,
							 prog->auxv.at_sysinfo_ehdr,
							 &ehdr);
	if (err == &drgn_not_found)
		goto no_vdso;
	else if (err)
		return err;

	drgn_log_debug(prog,
		       "reading %" PRIu16 " program headers at 0x%" PRIx64,
		       ehdr.e_phnum, prog->auxv.at_sysinfo_ehdr + ehdr.e_phoff);

	// It is effectively part of the ABI that the vDSO program headers are
	// mapped at AT_SYSINFO_EHDR + e_phoff (see the Linux kernel's reference
	// vDSO parser: vdso_init_from_sysinfo_ehdr() in
	// tools/testing/selftests/vDSO/parse_vdso.c, glibc: setup_vdso() in
	// elf/setup-vdso.h, and musl: __vdsosym() in src/internal/vdso.c).
	err = userspace_loaded_module_iterator_read_phdrs(it,
							  prog->auxv.at_sysinfo_ehdr + ehdr.e_phoff,
							  ehdr.e_phnum);
	if (err == &drgn_not_found)
		goto no_vdso;
	else if (err)
		return err;

	// This is based on the Linux kernel's reference vDSO parser.
	uint64_t bias = prog->auxv.at_sysinfo_ehdr;
	// Silence -Wmaybe-uninitialized false positives on dyn_vaddr and
	// dyn_memsz last seen with GCC 12.
	uint64_t dyn_vaddr = 0, dyn_memsz = 0;
	bool have_load = false, have_dyn = false;
	for (size_t i = 0; i < ehdr.e_phnum; i++) {
		GElf_Phdr phdr;
		userspace_loaded_module_iterator_phdr(it, i, &phdr);
		if (phdr.p_type == PT_LOAD && !have_load) {
			drgn_log_debug(prog,
				       "found PT_LOAD with p_offset 0x%" PRIx64
				       " and p_vaddr 0x%" PRIx64,
				       phdr.p_offset, phdr.p_vaddr);
			have_load = true;
			bias = prog->auxv.at_sysinfo_ehdr + phdr.p_offset - phdr.p_vaddr;
		} else if (phdr.p_type == PT_DYNAMIC) {
			drgn_log_debug(prog,
				       "found PT_DYNAMIC with p_offset 0x%" PRIx64
				       " and p_memsz 0x%" PRIx64,
				       phdr.p_offset, phdr.p_memsz);
			dyn_vaddr = prog->auxv.at_sysinfo_ehdr + phdr.p_offset;
			dyn_memsz = phdr.p_memsz;
			have_dyn = true;
		}
	}
	if (!have_load) {
		drgn_log_warning(prog,
				 "can't find vDSO: "
				 "no PT_LOAD header in vDSO program headers");
		goto no_vdso;
	}
	drgn_log_debug(prog, "vDSO bias is 0x%" PRIx64, bias);
	if (!have_dyn) {
		drgn_log_warning(prog,
				 "can't find vDSO: "
				 "no PT_DYNAMIC header in vDSO program headers");
		goto no_vdso;
	}
	it->vdso_dyn_vaddr = dyn_vaddr;
	it->have_vdso_dyn = true;

	drgn_log_debug(prog, "reading vDSO dynamic section at 0x%" PRIx64,
		       dyn_vaddr);
	size_t num_dyn;
	err = userspace_loaded_module_iterator_read_dynamic(it, dyn_vaddr,
							    dyn_memsz,
							    &num_dyn);
	if (err == &drgn_not_found)
		goto no_vdso;
	else if (err)
		return err;

	// Silence -Wmaybe-uninitialized false positives on dt_strtab and
	// dt_soname last seen with GCC 12.
	uint64_t dt_strtab = 0, dt_soname = 0;
	bool have_dt_strtab = false, have_dt_soname = false;
	for (size_t i = 0; i < num_dyn; i++) {
		GElf_Dyn dyn;
		userspace_loaded_module_iterator_dyn(it, i, &dyn);
		if (dyn.d_tag == DT_STRTAB) {
			dt_strtab = dyn.d_un.d_ptr;
			have_dt_strtab = true;
			drgn_log_debug(prog, "found DT_STRTAB 0x%" PRIx64,
				       dt_strtab);
		} else if (dyn.d_tag == DT_SONAME) {
			dt_soname = dyn.d_un.d_val;
			have_dt_soname = true;
			drgn_log_debug(prog, "found DT_SONAME 0x%" PRIx64,
				       dt_soname);
		} else if (dyn.d_tag == DT_NULL) {
			break;
		}
	}
	if (!have_dt_strtab || !have_dt_soname) {
		drgn_log_warning(prog,
				 "can't find vDSO: "
				 "no %s%s%s entr%s in vDSO dynamic section",
				 have_dt_strtab ? "" : "DT_STRTAB",
				 have_dt_strtab || have_dt_soname ? "" : " or ",
				 have_dt_soname ? "" : "DT_SONAME",
				 have_dt_strtab || have_dt_soname ? "y" : "ies");
		goto no_vdso;
	}

	_cleanup_free_ char *name = NULL;
	err = drgn_program_read_c_string(prog, dt_strtab + bias + dt_soname,
					 false, SIZE_MAX, &name);
	if (err && err->code == DRGN_ERROR_FAULT) {
		drgn_log_warning(prog,
				 "can't find vDSO: "
				 "couldn't read soname at 0x%" PRIx64 ": %s",
				 err->address, err->message);
		drgn_error_destroy(err);
		goto no_vdso;
	} else if (err) {
		return err;
	}
	drgn_log_debug(prog, "read vDSO soname \"%s\"", name);

	_cleanup_(drgn_module_deletep) struct drgn_module *module = NULL;
	bool new;
	err = drgn_module_find_or_create_vdso(prog, name, dyn_vaddr, &module,
					      &new);
	if (err)
		return err;
	if (!new) {
		*ret = no_cleanup_ptr(module);
		if (new_ret)
			*new_ret = new;
		return NULL;
	}

	err = identify_module_from_phdrs(it, module, ehdr.e_phnum, bias);
	if (err)
		return err;
	*ret = no_cleanup_ptr(module);
	if (new_ret)
		*new_ret = new;
	return NULL;
}

#define read_struct64(prog, struct64p, address, type32, visit_members)		\
	read_struct64_impl(prog, struct64p, address, type32, visit_members,	\
			   PP_UNIQUE(prog), PP_UNIQUE(struct64p),		\
			   PP_UNIQUE(is_64_bit), PP_UNIQUE(err))
#define read_struct64_impl(prog, struct64p, address, type32, visit_members,	\
			   unique_prog, unique_struct64, unique_is_64_bit,	\
			   unique_err) ({					\
	struct drgn_program *unique_prog = (prog);				\
	__auto_type unique_struct64p = (struct64p);				\
	static_assert(sizeof(*unique_struct64p) >= sizeof(type32),		\
		      "64-bit type is smaller than 32-bit type");		\
	const bool unique_is_64_bit =						\
		drgn_platform_is_64_bit(&unique_prog->platform);		\
	struct drgn_error *unique_err =						\
		drgn_program_read_memory(unique_prog, unique_struct64p,		\
					 (address),				\
					 unique_is_64_bit			\
					 ? sizeof(*unique_struct64p)		\
					 : sizeof(type32), false);		\
	if (!unique_err) {							\
		deserialize_struct64_inplace(unique_struct64p, type32,		\
					     visit_members, unique_is_64_bit,	\
					     drgn_platform_bswap(&unique_prog->platform));\
	}									\
	unique_err;								\
})

static struct drgn_error *
userspace_get_link_map(struct userspace_loaded_module_iterator *it)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	if (!it->read_main_phdrs) {
		err = userspace_loaded_module_iterator_read_main_phdrs(it);
		if (err)
			return err;
	}
	if (!it->have_main_dyn)
		return NULL;

	drgn_log_debug(prog, "reading main dynamic section");
	size_t num_dyn;
	err = userspace_loaded_module_iterator_read_dynamic(it,
							    it->main_dyn_vaddr,
							    it->main_dyn_memsz,
							    &num_dyn);
	if (err == &drgn_not_found) {
		drgn_log_warning(prog,
				 "can't find shared libraries: "
				 "couldn't read main dynamic section");
		return NULL;
	} else if (err) {
		return err;
	}

	GElf_Dyn dyn;
	size_t i;
	for (i = 0; i < num_dyn; i++) {
		userspace_loaded_module_iterator_dyn(it, i, &dyn);
		if (dyn.d_tag == DT_NULL) {
			i = num_dyn;
			break;
		}
		if (dyn.d_tag == DT_DEBUG) {
			drgn_log_debug(prog, "found DT_DEBUG 0x%" PRIx64,
				       dyn.d_un.d_ptr);
			break;
		}
	}
	if (i >= num_dyn) {
		drgn_log_warning(prog,
				 "can't find shared libraries: "
				 "no DT_DEBUG entry in main dynamic section");
		return NULL;
	}

	struct drgn_r_debug {
		int32_t r_version;
		alignas(8) uint64_t r_map;
	} r_debug;
	struct drgn_r_debug32 {
		int32_t r_version;
		uint32_t r_map;
	};
#define visit_r_debug_members(visit_scalar_member, visit_raw_member) do {	\
	visit_scalar_member(r_version);						\
	visit_scalar_member(r_map);						\
} while (0)
	err = read_struct64(prog, &r_debug, dyn.d_un.d_ptr,
			    struct drgn_r_debug32, visit_r_debug_members);
#undef visit_r_debug_members
	if (err && err->code == DRGN_ERROR_FAULT) {
		// Note: musl doesn't update DT_DEBUG for static PIE binaries
		// compiled with GCC (as of musl v1.2.3 and GCC 13), so that
		// case is known to fail here.
		drgn_log_warning(prog,
				 "can't find shared libraries: "
				 "couldn't read r_debug at 0x%" PRIx64 ": %s",
				 err->address, err->message);
		drgn_error_destroy(err);
		return NULL;
	} else if (err) {
		return err;
	}
	drgn_log_debug(prog,
		       "read r_debug = { .r_version = %" PRId32 ", .r_map = 0x%" PRIx64 " }",
		       r_debug.r_version, r_debug.r_map);

	if (r_debug.r_version < 1) {
		drgn_log_warning(prog,
				 "can't find shared libraries: "
				 "invalid r_debug.r_version %" PRId32,
				 r_debug.r_version);
		return NULL;
	}
	it->link_map = r_debug.r_map;
	return NULL;
}

static struct drgn_error *
identify_module_from_link_map(struct userspace_loaded_module_iterator *it,
			      struct drgn_module *module,
			      struct drgn_mapped_file *file, uint64_t l_addr)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	// Even if it is a 32-bit file, segments should be at least a page, so
	// we should be able to read the 64-bit size.
	if (file->offset0_size < sizeof(Elf64_Ehdr)) {
		drgn_log_debug(prog, "didn't find mapped ELF header");
		return NULL;
	}

	drgn_log_debug(prog, "reading ELF header at 0x%" PRIx64,
		       file->offset0_vaddr);
	GElf_Ehdr ehdr;
	err = userspace_loaded_module_iterator_read_ehdr(it,
							 file->offset0_vaddr,
							 &ehdr);
	if (err == &drgn_not_found)
		return NULL;
	else if (err)
		return err;

	drgn_log_debug(prog,
		       "reading %" PRIu16 " program headers from 0x%" PRIx64,
		       ehdr.e_phnum, file->offset0_vaddr + ehdr.e_phoff);
	// e_phnum and e_phentsize are uint16_t, so this can't overflow.
	uint32_t phdrs_size =
		(uint32_t)ehdr.e_phnum * (uint32_t)ehdr.e_phentsize;
	if (ehdr.e_phoff > file->offset0_size ||
	    phdrs_size > file->offset0_size - ehdr.e_phoff) {
		drgn_log_debug(prog,
			       "program header table is not mapped with ELF header");
		return NULL;
	}
	err = userspace_loaded_module_iterator_read_phdrs(it,
							  file->offset0_vaddr + ehdr.e_phoff,
							  ehdr.e_phnum);
	if (err == &drgn_not_found)
		return NULL;
	else if (err)
		return err;

	return identify_module_from_phdrs(it, module, ehdr.e_phnum, l_addr);
}

// This is the public definition of struct link_map from glibc's link.h:
//
// struct link_map
//   {
//     /* These first few members are part of the protocol with the debugger.
//        This is the same format used in SVR4.  */
//
//     ElfW(Addr) l_addr;          /* Difference between the address in the ELF
//                                    file and the addresses in memory.  */
//     char *l_name;               /* Absolute file name object was found in.  */
//     ElfW(Dyn) *l_ld;            /* Dynamic section of the shared object.  */
//     struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
//   };
//
// We don't need l_prev, so we exclude it from our definition.
struct drgn_link_map {
	uint64_t l_addr;
	uint64_t l_name;
	uint64_t l_ld;
	uint64_t l_next;
};
struct drgn_link_map32 {
	uint32_t l_addr;
	uint32_t l_name;
	uint32_t l_ld;
	uint32_t l_next;
};

static struct drgn_error *
userspace_next_link_map(struct userspace_loaded_module_iterator *it,
			struct drgn_link_map *ret, char **name_ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	if (!it->link_map) {
		drgn_log_debug(prog, "found end of link_map list");
		return &drgn_stop;
	}

	if (it->state
	    >= USERSPACE_LOADED_MODULE_ITERATOR_STATE_LINK_MAP
	    + MAX_LINK_MAP_LIST_ITERATIONS) {
		drgn_log_warning(prog,
				 "can't find remaining shared libraries: "
				 "too many entries or cycle in link_map list");
		return &drgn_stop;
	}
	it->state++;

#define visit_link_map_members(visit_scalar_member, visit_raw_member) do {	\
	visit_scalar_member(l_addr);						\
	visit_scalar_member(l_name);						\
	visit_scalar_member(l_ld);						\
	visit_scalar_member(l_next);						\
} while (0)
	err = read_struct64(prog, ret, it->link_map, struct drgn_link_map32,
			    visit_link_map_members);
#undef visit_link_map_members
	if (err && err->code == DRGN_ERROR_FAULT) {
		drgn_log_warning(prog,
				 "can't find remaining shared libraries: "
				 "couldn't read next link_map at 0x%" PRIx64 ": %s",
				 err->address, err->message);
		drgn_error_destroy(err);
		return &drgn_stop;
	} else if (err) {
		return err;
	}

	it->link_map = ret->l_next;

	err = drgn_program_read_c_string(prog, ret->l_name, false, SIZE_MAX,
					 name_ret);
	if (err && err->code == DRGN_ERROR_FAULT)
		*name_ret = NULL;
	else if (err)
		return err;
	drgn_log_debug(prog,
		       "read link_map = { .l_addr = 0x%" PRIx64 ", .l_name = 0x%" PRIx64 "%s%s%s, .l_ld = 0x%" PRIx64 ", .l_next = 0x%" PRIx64 " }",
		       ret->l_addr, ret->l_name, *name_ret ? " = \"" : "",
		       *name_ret ? *name_ret : "", *name_ret ? "\"" : "",
		       ret->l_ld, ret->l_next);
	if (err) {
		drgn_log_debug(prog,
			       "couldn't read l_name at 0x%" PRIx64 ": %s"
			       "; skipping",
			       err->address, err->message);
		drgn_error_destroy(err);
	}
	return NULL;
}

static struct drgn_error *
yield_from_link_map(struct userspace_loaded_module_iterator *it,
		    struct drgn_module **ret, bool *new_ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	for (;;) {
		struct drgn_link_map link_map;
		_cleanup_free_ char *name = NULL;
		err = userspace_next_link_map(it, &link_map, &name);
		if (err == &drgn_stop) {
			*ret = NULL;
			return NULL;
		} else if (err) {
			return err;
		}

		if (link_map.l_ld == it->main_dyn_vaddr) {
			drgn_log_debug(prog,
				       "l_ld matches main dynamic section; skipping");
			continue;
		}
		if (it->have_vdso_dyn && link_map.l_ld == it->vdso_dyn_vaddr) {
			drgn_log_debug(prog,
				       "l_ld matches vDSO dynamic section; skipping");
			continue;
		}
		if (!name)
			continue;

		_cleanup_(drgn_module_deletep) struct drgn_module *module = NULL;
		bool new;
		err = drgn_module_find_or_create_shared_library(prog, name,
								link_map.l_ld,
								&module, &new);
		if (err)
			return err;
		if (!new) {
			*ret = no_cleanup_ptr(module);
			if (new_ret)
				*new_ret = new;
			return NULL;
		}

		struct drgn_mapped_file_segment *segment =
			find_mapped_file_segment(it, link_map.l_ld);
		if (segment) {
			err = identify_module_from_link_map(it, module,
							    segment->file,
							    link_map.l_addr);
			if (err)
				return err;
		} else {
			drgn_log_debug(prog,
				       "couldn't find mapped file segment containing l_ld");
		}
		*ret = no_cleanup_ptr(module);
		if (new_ret)
			*new_ret = new;
		return NULL;
	}
}

static struct drgn_error *
userspace_loaded_module_iterator_next(struct drgn_module_iterator *_it,
				      struct drgn_module **ret,
				      bool *new_ret)
{
	struct drgn_error *err;
	struct userspace_loaded_module_iterator *it =
		container_of(_it, struct userspace_loaded_module_iterator, it);
	switch (it->state) {
	case USERSPACE_LOADED_MODULE_ITERATOR_STATE_MAIN:
		err = drgn_program_cache_auxv(it->it.prog);
		if (err)
			return err;
		it->state = USERSPACE_LOADED_MODULE_ITERATOR_STATE_VDSO;
		return userspace_loaded_module_iterator_yield_main(it, ret,
								   new_ret);
	case USERSPACE_LOADED_MODULE_ITERATOR_STATE_VDSO:
		it->state = USERSPACE_LOADED_MODULE_ITERATOR_STATE_R_DEBUG;
		err = userspace_loaded_module_iterator_yield_vdso(it, ret,
								  new_ret);
		if (err || *ret)
			return err;
		fallthrough;
	case USERSPACE_LOADED_MODULE_ITERATOR_STATE_R_DEBUG:
		it->state = USERSPACE_LOADED_MODULE_ITERATOR_STATE_LINK_MAP;
		err = userspace_get_link_map(it);
		if (err)
			return err;
		fallthrough;
	default:
		return yield_from_link_map(it, ret, new_ret);
	}
}

struct process_mapped_file_entry {
	dev_t dev;
	ino_t ino;
	struct drgn_mapped_file *file;
};

struct process_mapped_file_key {
	dev_t dev;
	ino_t ino;
	const char *path;
};

static struct process_mapped_file_key
process_mapped_file_entry_to_key(const struct process_mapped_file_entry *entry)
{
	return (struct process_mapped_file_key){
		.dev = entry->dev,
		.ino = entry->ino,
		.path = entry->file->path,
	};
}

static struct hash_pair
process_mapped_file_key_hash_pair(const struct process_mapped_file_key *key)
{
	size_t hash = hash_combine(key->dev, key->ino);
	hash = hash_combine(hash, hash_c_string(key->path));
	return hash_pair_from_avalanching_hash(hash);
}

static bool process_mapped_file_key_eq(const struct process_mapped_file_key *a,
				       const struct process_mapped_file_key *b)
{
	return (a->dev == b->dev
		&& a->ino == b->ino
		&& strcmp(a->path, b->path) == 0);
}

DEFINE_HASH_TABLE(process_mapped_files, struct process_mapped_file_entry,
		  process_mapped_file_entry_to_key,
		  process_mapped_file_key_hash_pair,
		  process_mapped_file_key_eq);

struct process_loaded_module_iterator {
	struct userspace_loaded_module_iterator u;
	struct process_mapped_files files;
};

static struct drgn_error *
process_add_mapping(struct process_loaded_module_iterator *it,
		    const char *maps_path, const char *map_files_path,
		    int map_files_fd, bool *logged_readlink_eperm,
		    bool *logged_stat_eperm,
		    struct drgn_map_files_segment_vector *map_files_segments,
		    struct drgn_mapped_file_segments *segments,
		    char *line, size_t line_len)
{
	struct drgn_program *prog = it->u.it.prog;

	struct drgn_map_files_segment segment;
	uint64_t segment_file_offset;
	unsigned int dev_major, dev_minor;
	uint64_t ino;
	int map_name_len, path_index;
	if (sscanf(line,
		   "%" SCNx64 "-%" SCNx64 "%n %*s %" SCNx64 " %x:%x %" SCNu64 " %n",
		   &segment.start, &segment.end, &map_name_len,
		   &segment_file_offset, &dev_major, &dev_minor, &ino,
		   &path_index) != 6) {
		return drgn_error_format(DRGN_ERROR_OTHER, "couldn't parse %s",
					 maps_path);
	}
	// Skip anonymous mappings.
	if (ino == 0)
		return NULL;

	if (!drgn_map_files_segment_vector_append(map_files_segments, &segment))
		return &drgn_enomem;

	struct process_mapped_file_key key = {
		.dev = makedev(dev_major, dev_minor),
		.ino = ino,
		.path = line + path_index,
	};
	_cleanup_free_ char *real_path = NULL;

	// /proc/$pid/maps has a couple of ambiguities that
	// /proc/$pid/map_files/<address> can help with:
	//
	// 1. Newlines in the file path from /proc/$pid/maps are escaped as
	//    \012. However, \ is not escaped, so it is ambiguous whether \012
	//    is a newline or appeared literally in the path. We can read the
	//    map_files link to get the unescaped path.
	// 2. The device number in /proc/$pid/maps is incorrect for some
	//    filesystems. Specifically, for Btrfs as of Linux 6.5, it refers to
	//    a filesystem-wide device number rather than the subvolume-specific
	//    device numbers returned by stat. We can stat the map_files link to
	//    get the correct device number.
	if (map_files_fd >= 0) {
		char map_files_name[34];
		snprintf(map_files_name, sizeof(map_files_name),
			 "%" PRIx64 "-%" PRIx64, segment.start, segment.end);

		// The escaped path must be at least as long as the original
		// path, so use that as the readlink buffer size.
		size_t bufsiz = line_len - path_index + 1;
		real_path = malloc(bufsiz);
		if (!real_path)
			return &drgn_enomem;
		// Before Linux kernel commit bdb4d100afe9 ("procfs: always
		// expose /proc/<pid>/map_files/ and make it readable") (in
		// v4.3), reading these links required CAP_SYS_ADMIN. Since that
		// commit, it only requires PTRACE_MODE_READ, which we must have
		// since we opened /proc/$pid/maps.
		//
		// If we can't read this link, we have to fall back to the
		// escaped path. Newlines and the literal sequence \012 are
		// unlikely to appear in a path, so it's not a big deal.
		ssize_t r = readlinkat(map_files_fd, map_files_name, real_path,
				       bufsiz);
		if (r < 0) {
			if (errno == EPERM) {
				free(real_path);
				real_path = NULL;
				if (!*logged_readlink_eperm) {
					drgn_log_debug(prog,
						       "don't have permission to read symlinks in %s",
						       map_files_path);
				}
				*logged_readlink_eperm = true;
			} else if (errno == ENOENT) {
				// We raced with a change to the mapping.
				drgn_log_debug(prog, "mapping %s disappeared",
					       map_files_name);
				return NULL;
			} else {
				return drgn_error_format_os("readlink", errno,
							    "%s/%s",
							    map_files_path,
							    map_files_name);
			}
		} else if (r >= bufsiz) {
			// We didn't allocate enough for the link contents. The
			// only way this is possible is if we raced with the
			// mapping being replaced by a different path.
			drgn_log_debug(prog,
				       "mapping %s path changed; skipping",
				       map_files_name);
			return NULL;
		} else {
			real_path[r] = '\0';
			key.path = real_path;
		}

		// Following these links requires CAP_SYS_ADMIN. If we can't, we
		// have to fall back to using the device number from
		// /proc/$pid/maps. Mapping files with the same path and inode
		// number in different Btrfs subvolumes is unlikely, so this is
		// also not a big deal.
		struct stat st;
		if (fstatat(map_files_fd, map_files_name, &st, 0) < 0) {
			if (errno == EPERM) {
				if (!*logged_stat_eperm) {
					drgn_log_debug(prog,
						       "don't have permission to follow symlinks in %s",
						       map_files_path);
				}
				*logged_stat_eperm = true;
			} else if (errno == ENOENT) {
				// We raced with a change to the mapping.
				drgn_log_debug(prog, "mapping %s disappeared",
					       map_files_name);
				return NULL;
			} else {
				return drgn_error_format_os("stat", errno,
							    "%s/%s",
							    map_files_path,
							    map_files_name);
			}
		} else {
			key.dev = st.st_dev;
		}
	}

	struct hash_pair hp = process_mapped_files_hash(&key);
	struct process_mapped_files_iterator files_it =
		process_mapped_files_search_hashed(&it->files, &key, hp);
	if (!files_it.entry) {
		if (!real_path) {
			real_path = strdup(key.path);
			if (!real_path)
				return &drgn_enomem;
		}
		struct drgn_mapped_file *file =
			drgn_mapped_file_create(real_path);
		if (!file)
			return &drgn_enomem;
		struct process_mapped_file_entry entry = {
			.dev = key.dev,
			.ino = key.ino,
			.file = file,
		};
		if (process_mapped_files_insert_searched(&it->files, &entry, hp,
							 &files_it) < 0) {
			drgn_mapped_file_destroy(file);
			return &drgn_enomem;
		}
		// real_path is owned by the iterator now.
		real_path = NULL;
	}
	return drgn_add_mapped_file_segment(segments, segment.start, segment.end,
					    segment_file_offset,
					    files_it.entry->file);
}

static struct drgn_error *
process_get_mapped_files(struct process_loaded_module_iterator *it)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->u.it.prog;

#define FORMAT "/proc/%ld/maps"
	char maps_path[sizeof(FORMAT)
		       - sizeof("%ld")
		       + max_decimal_length(long)
		       + 1];
	snprintf(maps_path, sizeof(maps_path), FORMAT, (long)prog->pid);
#undef FORMAT
	_cleanup_fclose_ FILE *maps_file = fopen(maps_path, "r");
	if (!maps_file)
		return drgn_error_create_os("fopen", errno, maps_path);
	drgn_log_debug(prog, "parsing %s", maps_path);

#define FORMAT "/proc/%ld/map_files"
	char map_files_path[sizeof(FORMAT)
		            - sizeof("%ld")
			    + max_decimal_length(long)
			    + 1];
	snprintf(map_files_path, sizeof(map_files_path), FORMAT,
		 (long)prog->pid);
#undef FORMAT
	// Since Linux kernel commit bdb4d100afe9 ("procfs: always expose
	// /proc/<pid>/map_files/ and make it readable") (in v4.3),
	// /proc/$pid/map_files always exists. Before that, it only exists if
	// CONFIG_CHECKPOINT_RESTORE is enabled.
	//
	// If it exists, we should always have permission to open it since we
	// were able to open /proc/$pid/maps.
	_cleanup_close_ int map_files_fd =
		open(map_files_path, O_RDONLY | O_DIRECTORY);
	if (map_files_fd < 0) {
		if (errno != ENOENT) {
			return drgn_error_create_os("open", errno,
						    map_files_path);
		}
		drgn_log_debug(prog, "%s: %m", map_files_path);
	}

	_cleanup_free_ char *line = NULL;
	size_t n = 0;
	bool logged_readlink_eperm = false, logged_stat_eperm = false;
	// While we're reading /proc/$pid/maps, we might as well cache the
	// segments for drgn_module_try_proc_files_for_shared_library().
	VECTOR(drgn_map_files_segment_vector, map_files_segments);
	struct drgn_mapped_file_segments segments = DRGN_MAPPED_FILE_SEGMENTS_INIT;
	for (;;) {
		errno = 0;
		ssize_t len;
		if ((len = getline(&line, &n, maps_file)) == -1) {
			if (errno) {
				err = drgn_error_create_os("getline", errno,
							   maps_path);
			} else {
				err = NULL;
			}
			break;
		}
		// Remove the newline.
		if (len > 0 && line[len - 1] == '\n')
			line[--len] = '\0';

		drgn_log_debug(prog, "read %s", line);
		err = process_add_mapping(it, maps_path, map_files_path,
					  map_files_fd, &logged_readlink_eperm,
					  &logged_stat_eperm,
					  &map_files_segments, &segments, line,
					  len);
		if (err)
			break;
	}
	if (err) {
		drgn_mapped_file_segments_abort(&segments);
	} else {
		drgn_debug_info_set_map_files_segments(&prog->dbinfo,
						       &map_files_segments,
						       segments.sorted);
		userspace_loaded_module_iterator_set_file_segments(&it->u,
								   &segments);
	}
	return err;
}

static void
process_loaded_module_iterator_destroy(struct drgn_module_iterator *_it)
{
	struct process_loaded_module_iterator *it =
		container_of(_it, struct process_loaded_module_iterator, u.it);
	hash_table_for_each(process_mapped_files, files_it, &it->files) {
		free((char *)files_it.entry->file->path);
		drgn_mapped_file_destroy(files_it.entry->file);
	}
	process_mapped_files_deinit(&it->files);
	userspace_loaded_module_iterator_deinit(&it->u);
	free(it);
}

static struct drgn_error *
process_loaded_module_iterator_create(struct drgn_program *prog,
				      struct drgn_module_iterator **ret)
{
	struct drgn_error *err;
	struct process_loaded_module_iterator *it = calloc(1, sizeof(*it));
	if (!it)
		return &drgn_enomem;
	drgn_module_iterator_init(&it->u.it, prog,
				  process_loaded_module_iterator_destroy,
				  userspace_loaded_module_iterator_next);
	process_mapped_files_init(&it->files);
	err = process_get_mapped_files(it);
	if (err) {
		process_loaded_module_iterator_destroy(&it->u.it);
		return err;
	}
	*ret = &it->u.it;
	return NULL;
}

static const char *
core_mapped_file_entry_to_key(struct drgn_mapped_file * const *entry)
{
	return (*entry)->path;
}

DEFINE_HASH_TABLE(core_mapped_files, struct drgn_mapped_file *,
		  core_mapped_file_entry_to_key, c_string_key_hash_pair,
		  c_string_key_eq);

struct core_loaded_module_iterator {
	struct userspace_loaded_module_iterator u;
	struct core_mapped_files files;
};

static struct drgn_error *parse_nt_file_error(struct binary_buffer *bb,
					      const char *pos,
					      const char *message)
{
	return drgn_error_create(DRGN_ERROR_OTHER, "couldn't parse NT_FILE");
}

static struct drgn_error *
core_get_mapped_files(struct core_loaded_module_iterator *it)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->u.it.prog;

	const void *note;
	size_t note_size;
	if (find_elf_note(prog->core, "CORE", NT_FILE, &note, &note_size))
		return drgn_error_libelf();
	if (!note) {
		drgn_log_debug(prog, "core doesn't have NT_FILE note");
		return NULL;
	}

	drgn_log_debug(prog, "parsing NT_FILE");

	bool is_64_bit = drgn_platform_is_64_bit(&prog->platform);
	bool little_endian = drgn_platform_is_little_endian(&prog->platform);

	struct binary_buffer bb;
	binary_buffer_init(&bb, note, note_size, little_endian,
			   parse_nt_file_error);

	// fs/binfmt_elf.c in the Linux kernel source code documents the format
	// of NT_FILE as:
	//
	// long count     -- how many files are mapped
	// long page_size -- units for file_ofs
	// array of [COUNT] elements of
	//   long start
	//   long end
	//   long file_ofs
	// followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
	struct nt_file_segment64 {
		uint64_t start;
		uint64_t end;
		uint64_t file_offset;
	};
	struct nt_file_segment32 {
		uint32_t start;
		uint32_t end;
		uint32_t file_offset;
	};
	uint64_t count, page_size;
	if (is_64_bit) {
		if ((err = binary_buffer_next_u64(&bb, &count)))
			return err;
		if (count > UINT64_MAX / sizeof(struct nt_file_segment64))
			return binary_buffer_error(&bb, "count is too large");
		if ((err = binary_buffer_next_u64(&bb, &page_size)) ||
		    (err = binary_buffer_skip(&bb,
					      count * sizeof(struct nt_file_segment64))))
			return err;
	} else {
		if ((err = binary_buffer_next_u32_into_u64(&bb, &count)))
			return err;
		if (count > UINT64_MAX / sizeof(struct nt_file_segment32))
			return binary_buffer_error(&bb, "count is too large");
		if ((err = binary_buffer_next_u32_into_u64(&bb, &page_size)) ||
		    (err = binary_buffer_skip(&bb,
					      count * sizeof(struct nt_file_segment32))))
			return err;
	}

	struct drgn_mapped_file_segments segments =
		DRGN_MAPPED_FILE_SEGMENTS_INIT;
	for (uint64_t i = 0; i < count; i++) {
		struct nt_file_segment64 segment;
#define visit_nt_file_segment_members(visit_scalar_member, visit_raw_member) do {	\
	visit_scalar_member(start);							\
	visit_scalar_member(end);							\
	visit_scalar_member(file_offset);						\
} while (0)
		deserialize_struct64(&segment, struct nt_file_segment32,
				     visit_nt_file_segment_members,
				     (char *)note
				     + (is_64_bit
					? 16 + i * sizeof(struct nt_file_segment64)
					: 8 + i * sizeof(struct nt_file_segment32)),
				     is_64_bit, bb.bswap);
#undef visit_nt_file_segment_members
		segment.file_offset *= page_size;
		const char *path = bb.pos;
		if ((err = binary_buffer_skip_string(&bb)))
			goto err;
		drgn_log_debug(prog,
			       "found 0x%" PRIx64 "-0x%" PRIx64 " 0x%" PRIx64 " %s",
			       segment.start, segment.end, segment.file_offset,
			       path);
		if (segment.start >= segment.end)
			continue;

		struct hash_pair hp = core_mapped_files_hash(&path);
		struct core_mapped_files_iterator files_it =
			core_mapped_files_search_hashed(&it->files, &path, hp);
		struct drgn_mapped_file *file;
		if (files_it.entry) {
			file = *files_it.entry;
		} else {
			file = drgn_mapped_file_create(path);
			if (!file) {
				err = &drgn_enomem;
				goto err;
			}
			if (core_mapped_files_insert_searched(&it->files, &file,
							      hp, NULL) < 0) {
				drgn_mapped_file_destroy(file);
				err = &drgn_enomem;
				goto err;
			}
		}
		err = drgn_add_mapped_file_segment(&segments, segment.start,
						   segment.end,
						   segment.file_offset, file);
		if (err)
			goto err;
	}
	userspace_loaded_module_iterator_set_file_segments(&it->u, &segments);
	return NULL;

err:
	drgn_mapped_file_segments_abort(&segments);
	return err;
}

static void
core_loaded_module_iterator_destroy(struct drgn_module_iterator *_it)
{
	struct core_loaded_module_iterator *it =
		container_of(_it, struct core_loaded_module_iterator, u.it);
	hash_table_for_each(core_mapped_files, files_it, &it->files)
		drgn_mapped_file_destroy(*files_it.entry);
	core_mapped_files_deinit(&it->files);
	userspace_loaded_module_iterator_deinit(&it->u);
	free(it);
}

static struct drgn_error *
core_loaded_module_iterator_create(struct drgn_program *prog,
				   struct drgn_module_iterator **ret)
{
	struct drgn_error *err;
	struct core_loaded_module_iterator *it = calloc(1, sizeof(*it));
	if (!it)
		return &drgn_enomem;
	drgn_module_iterator_init(&it->u.it, prog,
				  core_loaded_module_iterator_destroy,
				  userspace_loaded_module_iterator_next);
	core_mapped_files_init(&it->files);
	err = core_get_mapped_files(it);
	if (err) {
		core_loaded_module_iterator_destroy(&it->u.it);
		return err;
	}
	*ret = &it->u.it;
	return NULL;
}

static struct drgn_error *
null_module_iterator_create(struct drgn_program *prog,
			    struct drgn_module_iterator **ret)
{
	struct drgn_module_iterator *it = calloc(1, sizeof(*it));
	if (!it)
		return &drgn_enomem;
	drgn_module_iterator_init(it, prog, NULL, NULL);
	*ret = it;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_loaded_module_iterator_create(struct drgn_program *prog,
				   struct drgn_module_iterator **ret)
{
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return linux_kernel_loaded_module_iterator_create(prog, ret);
	else if (drgn_program_is_userspace_process(prog))
		return process_loaded_module_iterator_create(prog, ret);
	else if (drgn_program_is_userspace_core(prog))
		return core_loaded_module_iterator_create(prog, ret);
	else
		return null_module_iterator_create(prog, ret);
}

static inline void drgn_module_iterator_destroyp(struct drgn_module_iterator **itp)
{
	drgn_module_iterator_destroy(*itp);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_create_loaded_modules(struct drgn_program *prog)
{
	_cleanup_(drgn_module_iterator_destroyp)
		struct drgn_module_iterator *it = NULL;
	struct drgn_error *err = drgn_loaded_module_iterator_create(prog, &it);
	if (err)
		return err;
	struct drgn_module *module;
	while (!(err = drgn_module_iterator_next(it, &module, NULL)) && module);
	return err;
}

struct load_debug_info_file {
	const char *path;
	// We only keep this to keep load_debug_info_provided::build_id alive
	// without needing to copy it. If we add a drgn_module_try_file API that
	// allows providing an Elf handle, we could pass it down.
	Elf *elf;
	// This may be consumed and set to -1.
	int fd;
};

DEFINE_VECTOR(load_debug_info_file_vector, struct load_debug_info_file);

struct load_debug_info_provided {
	const void *build_id;
	size_t build_id_len;
	struct load_debug_info_file_vector files;
	bool matched;
};

static struct nstring
load_debug_info_provided_key(const struct load_debug_info_provided *provided)
{
	return (struct nstring){ provided->build_id, provided->build_id_len };
}

DEFINE_HASH_TABLE(load_debug_info_provided_table,
		  struct load_debug_info_provided,
		  load_debug_info_provided_key, nstring_hash_pair, nstring_eq);

struct load_debug_info_state {
	// Provided files grouped by build ID.
	struct load_debug_info_provided_table provided;
	// Number of entries in the provided table that haven't matched any
	// modules.
	size_t unmatched_provided;
};

static struct drgn_error *
load_debug_info_add_provided_file(struct drgn_program *prog,
				  struct load_debug_info_state *state,
				  const char *path)
{
	_cleanup_close_ int fd = open(path, O_RDONLY);
	if (fd < 0) {
		drgn_log_warning(prog, "%s: %m; ignoring", path);
		return NULL;
	}
	_cleanup_elf_end_ Elf *elf = dwelf_elf_begin(fd);
	if (!elf) {
		drgn_log_warning(prog, "%s: %s; ignoring", path,
				 elf_errmsg(-1));
		return NULL;
	}
	if (elf_kind(elf) != ELF_K_ELF) {
		drgn_log_warning(prog, "%s: not an ELF file; ignoring", path);
		return NULL;
	}
	const void *build_id;
	ssize_t build_id_len = drgn_elf_gnu_build_id(elf, &build_id);
	if (build_id_len <= 0) {
		if (build_id_len < 0) {
			drgn_log_warning(prog, "%s: %s; ignoring", path,
					 elf_errmsg(-1));
		} else {
			drgn_log_warning(prog, "%s: no build ID; ignoring",
					 path);
		}
		return NULL;
	}

	if (drgn_log_is_enabled(prog, DRGN_LOG_DEBUG)) {
		_cleanup_free_ char *build_id_str =
			ahexlify(build_id, build_id_len);
		if (!build_id_str)
			return &drgn_enomem;
		drgn_log_debug(prog, "provided file %s build ID %s",
			       path, build_id_str);
	}

	struct load_debug_info_provided provided = {
		.build_id = build_id,
		.build_id_len = build_id_len,
	};
	struct load_debug_info_provided_table_iterator it;
	int r = load_debug_info_provided_table_insert(&state->provided,
						      &provided, &it);
	if (r < 0)
		return &drgn_enomem;
	if (r > 0) {
		load_debug_info_file_vector_init(&it.entry->files);
		state->unmatched_provided++;
	}

	struct load_debug_info_file file = {
		.path = path,
		.fd = fd,
		.elf = elf,
	};
	if (!load_debug_info_file_vector_append(&it.entry->files, &file)) {
		if (load_debug_info_file_vector_empty(&it.entry->files)) {
			// The key will no longer be valid once we free the Elf
			// handle, so we need to delete the entry.
			load_debug_info_provided_table_delete_iterator(&state->provided,
								       it);
		}
		return &drgn_enomem;
	}
	// fd and elf are owned by state now.
	fd = -1;
	elf = NULL;
	return NULL;
}

static void load_debug_info_state_deinit(struct load_debug_info_state *state)
{
	hash_table_for_each(load_debug_info_provided_table, it,
			    &state->provided) {
		vector_for_each(load_debug_info_file_vector, file,
				&it.entry->files) {
			elf_end(file->elf);
			if (file->fd >= 0)
				close(file->fd);
		}
		load_debug_info_file_vector_deinit(&it.entry->files);
	}
	load_debug_info_provided_table_deinit(&state->provided);
}

static struct load_debug_info_provided *
load_debug_info_find_provided(struct load_debug_info_state *state,
			      const void *build_id, size_t build_id_len)
{
	struct nstring key = { build_id, build_id_len };
	struct load_debug_info_provided *provided =
		load_debug_info_provided_table_search(&state->provided,
						      &key).entry;
	if (provided && !provided->matched) {
		state->unmatched_provided--;
		provided->matched = true;
	}
	return provided;
}

static struct drgn_error *
load_debug_info_try_provided(struct drgn_module *module,
			     struct load_debug_info_provided *provided,
			     enum drgn_module_file_status not_status)
{
	struct drgn_error *err;
	vector_for_each(load_debug_info_file_vector, file, &provided->files) {
		// No need to check build ID again.
		err = drgn_module_try_file_internal(module, file->path,
						    file->fd, false, NULL);
		// drgn_module_try_file_internal took ownership of file->fd. In
		// the unlikely scenario that another module has the same build
		// ID, we'll just have to reopen it by path.
		file->fd = -1;
		if (err)
			return err;

		if (module->loaded_file_status != not_status
		    && module->debug_file_status != not_status)
			break;
	}
	return NULL;
}

static struct drgn_error *
load_debug_info_try_provided_supplementary_files(struct drgn_module *module,
						 struct load_debug_info_state *state)
{
	const void *checksum;
	size_t checksum_len;
	if (drgn_module_wanted_supplementary_debug_file(module, NULL, NULL,
							&checksum,
							&checksum_len)
	    != DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK)
		return NULL;
	struct load_debug_info_provided *provided =
		load_debug_info_find_provided(state, checksum, checksum_len);
	if (!provided)
		return NULL;
	drgn_module_try_supplementary_debug_file_log(module,
						     "trying provided files for");
	return load_debug_info_try_provided(module, provided,
					    DRGN_MODULE_FILE_WANT_SUPPLEMENTARY);
}

static struct drgn_error *
load_debug_info_try_provided_vmlinux(struct drgn_module *module,
				     struct load_debug_info_state *state)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;
	bool logged_trying = false;
	hash_table_for_each(load_debug_info_provided_table, it,
			    &state->provided) {
		vector_for_each(load_debug_info_file_vector, file,
				&it.entry->files) {
			int r = elf_is_vmlinux(file->elf);
			if (r < 0) {
				drgn_log_debug(prog, "%s: %s", file->path,
					       elf_errmsg(-1));
			}
			if (r <= 0)
				continue;

			if (!logged_trying) {
				drgn_module_try_files_log(module,
							  "(Linux version %s): trying provided files for",
							  prog->vmcoreinfo.osrelease);
				logged_trying = true;
			}

			const char *release;
			ssize_t release_len =
				elf_vmlinux_release(file->elf, &release);
			if (release_len < 0) {
				drgn_log_debug(prog, "%s: %s", file->path,
					       elf_errmsg(-1));
				continue;
			} else if (release_len == 0) {
				drgn_log_debug(prog, "%s: %s Linux version not found",
					       module->name, file->path);
				continue;
			}

			if (strlen(prog->vmcoreinfo.osrelease) == release_len
			    && memcmp(release, prog->vmcoreinfo.osrelease,
				      release_len) == 0) {
				drgn_log_debug(prog, "%s: %s Linux version matches",
					       module->name, file->path);
			} else {
				drgn_log_debug(prog,
					       "%s: %s Linux version (%.*s) does not match",
					       module->name, file->path,
					       release_len > INT_MAX
					       ? INT_MAX : (int)release_len,
					       release);
				continue;
			}

			if (!it.entry->matched) {
				state->unmatched_provided--;
				it.entry->matched = true;
			}

			err = drgn_module_try_file_internal(module, file->path,
							    file->fd, true,
							    NULL);
			file->fd = -1;
			if (err)
				return err;
			if (module->loaded_file_status != DRGN_MODULE_FILE_WANT
			    && module->debug_file_status != DRGN_MODULE_FILE_WANT)
				break;
		}
	}
	return NULL;
}

static struct drgn_error *
load_debug_info_try_provided_files(struct drgn_module *module,
				   struct load_debug_info_state *state)
{
	struct drgn_error *err;

	err = load_debug_info_try_provided_supplementary_files(module, state);
	if (err)
		return err;

	const void *build_id;
	size_t build_id_len;
	drgn_module_build_id(module, &build_id, &build_id_len);
	if (build_id_len > 0) {
		// Look up the provided file even if we don't need it so that it
		// counts as matched.
		struct load_debug_info_provided *provided =
			load_debug_info_find_provided(state, build_id,
						      build_id_len);
		if (provided && drgn_module_wants_file(module)) {
			uint64_t orig_supplementary_file_generation =
				module->prog->dbinfo.supplementary_file_generation;
			drgn_module_try_files_log(module,
						  "trying provided files for");
			err = load_debug_info_try_provided(module, provided,
							   DRGN_MODULE_FILE_WANT);
			if (err)
				return err;
			// If the wanted supplementary debug file changed, try
			// finding it again.
			if (drgn_module_wanted_supplementary_debug_file_is_new(module,
						orig_supplementary_file_generation)) {
				err = load_debug_info_try_provided_supplementary_files(module,
										       state);
				if (err)
					return err;
			}
		}
	} else if (module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL
		   && drgn_module_kind(module) == DRGN_MODULE_MAIN) {
		// Before Linux kernel commit 0935288c6e00 ("kdump: append
		// kernel build-id string to VMCOREINFO") (in v5.9) and in a few
		// broken stable versions (see
		// ignore_broken_vmcoreinfo_build_id()), we can't get the
		// vmlinux build ID from a kernel core dump. Fall back to
		// checking every provided file for a vmlinux file with a
		// matching version.
		err = load_debug_info_try_provided_vmlinux(module, state);
		if (err)
			return err;
	}
	return NULL;
}

static void load_debug_info_log_missing(struct drgn_module *module,
					unsigned int max_warnings,
					unsigned int *num_missing)
{
	if (++(*num_missing) > max_warnings)
		return;
	const char *missing_loaded = "";
	if (drgn_module_loaded_file_status(module) == DRGN_MODULE_FILE_WANT) {
		switch (drgn_module_kind(module)) {
		case DRGN_MODULE_MAIN:
			missing_loaded = "executable file";
			break;
		case DRGN_MODULE_SHARED_LIBRARY:
		case DRGN_MODULE_VDSO:
			missing_loaded = "shared object file";
			break;
		default:
			missing_loaded = "loaded file";
			break;
		}
	}
	const char *missing_debug;
	switch (drgn_module_debug_file_status(module)) {
	case DRGN_MODULE_FILE_WANT:
		missing_debug = "debugging symbols";
		break;
	case DRGN_MODULE_FILE_WANT_SUPPLEMENTARY:
		missing_debug = "supplementary debugging symbols";
		break;
	default:
		missing_debug = "";
		break;
	}
	const char *name_extra = "";
	if (module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL
	    && drgn_module_kind(module) == DRGN_MODULE_MAIN)
		name_extra = module->prog->vmcoreinfo.osrelease;
	drgn_log_warning(module->prog, "missing %s%s%s for %s%s%s", missing_loaded,
			 missing_loaded[0] && missing_debug[0] ? " and ": "",
			 missing_debug, module->name, name_extra[0] ? " " : "",
			 name_extra);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_debug_info(struct drgn_program *prog, const char **paths,
			     size_t n, bool load_default, bool load_main)
{
	struct drgn_error *err;

	if (n == 0 && !load_default && !load_main) {
		// We don't have any files to try. Don't create any modules.
		return NULL;
	}

	drgn_blocking_guard();

	const char *env = getenv("DRGN_MAX_DEBUG_INFO_ERRORS");
	unsigned int max_warnings = env ? atoi(env) : 5;
	unsigned int num_missing = 0;

	drgn_log_debug(prog, "loading %sdebugging symbols",
		       load_default ? "default " : load_main ? "main " : "");

	_cleanup_(load_debug_info_state_deinit)
	struct load_debug_info_state state = {
		.provided = HASH_TABLE_INIT,
	};
	for (size_t i = 0; i < n; i++) {
		err = load_debug_info_add_provided_file(prog, &state, paths[i]);
		if (err)
			return err;
	}

	if (load_debug_info_provided_table_empty(&state.provided)
	    && !load_default && !load_main) {
		drgn_log_debug(prog, "no usable provided files");
		return NULL;
	}

	uint64_t old_generation = prog->dbinfo.load_debug_info_generation;

	_cleanup_(drgn_module_iterator_destroyp)
		struct drgn_module_iterator *it = NULL;
	err = drgn_loaded_module_iterator_create(prog, &it);
	if (err)
		return err;
	it->for_load_debug_info = true;
	VECTOR(drgn_module_vector, modules);
	struct drgn_module *module;
	while (!(err = drgn_module_iterator_next(it, &module, NULL)) && module) {
		// Reset DONT_WANT to WANT.
		if (module->loaded_file_status == DRGN_MODULE_FILE_DONT_WANT)
			module->loaded_file_status = DRGN_MODULE_FILE_WANT;
		if (module->debug_file_status == DRGN_MODULE_FILE_DONT_WANT)
			module->debug_file_status = DRGN_MODULE_FILE_WANT;

		err = load_debug_info_try_provided_files(module, &state);
		if (err)
			return err;

		if (drgn_module_wants_file(module)
		    && (load_default
			|| (load_main
			    && drgn_module_kind(module) == DRGN_MODULE_MAIN))
		    && !drgn_module_vector_append(&modules, &module))
			return &drgn_enomem;
	}
	if (err)
		return err;

	struct drgn_module **wanted_modules =
		drgn_module_vector_begin(&modules);
	size_t num_wanted_modules = drgn_module_vector_size(&modules);

	// The module iterator may have tried to load debug info, so we need to
	// check each module again.
	if (num_wanted_modules > 0) {
		uint64_t new_generation =
			++prog->dbinfo.load_debug_info_generation;
		size_t new_num_wanted_modules = 0;
		for (size_t i = 0; i < num_wanted_modules; i++) {
			module = wanted_modules[i];
			if (module->load_debug_info_generation <= old_generation) {
				// Reset DONT_WANT to WANT.
				if (module->loaded_file_status == DRGN_MODULE_FILE_DONT_WANT)
					module->loaded_file_status = DRGN_MODULE_FILE_WANT;
				if (module->debug_file_status == DRGN_MODULE_FILE_DONT_WANT)
					module->debug_file_status = DRGN_MODULE_FILE_WANT;
				if (drgn_module_wants_file(module)) {
					wanted_modules[new_num_wanted_modules++] = module;
					module->load_debug_info_generation = new_generation;
				}
			} else if (drgn_module_wants_file(module)) {
				load_debug_info_log_missing(module,
							    max_warnings,
							    &num_missing);
			}
		}
		num_wanted_modules = new_num_wanted_modules;
	}

	if (num_wanted_modules > 0) {
		uint64_t orig_supplementary_file_generation =
			prog->dbinfo.supplementary_file_generation;
		drgn_handler_list_for_each_enabled(struct drgn_debug_info_finder,
						   finder,
						   &prog->dbinfo.debug_info_finders) {
			err = finder->ops.find(wanted_modules,
					       num_wanted_modules, finder->arg);
			if (err)
				return err;
			size_t new_num_wanted_modules = 0;
			for (size_t i = 0; i < num_wanted_modules; i++) {
				module = wanted_modules[i];
				// If there are no more finders to try after
				// this and a finder changed the wanted
				// supplementary debug file, try to find a
				// provided file for it one last time.
				if (drgn_handler_is_last_enabled(&finder->handler)
				    && drgn_module_wanted_supplementary_debug_file_is_new(module,
						orig_supplementary_file_generation)) {
					err = load_debug_info_try_provided_supplementary_files(module,
											       &state);
					if (err)
						return err;
				}
				if (drgn_module_wants_file(module)) {
					wanted_modules[new_num_wanted_modules++] =
						module;
				}
			}
			num_wanted_modules = new_num_wanted_modules;
			if (num_wanted_modules == 0)
				break;
		}
	}

	if (state.unmatched_provided != 0) {
		hash_table_for_each(load_debug_info_provided_table, pit,
				    &state.provided) {
			if (!pit.entry->matched) {
				vector_for_each(load_debug_info_file_vector,
						file, &pit.entry->files) {
					drgn_log_warning(prog,
							 "provided file %s did not match any loaded modules; ignoring",
							 file->path);
				}
			}
		}
	}

	for (size_t i = 0; i < num_wanted_modules; i++) {
		load_debug_info_log_missing(wanted_modules[i], max_warnings,
					    &num_missing);
	}
	if (num_missing > max_warnings) {
		drgn_log_warning(prog, "... missing %u more",
				 num_missing - max_warnings);
	}

	// Update the DWARF index eagerly, mostly because that's what we did
	// back when we used libdwfl. We may want to remove this in the future.
	err = drgn_dwarf_info_update_index(&prog->dbinfo);
	if (err)
		return err;

	if (num_missing > 0) {
		return drgn_error_create(DRGN_ERROR_MISSING_DEBUG_INFO,
					"missing some debugging symbols; see https://drgn.readthedocs.io/en/latest/getting_debugging_symbols.html");
	}

	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_load_module_debug_info(struct drgn_module **modules, size_t *num_modulesp)
{
	struct drgn_error *err;

	const size_t orig_num_modules = *num_modulesp;
	if (orig_num_modules == 0)
		return NULL;

	struct drgn_program *prog = modules[0]->prog;
	drgn_log_debug(prog, "loading debugging symbols for %zu modules",
		       orig_num_modules);

	size_t num_wanted_modules = 0;
	for (size_t i = 0; i < orig_num_modules; i++) {
		if (modules[i]->prog != prog) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "modules are from different programs");
		}
		if (drgn_module_wants_file(modules[i])) {
			modules[num_wanted_modules++] = modules[i];
		} else if (modules[i]->loaded_file_status == DRGN_MODULE_FILE_DONT_WANT
			   || modules[i]->loaded_file_status == DRGN_MODULE_FILE_DONT_WANT) {
			drgn_log_debug(prog,
				       "debugging symbols not wanted for %s",
				       modules[i]->name);
		} else {
			drgn_log_debug(prog,
				       "debugging symbols already loaded for %s",
				       modules[i]->name);
		}
	}
	if (num_wanted_modules == 0) {
		*num_modulesp = 0;
		return NULL;
	}

	uint64_t generation = ++prog->dbinfo.load_debug_info_generation;
	for (size_t i = 0; i < num_wanted_modules; i++)
		modules[i]->load_debug_info_generation = generation;

	drgn_blocking_guard();

	const size_t orig_num_wanted_modules = num_wanted_modules;
	drgn_handler_list_for_each_enabled(struct drgn_debug_info_finder,
					   finder,
					   &prog->dbinfo.debug_info_finders) {
		err = finder->ops.find(modules, num_wanted_modules,
				       finder->arg);
		if (err)
			return err;
		size_t new_num_wanted_modules = 0;
		for (size_t i = 0; i < num_wanted_modules; i++) {
			if (drgn_module_wants_file(modules[i]))
				modules[new_num_wanted_modules++] = modules[i];
		}
		num_wanted_modules = new_num_wanted_modules;
		if (num_wanted_modules == 0)
			break;
	}
	drgn_log_debug(prog, "debugging symbols loaded for %zu/%zu modules",
		       orig_num_wanted_modules - num_wanted_modules,
		       orig_num_wanted_modules);
	*num_modulesp = num_wanted_modules;
	return NULL;
}

static struct drgn_error *
elf_symbols_search(const char *name, uint64_t addr,
		   enum drgn_find_symbol_flags flags, void *data,
		   struct drgn_symbol_result_builder *builder)
{
	struct drgn_error *err;
	struct drgn_program *prog = data;

	if (flags & DRGN_FIND_SYMBOL_ADDR) {
		struct drgn_module *module =
			drgn_module_find_by_address(prog, addr);
		if (!module)
			return NULL;
		return drgn_module_elf_symbols_search(module, name, addr, flags,
						      builder);
	} else {
		hash_table_for_each(drgn_module_table, it,
				    &prog->dbinfo.modules) {
			for (struct drgn_module *module = *it.entry; module;
			     module = module->next_same_name) {
				err = drgn_module_elf_symbols_search(module,
								     name, addr,
								     flags,
								     builder);
				if (err == &drgn_stop)
					break;
				if (err)
					return err;
			}
		}
		return NULL;
	}
}

void drgn_debug_info_init(struct drgn_debug_info *dbinfo,
			  struct drgn_program *prog)
{
	elf_version(EV_CURRENT);
	dbinfo->prog = prog;
	drgn_module_table_init(&dbinfo->modules);
	drgn_module_address_tree_init(&dbinfo->modules_by_address);
	const struct drgn_type_finder_ops type_finder_ops = {
		.find = drgn_debug_info_find_type,
	};
	drgn_program_register_type_finder_impl(prog, &dbinfo->type_finder,
					       "dwarf", &type_finder_ops,
					       dbinfo, 0);
	const struct drgn_object_finder_ops object_finder_ops = {
		.find = drgn_debug_info_find_object,
	};
	drgn_program_register_object_finder_impl(prog, &dbinfo->object_finder,
						 "dwarf", &object_finder_ops,
						 dbinfo, 0);
	const struct drgn_symbol_finder_ops symbol_finder_ops = {
		.find = elf_symbols_search,
	};
	drgn_program_register_symbol_finder_impl(prog, &dbinfo->symbol_finder,
						 "elf", &symbol_finder_ops,
						 prog, 0);
	const struct drgn_debug_info_finder_ops
		standard_debug_info_finder_ops = {
			.find = drgn_standard_debug_info_find,
		};
	drgn_program_register_debug_info_finder_impl(prog,
					&dbinfo->standard_debug_info_finder,
					"standard",
					&standard_debug_info_finder_ops,
					&dbinfo->options, 0);
	drgn_debug_info_options_init(&dbinfo->options);
#if WITH_DEBUGINFOD
	dbinfo->debuginfod_client = NULL;
	if (drgn_have_debuginfod()) {
		const struct drgn_debug_info_finder_ops
			debuginfod_debug_info_finder_ops = {
				.find = drgn_debuginfod_find,
			};
		drgn_program_register_debug_info_finder_impl(prog,
					&dbinfo->debuginfod_debug_info_finder,
					"debuginfod",
					&debuginfod_debug_info_finder_ops,
					prog,
					DRGN_HANDLER_REGISTER_ENABLE_LAST);
	}
#endif
	drgn_dwarf_info_init(dbinfo);
}

void drgn_debug_info_deinit(struct drgn_debug_info *dbinfo)
{
	free(dbinfo->map_files_segments);
	drgn_debug_info_options_deinit(&dbinfo->options);
#if WITH_DEBUGINFOD
	if (dbinfo->debuginfod_client)
		drgn_debuginfod_end(dbinfo->debuginfod_client);
#endif
	drgn_handler_list_deinit(struct drgn_debug_info_finder, finder,
				 &dbinfo->debug_info_finders,
		if (finder->ops.destroy)
			finder->ops.destroy(finder->arg);
	);
	drgn_dwarf_info_deinit(dbinfo);
	hash_table_for_each(drgn_module_table, it, &dbinfo->modules) {
		struct drgn_module *module = *it.entry;
		do {
			struct drgn_module *next = module->next_same_name;
			drgn_module_destroy(module);
			module = next;
		} while (module);
	}
	drgn_module_table_deinit(&dbinfo->modules);
}

struct drgn_elf_file *drgn_module_find_dwarf_file(struct drgn_module *module,
						  Dwarf *dwarf)
{
	if (!module->debug_file)
		return NULL;
	if (dwarf == module->debug_file->_dwarf)
		return module->debug_file;
	if (module->supplementary_debug_file
	    && dwarf == module->supplementary_debug_file->_dwarf)
		return module->supplementary_debug_file;
	struct drgn_elf_file_dwarf_table_iterator it =
		drgn_elf_file_dwarf_table_search(&module->split_dwarf_files,
						 &dwarf);
	return it.entry ? *it.entry : NULL;
}

struct drgn_error *
drgn_module_create_split_dwarf_file(struct drgn_module *module,
				    const char *name, Dwarf *dwarf,
				    struct drgn_elf_file **ret)
{
	struct drgn_error *err;
	err = drgn_elf_file_create(module, name, -1, NULL, dwarf_getelf(dwarf),
				   ret);
	if (err)
		return err;
	(*ret)->_dwarf = dwarf;
	int r = drgn_elf_file_dwarf_table_insert(&module->split_dwarf_files,
						 ret, NULL);
	if (r < 0) {
		drgn_elf_file_destroy(*ret);
		return &drgn_enomem;
	}
	assert(r > 0);
	return NULL;
}

struct drgn_error *
drgn_module_find_cfi(struct drgn_program *prog, struct drgn_module *module,
		     uint64_t pc, struct drgn_elf_file **file_ret,
		     struct drgn_cfi_row **row_ret, bool *interrupted_ret,
		     drgn_register_number *ret_addr_regno_ret)
{
	struct drgn_error *err;

	// If the file's platform doesn't match the program's, we can't use its
	// CFI.
	const bool can_use_loaded_file =
		(module->loaded_file &&
		 drgn_platforms_equal(&module->loaded_file->platform,
				      &prog->platform));
	const bool can_use_debug_file =
		(module->debug_file &&
		 drgn_platforms_equal(&module->debug_file->platform,
				      &prog->platform));

	bool prefer_orc = false;
	if (can_use_debug_file) {
		if (!module->parsed_debug_frame) {
			err = drgn_module_parse_debug_frame(module);
			if (err)
				return err;
			module->parsed_debug_frame = true;
		}
		if (!module->parsed_orc) {
			err = drgn_module_parse_orc(module, false);
			if (err)
				return err;

			// For some distributions, such as Fedora & derivatives,
			// ORC sections are stripped from the debug file. Try
			// using built-in ORC if nothing was loaded from the
			// debug_file.
			if (!module->orc.num_entries)
				err = drgn_module_parse_orc(module, true);
			if (err)
				return err;

			module->parsed_orc = true;
		}

		prefer_orc = drgn_module_should_prefer_orc_cfi(module, pc);

		*file_ret = module->debug_file;
		if (prefer_orc) {
			err = drgn_module_find_orc_cfi(module, pc, row_ret,
						       interrupted_ret,
						       ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
		}
		err = drgn_module_find_dwarf_cfi(module, pc, row_ret,
						 interrupted_ret,
						 ret_addr_regno_ret);
		if (err != &drgn_not_found)
			return err;
	}

	if (can_use_loaded_file) {
		if (!module->parsed_eh_frame) {
			err = drgn_module_parse_eh_frame(module);
			if (err)
				return err;
			module->parsed_eh_frame = true;
		}
		*file_ret = module->loaded_file;
		err = drgn_module_find_eh_cfi(module, pc, row_ret,
					      interrupted_ret,
					      ret_addr_regno_ret);
		if (err != &drgn_not_found)
			return err;
	}

	if (can_use_debug_file && !prefer_orc) {
		err = drgn_module_find_orc_cfi(module, pc, row_ret,
					       interrupted_ret,
					       ret_addr_regno_ret);
		if (err != &drgn_not_found)
			return err;
	}

	if (!can_use_debug_file) {
		if (!module->parsed_orc) {
			err = drgn_module_parse_orc(module, true);
			if (err)
				return err;
			module->parsed_orc = true;
		}
		*file_ret = NULL;
		err = drgn_module_find_orc_cfi(module, pc, row_ret,
					       interrupted_ret,
					       ret_addr_regno_ret);
		if (err != &drgn_not_found)
			return err;
	}

	return &drgn_not_found;
}
