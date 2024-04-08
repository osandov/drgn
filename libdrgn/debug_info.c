// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <byteswap.h>
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
#include "cleanup.h"
#include "crc32.h"
#include "debug_info.h"
#include "elf_file.h"
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

struct drgn_module_trying_gnu_debugaltlink {
	struct drgn_elf_file *debug_file;
	const char *debugaltlink_path;
	const void *build_id;
	size_t build_id_len;
	char *build_id_str;
	struct drgn_elf_file *found;
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

static inline bool drgn_have_debuginfod(void)
{
	return drgn_debuginfod_begin != NULL;
}
#else
// GCC and Clang optimize out the function pointer.
#define X(name) static const typeof(&name) drgn_##name = name;
DRGN_DEBUGINFOD_FUNCTIONS
#undef X

static inline bool drgn_have_debuginfod(void)
{
	return true;
}
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

static inline
struct drgn_module_key drgn_module_entry_key(struct drgn_module * const *entry)
{
	struct drgn_module_key key;
	key.kind = (*entry)->kind;
	SWITCH_ENUM(key.kind,
	case DRGN_MODULE_SHARED_LIBRARY:
		key.shared_library.name = (*entry)->name;
		key.shared_library.dynamic_address =
			(*entry)->shared_library.dynamic_address;
		break;
	case DRGN_MODULE_VDSO:
		key.vdso.name = (*entry)->name;
		key.vdso.dynamic_address = (*entry)->vdso.dynamic_address;
		break;
	case DRGN_MODULE_LINUX_KERNEL_LOADABLE:
		key.linux_kernel_loadable.name = (*entry)->name;
		key.linux_kernel_loadable.base_address =
			(*entry)->linux_kernel_loadable.base_address;
		break;
	case DRGN_MODULE_EXTRA:
		key.extra.name = (*entry)->name;
		key.extra.id = (*entry)->extra.id;
		break;
	case DRGN_MODULE_MAIN:
	)
	return key;
}

static inline struct hash_pair
drgn_module_key_hash_pair(const struct drgn_module_key *key)
{
	size_t hash = key->kind;
	SWITCH_ENUM(key->kind,
	case DRGN_MODULE_SHARED_LIBRARY:
		hash = hash_combine(hash,
				    hash_c_string(key->shared_library.name));
		hash = hash_combine(hash, key->shared_library.dynamic_address);
		break;
	case DRGN_MODULE_VDSO:
		hash = hash_combine(hash, hash_c_string(key->vdso.name));
		hash = hash_combine(hash, key->vdso.dynamic_address);
		break;
	case DRGN_MODULE_LINUX_KERNEL_LOADABLE:
		hash = hash_combine(hash,
				    hash_c_string(key->linux_kernel_loadable.name));
		hash = hash_combine(hash, key->linux_kernel_loadable.base_address);
		break;
	case DRGN_MODULE_EXTRA:
		hash = hash_combine(hash, hash_c_string(key->extra.name));
		hash = hash_combine(hash, key->extra.id);
		break;
	case DRGN_MODULE_MAIN:
	)
	return hash_pair_from_avalanching_hash(hash);
}

static inline bool drgn_module_key_eq(const struct drgn_module_key *a,
				      const struct drgn_module_key *b)
{
	if (a->kind != b->kind)
		return false;
	SWITCH_ENUM(a->kind,
	case DRGN_MODULE_SHARED_LIBRARY:
		return (strcmp(a->shared_library.name,
			       b->shared_library.name) == 0
			&& a->shared_library.dynamic_address
			== b->shared_library.dynamic_address);
		break;
	case DRGN_MODULE_VDSO:
		return (strcmp(a->vdso.name, b->vdso.name) == 0
			&& a->vdso.dynamic_address == b->vdso.dynamic_address);
		break;
	case DRGN_MODULE_LINUX_KERNEL_LOADABLE:
		return (strcmp(a->linux_kernel_loadable.name,
			       b->linux_kernel_loadable.name) == 0
			&& a->linux_kernel_loadable.base_address
			== b->linux_kernel_loadable.base_address);
		break;
	case DRGN_MODULE_EXTRA:
		return (strcmp(a->extra.name, b->extra.name) == 0
			&& a->extra.id == b->extra.id);
		break;
	case DRGN_MODULE_MAIN:
	)
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_module_table, drgn_module_entry_key,
			    drgn_module_key_hash_pair, drgn_module_key_eq);

static inline uint64_t drgn_module_address_key(const struct drgn_module *entry)
{
	return entry->start;
}

DEFINE_BINARY_SEARCH_TREE_FUNCTIONS(drgn_module_address_tree, node,
				    drgn_module_address_key,
				    binary_search_tree_scalar_cmp, splay);

static void drgn_module_free_section_addresses(struct drgn_module *module)
{
	for (auto it =
	     drgn_module_section_address_map_first(&module->section_addresses);
	     it.entry;
	     it = drgn_module_section_address_map_next(it))
		free(it.entry->key);
}

LIBDRGN_PUBLIC
struct drgn_module *drgn_module_find(struct drgn_program *prog,
				     const struct drgn_module_key *key)
{
	if (key->kind == DRGN_MODULE_MAIN) {
		return prog->dbinfo.main_module;
	} else {
		struct drgn_module_table_iterator it =
			drgn_module_table_search(&prog->dbinfo.modules, key);
		return it.entry ? *it.entry : NULL;
	}
}

struct drgn_error *drgn_module_find_or_create(struct drgn_program *prog,
					      const struct drgn_module_key *key,
					      const char *name,
					      struct drgn_module **ret,
					      bool *new_ret)
{
	struct drgn_error *err;

	struct hash_pair hp;
	if (key->kind == DRGN_MODULE_MAIN) {
		if (prog->dbinfo.main_module) {
			*ret = prog->dbinfo.main_module;
			if (new_ret)
				*new_ret = false;
			return NULL;
		}
	} else {
		hp = drgn_module_table_hash(key);
		struct drgn_module_table_iterator it =
			drgn_module_table_search_hashed(&prog->dbinfo.modules,
							key, hp);
		if (it.entry) {
			*ret = *it.entry;
			if (new_ret)
				*new_ret = false;
			return NULL;
		}
	}

	struct drgn_module *module = calloc(1, sizeof(*module));
	if (!module)
		return &drgn_enomem;
	module->start = module->end = UINT64_MAX;

	module->prog = prog;
	module->kind = key->kind;
	SWITCH_ENUM(key->kind,
	case DRGN_MODULE_MAIN:
		break;
	case DRGN_MODULE_SHARED_LIBRARY:
		module->shared_library.dynamic_address =
			key->shared_library.dynamic_address;
		break;
	case DRGN_MODULE_VDSO:
		module->vdso.dynamic_address = key->vdso.dynamic_address;
		break;
	case DRGN_MODULE_LINUX_KERNEL_LOADABLE:
		module->linux_kernel_loadable.base_address =
			key->linux_kernel_loadable.base_address;
		break;
	case DRGN_MODULE_EXTRA:
		module->extra.id = key->extra.id;
		break;
	)

	module->name = strdup(name);
	if (!module->name) {
		err = &drgn_enomem;
		goto err_module;
	}

	if (key->kind == DRGN_MODULE_MAIN) {
		prog->dbinfo.main_module = module;
	} else if (drgn_module_table_insert_searched(&prog->dbinfo.modules,
						     &module, hp, NULL) < 0) {
		err = &drgn_enomem;
		goto err_name;
	}

	drgn_elf_file_dwarf_table_init(&module->split_dwarf_files);
	drgn_module_section_address_map_init(&module->section_addresses);

	SWITCH_ENUM(module->kind,
	case DRGN_MODULE_MAIN:
		drgn_log_debug(prog, "created main module %s", module->name);
		break;
	case DRGN_MODULE_SHARED_LIBRARY:
		drgn_log_debug(prog,
			       "created shared library module %s@0x%" PRIx64,
			       module->name,
			       module->shared_library.dynamic_address);
		break;
	case DRGN_MODULE_VDSO:
		drgn_log_debug(prog,
			       "created vDSO module %s@0x%" PRIx64,
			       module->name, module->vdso.dynamic_address);
		break;
	case DRGN_MODULE_LINUX_KERNEL_LOADABLE:
		drgn_log_debug(prog,
			       "created Linux kernel loadable module %s@0x%" PRIx64,
			       module->name,
			       module->linux_kernel_loadable.base_address);
		break;
	case DRGN_MODULE_EXTRA:
		drgn_log_debug(prog,
			       "created extra module %s 0x%" PRIx64,
			       module->name, module->extra.id);
		break;
	)

	*ret = module;
	if (new_ret)
		*new_ret = true;
	return NULL;

err_name:
	free(module->name);
err_module:
	free(module);
	return err;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_find_or_create_main(struct drgn_program *prog,
						   const char *name,
						   struct drgn_module **ret,
						   bool *new_ret)
{
	struct drgn_module_key key = { .kind = DRGN_MODULE_MAIN };
	return drgn_module_find_or_create(prog, &key, name, ret, new_ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_find_or_create_shared_library(struct drgn_program *prog,
					  const char *name,
					  uint64_t dynamic_address,
					  struct drgn_module **ret,
					  bool *new_ret)
{
	const struct drgn_module_key key = {
		.kind = DRGN_MODULE_SHARED_LIBRARY,
		.shared_library.name = name,
		.shared_library.dynamic_address = dynamic_address,
	};
	return drgn_module_find_or_create(prog, &key, name, ret, new_ret);
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_find_or_create_vdso(struct drgn_program *prog,
						   const char *name,
						   uint64_t dynamic_address,
						   struct drgn_module **ret,
						   bool *new_ret)
{
	const struct drgn_module_key key = {
		.kind = DRGN_MODULE_VDSO,
		.vdso.name = name,
		.vdso.dynamic_address = dynamic_address,
	};
	return drgn_module_find_or_create(prog, &key, name, ret, new_ret);
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_find_or_create_extra(struct drgn_program *prog,
						    const char *name,
						    uint64_t id,
						    struct drgn_module **ret,
						    bool *new_ret)
{
	const struct drgn_module_key key = {
		.kind = DRGN_MODULE_EXTRA,
		.extra.name = name,
		.extra.id = id,
	};
	return drgn_module_find_or_create(prog, &key, name, ret, new_ret);
}

// Note: this doesn't remove the module from the module tables.
static void drgn_module_destroy(struct drgn_module *module)
{
	drgn_module_free_section_addresses(module);
	drgn_module_section_address_map_deinit(&module->section_addresses);
	drgn_module_orc_info_deinit(module);
	drgn_module_dwarf_info_deinit(module);
	drgn_elf_file_destroy(module->gnu_debugaltlink_file);
	if (module->debug_file != module->loaded_file)
		drgn_elf_file_destroy(module->debug_file);
	drgn_elf_file_destroy(module->loaded_file);
	free(module->build_id);
	free(module->name);
	free(module);
}

void drgn_module_delete(struct drgn_module *module)
{
	assert(!module->loaded_file);
	assert(!module->debug_file);
	if (module->start < module->end) {
		drgn_module_address_tree_delete_entry(&module->prog->dbinfo.modules_by_address,
						      module);
	}
	if (module->kind == DRGN_MODULE_MAIN) {
		module->prog->dbinfo.main_module = NULL;
	} else {
		struct drgn_module_key key =
			drgn_module_entry_key((struct drgn_module * const *)&module);
		drgn_module_table_delete(&module->prog->dbinfo.modules, &key);
	}
	drgn_module_destroy(module);
}

LIBDRGN_PUBLIC
struct drgn_program *drgn_module_program(const struct drgn_module *module)
{
	return module->prog;
}

LIBDRGN_PUBLIC
struct drgn_module_key drgn_module_key(const struct drgn_module *module)
{
	if (module->kind == DRGN_MODULE_MAIN) {
		struct drgn_module_key key;
		key.kind = DRGN_MODULE_MAIN;
		return key;
	}
	return drgn_module_entry_key((struct drgn_module * const *)&module);
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

LIBDRGN_PUBLIC bool drgn_module_address_range(const struct drgn_module *module,
					      uint64_t *start_ret,
					      uint64_t *end_ret)
{
	if (module->start == UINT64_MAX)
		return false;
	*start_ret = module->start;
	*end_ret = module->end;
	return true;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_set_address_range(struct drgn_module *module, uint64_t start,
			      uint64_t end)
{
	if (start >= end && start != 0 && end != UINT64_MAX) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid module address range");
	}

	if (module->start < module->end) {
		drgn_module_address_tree_delete_entry(&module->prog->dbinfo.modules_by_address,
						      module);
	}

	module->start = start;
	module->end = end;
	if (start < end) {
		// TODO: check for overlap?
		drgn_module_address_tree_insert(&module->prog->dbinfo.modules_by_address,
						module, NULL);
	}
	return NULL;
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

LIBDRGN_PUBLIC const char *
drgn_module_gnu_debugaltlink_file_path(const struct drgn_module *module)
{
	return module->gnu_debugaltlink_file ?
	       module->gnu_debugaltlink_file->path : NULL;
}

bool drgn_module_set_section_address(struct drgn_module *module, const char *name,
				     uint64_t address)
{
	struct hash_pair hp =
		drgn_module_section_address_map_hash((char **)&name);
	struct drgn_module_section_address_map_iterator it =
		drgn_module_section_address_map_search_hashed(&module->section_addresses,
							      (char **)&name,
							      hp);
	if (it.entry) {
		it.entry->value = address;
		return true;
	}
	struct drgn_module_section_address_map_entry entry = {
		.key = strdup(name),
		.value = address,
	};
	if (!entry.key)
		return false;
	if (drgn_module_section_address_map_insert_searched(&module->section_addresses,
							    &entry, hp,
							    NULL) < 0) {
		free(entry.key);
		return false;
	}
	return true;
}

bool drgn_module_try_files_done(struct drgn_module_try_files_state *state)
{
	return !state->want_loaded && !state->want_debug;
}

static void drgn_module_try_files_log(struct drgn_module_try_files_state *state,
				      const char *how)
{
	if (state->module->trying_gnu_debugaltlink) {
		drgn_log_debug(state->module->prog,
			       "%s gnu_debugaltlink file with build ID %s",
			       how,
			       state->module->trying_gnu_debugaltlink->build_id_str);
	} else {
		drgn_log_debug(state->module->prog,
			       "%s %s%s%s file%s for module %s with %s%s", how,
			       state->want_loaded ? "loaded" : "",
			       state->want_loaded && state->want_debug
			       ? " and " : "",
			       state->want_debug ? "debug" : "",
			       state->want_loaded && state->want_debug
			       ? "s" : "",
			       state->module->name,
			       state->module->build_id_str
			       ? "build ID " : "no build ID",
			       state->module->build_id_str
			       ? state->module->build_id_str : "");
	}
}

// Get the build ID to use for trying module files. This is the
// .gnu_debugaltlink build ID if we're currently trying to find the
// .gnu_debugaltlink file and the module build ID otherwise.
static const char *
drgn_module_try_files_build_id(const struct drgn_module *module,
			       const void **raw_ret, size_t *raw_len_ret)
{
	if (module->trying_gnu_debugaltlink) {
		if (raw_ret)
			*raw_ret = module->trying_gnu_debugaltlink->build_id;
		if (raw_len_ret)
			*raw_len_ret = module->trying_gnu_debugaltlink->build_id_len;
		return module->trying_gnu_debugaltlink->build_id_str;
	} else {
		return drgn_module_build_id(module, raw_ret, raw_len_ret);
	}
}

static struct drgn_error *
drgn_module_find_gnu_debugaltlink_file(struct drgn_module_try_files_state *state,
				       struct drgn_elf_file *file,
				       struct drgn_elf_file **ret)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;

	*ret = NULL;

	// We don't cache .gnu_debugaltlink, and it doesn't need relocation, so
	// don't use drgn_elf_file_read_section().
	Elf_Data *data;
	err = read_elf_section(file->scns[DRGN_SCN_GNU_DEBUGALTLINK], &data);
	if (err) {
		if (drgn_error_should_log(err)) {
			drgn_error_log_debug(prog, err,
					     "%s: couldn't read .gnu_debugaltlink: ",
					     file->path);
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}

	const char *debugaltlink = data->d_buf;
	const char *nul = memchr(debugaltlink, 0, data->d_size);
	if (!nul || nul + 1 == debugaltlink + data->d_size) {
		drgn_log_debug(prog, "%s: couldn't parse .gnu_debugaltlink",
			       file->path);
		return NULL;
	}
	const void *build_id = nul + 1;
	size_t build_id_len = debugaltlink + data->d_size - (nul + 1);
	_cleanup_free_ char *build_id_str = ahexlify(build_id, build_id_len);
	if (!build_id_str)
		return &drgn_enomem;
	drgn_log_debug(prog, "%s has gnu_debugaltlink %s build ID %s", file->path,
		       debugaltlink, build_id_str);

	module->trying_gnu_debugaltlink = &(struct drgn_module_trying_gnu_debugaltlink){
		.debug_file = file,
		.debugaltlink_path = debugaltlink,
		.build_id = build_id,
		.build_id_len = build_id_len,
		.build_id_str = build_id_str,
	};
	struct drgn_module_try_files_args args = {
		.want_loaded = false,
		.want_debug = true,
		// Copy the rest directly from the original args.
		.debug_directories = state->args->debug_directories,
		.arg = state->args->arg,
		.need_gnu_debugaltlink_file = state->args->need_gnu_debugaltlink_file,
	};
	if (args.need_gnu_debugaltlink_file) {
		err = args.need_gnu_debugaltlink_file(module, &args, file->path,
						      debugaltlink, build_id,
						      build_id_len,
						      build_id_str);
	} else {
		err = drgn_module_try_default_files(module, &args);
	}
	if (err)
		drgn_elf_file_destroy(module->trying_gnu_debugaltlink->found);
	else
		*ret = module->trying_gnu_debugaltlink->found;
	module->trying_gnu_debugaltlink = NULL;
	return err;
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
	if ((prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
	    module->kind == DRGN_MODULE_MAIN) {
		*ret = prog->vmcoreinfo.kaslr_offset;
		drgn_log_debug(prog,
			       "got bias 0x%" PRIx64 " from VMCOREINFO",
			       *ret);
		return true;
	} else if (module->kind == DRGN_MODULE_MAIN) {
		return elf_main_bias(prog, file->elf, ret);
	} else if (module->kind == DRGN_MODULE_SHARED_LIBRARY) {
		return elf_dso_bias(prog, file->elf,
				    module->shared_library.dynamic_address,
				    ret);
	} else if (module->kind == DRGN_MODULE_VDSO) {
		return elf_dso_bias(prog, file->elf,
				    module->vdso.dynamic_address, ret);
	} else {
		*ret = 0;
		return true;
	}
}

// Get the address range of an ELF file from the start address of the first
// loadable segment and the end address of the last loadable segment.
static bool
elf_address_range_from_first_and_last_phdr(struct drgn_program *prog, Elf *elf,
					   uint64_t bias, uint64_t *start_ret,
					   uint64_t *end_ret)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum) != 0) {
		drgn_log_debug(prog, "elf_getphdrnum: %s", elf_errmsg(-1));
		return false;
	}

	uint64_t start;
	GElf_Phdr phdr_mem, *phdr;
	size_t i;
	for (i = 0; i < phnum; i++) {
		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr) {
			drgn_log_debug(prog, "gelf_getphdr: %s",
				       elf_errmsg(-1));
			return false;
		}
		if (phdr->p_type == PT_LOAD) {
			start = phdr->p_vaddr + bias;
			break;
		}
	}
	if (i >= phnum) {
		drgn_log_debug(prog, "file has no loadable segments");
		*start_ret = *end_ret = 0;
		return true;
	}

	for (i = phnum; i-- > 0;) {
		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr) {
			drgn_log_debug(prog, "gelf_getphdr: %s",
				       elf_errmsg(-1));
			return false;
		}
		if (phdr->p_type == PT_LOAD) {
			uint64_t end = phdr->p_vaddr + phdr->p_memsz + bias;
			if (start < end) {
				*start_ret = start;
				*end_ret = end;
				return true;
			}
			drgn_log_debug(prog,
				       "first and last loadable segments are not valid");
			*start_ret = *end_ret = 0;
			return true;
		}
	}
	// This shouldn't happen.
	drgn_log_debug(prog, "loadable segment disappeared");
	return false;
}

// Get the address range of an ELF file from the minimum start address of any
// loadable segment and the maximum end address of any loadable segment.
static bool
elf_address_range_from_min_and_max_phdr(struct drgn_program *prog, Elf *elf,
					uint64_t bias, uint64_t *start_ret,
					uint64_t *end_ret)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum) != 0) {
		drgn_log_debug(prog, "elf_getphdrnum: %s", elf_errmsg(-1));
		return false;
	}

	uint64_t start = UINT64_MAX, end = 0;
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr) {
			drgn_log_debug(prog, "gelf_getphdr: %s",
				       elf_errmsg(-1));
			return false;
		}
		if (phdr->p_type == PT_LOAD) {
			start = min(start, phdr->p_vaddr + bias);
			end = max(end, phdr->p_vaddr + phdr->p_memsz + bias);
		}
	}
	if (start < end) {
		*start_ret = start;
		*end_ret = end;
		return true;
	}

	drgn_log_debug(prog, "file has no valid loadable segments");
	*start_ret = *end_ret = 0;
	return true;
}

static bool drgn_module_elf_file_address_range(struct drgn_module *module,
					       struct drgn_elf_file *file,
					       uint64_t bias,
					       uint64_t *start_ret,
					       uint64_t *end_ret)
{
	struct drgn_program *prog = module->prog;
	// The ELF specification says that "loadable segment entries in the
	// program header table appear in ascending order, sorted on the p_vaddr
	// member." However, this is not the case in practice.
	if ((prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
	    module->kind == DRGN_MODULE_MAIN) {
		// vmlinux on some architectures contains special segments whose
		// addresses are not meaningful (e.g., segments corresponding to
		// the .data..percpu section on x86-64 and the .vectors and
		// .stubs sections on Arm). Rather than adding special cases
		// based on section names, we assume that these special segments
		// are never first or last and that the segments are otherwise
		// sorted, which seems to always be true.
		return elf_address_range_from_first_and_last_phdr(prog,
								  file->elf,
								  bias,
								  start_ret,
								  end_ret);
	} else if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
		   (module->kind == DRGN_MODULE_MAIN ||
		    module->kind == DRGN_MODULE_SHARED_LIBRARY ||
		    module->kind == DRGN_MODULE_VDSO)) {
		// Userspace ELF loaders disagree about whether to assume this
		// sorting:
		//
		// - As of Linux kernel commit 10b19249192a ("ELF: fix overflow
		//   in total mapping size calculation") (in v5.18), the Linux
		//   kernel DOES NOT assume sorting. Before that, it DOES.
		// - glibc as of v2.37 DOES assume sorting; see
		//   _dl_map_object_from_fd() in elf/dl-load.c and
		//   _dl_map_segments() in elf/dl-map-segments.h.
		// - musl as of v1.2.3 DOES NOT assume sorting; see
		//   map_library() in ldso/dynlink.c.
		//
		// Since it's not enforced by some ELF loaders that we might
		// encounter, we don't assume the sorted order, either.
		return elf_address_range_from_min_and_max_phdr(prog, file->elf,
							       bias, start_ret,
							       end_ret);
	} else {
		*start_ret = *end_ret = 0;
		return true;
	}
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

// Takes ownership of file unless it is already owned by module.
static struct drgn_error *
drgn_module_maybe_use_elf_file(struct drgn_module_try_files_state *state,
			       struct drgn_elf_file *file)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;

	// We shouldn't be here if we already have everything we need.
	assert(state->want_loaded || state->want_debug);
	const bool use_loaded = state->want_loaded && file->is_loadable;
	const bool has_dwarf = drgn_elf_file_has_dwarf(file);
	bool use_debug = state->want_debug && has_dwarf;

	_cleanup_free_ void *build_id_buf = NULL;

	if (!use_loaded && !use_debug) {
		if (file->is_loadable) {
			drgn_log_debug(prog,
				       "loadable, but don't want loaded file; ignoring");
		} else if (has_dwarf) {
			drgn_log_debug(prog,
				       "has debug info, but don't want debug info; ignoring");
		} else {
			drgn_log_debug(prog,
				       "not loadable and no debug info; ignoring");
		}
		err = NULL;
		goto unused;
	}

	// Get everything that might fail before we commit to using the file.
	const void *elf_build_id;
	ssize_t elf_build_id_len = 0;
	uint64_t bias = 0;
	uint64_t elf_start = 0, elf_end = 0;
	if (!module->trying_gnu_debugaltlink) {
		if (module->build_id_len == 0) {
			elf_build_id_len =
				dwelf_elf_gnu_build_id(file->elf,
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

		if (!drgn_module_elf_file_bias(module, file, &bias)) {
			err = NULL;
			goto unused;
		}
		if (module->start == UINT64_MAX
		    && !drgn_module_elf_file_address_range(module, file, bias,
							   &elf_start,
							   &elf_end)) {
			err = NULL;
			goto unused;
		}
	}

	if (file != module->loaded_file && file != module->debug_file
	    && !drgn_module_copy_section_addresses(module, file->elf)) {
		drgn_log_debug(prog, "%s: %s", file->path, elf_errmsg(-1));
		err = NULL;
		goto unused;
	}

	if (use_debug) {
		// If the file has .gnu_debugaltlink, find it before we use the
		// file.
		if (module->trying_gnu_debugaltlink) {
			drgn_log_info(prog,
				      "using gnu_debugaltlink file %s for %s",
				      file->path, state->module->name);
			module->trying_gnu_debugaltlink->found = file;
			state->want_debug = false;
			return NULL;
		} else if (file->scns[DRGN_SCN_GNU_DEBUGALTLINK]) {
			struct drgn_elf_file *gnu_debugaltlink_file;
			err = drgn_module_find_gnu_debugaltlink_file(state,
								     file,
								     &gnu_debugaltlink_file);
			if (err)
				goto unused;

			if (gnu_debugaltlink_file) {
				module->gnu_debugaltlink_file =
					gnu_debugaltlink_file;
			} else {
				drgn_log_debug(prog,
					       "couldn't find gnu_debugaltlink file; ignoring debug info");
				use_debug = false;
			}
		}
	}
	if (!use_loaded && !use_debug) {
		err = NULL;
		goto unused;
	}

	// At this point, we've committed to using the file. Nothing after this
	// is allowed to fail.

	if (use_loaded && use_debug) {
		drgn_log_info(prog,
			      "using loadable file with debug info %s for %s",
			      file->path, module->name);
	} else if (use_loaded) {
		drgn_log_info(prog, "using loadable file %s for %s", file->path,
			      module->name);
	} else if (use_debug) {
		drgn_log_info(prog, "using debug info file %s for %s",
			      file->path, module->name);
	}

	// If we got a build ID or address range earlier, install them. Note
	// that the need_gnu_debugaltlink_file callback could've set these in
	// between when we checked whether they were already set and now, so
	// check again.
	if (module->build_id_len == 0 && elf_build_id_len > 0) {
		drgn_module_set_build_id_impl(module, elf_build_id,
					      elf_build_id_len,
					      no_cleanup_ptr(build_id_buf));
		drgn_log_debug(prog, "got build ID %s from file",
			       module->build_id_str);
	}
	if (module->start == UINT64_MAX && elf_start < elf_end) {
		drgn_log_debug(prog,
			       "got address range 0x%" PRIx64
			       "-0x%" PRIx64 " from file",
			       elf_start, elf_end);
		err = drgn_module_set_address_range(module, elf_start, elf_end);
		// This can only fail if the address range is invalid, which we
		// just checked for.
		assert(!err);
	}

	if (use_loaded) {
		module->loaded_file = file;
		module->loaded_file_bias = bias;
		state->want_loaded = false;
	}
	if (use_debug) {
		module->debug_file = file;
		module->debug_file_bias = bias;
		state->want_debug = false;
		module->pending_indexing_next =
			prog->dbinfo.modules_pending_indexing;
		prog->dbinfo.modules_pending_indexing = module;
		prog->tried_main_language = false;
	}
	if (!prog->has_platform) {
		drgn_log_debug(prog, "setting program platform from file");
		drgn_program_set_platform(prog, &file->platform);
	}
	return NULL;

unused:
	if (file != module->loaded_file && file != module->debug_file)
		drgn_elf_file_destroy(file);
	return err;
}

// Takes ownership of fd.
struct drgn_error *
drgn_module_try_file_internal(struct drgn_module_try_files_state *state,
			      const char *path, int fd_, bool check_build_id,
			      const uint32_t *expected_crc)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;

	_cleanup_close_ int fd = fd_;
	if (fd >= 0) {
		if (path)
			drgn_log_debug(prog, "trying %s with fd %d", path, fd);
		else
			drgn_log_debug(prog, "trying fd %d", fd);
	} else {
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			drgn_log_debug(prog, "%s: %m", path);
			return NULL;
		}
		drgn_log_debug(prog, "trying %s", path);
	}

	// Try to canonicalize the path, first via
	// readlink("/proc/self/fd/$fd"), then via realpath().
#define FORMAT "/proc/self/fd/%d"
	char fd_path[sizeof(FORMAT)
		     - (sizeof("%d") - 1)
		     + max_decimal_length(int)];
	snprintf(fd_path, sizeof(fd_path), FORMAT, fd);
#undef FORMAT

	size_t link_buf_size = PATH_MAX;
	_cleanup_free_ char *link_buf = malloc(link_buf_size);
	if (!link_buf)
		return &drgn_enomem;

	for (;;) {
		ssize_t r = readlink(fd_path, link_buf, link_buf_size);
		if (r < 0) {
			drgn_log_debug(prog, "readlink: %s: %m", fd_path);
			if (path) {
				free(link_buf);
				link_buf = realpath(path, NULL);
				if (link_buf) {
					drgn_log_debug(prog,
						       "canonical path is %s",
						       link_buf);
					path = link_buf;
				} else {
					drgn_log_debug(prog, "realpath: %s: %m",
						       path);
				}
			} else {
				path = fd_path;
			}
			break;
		}

		if (r < link_buf_size) {
			link_buf[r] = '\0';
			if (drgn_log_is_enabled(prog, DRGN_LOG_DEBUG)
			    && (!path || strcmp(path, link_buf) != 0)) {
				drgn_log_debug(prog, "canonical path is %s",
					       link_buf);
			}
			path = link_buf;
			break;
		}

		if (__builtin_mul_overflow(link_buf_size, 2U, &link_buf_size))
			return &drgn_enomem;
		free(link_buf);
		link_buf = malloc(link_buf_size);
		if (!link_buf)
			return &drgn_enomem;
	}

	_cleanup_elf_end_ Elf *elf = dwelf_elf_begin(fd);
	if (!elf) {
		drgn_log_debug(prog, "%s: %s", path, elf_errmsg(-1));
		return NULL;
	}
	if (elf_kind(elf) != ELF_K_ELF) {
		drgn_log_debug(prog, "%s: not an ELF file", path);
		return NULL;
	}

	if (check_build_id) {
		const void *build_id;
		size_t build_id_len;
		if (drgn_module_try_files_build_id(module, &build_id,
						   &build_id_len)) {
			const void *elf_build_id;
			ssize_t elf_build_id_len =
				dwelf_elf_gnu_build_id(elf, &elf_build_id);
			if (elf_build_id_len < 0) {
				drgn_log_debug(prog, "%s: %s", path,
					       elf_errmsg(-1));
				return NULL;
			}
			if (elf_build_id_len != build_id_len ||
			    memcmp(elf_build_id, build_id, build_id_len) != 0) {
				if (elf_build_id_len == 0) {
					drgn_log_debug(prog,
						       "file is missing build ID");
				} else {
					drgn_log_debug(prog,
						       "build ID does not match");
				}
				return NULL;
			}
			drgn_log_debug(prog, "build ID matches");
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
				       "CRC 0x%08" PRIx32 " does not match",
				       crc);
			return NULL;
		}
		drgn_log_debug(prog, "CRC matches");
	}

	struct drgn_elf_file *file;
	err = drgn_elf_file_create(module, path, fd, NULL, elf, &file);
	if (err) {
		if (drgn_error_should_log(err)) {
			drgn_error_log_debug(prog, err, "");
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}
	// fd and elf are owned by the drgn_elf_file now.
	fd = -1;
	elf = NULL;
	return drgn_module_maybe_use_elf_file(state, file);
}

// Arbitrary limit on the number of bytes we'll allocate and read from the
// program's memory at once when finding modules/debug info.
static const uint64_t MAX_MEMORY_READ_FOR_DEBUG_INFO = UINT64_C(1048576);

static struct drgn_error *
drgn_module_try_vdso_in_core(struct drgn_module_try_files_state *state)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;

	// The Linux kernel has included the entire vDSO in core dumps since
	// Linux kernel commit f47aef55d9a1 ("[PATCH] i386 vDSO: use
	// VM_ALWAYSDUMP") (in v2.6.20). Try to read it from program memory.

	// The vDSO is always stripped.
	if (!state->want_loaded)
		return NULL;

	uint64_t start, end;
	if (!drgn_module_address_range(module, &start, &end)) {
		drgn_log_debug(prog,
			       "vDSO address range is not known; "
			       "can't read from program");
		return NULL;
	}
	if (start >= end) {
		drgn_log_debug(prog,
			       "vDSO address range is empty; "
			       "can't read from program");
		return NULL;
	}
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
		if (drgn_error_should_log(err)) {
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
	err = drgn_elf_file_create(module, "", -1, image, elf, &file);
	if (err) {
		if (drgn_error_should_log(err)) {
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
	return drgn_module_maybe_use_elf_file(state, file);
}

// An entry in /proc/$pid/map_files.
struct drgn_map_files_segment {
	uint64_t start;
	uint64_t end;
};

static inline int drgn_map_files_segment_compare(const void *_a, const void *_b)
{
	const struct drgn_map_files_segment *a = _a;
	const struct drgn_map_files_segment *b = _b;
	return (a->start > b->start) - (a->start < b->start);
}

DEFINE_VECTOR(drgn_map_files_segment_vector, struct drgn_map_files_segment);

static struct drgn_error *
open_map_files_for_shared_library(struct drgn_module *module, int *fd_ret)
{
	struct drgn_program *prog = module->prog;
	uint64_t address = module->shared_library.dynamic_address;
	int fd = -1;

#define DIR_FORMAT "/proc/%ld/map_files"
#define ENTRY_FORMAT "/%" PRIx64 "-%" PRIx64
	char path[sizeof(DIR_FORMAT ENTRY_FORMAT)
		  - (sizeof("%ld") - 1)
		  + max_decimal_length(long)
		  - 2 * (sizeof("%" PRIx64) - 1)
		  + 2 * 16];
	int dir_len = sprintf(path, DIR_FORMAT, (long)prog->pid);

	// Check the cache first.
	struct drgn_map_files_segment *cache = prog->map_files_segments;
	size_t lo = 0;
	size_t hi = prog->num_map_files_segments;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (address < cache[mid].start)
			hi = mid;
		else
			lo = mid + 1;
	}

	if (lo > 0 && address < cache[lo - 1].end) {
		sprintf(path + dir_len, ENTRY_FORMAT, cache[lo - 1].start,
			cache[lo - 1].end);

		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			drgn_log_debug(prog,
				       "found %s containing dynamic section 0x%" PRIx64,
				       path, address);
			*fd_ret = fd;
			return NULL;
		}

		// We found a match in the cache, but we couldn't open it. If it
		// doesn't exist anymore, then we need to rebuild the cache. If
		// it failed for any other reason, ignore it like we do in the
		// cache miss case.
		if (errno != ENOENT) {
			drgn_log_debug(prog, "%s: %m", path);
			return NULL;
		}

		path[dir_len] = '\0';
	}
#undef DIR_FORMAT
#undef ENTRY_FORMAT

	// Walk /proc/$pid/map_files, caching it while looking for a match.
	_cleanup_closedir_ DIR *dir = opendir(path);
	if (!dir) {
		if (errno != ENOENT)
			return drgn_error_create_os("opendir", errno, path);
		drgn_log_debug(prog, "%s: %m", path);
		return NULL;
	}
	_cleanup_(drgn_map_files_segment_vector_deinit)
		struct drgn_map_files_segment_vector segments = VECTOR_INIT;
	bool sorted = true;
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
		    && fd < 0) {
			fd = openat(dirfd(dir), ent->d_name, O_RDONLY);
			if (fd >= 0) {
				drgn_log_debug(prog,
					       "found %s/%s containing dynamic section 0x%" PRIx64,
					       path, ent->d_name, address);
				*fd_ret = fd;
			} else {
				drgn_log_debug(prog, "%s/%s: %m", path,
					       ent->d_name);
			}
		}
	}
	if (errno)
		return drgn_error_create_os("readdir", errno, path);

	free(prog->map_files_segments);
	drgn_map_files_segment_vector_shrink_to_fit(&segments);
	drgn_map_files_segment_vector_steal(&segments,
					    &prog->map_files_segments,
					    &prog->num_map_files_segments);
	// The Linux kernel always returns these entries in order, but sort it
	// just in case.
	if (!sorted) {
		qsort(prog->map_files_segments, prog->num_map_files_segments,
		      sizeof(prog->map_files_segments[0]),
		      drgn_map_files_segment_compare);
	}

	if (fd < 0) {
		drgn_log_debug(prog,
			       "didn't find entry in %s containing dynamic section 0x%" PRIx64,
			       path, address);
	}
	return NULL;
}

static struct drgn_error *
drgn_module_try_proc_files(struct drgn_module_try_files_state *state,
			   bool *tried)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;

	*tried = false;

	_cleanup_close_ int fd = -1;
	if (module->kind == DRGN_MODULE_MAIN) {
#define FORMAT "/proc/%ld/exe"
		char path[sizeof(FORMAT)
			  - (sizeof("%ld") - 1)
			  + max_decimal_length(long)];
		snprintf(path, sizeof(path), FORMAT, (long)prog->pid);
#undef FORMAT
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			drgn_log_debug(prog, "%s: %m", path);
			return NULL;
		}
		drgn_log_debug(prog, "found %s", path);
	} else if (module->kind == DRGN_MODULE_SHARED_LIBRARY) {
		err = open_map_files_for_shared_library(module, &fd);
		if (err || fd < 0)
			return err;
	} else {
		return NULL;
	}

	err = drgn_module_try_file_internal(state, NULL, fd, false, NULL);
	// drgn_module_try_file_internal took ownership of fd.
	fd = -1;
	*tried = true;
	return err;
}

static struct drgn_error *
drgn_module_try_files_by_build_id(struct drgn_module_try_files_state *state)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;

	size_t build_id_len;
	const char *build_id_str =
		drgn_module_try_files_build_id(module, NULL, &build_id_len);
	// We need at least 2 bytes (4 hex characters) to build the paths.
	if (build_id_len < 2)
		return NULL;

	STRING_BUILDER(sb);
	for (size_t i = 0; state->debug_directories[i]; i++) {
		if (state->debug_directories[i][0] != '/')
			continue;
		if (!string_builder_appendf(&sb, "%s/.build-id/%c%c/%s.debug",
					    state->debug_directories[i],
					    build_id_str[0], build_id_str[1],
					    &build_id_str[2]) ||
		    !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		// We trust the build ID encoded in the path and don't check it
		// again.
		if (state->want_debug) {
			err = drgn_module_try_file_internal(state, sb.str, -1,
							    false, NULL);
			if (err || drgn_module_try_files_done(state))
				return err;
		}
		if (state->want_loaded) {
			// Remove the ".debug" extension.
			sb.str[sb.len - sizeof(".debug") + 1] = '\0';
			err = drgn_module_try_file_internal(state, sb.str, -1,
							    false, NULL);
			if (err || drgn_module_try_files_done(state))
				return err;
		}
		sb.len = 0;
	}
	return NULL;
}

static struct drgn_error *
drgn_module_try_files_by_gnu_debuglink(struct drgn_module_try_files_state *state)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;

	struct drgn_elf_file *file = module->loaded_file;
	if (!file || !file->scns[DRGN_SCN_GNU_DEBUGLINK])
		return NULL;
	// We don't cache .gnu_debuglink, and it doesn't need relocation, so
	// don't use drgn_elf_file_read_section().
	Elf_Data *data;
	err = read_elf_section(file->scns[DRGN_SCN_GNU_DEBUGLINK], &data);
	if (err) {
		if (drgn_error_should_log(err)) {
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
		if (drgn_error_should_log(err)) {
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
		err = drgn_module_try_file_internal(state, debuglink, -1, false,
						    &crc);
		if (err || drgn_module_try_files_done(state))
			return err;
	} else if (file->path[0] && debuglink[0]) {
		// debuglink is relative. Try it in the debug directories.
		const char *slash = strrchr(file->path, '/');
		size_t dirslash_len = slash ? slash - file->path + 1 : 0;
		for (size_t i = 0; state->debug_directories[i]; i++) {
			const char *debug_dir = state->debug_directories[i];
			// If debug_dir is empty, then try:
			// $(dirname $path)/$debuglink
			// If debug_dir is relative, then try:
			// $(dirname $path)/$debug_dir/$debuglink
			// If debug_dir is absolute, then try:
			// $debug_dir/$(dirname $path)/$debuglink
			if (debug_dir[0] == '/') {
				if (file->path[0] != '/')
					continue;
				if (!string_builder_append(&sb, debug_dir))
					return &drgn_enomem;
			}
			if (!string_builder_appendn(&sb, file->path,
						    dirslash_len)
			    || (debug_dir[0] && debug_dir[0] != '/'
				&& !string_builder_appendf(&sb, "%s/",
							   debug_dir))
			    || !string_builder_appendn(&sb, debuglink,
						       debuglink_len)
			    || !string_builder_null_terminate(&sb))
				return &drgn_enomem;
			err = drgn_module_try_file_internal(state, sb.str, -1,
							    false, &crc);
			if (err || drgn_module_try_files_done(state))
				return err;
			sb.len = 0;
		}
	}
	return NULL;
}

static struct drgn_error *
drgn_module_try_local_files_gnu_debugaltlink(struct drgn_module_try_files_state *state)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	const struct drgn_module_trying_gnu_debugaltlink *trying =
		module->trying_gnu_debugaltlink;

	STRING_BUILDER(sb);
	const char *slash;
	if (trying->debugaltlink_path[0] == '/'
	    || !(slash = strrchr(trying->debug_file->path, '/'))) {
		// debugaltlink is absolute, or the debug file doesn't have a
		// directory component and is therefore in the current working
		// directory. Try debugaltlink directly.
		err = drgn_module_try_file_internal(state,
						    trying->debugaltlink_path,
						    -1, true, NULL);
	} else {
		// Try $(dirname $path)/$debugaltlink.
		if (!string_builder_appendn(&sb, trying->debug_file->path,
					    slash + 1
					    - trying->debug_file->path)
		    || !string_builder_append(&sb, trying->debugaltlink_path)
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		err = drgn_module_try_file_internal(state, sb.str, -1, true,
						    NULL);
	}
	if (err || drgn_module_try_files_done(state))
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
	const char *dwz = strstr(trying->debugaltlink_path, "/.dwz/");
	if (dwz) {
		for (size_t i = 0; state->debug_directories[i]; i++) {
			if (state->debug_directories[i][0] != '/')
				continue;

			sb.len = 0;
			if (!string_builder_append(&sb,
						   state->debug_directories[i])
			    || !string_builder_append(&sb, dwz)
			    || !string_builder_null_terminate(&sb))
				return &drgn_enomem;

			// Don't bother trying debugaltlink directly again.
			if (strcmp(sb.str, trying->debugaltlink_path) == 0)
				continue;

			err = drgn_module_try_file_internal(state, sb.str, -1,
							    true, NULL);
			if (err || drgn_module_try_files_done(state))
				return err;
		}
	}
	return NULL;
}

static struct drgn_error *
drgn_module_try_local_files_internal(struct drgn_module_try_files_state *state)
{
	struct drgn_error *err;
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;

	drgn_module_try_files_log(state, "checking standard paths for");

	if (module->trying_gnu_debugaltlink) {
		return drgn_module_try_local_files_gnu_debugaltlink(state);
	}

	// If a previous attempt used a loadable file with debug info but didn't
	// want both, we might be able to reuse it.
	if (state->want_loaded && module->debug_file
	    && module->debug_file->is_loadable) {
		drgn_log_debug(prog,
			       "reusing loadable debug file %s as loaded file",
			       module->debug_file->path);
		err = drgn_module_maybe_use_elf_file(state, module->debug_file);
		if (err || drgn_module_try_files_done(state))
			return err;
	}
	// ... and vice versa.
	if (state->want_debug && module->loaded_file
	    && drgn_elf_file_has_dwarf(module->loaded_file)) {
		drgn_log_debug(prog,
			       "reusing loaded file with debug info %s as debug file",
			       module->loaded_file->path);
		err = drgn_module_maybe_use_elf_file(state,
						     module->loaded_file);
		if (err || drgn_module_try_files_done(state))
			return err;
	}

	// First, try methods that are guaranteed to find the right file:
	// reading a vDSO from the core dump and opening a file via a magic
	// symlink in /proc.
	bool tried_proc_symlink = false;
	if (module->kind == DRGN_MODULE_VDSO) {
		err = drgn_module_try_vdso_in_core(state);
		if (err || drgn_module_try_files_done(state))
			return err;
	} else if ((module->prog->flags
		    & (DRGN_PROGRAM_IS_LINUX_KERNEL | DRGN_PROGRAM_IS_LIVE))
		   == DRGN_PROGRAM_IS_LIVE) {
		err = drgn_module_try_proc_files(state, &tried_proc_symlink);
		if (err || drgn_module_try_files_done(state))
			return err;
	}

	// If we already have the build ID, try it now before wasting time with
	// the expected paths. If this is a Linux kernel loadable module, this
	// can save us from needing the depmod index. If not, it can still save
	// us from trying a file with the wrong build ID.
	const bool had_build_id = module->build_id_len > 0;
	if (had_build_id) {
		err = drgn_module_try_files_by_build_id(state);
		if (err || drgn_module_try_files_done(state))
			return err;
	}

	// Next, try opening things at their expected paths. If this is the
	// Linux kernel or a Linux kernel loadable module, try some well-known
	// paths.
	if (module->kind == DRGN_MODULE_MAIN
	    && (module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		err = drgn_module_try_vmlinux_files(state);
		if (err || drgn_module_try_files_done(state))
			return err;
	} else if (module->kind == DRGN_MODULE_LINUX_KERNEL_LOADABLE) {
		err = drgn_module_try_linux_kmod_files(state);
		if (err || drgn_module_try_files_done(state))
			return err;
	// Otherwise, if the module name looks like a path (i.e., it contains a
	// slash), try it. The vDSO is embedded in the kernel and isn't on disk,
	// so there's no point in trying it. Additionally, if we already tried a
	// /proc symlink, we already tried the file that the path is supposed to
	// refer to, so don't try again.
	} else if (module->kind != DRGN_MODULE_VDSO
		   && !tried_proc_symlink
		   && strchr(module->name, '/')) {
		err = drgn_module_try_file_internal(state, module->name, -1,
						    true, NULL);
		if (err || drgn_module_try_files_done(state))
			return err;
	}

	// If we didn't have the build ID before, we might have found the loaded
	// file and gotten a build ID from it. Try to find the debug file by
	// build ID now.
	if (!had_build_id) {
		err = drgn_module_try_files_by_build_id(state);
		if (err || drgn_module_try_files_done(state))
			return err;
	}

	// We might have a loaded file with a .gnu_debuglink. Try to find the
	// corresponding debug file.
	err = drgn_module_try_files_by_gnu_debuglink(state);
	if (err || drgn_module_try_files_done(state))
		return err;
	return NULL;
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
				       "couldn't download %s%s from debuginfod: %m",
				       prog->dbinfo.debuginfod_current_name,
				       prog->dbinfo.debuginfod_current_type);
		} else if (!prog->dbinfo.logged_no_debuginfod) {
			drgn_log_debug(prog,
				       "no debuginfod servers configured; "
				       "try setting DEBUGINFOD_URLS");
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
		drgn_log_debug(prog, "found %s%s in debuginfod cache",
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
#endif // WITH_DEBUGINFOD

static struct drgn_error *
drgn_module_try_download_files_internal(struct drgn_module_try_files_state *state)
{
	struct drgn_module *module = state->module;
	struct drgn_program *prog = module->prog;

	drgn_module_try_files_log(state, "trying to download");

#if WITH_DEBUGINFOD
	if (!prog->dbinfo.debuginfod_client) {
		if (!drgn_have_debuginfod()) {
			if (!prog->dbinfo.logged_no_debuginfod) {
				drgn_log_debug(prog,
					       "debuginfod client library is not installed");
				prog->dbinfo.logged_no_debuginfod = true;
			}
			return NULL;
		}
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

	const void *build_id;
	size_t build_id_len;
	const char *build_id_str =
		drgn_module_try_files_build_id(module, &build_id,
					       &build_id_len);
	if (!build_id_str)
		return NULL;

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
	if (!string_builder_appendf(&sb, "/%s/", build_id_str))
		return &drgn_enomem;
	size_t cache_dir_len = sb.len;

#define try_debuginfod(which)							\
	do {									\
		sb.len = cache_dir_len;						\
		if (!string_builder_append(&sb, #which)				\
		    || !string_builder_null_terminate(&sb))			\
			return &drgn_enomem;					\
										\
		prog->dbinfo.debuginfod_current_name = module->name;		\
		enum {								\
			executable_is_debug = 0,				\
			debuginfo_is_debug = 1,					\
		};								\
		if (module->trying_gnu_debugaltlink)				\
			prog->dbinfo.debuginfod_current_type = " alternate debug info";\
		else if (which##_is_debug)					\
			prog->dbinfo.debuginfod_current_type = " debug info";	\
		else								\
			prog->dbinfo.debuginfod_current_type = "";		\
		prog->dbinfo.debuginfod_have_url = false;			\
		prog->dbinfo.logged_debuginfod_progress = false;		\
		bool restore_sigaction = drgn_prepare_debuginfod_find(prog);	\
		char *path;							\
		int fd = drgn_debuginfod_find_##which(prog->dbinfo.debuginfod_client,\
						      build_id, build_id_len,	\
						      &path);			\
		drgn_finish_debuginfod_find(restore_sigaction);			\
		if (fd == -ENOENT && drgn_cancel_debuginfod) {			\
			/*							\
			 * Before elfutils commit 5527216460c6			\
			 * ("debuginfod-client.c: Skip empty file creation for	\
			 * cancelled queries") (in elfutils 0.190),		\
			 * libdebuginfod has a nasty bug that causes it to	\
			 * cache a cancelled download as a negative hit. Work	\
			 * around it by deleting the cache file.		\
			 */							\
			unlink(sb.str);						\
			return drgn_error_create_os("download cancelled",	\
						    EINTR, NULL);		\
		}								\
		drgn_log_debuginfod_progress(prog->dbinfo.debuginfod_client, -1,\
					     fd);				\
		if (fd >= 0) {							\
			struct drgn_error *err =				\
				drgn_module_try_file_internal(state, path, fd,	\
							      false, NULL);	\
			free(path);						\
			if (err)						\
				return err;					\
		}								\
	} while (0)

	if (state->want_debug)
		try_debuginfod(debuginfo);
	if (state->want_loaded)
		try_debuginfod(executable);
#undef try_debuginfod
#else
	if (!prog->dbinfo.logged_no_debuginfod) {
		drgn_log_debug(prog,
			       "drgn was built without debuginfod support");
		prog->dbinfo.logged_no_debuginfod = true;
	}
#endif
	return NULL;
}

static struct drgn_error *
drgn_module_try_default_files_internal(struct drgn_module_try_files_state *state)
{
	struct drgn_error *err;
	err = drgn_module_try_local_files_internal(state);
	if (err || drgn_module_try_files_done(state))
		return err;
	return drgn_module_try_download_files_internal(state);
}

LIBDRGN_PUBLIC const char * const drgn_default_debug_directories[] = {
	"", ".debug", "/usr/lib/debug", NULL,
};

static bool drgn_module_needs_loaded_file(struct drgn_module *module)
{
	// Linux userspace core dumps usually filter out file-backed mappings
	// (see coredump_filter in core(5)), so we need the loaded file to read
	// the text. Additionally, .eh_frame is in the loaded file and not the
	// debug file.
	//
	// Linux kernel core dumps preserve the main kernel and kernel module
	// text, and the kernel doesn't use .eh_frame, so we don't need the
	// loaded file for the kernel.
	SWITCH_ENUM(module->kind,
	case DRGN_MODULE_MAIN:
		return !(module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL);
	case DRGN_MODULE_SHARED_LIBRARY:
	case DRGN_MODULE_VDSO:
	case DRGN_MODULE_EXTRA:
		return true;
	case DRGN_MODULE_LINUX_KERNEL_LOADABLE:
		return false;
	)
}

static void
drgn_module_try_files_begin(struct drgn_module *module,
			    struct drgn_module_try_files_args *args,
			    struct drgn_module_try_files_state *state)
{
	*state = (struct drgn_module_try_files_state){
		.module = module,
		.debug_directories =
			args->debug_directories
			? args->debug_directories
			: drgn_default_debug_directories,
		.args = args,
	};

	if (module->trying_gnu_debugaltlink) {
		args->loaded_status = DRGN_MODULE_FILE_NOT_NEEDED;
		if (module->trying_gnu_debugaltlink->found) {
			args->debug_status = DRGN_MODULE_FILE_ALREADY_HAD;
		} else {
			args->debug_status = DRGN_MODULE_FILE_SUCCEEDED;
			state->want_debug = true;
		}
		return;
	}

	if (module->loaded_file) {
		args->loaded_status = DRGN_MODULE_FILE_ALREADY_HAD;
	} else if (!drgn_module_needs_loaded_file(module)) {
		args->loaded_status = DRGN_MODULE_FILE_NOT_NEEDED;
	} else if (!args->want_loaded) {
		args->loaded_status = DRGN_MODULE_FILE_NOT_WANTED;
	} else {
		args->loaded_status = DRGN_MODULE_FILE_SUCCEEDED;
		state->want_loaded = true;
	}
	if (module->debug_file) {
		args->debug_status = DRGN_MODULE_FILE_ALREADY_HAD;
	} else if (!args->want_debug) {
		args->debug_status = DRGN_MODULE_FILE_NOT_WANTED;
	} else {
		args->debug_status = DRGN_MODULE_FILE_SUCCEEDED;
		state->want_debug = true;
	}
}

static void drgn_module_try_files_end(struct drgn_module_try_files_state *state)
{
	if (state->want_loaded)
		state->args->loaded_status = DRGN_MODULE_FILE_FAILED;
	if (state->want_debug)
		state->args->debug_status = DRGN_MODULE_FILE_FAILED;
}

#define DRGN_MODULE_TRY_FILES_WRAPPER(name)				\
LIBDRGN_PUBLIC struct drgn_error *					\
drgn_module_try_##name##_files(struct drgn_module *module,		\
			       struct drgn_module_try_files_args *args)	\
{									\
	struct drgn_error *err;						\
	struct drgn_module_try_files_state state;			\
	drgn_module_try_files_begin(module, args, &state);		\
	if (!drgn_module_try_files_done(&state)) {			\
		err = drgn_module_try_##name##_files_internal(&state);	\
		if (err)						\
			return err;					\
	}								\
	drgn_module_try_files_end(&state);				\
	return NULL;							\
}
DRGN_MODULE_TRY_FILES_WRAPPER(default)
DRGN_MODULE_TRY_FILES_WRAPPER(local)
DRGN_MODULE_TRY_FILES_WRAPPER(download)
#undef DRGN_MODULE_TRY_FILES_WRAPPER

LIBDRGN_PUBLIC
struct drgn_error *drgn_module_try_file(struct drgn_module *module,
					const char *path, int fd, bool force,
					struct drgn_module_try_files_args *args)
{
	struct drgn_error *err;
	struct drgn_module_try_files_state state;
	drgn_module_try_files_begin(module, args, &state);
	if (!drgn_module_try_files_done(&state)) {
		drgn_module_try_files_log(&state, "trying provided file as");
		err = drgn_module_try_file_internal(&state, path, fd, !force,
						    NULL);
		if (err)
			return err;
	} else if (fd >= 0) {
		close(fd);
	}
	drgn_module_try_files_end(&state);
	return NULL;
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
					     struct drgn_module **ret)
{
	if (!it->next) {
		*ret = NULL;
		return NULL;
	}
	struct drgn_error *err = it->next(it, ret);
	if (err || !*ret)
		it->next = NULL;
	return err;
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
	size_t lo = 0, hi = it->num_file_segments;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (address < it->file_segments[mid].start)
			hi = mid;
		else
			lo = mid + 1;
	}
	if (lo == 0 || address >= it->file_segments[lo - 1].end)
		return NULL;
	return &it->file_segments[lo - 1];
}

size_t parse_gnu_build_id_from_note(const void *note, size_t note_size,
				    unsigned int align, bool bswap,
				    const void **ret)
{
	Elf32_Nhdr nhdr;
	const char *name;
	const void *desc;
	while (next_elf_note(&note, &note_size, align, bswap, &nhdr, &name,
			     &desc)) {
		if (nhdr.n_namesz == sizeof("GNU")
		    && memcmp(name, "GNU", sizeof("GNU")) == 0
		    && nhdr.n_type == NT_GNU_BUILD_ID
		    && nhdr.n_descsz > 0) {
			*ret = desc;
			return nhdr.n_descsz;
		}
	}
	*ret = NULL;
	return 0;
}

struct drgn_error *find_elf_note(Elf *elf, const char *name, uint32_t type,
				 const void **ret, size_t *size_ret)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum) != 0)
		return drgn_error_libelf();
	size_t name_size = strlen(name) + 1;
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return drgn_error_libelf();
		if (phdr->p_type != PT_NOTE)
			continue;
		Elf_Data *data = elf_getdata_rawchunk(elf, phdr->p_offset,
						      phdr->p_filesz,
						      note_header_type(phdr->p_align));
		if (!data)
			return drgn_error_libelf();
		GElf_Nhdr nhdr;
		size_t offset = 0, name_offset, desc_offset;
		while (offset < data->d_size &&
		       (offset = gelf_getnote(data, offset, &nhdr,
					      &name_offset,
					      &desc_offset))) {
			const char *note_name = (char *)data->d_buf + name_offset;
			if (nhdr.n_namesz == name_size &&
			    memcmp(note_name, name, name_size) == 0 &&
			    nhdr.n_type == type) {
				*ret = (char *)data->d_buf + desc_offset;
				*size_ret = nhdr.n_descsz;
				return NULL;
			}
		}
	}
	*ret = NULL;
	*size_ret = 0;
	return NULL;
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
	to_struct64(ret, Elf32_Ehdr, visit_elf_ehdr_members,
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
			       "couldn't read program header table from at 0x%" PRIx64 ": %s",
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
	copy_struct64(ret,
		      (char *)it->phdrs_buf + i * phentsize,
		      Elf32_Phdr, visit_phdr_members,
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
	copy_struct64(ret, (char *)it->segment_buf + i * dyn_size, Elf32_Dyn,
		      visit_elf_dyn_members,
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

	uint64_t phdr_vaddr, dyn_vaddr, dyn_memsz;
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
				parse_gnu_build_id_from_note(it->segment_buf,
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
					    struct drgn_module **ret)
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

	bool new;
	err = drgn_module_find_or_create_main(prog,
					      segment ? segment->file->path : "",
					      ret, &new);
	if (err || !new)
		return err;
	err = userspace_loaded_module_iterator_read_main_phdrs(it);
	if (err)
		goto delete_module;
	if (it->read_main_phdrs) {
		err = identify_module_from_phdrs(it, *ret, prog->auxv.at_phnum,
						 it->main_bias);
		if (err)
			goto delete_module;
	}
	return NULL;

delete_module:
	drgn_module_delete(*ret);
	return err;
}

static struct drgn_error *
userspace_loaded_module_iterator_yield_vdso(struct userspace_loaded_module_iterator *it,
					    struct drgn_module **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	if (!prog->auxv.at_sysinfo_ehdr) {
		drgn_log_debug(prog, "no vDSO");
		*ret = NULL;
		return NULL;
	}

	drgn_log_debug(prog, "reading vDSO ELF header from AT_SYSINFO_EHDR");
	GElf_Ehdr ehdr;
	err = userspace_loaded_module_iterator_read_ehdr(it,
							 prog->auxv.at_sysinfo_ehdr,
							 &ehdr);
	if (err == &drgn_not_found) {
		*ret = NULL;
		return NULL;
	} else if (err)
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
	if (err == &drgn_not_found) {
		*ret = NULL;
		return NULL;
	} else if (err)
		return err;

	// This is based on the Linux kernel's reference vDSO parser.
	uint64_t bias = prog->auxv.at_sysinfo_ehdr;
	uint64_t dyn_vaddr, dyn_memsz = 0;
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
		*ret = NULL;
		return NULL;
	}
	drgn_log_debug(prog, "vDSO bias is 0x%" PRIx64, bias);
	if (!have_dyn) {
		drgn_log_warning(prog,
				 "can't find vDSO: "
				 "no PT_DYNAMIC header in vDSO program headers");
		*ret = NULL;
		return NULL;
	}
	it->vdso_dyn_vaddr = dyn_vaddr;
	it->have_vdso_dyn = true;

	drgn_log_debug(prog, "reading vDSO dynamic section at 0x%" PRIx64,
		       dyn_vaddr);
	size_t num_dyn;
	err = userspace_loaded_module_iterator_read_dynamic(it, dyn_vaddr,
							    dyn_memsz,
							    &num_dyn);
	if (err == &drgn_not_found) {
		*ret = NULL;
		return NULL;
	} else if (err)
		return err;

	uint64_t dt_strtab, dt_soname;
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
		*ret = NULL;
		return NULL;
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
		*ret = NULL;
		return NULL;
	} else if (err) {
		return err;
	}
	drgn_log_debug(prog, "read vDSO soname \"%s\"", name);

	bool new;
	err = drgn_module_find_or_create_vdso(prog, name, dyn_vaddr, ret, &new);
	if (err || !new)
		return err;

	err = identify_module_from_phdrs(it, *ret, ehdr.e_phnum, bias);
	if (err)
		drgn_module_delete(*ret);
	return err;
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
		to_struct64(unique_struct64p, type32, visit_members,		\
			    unique_is_64_bit,					\
			    drgn_platform_bswap(&unique_prog->platform));	\
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
		    struct drgn_module **ret)
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

		bool new;
		err = drgn_module_find_or_create_shared_library(prog, name,
								link_map.l_ld,
								ret, &new);
		if (err || !new)
			return err;

		struct drgn_mapped_file_segment *segment =
			find_mapped_file_segment(it, link_map.l_ld);
		if (segment) {
			err = identify_module_from_link_map(it, *ret,
							    segment->file,
							    link_map.l_addr);
			if (err) {
				drgn_module_delete(*ret);
				return err;
			}
		} else {
			drgn_log_debug(prog,
				       "couldn't find mapped file segment containing l_ld");
		}
		return NULL;
	}
}

static struct drgn_error *
userspace_loaded_module_iterator_next(struct drgn_module_iterator *_it,
				      struct drgn_module **ret)
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
		return userspace_loaded_module_iterator_yield_main(it, ret);
	case USERSPACE_LOADED_MODULE_ITERATOR_STATE_VDSO:
		it->state = USERSPACE_LOADED_MODULE_ITERATOR_STATE_R_DEBUG;
		err = userspace_loaded_module_iterator_yield_vdso(it, ret);
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
		return yield_from_link_map(it, ret);
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
		    struct drgn_mapped_file_segments *segments, char *line,
		    size_t line_len)
{
	struct drgn_program *prog = it->u.it.prog;

	uint64_t segment_start, segment_end, segment_file_offset;
	unsigned int dev_major, dev_minor;
	uint64_t ino;
	int map_name_len, path_index;
	if (sscanf(line,
		   "%" SCNx64 "-%" SCNx64 "%n %*s %" SCNx64 " %x:%x %" SCNu64 " %n",
		   &segment_start, &segment_end, &map_name_len,
		   &segment_file_offset, &dev_major, &dev_minor, &ino,
		   &path_index) != 6) {
		return drgn_error_format(DRGN_ERROR_OTHER, "couldn't parse %s",
					 maps_path);
	}
	// Skip anonymous mappings.
	if (ino == 0)
		return NULL;

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
			 "%" PRIx64 "-%" PRIx64, segment_start, segment_end);

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
	return drgn_add_mapped_file_segment(segments, segment_start, segment_end,
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
	struct drgn_mapped_file_segments segments =
		DRGN_MAPPED_FILE_SEGMENTS_INIT;
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
					  &logged_stat_eperm, &segments, line,
					  len);
		if (err)
			break;
	}
	if (err) {
		drgn_mapped_file_segments_abort(&segments);
	} else {
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
	for (struct process_mapped_files_iterator files_it =
	     process_mapped_files_first(&it->files);
	     files_it.entry; files_it = process_mapped_files_next(files_it)) {
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
	err = find_elf_note(prog->core, "CORE", NT_FILE, &note, &note_size);
	if (err)
		return err;
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
		copy_struct64(&segment,
			      (char *)note
			      + (is_64_bit
				 ? 16 + i * sizeof(struct nt_file_segment64)
				 : 8 + i * sizeof(struct nt_file_segment32)),
			      struct nt_file_segment32,
			      visit_nt_file_segment_members, is_64_bit,
			      bb.bswap);
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
	for (struct core_mapped_files_iterator files_it =
	     core_mapped_files_first(&it->files);
	     files_it.entry;
	     files_it = core_mapped_files_next(files_it))
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
null_loaded_module_iterator_create(struct drgn_program *prog,
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
	else if (prog->flags & DRGN_PROGRAM_IS_LIVE)
		return process_loaded_module_iterator_create(prog, ret);
	else if (prog->core)
		return core_loaded_module_iterator_create(prog, ret);
	else
		return null_loaded_module_iterator_create(prog, ret);
}

struct load_debug_info_file {
	const char *path;
	// We only keep this to keep load_debug_info_candidate::build_id alive
	// without needing to copy it. If we add a drgn_module_try_files API
	// that allows providing an Elf handle, we could pass it down.
	Elf *elf;
	// This may be consumed and set to -1.
	int fd;
};

DEFINE_VECTOR(load_debug_info_file_vector, struct load_debug_info_file);

struct load_debug_info_candidate {
	const void *build_id;
	size_t build_id_len;
	struct load_debug_info_file_vector files;
	bool matched;
};

static struct nstring
load_debug_info_candidate_key(const struct load_debug_info_candidate *candidate)
{
	return (struct nstring){ candidate->build_id, candidate->build_id_len };
}

DEFINE_HASH_TABLE(load_debug_info_candidate_table,
		  struct load_debug_info_candidate,
		  load_debug_info_candidate_key, nstring_hash_pair, nstring_eq);

struct load_debug_info_state {
	struct drgn_program *prog;
	struct load_debug_info_candidate_table candidates;
	// Number of entries in the candidates table that haven't matched any
	// modules.
	size_t unmatched_candidates;
	bool load_default;
	bool load_main;
};

static struct drgn_error *
load_debug_info_add_candidate(struct load_debug_info_state *state,
			      const char *path)
{
	struct drgn_program *prog = state->prog;

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
	ssize_t build_id_len = dwelf_elf_gnu_build_id(elf, &build_id);
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

	struct load_debug_info_candidate candidate = {
		.build_id = build_id,
		.build_id_len = build_id_len,
	};
	struct load_debug_info_candidate_table_iterator it;
	int r = load_debug_info_candidate_table_insert(&state->candidates,
						       &candidate, &it);
	if (r < 0)
		return &drgn_enomem;
	if (r > 0) {
		load_debug_info_file_vector_init(&it.entry->files);
		state->unmatched_candidates++;
	}

	struct load_debug_info_file file = {
		.path = path,
		.fd = fd,
		.elf = elf,
	};
	if (!load_debug_info_file_vector_append(&it.entry->files, &file))
		return &drgn_enomem;
	// fd and elf are owned by state now.
	fd = -1;
	elf = NULL;
	return NULL;
}

static void load_debug_info_state_deinit(struct load_debug_info_state *state)
{
	for (struct load_debug_info_candidate_table_iterator it =
	     load_debug_info_candidate_table_first(&state->candidates);
	     it.entry;
	     it = load_debug_info_candidate_table_next(it)) {
		vector_for_each(load_debug_info_file_vector, file,
				&it.entry->files) {
			elf_end(file->elf);
			if (file->fd >= 0)
				close(file->fd);
		}
		load_debug_info_file_vector_deinit(&it.entry->files);
	}
	load_debug_info_candidate_table_deinit(&state->candidates);
}

static struct drgn_error *
load_debug_info_try_files(struct drgn_module *module,
			  const void *build_id, size_t build_id_len,
			  struct drgn_module_try_files_args *args,
			  bool *missing)
{
	struct drgn_error *err;
	struct load_debug_info_state *state = args->arg;

	struct nstring key = { build_id, build_id_len };
	struct load_debug_info_candidate *candidate;
	if (build_id_len > 0
	    && (candidate =
		load_debug_info_candidate_table_search(&state->candidates,
						       &key).entry)) {
		if (!candidate->matched) {
			state->unmatched_candidates--;
			candidate->matched = true;
		}
		vector_for_each(load_debug_info_file_vector, file,
				&candidate->files) {
			err = drgn_module_try_file(module, file->path, file->fd,
						   false, args);
			// drgn_module_try_file took ownership of file->fd. In
			// the unlikely scenario that another module has the
			// same build ID, we'll just have to reopen it by path.
			file->fd = -1;
			if (err)
				return err;
			if (args->loaded_status != DRGN_MODULE_FILE_FAILED
			    && args->debug_status != DRGN_MODULE_FILE_FAILED)
				return NULL;
		}
	}

	if (state->load_default
	    || (state->load_main
		&& drgn_module_kind(module) == DRGN_MODULE_MAIN)) {
		err = drgn_module_try_default_files(module, args);
		if (err)
			return err;
		if (missing
		    && (args->loaded_status == DRGN_MODULE_FILE_FAILED
			|| args->debug_status == DRGN_MODULE_FILE_FAILED)) {
			const char *missing_loaded = "";
			if (args->loaded_status == DRGN_MODULE_FILE_FAILED) {
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
			const char *missing_debug =
				args->debug_status == DRGN_MODULE_FILE_FAILED
				? "debugging symbols" : "";
			drgn_log_warning(module->prog,
					 "missing %s%s%s for %s",
					 missing_loaded,
					 missing_loaded[0] && missing_debug[0]
					 ? " and ": "",
					 missing_debug, module->name);
			*missing = true;
		}
	}
	return NULL;
}

static struct drgn_error *
load_debug_info_need_gnu_debugaltlink_file(struct drgn_module *module,
					   struct drgn_module_try_files_args *args,
					   const char *debug_file_path,
					   const char *debugaltlink_path,
					   const void *build_id,
					   size_t build_id_len,
					   const char *build_id_str)
{
	return load_debug_info_try_files(module, build_id, build_id_len, args,
					 NULL);
}

static inline void drgn_module_iterator_destroyp(struct drgn_module_iterator **itp)
{
	drgn_module_iterator_destroy(*itp);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_debug_info(struct drgn_program *prog, const char **paths,
			     size_t n, bool load_default, bool load_main)
{
	struct drgn_error *err;

	_cleanup_(load_debug_info_state_deinit) struct load_debug_info_state state = {
		.prog = prog,
		.candidates = HASH_TABLE_INIT,
		.load_default = load_default,
		.load_main = load_main,
	};
	for (size_t i = 0; i < n; i++) {
		err = load_debug_info_add_candidate(&state, paths[i]);
		if (err)
			return err;
	}

	if (load_debug_info_candidate_table_empty(&state.candidates)
	    && !load_default && !load_main) {
		// We don't have any files to try, so don't create any modules.
		return NULL;
	}

	_cleanup_(drgn_module_iterator_destroyp)
		struct drgn_module_iterator *it = NULL;
	err = drgn_loaded_module_iterator_create(prog, &it);
	if (err)
		return err;
	struct drgn_module *module;
	bool missing = false;
	while (!(err = drgn_module_iterator_next(it, &module)) && module) {
		struct drgn_module_try_files_args args = {
			.want_loaded = true,
			.want_debug = true,
			.arg = &state,
			.need_gnu_debugaltlink_file =
				load_debug_info_need_gnu_debugaltlink_file,
		};
		const void *build_id;
		size_t build_id_len;
		drgn_module_build_id(module, &build_id, &build_id_len);
		err = load_debug_info_try_files(module, build_id, build_id_len,
						&args, &missing);
		if (err)
			return err;
		// If we are only trying files for the main module (i.e., if
		// we're not loading all default debug info and any provided
		// files were all for the main module), then we only want to
		// create the main module.
		if (drgn_module_kind(module) == DRGN_MODULE_MAIN
		    && !load_default && state.unmatched_candidates == 0) {
			err = NULL;
			break;
		}
	}
	if (err)
		return err;

	if (state.unmatched_candidates != 0) {
		for (struct load_debug_info_candidate_table_iterator cit =
		     load_debug_info_candidate_table_first(&state.candidates);
		     cit.entry;
		     cit = load_debug_info_candidate_table_next(cit)) {
			vector_for_each(load_debug_info_file_vector, file,
					&cit.entry->files) {
				drgn_log_warning(prog,
						 "%s did not match any loaded modules; ignoring",
						 file->path);
			}
		}
	}

	if (missing) {
		return drgn_error_create(DRGN_ERROR_MISSING_DEBUG_INFO,
					"missing some debugging symbols; see https://drgn.readthedocs.io/en/latest/getting_debugging_symbols.html");
	}

	return NULL;
}

#if 0
struct elf_symbols_search_arg {
	const char *name;
	uint64_t address;
	enum drgn_find_symbol_flags flags;
	struct drgn_error *err;
	struct drgn_symbol_result_builder *builder;
};

static bool elf_symbol_match(struct elf_symbols_search_arg *arg, GElf_Addr addr,
			 const GElf_Sym *sym, const char *name)
{
	if ((arg->flags & DRGN_FIND_SYMBOL_NAME) && strcmp(name, arg->name) != 0)
		return false;
	if ((arg->flags & DRGN_FIND_SYMBOL_ADDR) &&
	    (arg->address < addr || arg->address >= addr + sym->st_size))
		return false;
	return true;
}

static bool elf_symbol_store_match(struct elf_symbols_search_arg *arg,
				   GElf_Sym *elf_sym, GElf_Addr addr,
				   const char *name)
{
	struct drgn_symbol *sym;
	if (arg->flags == (DRGN_FIND_SYMBOL_ONE | DRGN_FIND_SYMBOL_NAME)) {
		int binding = GELF_ST_BIND(elf_sym->st_info);
		/*
		 * The order of precedence is
		 * GLOBAL = UNIQUE > WEAK > LOCAL = everything else
		 *
		 * If we found a global or unique symbol, return it
		 * immediately. If we found a weak symbol, then save it,
		 * which may overwrite a previously found weak or local
		 * symbol. Otherwise, save the symbol only if we haven't
		 * found another symbol.
		 */
		if (binding != STB_GLOBAL
		    && binding != STB_GNU_UNIQUE
		    && binding != STB_WEAK
		    && drgn_symbol_result_builder_count(arg->builder) > 0)
			return false;
		sym = malloc(sizeof(*sym));
		if (!sym) {
			arg->err = &drgn_enomem;
			return true;
		}
		drgn_symbol_from_elf(name, addr, elf_sym, sym);
		if (!drgn_symbol_result_builder_add(arg->builder, sym)) {
			arg->err = &drgn_enomem;
			drgn_symbol_destroy(sym);
		}

		/* Abort on error, or short-circuit if we found a global or
		 * unique symbol */
		return (arg->err || sym->binding == DRGN_SYMBOL_BINDING_GLOBAL
			|| sym->binding == DRGN_SYMBOL_BINDING_UNIQUE);
	} else {
		sym = malloc(sizeof(*sym));
		if (!sym) {
			arg->err = &drgn_enomem;
			return true;
		}
		drgn_symbol_from_elf(name, addr, elf_sym, sym);
		if (!drgn_symbol_result_builder_add(arg->builder, sym)) {
			arg->err = &drgn_enomem;
			drgn_symbol_destroy(sym);
		}
		/* Abort on error, or short-circuit for single lookup */
		return (arg->err || (arg->flags & DRGN_FIND_SYMBOL_ONE));
	}
}

static int elf_symbols_search_cb(Dwfl_Module *dwfl_module, void **userdatap,
			     const char *module_name, Dwarf_Addr base,
			     void *cb_arg)
{
	struct elf_symbols_search_arg *arg = cb_arg;

	int symtab_len = dwfl_module_getsymtab(dwfl_module);
	if (symtab_len == -1)
		return DWARF_CB_OK;

	/* Ignore the zeroth null symbol */
	for (int i = 1; i < symtab_len; i++) {
		GElf_Sym elf_sym;
		GElf_Addr elf_addr;
		const char *name = dwfl_module_getsym_info(dwfl_module, i,
							   &elf_sym, &elf_addr,
							   NULL, NULL, NULL);
		if (!name || !elf_symbol_match(arg, elf_addr, &elf_sym, name))
			continue;
		if (elf_symbol_store_match(arg, &elf_sym, elf_addr, name))
			return DWARF_CB_ABORT;
	}
	return DWARF_CB_OK;
}
#endif

static struct drgn_error *
elf_symbols_search(const char *name, uint64_t addr, enum drgn_find_symbol_flags flags,
		   void *data, struct drgn_symbol_result_builder *builder)
{
#if 0
	Dwfl_Module *dwfl_module = NULL;
	struct drgn_program *prog = data;
	struct elf_symbols_search_arg arg = {
		.name = name,
		.address = addr,
		.flags = flags,
		.err = NULL,
		.builder = builder,
	};

	if (arg.flags & DRGN_FIND_SYMBOL_ADDR) {
		dwfl_module = dwfl_addrmodule(prog->dbinfo.dwfl, arg.address);
		if (!dwfl_module)
			return NULL;
	}

	if ((arg.flags & (DRGN_FIND_SYMBOL_ADDR | DRGN_FIND_SYMBOL_ONE))
	    == (DRGN_FIND_SYMBOL_ADDR | DRGN_FIND_SYMBOL_ONE)) {
		GElf_Off offset;
		GElf_Sym elf_sym;
		const char *sym_name = dwfl_module_addrinfo(dwfl_module, addr,
							    &offset, &elf_sym,
							    NULL, NULL, NULL);
		if (!sym_name)
			return NULL;
		struct drgn_symbol *sym = malloc(sizeof(*sym));
		if (!sym)
			return &drgn_enomem;
		drgn_symbol_from_elf(sym_name, addr - offset, &elf_sym, sym);
		if (!drgn_symbol_result_builder_add(builder, sym)) {
			arg.err = &drgn_enomem;
			drgn_symbol_destroy(sym);
		}
	} else if (dwfl_module) {
		elf_symbols_search_cb(dwfl_module, NULL, NULL, 0, &arg);
	} else {
		dwfl_getmodules(prog->dbinfo.dwfl, elf_symbols_search_cb, &arg, 0);
	}
	return arg.err;
#endif
	return NULL; // TODO
}

struct drgn_module *drgn_module_by_address(struct drgn_debug_info *dbinfo,
					   uint64_t address)
{
	struct drgn_module_address_tree_iterator it =
		drgn_module_address_tree_search_le(&dbinfo->modules_by_address,
						   &address);
	if (!it.entry || address >= it.entry->end)
		return NULL;
	return it.entry;
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
#if WITH_DEBUGINFOD
	dbinfo->debuginfod_client = NULL;
#endif
	drgn_dwarf_info_init(dbinfo);
}

void drgn_debug_info_deinit(struct drgn_debug_info *dbinfo)
{
	depmod_index_deinit(&dbinfo->modules_dep);
	drgn_dwarf_info_deinit(dbinfo);
	for (auto it = drgn_module_table_first(&dbinfo->modules); it.entry;
	     it = drgn_module_table_next(it))
		drgn_module_destroy(*it.entry);
	drgn_module_table_deinit(&dbinfo->modules);
#if WITH_DEBUGINFOD
	if (dbinfo->debuginfod_client)
		drgn_debuginfod_end(dbinfo->debuginfod_client);
#endif
}

struct drgn_elf_file *drgn_module_find_dwarf_file(struct drgn_module *module,
						  Dwarf *dwarf)
{
	if (!module->debug_file)
		return NULL;
	if (dwarf == module->debug_file->_dwarf)
		return module->debug_file;
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

	if (prog->prefer_orc_unwinder) {
		if (can_use_debug_file) {
			*file_ret = module->debug_file;
			err = drgn_module_find_orc_cfi(module, pc, row_ret,
						       interrupted_ret,
						       ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
			err = drgn_module_find_dwarf_cfi(module, pc, row_ret,
							 interrupted_ret,
							 ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
		}
		if (can_use_loaded_file) {
			*file_ret = module->loaded_file;
			return drgn_module_find_eh_cfi(module, pc, row_ret,
						       interrupted_ret,
						       ret_addr_regno_ret);
		}
	} else {
		if (can_use_debug_file) {
			*file_ret = module->debug_file;
			err = drgn_module_find_dwarf_cfi(module, pc, row_ret,
							 interrupted_ret,
							 ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
		}
		if (can_use_loaded_file) {
			*file_ret = module->loaded_file;
			err = drgn_module_find_eh_cfi(module, pc, row_ret,
						      interrupted_ret,
						      ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
		}
		if (can_use_debug_file) {
			*file_ret = module->debug_file;
			return drgn_module_find_orc_cfi(module, pc, row_ret,
							interrupted_ret,
							ret_addr_regno_ret);
		}
	}
	return &drgn_not_found;
}
