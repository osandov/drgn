// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <assert.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwelf.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "internal.h"
#include "dwarf_index.h"
#include "mread.h"
#include "siphash.h"
#include "string_builder.h"

DEFINE_VECTOR_FUNCTIONS(dwfl_module_vector)
DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_module_vector)

static inline struct hash_pair
drgn_dwarf_module_hash(const struct drgn_dwarf_module_key *key)
{
	size_t hash;

	hash = cityhash_size_t(key->build_id, key->build_id_len);
	hash = hash_combine(hash, key->start);
	hash = hash_combine(hash, key->end);
	return hash_pair_from_avalanching_hash(hash);
}
static inline bool drgn_dwarf_module_eq(const struct drgn_dwarf_module_key *a,
					const struct drgn_dwarf_module_key *b)
{
	return (a->build_id_len == b->build_id_len &&
		(a->build_id_len == 0 ||
		 memcmp(a->build_id, b->build_id, a->build_id_len) == 0) &&
		a->start == b->start && a->end == b->end);
}
DEFINE_HASH_TABLE_FUNCTIONS(drgn_dwarf_module_table, drgn_dwarf_module_hash,
			    drgn_dwarf_module_eq)

DEFINE_HASH_TABLE_FUNCTIONS(c_string_set, c_string_hash, c_string_eq)

/**
 * @c Dwfl_Callbacks::find_elf() implementation.
 *
 * Ideally we'd use @c dwfl_report_elf() instead, but that doesn't take an @c
 * Elf handle, which we need for a couple of reasons:
 *
 * - We usually already have the @c Elf handle open in order to identify the
 *   file.
 * - For kernel modules, we set the section addresses in the @c Elf handle
 *   ourselves instead of using @c Dwfl_Callbacks::section_address().
 *
 * Additionally, there's a special case for vmlinux. It is usually an @c ET_EXEC
 * ELF file, but when KASLR is enabled, it needs to be handled like an @c ET_DYN
 * file. libdwfl has a hack for this when @c dwfl_report_module() is used, but
 * @ref dwfl_report_elf() bypasses this hack.
 *
 * So, we're stuck using @c dwfl_report_module() and this dummy callback.
 */
static int drgn_dwfl_find_elf(Dwfl_Module *dwfl_module, void **userdatap,
			      const char *name, Dwarf_Addr base,
			      char **file_name, Elf **elfp)
{
	struct drgn_dwfl_module_userdata *userdata = *userdatap;
	int fd;

	/*
	 * libdwfl consumes the returned path, file descriptor, and ELF handle,
	 * so clear the fields.
	 */
	*file_name = userdata->path;
	fd = userdata->fd;
	*elfp = userdata->elf;
	userdata->path = NULL;
	userdata->fd = -1;
	userdata->elf = NULL;
	return fd;
}

/*
 * Uses drgn_dwfl_find_elf() if the ELF file was reported directly and falls
 * back to dwfl_linux_proc_find_elf() otherwise.
 */
static int drgn_dwfl_linux_proc_find_elf(Dwfl_Module *dwfl_module,
					 void **userdatap, const char *name,
					 Dwarf_Addr base, char **file_name,
					 Elf **elfp)
{
	struct drgn_dwfl_module_userdata *userdata = *userdatap;

	if (userdata->elf) {
		return drgn_dwfl_find_elf(dwfl_module, userdatap, name, base,
					  file_name, elfp);
	}
	return dwfl_linux_proc_find_elf(dwfl_module, userdatap, name, base,
					file_name, elfp);
}

/*
 * Uses drgn_dwfl_find_elf() if the ELF file was reported directly and falls
 * back to dwfl_build_id_find_elf() otherwise.
 */
static int drgn_dwfl_build_id_find_elf(Dwfl_Module *dwfl_module,
				       void **userdatap, const char *name,
				       Dwarf_Addr base, char **file_name,
				       Elf **elfp)
{
	struct drgn_dwfl_module_userdata *userdata = *userdatap;

	if (userdata->elf) {
		return drgn_dwfl_find_elf(dwfl_module, userdatap, name, base,
					  file_name, elfp);
	}
	return dwfl_build_id_find_elf(dwfl_module, userdatap, name, base,
				      file_name, elfp);
}

/**
 * @c Dwfl_Callbacks::section_address() implementation.
 *
 * We set the section header @c sh_addr in memory instead of using this, but
 * libdwfl requires the callback pointer to be non-@c NULL. It will be called
 * for any sections that still have a zero @c sh_addr, meaning they are not
 * present in memory.
 */
static int drgn_dwfl_section_address(Dwfl_Module *module, void **userdatap,
				     const char *name, Dwarf_Addr base,
				     const char *secname, Elf32_Word shndx,
				     const GElf_Shdr *shdr, Dwarf_Addr *addr)
{
	*addr = -1;
	return DWARF_CB_OK;
}

const Dwfl_Callbacks drgn_dwfl_callbacks = {
	.find_elf = drgn_dwfl_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
	.section_address = drgn_dwfl_section_address,
};

const Dwfl_Callbacks drgn_linux_proc_dwfl_callbacks = {
	.find_elf = drgn_dwfl_linux_proc_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
	.section_address = drgn_dwfl_section_address,
};

const Dwfl_Callbacks drgn_userspace_core_dump_dwfl_callbacks = {
	.find_elf = drgn_dwfl_build_id_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
	.section_address = drgn_dwfl_section_address,
};

/*
 * The DWARF abbreviation table gets translated into a series of instructions.
 * An instruction <= INSN_MAX_SKIP indicates a number of bytes to be skipped
 * over. The next few instructions mean that the corresponding attribute can be
 * skipped over. The remaining instructions indicate that the corresponding
 * attribute should be parsed. Finally, every sequence of instructions
 * corresponding to a DIE is terminated by a zero byte followed by the DIE
 * flags, which are a bitmask of flags combined with the DWARF tag (which may be
 * set to zero if the tag is not of interest); see DIE_FLAG_*.
 */
enum {
	INSN_MAX_SKIP = 226,
	ATTRIB_BLOCK1,
	ATTRIB_BLOCK2,
	ATTRIB_BLOCK4,
	ATTRIB_EXPRLOC,
	ATTRIB_LEB128,
	ATTRIB_STRING,
	ATTRIB_SIBLING_REF1,
	ATTRIB_SIBLING_REF2,
	ATTRIB_SIBLING_REF4,
	ATTRIB_SIBLING_REF8,
	ATTRIB_SIBLING_REF_UDATA,
	ATTRIB_NAME_STRP4,
	ATTRIB_NAME_STRP8,
	ATTRIB_NAME_STRING,
	ATTRIB_STMT_LIST_LINEPTR4,
	ATTRIB_STMT_LIST_LINEPTR8,
	ATTRIB_DECL_FILE_DATA1,
	ATTRIB_DECL_FILE_DATA2,
	ATTRIB_DECL_FILE_DATA4,
	ATTRIB_DECL_FILE_DATA8,
	ATTRIB_DECL_FILE_UDATA,
	ATTRIB_DECLARATION_FLAG,
	ATTRIB_SPECIFICATION_REF1,
	ATTRIB_SPECIFICATION_REF2,
	ATTRIB_SPECIFICATION_REF4,
	ATTRIB_SPECIFICATION_REF8,
	ATTRIB_SPECIFICATION_REF_UDATA,
	ATTRIB_SPECIFICATION_REF_ADDR4,
	ATTRIB_SPECIFICATION_REF_ADDR8,
	ATTRIB_MAX_INSN = ATTRIB_SPECIFICATION_REF_ADDR8,
};

enum {
	/* Mask of tags that we care about. */
	DIE_FLAG_TAG_MASK = 0x3f,
	/* The remaining bits can be used for other purposes. */
	DIE_FLAG_DECLARATION = 0x40,
	DIE_FLAG_CHILDREN = 0x80,
};

DEFINE_VECTOR(uint8_vector, uint8_t)
DEFINE_VECTOR(uint32_vector, uint32_t)
DEFINE_VECTOR(uint64_vector, uint64_t)

struct drgn_dwarf_index_cu {
	struct drgn_dwfl_module_userdata *userdata;
	const char *ptr;
	size_t unit_length;
	uint64_t debug_abbrev_offset;
	uint8_t version;
	uint8_t address_size;
	bool is_64_bit;
	bool bswap;
	/*
	 * This is indexed on the DWARF abbreviation code minus one. It maps the
	 * abbreviation code to an index in abbrev_insns where the instruction
	 * stream for that code begins.
	 *
	 * Technically, abbreviation codes don't have to be sequential. In
	 * practice, GCC and Clang seem to always generate sequential codes
	 * starting at one, so we can get away with a flat array.
	 */
	uint32_t *abbrev_decls;
	size_t num_abbrev_decls;
	uint8_t *abbrev_insns;
	uint64_t *file_name_hashes;
	size_t num_file_names;
};

DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_cu_vector)

/* DIE which needs to be indexed. */
struct drgn_dwarf_index_pending_die {
	/* Compilation unit containing DIE. */
	struct drgn_dwarf_index_cu *cu;
	/* Offset of DIE in .debug_info. */
	size_t offset;
};

DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_pending_die_vector)

static inline const char *section_ptr(Elf_Data *data, size_t offset)
{
	if (offset > data->d_size)
		return NULL;
	return (const char *)data->d_buf + offset;
}

static inline const char *section_end(Elf_Data *data)
{
	return (const char *)data->d_buf + data->d_size;
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_dwarf_index_die_map, string_hash, string_eq)
DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_die_vector)
DEFINE_HASH_TABLE_FUNCTIONS(drgn_dwarf_index_specification_map,
			    hash_pair_int_type, hash_table_scalar_eq)

static inline size_t hash_pair_to_shard(struct hash_pair hp)
{
	/*
	 * The 8 most significant bits of the hash are used as the F14 tag, so
	 * we don't want to use those for sharding.
	 */
	return ((hp.first >>
		 (8 * sizeof(size_t) - 8 - DRGN_DWARF_INDEX_SHARD_BITS)) &
		(((size_t)1 << DRGN_DWARF_INDEX_SHARD_BITS) - 1));
}

static inline struct drgn_error *drgn_eof(void)
{
	return drgn_error_create(DRGN_ERROR_OTHER,
				 "debug information is truncated");
}

static inline bool mread_skip_leb128(const char **ptr, const char *end)
{
	while (*ptr < end) {
		if (!(*(const uint8_t *)(*ptr)++ & 0x80))
			return true;
	}
	return false;
}

static inline struct drgn_error *mread_uleb128(const char **ptr,
					       const char *end, uint64_t *value)
{
	int shift = 0;
	*value = 0;
	while (*ptr < end) {
		uint8_t byte = *(const uint8_t *)*ptr;
		(*ptr)++;
		if (shift == 63 && byte > 1) {
			return drgn_error_create(DRGN_ERROR_OVERFLOW,
						 "ULEB128 overflowed unsigned 64-bit integer");
		}
		*value |= (uint64_t)(byte & 0x7f) << shift;
		shift += 7;
		if (!(byte & 0x80))
			return NULL;
	}
	return drgn_eof();
}

static inline struct drgn_error *mread_uleb128_into_size_t(const char **ptr,
							   const char *end,
							   size_t *value)
{
	struct drgn_error *err;
	uint64_t tmp;

	if ((err = mread_uleb128(ptr, end, &tmp)))
		return err;

	if (tmp > SIZE_MAX)
		return drgn_eof();
	*value = tmp;
	return NULL;
}

static void drgn_dwarf_module_destroy(struct drgn_dwarf_module *module)
{
	if (module) {
		dwfl_module_vector_deinit(&module->dwfl_modules);
		free(module->name);
		free(module->build_id);
		free(module);
	}
}

static void
drgn_dwfl_module_userdata_destroy(struct drgn_dwfl_module_userdata *userdata)
{
	if (userdata) {
		elf_end(userdata->elf);
		if (userdata->fd != -1)
			close(userdata->fd);
		free(userdata->path);
		free(userdata);
	}
}

struct drgn_dwfl_module_removed_arg {
	Dwfl *dwfl;
	bool finish_indexing;
	bool free_all;
};

static int drgn_dwfl_module_removed(Dwfl_Module *dwfl_module, void *userdatap,
				    const char *name, Dwarf_Addr base,
				    void *_arg)
{
	struct drgn_dwfl_module_removed_arg *arg = _arg;
	/*
	 * userdatap is actually a void ** like for the other libdwfl callbacks,
	 * but dwfl_report_end() has the wrong signature for the removed
	 * callback.
	 */
	struct drgn_dwfl_module_userdata *userdata = *(void **)userdatap;

	if (arg->finish_indexing && userdata &&
	    userdata->state == DRGN_DWARF_MODULE_INDEXING)
		userdata->state = DRGN_DWARF_MODULE_INDEXED;
	if (arg->free_all || !userdata ||
	    userdata->state != DRGN_DWARF_MODULE_INDEXED) {
		drgn_dwfl_module_userdata_destroy(userdata);
	} else {
		Dwarf_Addr end;

		/*
		 * The module was already indexed. Report it again so libdwfl
		 * doesn't remove it.
		 */
		dwfl_module_info(dwfl_module, NULL, NULL, &end, NULL, NULL,
				 NULL, NULL);
		dwfl_report_module(arg->dwfl, name, base, end);
	}
	return DWARF_CB_OK;
}

static void drgn_dwarf_module_finish_indexing(struct drgn_dwarf_index *dindex,
					      struct drgn_dwarf_module *module)
{
	module->state = DRGN_DWARF_MODULE_INDEXED;
	/*
	 * We don't need this anymore (but reinitialize it to empty so that
	 * drgn_dwarf_index_get_unindexed() skips this module).
	 */
	dwfl_module_vector_deinit(&module->dwfl_modules);
	dwfl_module_vector_init(&module->dwfl_modules);
	if (module->name) {
		int ret;

		ret = c_string_set_insert(&dindex->names,
					  (const char **)&module->name, NULL);
		/* drgn_dwarf_index_get_unindexed() should've reserved enough for us. */
		assert(ret != -1);
	}
}

static void drgn_dwarf_index_free_modules(struct drgn_dwarf_index *dindex,
					  bool finish_indexing, bool free_all)
{
	struct drgn_dwfl_module_removed_arg arg = {
		.dwfl = dindex->dwfl,
		.finish_indexing = finish_indexing,
		.free_all = free_all,
	};
	struct drgn_dwarf_module_table_iterator it;
	size_t i;

	for (it = drgn_dwarf_module_table_first(&dindex->module_table);
	     it.entry; ) {
		struct drgn_dwarf_module *module = *it.entry;

		if (finish_indexing &&
		    module->state == DRGN_DWARF_MODULE_INDEXING)
			drgn_dwarf_module_finish_indexing(dindex, module);
		if (free_all || module->state != DRGN_DWARF_MODULE_INDEXED) {
			it = drgn_dwarf_module_table_delete_iterator(&dindex->module_table,
								     it);
			drgn_dwarf_module_destroy(module);
		} else {
			it = drgn_dwarf_module_table_next(it);
		}
	}

	for (i = dindex->no_build_id.size; i-- > 0; ) {
		struct drgn_dwarf_module *module = dindex->no_build_id.data[i];

		if (finish_indexing &&
		    module->state == DRGN_DWARF_MODULE_INDEXING)
			drgn_dwarf_module_finish_indexing(dindex, module);
		if (free_all || module->state != DRGN_DWARF_MODULE_INDEXED) {
			dindex->no_build_id.size--;
			if (i != dindex->no_build_id.size) {
				dindex->no_build_id.data[i] =
					dindex->no_build_id.data[dindex->no_build_id.size];
			}
			drgn_dwarf_module_destroy(module);
		}
	}

	dwfl_report_begin(dindex->dwfl);
	dwfl_report_end(dindex->dwfl, drgn_dwfl_module_removed, &arg);
}

static void
drgn_dwarf_index_namespace_init(struct drgn_dwarf_index_namespace *ns,
				struct drgn_dwarf_index *dindex)
{
	for (size_t i = 0; i < ARRAY_SIZE(ns->shards); i++) {
		struct drgn_dwarf_index_shard *shard = &ns->shards[i];
		omp_init_lock(&shard->lock);
		drgn_dwarf_index_die_map_init(&shard->map);
		drgn_dwarf_index_die_vector_init(&shard->dies);
	}
	ns->dindex = dindex;
	drgn_dwarf_index_pending_die_vector_init(&ns->pending_dies);
	ns->saved_err = NULL;
}

struct drgn_error *drgn_dwarf_index_init(struct drgn_dwarf_index *dindex,
					 const Dwfl_Callbacks *callbacks)
{
	dindex->dwfl = dwfl_begin(callbacks);
	if (!dindex->dwfl)
		return drgn_error_libdwfl();
	drgn_dwarf_index_namespace_init(&dindex->global, dindex);
	drgn_dwarf_index_specification_map_init(&dindex->specifications);
	drgn_dwarf_index_cu_vector_init(&dindex->cus);
	memset(&dindex->errors, 0, sizeof(dindex->errors));
	dindex->num_errors = 0;
	const char *max_errors = getenv("DRGN_MAX_DEBUG_INFO_ERRORS");
	if (max_errors)
		dindex->max_errors = atoi(max_errors);
	else
		dindex->max_errors = 5;
	drgn_dwarf_module_table_init(&dindex->module_table);
	drgn_dwarf_module_vector_init(&dindex->no_build_id);
	c_string_set_init(&dindex->names);
	return NULL;
}

static void drgn_dwarf_index_cu_deinit(struct drgn_dwarf_index_cu *cu)
{
	free(cu->file_name_hashes);
	free(cu->abbrev_insns);
	free(cu->abbrev_decls);
}

static void
drgn_dwarf_index_namespace_deinit(struct drgn_dwarf_index_namespace *ns)
{
	drgn_error_destroy(ns->saved_err);
	drgn_dwarf_index_pending_die_vector_deinit(&ns->pending_dies);
	for (size_t i = 0; i < ARRAY_SIZE(ns->shards); i++) {
		struct drgn_dwarf_index_shard *shard = &ns->shards[i];
		for (size_t j = 0; j < shard->dies.size; j++) {
			struct drgn_dwarf_index_die *die = &shard->dies.data[j];
			if (die->tag == DW_TAG_namespace) {
				drgn_dwarf_index_namespace_deinit(die->namespace);
				free(die->namespace);
			}
		}
		drgn_dwarf_index_die_vector_deinit(&shard->dies);
		drgn_dwarf_index_die_map_deinit(&shard->map);
		omp_destroy_lock(&shard->lock);
	}
}

void drgn_dwarf_index_deinit(struct drgn_dwarf_index *dindex)
{
	if (!dindex)
		return;
	c_string_set_deinit(&dindex->names);
	drgn_dwarf_index_free_modules(dindex, false, true);
	assert(dindex->no_build_id.size == 0);
	assert(drgn_dwarf_module_table_size(&dindex->module_table) == 0);
	drgn_dwarf_module_vector_deinit(&dindex->no_build_id);
	drgn_dwarf_module_table_deinit(&dindex->module_table);
	for (size_t i = 0; i < dindex->cus.size; i++)
		drgn_dwarf_index_cu_deinit(&dindex->cus.data[i]);
	drgn_dwarf_index_cu_vector_deinit(&dindex->cus);
	drgn_dwarf_index_specification_map_deinit(&dindex->specifications);
	drgn_dwarf_index_namespace_deinit(&dindex->global);
	dwfl_end(dindex->dwfl);
}

void drgn_dwarf_index_report_begin(struct drgn_dwarf_index *dindex)
{
	dwfl_report_begin_add(dindex->dwfl);
}

struct drgn_error *
drgn_dwarf_index_report_error(struct drgn_dwarf_index *dindex, const char *name,
			      const char *message, struct drgn_error *err)
{
	if (err && err->code == DRGN_ERROR_NO_MEMORY) {
		/* Always fail hard if we're out of memory. */
		goto err;
	}
	if (dindex->num_errors == 0 &&
	    !string_builder_append(&dindex->errors,
				   "could not get debugging information for:"))
		goto err;
	if (dindex->num_errors < dindex->max_errors) {
		if (!string_builder_line_break(&dindex->errors))
			goto err;
		if (name && !string_builder_append(&dindex->errors, name))
			goto err;
		if (name && (message || err) &&
		    !string_builder_append(&dindex->errors, " ("))
			goto err;
		if (message && !string_builder_append(&dindex->errors, message))
			goto err;
		if (message && err &&
		    !string_builder_append(&dindex->errors, ": "))
			goto err;
		if (err && !string_builder_append_error(&dindex->errors, err))
			goto err;
		if (name && (message || err) &&
		    !string_builder_appendc(&dindex->errors, ')'))
			goto err;
	}
	dindex->num_errors++;
	drgn_error_destroy(err);
	return NULL;

err:
	drgn_error_destroy(err);
	return &drgn_enomem;
}

static void drgn_dwarf_index_reset_errors(struct drgn_dwarf_index *dindex)
{
	dindex->errors.len = 0;
	dindex->num_errors = 0;
}

static struct drgn_error *
drgn_dwarf_index_finalize_errors(struct drgn_dwarf_index *dindex)
{
	struct drgn_error *err;

	if (dindex->num_errors > dindex->max_errors &&
	    (!string_builder_line_break(&dindex->errors) ||
	     !string_builder_appendf(&dindex->errors, "... %u more",
				     dindex->num_errors - dindex->max_errors))) {
		drgn_dwarf_index_reset_errors(dindex);
		return &drgn_enomem;
	}
	if (dindex->num_errors) {
		err = drgn_error_from_string_builder(DRGN_ERROR_MISSING_DEBUG_INFO,
						     &dindex->errors);
		memset(&dindex->errors, 0, sizeof(dindex->errors));
		dindex->num_errors = 0;
		return err;
	} else {
		return NULL;
	}
}

static struct drgn_error *
drgn_dwarf_index_insert_module(struct drgn_dwarf_index *dindex,
			       const void *build_id, size_t build_id_len,
			       uint64_t start, uint64_t end, const char *name,
			       struct drgn_dwarf_module **ret)
{
	struct hash_pair hp;
	struct drgn_dwarf_module_table_iterator it;
	struct drgn_dwarf_module *module;

	if (build_id_len) {
		struct drgn_dwarf_module_key key = {
			.build_id = build_id,
			.build_id_len = build_id_len,
			.start = start,
			.end = end,
		};

		hp = drgn_dwarf_module_table_hash(&key);
		it = drgn_dwarf_module_table_search_hashed(&dindex->module_table,
							   &key, hp);
		if (it.entry) {
			module = *it.entry;
			goto out;
		}
	}

	module = malloc(sizeof(*module));
	if (!module)
		return &drgn_enomem;
	module->start = start;
	module->end = end;
	if (name) {
		module->name = strdup(name);
		if (!module->name)
			goto err_module;
	} else {
		module->name = NULL;
	}
	module->build_id_len = build_id_len;
	if (build_id_len) {
		module->build_id = malloc(build_id_len);
		if (!module->build_id)
			goto err_name;
		memcpy(module->build_id, build_id, build_id_len);
		if (drgn_dwarf_module_table_insert_searched(&dindex->module_table,
							    &module, hp,
							    &it) == -1) {
			free(module->build_id);
err_name:
			free(module->name);
err_module:
			free(module);
			return &drgn_enomem;
		}
	} else {
		module->build_id = NULL;
		if (!drgn_dwarf_module_vector_append(&dindex->no_build_id,
						     &module))
			goto err_name;
	}
	module->state = DRGN_DWARF_MODULE_NEW;
	dwfl_module_vector_init(&module->dwfl_modules);
out:
	*ret = module;
	return NULL;
}

struct drgn_error *drgn_dwarf_index_report_elf(struct drgn_dwarf_index *dindex,
					       const char *path, int fd,
					       Elf *elf, uint64_t start,
					       uint64_t end, const char *name,
					       bool *new_ret)
{
	struct drgn_error *err;
	const void *build_id;
	ssize_t build_id_len;
	struct drgn_dwarf_module *module;
	char *path_key = NULL;
	Dwfl_Module *dwfl_module;
	void **userdatap;
	struct drgn_dwfl_module_userdata *userdata;

	if (new_ret)
		*new_ret = false;

	build_id_len = dwelf_elf_gnu_build_id(elf, &build_id);
	if (build_id_len == -1) {
		err = drgn_dwarf_index_report_error(dindex, path, NULL,
						    drgn_error_libdwfl());
		goto free;
	}

	err = drgn_dwarf_index_insert_module(dindex, build_id, build_id_len,
					     start, end, name, &module);
	if (err)
		goto free;
	if (module->state == DRGN_DWARF_MODULE_INDEXED) {
		/* We've already indexed this module. */
		err = NULL;
		goto free;
	}

	path_key = realpath(path, NULL);
	if (!path_key) {
		path_key = strdup(path);
		if (!path_key) {
			err = &drgn_enomem;
			goto free;
		}
	}
	dwfl_module = dwfl_report_module(dindex->dwfl, path_key, start, end);
	if (!dwfl_module) {
		err = drgn_error_libdwfl();
		goto free;
	}

	dwfl_module_info(dwfl_module, &userdatap, NULL, NULL, NULL, NULL, NULL,
			 NULL);
	if (*userdatap) {
		/* We've already reported this file at this offset. */
		err = NULL;
		goto free;
	}

	userdata = malloc(sizeof(*userdata));
	if (!userdata) {
		err = &drgn_enomem;
		goto free;
	}
	userdata->path = path_key;
	userdata->fd = fd;
	userdata->elf = elf;
	userdata->state = DRGN_DWARF_MODULE_NEW;
	userdata->module = dwfl_module;
	*userdatap = userdata;
	if (new_ret)
		*new_ret = true;

	if (!dwfl_module_vector_append(&module->dwfl_modules, &dwfl_module)) {
		/*
		 * NB: not goto free now that we're referencing the file from a
		 * Dwfl_Module.
		 */
		return &drgn_enomem;
	}
	return NULL;

free:
	elf_end(elf);
	close(fd);
	free(path_key);
	return err;
}

static int drgn_dwarf_index_report_dwfl_module(Dwfl_Module *dwfl_module,
					       void **userdatap,
					       const char *name,
					       Dwarf_Addr base, void *arg)
{
	struct drgn_error *err;
	struct drgn_dwarf_index *dindex = arg;
	struct drgn_dwfl_module_userdata *userdata = *userdatap;
	const unsigned char *build_id;
	int build_id_len;
	GElf_Addr build_id_vaddr;
	Dwarf_Addr end;
	struct drgn_dwarf_module *module;

	if (userdata) {
		/*
		 * This was either reported from
		 * drgn_dwarf_index_report_module() or already indexed.
		 */
		return DWARF_CB_OK;
	}

	build_id_len = dwfl_module_build_id(dwfl_module, &build_id,
					    &build_id_vaddr);
	if (build_id_len == -1) {
		err = drgn_dwarf_index_report_error(dindex, name, NULL,
						    drgn_error_libdwfl());
		if (err) {
			drgn_error_destroy(err);
			return DWARF_CB_ABORT;
		}
		return DWARF_CB_OK;
	}
	dwfl_module_info(dwfl_module, NULL, NULL, &end, NULL, NULL, NULL, NULL);

	err = drgn_dwarf_index_insert_module(dindex, build_id, build_id_len,
					     base, end, NULL, &module);
	if (err) {
		drgn_error_destroy(err);
		return DWARF_CB_ABORT;
	}

	userdata = malloc(sizeof(*userdata));
	if (!userdata)
		return DWARF_CB_ABORT;
	*userdatap = userdata;
	userdata->path = NULL;
	userdata->fd = -1;
	userdata->elf = NULL;
	userdata->module = dwfl_module;
	if (module->state == DRGN_DWARF_MODULE_INDEXED) {
		/*
		 * We've already indexed this module. Don't index it again, but
		 * keep the Dwfl_Module.
		 */
		userdata->state = DRGN_DWARF_MODULE_INDEXING;
	} else {
		userdata->state = DRGN_DWARF_MODULE_NEW;
		if (!dwfl_module_vector_append(&module->dwfl_modules,
					       &dwfl_module))
			return DWARF_CB_ABORT;
	}
	return DWARF_CB_OK;
}

static struct drgn_error *
append_unindexed_module(struct drgn_dwarf_module *module,
			struct drgn_dwarf_module_vector *unindexed,
			size_t *num_names)
{
	if (!module->dwfl_modules.size) {
		/* This was either already indexed or had no new files. */
		return NULL;
	}
	if (!drgn_dwarf_module_vector_append(unindexed, &module))
		return &drgn_enomem;
	*num_names += 1;
	return NULL;
}

static struct drgn_error *
drgn_dwarf_index_get_unindexed(struct drgn_dwarf_index *dindex,
			       struct drgn_dwarf_module_vector *unindexed)
{
	struct drgn_error *err;
	size_t num_names = 0;
	struct drgn_dwarf_module_table_iterator it;
	size_t i;

	/*
	 * Walk the module table and no build ID lists, but skip modules with no
	 * Dwfl_Module (which may be because they were already indexed or
	 * because the files were already reported).
	 */
	for (it = drgn_dwarf_module_table_first(&dindex->module_table);
	     it.entry; it = drgn_dwarf_module_table_next(it)) {
		err = append_unindexed_module(*it.entry, unindexed, &num_names);
		if (err)
			return err;
	}
	for (i = dindex->no_build_id.size; i-- > 0; ) {
		struct drgn_dwarf_module *module = dindex->no_build_id.data[i];

		if (module->state == DRGN_DWARF_MODULE_INDEXED) {
			/*
			 * If this module is indexed, then every module before
			 * it must be indexed, so we can stop looking.
			 */
			break;
		}
		err = append_unindexed_module(module, unindexed, &num_names);
		if (err)
			return err;
	}
	if (num_names &&
	    !c_string_set_reserve(&dindex->names,
				  c_string_set_size(&dindex->names) + num_names))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *apply_relocation(Elf_Data *data, uint64_t r_offset,
					   uint32_t r_type, int64_t r_addend,
					   uint64_t st_value)
{
	char *p;

	p = (char *)data->d_buf + r_offset;
	switch (r_type) {
	case R_X86_64_NONE:
		break;
	case R_X86_64_32:
		if (r_offset > SIZE_MAX - sizeof(uint32_t) ||
		    r_offset + sizeof(uint32_t) > data->d_size) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid relocation offset");
		}
		*(uint32_t *)p = st_value + r_addend;
		break;
	case R_X86_64_64:
		if (r_offset > SIZE_MAX - sizeof(uint64_t) ||
		    r_offset + sizeof(uint64_t) > data->d_size) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid relocation offset");
		}
		*(uint64_t *)p = st_value + r_addend;
		break;
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unimplemented relocation type %" PRIu32,
					 r_type);
	}
	return NULL;
}

static struct drgn_error *relocate_section(Elf_Scn *scn, Elf_Scn *rela_scn,
					   Elf_Scn *symtab_scn,
					   uint64_t *sh_addrs, size_t shdrnum)
{
	struct drgn_error *err;
	Elf_Data *data, *rela_data, *symtab_data;
	const Elf64_Rela *relocs;
	const Elf64_Sym *syms;
	size_t num_relocs, num_syms;
	size_t i;
	GElf_Shdr *shdr, shdr_mem;

	err = read_elf_section(scn, &data);
	if (err)
		return err;
	err = read_elf_section(rela_scn, &rela_data);
	if (err)
		return err;
	err = read_elf_section(symtab_scn, &symtab_data);
	if (err)
		return err;

	relocs = (Elf64_Rela *)rela_data->d_buf;
	num_relocs = rela_data->d_size / sizeof(Elf64_Rela);
	syms = (Elf64_Sym *)symtab_data->d_buf;
	num_syms = symtab_data->d_size / sizeof(Elf64_Sym);

	for (i = 0; i < num_relocs; i++) {
		const Elf64_Rela *reloc = &relocs[i];
		uint32_t r_sym, r_type;
		uint16_t st_shndx;
		uint64_t sh_addr;

		r_sym = ELF64_R_SYM(reloc->r_info);
		r_type = ELF64_R_TYPE(reloc->r_info);

		if (r_sym >= num_syms) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid relocation symbol");
		}
		st_shndx = syms[r_sym].st_shndx;
		if (st_shndx == 0) {
			sh_addr = 0;
		} else if (st_shndx < shdrnum) {
			sh_addr = sh_addrs[st_shndx - 1];
		} else {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid symbol section index");
		}
		err = apply_relocation(data, reloc->r_offset, r_type,
				       reloc->r_addend,
				       sh_addr + syms[r_sym].st_value);
		if (err)
			return err;
	}

	/*
	 * Mark the relocation section as empty so that libdwfl doesn't try to
	 * apply it again.
	 */
	shdr = gelf_getshdr(rela_scn, &shdr_mem);
	if (!shdr)
		return drgn_error_libelf();
	shdr->sh_size = 0;
	if (!gelf_update_shdr(rela_scn, shdr))
		return drgn_error_libelf();
	rela_data->d_size = 0;
	return NULL;
}

/*
 * Before the debugging information in a relocatable ELF file (e.g., Linux
 * kernel module) can be used, it must have ELF relocations applied. This is
 * usually done by libdwfl. However, libdwfl is relatively slow at it. This is a
 * much faster implementation. It is only implemented for x86-64; for other
 * architectures, we can fall back to libdwfl.
 */
static struct drgn_error *apply_elf_relocations(Elf *elf)
{
	struct drgn_error *err;
	GElf_Ehdr ehdr_mem, *ehdr;
	size_t shdrnum, shstrndx;
	uint64_t *sh_addrs;
	Elf_Scn *scn;

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr)
		return drgn_error_libelf();

	if (ehdr->e_type != ET_REL ||
	    ehdr->e_machine != EM_X86_64 ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] !=
	    (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ?
	     ELFDATA2LSB : ELFDATA2MSB)) {
		/* Unsupported; fall back to libdwfl. */
		return NULL;
	}

	if (elf_getshdrnum(elf, &shdrnum))
		return drgn_error_libelf();
	if (shdrnum > 1) {
		sh_addrs = calloc(shdrnum - 1, sizeof(*sh_addrs));
		if (!sh_addrs)
			return &drgn_enomem;

		scn = NULL;
		while ((scn = elf_nextscn(elf, scn))) {
			size_t ndx;

			ndx = elf_ndxscn(scn);
			if (ndx > 0 && ndx < shdrnum) {
				GElf_Shdr *shdr, shdr_mem;

				shdr = gelf_getshdr(scn, &shdr_mem);
				if (!shdr) {
					err = drgn_error_libelf();
					goto out;
				}
				sh_addrs[ndx - 1] = shdr->sh_addr;
			}
		}
	} else {
		sh_addrs = NULL;
	}

	if (elf_getshdrstrndx(elf, &shstrndx)) {
		err = drgn_error_libelf();
		goto out;
	}

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr *shdr, shdr_mem;
		const char *scnname;

		shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr) {
			err = drgn_error_libelf();
			goto out;
		}

		if (shdr->sh_type != SHT_RELA)
			continue;

		scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname)
			continue;

		if (strstartswith(scnname, ".rela.debug_")) {
			Elf_Scn *info_scn, *link_scn;

			info_scn = elf_getscn(elf, shdr->sh_info);
			if (!info_scn) {
				err = drgn_error_libelf();
				goto out;
			}

			link_scn = elf_getscn(elf, shdr->sh_link);
			if (!link_scn) {
				err = drgn_error_libelf();
				goto out;
			}

			err = relocate_section(info_scn, scn, link_scn,
					       sh_addrs, shdrnum);
			if (err)
				goto out;
		}
	}
out:
	free(sh_addrs);
	return NULL;
}

static struct drgn_error *
get_debug_sections(struct drgn_dwfl_module_userdata *userdata,
		   bool *bswap_ret)
{
	struct drgn_error *err;

	if (userdata->elf) {
		err = apply_elf_relocations(userdata->elf);
		if (err)
			return err;
	}

	/*
	 * Note: not dwfl_module_getelf(), because then libdwfl applies
	 * ELF relocations to all sections, not just debug sections.
	 */
	Dwarf_Addr bias;
	Dwarf *dwarf = dwfl_module_getdwarf(userdata->module, &bias);
	if (!dwarf)
		return drgn_error_libdwfl();

	Elf *elf = dwarf_getelf(dwarf);
	if (!elf)
		return drgn_error_libdw();

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	userdata->debug_info = NULL;
	userdata->debug_abbrev = NULL;
	userdata->debug_str = NULL;
	userdata->debug_line = NULL;
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr_mem;
		GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return drgn_error_libelf();

		if (shdr->sh_type == SHT_NOBITS || (shdr->sh_flags & SHF_GROUP))
			continue;

		const char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname)
			continue;

		Elf_Data **sectionp;
		if (!userdata->debug_info && strcmp(scnname, ".debug_info") == 0)
			sectionp = &userdata->debug_info;
		else if (!userdata->debug_abbrev && strcmp(scnname, ".debug_abbrev") == 0)
			sectionp = &userdata->debug_abbrev;
		else if (!userdata->debug_str && strcmp(scnname, ".debug_str") == 0)
			sectionp = &userdata->debug_str;
		else if (!userdata->debug_line && strcmp(scnname, ".debug_line") == 0)
			sectionp = &userdata->debug_line;
		else
			continue;
		err = read_elf_section(scn, sectionp);
		if (err)
			return err;
	}

	if (!userdata->debug_info) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "no .debug_info section");
	} else if (!userdata->debug_abbrev) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "no .debug_abbrev section");
	} else if (!userdata->debug_str) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "no .debug_str section");
	}

	if (userdata->debug_str->d_size == 0 ||
	    ((char *)userdata->debug_str->d_buf)[userdata->debug_str->d_size - 1]) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 ".debug_str is not null terminated");
	}

	*bswap_ret = (elf_getident(elf, NULL)[EI_DATA] !=
		      (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ?
		       ELFDATA2LSB : ELFDATA2MSB));
	return NULL;
}

static struct drgn_error *read_compilation_unit_header(const char *ptr,
						       const char *end,
						       struct drgn_dwarf_index_cu *cu)
{
	uint32_t tmp;
	if (!mread_u32(&ptr, end, cu->bswap, &tmp))
		return drgn_eof();
	cu->is_64_bit = tmp == UINT32_C(0xffffffff);
	if (cu->is_64_bit) {
		if (!mread_u64_into_size_t(&ptr, end, cu->bswap,
					   &cu->unit_length))
			return drgn_eof();
	} else {
		cu->unit_length = tmp;
	}

	uint16_t version;
	if (!mread_u16(&ptr, end, cu->bswap, &version))
		return drgn_eof();
	if (version != 2 && version != 3 && version != 4) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown DWARF CU version %" PRIu16,
					 version);
	}
	cu->version = version;

	if (cu->is_64_bit) {
		if (!mread_u64(&ptr, end, cu->bswap, &cu->debug_abbrev_offset))
			return drgn_eof();
	} else {
		if (!mread_u32_into_u64(&ptr, end, cu->bswap,
					&cu->debug_abbrev_offset))
			return drgn_eof();
	}

	if (!mread_u8(&ptr, end, &cu->address_size))
		return drgn_eof();

	return NULL;
}


static struct drgn_error *
read_dwfl_module_cus(struct drgn_dwfl_module_userdata *userdata,
		     struct drgn_dwarf_index_cu_vector *cus)
{
	struct drgn_error *err;

	bool bswap;
	err = get_debug_sections(userdata, &bswap);
	if (err)
		return err;

	const char *ptr = section_ptr(userdata->debug_info, 0);
	const char *end = section_end(userdata->debug_info);
	while (ptr < end) {
		struct drgn_dwarf_index_cu *cu =
			drgn_dwarf_index_cu_vector_append_entry(cus);
		if (!cu)
			return &drgn_enomem;
		cu->userdata = userdata;
		cu->ptr = ptr;
		cu->bswap = bswap;
		err = read_compilation_unit_header(ptr, end, cu);
		if (err)
			return err;
		cu->abbrev_decls = NULL;
		cu->num_abbrev_decls = 0;
		cu->abbrev_insns = NULL;
		cu->file_name_hashes = NULL;
		cu->num_file_names = 0;

		if (!mread_skip(&ptr, end,
				(cu->is_64_bit ? 12 : 4) + cu->unit_length))
			return drgn_eof();
	}
	return NULL;
}

static struct drgn_error *
read_module_cus(struct drgn_dwarf_module *module,
		struct drgn_dwarf_index_cu_vector *cus, const char **name_ret)
{
	const size_t orig_cus_size = cus->size;
	for (size_t i = 0; i < module->dwfl_modules.size; i++) {
		void **userdatap;
		*name_ret = dwfl_module_info(module->dwfl_modules.data[i],
					     &userdatap, NULL, NULL, NULL, NULL,
					     NULL, NULL);
		struct drgn_dwfl_module_userdata *userdata = *userdatap;
		struct drgn_error *err = read_dwfl_module_cus(userdata, cus);
		if (err) {
			/*
			 * Ignore the error unless we have no more Dwfl_Modules
			 * to try.
			 */
			if (i == module->dwfl_modules.size - 1)
				return err;
			drgn_error_destroy(err);
			cus->size = orig_cus_size;
			continue;
		}
		userdata->state = DRGN_DWARF_MODULE_INDEXING;
		module->state = DRGN_DWARF_MODULE_INDEXING;
		return NULL;
	}
	UNREACHABLE();
}

static struct drgn_error *read_cus(struct drgn_dwarf_index *dindex,
				   struct drgn_dwarf_module **unindexed,
				   size_t num_unindexed)
{
	struct drgn_error *err = NULL;

	#pragma omp parallel
	{
		int thread_num = omp_get_thread_num();
		struct drgn_dwarf_index_cu_vector cus = VECTOR_INIT;

		#pragma omp for schedule(dynamic)
		for (size_t i = 0; i < num_unindexed; i++) {
			struct drgn_error *module_err;
			const char *name;

			if (err)
				continue;

			module_err = read_module_cus(unindexed[i],
						     thread_num == 0 ?
						     &dindex->cus : &cus,
						     &name);
			if (module_err) {
				#pragma omp critical(drgn_read_cus)
				if (err) {
					drgn_error_destroy(module_err);
				} else {
					err = drgn_dwarf_index_report_error(dindex,
									    name,
									    NULL,
									    module_err);
				}
				continue;
			}
		}

		if (cus.size) {
			#pragma omp critical(drgn_read_cus)
			if (!err) {
				if (drgn_dwarf_index_cu_vector_reserve(&dindex->cus,
								       dindex->cus.size + cus.size)) {
					memcpy(dindex->cus.data + dindex->cus.size,
					       cus.data,
					       cus.size * sizeof(*cus.data));
					dindex->cus.size += cus.size;
				} else {
					err = &drgn_enomem;
				}
			}
		}
		drgn_dwarf_index_cu_vector_deinit(&cus);
	}
	return err;
}

static struct drgn_error *read_abbrev_decl(const char **ptr, const char *end,
					   struct drgn_dwarf_index_cu *cu,
					   struct uint32_vector *decls,
					   struct uint8_vector *insns)
{
	struct drgn_error *err;

	static_assert(ATTRIB_MAX_INSN == UINT8_MAX,
		      "maximum DWARF attribute instruction is invalid");

	uint64_t code;
	if ((err = mread_uleb128(ptr, end, &code)))
		return err;
	if (code == 0)
		return &drgn_stop;
	if (code != decls->size + 1) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DWARF abbreviation table is not sequential");
	}

	uint32_t insn_index = insns->size;
	if (!uint32_vector_append(decls, &insn_index))
		return &drgn_enomem;

	uint64_t tag;
	if ((err = mread_uleb128(ptr, end, &tag)))
		return err;

	bool should_index;
	switch (tag) {
	/* Types. */
	case DW_TAG_base_type:
	case DW_TAG_class_type:
	case DW_TAG_enumeration_type:
	case DW_TAG_structure_type:
	case DW_TAG_typedef:
	case DW_TAG_union_type:
	/* Variables. */
	case DW_TAG_variable:
	/* Constants. */
	case DW_TAG_enumerator:
	/* Functions. */
	case DW_TAG_subprogram:
	/* Namespaces */
	case DW_TAG_namespace:
	/* If adding anything here, make sure it fits in DIE_FLAG_TAG_MASK. */
		should_index = true;
		break;
	default:
		should_index = false;
		break;
	}
	uint8_t die_flags = should_index ? tag : 0;

	uint8_t children;
	if (!mread_u8(ptr, end, &children))
		return drgn_eof();
	if (children)
		die_flags |= DIE_FLAG_CHILDREN;

	bool first = true;
	uint8_t insn;
	for (;;) {
		uint64_t name, form;
		if ((err = mread_uleb128(ptr, end, &name)))
			return err;
		if ((err = mread_uleb128(ptr, end, &form)))
			return err;
		if (name == 0 && form == 0)
			break;

		if (name == DW_AT_sibling) {
			switch (form) {
			case DW_FORM_ref1:
				insn = ATTRIB_SIBLING_REF1;
				goto append_insn;
			case DW_FORM_ref2:
				insn = ATTRIB_SIBLING_REF2;
				goto append_insn;
			case DW_FORM_ref4:
				insn = ATTRIB_SIBLING_REF4;
				goto append_insn;
			case DW_FORM_ref8:
				insn = ATTRIB_SIBLING_REF8;
				goto append_insn;
			case DW_FORM_ref_udata:
				insn = ATTRIB_SIBLING_REF_UDATA;
				goto append_insn;
			default:
				break;
			}
		} else if (name == DW_AT_name && should_index) {
			switch (form) {
			case DW_FORM_strp:
				if (cu->is_64_bit)
					insn = ATTRIB_NAME_STRP8;
				else
					insn = ATTRIB_NAME_STRP4;
				goto append_insn;
			case DW_FORM_string:
				insn = ATTRIB_NAME_STRING;
				goto append_insn;
			default:
				break;
			}
		} else if (name == DW_AT_stmt_list &&
			   cu->userdata->debug_line) {
			switch (form) {
			case DW_FORM_data4:
				insn = ATTRIB_STMT_LIST_LINEPTR4;
				goto append_insn;
			case DW_FORM_data8:
				insn = ATTRIB_STMT_LIST_LINEPTR8;
				goto append_insn;
			case DW_FORM_sec_offset:
				if (cu->is_64_bit)
					insn = ATTRIB_STMT_LIST_LINEPTR8;
				else
					insn = ATTRIB_STMT_LIST_LINEPTR4;
				goto append_insn;
			default:
				break;
			}
		} else if (name == DW_AT_decl_file && should_index &&
			   /* Namespaces are merged, so we ignore their file. */
			   tag != DW_TAG_namespace) {
			switch (form) {
			case DW_FORM_data1:
				insn = ATTRIB_DECL_FILE_DATA1;
				goto append_insn;
			case DW_FORM_data2:
				insn = ATTRIB_DECL_FILE_DATA2;
				goto append_insn;
			case DW_FORM_data4:
				insn = ATTRIB_DECL_FILE_DATA4;
				goto append_insn;
			case DW_FORM_data8:
				insn = ATTRIB_DECL_FILE_DATA8;
				goto append_insn;
			/*
			 * decl_file must be positive, so if the compiler uses
			 * DW_FORM_sdata for some reason, just treat it as
			 * udata.
			 */
			case DW_FORM_sdata:
			case DW_FORM_udata:
				insn = ATTRIB_DECL_FILE_UDATA;
				goto append_insn;
			default:
				break;
			}
		} else if (name == DW_AT_declaration && should_index) {
			switch (form) {
			case DW_FORM_flag:
				insn = ATTRIB_DECLARATION_FLAG;
				goto append_insn;
			case DW_FORM_flag_present:
				/*
				 * This could be an instruction, but as long as
				 * we have a free DIE flag bit, we might as well
				 * use it.
				 */
				die_flags |= DIE_FLAG_DECLARATION;
				break;
			default:
				return drgn_error_format(DRGN_ERROR_OTHER,
							 "unknown attribute form %" PRIu64 " for DW_AT_declaration",
							 form);
			}
		} else if (name == DW_AT_specification && should_index) {
			switch (form) {
			case DW_FORM_ref1:
				insn = ATTRIB_SPECIFICATION_REF1;
				goto append_insn;
			case DW_FORM_ref2:
				insn = ATTRIB_SPECIFICATION_REF2;
				goto append_insn;
			case DW_FORM_ref4:
				insn = ATTRIB_SPECIFICATION_REF4;
				goto append_insn;
			case DW_FORM_ref8:
				insn = ATTRIB_SPECIFICATION_REF8;
				goto append_insn;
			case DW_FORM_ref_udata:
				insn = ATTRIB_SPECIFICATION_REF_UDATA;
				goto append_insn;
			case DW_FORM_ref_addr:
				if (cu->version >= 3) {
					if (cu->is_64_bit)
						insn = ATTRIB_SPECIFICATION_REF_ADDR8;
					else
						insn = ATTRIB_SPECIFICATION_REF_ADDR4;
				} else {
					if (cu->address_size == 8)
						insn = ATTRIB_SPECIFICATION_REF_ADDR8;
					else if (cu->address_size == 4)
						insn = ATTRIB_SPECIFICATION_REF_ADDR4;
					else
						return drgn_error_format(DRGN_ERROR_OTHER,
									 "unsupported address size %" PRIu8,
									 cu->address_size);
				}
				goto append_insn;
			default:
				return drgn_error_format(DRGN_ERROR_OTHER,
							 "unknown attribute form %" PRIu64 " for DW_AT_specification",
							 form);
			}
		}

		switch (form) {
		case DW_FORM_addr:
			insn = cu->address_size;
			break;
		case DW_FORM_data1:
		case DW_FORM_ref1:
		case DW_FORM_flag:
			insn = 1;
			break;
		case DW_FORM_data2:
		case DW_FORM_ref2:
			insn = 2;
			break;
		case DW_FORM_data4:
		case DW_FORM_ref4:
			insn = 4;
			break;
		case DW_FORM_data8:
		case DW_FORM_ref8:
		case DW_FORM_ref_sig8:
			insn = 8;
			break;
		case DW_FORM_block1:
			insn = ATTRIB_BLOCK1;
			goto append_insn;
		case DW_FORM_block2:
			insn = ATTRIB_BLOCK2;
			goto append_insn;
		case DW_FORM_block4:
			insn = ATTRIB_BLOCK4;
			goto append_insn;
		case DW_FORM_exprloc:
			insn = ATTRIB_EXPRLOC;
			goto append_insn;
		case DW_FORM_sdata:
		case DW_FORM_udata:
		case DW_FORM_ref_udata:
			insn = ATTRIB_LEB128;
			goto append_insn;
		case DW_FORM_ref_addr:
		case DW_FORM_sec_offset:
		case DW_FORM_strp:
			insn = cu->is_64_bit ? 8 : 4;
			break;
		case DW_FORM_string:
			insn = ATTRIB_STRING;
			goto append_insn;
		case DW_FORM_flag_present:
			continue;
		case DW_FORM_indirect:
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_FORM_indirect is not implemented");
		default:
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "unknown attribute form %" PRIu64,
						 form);
		}

		if (!first) {
			uint8_t last_insn = insns->data[insns->size - 1];
			if (last_insn + insn <= INSN_MAX_SKIP) {
				insns->data[insns->size - 1] += insn;
				continue;
			} else if (last_insn < INSN_MAX_SKIP) {
				insn = last_insn + insn - INSN_MAX_SKIP;
				insns->data[insns->size - 1] = INSN_MAX_SKIP;
			}
		}

append_insn:
		first = false;
		if (!uint8_vector_append(insns, &insn))
			return &drgn_enomem;
	}
	insn = 0;
	if (!uint8_vector_append(insns, &insn) ||
	    !uint8_vector_append(insns, &die_flags))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *read_abbrev_table(struct drgn_dwarf_index_cu *cu)
{
	Elf_Data *debug_abbrev = cu->userdata->debug_abbrev;
	const char *ptr = section_ptr(debug_abbrev, cu->debug_abbrev_offset);
	if (!ptr)
		return drgn_eof();
	const char *end = section_end(debug_abbrev);
	struct uint32_vector decls = VECTOR_INIT;
	struct uint8_vector insns = VECTOR_INIT;
	for (;;) {
		struct drgn_error *err = read_abbrev_decl(&ptr, end, cu, &decls,
							  &insns);
		if (err && err->code == DRGN_ERROR_STOP) {
			break;
		} else if (err) {
			uint8_vector_deinit(&insns);
			uint32_vector_deinit(&decls);
			return err;
		}
	}
	cu->abbrev_decls = decls.data;
	cu->num_abbrev_decls = decls.size;
	cu->abbrev_insns = insns.data;
	return NULL;
}

static struct drgn_error *skip_lnp_header(struct drgn_dwarf_index_cu *cu,
					  const char **ptr, const char *end)
{
	uint32_t tmp;
	if (!mread_u32(ptr, end, cu->bswap, &tmp))
		return drgn_eof();
	bool is_64_bit = tmp == UINT32_C(0xffffffff);
	if (is_64_bit && !mread_skip(ptr, end, sizeof(uint64_t)))
		return drgn_eof();

	uint16_t version;
	if (!mread_u16(ptr, end, cu->bswap, &version))
		return drgn_eof();
	if (version != 2 && version != 3 && version != 4) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown DWARF LNP version %" PRIu16,
					 version);
	}

	/*
	 * Skip:
	 * header_length
	 * minimum_instruction_length
	 * maximum_operations_per_instruction (DWARF 4 only)
	 * default_is_stmt
	 * line_base
	 * line_range
	 * standard_opcode_lengths
	 */
	uint8_t opcode_base;
	if (!mread_skip(ptr, end, (is_64_bit ? 8 : 4) + 4 + (version >= 4)) ||
	    !mread_u8(ptr, end, &opcode_base) ||
	    !mread_skip(ptr, end, opcode_base - 1))
		return drgn_eof();

	return NULL;
}

/*
 * Hash the canonical path of a directory. Components are hashed in reverse
 * order. We always include a trailing slash.
 */
static void hash_directory(struct siphash *hash, const char *path,
			   size_t path_len)
{
	struct path_iterator it = {
		.components = (struct path_iterator_component []){
			{ path, path_len, },
		},
		.num_components = 1,
	};
	const char *component;
	size_t component_len;

	while (path_iterator_next(&it, &component, &component_len)) {
		siphash_update(hash, component, component_len);
		siphash_update(hash, "/", 1);
	}
}

DEFINE_VECTOR(siphash_vector, struct siphash)

static struct drgn_error *
read_file_name_table(struct drgn_dwarf_index *dindex,
		     struct drgn_dwarf_index_cu *cu, size_t stmt_list)
{
	/*
	 * We don't care about hash flooding attacks, so don't bother with the
	 * random key.
	 */
	static const uint64_t siphash_key[2];
	struct drgn_error *err;

	Elf_Data *debug_line = cu->userdata->debug_line;
	const char *ptr = section_ptr(debug_line, stmt_list);
	if (!ptr)
		return drgn_eof();
	const char *end = section_end(debug_line);

	err = skip_lnp_header(cu, &ptr, end);
	if (err)
		return err;

	struct siphash_vector directories = VECTOR_INIT;
	for (;;) {
		const char *path;
		size_t path_len;
		if (!mread_string(&ptr, end, &path, &path_len)) {
			err = drgn_eof();
			goto out_directories;
		}
		if (!path_len)
			break;

		struct siphash *hash =
			siphash_vector_append_entry(&directories);
		if (!hash) {
			err = &drgn_enomem;
			goto out_directories;
		}
		siphash_init(hash, siphash_key);
		hash_directory(hash, path, path_len);
	}

	struct uint64_vector file_name_hashes = VECTOR_INIT;
	for (;;) {
		const char *path;
		size_t path_len;
		if (!mread_string(&ptr, end, &path, &path_len)) {
			err = drgn_eof();
			goto out_hashes;
		}
		if (!path_len)
			break;

		uint64_t directory_index;
		if ((err = mread_uleb128(&ptr, end, &directory_index)))
			goto out_hashes;
		/* mtime, size */
		if (!mread_skip_leb128(&ptr, end) ||
		    !mread_skip_leb128(&ptr, end)) {
			err = drgn_eof();
			goto out_hashes;
		}

		if (directory_index > directories.size) {
			err = drgn_error_format(DRGN_ERROR_OTHER,
						"directory index %" PRIu64 " is invalid",
						directory_index);
			goto out_hashes;
		}

		struct siphash hash;
		if (directory_index)
			hash = directories.data[directory_index - 1];
		else
			siphash_init(&hash, siphash_key);
		siphash_update(&hash, path, path_len);

		uint64_t file_name_hash = siphash_final(&hash);
		if (!uint64_vector_append(&file_name_hashes, &file_name_hash)) {
			err = &drgn_enomem;
			goto out_hashes;
		}
	}

	cu->file_name_hashes = file_name_hashes.data;
	cu->num_file_names = file_name_hashes.size;
	err = NULL;
	goto out_directories;

out_hashes:
	uint64_vector_deinit(&file_name_hashes);
out_directories:
	siphash_vector_deinit(&directories);
	return err;
}

static struct drgn_error *
index_specification(struct drgn_dwarf_index *dindex, uintptr_t declaration,
		    Dwfl_Module *module, size_t offset)
{
	struct drgn_dwarf_index_specification entry = {
		.declaration = declaration,
		.module = module,
		.offset = offset,
	};
	struct hash_pair hp =
		drgn_dwarf_index_specification_map_hash(&declaration);
	int ret;
	#pragma omp critical(drgn_index_specification)
	ret = drgn_dwarf_index_specification_map_insert_hashed(&dindex->specifications,
							       &entry, hp,
							       NULL);
	/*
	 * There may be duplicates if multiple DIEs reference one declaration,
	 * but we ignore them.
	 */
	return ret == -1 ? &drgn_enomem : NULL;
}

/*
 * First pass: read the abbreviation and file name tables and index DIEs with
 * DW_AT_specification. This recurses into namespaces.
 */
static struct drgn_error *index_cu_first_pass(struct drgn_dwarf_index *dindex,
					      struct drgn_dwarf_index_cu *cu)
{
	struct drgn_error *err;
	const char *ptr = &cu->ptr[cu->is_64_bit ? 23 : 11];
	const char *end = &cu->ptr[(cu->is_64_bit ? 12 : 4) + cu->unit_length];
	Elf_Data *debug_info = cu->userdata->debug_info;
	const char *debug_info_buffer = section_ptr(debug_info, 0);
	unsigned int depth = 0;

	if ((err = read_abbrev_table(cu)))
		return err;

	for (;;) {
		size_t die_offset = ptr - debug_info_buffer;

		uint64_t code;
		if ((err = mread_uleb128(&ptr, end, &code)))
			return err;
		if (code == 0) {
			if (depth-- > 1)
				continue;
			else
				break;
		} else if (code > cu->num_abbrev_decls) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "unknown abbreviation code %" PRIu64,
						 code);
		}

		uint8_t *insnp = &cu->abbrev_insns[cu->abbrev_decls[code - 1]];
		bool declaration = false;
		uintptr_t specification = 0;
		size_t stmt_list = SIZE_MAX;
		const char *sibling = NULL;
		uint8_t insn;
		while ((insn = *insnp++)) {
			size_t skip, tmp;
			switch (insn) {
			case ATTRIB_BLOCK1:
				if (!mread_u8_into_size_t(&ptr, end, &skip))
					return drgn_eof();
				goto skip;
			case ATTRIB_BLOCK2:
				if (!mread_u16_into_size_t(&ptr, end, cu->bswap,
							   &skip))
					return drgn_eof();
				goto skip;
			case ATTRIB_BLOCK4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &skip))
					return drgn_eof();
				goto skip;
			case ATTRIB_EXPRLOC:
				if ((err = mread_uleb128_into_size_t(&ptr, end,
								     &skip)))
					return err;
				goto skip;
			case ATTRIB_LEB128:
			case ATTRIB_DECL_FILE_UDATA:
				if (!mread_skip_leb128(&ptr, end))
					return drgn_eof();
				break;
			case ATTRIB_STRING:
			case ATTRIB_NAME_STRING:
				if (!mread_skip_string(&ptr, end))
					return drgn_eof();
				break;
			case ATTRIB_SIBLING_REF1:
				if (!mread_u8_into_size_t(&ptr, end, &tmp))
					return drgn_eof();
				goto sibling;
			case ATTRIB_SIBLING_REF2:
				if (!mread_u16_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto sibling;
			case ATTRIB_SIBLING_REF4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto sibling;
			case ATTRIB_SIBLING_REF8:
				if (!mread_u64_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto sibling;
			case ATTRIB_SIBLING_REF_UDATA:
				if ((err = mread_uleb128_into_size_t(&ptr, end,
								     &tmp)))
					return err;
sibling:
				if (!(sibling = mread_begin(cu->ptr, end, tmp)))
					return drgn_eof();
				__builtin_prefetch(sibling);
				break;
			case ATTRIB_STMT_LIST_LINEPTR4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &stmt_list))
					return drgn_eof();
				break;
			case ATTRIB_STMT_LIST_LINEPTR8:
				if (!mread_u64_into_size_t(&ptr, end, cu->bswap,
							   &stmt_list))
					return drgn_eof();
				break;
			case ATTRIB_DECL_FILE_DATA1:
				skip = 1;
				goto skip;
			case ATTRIB_DECL_FILE_DATA2:
				skip = 2;
				goto skip;
			case ATTRIB_NAME_STRP4:
			case ATTRIB_DECL_FILE_DATA4:
				skip = 4;
				goto skip;
			case ATTRIB_NAME_STRP8:
			case ATTRIB_DECL_FILE_DATA8:
				skip = 8;
				goto skip;
			case ATTRIB_DECLARATION_FLAG: {
				uint8_t flag;
				if (!mread_u8(&ptr, end, &flag))
					return drgn_eof();
				if (flag)
					declaration = true;
				break;
			}
			case ATTRIB_SPECIFICATION_REF1:
				if (!mread_u8_into_size_t(&ptr, end, &tmp))
					return drgn_eof();
				goto specification;
			case ATTRIB_SPECIFICATION_REF2:
				if (!mread_u16_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto specification;
			case ATTRIB_SPECIFICATION_REF4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto specification;
			case ATTRIB_SPECIFICATION_REF8:
				if (!mread_u64_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto specification;
			case ATTRIB_SPECIFICATION_REF_UDATA:
				if ((err = mread_uleb128_into_size_t(&ptr, end,
								     &tmp)))
					return err;
specification:
				specification = (uintptr_t)cu->ptr + tmp;
				break;
			case ATTRIB_SPECIFICATION_REF_ADDR4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto specification_ref_addr;
			case ATTRIB_SPECIFICATION_REF_ADDR8:
				if (!mread_u64_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
specification_ref_addr:
				specification = (uintptr_t)debug_info_buffer + tmp;
				break;
			default:
				skip = insn;
skip:
				if (!mread_skip(&ptr, end, skip))
					return drgn_eof();
				break;
			}
		}
		insn = *insnp;

		if (depth == 0) {
			if (stmt_list != SIZE_MAX &&
			    (err = read_file_name_table(dindex, cu, stmt_list)))
				return err;
		} else if (specification) {
			if (insn & DIE_FLAG_DECLARATION)
				declaration = true;
			/*
			 * For now, we don't handle DIEs with
			 * DW_AT_specification which are themselves
			 * declarations. We may need to handle
			 * DW_AT_specification "chains" in the future.
			 */
			if (!declaration &&
			    (err = index_specification(dindex, specification,
						       cu->userdata->module,
						       die_offset)))
				return err;
		}

		if (insn & DIE_FLAG_CHILDREN) {
			if (sibling &&
			    (insn & DIE_FLAG_TAG_MASK) != DW_TAG_namespace)
				ptr = sibling;
			else
				depth++;
		} else if (depth == 0) {
			break;
		}
	}
	return NULL;
}

static bool find_definition(struct drgn_dwarf_index *dindex, uintptr_t die_addr,
			    Dwfl_Module **module_ret, size_t *offset_ret)
{
	struct drgn_dwarf_index_specification_map_iterator it =
		drgn_dwarf_index_specification_map_search(&dindex->specifications,
							  &die_addr);
	if (!it.entry)
		return false;
	*module_ret = it.entry->module;
	*offset_ret = it.entry->offset;
	return true;
}

static bool append_die_entry(struct drgn_dwarf_index *dindex,
			     struct drgn_dwarf_index_shard *shard, uint8_t tag,
			     uint64_t file_name_hash, Dwfl_Module *module,
			     size_t offset)
{
	if (shard->dies.size == UINT32_MAX)
		return false;
	struct drgn_dwarf_index_die *die =
		drgn_dwarf_index_die_vector_append_entry(&shard->dies);
	if (!die)
		return false;
	die->next = UINT32_MAX;
	die->tag = tag;
	if (die->tag == DW_TAG_namespace) {
		die->namespace = malloc(sizeof(*die->namespace));
		if (!die->namespace) {
			shard->dies.size--;
			return false;
		}
		drgn_dwarf_index_namespace_init(die->namespace, dindex);
	} else {
		die->file_name_hash = file_name_hash;
	}
	die->module = module;
	die->offset = offset;

	return true;
}

static struct drgn_error *index_die(struct drgn_dwarf_index_namespace *ns,
				    struct drgn_dwarf_index_cu *cu,
				    const char *name, uint8_t tag,
				    uint64_t file_name_hash,
				    Dwfl_Module *module, size_t offset)
{
	struct drgn_error *err;
	struct drgn_dwarf_index_die_map_entry entry = {
		.key = {
			.str = name,
			.len = strlen(name),
		},
	};
	struct hash_pair hp;
	struct drgn_dwarf_index_shard *shard;
	struct drgn_dwarf_index_die_map_iterator it;
	size_t index;
	struct drgn_dwarf_index_die *die;

	hp = drgn_dwarf_index_die_map_hash(&entry.key);
	shard = &ns->shards[hash_pair_to_shard(hp)];
	omp_set_lock(&shard->lock);
	it = drgn_dwarf_index_die_map_search_hashed(&shard->map, &entry.key,
						    hp);
	if (!it.entry) {
		if (!append_die_entry(ns->dindex, shard, tag, file_name_hash,
				      module, offset)) {
			err = &drgn_enomem;
			goto err;
		}
		entry.value = shard->dies.size - 1;
		if (!drgn_dwarf_index_die_map_insert_searched(&shard->map,
							      &entry, hp,
							      NULL)) {
			err = &drgn_enomem;
			goto err;
		}
		die = &shard->dies.data[shard->dies.size - 1];
		goto out;
	}

	die = &shard->dies.data[it.entry->value];
	for (;;) {
		const uint64_t die_file_name_hash =
			die->tag == DW_TAG_namespace ? 0 : die->file_name_hash;
		if (die->tag == tag && die_file_name_hash == file_name_hash)
			goto out;

		if (die->next == UINT32_MAX)
			break;
		die = &shard->dies.data[die->next];
	}

	index = die - shard->dies.data;
	if (!append_die_entry(ns->dindex, shard, tag, file_name_hash, module,
			      offset)) {
		err = &drgn_enomem;
		goto err;
	}
	die = &shard->dies.data[shard->dies.size - 1];
	shard->dies.data[index].next = shard->dies.size - 1;
out:
	if (tag == DW_TAG_namespace) {
		struct drgn_dwarf_index_pending_die *pending =
			drgn_dwarf_index_pending_die_vector_append_entry(&die->namespace->pending_dies);
		if (!pending) {
			err = &drgn_enomem;
			goto err;
		}
		pending->cu = cu;
		pending->offset = offset;
	}
	err = NULL;
err:
	omp_unset_lock(&shard->lock);
	return err;
}

/* Second pass: index the actual DIEs. */
static struct drgn_error *
index_cu_second_pass(struct drgn_dwarf_index_namespace *ns,
		     struct drgn_dwarf_index_cu *cu, const char *ptr)
{
	struct drgn_error *err;
	const char *end = &cu->ptr[(cu->is_64_bit ? 12 : 4) + cu->unit_length];
	Elf_Data *debug_info = cu->userdata->debug_info;
	const char *debug_info_buffer = section_ptr(debug_info, 0);
	Elf_Data *debug_str = cu->userdata->debug_str;
	unsigned int depth = 0;
	uint8_t depth1_tag = 0;
	size_t depth1_offset = 0;

	for (;;) {
		size_t die_offset = ptr - debug_info_buffer;

		uint64_t code;
		if ((err = mread_uleb128(&ptr, end, &code)))
			return err;
		if (code == 0) {
			if (depth-- > 1)
				continue;
			else
				break;
		} else if (code > cu->num_abbrev_decls) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "unknown abbreviation code %" PRIu64,
						 code);
		}

		uint8_t *insnp = &cu->abbrev_insns[cu->abbrev_decls[code - 1]];
		const char *name = NULL;
		size_t decl_file = 0;
		bool declaration = false;
		bool specification = false;
		const char *sibling = NULL;
		uint8_t insn;
		while ((insn = *insnp++)) {
			size_t skip, tmp;
			switch (insn) {
			case ATTRIB_BLOCK1:
				if (!mread_u8_into_size_t(&ptr, end, &skip))
					return drgn_eof();
				goto skip;
			case ATTRIB_BLOCK2:
				if (!mread_u16_into_size_t(&ptr, end, cu->bswap,
							   &skip))
					return drgn_eof();
				goto skip;
			case ATTRIB_BLOCK4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &skip))
					return drgn_eof();
				goto skip;
			case ATTRIB_EXPRLOC:
				if ((err = mread_uleb128_into_size_t(&ptr, end,
								     &skip)))
					return err;
				goto skip;
			case ATTRIB_SPECIFICATION_REF_UDATA:
				specification = true;
				/* fallthrough */
			case ATTRIB_LEB128:
				if (!mread_skip_leb128(&ptr, end))
					return drgn_eof();
				break;
			case ATTRIB_NAME_STRING:
				name = ptr;
				/* fallthrough */
			case ATTRIB_STRING:
				if (!mread_skip_string(&ptr, end))
					return drgn_eof();
				break;
			case ATTRIB_SIBLING_REF1:
				if (!mread_u8_into_size_t(&ptr, end, &tmp))
					return drgn_eof();
				goto sibling;
			case ATTRIB_SIBLING_REF2:
				if (!mread_u16_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto sibling;
			case ATTRIB_SIBLING_REF4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto sibling;
			case ATTRIB_SIBLING_REF8:
				if (!mread_u64_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto sibling;
			case ATTRIB_SIBLING_REF_UDATA:
				if ((err = mread_uleb128_into_size_t(&ptr, end,
								     &tmp)))
					return err;
sibling:
				if (!(sibling = mread_begin(cu->ptr, end, tmp)))
					return drgn_eof();
				__builtin_prefetch(sibling);
				break;
			case ATTRIB_NAME_STRP4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
				goto strp;
			case ATTRIB_NAME_STRP8:
				if (!mread_u64_into_size_t(&ptr, end, cu->bswap,
							   &tmp))
					return drgn_eof();
strp:
				if (!(name = section_ptr(debug_str, tmp)))
					return drgn_eof();
				__builtin_prefetch(name);
				break;
			case ATTRIB_STMT_LIST_LINEPTR4:
				skip = 4;
				goto skip;
			case ATTRIB_STMT_LIST_LINEPTR8:
				skip = 8;
				goto skip;
			case ATTRIB_DECL_FILE_DATA1:
				if (!mread_u8_into_size_t(&ptr, end,
							  &decl_file))
					return drgn_eof();
				break;
			case ATTRIB_DECL_FILE_DATA2:
				if (!mread_u16_into_size_t(&ptr, end, cu->bswap,
							   &decl_file))
					return drgn_eof();
				break;
			case ATTRIB_DECL_FILE_DATA4:
				if (!mread_u32_into_size_t(&ptr, end, cu->bswap,
							   &decl_file))
					return drgn_eof();
				break;
			case ATTRIB_DECL_FILE_DATA8:
				if (!mread_u64_into_size_t(&ptr, end, cu->bswap,
							   &decl_file))
					return drgn_eof();
				break;
			case ATTRIB_DECL_FILE_UDATA:
				if ((err = mread_uleb128_into_size_t(&ptr, end,
								     &decl_file)))
					return err;
				break;
			case ATTRIB_DECLARATION_FLAG: {
				uint8_t flag;
				if (!mread_u8(&ptr, end, &flag))
					return drgn_eof();
				if (flag)
					declaration = true;
				break;
			}
			case ATTRIB_SPECIFICATION_REF1:
				specification = true;
				skip = 1;
				goto skip;
			case ATTRIB_SPECIFICATION_REF2:
				specification = true;
				skip = 2;
				goto skip;
			case ATTRIB_SPECIFICATION_REF4:
			case ATTRIB_SPECIFICATION_REF_ADDR4:
				specification = true;
				skip = 4;
				goto skip;
			case ATTRIB_SPECIFICATION_REF8:
			case ATTRIB_SPECIFICATION_REF_ADDR8:
				specification = true;
				skip = 8;
				goto skip;
			default:
				skip = insn;
skip:
				if (!mread_skip(&ptr, end, skip))
					return drgn_eof();
				break;
			}
		}
		insn = *insnp;

		uint8_t tag = insn & DIE_FLAG_TAG_MASK;
		if (depth == 1) {
			depth1_tag = tag;
			depth1_offset = die_offset;
		}
		if (depth == (tag == DW_TAG_enumerator ? 2 : 1) && name &&
		    !specification) {
			if (insn & DIE_FLAG_DECLARATION)
				declaration = true;
			Dwfl_Module *module = cu->userdata->module;
			if (tag == DW_TAG_enumerator) {
				if (depth1_tag != DW_TAG_enumeration_type)
					goto next;
				/*
				 * NB: the enumerator name points to the
				 * enumeration_type DIE. Also, enumerators can't
				 * be declared in C/C++, so we don't check for
				 * that.
				 */
				die_offset = depth1_offset;
			} else if (declaration &&
				   !find_definition(ns->dindex,
						    (uintptr_t)debug_info_buffer +
						    die_offset,
						    &module, &die_offset)) {
					goto next;
			}

			if (decl_file > cu->num_file_names) {
				return drgn_error_format(DRGN_ERROR_OTHER,
							 "invalid DW_AT_decl_file %zu",
							 decl_file);
			}
			uint64_t file_name_hash;
			if (decl_file)
				file_name_hash = cu->file_name_hashes[decl_file - 1];
			else
				file_name_hash = 0;
			if ((err = index_die(ns, cu, name, tag, file_name_hash,
					     module, die_offset)))
				return err;
		}

next:
		if (insn & DIE_FLAG_CHILDREN) {
			/*
			 * We must descend into the children of enumeration_type
			 * DIEs to index enumerator DIEs. We don't want to skip
			 * over the children of the top-level DIE even if it has
			 * a sibling pointer.
			 */
			if (sibling && tag != DW_TAG_enumeration_type &&
			    depth > 0)
				ptr = sibling;
			else
				depth++;
		} else if (depth == 0) {
			break;
		}
	}
	return NULL;
}

static void rollback_dwarf_index(struct drgn_dwarf_index *dindex)
{
	for (size_t i = 0; i < ARRAY_SIZE(dindex->global.shards); i++) {
		struct drgn_dwarf_index_shard *shard =
			&dindex->global.shards[i];

		/*
		 * Because we're deleting everything that was added since the
		 * last update, we can just shrink the dies array to the first
		 * entry that was added for this update.
		 */
		while (shard->dies.size) {
			struct drgn_dwarf_index_die *die =
				&shard->dies.data[shard->dies.size - 1];
			void **userdatap;
			dwfl_module_info(die->module, &userdatap, NULL,
					 NULL, NULL, NULL, NULL, NULL);
			struct drgn_dwfl_module_userdata *userdata = *userdatap;
			if (userdata->state == DRGN_DWARF_MODULE_INDEXED)
				break;
			else
				shard->dies.size--;
		}

		/*
		 * The new entries may be chained off of existing entries;
		 * unchain them. Note that any entries chained off of the new
		 * entries must also be new, so there's no need to preserve
		 * them.
		 */
		for (size_t index = 0; index < shard->dies.size; i++) {
			struct drgn_dwarf_index_die *die =
				&shard->dies.data[index];
			if (die->next != UINT32_MAX &&
			    die->next >= shard->dies.size)
				die->next = UINT32_MAX;
		}

		/* Finally, delete the new entries in the map. */
		for (struct drgn_dwarf_index_die_map_iterator it =
		     drgn_dwarf_index_die_map_first(&shard->map);
		     it.entry; ) {
			if (it.entry->value >= shard->dies.size) {
				it = drgn_dwarf_index_die_map_delete_iterator(&shard->map,
									      it);
			} else {
				it = drgn_dwarf_index_die_map_next(it);
			}
		}
	}

	for (struct drgn_dwarf_index_specification_map_iterator it =
	     drgn_dwarf_index_specification_map_first(&dindex->specifications);
	     it.entry; ) {
		void **userdatap;
		dwfl_module_info(it.entry->module, &userdatap, NULL, NULL, NULL,
				 NULL, NULL, NULL);
		struct drgn_dwfl_module_userdata *userdata = *userdatap;
		if (userdata->state == DRGN_DWARF_MODULE_INDEXED) {
			it = drgn_dwarf_index_specification_map_next(it);
		} else {
			it = drgn_dwarf_index_specification_map_delete_iterator(&dindex->specifications,
										it);
		}
	}
}

static struct drgn_error *index_cus(struct drgn_dwarf_index *dindex,
				    const size_t old_cus_size)
{
	struct drgn_error *err = NULL;
	#pragma omp parallel
	{
		#pragma omp for schedule(dynamic)
		for (size_t i = old_cus_size; i < dindex->cus.size; i++) {
			if (!err) {
				struct drgn_dwarf_index_cu *cu = &dindex->cus.data[i];
				struct drgn_error *cu_err =
					index_cu_first_pass(dindex, cu);
				if (cu_err) {
					#pragma omp critical(drgn_index_cus)
					if (err)
						drgn_error_destroy(cu_err);
					else
						err = cu_err;
				}
			}
		}

		#pragma omp for schedule(dynamic)
		for (size_t i = old_cus_size; i < dindex->cus.size; i++) {
			if (!err) {
				struct drgn_dwarf_index_cu *cu = &dindex->cus.data[i];
				const char *ptr = &cu->ptr[cu->is_64_bit ? 23 : 11];
				struct drgn_error *cu_err =
					index_cu_second_pass(&dindex->global,
							     cu, ptr);
				if (cu_err) {
					#pragma omp critical(drgn_index_cus)
					if (err)
						drgn_error_destroy(cu_err);
					else
						err = cu_err;
				}
			}
		}
	}
	return err;
}

/*
 * Like drgn_dwarf_index_report_end(), but doesn't finalize reported errors or
 * free unindexed modules on success.
 */
static struct drgn_error *
drgn_dwarf_index_report_end_internal(struct drgn_dwarf_index *dindex,
				     bool report_from_dwfl)
{
	struct drgn_error *err;
	struct drgn_dwarf_module_vector unindexed = VECTOR_INIT;
	const size_t old_cus_size = dindex->cus.size;

	dwfl_report_end(dindex->dwfl, NULL, NULL);
	if (report_from_dwfl &&
	    dwfl_getmodules(dindex->dwfl, drgn_dwarf_index_report_dwfl_module,
			    dindex, 0)) {
		err = &drgn_enomem;
		goto err;
	}
	err = drgn_dwarf_index_get_unindexed(dindex, &unindexed);
	if (err)
		goto err;
	err = read_cus(dindex, unindexed.data, unindexed.size);
	if (err)
		goto err;
	/*
	 * After this point, if we hit an error, then we have to roll back the
	 * index.
	 */
	err = index_cus(dindex, old_cus_size);
	if (err) {
		rollback_dwarf_index(dindex);
		goto err;
	}

out:
	drgn_dwarf_module_vector_deinit(&unindexed);
	return err;

err:
	for (size_t i = old_cus_size; i < dindex->cus.size; i++)
		drgn_dwarf_index_cu_deinit(&dindex->cus.data[i]);
	dindex->cus.size = old_cus_size;
	drgn_dwarf_index_free_modules(dindex, false, false);
	drgn_dwarf_index_reset_errors(dindex);
	goto out;
}

struct drgn_error *drgn_dwarf_index_report_end(struct drgn_dwarf_index *dindex,
					       bool report_from_dwfl)
{
	struct drgn_error *err;

	err = drgn_dwarf_index_report_end_internal(dindex, report_from_dwfl);
	if (err)
		return err;
	err = drgn_dwarf_index_finalize_errors(dindex);
	if (err && err->code != DRGN_ERROR_MISSING_DEBUG_INFO) {
		rollback_dwarf_index(dindex);
		drgn_dwarf_index_free_modules(dindex, false, false);
		return err;
	}
	drgn_dwarf_index_free_modules(dindex, true, false);
	return err;
}

struct drgn_error *drgn_dwarf_index_flush(struct drgn_dwarf_index *dindex,
					  bool report_from_dwfl)
{
	struct drgn_error *err;

	err = drgn_dwarf_index_report_end_internal(dindex, report_from_dwfl);
	if (err)
		return err;
	drgn_dwarf_index_free_modules(dindex, true, false);
	drgn_dwarf_index_report_begin(dindex);
	return NULL;
}

void drgn_dwarf_index_report_abort(struct drgn_dwarf_index *dindex)
{
	dwfl_report_end(dindex->dwfl, NULL, NULL);
	drgn_dwarf_index_free_modules(dindex, false, false);
	drgn_dwarf_index_reset_errors(dindex);
}

bool drgn_dwarf_index_is_indexed(struct drgn_dwarf_index *dindex,
				 const char *name)
{
	return c_string_set_search(&dindex->names, &name).entry != NULL;
}

static struct drgn_error *index_namespace(struct drgn_dwarf_index_namespace *ns)
{
	if (ns->saved_err)
		return drgn_error_copy(ns->saved_err);

	struct drgn_error *err = NULL;
	#pragma omp for schedule(dynamic)
	for (size_t i = 0; i < ns->pending_dies.size; i++) {
		if (!err) {
			struct drgn_dwarf_index_pending_die *pending =
				&ns->pending_dies.data[i];
			const char *ptr =
				section_ptr(pending->cu->userdata->debug_info,
					    pending->offset);
			struct drgn_error *cu_err =
				index_cu_second_pass(ns, pending->cu, ptr);
			if (cu_err) {
				#pragma omp critical(drgn_index_namespace)
				if (err)
					drgn_error_destroy(cu_err);
				else
					err = cu_err;
			}
		}
	}
	if (err) {
		ns->saved_err = err;
		return drgn_error_copy(ns->saved_err);
	}
	ns->pending_dies.size = 0;
	return err;
}

struct drgn_error *
drgn_dwarf_index_iterator_init(struct drgn_dwarf_index_iterator *it,
			       struct drgn_dwarf_index_namespace *ns,
			       const char *name, size_t name_len,
			       const uint64_t *tags, size_t num_tags)
{
	struct drgn_error *err = index_namespace(ns);
	if (err)
		return err;
	it->ns = ns;
	if (name) {
		struct string key = {
			.str = name,
			.len = name_len,
		};
		struct hash_pair hp;
		struct drgn_dwarf_index_shard *shard;
		struct drgn_dwarf_index_die_map_iterator map_it;

		hp = drgn_dwarf_index_die_map_hash(&key);
		it->shard = hash_pair_to_shard(hp);
		shard = &ns->shards[it->shard];
		map_it = drgn_dwarf_index_die_map_search_hashed(&shard->map,
								&key, hp);
		it->index = map_it.entry ? map_it.entry->value : UINT32_MAX;
		it->any_name = false;
	} else {
		it->index = 0;
		for (it->shard = 0; it->shard < ARRAY_SIZE(ns->shards);
		     it->shard++) {
			if (ns->shards[it->shard].dies.size)
				break;
		}
		it->any_name = true;
	}
	it->tags = tags;
	it->num_tags = num_tags;
	return NULL;
}

static inline bool
drgn_dwarf_index_iterator_matches_tag(struct drgn_dwarf_index_iterator *it,
				      struct drgn_dwarf_index_die *die)
{
	size_t i;

	if (it->num_tags == 0)
		return true;
	for (i = 0; i < it->num_tags; i++) {
		if (die->tag == it->tags[i])
			return true;
	}
	return false;
}

struct drgn_dwarf_index_die *
drgn_dwarf_index_iterator_next(struct drgn_dwarf_index_iterator *it)
{
	struct drgn_dwarf_index_namespace *ns = it->ns;
	struct drgn_dwarf_index_die *die;
	if (it->any_name) {
		for (;;) {
			if (it->shard >= ARRAY_SIZE(ns->shards))
				return NULL;

			struct drgn_dwarf_index_shard *shard =
				&ns->shards[it->shard];
			die = &shard->dies.data[it->index];

			if (++it->index >= shard->dies.size) {
				it->index = 0;
				while (++it->shard < ARRAY_SIZE(ns->shards)) {
					if (ns->shards[it->shard].dies.size)
						break;
				}
			}

			if (drgn_dwarf_index_iterator_matches_tag(it, die))
				break;
		}
	} else {
		for (;;) {
			if (it->index == UINT32_MAX)
				return NULL;

			struct drgn_dwarf_index_shard *shard =
				&ns->shards[it->shard];
			die = &shard->dies.data[it->index];

			it->index = die->next;

			if (drgn_dwarf_index_iterator_matches_tag(it, die))
				break;
		}
	}
	return die;
}

struct drgn_error *drgn_dwarf_index_get_die(struct drgn_dwarf_index_die *die,
					    Dwarf_Die *die_ret,
					    uint64_t *bias_ret)
{
	Dwarf_Addr bias;
	Dwarf *dwarf = dwfl_module_getdwarf(die->module, &bias);
	if (!dwarf)
		return drgn_error_libdwfl();
	if (!dwarf_offdie(dwarf, die->offset, die_ret))
		return drgn_error_libdw();
	if (bias_ret)
		*bias_ret = bias;
	return NULL;
}
