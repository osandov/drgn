// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <assert.h>
#include <dwarf.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>

#include "debug_info.h"
#include "drgn.h"
#include "dwarf_index.h"
#include "error.h"
#include "mread.h"
#include "path.h"
#include "siphash.h"
#include "util.h"

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
	struct drgn_debug_info_module *module;
	const char *ptr;
	const char *end;
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
	/* Index of compilation unit containing DIE. */
	size_t cu;
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

DEFINE_HASH_TABLE_FUNCTIONS(drgn_dwarf_index_die_map, string_hash_pair,
			    string_eq)
DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_die_vector)
DEFINE_HASH_TABLE_FUNCTIONS(drgn_dwarf_index_specification_map,
			    int_key_hash_pair, scalar_key_eq)

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

void drgn_dwarf_index_init(struct drgn_dwarf_index *dindex)
{
	drgn_dwarf_index_namespace_init(&dindex->global, dindex);
	drgn_dwarf_index_specification_map_init(&dindex->specifications);
	drgn_dwarf_index_cu_vector_init(&dindex->cus);
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
	for (size_t i = 0; i < dindex->cus.size; i++)
		drgn_dwarf_index_cu_deinit(&dindex->cus.data[i]);
	drgn_dwarf_index_cu_vector_deinit(&dindex->cus);
	drgn_dwarf_index_specification_map_deinit(&dindex->specifications);
	drgn_dwarf_index_namespace_deinit(&dindex->global);
}

void drgn_dwarf_index_update_begin(struct drgn_dwarf_index_update_state *state,
				   struct drgn_dwarf_index *dindex)
{
	state->dindex = dindex;
	state->old_cus_size = dindex->cus.size;
	state->err = NULL;
}

void drgn_dwarf_index_update_cancel(struct drgn_dwarf_index_update_state *state,
				    struct drgn_error *err)
{
	#pragma omp critical(drgn_dwarf_index_update_cancel)
	if (state->err)
		drgn_error_destroy(err);
	else
		state->err = err;
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
				if (!cu->module->debug_str) {
					return drgn_error_create(DRGN_ERROR_OTHER,
								 "DW_FORM_strp without .debug_str section");
				}
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
		} else if (name == DW_AT_stmt_list && cu->module->debug_line) {
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

static struct drgn_error *read_abbrev_table(struct drgn_dwarf_index_cu *cu,
					    size_t debug_abbrev_offset)
{
	Elf_Data *debug_abbrev = cu->module->debug_abbrev;
	const char *ptr = section_ptr(debug_abbrev, debug_abbrev_offset);
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

static struct drgn_error *read_cu(struct drgn_dwarf_index_cu *cu)
{

	const char *ptr = &cu->ptr[cu->is_64_bit ? 12 : 4];
	uint16_t version;
	if (!mread_u16(&ptr, cu->end, cu->bswap, &version))
		return drgn_eof();
	if (version < 2 || version > 4) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown DWARF CU version %" PRIu16,
					 version);
	}
	cu->version = version;

	size_t debug_abbrev_offset;
	if (cu->is_64_bit) {
		if (!mread_u64_into_size_t(&ptr, cu->end, cu->bswap,
					   &debug_abbrev_offset))
			return drgn_eof();
	} else {
		if (!mread_u32_into_size_t(&ptr, cu->end, cu->bswap,
					   &debug_abbrev_offset))
			return drgn_eof();
	}

	if (!mread_u8(&ptr, cu->end, &cu->address_size))
		return drgn_eof();

	return read_abbrev_table(cu, debug_abbrev_offset);
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

	Elf_Data *debug_line = cu->module->debug_line;
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
 * First pass: read the file name tables and index DIEs with
 * DW_AT_specification. This recurses into namespaces.
 */
static struct drgn_error *index_cu_first_pass(struct drgn_dwarf_index *dindex,
					      struct drgn_dwarf_index_cu *cu)
{
	struct drgn_error *err;
	Elf_Data *debug_info = cu->module->debug_info;
	const char *debug_info_buffer = section_ptr(debug_info, 0);
	const char *ptr = &cu->ptr[cu->is_64_bit ? 23 : 11];
	const char *end = cu->end;
	unsigned int depth = 0;
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
						       cu->module->dwfl_module,
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

void drgn_dwarf_index_read_module(struct drgn_dwarf_index_update_state *state,
				  struct drgn_debug_info_module *module)
{
	const bool bswap = module->bswap;
	const char *ptr = section_ptr(module->debug_info, 0);
	const char *end = section_end(module->debug_info);
	while (ptr < end) {
		const char *cu_ptr = ptr;
		uint32_t tmp;
		if (!mread_u32(&ptr, end, bswap, &tmp))
			goto err;
		bool is_64_bit = tmp == UINT32_C(0xffffffff);
		size_t unit_length;
		if (is_64_bit) {
			if (!mread_u64_into_size_t(&ptr, end, bswap,
						   &unit_length))
				goto err;
		} else {
			unit_length = tmp;
		}
		if (!mread_skip(&ptr, end, unit_length))
			goto err;

		#pragma omp task
		{
			struct drgn_dwarf_index_cu cu = {
				.module = module,
				.ptr = cu_ptr,
				.end = ptr,
				.is_64_bit = is_64_bit,
				.bswap = module->bswap,
			};
			struct drgn_error *cu_err = read_cu(&cu);
			if (cu_err)
				goto cu_err;

			cu_err = index_cu_first_pass(state->dindex, &cu);
			if (cu_err)
				goto cu_err;

			#pragma omp critical(drgn_dwarf_index_cus)
			if (!drgn_dwarf_index_cu_vector_append(&state->dindex->cus,
							       &cu))
				cu_err = &drgn_enomem;
			if (cu_err) {
cu_err:
				drgn_dwarf_index_cu_deinit(&cu);
				drgn_dwarf_index_update_cancel(state, cu_err);
			}
		}
	}
	return;

err:
	drgn_dwarf_index_update_cancel(state, drgn_eof());
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
		pending->cu = cu - ns->dindex->cus.data;
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
	Elf_Data *debug_info = cu->module->debug_info;
	const char *debug_info_buffer = section_ptr(debug_info, 0);
	Elf_Data *debug_str = cu->module->debug_str;
	const char *end = cu->end;
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
			Dwfl_Module *module = cu->module->dwfl_module;
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

static void drgn_dwarf_index_rollback(struct drgn_dwarf_index *dindex)
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
			struct drgn_debug_info_module *module = *userdatap;
			if (module->state == DRGN_DEBUG_INFO_MODULE_INDEXED)
				break;
			if (die->tag == DW_TAG_namespace) {
				drgn_dwarf_index_namespace_deinit(die->namespace);
				free(die->namespace);
			}
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
		struct drgn_debug_info_module *module = *userdatap;
		if (module->state == DRGN_DEBUG_INFO_MODULE_INDEXED) {
			it = drgn_dwarf_index_specification_map_next(it);
		} else {
			it = drgn_dwarf_index_specification_map_delete_iterator(&dindex->specifications,
										it);
		}
	}
}

struct drgn_error *
drgn_dwarf_index_update_end(struct drgn_dwarf_index_update_state *state)
{
	struct drgn_dwarf_index *dindex = state->dindex;

	if (state->err)
		goto err;

	#pragma omp parallel for schedule(dynamic)
	for (size_t i = state->old_cus_size; i < dindex->cus.size; i++) {
		if (drgn_dwarf_index_update_cancelled(state))
			continue;
		struct drgn_dwarf_index_cu *cu = &dindex->cus.data[i];
		const char *ptr = &cu->ptr[cu->is_64_bit ? 23 : 11];
		struct drgn_error *cu_err =
			index_cu_second_pass(&dindex->global, cu, ptr);
		if (cu_err)
			drgn_dwarf_index_update_cancel(state, cu_err);
	}
	if (state->err) {
		drgn_dwarf_index_rollback(state->dindex);
		goto err;
	}
	return NULL;

err:
	for (size_t i = state->old_cus_size; i < dindex->cus.size; i++)
		drgn_dwarf_index_cu_deinit(&dindex->cus.data[i]);
	dindex->cus.size = state->old_cus_size;
	return state->err;
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
			struct drgn_dwarf_index_cu *cu =
				&ns->dindex->cus.data[pending->cu];
			const char *ptr = section_ptr(cu->module->debug_info,
						      pending->offset);
			struct drgn_error *cu_err =
				index_cu_second_pass(ns, cu, ptr);
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
