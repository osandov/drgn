// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>

#include "binary_buffer.h"
#include "debug_info.h"
#include "drgn.h"
#include "dwarf_index.h"
#include "error.h"
#include "path.h"
#include "platform.h"
#include "siphash.h"
#include "util.h"

struct drgn_dwarf_index_pending_cu {
	struct drgn_debug_info_module *module;
	const char *buf;
	size_t len;
	bool is_64_bit;
	enum drgn_debug_info_scn scn;
};

DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_pending_cu_vector)

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
	INSN_MAX_SKIP = 219,
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
	ATTRIB_INDIRECT,
	ATTRIB_SIBLING_INDIRECT,
	ATTRIB_NAME_INDIRECT,
	ATTRIB_STMT_LIST_INDIRECT,
	ATTRIB_DECL_FILE_INDIRECT,
	ATTRIB_DECLARATION_INDIRECT,
	ATTRIB_SPECIFICATION_INDIRECT,
	ATTRIB_MAX_INSN = ATTRIB_SPECIFICATION_INDIRECT,
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
	const char *buf;
	size_t len;
	uint8_t version;
	uint8_t address_size;
	bool is_64_bit;
	bool is_type_unit;
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

struct drgn_dwarf_index_cu_buffer {
	struct binary_buffer bb;
	struct drgn_dwarf_index_cu *cu;
};

static struct drgn_error *
drgn_dwarf_index_cu_buffer_error(struct binary_buffer *bb, const char *pos,
				 const char *message)
{
	struct drgn_dwarf_index_cu_buffer *buffer =
		container_of(bb, struct drgn_dwarf_index_cu_buffer, bb);
	return drgn_error_debug_info_scn(buffer->cu->module,
					 DRGN_SCN_DEBUG_INFO, pos, message);
}

static void
drgn_dwarf_index_cu_buffer_init(struct drgn_dwarf_index_cu_buffer *buffer,
				struct drgn_dwarf_index_cu *cu)
{
	binary_buffer_init(&buffer->bb, cu->buf, cu->len,
			   drgn_platform_is_little_endian(&cu->module->platform),
			   drgn_dwarf_index_cu_buffer_error);
	buffer->cu = cu;
}

DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_cu_vector)

/* DIE which needs to be indexed. */
struct drgn_dwarf_index_pending_die {
	/* Index of compilation unit containing DIE. */
	size_t cu;
	/* Address of DIE */
	uintptr_t addr;
};

DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_pending_die_vector)

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

bool
drgn_dwarf_index_update_state_init(struct drgn_dwarf_index_update_state *state,
				   struct drgn_dwarf_index *dindex)
{
	state->dindex = dindex;
	state->max_threads = omp_get_max_threads();
	state->cus = malloc_array(state->max_threads, sizeof(*state->cus));
	if (!state->cus)
		return false;
	for (size_t i = 0; i < state->max_threads; i++)
		drgn_dwarf_index_pending_cu_vector_init(&state->cus[i]);
	return true;
}

void
drgn_dwarf_index_update_state_deinit(struct drgn_dwarf_index_update_state *state)
{
	for (size_t i = 0; i < state->max_threads; i++)
		drgn_dwarf_index_pending_cu_vector_deinit(&state->cus[i]);
	free(state->cus);
}

static struct drgn_error *dw_form_to_insn(struct drgn_dwarf_index_cu *cu,
					  struct binary_buffer *bb,
					  uint64_t form, uint8_t *insn_ret)
{
	switch (form) {
	case DW_FORM_addr:
		*insn_ret = cu->address_size;
		return NULL;
	case DW_FORM_data1:
	case DW_FORM_ref1:
	case DW_FORM_flag:
		*insn_ret = 1;
		return NULL;
	case DW_FORM_data2:
	case DW_FORM_ref2:
		*insn_ret = 2;
		return NULL;
	case DW_FORM_data4:
	case DW_FORM_ref4:
		*insn_ret = 4;
		return NULL;
	case DW_FORM_data8:
	case DW_FORM_ref8:
	case DW_FORM_ref_sig8:
		*insn_ret = 8;
		return NULL;
	case DW_FORM_block1:
		*insn_ret = ATTRIB_BLOCK1;
		return NULL;
	case DW_FORM_block2:
		*insn_ret = ATTRIB_BLOCK2;
		return NULL;
	case DW_FORM_block4:
		*insn_ret = ATTRIB_BLOCK4;
		return NULL;
	case DW_FORM_exprloc:
		*insn_ret = ATTRIB_EXPRLOC;
		return NULL;
	case DW_FORM_sdata:
	case DW_FORM_udata:
	case DW_FORM_ref_udata:
		*insn_ret = ATTRIB_LEB128;
		return NULL;
	case DW_FORM_ref_addr:
	case DW_FORM_sec_offset:
	case DW_FORM_strp:
		*insn_ret = cu->is_64_bit ? 8 : 4;
		return NULL;
	case DW_FORM_string:
		*insn_ret = ATTRIB_STRING;
		return NULL;
	case DW_FORM_flag_present:
		*insn_ret = 0;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = ATTRIB_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %" PRIu64,
					   form);
	}
}

static struct drgn_error *dw_at_sibling_to_insn(struct binary_buffer *bb,
						uint64_t form,
						uint8_t *insn_ret)
{
	switch (form) {
	case DW_FORM_ref1:
		*insn_ret = ATTRIB_SIBLING_REF1;
		return NULL;
	case DW_FORM_ref2:
		*insn_ret = ATTRIB_SIBLING_REF2;
		return NULL;
	case DW_FORM_ref4:
		*insn_ret = ATTRIB_SIBLING_REF4;
		return NULL;
	case DW_FORM_ref8:
		*insn_ret = ATTRIB_SIBLING_REF8;
		return NULL;
	case DW_FORM_ref_udata:
		*insn_ret = ATTRIB_SIBLING_REF_UDATA;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = ATTRIB_SIBLING_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %" PRIu64 " for DW_AT_sibling",
					   form);
	}
}

static struct drgn_error *dw_at_name_to_insn(struct drgn_dwarf_index_cu *cu,
					     struct binary_buffer *bb,
					     uint64_t form, uint8_t *insn_ret)
{
	switch (form) {
	case DW_FORM_strp:
		if (!cu->module->scn_data[DRGN_SCN_DEBUG_STR]) {
			return binary_buffer_error(bb,
						   "DW_FORM_strp without .debug_str section");
		}
		if (cu->is_64_bit)
			*insn_ret = ATTRIB_NAME_STRP8;
		else
			*insn_ret = ATTRIB_NAME_STRP4;
		return NULL;
	case DW_FORM_string:
		*insn_ret = ATTRIB_NAME_STRING;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = ATTRIB_NAME_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %" PRIu64 " for DW_AT_name",
					   form);
	}
}

static struct drgn_error *
dw_at_stmt_list_to_insn(struct drgn_dwarf_index_cu *cu,
			struct binary_buffer *bb, uint64_t form,
			uint8_t *insn_ret)
{
	switch (form) {
	case DW_FORM_data4:
		*insn_ret = ATTRIB_STMT_LIST_LINEPTR4;
		return NULL;
	case DW_FORM_data8:
		*insn_ret = ATTRIB_STMT_LIST_LINEPTR8;
		return NULL;
	case DW_FORM_sec_offset:
		if (cu->is_64_bit)
			*insn_ret = ATTRIB_STMT_LIST_LINEPTR8;
		else
			*insn_ret = ATTRIB_STMT_LIST_LINEPTR4;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = ATTRIB_STMT_LIST_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %" PRIu64 " for DW_AT_stmt_list",
					   form);
	}
}

static struct drgn_error *dw_at_decl_file_to_insn(struct binary_buffer *bb,
						  uint64_t form,
						  uint8_t *insn_ret)
{
	switch (form) {
	case DW_FORM_data1:
		*insn_ret = ATTRIB_DECL_FILE_DATA1;
		return NULL;
	case DW_FORM_data2:
		*insn_ret = ATTRIB_DECL_FILE_DATA2;
		return NULL;
	case DW_FORM_data4:
		*insn_ret = ATTRIB_DECL_FILE_DATA4;
		return NULL;
	case DW_FORM_data8:
		*insn_ret = ATTRIB_DECL_FILE_DATA8;
		return NULL;
		/*
		 * decl_file must be positive, so if the compiler uses
		 * DW_FORM_sdata for some reason, just treat it as udata.
		 */
	case DW_FORM_sdata:
	case DW_FORM_udata:
		*insn_ret = ATTRIB_DECL_FILE_UDATA;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = ATTRIB_DECL_FILE_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %" PRIu64 " for DW_AT_decl_file",
					   form);
	}
}

static struct drgn_error *
dw_at_declaration_to_insn(struct binary_buffer *bb, uint64_t form,
			  uint8_t *insn_ret, uint8_t *die_flags)
{
	switch (form) {
	case DW_FORM_flag:
		*insn_ret = ATTRIB_DECLARATION_FLAG;
		return NULL;
	case DW_FORM_flag_present:
		/*
		 * This could be an instruction, but as long as we have a free
		 * DIE flag bit, we might as well use it.
		 */
		*insn_ret = 0;
		*die_flags |= DIE_FLAG_DECLARATION;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = ATTRIB_DECLARATION_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %" PRIu64 " for DW_AT_declaration",
					   form);
	}
}

static struct drgn_error *
dw_at_specification_to_insn(struct drgn_dwarf_index_cu *cu,
			    struct binary_buffer *bb, uint64_t form,
			    uint8_t *insn_ret)
{
	switch (form) {
	case DW_FORM_ref1:
		*insn_ret = ATTRIB_SPECIFICATION_REF1;
		return NULL;
	case DW_FORM_ref2:
		*insn_ret = ATTRIB_SPECIFICATION_REF2;
		return NULL;
	case DW_FORM_ref4:
		*insn_ret = ATTRIB_SPECIFICATION_REF4;
		return NULL;
	case DW_FORM_ref8:
		*insn_ret = ATTRIB_SPECIFICATION_REF8;
		return NULL;
	case DW_FORM_ref_udata:
		*insn_ret = ATTRIB_SPECIFICATION_REF_UDATA;
		return NULL;
	case DW_FORM_ref_addr:
		if (cu->version >= 3) {
			if (cu->is_64_bit)
				*insn_ret = ATTRIB_SPECIFICATION_REF_ADDR8;
			else
				*insn_ret = ATTRIB_SPECIFICATION_REF_ADDR4;
		} else {
			if (cu->address_size == 8)
				*insn_ret = ATTRIB_SPECIFICATION_REF_ADDR8;
			else if (cu->address_size == 4)
				*insn_ret = ATTRIB_SPECIFICATION_REF_ADDR4;
			else
				return binary_buffer_error(bb,
							   "unsupported address size %" PRIu8 " for DW_FORM_ref_addr",
							   cu->address_size);
		}
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = ATTRIB_SPECIFICATION_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %" PRIu64 " for DW_AT_specification",
					   form);
	}
}

static struct drgn_error *
read_abbrev_decl(struct drgn_debug_info_buffer *buffer,
		 struct drgn_dwarf_index_cu *cu, struct uint32_vector *decls,
		 struct uint8_vector *insns)
{
	struct drgn_error *err;

	static_assert(ATTRIB_MAX_INSN == UINT8_MAX,
		      "maximum DWARF attribute instruction is invalid");

	uint64_t code;
	if ((err = binary_buffer_next_uleb128(&buffer->bb, &code)))
		return err;
	if (code == 0)
		return &drgn_stop;
	if (code != decls->size + 1) {
		return binary_buffer_error(&buffer->bb,
					   "DWARF abbrevation table is not sequential");
	}

	uint32_t insn_index = insns->size;
	if (!uint32_vector_append(decls, &insn_index))
		return &drgn_enomem;

	uint64_t tag;
	if ((err = binary_buffer_next_uleb128(&buffer->bb, &tag)))
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
	if ((err = binary_buffer_next_u8(&buffer->bb, &children)))
		return err;
	if (children)
		die_flags |= DIE_FLAG_CHILDREN;

	bool first = true;
	uint8_t insn;
	for (;;) {
		uint64_t name, form;
		if ((err = binary_buffer_next_uleb128(&buffer->bb, &name)))
			return err;
		if ((err = binary_buffer_next_uleb128(&buffer->bb, &form)))
			return err;
		if (name == 0 && form == 0)
			break;

		if (name == DW_AT_sibling) {
			err = dw_at_sibling_to_insn(&buffer->bb, form, &insn);
		} else if (name == DW_AT_name && should_index) {
			err = dw_at_name_to_insn(cu, &buffer->bb, form, &insn);
		} else if (name == DW_AT_stmt_list) {
			if (!cu->module->scn_data[DRGN_SCN_DEBUG_LINE]) {
				return binary_buffer_error(&buffer->bb,
							   "DW_AT_stmt_list without .debug_line section");
			}
			err = dw_at_stmt_list_to_insn(cu, &buffer->bb, form,
						      &insn);
		} else if (name == DW_AT_decl_file && should_index &&
			   /* Namespaces are merged, so we ignore their file. */
			   tag != DW_TAG_namespace) {
			err = dw_at_decl_file_to_insn(&buffer->bb, form, &insn);
		} else if (name == DW_AT_declaration && should_index) {
			err = dw_at_declaration_to_insn(&buffer->bb, form,
							&insn, &die_flags);
		} else if (name == DW_AT_specification && should_index) {
			err = dw_at_specification_to_insn(cu, &buffer->bb, form,
							  &insn);
		} else {
			err = dw_form_to_insn(cu, &buffer->bb, form, &insn);
		}
		if (err)
			return err;

		if (insn != 0) {
			if (!first && insn <= INSN_MAX_SKIP) {
				uint8_t last_insn = insns->data[insns->size - 1];
				if (last_insn + insn <= INSN_MAX_SKIP) {
					insns->data[insns->size - 1] += insn;
					continue;
				} else if (last_insn < INSN_MAX_SKIP) {
					insn = last_insn + insn - INSN_MAX_SKIP;
					insns->data[insns->size - 1] = INSN_MAX_SKIP;
				}
			}

			if (!uint8_vector_append(insns, &insn))
				return &drgn_enomem;
			first = false;
		}
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
	struct drgn_debug_info_buffer buffer;
	drgn_debug_info_buffer_init(&buffer, cu->module, DRGN_SCN_DEBUG_ABBREV);
	/* Checked in read_cu(). */
	buffer.bb.pos += debug_abbrev_offset;
	struct uint32_vector decls = VECTOR_INIT;
	struct uint8_vector insns = VECTOR_INIT;
	for (;;) {
		struct drgn_error *err = read_abbrev_decl(&buffer, cu, &decls,
							  &insns);
		if (err == &drgn_stop) {
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

static struct drgn_error *read_cu(struct drgn_dwarf_index_cu_buffer *buffer)
{
	struct drgn_error *err;
	buffer->bb.pos += buffer->cu->is_64_bit ? 12 : 4;
	uint16_t version;
	if ((err = binary_buffer_next_u16(&buffer->bb, &version)))
		return err;
	if (version < 2 || version > 4) {
		return binary_buffer_error(&buffer->bb,
					   "unknown DWARF CU version %" PRIu16,
					   version);
	}
	buffer->cu->version = version;

	uint64_t debug_abbrev_offset;
	if (buffer->cu->is_64_bit) {
		if ((err = binary_buffer_next_u64(&buffer->bb,
						  &debug_abbrev_offset)))
			return err;
	} else {
		if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
							   &debug_abbrev_offset)))
			return err;
	}
	if (debug_abbrev_offset >
	    buffer->cu->module->scn_data[DRGN_SCN_DEBUG_ABBREV]->d_size) {
		return binary_buffer_error(&buffer->bb,
					   "debug_abbrev_offset is out of bounds");
	}

	if ((err = binary_buffer_next_u8(&buffer->bb,
					 &buffer->cu->address_size)))
		return err;

	/* Skip type_signature and type_offset for type units. */
	if (buffer->cu->is_type_unit &&
	    (err = binary_buffer_skip(&buffer->bb,
				      buffer->cu->is_64_bit ? 16 : 12)))
		return err;

	return read_abbrev_table(buffer->cu, debug_abbrev_offset);
}

static struct drgn_error *skip_lnp_header(struct drgn_debug_info_buffer *buffer)
{
	struct drgn_error *err;
	uint32_t tmp;
	if ((err = binary_buffer_next_u32(&buffer->bb, &tmp)))
		return err;
	bool is_64_bit = tmp == UINT32_C(0xffffffff);
	if (is_64_bit &&
	    (err = binary_buffer_skip(&buffer->bb, sizeof(uint64_t))))
		return err;

	uint16_t version;
	if ((err = binary_buffer_next_u16(&buffer->bb, &version)))
		return err;
	if (version < 2 || version > 4) {
		return binary_buffer_error(&buffer->bb,
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
	if ((err = binary_buffer_skip(&buffer->bb,
				      (is_64_bit ? 8 : 4) + 4 + (version >= 4))) ||
	    (err = binary_buffer_next_u8(&buffer->bb, &opcode_base)) ||
	    (err = binary_buffer_skip(&buffer->bb, opcode_base - 1)))
		return err;

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

	struct drgn_debug_info_buffer buffer;
	drgn_debug_info_buffer_init(&buffer, cu->module, DRGN_SCN_DEBUG_LINE);
	/* Checked in index_cu_first_pass(). */
	buffer.bb.pos += stmt_list;

	if ((err = skip_lnp_header(&buffer)))
		return err;

	struct siphash_vector directories = VECTOR_INIT;
	for (;;) {
		const char *path;
		size_t path_len;
		if ((err = binary_buffer_next_string(&buffer.bb, &path,
						     &path_len)))
			goto out_directories;
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
		if ((err = binary_buffer_next_string(&buffer.bb, &path,
						     &path_len)))
			goto out_hashes;
		if (!path_len)
			break;

		uint64_t directory_index;
		if ((err = binary_buffer_next_uleb128(&buffer.bb,
						      &directory_index)))
			goto out_hashes;
		if (directory_index > directories.size) {
			err = binary_buffer_error(&buffer.bb,
						  "directory index %" PRIu64 " is invalid",
						  directory_index);
			goto out_hashes;
		}

		/* mtime, size */
		if ((err = binary_buffer_skip_leb128(&buffer.bb)) ||
		    (err = binary_buffer_skip_leb128(&buffer.bb)))
			goto out_hashes;

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
		    struct drgn_debug_info_module *module, uintptr_t addr)
{
	struct drgn_dwarf_index_specification entry = {
		.declaration = declaration,
		.module = module,
		.addr = addr,
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

static struct drgn_error *read_indirect_insn(struct drgn_dwarf_index_cu *cu,
					     struct binary_buffer *bb,
					     uint8_t insn, uint8_t *insn_ret,
					     uint8_t *die_flags)
{
	struct drgn_error *err;
	uint64_t form;
	if ((err = binary_buffer_next_uleb128(bb, &form)))
		return err;
	switch (insn) {
	case ATTRIB_INDIRECT:
		return dw_form_to_insn(cu, bb, form, insn_ret);
	case ATTRIB_SIBLING_INDIRECT:
		return dw_at_sibling_to_insn(bb, form, insn_ret);
	case ATTRIB_NAME_INDIRECT:
		return dw_at_name_to_insn(cu, bb, form, insn_ret);
	case ATTRIB_STMT_LIST_INDIRECT:
		return dw_at_stmt_list_to_insn(cu, bb, form, insn_ret);
	case ATTRIB_DECL_FILE_INDIRECT:
		return dw_at_decl_file_to_insn(bb, form, insn_ret);
	case ATTRIB_DECLARATION_INDIRECT:
		return dw_at_declaration_to_insn(bb, form, insn_ret, die_flags);
	case ATTRIB_SPECIFICATION_INDIRECT:
		return dw_at_specification_to_insn(cu, bb, form, insn_ret);
	default:
		UNREACHABLE();
	}
}

/*
 * First pass: read the file name tables and index DIEs with
 * DW_AT_specification. This recurses into namespaces.
 */
static struct drgn_error *
index_cu_first_pass(struct drgn_dwarf_index *dindex,
		    struct drgn_dwarf_index_cu_buffer *buffer)
{
	struct drgn_error *err;
	struct drgn_dwarf_index_cu *cu = buffer->cu;
	Elf_Data *debug_info = cu->module->scn_data[
		cu->is_type_unit ? DRGN_SCN_DEBUG_TYPES : DRGN_SCN_DEBUG_INFO];
	const char *debug_info_buffer = debug_info->d_buf;
	unsigned int depth = 0;
	for (;;) {
		size_t die_addr = (uintptr_t)buffer->bb.pos;

		uint64_t code;
		if ((err = binary_buffer_next_uleb128(&buffer->bb, &code)))
			return err;
		if (code == 0) {
			if (depth-- > 1)
				continue;
			else
				break;
		} else if (code > cu->num_abbrev_decls) {
			return binary_buffer_error(&buffer->bb,
						   "unknown abbreviation code %" PRIu64,
						   code);
		}

		uint8_t *insnp = &cu->abbrev_insns[cu->abbrev_decls[code - 1]];
		bool declaration = false;
		uintptr_t specification = 0;
		const char *stmt_list_ptr = NULL;
		uint64_t stmt_list;
		const char *sibling = NULL;
		uint8_t insn;
		uint8_t extra_die_flags = 0;
		while ((insn = *insnp++)) {
indirect_insn:;
			uint64_t skip, tmp;
			switch (insn) {
			case ATTRIB_BLOCK1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &skip)))
					return err;
				goto skip;
			case ATTRIB_BLOCK2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &skip)))
					return err;
				goto skip;
			case ATTRIB_BLOCK4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &skip)))
					return err;
				goto skip;
			case ATTRIB_EXPRLOC:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &skip)))
					return err;
				goto skip;
			case ATTRIB_LEB128:
			case ATTRIB_DECL_FILE_UDATA:
				if ((err = binary_buffer_skip_leb128(&buffer->bb)))
					return err;
				break;
			case ATTRIB_STRING:
			case ATTRIB_NAME_STRING:
				if ((err = binary_buffer_skip_string(&buffer->bb)))
					return err;
				break;
			case ATTRIB_SIBLING_REF1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &tmp)))
					return err;
				goto sibling;
			case ATTRIB_SIBLING_REF2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto sibling;
			case ATTRIB_SIBLING_REF4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto sibling;
			case ATTRIB_SIBLING_REF8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
				goto sibling;
			case ATTRIB_SIBLING_REF_UDATA:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &tmp)))
					return err;
sibling:
				if (tmp > cu->len) {
					return binary_buffer_error(&buffer->bb,
								   "DW_AT_sibling is out of bounds");
				}
				sibling = cu->buf + tmp;
				__builtin_prefetch(sibling);
				if (sibling < buffer->bb.pos) {
					return binary_buffer_error(&buffer->bb,
								   "DW_AT_sibling points backwards");
				}
				break;
			case ATTRIB_STMT_LIST_LINEPTR4:
				stmt_list_ptr = buffer->bb.pos;
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &stmt_list)))
					return err;
				break;
			case ATTRIB_STMT_LIST_LINEPTR8:
				stmt_list_ptr = buffer->bb.pos;
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &stmt_list)))
					return err;
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
				if ((err = binary_buffer_next_u8(&buffer->bb,
								 &flag)))
					return err;
				if (flag)
					declaration = true;
				break;
			}
			case ATTRIB_SPECIFICATION_REF1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &tmp)))
					return err;
				goto specification;
			case ATTRIB_SPECIFICATION_REF2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto specification;
			case ATTRIB_SPECIFICATION_REF4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto specification;
			case ATTRIB_SPECIFICATION_REF8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
				goto specification;
			case ATTRIB_SPECIFICATION_REF_UDATA:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &tmp)))
					return err;
specification:
				specification = (uintptr_t)cu->buf + tmp;
				break;
			case ATTRIB_SPECIFICATION_REF_ADDR4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto specification_ref_addr;
			case ATTRIB_SPECIFICATION_REF_ADDR8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
specification_ref_addr:
				specification = (uintptr_t)debug_info_buffer + tmp;
				break;
			case ATTRIB_INDIRECT:
			case ATTRIB_SIBLING_INDIRECT:
			case ATTRIB_NAME_INDIRECT:
			case ATTRIB_STMT_LIST_INDIRECT:
			case ATTRIB_DECL_FILE_INDIRECT:
			case ATTRIB_DECLARATION_INDIRECT:
			case ATTRIB_SPECIFICATION_INDIRECT:
				if ((err = read_indirect_insn(cu, &buffer->bb,
							      insn, &insn,
							      &extra_die_flags)))
					return err;
				if (insn)
					goto indirect_insn;
				else
					continue;
			default:
				skip = insn;
skip:
				if ((err = binary_buffer_skip(&buffer->bb,
							      skip)))
					return err;
				break;
			}
		}
		insn = *insnp | extra_die_flags;

		if (depth == 0) {
			if (stmt_list_ptr) {
				if (stmt_list >
				    cu->module->scn_data[DRGN_SCN_DEBUG_LINE]->d_size) {
					return binary_buffer_error_at(&buffer->bb,
								      stmt_list_ptr,
								      "DW_AT_stmt_list is out of bounds");
				}
				if ((err = read_file_name_table(dindex, cu,
								stmt_list)))
					return err;
			}
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
						       cu->module, die_addr)))
				return err;
		}

		if (insn & DIE_FLAG_CHILDREN) {
			if (sibling &&
			    (insn & DIE_FLAG_TAG_MASK) != DW_TAG_namespace)
				buffer->bb.pos = sibling;
			else
				depth++;
		} else if (depth == 0) {
			break;
		}
	}
	return NULL;
}

static struct drgn_error *
drgn_dwarf_index_read_cus(struct drgn_dwarf_index_update_state *state,
			  struct drgn_debug_info_module *module,
			  enum drgn_debug_info_scn scn)
{
	struct drgn_dwarf_index_pending_cu_vector *cus =
		&state->cus[omp_get_thread_num()];

	struct drgn_error *err;
	struct drgn_debug_info_buffer buffer;
	drgn_debug_info_buffer_init(&buffer, module, scn);
	while (binary_buffer_has_next(&buffer.bb)) {
		struct drgn_dwarf_index_pending_cu *cu =
			drgn_dwarf_index_pending_cu_vector_append_entry(cus);
		if (!cu)
			return &drgn_enomem;
		cu->module = module;
		cu->buf = buffer.bb.pos;
		uint32_t unit_length32;
		if ((err = binary_buffer_next_u32(&buffer.bb, &unit_length32)))
			return err;
		cu->is_64_bit = unit_length32 == UINT32_C(0xffffffff);
		if (cu->is_64_bit) {
			uint64_t unit_length64;
			if ((err = binary_buffer_next_u64(&buffer.bb,
							  &unit_length64)))
				return err;
			if (unit_length64 > SIZE_MAX) {
				return binary_buffer_error(&buffer.bb,
							   "unit length is too large");
			}
			if ((err = binary_buffer_skip(&buffer.bb,
						      unit_length64)))
				return err;
		} else {
			if ((err = binary_buffer_skip(&buffer.bb,
						      unit_length32)))
				return err;
		}
		cu->len = buffer.bb.pos - cu->buf;
		cu->scn = scn;
	}
	return NULL;
}

struct drgn_error *
drgn_dwarf_index_read_module(struct drgn_dwarf_index_update_state *state,
			     struct drgn_debug_info_module *module)
{
	struct drgn_error *err;
	err = drgn_dwarf_index_read_cus(state, module, DRGN_SCN_DEBUG_INFO);
	if (!err && module->scn_data[DRGN_SCN_DEBUG_TYPES]) {
		err = drgn_dwarf_index_read_cus(state, module,
						DRGN_SCN_DEBUG_TYPES);
	}
	return err;
}

bool
drgn_dwarf_index_find_definition(struct drgn_dwarf_index *dindex,
				 uintptr_t die_addr,
				 struct drgn_debug_info_module **module_ret,
				 uintptr_t *addr_ret)
{
	struct drgn_dwarf_index_specification_map_iterator it =
		drgn_dwarf_index_specification_map_search(&dindex->specifications,
							  &die_addr);
	if (!it.entry)
		return false;
	*module_ret = it.entry->module;
	*addr_ret = it.entry->addr;
	return true;
}

static bool append_die_entry(struct drgn_dwarf_index *dindex,
			     struct drgn_dwarf_index_shard *shard, uint8_t tag,
			     uint64_t file_name_hash,
			     struct drgn_debug_info_module *module,
			     uintptr_t addr)
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
	die->addr = addr;

	return true;
}

static struct drgn_error *index_die(struct drgn_dwarf_index_namespace *ns,
				    struct drgn_dwarf_index_cu *cu,
				    const char *name, uint8_t tag,
				    uint64_t file_name_hash,
				    struct drgn_debug_info_module *module,
				    uintptr_t addr)
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
				      module, addr)) {
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
			      addr)) {
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
		pending->addr = addr;
	}
	err = NULL;
err:
	omp_unset_lock(&shard->lock);
	return err;
}

/* Second pass: index the actual DIEs. */
static struct drgn_error *
index_cu_second_pass(struct drgn_dwarf_index_namespace *ns,
		     struct drgn_dwarf_index_cu_buffer *buffer)
{
	struct drgn_error *err;
	struct drgn_dwarf_index_cu *cu = buffer->cu;
	Elf_Data *debug_str = cu->module->scn_data[DRGN_SCN_DEBUG_STR];
	unsigned int depth = 0;
	uint8_t depth1_tag = 0;
	size_t depth1_addr = 0;
	for (;;) {
		size_t die_addr = (uintptr_t)buffer->bb.pos;

		uint64_t code;
		if ((err = binary_buffer_next_uleb128(&buffer->bb, &code)))
			return err;
		if (code == 0) {
			if (depth-- > 1)
				continue;
			else
				break;
		} else if (code > cu->num_abbrev_decls) {
			return binary_buffer_error(&buffer->bb,
						   "unknown abbreviation code %" PRIu64,
						   code);
		}

		uint8_t *insnp = &cu->abbrev_insns[cu->abbrev_decls[code - 1]];
		const char *name = NULL;
		const char *decl_file_ptr = NULL;
		uint64_t decl_file = 0;
		bool declaration = false;
		bool specification = false;
		const char *sibling = NULL;
		uint8_t insn;
		uint8_t extra_die_flags = 0;
		while ((insn = *insnp++)) {
indirect_insn:;
			uint64_t skip, tmp;
			switch (insn) {
			case ATTRIB_BLOCK1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &skip)))
					return err;
				goto skip;
			case ATTRIB_BLOCK2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &skip)))
					return err;
				goto skip;
			case ATTRIB_BLOCK4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &skip)))
					return err;
				goto skip;
			case ATTRIB_EXPRLOC:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &skip)))
					return err;
				goto skip;
			case ATTRIB_SPECIFICATION_REF_UDATA:
				specification = true;
				/* fallthrough */
			case ATTRIB_LEB128:
				if ((err = binary_buffer_skip_leb128(&buffer->bb)))
					return err;
				break;
			case ATTRIB_NAME_STRING:
				name = buffer->bb.pos;
				/* fallthrough */
			case ATTRIB_STRING:
				if ((err = binary_buffer_skip_string(&buffer->bb)))
					return err;
				break;
			case ATTRIB_SIBLING_REF1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &tmp)))
					return err;
				goto sibling;
			case ATTRIB_SIBLING_REF2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto sibling;
			case ATTRIB_SIBLING_REF4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto sibling;
			case ATTRIB_SIBLING_REF8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
				goto sibling;
			case ATTRIB_SIBLING_REF_UDATA:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &tmp)))
					return err;
sibling:
				if (tmp > cu->len) {
					return binary_buffer_error(&buffer->bb,
								   "DW_AT_sibling is out of bounds");
				}
				sibling = cu->buf + tmp;
				__builtin_prefetch(sibling);
				if (sibling < buffer->bb.pos) {
					return binary_buffer_error(&buffer->bb,
								   "DW_AT_sibling points backwards");
				}
				break;
			case ATTRIB_NAME_STRP4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto strp;
			case ATTRIB_NAME_STRP8:
				if ((err = binary_buffer_next_u64(&buffer->bb, &tmp)))
					return err;
strp:
				if (tmp > debug_str->d_size) {
					return binary_buffer_error(&buffer->bb,
								   "DW_AT_name is out of bounds");
				}
				name = (const char *)debug_str->d_buf + tmp;
				__builtin_prefetch(name);
				break;
			case ATTRIB_STMT_LIST_LINEPTR4:
				skip = 4;
				goto skip;
			case ATTRIB_STMT_LIST_LINEPTR8:
				skip = 8;
				goto skip;
			case ATTRIB_DECL_FILE_DATA1:
				decl_file_ptr = buffer->bb.pos;
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &decl_file)))
					return err;
				break;
			case ATTRIB_DECL_FILE_DATA2:
				decl_file_ptr = buffer->bb.pos;
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &decl_file)))
					return err;
				break;
			case ATTRIB_DECL_FILE_DATA4:
				decl_file_ptr = buffer->bb.pos;
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &decl_file)))
					return err;
				break;
			case ATTRIB_DECL_FILE_DATA8:
				decl_file_ptr = buffer->bb.pos;
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &decl_file)))
					return err;
				break;
			case ATTRIB_DECL_FILE_UDATA:
				decl_file_ptr = buffer->bb.pos;
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &decl_file)))
					return err;
				break;
			case ATTRIB_DECLARATION_FLAG: {
				uint8_t flag;
				if ((err = binary_buffer_next_u8(&buffer->bb,
								 &flag)))
					return err;
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
			case ATTRIB_INDIRECT:
			case ATTRIB_SIBLING_INDIRECT:
			case ATTRIB_NAME_INDIRECT:
			case ATTRIB_STMT_LIST_INDIRECT:
			case ATTRIB_DECL_FILE_INDIRECT:
			case ATTRIB_DECLARATION_INDIRECT:
			case ATTRIB_SPECIFICATION_INDIRECT:
				if ((err = read_indirect_insn(cu, &buffer->bb,
							      insn, &insn,
							      &extra_die_flags)))
					return err;
				if (insn)
					goto indirect_insn;
				else
					continue;
			default:
				skip = insn;
skip:
				if ((err = binary_buffer_skip(&buffer->bb,
							      skip)))
					return err;
				break;
			}
		}
		insn = *insnp | extra_die_flags;

		uint8_t tag = insn & DIE_FLAG_TAG_MASK;
		if (depth == 1) {
			depth1_tag = tag;
			depth1_addr = die_addr;
		}
		if (depth == (tag == DW_TAG_enumerator ? 2 : 1) && name &&
		    !specification) {
			if (insn & DIE_FLAG_DECLARATION)
				declaration = true;
			struct drgn_debug_info_module *module = cu->module;
			if (tag == DW_TAG_enumerator) {
				if (depth1_tag != DW_TAG_enumeration_type)
					goto next;
				/*
				 * NB: the enumerator name points to the
				 * enumeration_type DIE. Also, enumerators can't
				 * be declared in C/C++, so we don't check for
				 * that.
				 */
				die_addr = depth1_addr;
			} else if (declaration &&
				   !drgn_dwarf_index_find_definition(ns->dindex,
								     die_addr,
								     &module,
								     &die_addr)) {
				goto next;
			}

			uint64_t file_name_hash;
			if (decl_file) {
				if (decl_file > cu->num_file_names) {
					return binary_buffer_error_at(&buffer->bb,
								      decl_file_ptr,
								      "invalid DW_AT_decl_file %" PRIu64,
								      decl_file);
				}
				file_name_hash = cu->file_name_hashes[decl_file - 1];
			} else {
				file_name_hash = 0;
			}
			if ((err = index_die(ns, cu, name, tag, file_name_hash,
					     module, die_addr)))
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
				buffer->bb.pos = sibling;
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
			if (die->module->state ==
			    DRGN_DEBUG_INFO_MODULE_INDEXED)
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
		if (it.entry->module->state == DRGN_DEBUG_INFO_MODULE_INDEXED) {
			it = drgn_dwarf_index_specification_map_next(it);
		} else {
			it = drgn_dwarf_index_specification_map_delete_iterator(&dindex->specifications,
										it);
		}
	}
}

struct drgn_error *
drgn_dwarf_index_update(struct drgn_dwarf_index_update_state *state)
{
	struct drgn_dwarf_index *dindex = state->dindex;

	size_t old_cus_size = dindex->cus.size;
	size_t new_cus_size = old_cus_size;
	for (size_t i = 0; i < state->max_threads; i++)
		new_cus_size += state->cus[i].size;
	if (!drgn_dwarf_index_cu_vector_reserve(&dindex->cus, new_cus_size))
		return &drgn_enomem;
	for (size_t i = 0; i < state->max_threads; i++) {
		for (size_t j = 0; j < state->cus[i].size; j++) {
			struct drgn_dwarf_index_pending_cu *pending_cu =
				&state->cus[i].data[j];
			dindex->cus.data[dindex->cus.size++] = (struct drgn_dwarf_index_cu){
				.module = pending_cu->module,
				.buf = pending_cu->buf,
				.len = pending_cu->len,
				.is_64_bit = pending_cu->is_64_bit,
				.is_type_unit =
					pending_cu->scn == DRGN_SCN_DEBUG_TYPES,
			};
		}
	}

	struct drgn_error *err = NULL;
	#pragma omp parallel for schedule(dynamic)
	for (size_t i = old_cus_size; i < dindex->cus.size; i++) {
		if (err)
			continue;
		struct drgn_dwarf_index_cu *cu = &dindex->cus.data[i];
		struct drgn_dwarf_index_cu_buffer cu_buffer;
		drgn_dwarf_index_cu_buffer_init(&cu_buffer, cu);
		struct drgn_error *cu_err = read_cu(&cu_buffer);
		if (!cu_err)
			cu_err = index_cu_first_pass(state->dindex, &cu_buffer);
		if (cu_err) {
			#pragma omp critical(drgn_dwarf_index_update_end_error)
			if (err)
				drgn_error_destroy(cu_err);
			else
				err = cu_err;
		}
	}
	if (err)
		goto err;

	#pragma omp parallel for schedule(dynamic)
	for (size_t i = old_cus_size; i < dindex->cus.size; i++) {
		if (err)
			continue;
		struct drgn_dwarf_index_cu *cu = &dindex->cus.data[i];
		struct drgn_dwarf_index_cu_buffer buffer;
		drgn_dwarf_index_cu_buffer_init(&buffer, cu);
		buffer.bb.pos += cu->is_64_bit ? 23 : 11;
		if (cu->is_type_unit)
			buffer.bb.pos += cu->is_64_bit ? 16 : 12;
		struct drgn_error *cu_err =
			index_cu_second_pass(&dindex->global, &buffer);
		if (cu_err) {
			#pragma omp critical(drgn_dwarf_index_update_end_error)
			if (err)
				drgn_error_destroy(cu_err);
			else
				err = cu_err;
		}
	}
	if (err) {
		drgn_dwarf_index_rollback(dindex);
err:
		for (size_t i = old_cus_size; i < dindex->cus.size; i++)
			drgn_dwarf_index_cu_deinit(&dindex->cus.data[i]);
		dindex->cus.size = old_cus_size;
	}
	return err;
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
			struct drgn_dwarf_index_cu_buffer buffer;
			drgn_dwarf_index_cu_buffer_init(&buffer, cu);
			buffer.bb.pos = (char *)pending->addr;
			struct drgn_error *cu_err =
				index_cu_second_pass(ns, &buffer);
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
					    Dwarf_Die *die_ret)
{
	Dwarf_Addr bias;
	Dwarf *dwarf = dwfl_module_getdwarf(die->module->dwfl_module, &bias);
	if (!dwarf)
		return drgn_error_libdwfl();
	uintptr_t start =
		(uintptr_t)die->module->scn_data[DRGN_SCN_DEBUG_INFO]->d_buf;
	size_t size = die->module->scn_data[DRGN_SCN_DEBUG_INFO]->d_size;
	if (die->addr >= start && die->addr < start + size) {
		if (!dwarf_offdie(dwarf, die->addr - start, die_ret))
			return drgn_error_libdw();
	} else {
		start = (uintptr_t)die->module->scn_data[DRGN_SCN_DEBUG_TYPES]->d_buf;
		if (!dwarf_offdie_types(dwarf, die->addr - start, die_ret))
			return drgn_error_libdw();
	}
	return NULL;
}
