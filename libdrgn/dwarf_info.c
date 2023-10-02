// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <byteswap.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <gelf.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "binary_buffer.h"
#include "cleanup.h"
#include "debug_info.h" // IWYU pragma: associated
#include "dwarf_constants.h"
#include "elf_file.h"
#include "error.h"
#include "language.h"
#include "lazy_object.h"
#include "log.h"
#include "minmax.h"
#include "object.h"
#include "openmp.h"
#include "path.h"
#include "program.h"
#include "platform.h"
#include "register_state.h"
#include "serialize.h"
#include "type.h"
#include "util.h"

void drgn_module_dwarf_info_deinit(struct drgn_module *module)
{
	free(module->dwarf.eh_frame.fdes);
	free(module->dwarf.eh_frame.cies);
	free(module->dwarf.debug_frame.fdes);
	free(module->dwarf.debug_frame.cies);
}

DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_die_vector);

DEFINE_HASH_MAP_FUNCTIONS(drgn_dwarf_index_die_map, nstring_hash_pair,
			  nstring_eq);

static inline struct nstring
drgn_namespace_key(struct drgn_namespace_dwarf_index * const *entry)
{
	return (struct nstring){ (*entry)->name, (*entry)->name_len };
}
DEFINE_HASH_TABLE_FUNCTIONS(drgn_namespace_table, drgn_namespace_key,
			    nstring_hash_pair, nstring_eq);

DEFINE_HASH_MAP_FUNCTIONS(drgn_dwarf_base_type_map, nstring_hash_pair,
			  nstring_eq);

DEFINE_HASH_MAP_FUNCTIONS(drgn_dwarf_specification_map, int_key_hash_pair,
			  scalar_key_eq);

/** DWARF compilation unit indexed in a @ref drgn_namespace_dwarf_index. */
struct drgn_dwarf_index_cu {
	/** File containing CU. */
	struct drgn_elf_file *file;
	/** Address of CU data. */
	const char *buf;
	/** Length of CU data. */
	size_t len;
	/** DWARF version from CU header. */
	uint8_t version;
	/** `DW_UT_*` type from CU header. */
	uint8_t unit_type;
	/** Address size from CU header. */
	uint8_t address_size;
	/** Whether CU uses 64-bit DWARF format. */
	bool is_64_bit;
	/**
	 * Section containing CU (@ref DRGN_SCN_DEBUG_INFO or @ref
	 * DRGN_SCN_DEBUG_TYPES).
	 */
	enum drgn_section_index scn;
	/**
	 * Mapping from DWARF abbreviation code to instructions for that
	 * abbreviation.
	 *
	 * This is indexed on the DWARF abbreviation code minus one. I.e.,
	 * `abbrev_insns[abbrev_decls[abbrev_code - 1]]` is the first
	 * instruction for that abbreviation code.
	 *
	 * Technically, abbreviation codes don't have to be sequential. In
	 * practice, GCC and Clang seem to always generate sequential codes
	 * starting at one, so we can get away with a flat array.
	 */
	uint32_t *abbrev_decls;
	union {
		/** Number of abbreviation codes. */
		size_t num_abbrev_decls;
		/**
		 * Pointer in .debug_abbrev for this CU.
		 *
		 * This is only used before indexing, then it is replaced by @c
		 * abbrev_decls, @c num_abbrev_decls, and @c abbrev_insns. It is
		 * a union with @c num_abbrev_decls rather than one of the other
		 * two fields because that way we don't need to worry about
		 * accidentally freeing it.
		 */
		const char *pending_abbrev;
	};
	/**
	 * Buffer of @ref drgn_dwarf_index_abbrev_insn instructions for all
	 * abbreviation codes.
	 *
	 * These are all stored in one array for cache locality.
	 */
	uint8_t *abbrev_insns;
	/**
	 * Pointer in `.debug_str_offsets` section to string offset entries for
	 * this CU.
	 */
	const char *str_offsets;
	/** libdw structure for this CU. */
	Dwarf_CU *libdw_cu;
};

DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_cu_vector);

DEFINE_HASH_MAP_FUNCTIONS(drgn_dwarf_type_map, ptr_key_hash_pair,
			  scalar_key_eq);

static void
drgn_namespace_dwarf_index_init(struct drgn_namespace_dwarf_index *dindex,
				const char *name, size_t name_len,
				struct drgn_namespace_dwarf_index *parent)
{
	dindex->dbinfo = parent->dbinfo;
	dindex->name = name;
	dindex->name_len = name_len;
	dindex->parent = parent;
	drgn_namespace_table_init(&dindex->children);
	array_for_each(tag_map, dindex->map)
		drgn_dwarf_index_die_map_init(tag_map);
	dindex->cus_indexed = 0;
	memset(dindex->dies_indexed, 0, sizeof(dindex->dies_indexed));
	dindex->saved_err = NULL;
}

static void
drgn_namespace_dwarf_index_deinit(struct drgn_namespace_dwarf_index *dindex)
{
	drgn_error_destroy(dindex->saved_err);
	array_for_each(tag_map, dindex->map) {
		for (auto it = drgn_dwarf_index_die_map_first(tag_map); it.entry;
		     it = drgn_dwarf_index_die_map_next(it))
			drgn_dwarf_index_die_vector_deinit(&it.entry->value);
		drgn_dwarf_index_die_map_deinit(tag_map);
	}
	for (auto it = drgn_namespace_table_first(&dindex->children); it.entry;
	     it = drgn_namespace_table_next(it)) {
		drgn_namespace_dwarf_index_deinit(*it.entry);
		free(*it.entry);
	}
	drgn_namespace_table_deinit(&dindex->children);
}

void drgn_dwarf_info_init(struct drgn_debug_info *dbinfo)
{
	dbinfo->dwarf.global.dbinfo = dbinfo;
	drgn_namespace_dwarf_index_init(&dbinfo->dwarf.global, "", 0,
					&dbinfo->dwarf.global);
	dbinfo->dwarf.global.parent = NULL;
	drgn_dwarf_base_type_map_init(&dbinfo->dwarf.base_types);
	drgn_dwarf_specification_map_init(&dbinfo->dwarf.specifications);
	drgn_dwarf_index_cu_vector_init(&dbinfo->dwarf.index_cus);
	drgn_dwarf_type_map_init(&dbinfo->dwarf.types);
	drgn_dwarf_type_map_init(&dbinfo->dwarf.cant_be_incomplete_array_types);
	dbinfo->dwarf.depth = 0;
}

static void drgn_dwarf_index_cu_deinit(struct drgn_dwarf_index_cu *cu)
{
	free(cu->abbrev_insns);
	free(cu->abbrev_decls);
}

void drgn_dwarf_info_deinit(struct drgn_debug_info *dbinfo)
{
	drgn_dwarf_type_map_deinit(&dbinfo->dwarf.cant_be_incomplete_array_types);
	drgn_dwarf_type_map_deinit(&dbinfo->dwarf.types);
	vector_for_each(drgn_dwarf_index_cu_vector, cu,
			&dbinfo->dwarf.index_cus)
		drgn_dwarf_index_cu_deinit(cu);
	drgn_dwarf_index_cu_vector_deinit(&dbinfo->dwarf.index_cus);
	drgn_dwarf_specification_map_deinit(&dbinfo->dwarf.specifications);
	drgn_dwarf_base_type_map_deinit(&dbinfo->dwarf.base_types);
	drgn_namespace_dwarf_index_deinit(&dbinfo->dwarf.global);
}

/*
 * Diagnostics.
 */

/** Like @ref dw_tag_str(), but takes a @c Dwarf_Die. */
static const char *dwarf_tag_str(Dwarf_Die *die, char buf[DW_TAG_STR_BUF_LEN])
{
	return dw_tag_str(dwarf_tag(die), buf);
}

static inline struct drgn_error *drgn_check_address_size(uint8_t address_size)
{
	if (address_size < 1 || address_size > 8) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unsupported address size %" PRIu8,
					 address_size);
	}
	return NULL;
}

/*
 * Indexing.
 *
 * A core part of debugger functionality is looking up types, variables, etc. by
 * name. DWARF information can be very large, so scanning through all of it for
 * every lookup would be too slow. Instead, when we load debugging information,
 * we build an index of DIEs by name.
 *
 * This indexing step is parallelized and highly optimized. It is implemented as
 * a bespoke DWARF parser specialized for the task of scanning over DIEs
 * quickly.
 *
 * Although the DWARF standard defines ".debug_pubnames" and ".debug_names"
 * sections, GCC and Clang currently don't emit them by default, so we don't use
 * them.
 *
 * Every namespace has a separate index (@ref drgn_namespace_dwarf_index). The
 * global namespace is indexed immediately upon loading debugging information.
 * Other namespaces are indexed when they are first accessed.
 */

/**
 * DWARF abbreviation table instructions.
 *
 * The DWARF abbreviation table can be large and contains more information than
 * is strictly necessary for indexing. So, we translate the table into a series
 * of instructions which specify how to process a DIE. This instruction stream
 * omits unnecessary information and is more compact (and thus more cache
 * friendly), which is important for the tight DIE parsing loop.
 */
enum drgn_dwarf_index_abbrev_insn {
	/*
	 * Instructions > 0 and <= INSN_MAX_SKIP indicate a number of bytes to
	 * be skipped over.
	 */
	INSN_MAX_SKIP = 219,

	/* These instructions indicate an attribute that can be skipped over. */
	INSN_SKIP_BLOCK,
	INSN_SKIP_BLOCK1,
	INSN_SKIP_BLOCK2,
	INSN_SKIP_BLOCK4,
	INSN_SKIP_LEB128,
	INSN_SKIP_STRING,

	/* These instructions indicate an attribute that should be parsed. */
	INSN_SIBLING_REF1,
	INSN_SIBLING_REF2,
	INSN_SIBLING_REF4,
	INSN_SIBLING_REF8,
	INSN_SIBLING_REF_UDATA,
	INSN_NAME_STRP4,
	INSN_NAME_STRP8,
	INSN_NAME_STRING,
	INSN_NAME_STRX,
	INSN_NAME_STRX1,
	INSN_NAME_STRX2,
	INSN_NAME_STRX3,
	INSN_NAME_STRX4,
	INSN_NAME_STRP_ALT4,
	INSN_NAME_STRP_ALT8,
	INSN_DECLARATION_FLAG,
	INSN_SPECIFICATION_REF1,
	INSN_SPECIFICATION_REF2,
	INSN_SPECIFICATION_REF4,
	INSN_SPECIFICATION_REF8,
	INSN_SPECIFICATION_REF_UDATA,
	INSN_SPECIFICATION_REF_ADDR4,
	INSN_SPECIFICATION_REF_ADDR8,
	INSN_SPECIFICATION_REF_ALT4,
	INSN_SPECIFICATION_REF_ALT8,
	INSN_INDIRECT,
	INSN_SIBLING_INDIRECT,
	INSN_NAME_INDIRECT,
	INSN_DECLARATION_INDIRECT,
	INSN_SPECIFICATION_INDIRECT,

	NUM_INSNS,

	/*
	 * Every sequence of instructions for a DIE is terminated by a zero
	 * byte.
	 */
	INSN_END = 0,

	/*
	 * The byte after INSN_END contains the DIE flags, which are a bitmask
	 * of flags combined with the drgn_dwarf_index_tag.
	 */
	INSN_DIE_FLAG_TAG_MASK = 0x3f,
	/* DIE is a declaration. */
	INSN_DIE_FLAG_DECLARATION = 0x40,
	/* DIE has children. */
	INSN_DIE_FLAG_CHILDREN = 0x80,
};

// We use INSN_DIE_FLAG_TAG_MASK as a sentinel when the DIE shouldn't be
// indexed, so this is < and not <=.
static_assert((int)DRGN_DWARF_INDEX_NUM_TAGS < (int)INSN_DIE_FLAG_TAG_MASK,
	      "too many instruction DIE tags");

/* Instructions are 8 bits. */
static_assert(NUM_INSNS - 1 == UINT8_MAX,
	      "maximum DWARF index instruction is invalid");

DEFINE_VECTOR(uint8_vector, uint8_t);
DEFINE_VECTOR(uint32_vector, uint32_t);
DEFINE_VECTOR(uint64_vector, uint64_t);

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
	return drgn_elf_file_section_error(buffer->cu->file,
					   buffer->cu->file->scns[buffer->cu->scn],
					   buffer->cu->file->scn_data[buffer->cu->scn],
					   pos, message);
}

static void
drgn_dwarf_index_cu_buffer_init(struct drgn_dwarf_index_cu_buffer *buffer,
				struct drgn_dwarf_index_cu *cu)
{
	binary_buffer_init(&buffer->bb, cu->buf, cu->len,
			   drgn_elf_file_is_little_endian(cu->file),
			   drgn_dwarf_index_cu_buffer_error);
	buffer->cu = cu;
}

bool drgn_dwarf_index_state_init(struct drgn_dwarf_index_state *state,
				 struct drgn_debug_info *dbinfo)
{
	state->dbinfo = dbinfo;
	state->cus = malloc_array(drgn_num_threads, sizeof(*state->cus));
	if (!state->cus)
		return false;
	for (int i = 0; i < drgn_num_threads; i++)
		drgn_dwarf_index_cu_vector_init(&state->cus[i]);
	return true;
}

void drgn_dwarf_index_state_deinit(struct drgn_dwarf_index_state *state)
{
	for (int i = 0; i < drgn_num_threads; i++)
		drgn_dwarf_index_cu_vector_deinit(&state->cus[i]);
	free(state->cus);
}

static const char *drgn_dwarf_dwo_name(Dwarf_Die *die)
{
	Dwarf_Attribute attr_mem, *attr;
	if ((attr = dwarf_attr(die, DW_AT_dwo_name, &attr_mem))
	    || (attr = dwarf_attr(die, DW_AT_GNU_dwo_name, &attr_mem)))
		return dwarf_formstring(attr);
	return NULL;
}

static struct drgn_error *
drgn_dwarf_index_read_cus(struct drgn_dwarf_index_state *state,
			  struct drgn_elf_file *file,
			  enum drgn_section_index scn)
{
	struct drgn_error *err;
	struct drgn_dwarf_index_cu_vector *cus =
		&state->cus[omp_get_thread_num()];

	Dwarf_Off off = 0;
	Dwarf_Off next_off;
	size_t header_size;
	Dwarf_Half version;
	Dwarf_Off abbrev_offset;
	uint8_t address_size;
	uint8_t offset_size;
	uint64_t v4_type_signature;
	uint64_t *v4_type_signaturep =
		scn == DRGN_SCN_DEBUG_TYPES ? &v4_type_signature : NULL;
	int ret;
	while ((ret = dwarf_next_unit(file->dwarf, off, &next_off, &header_size,
				      &version, &abbrev_offset, &address_size,
				      &offset_size, v4_type_signaturep,
				      NULL)) == 0) {
		Dwarf_Die skeldie, cudie;
		if (scn == DRGN_SCN_DEBUG_TYPES) {
			if (!dwarf_offdie_types(file->dwarf, off + header_size,
						&skeldie))
				return drgn_error_libdw();
		} else {
			if (!dwarf_offdie(file->dwarf, off + header_size,
					  &skeldie))
				return drgn_error_libdw();
		}
		struct drgn_elf_file *cu_file = file;
		Dwarf_Off cu_start_off = off, cu_end_off = next_off;
		uint8_t unit_type;
#if _ELFUTILS_PREREQ(0, 171)
		if (dwarf_cu_info(skeldie.cu, NULL, &unit_type, &skeldie,
				  &cudie, NULL, NULL, NULL))
			return drgn_error_libdw();

		if (unit_type == DW_UT_skeleton && cudie.cu) {
			Dwarf *split_dwarf = dwarf_cu_getdwarf(cudie.cu);
			cu_file = drgn_module_find_dwarf_file(file->module,
							      split_dwarf);
			if (!cu_file) {
				const char *dwo_name =
					drgn_dwarf_dwo_name(&skeldie);
				if (!dwo_name)
					dwo_name = "";
				err = drgn_module_create_split_dwarf_file(file->module,
									  dwo_name,
									  split_dwarf,
									  &cu_file);
				if (err)
					return err;
			}

			cu_start_off = (dwarf_dieoffset(&cudie)
					- dwarf_cuoffset(&cudie));
			if (dwarf_next_unit(split_dwarf, cu_start_off,
					    &cu_end_off, NULL, &version,
					    &abbrev_offset, &address_size,
					    &offset_size, v4_type_signaturep,
					    NULL)
			    || dwarf_cu_info(cudie.cu, NULL, &unit_type, NULL,
					     NULL, NULL, NULL, NULL))
				return drgn_error_libdw();
		} else {
			if (unit_type == DW_UT_skeleton
			    && drgn_log_is_enabled(state->dbinfo->prog,
						   DRGN_LOG_WARNING)) {
				const char *dwo_name =
					drgn_dwarf_dwo_name(&skeldie);
				drgn_log_warning(state->dbinfo->prog,
						 "%s: split DWARF file%s%s not found",
						 file->path ?: "",
						 dwo_name ? " " : "",
						 dwo_name ? dwo_name : "");
			}
			cudie = skeldie;
		}
#else
		unit_type = (scn == DRGN_SCN_DEBUG_TYPES
			     ? DW_UT_type : DW_UT_compile);
		cudie = skeldie;
#endif

		if (!elf_data_contains_ptr(cu_file->scn_data[scn],
					   cudie.addr)) {
			return drgn_elf_file_section_error(cu_file, NULL, NULL,
							   cudie.addr,
							   "unit DIE from unexpected section");
		}
		if (cu_end_off > cu_file->scn_data[scn]->d_size)
			cu_end_off = cu_file->scn_data[scn]->d_size;
		const char *cu_buf =
			(char *)cu_file->scn_data[scn]->d_buf + cu_start_off;
		if (version < 2 || version > 5) {
			return drgn_elf_file_section_errorf(cu_file,
							    cu_file->scns[scn],
							    cu_file->scn_data[scn],
							    cu_buf,
							    "unknown DWARF unit version %" PRIu16,
							    version);
		}
		if (address_size > 8) {
			return drgn_elf_file_section_errorf(cu_file,
							    cu_file->scns[scn],
							    cu_file->scn_data[scn],
							    cu_buf,
							    "unsupported DWARF unit address size %" PRIu8,
							    address_size);
		}

		Elf_Data *debug_abbrev =
			cu_file->scn_data[DRGN_SCN_DEBUG_ABBREV];
		if (abbrev_offset > debug_abbrev->d_size) {
			return drgn_elf_file_section_error(cu_file,
							   cu_file->scns[scn],
							   cu_file->scn_data[scn],
							   cu_buf,
							   "debug_abbrev_offset is out of bounds");
		}
		const char *pending_abbrev =
			(char *)debug_abbrev->d_buf + abbrev_offset;

		Elf_Data *debug_str_offsets =
			cu_file->scn_data[DRGN_SCN_DEBUG_STR_OFFSETS];
		const char *str_offsets = NULL;
		if (debug_str_offsets) {
			Dwarf_Word str_offsets_base;
			if (version >= 5) {
				Dwarf_Attribute attr_mem, *attr;
				if ((attr = dwarf_attr(&cudie,
						       DW_AT_str_offsets_base,
						       &attr_mem))) {
					if (dwarf_formudata(attr,
							    &str_offsets_base))
						return drgn_error_libdw();
					if (str_offsets_base
					    > debug_str_offsets->d_size) {
						return drgn_elf_file_section_error(cu_file,
										   cu_file->scns[scn],
										   cu_file->scn_data[scn],
										   (char *)attr->valp,
										   "DW_AT_str_offsets_base is out of bounds");
					}
				} else {
					// The default str_offsets_base is the
					// first entry in .debug_str_offsets
					// after the first header. (This isn't
					// explicit in the DWARF 5
					// specification, but it seems to be the
					// consensus.)
					str_offsets_base = 2 * offset_size;
					if (str_offsets_base
					    > debug_str_offsets->d_size) {
						return drgn_elf_file_section_error(cu_file,
										   cu_file->scns[DRGN_SCN_DEBUG_STR_OFFSETS],
										   debug_str_offsets,
										   (char *)debug_str_offsets->d_buf
										   + debug_str_offsets->d_size,
										   ".debug_str_offsets is too small");
					}
				}
			} else {
				// GNU Debug Fission doesn't have
				// DW_AT_str_offsets_base; the base is always 0.
				str_offsets_base = 0;
			}

			str_offsets =
				(char *)debug_str_offsets->d_buf
				+ str_offsets_base;
		}

		struct drgn_dwarf_index_cu *cu =
			drgn_dwarf_index_cu_vector_append_entry(cus);
		if (!cu)
			return &drgn_enomem;
		*cu = (struct drgn_dwarf_index_cu){
			.file = cu_file,
			.buf = cu_buf,
			.len = cu_end_off - cu_start_off,
			.version = version,
			.unit_type = unit_type,
			.address_size = address_size,
			.is_64_bit = offset_size == 8,
			.scn = scn,
			.pending_abbrev = pending_abbrev,
			.str_offsets = str_offsets,
			.libdw_cu = cudie.cu,
		};

		off = next_off;
	}
	if (ret < 0)
		return drgn_error_libdw();
	return NULL;
}

struct drgn_error *
drgn_dwarf_index_read_module(struct drgn_dwarf_index_state *state,
			     struct drgn_module *module)
{
	struct drgn_error *err;
	struct drgn_elf_file *file = module->debug_file;
	err = drgn_dwarf_index_read_cus(state, file, DRGN_SCN_DEBUG_INFO);
	if (!err && file->scn_data[DRGN_SCN_DEBUG_TYPES]) {
		err = drgn_dwarf_index_read_cus(state, file,
						DRGN_SCN_DEBUG_TYPES);
	}
	return err;
}

static struct drgn_error *read_strx(struct drgn_dwarf_index_cu_buffer *buffer,
				    uint64_t strx, const char **ret)
{
	if (!buffer->cu->str_offsets) {
		return binary_buffer_error(&buffer->bb,
					   "string index without .debug_str_offsets section");
	}
	Elf_Data *debug_str_offsets =
		buffer->cu->file->scn_data[DRGN_SCN_DEBUG_STR_OFFSETS];
	size_t offset_size = buffer->cu->is_64_bit ? 8 : 4;
	if (((char *)debug_str_offsets->d_buf + debug_str_offsets->d_size
	     - buffer->cu->str_offsets)
	    / offset_size <= strx) {
		return binary_buffer_error(&buffer->bb,
					   "string index out of bounds");
	}
	uint64_t strp;
	if (buffer->cu->is_64_bit) {
		memcpy(&strp, (uint64_t *)buffer->cu->str_offsets + strx,
		       sizeof(strp));
		if (buffer->bb.bswap)
			strp = bswap_64(strp);
	} else {
		uint32_t strp32;
		memcpy(&strp32, (uint32_t *)buffer->cu->str_offsets + strx,
		       sizeof(strp32));
		if (buffer->bb.bswap)
			strp32 = bswap_32(strp32);
		strp = strp32;
	}
	if (strp >= buffer->cu->file->scn_data[DRGN_SCN_DEBUG_STR]->d_size) {
		return binary_buffer_error(&buffer->bb,
					   "indirect string is out of bounds");
	}
	*ret = ((char *)buffer->cu->file->scn_data[DRGN_SCN_DEBUG_STR]->d_buf
		+ strp);
	return NULL;
}

static struct drgn_error *dw_form_to_insn(struct drgn_dwarf_index_cu *cu,
					  struct binary_buffer *bb,
					  uint64_t form, uint8_t *insn_ret)
{
	struct drgn_error *err;
	switch (form) {
	case DW_FORM_addr:
		*insn_ret = cu->address_size;
		return NULL;
	case DW_FORM_data1:
	case DW_FORM_ref1:
	case DW_FORM_flag:
	case DW_FORM_strx1:
	case DW_FORM_addrx1:
		*insn_ret = 1;
		return NULL;
	case DW_FORM_data2:
	case DW_FORM_ref2:
	case DW_FORM_strx2:
	case DW_FORM_addrx2:
		*insn_ret = 2;
		return NULL;
	case DW_FORM_strx3:
	case DW_FORM_addrx3:
		*insn_ret = 3;
		return NULL;
	case DW_FORM_data4:
	case DW_FORM_ref4:
	case DW_FORM_ref_sup4:
	case DW_FORM_strx4:
	case DW_FORM_addrx4:
		*insn_ret = 4;
		return NULL;
	case DW_FORM_data8:
	case DW_FORM_ref8:
	case DW_FORM_ref_sig8:
	case DW_FORM_ref_sup8:
		*insn_ret = 8;
		return NULL;
	case DW_FORM_data16:
		*insn_ret = 16;
		return NULL;
	case DW_FORM_block:
	case DW_FORM_exprloc:
		*insn_ret = INSN_SKIP_BLOCK;
		return NULL;
	case DW_FORM_block1:
		*insn_ret = INSN_SKIP_BLOCK1;
		return NULL;
	case DW_FORM_block2:
		*insn_ret = INSN_SKIP_BLOCK2;
		return NULL;
	case DW_FORM_block4:
		*insn_ret = INSN_SKIP_BLOCK4;
		return NULL;
	case DW_FORM_sdata:
	case DW_FORM_udata:
	case DW_FORM_ref_udata:
	case DW_FORM_strx:
	case DW_FORM_addrx:
	case DW_FORM_loclistx:
	case DW_FORM_rnglistx:
	case DW_FORM_GNU_addr_index:
	case DW_FORM_GNU_str_index:
		*insn_ret = INSN_SKIP_LEB128;
		return NULL;
	case DW_FORM_ref_addr:
		if (cu->version < 3) {
			*insn_ret = cu->address_size;
			return NULL;
		}
		fallthrough;
	case DW_FORM_sec_offset:
	case DW_FORM_strp:
	case DW_FORM_strp_sup:
	case DW_FORM_line_strp:
	case DW_FORM_GNU_ref_alt:
	case DW_FORM_GNU_strp_alt:
		*insn_ret = cu->is_64_bit ? 8 : 4;
		return NULL;
	case DW_FORM_string:
		*insn_ret = INSN_SKIP_STRING;
		return NULL;
	case DW_FORM_implicit_const:
		if ((err = binary_buffer_skip_leb128(bb)))
			return err;
		fallthrough;
	case DW_FORM_flag_present:
		*insn_ret = 0;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = INSN_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %#" PRIx64,
					   form);
	}
}

static struct drgn_error *dw_at_sibling_to_insn(struct binary_buffer *bb,
						uint64_t form,
						uint8_t *insn_ret)
{
	switch (form) {
	case DW_FORM_ref1:
		*insn_ret = INSN_SIBLING_REF1;
		return NULL;
	case DW_FORM_ref2:
		*insn_ret = INSN_SIBLING_REF2;
		return NULL;
	case DW_FORM_ref4:
		*insn_ret = INSN_SIBLING_REF4;
		return NULL;
	case DW_FORM_ref8:
		*insn_ret = INSN_SIBLING_REF8;
		return NULL;
	case DW_FORM_ref_udata:
		*insn_ret = INSN_SIBLING_REF_UDATA;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = INSN_SIBLING_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %#" PRIx64 " for DW_AT_sibling",
					   form);
	}
}

static struct drgn_error *dw_at_name_to_insn(struct drgn_dwarf_index_cu *cu,
					     struct binary_buffer *bb,
					     uint64_t form, uint8_t *insn_ret)
{
	switch (form) {
	case DW_FORM_strp:
		if (!cu->file->scn_data[DRGN_SCN_DEBUG_STR]) {
			return binary_buffer_error(bb,
						   "DW_FORM_strp without .debug_str section");
		}
		if (cu->is_64_bit)
			*insn_ret = INSN_NAME_STRP8;
		else
			*insn_ret = INSN_NAME_STRP4;
		return NULL;
	case DW_FORM_string:
		*insn_ret = INSN_NAME_STRING;
		return NULL;
	case DW_FORM_strx:
	case DW_FORM_GNU_str_index:
		*insn_ret = INSN_NAME_STRX;
		return NULL;
	case DW_FORM_strx1:
		*insn_ret = INSN_NAME_STRX1;
		return NULL;
	case DW_FORM_strx2:
		*insn_ret = INSN_NAME_STRX2;
		return NULL;
	case DW_FORM_strx3:
		*insn_ret = INSN_NAME_STRX3;
		return NULL;
	case DW_FORM_strx4:
		*insn_ret = INSN_NAME_STRX4;
		return NULL;
	case DW_FORM_GNU_strp_alt:
		if (!cu->file->alt_debug_str_data) {
			return binary_buffer_error(bb,
						   "DW_FORM_GNU_strp_alt without alternate .debug_str section");
		}
		if (cu->is_64_bit)
			*insn_ret = INSN_NAME_STRP_ALT8;
		else
			*insn_ret = INSN_NAME_STRP_ALT4;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = INSN_NAME_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %#" PRIx64 " for DW_AT_name",
					   form);
	}
}

static struct drgn_error *
dw_at_declaration_to_insn(struct binary_buffer *bb, uint64_t form,
			  uint8_t *insn_ret, uint8_t *die_flags)
{
	switch (form) {
	case DW_FORM_flag:
		*insn_ret = INSN_DECLARATION_FLAG;
		return NULL;
	case DW_FORM_flag_present:
		/*
		 * This could be an instruction, but as long as we have a free
		 * DIE flag bit, we might as well use it.
		 */
		*insn_ret = 0;
		*die_flags |= INSN_DIE_FLAG_DECLARATION;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = INSN_DECLARATION_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %#" PRIx64 " for DW_AT_declaration",
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
		*insn_ret = INSN_SPECIFICATION_REF1;
		return NULL;
	case DW_FORM_ref2:
		*insn_ret = INSN_SPECIFICATION_REF2;
		return NULL;
	case DW_FORM_ref4:
		*insn_ret = INSN_SPECIFICATION_REF4;
		return NULL;
	case DW_FORM_ref8:
		*insn_ret = INSN_SPECIFICATION_REF8;
		return NULL;
	case DW_FORM_ref_udata:
		*insn_ret = INSN_SPECIFICATION_REF_UDATA;
		return NULL;
	case DW_FORM_ref_addr:
		if (cu->version >= 3) {
			if (cu->is_64_bit)
				*insn_ret = INSN_SPECIFICATION_REF_ADDR8;
			else
				*insn_ret = INSN_SPECIFICATION_REF_ADDR4;
		} else {
			if (cu->address_size == 8)
				*insn_ret = INSN_SPECIFICATION_REF_ADDR8;
			else if (cu->address_size == 4)
				*insn_ret = INSN_SPECIFICATION_REF_ADDR4;
			else
				return binary_buffer_error(bb,
							   "unsupported address size %" PRIu8 " for DW_FORM_ref_addr",
							   cu->address_size);
		}
		return NULL;
	case DW_FORM_GNU_ref_alt:
		if (!cu->file->alt_debug_info_data) {
			return binary_buffer_error(bb,
						   "DW_FORM_GNU_ref_alt without alternate .debug_info section");
		}
		if (cu->is_64_bit)
			*insn_ret = INSN_SPECIFICATION_REF_ALT8;
		else
			*insn_ret = INSN_SPECIFICATION_REF_ALT4;
		return NULL;
	case DW_FORM_indirect:
		*insn_ret = INSN_SPECIFICATION_INDIRECT;
		return NULL;
	default:
		return binary_buffer_error(bb,
					   "unknown attribute form %#" PRIx64 " for DW_AT_specification",
					   form);
	}
}

static struct drgn_error *
read_abbrev_decl(struct drgn_elf_file_section_buffer *buffer,
		 struct drgn_dwarf_index_cu *cu, struct uint32_vector *decls,
		 struct uint8_vector *insns)
{
	struct drgn_error *err;

	uint64_t code;
	if ((err = binary_buffer_next_uleb128(&buffer->bb, &code)))
		return err;
	if (code == 0)
		return &drgn_stop;
	if (code != uint32_vector_size(decls) + 1) {
		return binary_buffer_error(&buffer->bb,
					   "DWARF abbreviation table is not sequential");
	}

	uint32_t insn_index = uint8_vector_size(insns);
	if (!uint32_vector_append(decls, &insn_index))
		return &drgn_enomem;

	uint64_t tag;
	if ((err = binary_buffer_next_uleb128(&buffer->bb, &tag)))
		return err;

	uint8_t die_flags;
	bool should_index = true;
	switch (tag) {
#define X(name) case DW_TAG_##name: die_flags = DRGN_DWARF_INDEX_##name; break;
	DRGN_DWARF_INDEX_TAGS
#undef X
	default:
		die_flags = INSN_DIE_FLAG_TAG_MASK;
		should_index = false;
		break;
	}

	uint8_t children;
	if ((err = binary_buffer_next_u8(&buffer->bb, &children)))
		return err;
	if (children)
		die_flags |= INSN_DIE_FLAG_CHILDREN;

	uint8_t insn, last_insn = UINT8_MAX;
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
			if (insn <= INSN_MAX_SKIP) {
				if (last_insn + insn <= INSN_MAX_SKIP) {
					*uint8_vector_last(insns) += insn;
					continue;
				} else if (last_insn < INSN_MAX_SKIP) {
					insn = last_insn + insn - INSN_MAX_SKIP;
					*uint8_vector_last(insns) = INSN_MAX_SKIP;
				}
			}
			last_insn = insn;

			if (!uint8_vector_append(insns, &insn))
				return &drgn_enomem;
		}
	}
	insn = INSN_END;
	if (!uint8_vector_append(insns, &insn) ||
	    !uint8_vector_append(insns, &die_flags))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *read_cu(struct drgn_dwarf_index_cu *cu)
{
	struct drgn_elf_file_section_buffer buffer;
	drgn_elf_file_section_buffer_init_index(&buffer, cu->file,
						DRGN_SCN_DEBUG_ABBREV);
	buffer.bb.pos = cu->pending_abbrev;
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
	uint8_vector_shrink_to_fit(&insns);
	uint32_vector_shrink_to_fit(&decls);
	uint32_vector_steal(&decls, &cu->abbrev_decls, &cu->num_abbrev_decls);
	uint8_vector_steal(&insns, &cu->abbrev_insns, NULL);
	return NULL;
}

/* Get the size of a unit header beyond that of a normal compilation unit. */
static size_t cu_header_extra_size(struct drgn_dwarf_index_cu *cu)
{
	switch (cu->unit_type) {
	case DW_UT_compile:
	case DW_UT_partial:
		return 0;
	case DW_UT_skeleton:
	case DW_UT_split_compile:
		/* dwo_id */
		return cu->version >= 5 ? 8 : 0;
	case DW_UT_type:
	case DW_UT_split_type:
		/* type_signature and type_offset */
		return cu->is_64_bit ? 16 : 12;
	default:
		UNREACHABLE();
	}
}

static size_t cu_header_size(struct drgn_dwarf_index_cu *cu)
{
	size_t size = cu->is_64_bit ? 23 : 11;
	if (cu->version >= 5)
		size++;
	size += cu_header_extra_size(cu);
	return size;
}

static bool
index_specification(struct drgn_dwarf_specification_map *specifications,
		    uintptr_t declaration, uintptr_t addr)
{
	struct drgn_dwarf_specification_map_entry entry = {
		.key = declaration,
		.value = addr,
	};
	struct hash_pair hp = drgn_dwarf_specification_map_hash(&declaration);
	// There may be duplicates if multiple DIEs reference one declaration,
	// but we ignore them.
	return drgn_dwarf_specification_map_insert_hashed(specifications, &entry,
							 hp, NULL) >= 0;
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
	if (form == DW_FORM_implicit_const) {
		return binary_buffer_error(bb,
					   "DW_FORM_implicit_const in DW_FORM_indirect");
	}
	switch (insn) {
	case INSN_INDIRECT:
		return dw_form_to_insn(cu, bb, form, insn_ret);
	case INSN_SIBLING_INDIRECT:
		return dw_at_sibling_to_insn(bb, form, insn_ret);
	case INSN_NAME_INDIRECT:
		return dw_at_name_to_insn(cu, bb, form, insn_ret);
	case INSN_DECLARATION_INDIRECT:
		return dw_at_declaration_to_insn(bb, form, insn_ret, die_flags);
	case INSN_SPECIFICATION_INDIRECT:
		return dw_at_specification_to_insn(cu, bb, form, insn_ret);
	default:
		UNREACHABLE();
	}
}

/*
 * First pass: index DIEs with DW_AT_specification. This recurses into
 * namespaces.
 */
static struct drgn_error *
index_cu_first_pass(struct drgn_dwarf_specification_map *specifications,
		    struct drgn_dwarf_index_cu_buffer *buffer)
{
	struct drgn_error *err;
	struct drgn_dwarf_index_cu *cu = buffer->cu;
	const char *debug_info_buffer = cu->file->scn_data[cu->scn]->d_buf;
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
		const char *sibling = NULL;
		uint8_t insn;
		uint8_t extra_die_flags = 0;
		while ((insn = *insnp++) != INSN_END) {
indirect_insn:;
			uint64_t skip, tmp;
			switch (insn) {
			case INSN_SKIP_BLOCK:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &skip)))
					return err;
				goto skip;
			case INSN_SKIP_BLOCK1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &skip)))
					return err;
				goto skip;
			case INSN_SKIP_BLOCK2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &skip)))
					return err;
				goto skip;
			case INSN_SKIP_BLOCK4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &skip)))
					return err;
				goto skip;
			case INSN_SKIP_LEB128:
			case INSN_NAME_STRX:
				if ((err = binary_buffer_skip_leb128(&buffer->bb)))
					return err;
				break;
			case INSN_SKIP_STRING:
			case INSN_NAME_STRING:
				if ((err = binary_buffer_skip_string(&buffer->bb)))
					return err;
				break;
			case INSN_SIBLING_REF1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &tmp)))
					return err;
				goto sibling;
			case INSN_SIBLING_REF2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto sibling;
			case INSN_SIBLING_REF4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto sibling;
			case INSN_SIBLING_REF8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
				goto sibling;
			case INSN_SIBLING_REF_UDATA:
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
			case INSN_NAME_STRX1:
				skip = 1;
				goto skip;
			case INSN_NAME_STRX2:
				skip = 2;
				goto skip;
			case INSN_NAME_STRX3:
				skip = 3;
				goto skip;
			case INSN_NAME_STRP4:
			case INSN_NAME_STRX4:
			case INSN_NAME_STRP_ALT4:
				skip = 4;
				goto skip;
			case INSN_NAME_STRP8:
			case INSN_NAME_STRP_ALT8:
				skip = 8;
				goto skip;
			case INSN_DECLARATION_FLAG: {
				uint8_t flag;
				if ((err = binary_buffer_next_u8(&buffer->bb,
								 &flag)))
					return err;
				if (flag)
					declaration = true;
				break;
			}
			case INSN_SPECIFICATION_REF1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &tmp)))
					return err;
				goto specification;
			case INSN_SPECIFICATION_REF2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto specification;
			case INSN_SPECIFICATION_REF4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto specification;
			case INSN_SPECIFICATION_REF8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
				goto specification;
			case INSN_SPECIFICATION_REF_UDATA:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &tmp)))
					return err;
specification:
				specification = (uintptr_t)cu->buf + tmp;
				break;
			case INSN_SPECIFICATION_REF_ADDR4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto specification_ref_addr;
			case INSN_SPECIFICATION_REF_ADDR8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
specification_ref_addr:
				specification = (uintptr_t)debug_info_buffer + tmp;
				break;
			case INSN_SPECIFICATION_REF_ALT4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto specification_ref_alt;
			case INSN_SPECIFICATION_REF_ALT8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
specification_ref_alt:
				specification = ((uintptr_t)cu->file->alt_debug_info_data->d_buf
						 + tmp);
				break;
			case INSN_INDIRECT:
			case INSN_SIBLING_INDIRECT:
			case INSN_NAME_INDIRECT:
			case INSN_DECLARATION_INDIRECT:
			case INSN_SPECIFICATION_INDIRECT:
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

		if (depth > 0 && specification) {
			if (insn & INSN_DIE_FLAG_DECLARATION)
				declaration = true;
			/*
			 * For now, we don't handle DIEs with
			 * DW_AT_specification which are themselves
			 * declarations. We may need to handle
			 * DW_AT_specification "chains" in the future.
			 */
			if (!declaration
			    && !index_specification(specifications,
						    specification, die_addr))
				return &drgn_enomem;
		}

		if (insn & INSN_DIE_FLAG_CHILDREN) {
			if (sibling
			    && ((insn & INSN_DIE_FLAG_TAG_MASK)
				!= DRGN_DWARF_INDEX_namespace))
				buffer->bb.pos = sibling;
			else
				depth++;
		} else if (depth == 0) {
			break;
		}
	}
	return NULL;
}

/**
 * Find a definition corresponding to a declaration DIE.
 *
 * This finds the address of a DIE with a @c DW_AT_specification attribute that
 * refers to the given address.
 *
 * @param[in] die_addr The address of the declaration DIE.
 * @param[out] ret Returned address of the definition DIE.
 * @return @c true if a definition DIE was found, @c false if not (in which case
 * `*ret` is not modified).
 */
static bool drgn_dwarf_find_definition(struct drgn_debug_info *dbinfo,
				       uintptr_t die_addr, uintptr_t *ret)
{
	struct drgn_dwarf_specification_map_iterator it =
		drgn_dwarf_specification_map_search(&dbinfo->dwarf.specifications,
						    &die_addr);
	if (!it.entry)
		return false;
	*ret = it.entry->value;
	return true;
}

static bool
index_die(struct drgn_dwarf_index_die_map map[static DRGN_DWARF_INDEX_MAP_SIZE],
	  struct drgn_dwarf_base_type_map *base_types, const char *name,
	  int tag, uintptr_t addr)
{
	size_t name_len = strlen(name);
	if (tag != DRGN_DWARF_INDEX_base_type) {
		struct drgn_dwarf_index_die_map_entry entry = {
			.key = { name, name_len },
			.value = VECTOR_INIT,
		};
		struct hash_pair hp = drgn_dwarf_index_die_map_hash(&entry.key);
		auto it = drgn_dwarf_index_die_map_search_hashed(&map[tag],
								 &entry.key,
								 hp);
		if (!it.entry
		    && drgn_dwarf_index_die_map_insert_searched(&map[tag],
								&entry, hp,
								&it) < 0)
			return false;
		return drgn_dwarf_index_die_vector_append(&it.entry->value,
							  &addr);
	} else if (base_types) {
		struct drgn_dwarf_base_type_map_entry entry = {
			.key = { name, name_len },
			.value = addr,
		};
		struct hash_pair hp = drgn_dwarf_base_type_map_hash(&entry.key);
		return drgn_dwarf_base_type_map_insert_hashed(base_types,
							      &entry, hp,
							      NULL) >= 0;
	}
	return true;
}

/* Second pass: index the actual DIEs. */
static struct drgn_error *
index_cu_second_pass(struct drgn_debug_info *dbinfo,
		     struct drgn_dwarf_index_die_map map[static DRGN_DWARF_INDEX_MAP_SIZE],
		     struct drgn_dwarf_base_type_map *base_types,
		     struct drgn_dwarf_index_cu_buffer *buffer)
{
	struct drgn_error *err;
	struct drgn_dwarf_index_cu *cu = buffer->cu;
	Elf_Data *debug_str = cu->file->scn_data[DRGN_SCN_DEBUG_STR];
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
		bool declaration = false;
		bool specification = false;
		const char *sibling = NULL;
		uint8_t insn;
		uint8_t extra_die_flags = 0;
		while ((insn = *insnp++) != INSN_END) {
indirect_insn:;
			uint64_t skip, tmp;
			switch (insn) {
			case INSN_SKIP_BLOCK:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &skip)))
					return err;
				goto skip;
			case INSN_SKIP_BLOCK1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &skip)))
					return err;
				goto skip;
			case INSN_SKIP_BLOCK2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &skip)))
					return err;
				goto skip;
			case INSN_SKIP_BLOCK4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &skip)))
					return err;
				goto skip;
			case INSN_SPECIFICATION_REF_UDATA:
				specification = true;
				fallthrough;
			case INSN_SKIP_LEB128:
				if ((err = binary_buffer_skip_leb128(&buffer->bb)))
					return err;
				break;
			case INSN_NAME_STRING:
				name = buffer->bb.pos;
				fallthrough;
			case INSN_SKIP_STRING:
				if ((err = binary_buffer_skip_string(&buffer->bb)))
					return err;
				break;
			case INSN_SIBLING_REF1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &tmp)))
					return err;
				goto sibling;
			case INSN_SIBLING_REF2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto sibling;
			case INSN_SIBLING_REF4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto sibling;
			case INSN_SIBLING_REF8:
				if ((err = binary_buffer_next_u64(&buffer->bb,
								  &tmp)))
					return err;
				goto sibling;
			case INSN_SIBLING_REF_UDATA:
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
			case INSN_NAME_STRP4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto strp;
			case INSN_NAME_STRP8:
				if ((err = binary_buffer_next_u64(&buffer->bb, &tmp)))
					return err;
strp:
				if (tmp >= debug_str->d_size) {
					return binary_buffer_error(&buffer->bb,
								   "DW_AT_name is out of bounds");
				}
				name = (const char *)debug_str->d_buf + tmp;
				__builtin_prefetch(name);
				break;
			case INSN_NAME_STRX:
				if ((err = binary_buffer_next_uleb128(&buffer->bb,
								      &tmp)))
					return err;
				goto name_strx;
			case INSN_NAME_STRX1:
				if ((err = binary_buffer_next_u8_into_u64(&buffer->bb,
									  &tmp)))
					return err;
				goto name_strx;
			case INSN_NAME_STRX2:
				if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto name_strx;
			case INSN_NAME_STRX3:
				if ((err = binary_buffer_next_uint(&buffer->bb,
								   3, &tmp)))
					return err;
				goto name_strx;
			case INSN_NAME_STRX4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
name_strx:
				if ((err = read_strx(buffer, tmp, &name)))
					return err;
				__builtin_prefetch(name);
				break;
			case INSN_NAME_STRP_ALT4:
				if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
									   &tmp)))
					return err;
				goto name_alt_strp;
			case INSN_NAME_STRP_ALT8:
				if ((err = binary_buffer_next_u64(&buffer->bb, &tmp)))
					return err;
name_alt_strp:
				if (tmp >= cu->file->alt_debug_str_data->d_size) {
					return binary_buffer_error(&buffer->bb,
								   "DW_AT_name is out of bounds");
				}
				name = (const char *)cu->file->alt_debug_str_data->d_buf + tmp;
				__builtin_prefetch(name);
				break;
			case INSN_DECLARATION_FLAG: {
				uint8_t flag;
				if ((err = binary_buffer_next_u8(&buffer->bb,
								 &flag)))
					return err;
				if (flag)
					declaration = true;
				break;
			}
			case INSN_SPECIFICATION_REF1:
				specification = true;
				skip = 1;
				goto skip;
			case INSN_SPECIFICATION_REF2:
				specification = true;
				skip = 2;
				goto skip;
			case INSN_SPECIFICATION_REF4:
			case INSN_SPECIFICATION_REF_ADDR4:
			case INSN_SPECIFICATION_REF_ALT4:
				specification = true;
				skip = 4;
				goto skip;
			case INSN_SPECIFICATION_REF8:
			case INSN_SPECIFICATION_REF_ADDR8:
			case INSN_SPECIFICATION_REF_ALT8:
				specification = true;
				skip = 8;
				goto skip;
			case INSN_INDIRECT:
			case INSN_SIBLING_INDIRECT:
			case INSN_NAME_INDIRECT:
			case INSN_DECLARATION_INDIRECT:
			case INSN_SPECIFICATION_INDIRECT:
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

		uint8_t tag = insn & INSN_DIE_FLAG_TAG_MASK;
		if (depth == 1) {
			depth1_tag = tag;
			depth1_addr = die_addr;
		}
		if (depth == (tag == DRGN_DWARF_INDEX_enumerator ? 2 : 1)
		    && name && !specification) {
			if (insn & INSN_DIE_FLAG_DECLARATION)
				declaration = true;
			if (tag == DRGN_DWARF_INDEX_enumerator) {
				if (depth1_tag != DRGN_DWARF_INDEX_enumeration_type)
					goto next;
				/*
				 * NB: the enumerator name points to the
				 * enumeration_type DIE. Also, enumerators can't
				 * be declared in C/C++, so we don't check for
				 * that.
				 */
				die_addr = depth1_addr;
			} else if (declaration) {
				// Declaration class, struct, and union DIEs
				// with children are treated like namespaces.
				if ((insn & INSN_DIE_FLAG_CHILDREN)
				    && (tag == DRGN_DWARF_INDEX_class_type
					|| tag == DRGN_DWARF_INDEX_structure_type
					|| tag == DRGN_DWARF_INDEX_union_type)
				    && !index_die(map, base_types, name,
						  DRGN_DWARF_INDEX_namespace,
						  die_addr))
					return &drgn_enomem;
				if (!drgn_dwarf_find_definition(dbinfo,
								die_addr,
								&die_addr))
					goto next;
			}

			if (!index_die(map, base_types, name, tag, die_addr))
				return &drgn_enomem;
		}

next:
		if (insn & INSN_DIE_FLAG_CHILDREN) {
			/*
			 * We must descend into the children of enumeration_type
			 * DIEs to index enumerator DIEs. We don't want to skip
			 * over the children of the top-level DIE even if it has
			 * a sibling pointer.
			 */
			if (sibling && tag != DRGN_DWARF_INDEX_enumeration_type
			    && depth > 0)
				buffer->bb.pos = sibling;
			else
				depth++;
		} else if (depth == 0) {
			break;
		}
	}
	return NULL;
}

static inline int drgn_dwarf_index_cu_cmp(const void *_a, const void *_b)
{
	uintptr_t a = (uintptr_t)((struct drgn_dwarf_index_cu *)_a)->buf;
	uintptr_t b = (uintptr_t)((struct drgn_dwarf_index_cu *)_b)->buf;
	return (a > b) - (a < b);
}

// die_addr must be from an indexed CU.
static struct drgn_dwarf_index_cu *
drgn_dwarf_index_find_cu(struct drgn_debug_info *dbinfo, uintptr_t die_addr)
{
	struct drgn_dwarf_index_cu *cus =
		drgn_dwarf_index_cu_vector_begin(&dbinfo->dwarf.index_cus);
	size_t lo = 0;
	size_t hi = drgn_dwarf_index_cu_vector_size(&dbinfo->dwarf.index_cus);
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (die_addr < (uintptr_t)cus[mid].buf)
			hi = mid;
		else
			lo = mid + 1;
	}
	// We don't check that the address is within bounds because this can
	// only be called with a valid address.
	return &cus[lo - 1];
}

// If there wasn't already an error, merge src into dst, and return an error if
// that fails. If there was already an error, return the original error. Free
// src whether or not there was an error.
static struct drgn_error *
drgn_dwarf_specification_map_merge(struct drgn_dwarf_specification_map *dst,
				   struct drgn_dwarf_specification_map *src,
				   struct drgn_error *err)
{
	if (!err) {
		for (auto it = drgn_dwarf_specification_map_first(src);
		     it.entry; it = drgn_dwarf_specification_map_next(it)) {
			if (drgn_dwarf_specification_map_insert(dst, it.entry,
								NULL) < 0) {
				err = &drgn_enomem;
				break;
			}
		}
	}
	drgn_dwarf_specification_map_deinit(src);
	return err;
}

static struct drgn_error *
drgn_dwarf_index_die_map_merge(struct drgn_dwarf_index_die_map *dst,
			       struct drgn_dwarf_index_die_map *src,
			       struct drgn_error *err)
{
	auto src_it = drgn_dwarf_index_die_map_first(src);
	for (; !err && src_it.entry;
	     src_it = drgn_dwarf_index_die_map_next(src_it)) {
		struct drgn_dwarf_index_die_vector *src_vector =
			&src_it.entry->value;

		struct hash_pair hp =
			drgn_dwarf_index_die_map_hash(&src_it.entry->key);
		auto dst_it = drgn_dwarf_index_die_map_search_hashed(dst,
								     &src_it.entry->key,
								     hp);
		// If dst already has the key, extend its vector with
		// src_vector, and free src_vector. Otherwise, move src_vector
		// into dst.
		if (dst_it.entry) {
			if (!drgn_dwarf_index_die_vector_extend(&dst_it.entry->value,
								src_vector))
				err = &drgn_enomem;
		} else if (drgn_dwarf_index_die_map_insert_searched(dst,
								    src_it.entry,
								    hp,
								    NULL) < 0) {
			err = &drgn_enomem;
		} else {
			// We stole src_vector; don't free it.
			continue;
		}
		drgn_dwarf_index_die_vector_deinit(src_vector);
	}
	for (; src_it.entry; src_it = drgn_dwarf_index_die_map_next(src_it))
		drgn_dwarf_index_die_vector_deinit(&src_it.entry->value);
	drgn_dwarf_index_die_map_deinit(src);
	return err;
}

static struct drgn_error *
drgn_dwarf_base_type_map_merge(struct drgn_dwarf_base_type_map *dst,
			       struct drgn_dwarf_base_type_map *src,
			       struct drgn_error *err)
{
	if (!err) {
		for (auto it = drgn_dwarf_base_type_map_first(src); it.entry;
		     it = drgn_dwarf_base_type_map_next(it)) {
			if (drgn_dwarf_base_type_map_insert(dst, it.entry, NULL)
			    < 0) {
				err = &drgn_enomem;
				break;
			}
		}
	}
	drgn_dwarf_base_type_map_deinit(src);
	return err;
}

struct drgn_error *
drgn_dwarf_info_update_index(struct drgn_dwarf_index_state *state)
{
	struct drgn_debug_info *dbinfo = state->dbinfo;
	struct drgn_dwarf_index_cu_vector *cus = &dbinfo->dwarf.index_cus;

	if (dbinfo->dwarf.global.saved_err)
		return drgn_error_copy(dbinfo->dwarf.global.saved_err);

	size_t new_cus_size = drgn_dwarf_index_cu_vector_size(cus);
	for (int i = 0; i < drgn_num_threads; i++)
		new_cus_size += drgn_dwarf_index_cu_vector_size(&state->cus[i]);
	if (new_cus_size == drgn_dwarf_index_cu_vector_size(cus))
		return NULL;

	// Per-thread array of maps to populate. Thread 0 uses the maps in the
	// dbinfo directly. These are merged into the dbinfo and freed.
	_cleanup_free_ union {
		// For first pass.
		struct drgn_dwarf_specification_map specifications;
		// For second pass.
		struct {
			struct drgn_dwarf_index_die_map map[DRGN_DWARF_INDEX_MAP_SIZE];
			struct drgn_dwarf_base_type_map base_types;
		};
	} *maps = NULL;
	if (drgn_num_threads > 1) {
		maps = malloc_array(drgn_num_threads - 1, sizeof(maps[0]));
		if (!maps)
			return &drgn_enomem;
	}

	if (!drgn_dwarf_index_cu_vector_reserve(cus, new_cus_size))
		return &drgn_enomem;
	for (int i = 0; i < drgn_num_threads; i++)
		drgn_dwarf_index_cu_vector_extend(cus, &state->cus[i]);

	struct drgn_error *err = NULL;
	#pragma omp parallel num_threads(drgn_num_threads)
	{
		struct drgn_dwarf_specification_map *specifications;
		int thread_num = omp_get_thread_num();
		if (thread_num == 0) {
			specifications = &dbinfo->dwarf.specifications;
		} else {
			specifications = &maps[thread_num - 1].specifications;
			drgn_dwarf_specification_map_init(specifications);
		}

		#pragma omp for schedule(dynamic)
		for (size_t i = dbinfo->dwarf.global.cus_indexed;
		     i < drgn_dwarf_index_cu_vector_size(cus); i++) {
			struct drgn_dwarf_index_cu *cu =
				drgn_dwarf_index_cu_vector_at(cus, i);
			if (err)
				continue;
			struct drgn_error *cu_err = read_cu(cu);
			if (!cu_err) {
				struct drgn_dwarf_index_cu_buffer buffer;
				drgn_dwarf_index_cu_buffer_init(&buffer, cu);
				buffer.bb.pos += cu_header_size(cu);
				cu_err = index_cu_first_pass(specifications,
							     &buffer);
			}
			if (cu_err) {
				#pragma omp critical(drgn_dwarf_info_update_index_error)
				if (err)
					drgn_error_destroy(cu_err);
				else
					err = cu_err;
			}
		}
	}
	for (int i = 0; i < drgn_num_threads - 1; i++) {
		err = drgn_dwarf_specification_map_merge(&dbinfo->dwarf.specifications,
							 &maps[i].specifications,
							 err);
	}
	if (err)
		goto err;

	#pragma omp parallel num_threads(drgn_num_threads)
	{
		struct drgn_error *thread_err;

		struct drgn_dwarf_index_die_map *map;
		struct drgn_dwarf_base_type_map *base_types;
		int thread_num = omp_get_thread_num();
		if (thread_num == 0) {
			map = dbinfo->dwarf.global.map;
			base_types = &dbinfo->dwarf.base_types;
		} else {
			array_for_each(tag_map, maps[thread_num - 1].map)
				drgn_dwarf_index_die_map_init(tag_map);
			map = maps[thread_num - 1].map;
			base_types = &maps[thread_num - 1].base_types;
			drgn_dwarf_base_type_map_init(base_types);
		}

		#pragma omp for schedule(dynamic)
		for (size_t i = dbinfo->dwarf.global.cus_indexed;
		     i < drgn_dwarf_index_cu_vector_size(cus); i++) {
			if (err)
				continue;
			struct drgn_dwarf_index_cu *cu =
				drgn_dwarf_index_cu_vector_at(cus, i);
			struct drgn_dwarf_index_cu_buffer buffer;
			drgn_dwarf_index_cu_buffer_init(&buffer, cu);
			buffer.bb.pos += cu_header_size(cu);
			thread_err = index_cu_second_pass(dbinfo, map,
							  base_types, &buffer);
			if (thread_err) {
				#pragma omp critical(drgn_dwarf_info_update_index_error)
				if (err)
					drgn_error_destroy(thread_err);
				else
					err = thread_err;
			}
		}

		thread_err = err;

		#pragma omp for schedule(dynamic) nowait
		for (size_t i = 0; i <= array_size(dbinfo->dwarf.global.map); i++) {
			if (i < array_size(dbinfo->dwarf.global.map)) {
				for (int j = 0; j < drgn_num_threads - 1; j++) {
					thread_err =
						drgn_dwarf_index_die_map_merge(&dbinfo->dwarf.global.map[i],
									       &maps[j].map[i],
									       thread_err);
				}
			} else {
				for (int j = 0; j < drgn_num_threads - 1; j++) {
					thread_err =
						drgn_dwarf_base_type_map_merge(&dbinfo->dwarf.base_types,
									       &maps[j].base_types,
									       thread_err);
				}
			}
		}
		if (thread_err) {
			#pragma omp critical(drgn_dwarf_info_update_index_error)
			if (err)
				drgn_error_destroy(thread_err);
			else
				err = thread_err;
		}
	}

	if (err) {
err:
		dbinfo->dwarf.global.saved_err = err;
		return drgn_error_copy(err);
	}
	qsort(drgn_dwarf_index_cu_vector_begin(cus),
	      drgn_dwarf_index_cu_vector_size(cus),
	      sizeof(struct drgn_dwarf_index_cu), drgn_dwarf_index_cu_cmp);
	dbinfo->dwarf.global.cus_indexed =
		drgn_dwarf_index_cu_vector_size(cus);
	return NULL;
}

static struct drgn_error *index_namespace(struct drgn_namespace_dwarf_index *ns)
{
	size_t num_index_cus =
		drgn_dwarf_index_cu_vector_size(&ns->dbinfo->dwarf.index_cus);
	if (ns->cus_indexed >= num_index_cus)
		return NULL;

	if (ns->saved_err)
		return drgn_error_copy(ns->saved_err);

	// The parent namespace must be indexed first so that the DIEs for this
	// namespace are populated.
	struct drgn_error *err = index_namespace(ns->parent);
	if (err)
		return err;

	drgn_blocking_guard(ns->dbinfo->prog);

	struct drgn_dwarf_index_die_vector
		*die_vectors_to_index[DRGN_DWARF_INDEX_NUM_NAMESPACE_TAGS];
	int tags_to_index[DRGN_DWARF_INDEX_NUM_NAMESPACE_TAGS];
	int num_tags_to_index = 0;
	struct nstring key = { ns->name, ns->name_len };
	struct hash_pair hp = drgn_dwarf_index_die_map_hash(&key);
	for (int i = 0; i < DRGN_DWARF_INDEX_NUM_NAMESPACE_TAGS; i++) {
		auto it = drgn_dwarf_index_die_map_search_hashed(&ns->parent->map[i],
								 &key, hp);
		if (!it.entry)
			continue;
		struct drgn_dwarf_index_die_vector *dies = &it.entry->value;
		if (ns->dies_indexed[i]
		    >= drgn_dwarf_index_die_vector_size(dies))
			continue;

		die_vectors_to_index[num_tags_to_index] = dies;
		tags_to_index[num_tags_to_index] = i;
		num_tags_to_index++;
	}
	if (num_tags_to_index == 0) {
		ns->cus_indexed = num_index_cus;
		return NULL;
	}

	_cleanup_free_ struct drgn_dwarf_index_die_map
		(*maps)[DRGN_DWARF_INDEX_MAP_SIZE] = NULL;
	if (drgn_num_threads > 1) {
		maps = malloc_array(drgn_num_threads - 1, sizeof(maps[0]));
		if (!maps)
			return &drgn_enomem;
	}

	err = NULL;
	#pragma omp parallel num_threads(drgn_num_threads)
	{
		struct drgn_error *thread_err;

		struct drgn_dwarf_index_die_map *map;
		int thread_num = omp_get_thread_num();
		if (thread_num == 0) {
			map = ns->map;
		} else {
			array_for_each(tag_map, maps[thread_num - 1])
				drgn_dwarf_index_die_map_init(tag_map);
			map = maps[thread_num - 1];
		}

		for (int i = 0; i < num_tags_to_index; i++) {
			struct drgn_dwarf_index_die_vector *dies =
				die_vectors_to_index[i];
			#pragma omp for schedule(dynamic) nowait
			for (uint32_t j = ns->dies_indexed[tags_to_index[i]];
			     j < drgn_dwarf_index_die_vector_size(dies); j++) {
				if (err)
					continue;
				uintptr_t die_addr =
					*drgn_dwarf_index_die_vector_at(dies, j);
				struct drgn_dwarf_index_cu *cu =
					drgn_dwarf_index_find_cu(ns->dbinfo, die_addr);
				struct drgn_dwarf_index_cu_buffer buffer;
				drgn_dwarf_index_cu_buffer_init(&buffer, cu);
				buffer.bb.pos = (void *)die_addr;
				thread_err = index_cu_second_pass(ns->dbinfo,
								  map, NULL,
								  &buffer);
				if (thread_err) {
					#pragma omp critical(drgn_index_namespace_error)
					if (err)
						drgn_error_destroy(thread_err);
					else
						err = thread_err;
				}
			}
		}
		#pragma omp barrier

		thread_err = err;

		#pragma omp for schedule(dynamic) nowait
		for (size_t i = 0; i < array_size(ns->map); i++) {
			for (int j = 0; j < drgn_num_threads - 1; j++) {
				thread_err =
					drgn_dwarf_index_die_map_merge(&ns->map[i],
								       &maps[j][i],
								       thread_err);
			}
		}
		if (thread_err) {
			#pragma omp critical(drgn_index_namespace_error)
			if (err)
				drgn_error_destroy(thread_err);
			else
				err = thread_err;
		}
	}
	if (err) {
		ns->saved_err = err;
		return drgn_error_copy(ns->saved_err);
	}
	ns->cus_indexed = num_index_cus;
	for (int i = 0; i < num_tags_to_index; i++) {
		ns->dies_indexed[tags_to_index[i]] =
			drgn_dwarf_index_die_vector_size(die_vectors_to_index[i]);
	}
	return NULL;
}

/**
 * Iterator over DWARF debugging information.
 *
 * An iterator is initialized with @ref drgn_dwarf_index_iterator_init(). It is
 * advanced with @ref drgn_dwarf_index_iterator_next().
 */
struct drgn_dwarf_index_iterator {
	struct drgn_namespace_dwarf_index *ns;
	const char *name;
	size_t name_len;
	const enum drgn_dwarf_index_tag *tags;
	size_t num_tags;
	struct drgn_dwarf_index_die_vector *dies;
	uint32_t index;
};

/**
 * Create an iterator over DIEs in a DWARF index namespace.
 *
 * @param[out] it DWARF index iterator to initialize.
 * @param[in] ns Namespace DWARF index.
 * @param[in] name Name of DIE to search for.
 * @param[in] name_len Length of @c name.
 * @param[in] tags List of DIE tags to search for.
 * @param[in] num_tags Number of tags in @p tags, or zero to search for any tag.
 * @return @c NULL on success, non-@c NULL on error.
 */
static struct drgn_error *
drgn_dwarf_index_iterator_init(struct drgn_dwarf_index_iterator *it,
			       struct drgn_namespace_dwarf_index *ns,
			       const char *name, size_t name_len,
			       const enum drgn_dwarf_index_tag *tags,
			       size_t num_tags)
{
	struct drgn_error *err = index_namespace(ns);
	if (err)
		return err;
	it->ns = ns;
	it->name = name;
	it->name_len = name_len;
	it->tags = tags;
	it->num_tags = num_tags;
	// Sentinel to simplify first iteration.
	static const struct drgn_dwarf_index_die_vector empty_dies = VECTOR_INIT;
	it->dies = (struct drgn_dwarf_index_die_vector *)&empty_dies;
	it->index = 0;
	return NULL;
}

/**
 * Get the next matching DIE from a DWARF index iterator.
 *
 * Note the quirks in @ref drgn_namespace_dwarf_index::map about
 * `DW_TAG_enumerator` and `DW_TAG_namespace`.
 *
 * @param[in] it DWARF index iterator.
 * @param[out] die_ret Returned DIE.
 * @param[out] file_ret If not @c NULL, returned file that DIE came from.
 * @return @c true on success, @c false if there are no more matching DIEs.
 */
static bool
drgn_dwarf_index_iterator_next(struct drgn_dwarf_index_iterator *it,
			       Dwarf_Die *die_ret,
			       struct drgn_elf_file **file_ret)
{
	uintptr_t die_addr;
	if (it->index < drgn_dwarf_index_die_vector_size(it->dies)) {
		die_addr = *drgn_dwarf_index_die_vector_at(it->dies,
							   it->index++);
	} else {
		for (;;) {
			if (it->num_tags == 0)
				return false;

			int tag = *it->tags++;
			it->num_tags--;
			if (tag == DRGN_DWARF_INDEX_base_type) {
				// Only look up base types in the global
				// namespace.
				if (it->ns->parent)
					continue;
				struct nstring key = { it->name, it->name_len };
				auto map_it = drgn_dwarf_base_type_map_search(&it->ns->dbinfo->dwarf.base_types,
									      &key);
				if (map_it.entry) {
					die_addr = map_it.entry->value;
					break;
				}
			} else {
				struct nstring key = { it->name, it->name_len };
				auto map_it =
					drgn_dwarf_index_die_map_search(&it->ns->map[tag],
									&key);
				if (map_it.entry) {
					die_addr = *drgn_dwarf_index_die_vector_first(&map_it.entry->value);
					it->dies = &map_it.entry->value;
					it->index = 1;
					break;
				}
			}
		}
	}

	struct drgn_dwarf_index_cu *cu =
		drgn_dwarf_index_find_cu(it->ns->dbinfo, die_addr);
	*die_ret = (Dwarf_Die){
		.addr = (void *)die_addr,
		.cu = cu->libdw_cu,
	};
	if (file_ret)
		*file_ret = cu->file;
	return true;
}

static struct drgn_error *
drgn_namespace_find_child(struct drgn_namespace_dwarf_index *ns,
			  const char *name, size_t name_len,
			  struct drgn_namespace_dwarf_index **ret)
{
	struct drgn_error *err = index_namespace(ns);
	if (err)
		return err;

	struct nstring key = { name, name_len };
	struct hash_pair hp = nstring_hash_pair(&key);
	auto it = drgn_namespace_table_search_hashed(&ns->children, &key, hp);
	if (it.entry) {
		*ret = *it.entry;
		return NULL;
	}

	for (int i = 0; i < DRGN_DWARF_INDEX_NUM_NAMESPACE_TAGS; i++) {
		auto die_it =
			drgn_dwarf_index_die_map_search_hashed(&ns->map[i],
							       &key, hp);
		if (die_it.entry) {
			struct drgn_namespace_dwarf_index *new_ns =
				malloc(sizeof(*new_ns));
			if (!new_ns)
				return &drgn_enomem;
			// Use the name from the DIE map, which has the same
			// lifetime as the namespace table.
			drgn_namespace_dwarf_index_init(new_ns,
							die_it.entry->key.str,
							die_it.entry->key.len,
							ns);
			if (drgn_namespace_table_insert_searched(&ns->children,
								 &new_ns, hp,
								 NULL) < 0) {
				drgn_namespace_dwarf_index_deinit(new_ns);
				free(new_ns);
				return &drgn_enomem;
			}
			*ret = new_ns;
			return NULL;
		}
	}
	return &drgn_not_found;
}

/*
 * Language support.
 */

/**
 * Return the @ref drgn_language of the CU of the given DIE.
 *
 * @param[in] fall_back Whether to fall back if the language is not found or
 * unknown. If @c true, @ref drgn_default_language is returned in this case. If
 * @c false, @c NULL is returned.
 * @param[out] ret Returned language.
 * @return @c NULL on success, non-@c NULL on error.
 */
static struct drgn_error *drgn_language_from_die(Dwarf_Die *die, bool fall_back,
						 const struct drgn_language **ret)
{
	Dwarf_Die cudie;
	if (!dwarf_cu_die(die->cu, &cudie, NULL, NULL, NULL, NULL, NULL, NULL))
		return drgn_error_libdw();
	switch (dwarf_srclang(&cudie)) {
	case DW_LANG_C:
	case DW_LANG_C89:
	case DW_LANG_C99:
	case DW_LANG_C11:
		*ret = &drgn_language_c;
		break;
	case DW_LANG_C_plus_plus:
	case DW_LANG_C_plus_plus_03:
	case DW_LANG_C_plus_plus_11:
	case DW_LANG_C_plus_plus_14:
		*ret = &drgn_language_cpp;
		break;
	default:
		*ret = fall_back ? &drgn_default_language : NULL;
		break;
	}
	return NULL;
}

struct drgn_error *
drgn_debug_info_main_language(struct drgn_debug_info *dbinfo,
			      const struct drgn_language **ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_index_iterator it;
	const enum drgn_dwarf_index_tag tag = DRGN_DWARF_INDEX_subprogram;
	err = drgn_dwarf_index_iterator_init(&it, &dbinfo->dwarf.global, "main",
					     strlen("main"), &tag, 1);
	if (err)
		return err;
	Dwarf_Die die;
	while (drgn_dwarf_index_iterator_next(&it, &die, NULL)) {
		err = drgn_language_from_die(&die, false, ret);
		if (err) {
			drgn_error_destroy(err);
			continue;
		}
		if (*ret)
			return NULL;
	}
	*ret = NULL;
	return NULL;
}

/*
 * DIE iteration.
 */

DEFINE_VECTOR(dwarf_die_vector, Dwarf_Die);

/** Iterator over DWARF DIEs in a @ref drgn_module. */
struct drgn_dwarf_die_iterator {
	/** Stack of current DIE and its ancestors. */
	struct dwarf_die_vector dies;
	/**
	 * Dwarf handle that we're iterating over. For split DWARF, this is the
	 * main file.
	 */
	Dwarf *dwarf;
	/**
	 * End of current CU (for bounds checking). For split DWARF, this is in
	 * the split file.
	 */
	const char *cu_end;
	/** Offset of next CU. For split DWARF, this is in the main file. */
	Dwarf_Off next_cu_off;
	/** Whether current CU is from .debug_types. */
	bool debug_types;
};

static void drgn_dwarf_die_iterator_init(struct drgn_dwarf_die_iterator *it,
					 Dwarf *dwarf)
{
	dwarf_die_vector_init(&it->dies);
	it->dwarf = dwarf;
	it->next_cu_off = 0;
	it->debug_types = false;
}

static void drgn_dwarf_die_iterator_deinit(struct drgn_dwarf_die_iterator *it)
{
	dwarf_die_vector_deinit(&it->dies);
}

/**
 * Return the next DWARF DIE in a @ref drgn_dwarf_die_iterator.
 *
 * The first call returns the top-level DIE for the first unit in the module.
 * Subsequent calls return children, siblings, and unit DIEs.
 *
 * This includes the .debug_types section.
 *
 * @param[in,out] it Iterator containing the returned DIE and its ancestors. The
 * last entry in `it->dies` is the DIE itself, the entry before that is its
 * parent, the entry before that is its grandparent, etc.
 * @param[in] children If @c true and the last returned DIE has children, return
 * its first child (this is a pre-order traversal). Otherwise, return the next
 * DIE at the level less than or equal to the last returned DIE, i.e., the last
 * returned DIE's sibling, or its ancestor's sibling, or the next top-level unit
 * DIE.
 * @param[in] subtree If zero, iterate over all DIEs in all units. If non-zero,
 * stop after returning all DIEs in the subtree rooted at the DIE that was
 * returned in the last call as entry `subtree - 1` in `it->dies`.
 * @return @c NULL on success, `&drgn_stop` if there are no more DIEs, in which
 * case the size of `it->dies` equals @p subtree and `it->dies` refers to the
 * root of the iterated subtree, non-@c NULL on error, in which case this should
 * not be called again.
 */
static struct drgn_error *
drgn_dwarf_die_iterator_next(struct drgn_dwarf_die_iterator *it, bool children,
			     size_t subtree)
{
#define TOP() (dwarf_die_vector_last(&it->dies))
	int r;
	Dwarf_Die die;
	assert(subtree <= dwarf_die_vector_size(&it->dies));
	if (dwarf_die_vector_empty(&it->dies)) {
		/* This is the first call. Get the first unit DIE. */
		if (!dwarf_die_vector_append_entry(&it->dies))
			return &drgn_enomem;
	} else {
		if (children) {
			r = dwarf_child(TOP(), &die);
			if (r == 0) {
				/* The previous DIE has a child. Return it. */
				if (!dwarf_die_vector_append(&it->dies, &die))
					return &drgn_enomem;
				return NULL;
			} else if (r < 0) {
				return drgn_error_libdw();
			}
			/* The previous DIE has no children. */
		}

		if (dwarf_die_vector_size(&it->dies) == subtree) {
			/*
			 * The previous DIE is the root of the subtree. We're
			 * done.
			 */
			return &drgn_stop;
		}

		if (dwarf_die_vector_size(&it->dies) > 1) {
			r = dwarf_siblingof(TOP(), &die);
			if (r == 0) {
				/* The previous DIE has a sibling. Return it. */
				*TOP() = die;
				return NULL;
			} else if (r > 0) {
				if (!die.addr)
					goto next_unit;
				/*
				 * The previous DIE is the last child of its
				 * parent.
				 */
				char *addr = die.addr;
				do {
					/*
					 * addr points to the null terminator
					 * for the list of siblings. Go back up
					 * to its parent. The next byte is
					 * either the parent's sibling or
					 * another null terminator.
					 */
					dwarf_die_vector_pop(&it->dies);
					addr++;
					if (dwarf_die_vector_size(&it->dies)
					    == subtree) {
						/*
						 * We're back to the root of the
						 * subtree. We're done.
						 */
						return &drgn_stop;
					}
					if (dwarf_die_vector_size(&it->dies) == 1
					    || addr >= it->cu_end)
						goto next_unit;
				} while (*addr == '\0');
				/*
				 * addr now points to the next DIE. Return it.
				 */
				*TOP() = (Dwarf_Die){
					.cu = dwarf_die_vector_first(&it->dies)->cu,
					.addr = addr,
				};
				return NULL;
			} else {
				return drgn_error_libdw();
			}
		}
	}

next_unit:;
	/* There are no more DIEs in the current unit.  */
	Dwarf_Off cu_off = it->next_cu_off;
	size_t cu_header_size;
	uint64_t type_signature;
	r = dwarf_next_unit(it->dwarf, cu_off, &it->next_cu_off,
			    &cu_header_size, NULL, NULL, NULL, NULL,
			    it->debug_types ? &type_signature : NULL, NULL);
	if (r == 0) {
		/* Got the next unit. Return the unit DIE. */
		Dwarf_Off offset = cu_off + cu_header_size;
		if (it->debug_types)
			r = !dwarf_offdie_types(it->dwarf, offset, TOP());
		else
			r = !dwarf_offdie(it->dwarf, offset, TOP());
		if (r)
			return drgn_error_libdw();
		Dwarf_Off cu_end_off = it->next_cu_off;
#if _ELFUTILS_PREREQ(0, 171)
		// If the unit is a skeleton, replace it with the split unit.
		Dwarf_Die subdie;
		uint8_t unit_type;
		if (dwarf_cu_info(TOP()->cu, NULL, &unit_type, NULL, &subdie,
				  NULL, NULL, NULL))
			return drgn_error_libdw();
		if (unit_type == DW_UT_skeleton && subdie.cu) {
			offset = dwarf_dieoffset(&subdie);
			if (dwarf_next_unit(dwarf_cu_getdwarf(subdie.cu),
					    offset - dwarf_cuoffset(&subdie),
					    &cu_end_off, NULL, NULL, NULL, NULL,
					    NULL, NULL, NULL))
				return drgn_error_libdw();
			*TOP() = subdie;
		}
#endif
		it->cu_end = ((const char *)TOP()->addr
			      - offset
			      + cu_end_off);
		return NULL;
	} else if (r > 0) {
		// Note that in split DWARF, there are no skeleton units for
		// type units, and the main file doesn't have a .debug_types
		// section. Instead, the split files contain a .debug_types.dwo
		// section per type unit. elfutils as of 0.189 doesn't support
		// multiple sections with the same name, so we don't support
		// type units with split DWARF.
		if (!it->debug_types) {
			it->next_cu_off = 0;
			it->debug_types = true;
			goto next_unit;
		}
		/* There are no more units. */
		return &drgn_stop;
	} else {
		return drgn_error_libdw();
	}
#undef TOP
}

struct drgn_error *drgn_module_find_dwarf_scopes(struct drgn_module *module,
						 uint64_t pc,
						 uint64_t *bias_ret,
						 Dwarf_Die **dies_ret,
						 size_t *length_ret)
{
	struct drgn_error *err;

	if (!module->debug_file) {
		*bias_ret = 0;
		*dies_ret = NULL;
		*length_ret = 0;
		return NULL;
	}
	Dwarf *dwarf = module->debug_file->dwarf;
	*bias_ret = module->debug_file_bias;
	pc -= module->debug_file_bias;

	/* First, try to get the CU containing the PC. */
	Dwarf_Aranges *aranges;
	size_t naranges;
	if (dwarf_getaranges(dwarf, &aranges, &naranges) < 0)
		return drgn_error_libdw();

	_cleanup_(drgn_dwarf_die_iterator_deinit)
		struct drgn_dwarf_die_iterator it;
	drgn_dwarf_die_iterator_init(&it, dwarf);
	size_t subtree;
	Dwarf_Off offset;
	if (dwarf_getarangeinfo(dwarf_getarange_addr(aranges, pc), NULL, NULL,
				&offset) >= 0) {
		Dwarf_Die *cu_die = dwarf_die_vector_append_entry(&it.dies);
		if (!cu_die)
			return &drgn_enomem;
		if (!dwarf_offdie(dwarf, offset, cu_die))
			return drgn_error_libdw();
#if _ELFUTILS_PREREQ(0, 171)
		// If the unit is a skeleton, replace it with the split unit.
		Dwarf_Die subdie;
		uint8_t unit_type;
		if (dwarf_cu_info(cu_die->cu, NULL, &unit_type, NULL, &subdie,
				  NULL, NULL, NULL))
			return drgn_error_libdw();
		if (unit_type == DW_UT_skeleton && subdie.cu) {
			dwarf = dwarf_cu_getdwarf(subdie.cu);
			offset = dwarf_dieoffset(&subdie);
			*cu_die = subdie;
		}
#endif
		if (dwarf_next_unit(dwarf, offset - dwarf_cuoffset(cu_die),
				    &it.next_cu_off, NULL, NULL, NULL, NULL,
				    NULL, NULL, NULL))
			return drgn_error_libdw();
		it.cu_end = ((const char *)cu_die->addr
			     - offset
			     + it.next_cu_off);
		subtree = 1;
	} else {
		/*
		 * Range was not found. .debug_aranges could be missing or
		 * incomplete, so fall back to checking each CU.
		 */
		subtree = 0;
	}

	/*
	 * Now find the most specific DIE containing the PC. Entry subtree - 1
	 * in it.dies is the most specific DIE we have found so far. We iterate
	 * over all of its children until we find a more specific DIE, then we
	 * descend into that one.
	 *
	 * We only want to descend into children DIEs when the last DIE
	 * contained the PC, which is when size(it.dies) == subtree.
	 */
	while (!(err = drgn_dwarf_die_iterator_next(&it,
						    dwarf_die_vector_size(&it.dies)
						    == subtree,
						    subtree))) {
		int r = dwarf_haspc(dwarf_die_vector_last(&it.dies), pc);
		if (r > 0) {
			subtree = dwarf_die_vector_size(&it.dies);
		} else if (r < 0) {
			return drgn_error_libdw();
		}
	}
	if (err != &drgn_stop)
		return err;

	dwarf_die_vector_steal(&it.dies, dies_ret, length_ret);
	return NULL;
}

struct drgn_error *drgn_find_die_ancestors(Dwarf_Die *die, Dwarf_Die **dies_ret,
					   size_t *length_ret)
{
	Dwarf *dwarf = dwarf_cu_getdwarf(die->cu);
	if (!dwarf)
		return drgn_error_libdw();

	_cleanup_(dwarf_die_vector_deinit)
		struct dwarf_die_vector dies = VECTOR_INIT;
	Dwarf_Die *cu_die = dwarf_die_vector_append_entry(&dies);
	if (!cu_die)
		return &drgn_enomem;

	Dwarf_Half cu_version;
	Dwarf_Off type_offset;
	if (!dwarf_cu_die(die->cu, cu_die, &cu_version, NULL, NULL, NULL, NULL,
			  &type_offset))
		return drgn_error_libdw();
	Dwarf_Off cu_die_offset = dwarf_dieoffset(cu_die);
	bool debug_types = cu_version == 4 && type_offset != 0;
	Dwarf_Off next_cu_offset;
	uint64_t type_signature;
	if (dwarf_next_unit(dwarf, cu_die_offset - dwarf_cuoffset(cu_die),
			    &next_cu_offset, NULL, NULL, NULL, NULL, NULL,
			    debug_types ? &type_signature : NULL, NULL))
		return drgn_error_libdw();
	const unsigned char *cu_end =
		(unsigned char *)cu_die->addr - cu_die_offset + next_cu_offset;

#define TOP() (dwarf_die_vector_last(&dies))
	while ((char *)TOP()->addr <= (char *)die->addr) {
		if (TOP()->addr == die->addr) {
			dwarf_die_vector_steal(&dies, dies_ret, length_ret);
			(*length_ret)--;
			return NULL;
		}

		Dwarf_Attribute attr;
		if (dwarf_attr(TOP(), DW_AT_sibling, &attr)) {
			/* The top DIE has a DW_AT_sibling attribute. */
			Dwarf_Die sibling;
			if (!dwarf_formref_die(&attr, &sibling))
				return drgn_error_libdw();
			if (sibling.cu != TOP()->cu ||
			    (char *)sibling.addr <= (char *)TOP()->addr)
				return drgn_error_create(DRGN_ERROR_OTHER,
							"invalid DW_AT_sibling");

			if ((char *)sibling.addr > (char *)die->addr) {
				/*
				 * The top DIE's sibling is after the target
				 * DIE. Therefore, the target DIE must be a
				 * descendant of the top DIE.
				 */
				Dwarf_Die *child =
					dwarf_die_vector_append_entry(&dies);
				if (!child)
					return &drgn_enomem;
				int r = dwarf_child(TOP() - 1, child);
				if (r < 0) {
					return drgn_error_libdw();
				} else if (r > 0) {
					/*
					 * The top DIE didn't have any children,
					 * which should be impossible.
					 */
					goto not_found;
				}
			} else {
				/*
				 * The top DIE's sibling is before or equal to
				 * the target DIE. Therefore, the target DIE
				 * isn't a descendant of the top DIE. Skip to
				 * the sibling.
				 */
				*TOP() = sibling;
			}
		} else {
			/*
			 * The top DIE does not have a DW_AT_sibling attribute.
			 * Instead, we found the end of the top DIE.
			 */
			unsigned char *addr = attr.valp;
			if (!addr || addr >= cu_end)
				goto not_found;

			/*
			 * If the top DIE has children, then addr is its first
			 * child. Otherwise, then addr is its sibling. (Unless
			 * it is a null terminator.)
			 */
			size_t new_size = dwarf_die_vector_size(&dies);
			if (dwarf_haschildren(TOP()) > 0)
				new_size++;

			while (*addr == '\0') {
				/*
				 * addr points to the null terminator for the
				 * list of siblings. Go back up to its parent.
				 * The next byte is either the parent's sibling
				 * or another null terminator.
				 */
				new_size--;
				addr++;
				if (new_size <= 1 || addr >= cu_end)
					goto not_found;
			}

			/* addr now points to the next DIE. Go to it. */
			if (new_size > dwarf_die_vector_size(&dies)) {
				if (!dwarf_die_vector_append_entry(&dies))
					return &drgn_enomem;
			} else {
				dwarf_die_vector_resize(&dies, new_size);
			}
			*TOP() = (Dwarf_Die){
				.cu = dwarf_die_vector_first(&dies)->cu,
				.addr = addr,
			};
		}
	}
#undef TOP

not_found:
	return drgn_error_create(DRGN_ERROR_OTHER,
				 "could not find DWARF DIE ancestors");
}

/*
 * Location lists.
 */

static struct drgn_error *drgn_dwarf_next_addrx(struct binary_buffer *bb,
						struct drgn_elf_file *file,
						Dwarf_Die *cu_die,
						uint8_t address_size,
						const char **addr_base,
						uint64_t *ret)
{
	struct drgn_error *err;

	// For split DWARF, .debug_addr is in the main debug file.
	file = file->module->debug_file;

	// addr_base is a cache of the address table base for the compilation
	// unit.
	if (!*addr_base) {
		Dwarf_Attribute attr_mem, *attr;
		if (!(attr = dwarf_attr_integrate(cu_die, DW_AT_addr_base,
						  &attr_mem)) &&
		    !(attr = dwarf_attr_integrate(cu_die, DW_AT_GNU_addr_base,
						  &attr_mem))) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "indirect address without DW_AT_addr_base");
		}
		Dwarf_Word base;
		if (dwarf_formudata(attr, &base))
			return drgn_error_libdw();

		if (!file->scns[DRGN_SCN_DEBUG_ADDR]) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "indirect address without .debug_addr section");
		}
		err = drgn_elf_file_cache_section(file, DRGN_SCN_DEBUG_ADDR);
		if (err)
			return err;

		if (base > file->scn_data[DRGN_SCN_DEBUG_ADDR]->d_size) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_AT_addr_base is out of bounds");
		}

		*addr_base = (char *)file->scn_data[DRGN_SCN_DEBUG_ADDR]->d_buf + base;
		// In DWARF 5, there is a header immediately before addr_base,
		// which ends with a segment selector size. We don't support a
		// segment selector yet. In GNU Debug Fission, .debug_addr
		// doesn't contain any headers or segment selectors.
		if (attr->code != DW_AT_GNU_addr_base) {
			if (base == 0) {
				return drgn_error_create(DRGN_ERROR_OTHER,
							 "DW_AT_addr_base is out of bounds");
			}
			uint8_t segment_selector_size = ((uint8_t *)*addr_base)[-1];
			if (segment_selector_size != 0) {
				return drgn_error_format(DRGN_ERROR_OTHER,
							 "unsupported segment selector size %" PRIu8,
							 segment_selector_size);
			}
		}
	}

	uint64_t index;
	if ((err = binary_buffer_next_uleb128(bb, &index)))
		return err;

	Elf_Data *data = file->scn_data[DRGN_SCN_DEBUG_ADDR];
	if (index >=
	    ((char *)data->d_buf + data->d_size - *addr_base) / address_size) {
		return binary_buffer_error(bb,
					   "address index is out of bounds");
	}
	copy_lsbytes(ret, sizeof(*ret), HOST_LITTLE_ENDIAN,
		     *addr_base + index * address_size, address_size,
		     drgn_elf_file_is_little_endian(file));
	return NULL;
}

static struct drgn_error *drgn_dwarf_read_loclistx(struct drgn_elf_file *file,
						   Dwarf_Die *cu_die,
						   uint8_t offset_size,
						   Dwarf_Word index,
						   Dwarf_Word *ret)
{
	struct drgn_error *err;

	assert(offset_size == 4 || offset_size == 8);

	Dwarf_Attribute attr_mem, *attr;
	Dwarf_Word base;
	if ((attr = dwarf_attr(cu_die, DW_AT_loclists_base, &attr_mem))) {
		if (dwarf_formudata(attr, &base))
			return drgn_error_libdw();
	} else {
		// The DWARF 5 specification doesn't say what it means if there
		// is no DW_AT_loclists_base. In practice, it seems like split
		// units don't have DW_AT_loclist_base, and the base is intended
		// to be the first entry in .debug_loclists immediately after
		// the first header.
		base = offset_size == 8 ? 20 : 12;
	}

	if (!file->scns[DRGN_SCN_DEBUG_LOCLISTS]) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_FORM_loclistx without .debug_loclists section");
	}
	err = drgn_elf_file_cache_section(file, DRGN_SCN_DEBUG_LOCLISTS);
	if (err)
		return err;
	Elf_Data *data = file->scn_data[DRGN_SCN_DEBUG_LOCLISTS];

	if (base > data->d_size) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_AT_loclists_base is out of bounds");
	}
	if (index >= (data->d_size - base) / offset_size) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_FORM_loclistx is out of bounds");
	}
	const char *basep = (char *)data->d_buf + base;
	if (offset_size == 8) {
		uint64_t offset;
		memcpy(&offset, (uint64_t *)basep + index, sizeof(offset));
		if (drgn_elf_file_bswap(file))
			offset = bswap_64(offset);
		*ret = base + offset;
	} else {
		uint32_t offset;
		memcpy(&offset, (uint32_t *)basep + index, sizeof(offset));
		if (drgn_elf_file_bswap(file))
			offset = bswap_32(offset);
		*ret = base + offset;
	}
	return NULL;
}

static struct drgn_error *drgn_dwarf5_location_list(struct drgn_elf_file *file,
						    Dwarf_Word offset,
						    Dwarf_Die *cu_die,
						    uint8_t address_size,
						    uint64_t pc,
						    const char **expr_ret,
						    size_t *expr_size_ret)
{
	struct drgn_error *err;

	if (!file->scns[DRGN_SCN_DEBUG_LOCLISTS]) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "loclist without .debug_loclists section");
	}
	err = drgn_elf_file_cache_section(file, DRGN_SCN_DEBUG_LOCLISTS);
	if (err)
		return err;
	struct drgn_elf_file_section_buffer buffer;
	drgn_elf_file_section_buffer_init_index(&buffer, file,
						DRGN_SCN_DEBUG_LOCLISTS);
	if (offset > buffer.bb.end - buffer.bb.pos) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "loclist is out of bounds");
	}
	buffer.bb.pos += offset;

	const char *addr_base = NULL;
	uint64_t base;
	bool base_valid = false;
	/* Default is unknown. May be overridden by DW_LLE_default_location. */
	*expr_ret = NULL;
	*expr_size_ret = 0;
	for (;;) {
		uint8_t kind;
		if ((err = binary_buffer_next_u8(&buffer.bb, &kind)))
			return err;
		uint64_t start, length, expr_size;
		switch (kind) {
		case DW_LLE_end_of_list:
			return NULL;
		case DW_LLE_base_addressx:
			if ((err = drgn_dwarf_next_addrx(&buffer.bb, file,
							 cu_die, address_size,
							 &addr_base, &base)))
				return err;
			base_valid = true;
			break;
		case DW_LLE_startx_endx:
			if ((err = drgn_dwarf_next_addrx(&buffer.bb, file,
							 cu_die, address_size,
							 &addr_base, &start)) ||
			    (err = drgn_dwarf_next_addrx(&buffer.bb, file,
							 cu_die, address_size,
							 &addr_base, &length)))
				return err;
			length -= start;
counted_location_description:
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &expr_size)))
				return err;
			if (expr_size > buffer.bb.end - buffer.bb.pos) {
				return binary_buffer_error(&buffer.bb,
							   "location description size is out of bounds");
			}
			if (pc >= start && pc - start < length) {
				*expr_ret = buffer.bb.pos;
				*expr_size_ret = expr_size;
				return NULL;
			}
			buffer.bb.pos += expr_size;
			break;
		case DW_LLE_startx_length:
			if ((err = drgn_dwarf_next_addrx(&buffer.bb, file,
							 cu_die, address_size,
							 &addr_base, &start)) ||
			    (err = binary_buffer_next_uleb128(&buffer.bb,
							      &length)))
				return err;
			goto counted_location_description;
		case DW_LLE_offset_pair:
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &start)) ||
			    (err = binary_buffer_next_uleb128(&buffer.bb,
							      &length)))
				return err;
			length -= start;
			if (!base_valid) {
				Dwarf_Addr low_pc;
				if (dwarf_lowpc(cu_die, &low_pc))
					return drgn_error_libdw();
				base = low_pc;
				base_valid = true;
			}
			start += base;
			goto counted_location_description;
		case DW_LLE_default_location:
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &expr_size)))
				return err;
			if (expr_size > buffer.bb.end - buffer.bb.pos) {
				return binary_buffer_error(&buffer.bb,
							   "location description size is out of bounds");
			}
			*expr_ret = buffer.bb.pos;
			*expr_size_ret = expr_size;
			buffer.bb.pos += expr_size;
			break;
		case DW_LLE_base_address:
			if ((err = binary_buffer_next_uint(&buffer.bb,
							   address_size,
							   &base)))
				return err;
			base_valid = true;
			break;
		case DW_LLE_start_end:
			if ((err = binary_buffer_next_uint(&buffer.bb,
							   address_size,
							   &start)) ||
			    (err = binary_buffer_next_uint(&buffer.bb,
							   address_size,
							   &length)))
				return err;
			length -= start;
			goto counted_location_description;
		case DW_LLE_start_length:
			if ((err = binary_buffer_next_uint(&buffer.bb,
							   address_size,
							   &start)) ||
			    (err = binary_buffer_next_uleb128(&buffer.bb,
							      &length)))
				return err;
			goto counted_location_description;
		default:
			return binary_buffer_error(&buffer.bb,
						   "unknown location list entry kind %#" PRIx8,
						   kind);
		}
	}
}

static struct drgn_error *
drgn_dwarf4_split_location_list(struct drgn_elf_file *file, Dwarf_Word offset,
				Dwarf_Die *cu_die, uint8_t address_size,
				uint64_t pc, const char **expr_ret,
				size_t *expr_size_ret)
{
	struct drgn_error *err;

	if (!file->scns[DRGN_SCN_DEBUG_LOC]) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "loclistptr without .debug_loc section");
	}
	err = drgn_elf_file_cache_section(file, DRGN_SCN_DEBUG_LOC);
	if (err)
		return err;
	struct drgn_elf_file_section_buffer buffer;
	drgn_elf_file_section_buffer_init_index(&buffer, file,
						DRGN_SCN_DEBUG_LOC);
	if (offset > buffer.bb.end - buffer.bb.pos) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "loclistptr is out of bounds");
	}
	buffer.bb.pos += offset;

	const char *addr_base = NULL;
	uint64_t base;
	bool base_valid = false;
	*expr_ret = NULL;
	*expr_size_ret = 0;
	for (;;) {
		uint8_t kind;
		if ((err = binary_buffer_next_u8(&buffer.bb, &kind)))
			return err;
		uint64_t start, length;
		switch (kind) {
		// The GNU Debug Fission design document
		// (https://gcc.gnu.org/wiki/DebugFission) uses slightly
		// different names for entry kinds than DWARF 5, but they're the
		// same as the DWARF 5 versions except as noted below.
		case DW_LLE_end_of_list: // DW_LLE_end_of_list_entry
			return NULL;
		case DW_LLE_base_addressx: // DW_LLE_base_address_selection_entry
			if ((err = drgn_dwarf_next_addrx(&buffer.bb, file,
							 cu_die, address_size,
							 &addr_base, &base)))
				return err;
			base_valid = true;
			break;
		case DW_LLE_startx_endx: // DW_LLE_start_end_entry
			if ((err = drgn_dwarf_next_addrx(&buffer.bb, file,
							 cu_die, address_size,
							 &addr_base, &start)) ||
			    (err = drgn_dwarf_next_addrx(&buffer.bb, file,
							 cu_die, address_size,
							 &addr_base, &length)))
				return err;
			length -= start;
counted_location_description:;
			// Note: this is ULEB128 in DWARF 5.
			uint16_t expr_size;
			if ((err = binary_buffer_next_u16(&buffer.bb,
							  &expr_size)))
				return err;
			if (expr_size > buffer.bb.end - buffer.bb.pos) {
				return binary_buffer_error(&buffer.bb,
							   "location description size is out of bounds");
			}
			if (pc >= start && pc - start < length) {
				*expr_ret = buffer.bb.pos;
				*expr_size_ret = expr_size;
				return NULL;
			}
			buffer.bb.pos += expr_size;
			break;
		case DW_LLE_startx_length: // DW_LLE_start_length_entry
			if ((err = drgn_dwarf_next_addrx(&buffer.bb, file,
							 cu_die, address_size,
							 &addr_base, &start)) ||
			    // Note: this is ULEB128 in DWARF 5.
			    (err = binary_buffer_next_u32_into_u64(&buffer.bb,
								   &length)))
				return err;
			goto counted_location_description;
		case DW_LLE_offset_pair: // DW_LLE_offset_pair_entry
			// Note: these are ULEB128 in DWARF 5.
			if ((err = binary_buffer_next_u32_into_u64(&buffer.bb,
								   &start)) ||
			    (err = binary_buffer_next_u32_into_u64(&buffer.bb,
								   &length)))
				return err;
			length -= start;
			if (!base_valid) {
				Dwarf_Addr low_pc;
				if (dwarf_lowpc(cu_die, &low_pc))
					return drgn_error_libdw();
				base = low_pc;
				base_valid = true;
			}
			start += base;
			goto counted_location_description;
		default:
			return binary_buffer_error(&buffer.bb,
						   "unknown location list entry kind %#" PRIx8,
						   kind);
		}
	}
}

static struct drgn_error *drgn_dwarf4_location_list(struct drgn_elf_file *file,
						    Dwarf_Word offset,
						    Dwarf_Die *cu_die,
						    uint8_t address_size,
						    uint64_t pc,
						    const char **expr_ret,
						    size_t *expr_size_ret)
{
	struct drgn_error *err;

	if (!file->scns[DRGN_SCN_DEBUG_LOC]) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "loclistptr without .debug_loc section");
	}
	err = drgn_elf_file_cache_section(file, DRGN_SCN_DEBUG_LOC);
	if (err)
		return err;
	struct drgn_elf_file_section_buffer buffer;
	drgn_elf_file_section_buffer_init_index(&buffer, file,
						DRGN_SCN_DEBUG_LOC);
	if (offset > buffer.bb.end - buffer.bb.pos) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "loclistptr is out of bounds");
	}
	buffer.bb.pos += offset;

	uint64_t address_max = uint_max(address_size);
	uint64_t base;
	bool base_valid = false;
	for (;;) {
		uint64_t start, end;
		if ((err = binary_buffer_next_uint(&buffer.bb, address_size,
						   &start)) ||
		    (err = binary_buffer_next_uint(&buffer.bb, address_size,
						   &end)))
			return err;
		if (start == 0 && end == 0) {
			*expr_ret = NULL;
			*expr_size_ret = 0;
			return NULL;
		} else if (start == address_max) {
			base = end;
			base_valid = true;
		} else {
			if (!base_valid) {
				Dwarf_Addr low_pc;
				if (dwarf_lowpc(cu_die, &low_pc))
					return drgn_error_libdw();
				base = low_pc;
				base_valid = true;
			}
			uint16_t expr_size;
			if ((err = binary_buffer_next_u16(&buffer.bb,
							  &expr_size)))
				return err;
			if (expr_size > buffer.bb.end - buffer.bb.pos) {
				return binary_buffer_error(&buffer.bb,
							   "location description size is out of bounds");
			}
			if (base + start <= pc && pc < base + end) {
				*expr_ret = buffer.bb.pos;
				*expr_size_ret = expr_size;
				return NULL;
			}
			buffer.bb.pos += expr_size;
		}
	}
}

static struct drgn_error *
drgn_dwarf_location(struct drgn_elf_file *file, Dwarf_Attribute *attr,
		    const struct drgn_register_state *regs,
		    const char **expr_ret, size_t *expr_size_ret)
{
	struct drgn_error *err;
	switch (attr->form) {
	/* DWARF 3 */
	case DW_FORM_data4:
	case DW_FORM_data8:
	/* DWARF 4-5 */
	case DW_FORM_sec_offset:
	/* DWARF 5 */
	case DW_FORM_loclistx: {
		Dwarf_Half cu_version;
		uint8_t unit_type;
		Dwarf_Die cu_die;
		uint8_t address_size;
		uint8_t offset_size;
#if _ELFUTILS_PREREQ(0, 171)
		if (dwarf_cu_info(attr->cu, &cu_version, &unit_type, &cu_die,
				   NULL, NULL, &address_size, &offset_size))
			return drgn_error_libdw();
#else
		unit_type = DW_UT_compile;
		if (!dwarf_cu_die(attr->cu, &cu_die, &cu_version, NULL,
				  &address_size, &offset_size, NULL, NULL))
			return drgn_error_libdw();
#endif
		if ((err = drgn_check_address_size(address_size)))
			return err;

		Dwarf_Word offset;
		if (dwarf_formudata(attr, &offset))
			return drgn_error_libdw();
		if (attr->form == DW_FORM_loclistx &&
		    ((err = drgn_dwarf_read_loclistx(file, &cu_die, offset_size,
						     offset, &offset))))
			return err;

		struct optional_uint64 pc;
		if (!regs ||
		    !(pc = drgn_register_state_get_pc(regs)).has_value) {
			*expr_ret = NULL;
			*expr_size_ret = 0;
			return NULL;
		}
		pc.value -= !regs->interrupted + file->module->debug_file_bias;

		if (cu_version >= 5) {
			return drgn_dwarf5_location_list(file, offset, &cu_die,
							 address_size, pc.value,
							 expr_ret,
							 expr_size_ret);
		} else if (unit_type == DW_UT_split_compile
			   || unit_type == DW_UT_split_type) {
			return drgn_dwarf4_split_location_list(file, offset,
							       &cu_die,
							       address_size,
							       pc.value,
							       expr_ret,
							       expr_size_ret);
		} else {
			return drgn_dwarf4_location_list(file, offset, &cu_die,
							 address_size, pc.value,
							 expr_ret,
							 expr_size_ret);
		}
	}
	default: {
		Dwarf_Block block;
		if (dwarf_formblock(attr, &block))
			return drgn_error_libdw();
		*expr_ret = (char *)block.data;
		*expr_size_ret = block.length;
		return NULL;
	}
	}
}

/*
 * DWARF expressions.
 */

/**
 * Arbitrary limit for number of operations to execute in a DWARF expression to
 * avoid infinite loops.
 */
static const int MAX_DWARF_EXPR_OPS = 10000;

/* A DWARF expression and the context it is being evaluated in. */
struct drgn_dwarf_expression_context {
	struct binary_buffer bb;
	const char *start;
	struct drgn_program *prog;
	struct drgn_elf_file *file;
	uint8_t address_size;
	Dwarf_Die cu_die;
	const char *cu_addr_base;
	Dwarf_Die *function;
	const struct drgn_register_state *regs;
};

static struct drgn_error *
drgn_dwarf_expression_buffer_error(struct binary_buffer *bb, const char *pos,
				   const char *message)
{
	struct drgn_dwarf_expression_context *ctx =
		container_of(bb, struct drgn_dwarf_expression_context, bb);
	return drgn_elf_file_section_error(ctx->file, NULL, NULL, pos, message);
}

static inline struct drgn_error *
drgn_dwarf_expression_context_init(struct drgn_dwarf_expression_context *ctx,
				   struct drgn_program *prog,
				   struct drgn_elf_file *file, Dwarf_CU *cu,
				   Dwarf_Die *function,
				   const struct drgn_register_state *regs,
				   const char *expr, size_t expr_size)
{
	struct drgn_error *err;
	binary_buffer_init(&ctx->bb, expr, expr_size,
			   drgn_elf_file_is_little_endian(file),
			   drgn_dwarf_expression_buffer_error);
	ctx->start = expr;
	ctx->prog = prog;
	ctx->file = file;
	if (cu) {
		if (!dwarf_cu_die(cu, &ctx->cu_die, NULL, NULL,
				  &ctx->address_size, NULL, NULL, NULL))
			return drgn_error_libdw();
		if ((err = drgn_check_address_size(ctx->address_size)))
			return err;
	} else {
		ctx->cu_die.addr = NULL;
		ctx->address_size = drgn_elf_file_address_size(file);
	}
	ctx->cu_addr_base = NULL;
	ctx->function = function;
	ctx->regs = regs;
	return NULL;
}

static struct drgn_error *
drgn_dwarf_frame_base(struct drgn_program *prog, struct drgn_elf_file *file,
		      Dwarf_Die *die, const struct drgn_register_state *regs,
		      int *remaining_ops, uint64_t *ret);

/*
 * Evaluate a DWARF expression up to the next location description operation or
 * operation that can't be evaluated in the given context.
 *
 * Returns &drgn_not_found if it tried to use an unknown register value.
 */
static struct drgn_error *
drgn_eval_dwarf_expression(struct drgn_dwarf_expression_context *ctx,
			   struct uint64_vector *stack,
			   int *remaining_ops)
{
	struct drgn_error *err;
	bool little_endian =
		drgn_elf_file_is_little_endian(ctx->file);
	uint8_t address_size = ctx->address_size;
	uint8_t address_bits = address_size * CHAR_BIT;
	uint64_t address_mask = uint_max(address_size);
	const struct drgn_register_layout *register_layout =
		ctx->file->platform.arch->register_layout;
	drgn_register_number (*dwarf_regno_to_internal)(uint64_t) =
		ctx->file->platform.arch->dwarf_regno_to_internal;

#define CHECK(n) do {								\
	size_t _n = (n);							\
	if (uint64_vector_size(stack) < _n) {					\
		return binary_buffer_error(&ctx->bb,				\
					   "DWARF expression stack underflow");	\
	}									\
} while (0)

#define ELEM(i) *uint64_vector_at(stack, uint64_vector_size(stack) - 1 - (i))

#define PUSH(x) do {					\
	uint64_t push = (x);				\
	if (!uint64_vector_append(stack, &push))	\
		return &drgn_enomem;			\
} while (0)

#define PUSH_MASK(x) PUSH((x) & address_mask)

	while (binary_buffer_has_next(&ctx->bb)) {
		if (*remaining_ops <= 0) {
			return binary_buffer_error(&ctx->bb,
						   "DWARF expression executed too many operations");
		}
		(*remaining_ops)--;
		uint8_t opcode;
		if ((err = binary_buffer_next_u8(&ctx->bb, &opcode)))
			return err;
		uint64_t uvalue;
		uint64_t dwarf_regno;
		uint8_t deref_size;
		switch (opcode) {
		/* Literal encodings. */
		case DW_OP_lit0 ... DW_OP_lit31:
			PUSH(opcode - DW_OP_lit0);
			break;
		case DW_OP_addr:
			if ((err = binary_buffer_next_uint(&ctx->bb,
							   address_size,
							   &uvalue)))
				return err;
			PUSH(uvalue);
			break;
		case DW_OP_const1u:
			if ((err = binary_buffer_next_u8_into_u64(&ctx->bb,
								  &uvalue)))
				return err;
			PUSH(uvalue);
			break;
		case DW_OP_const2u:
			if ((err = binary_buffer_next_u16_into_u64(&ctx->bb,
								   &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_const4u:
			if ((err = binary_buffer_next_u32_into_u64(&ctx->bb,
								   &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_const8u:
			if ((err = binary_buffer_next_u64(&ctx->bb, &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_const1s:
			if ((err = binary_buffer_next_s8_into_u64(&ctx->bb,
								  &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_const2s:
			if ((err = binary_buffer_next_s16_into_u64(&ctx->bb,
								   &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_const4s:
			if ((err = binary_buffer_next_s32_into_u64(&ctx->bb,
								   &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_const8s:
			if ((err = binary_buffer_next_s64_into_u64(&ctx->bb,
								   &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_constu:
			if ((err = binary_buffer_next_uleb128(&ctx->bb,
							      &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_consts:
			if ((err = binary_buffer_next_sleb128_into_u64(&ctx->bb,
								       &uvalue)))
				return err;
			PUSH_MASK(uvalue);
			break;
		case DW_OP_addrx:
		case DW_OP_constx:
		case DW_OP_GNU_addr_index:
		case DW_OP_GNU_const_index:
			if (!ctx->cu_die.addr) {
				ctx->bb.pos = ctx->bb.prev;
				return NULL;
			}
			if ((err = drgn_dwarf_next_addrx(&ctx->bb, ctx->file,
							 &ctx->cu_die,
							 address_size,
							 &ctx->cu_addr_base,
							 &uvalue)))
				return err;
			PUSH(uvalue);
			break;
		/* Register values. */
		case DW_OP_fbreg: {
			err = drgn_dwarf_frame_base(ctx->prog, ctx->file,
						    ctx->function, ctx->regs,
						    remaining_ops, &uvalue);
			if (err)
				return err;
			int64_t svalue;
			if ((err = binary_buffer_next_sleb128(&ctx->bb,
							      &svalue)))
				return err;
			PUSH_MASK(uvalue + svalue);
			break;
		}
		case DW_OP_breg0 ... DW_OP_breg31:
			dwarf_regno = opcode - DW_OP_breg0;
			goto breg;
		case DW_OP_bregx:
			if ((err = binary_buffer_next_uleb128(&ctx->bb,
							      &dwarf_regno)))
				return err;
breg:
		{
			if (!ctx->regs)
				return &drgn_not_found;
			drgn_register_number regno =
				dwarf_regno_to_internal(dwarf_regno);
			if (!drgn_register_state_has_register(ctx->regs, regno))
				return &drgn_not_found;
			const struct drgn_register_layout *layout =
				&register_layout[regno];
			copy_lsbytes(&uvalue, sizeof(uvalue),
				     HOST_LITTLE_ENDIAN,
				     &ctx->regs->buf[layout->offset],
				     layout->size, little_endian);
			int64_t svalue;
			if ((err = binary_buffer_next_sleb128(&ctx->bb,
							      &svalue)))
				return err;
			PUSH_MASK(uvalue + svalue);
			break;
		}
		/* Stack operations. */
		case DW_OP_dup:
			CHECK(1);
			PUSH(ELEM(0));
			break;
		case DW_OP_drop:
			CHECK(1);
			uint64_vector_pop(stack);
			break;
		case DW_OP_pick: {
			uint8_t index;
			if ((err = binary_buffer_next_u8(&ctx->bb, &index)))
				return err;
			CHECK(index + 1);
			PUSH(ELEM(index));
			break;
		}
		case DW_OP_over:
			CHECK(2);
			PUSH(ELEM(1));
			break;
		case DW_OP_swap:
			CHECK(2);
			uvalue = ELEM(0);
			ELEM(0) = ELEM(1);
			ELEM(1) = uvalue;
			break;
		case DW_OP_rot:
			CHECK(3);
			uvalue = ELEM(0);
			ELEM(0) = ELEM(1);
			ELEM(1) = ELEM(2);
			ELEM(2) = uvalue;
			break;
		case DW_OP_deref:
			deref_size = address_size;
			goto deref;
		case DW_OP_deref_size:
			if ((err = binary_buffer_next_u8(&ctx->bb,
							 &deref_size)))
				return err;
			if (deref_size > address_size) {
				return binary_buffer_error(&ctx->bb,
							   "DW_OP_deref_size has invalid size");
			}
deref:
		{
			CHECK(1);
			char deref_buf[8];
			err = drgn_program_read_memory(ctx->prog, deref_buf,
						       ELEM(0), deref_size,
						       false);
			if (err)
				return err;
			copy_lsbytes(&ELEM(0), sizeof(ELEM(0)),
				     HOST_LITTLE_ENDIAN, deref_buf, deref_size,
				     little_endian);
			break;
		}
		case DW_OP_call_frame_cfa: {
			if (!ctx->regs)
				return &drgn_not_found;
			/*
			 * The DWARF 5 specification says that
			 * DW_OP_call_frame_cfa cannot be used for CFI. For
			 * DW_CFA_def_cfa_expression, it is clearly invalid to
			 * define the CFA in terms of the CFA, and it will fail
			 * naturally below. This restriction doesn't make sense
			 * for DW_CFA_expression and DW_CFA_val_expression, as
			 * they push the CFA and thus depend on it anyways, so
			 * we don't bother enforcing it.
			 */
			struct optional_uint64 cfa =
				drgn_register_state_get_cfa(ctx->regs);
			if (!cfa.has_value)
				return &drgn_not_found;
			PUSH(cfa.value);
			break;
		}
		/* Arithmetic and logical operations. */
#define UNOP_MASK(op) do {			\
	CHECK(1);				\
	ELEM(0) = (op ELEM(0)) & address_mask;	\
} while (0)
#define BINOP(op) do {			\
	CHECK(2);			\
	ELEM(1) = ELEM(1) op ELEM(0);	\
	uint64_vector_pop(stack);	\
} while (0)
#define BINOP_MASK(op) do {				\
	CHECK(2);					\
	ELEM(1) = (ELEM(1) op ELEM(0)) & address_mask;	\
	uint64_vector_pop(stack);			\
} while (0)
		case DW_OP_abs:
			CHECK(1);
			if (ELEM(0) & (UINT64_C(1) << (address_bits - 1)))
				ELEM(0) = -ELEM(0) & address_mask;
			break;
		case DW_OP_and:
			BINOP(&);
			break;
		case DW_OP_div:
			CHECK(2);
			if (ELEM(0) == 0) {
				return binary_buffer_error(&ctx->bb,
							   "division by zero in DWARF expression");
			}
			ELEM(1) = ((truncate_signed(ELEM(1), address_bits)
				    / truncate_signed(ELEM(0), address_bits))
				   & address_mask);
			uint64_vector_pop(stack);
			break;
		case DW_OP_minus:
			BINOP_MASK(-);
			break;
		case DW_OP_mod:
			CHECK(2);
			if (ELEM(0) == 0) {
				return binary_buffer_error(&ctx->bb,
							   "modulo by zero in DWARF expression");
			}
			ELEM(1) = ELEM(1) % ELEM(0);
			uint64_vector_pop(stack);
			break;
		case DW_OP_mul:
			BINOP_MASK(*);
			break;
		case DW_OP_neg:
			UNOP_MASK(-);
			break;
		case DW_OP_not:
			UNOP_MASK(~);
			break;
		case DW_OP_or:
			BINOP(|);
			break;
		case DW_OP_plus:
			BINOP_MASK(+);
			break;
		case DW_OP_plus_uconst:
			CHECK(1);
			if ((err = binary_buffer_next_uleb128(&ctx->bb,
							      &uvalue)))
				return err;
			ELEM(0) = (ELEM(0) + uvalue) & address_mask;
			break;
		case DW_OP_shl:
			CHECK(2);
			if (ELEM(0) < address_bits)
				ELEM(1) = (ELEM(1) << ELEM(0)) & address_mask;
			else
				ELEM(1) = 0;
			uint64_vector_pop(stack);
			break;
		case DW_OP_shr:
			CHECK(2);
			if (ELEM(0) < address_bits)
				ELEM(1) >>= ELEM(0);
			else
				ELEM(1) = 0;
			uint64_vector_pop(stack);
			break;
		case DW_OP_shra:
			CHECK(2);
			if (ELEM(0) < address_bits) {
				ELEM(1) = ((truncate_signed(ELEM(1), address_bits)
					    >> ELEM(0))
					   & address_mask);
			} else if (ELEM(1) & (UINT64_C(1) << (address_bits - 1))) {
				ELEM(1) = -INT64_C(1) & address_mask;
			} else {
				ELEM(1) = 0;
			}
			uint64_vector_pop(stack);
			break;
		case DW_OP_xor:
			BINOP(^);
			break;
#undef BINOP_MASK
#undef BINOP
#undef UNOP_MASK
		/* Control flow operations. */
#define RELOP(op) do {						\
	CHECK(2);						\
	ELEM(1) = (truncate_signed(ELEM(1), address_bits) op	\
		   truncate_signed(ELEM(0), address_bits));	\
	uint64_vector_pop(stack);				\
} while (0)
		case DW_OP_le:
			RELOP(<=);
			break;
		case DW_OP_ge:
			RELOP(>=);
			break;
		case DW_OP_eq:
			RELOP(==);
			break;
		case DW_OP_lt:
			RELOP(<);
			break;
		case DW_OP_gt:
			RELOP(>);
			break;
		case DW_OP_ne:
			RELOP(!=);
			break;
#undef RELOP
		case DW_OP_skip:
branch:
		{
			int16_t skip;
			if ((err = binary_buffer_next_s16(&ctx->bb, &skip)))
				return err;
			if ((skip >= 0 && skip > ctx->bb.end - ctx->bb.pos) ||
			    (skip < 0 && -skip > ctx->bb.pos - ctx->start)) {
				return binary_buffer_error(&ctx->bb,
							   "DWARF expression branch is out of bounds");
			}
			ctx->bb.pos += skip;
			break;
		}
		case DW_OP_bra:
			CHECK(1);
			if (ELEM(0)) {
				uint64_vector_pop(stack);
				goto branch;
			} else {
				uint64_vector_pop(stack);
				if ((err = binary_buffer_skip(&ctx->bb, 2)))
					return err;
			}
			break;
		/* Special operations. */
		case DW_OP_nop:
			break;
		case DW_OP_entry_value:
		case DW_OP_GNU_entry_value:
			// TODO: DW_OP_(GNU_)entry_value followed by
			// DW_OP_reg<n> means the value of the register when the
			// current subprogram was entered. We could recover this
			// by finding the DW_TAG_(GNU_)call_site for the return
			// address and using the DW_AT_(GNU_)call_value of a
			// DW_TAG_(GNU_)call_parameter with a DW_AT_location
			// matching that register.
			return &drgn_not_found;
		/* Location description operations. */
		case DW_OP_reg0 ... DW_OP_reg31:
		case DW_OP_regx:
		case DW_OP_implicit_value:
		case DW_OP_stack_value:
		case DW_OP_piece:
		case DW_OP_bit_piece:
			/* The caller must handle it. */
			ctx->bb.pos = ctx->bb.prev;
			return NULL;
		/*
		 * We don't yet support:
		 *
		 * - DW_OP_push_object_address
		 * - DW_OP_form_tls_address
		 *   DW_OP_implicit_pointer
		 * - Procedure calls: DW_OP_call2, DW_OP_call4, DW_OP_call_ref.
		 * - Typed operations: DW_OP_const_type, DW_OP_regval_type,
		 *   DW_OP_deref_type, DW_OP_convert, DW_OP_reinterpret.
		 * - Operations for multiple address spaces: DW_OP_xderef,
		 *   DW_OP_xderef_size, DW_OP_xderef_type.
		 */
		default:
		{
			char op_buf[DW_OP_STR_BUF_LEN];
			return binary_buffer_error(&ctx->bb,
						   "unknown DWARF expression opcode %s; "
						   "please report this to %s",
						   dw_op_str(opcode, op_buf),
						   PACKAGE_BUGREPORT);
		}
		}
	}

#undef PUSH_MASK
#undef PUSH
#undef ELEM
#undef CHECK

	return NULL;
}

static struct drgn_error *
drgn_dwarf_frame_base(struct drgn_program *prog, struct drgn_elf_file *file,
		      Dwarf_Die *die, const struct drgn_register_state *regs,
		      int *remaining_ops, uint64_t *ret)
{
	struct drgn_error *err;
	bool little_endian = drgn_elf_file_is_little_endian(file);
	const struct drgn_register_layout *register_layout =
		file->platform.arch->register_layout;
	drgn_register_number (*dwarf_regno_to_internal)(uint64_t) =
		file->platform.arch->dwarf_regno_to_internal;

	if (!die)
		return &drgn_not_found;
	Dwarf_Attribute attr_mem, *attr;
	if (!(attr = dwarf_attr_integrate(die, DW_AT_frame_base, &attr_mem)))
		return &drgn_not_found;
	const char *expr;
	size_t expr_size;
	err = drgn_dwarf_location(file, attr, regs, &expr, &expr_size);
	if (err)
		return err;

	struct drgn_dwarf_expression_context ctx;
	if ((err = drgn_dwarf_expression_context_init(&ctx, prog, file, die->cu,
						      NULL, regs, expr,
						      expr_size)))
		return err;
	_cleanup_(uint64_vector_deinit)
		struct uint64_vector stack = VECTOR_INIT;
	for (;;) {
		err = drgn_eval_dwarf_expression(&ctx, &stack, remaining_ops);
		if (err)
			return err;
		if (binary_buffer_has_next(&ctx.bb)) {
			uint8_t opcode;
			if ((err = binary_buffer_next_u8(&ctx.bb, &opcode)))
				return err;

			uint64_t dwarf_regno;
			switch (opcode) {
			case DW_OP_reg0 ... DW_OP_reg31:
				dwarf_regno = opcode - DW_OP_reg0;
				goto reg;
			case DW_OP_regx:
				if ((err = binary_buffer_next_uleb128(&ctx.bb,
								      &dwarf_regno)))
					return err;
reg:
			{
				if (!regs)
					return &drgn_not_found;
				drgn_register_number regno =
					dwarf_regno_to_internal(dwarf_regno);
				if (!drgn_register_state_has_register(regs,
								      regno))
					return &drgn_not_found;
				const struct drgn_register_layout *layout =
					&register_layout[regno];
				/*
				 * Note that this doesn't mask the address since
				 * the caller does that.
				 */
				copy_lsbytes(ret, sizeof(*ret),
					     HOST_LITTLE_ENDIAN,
					     &regs->buf[layout->offset],
					     layout->size, little_endian);
				if (binary_buffer_has_next(&ctx.bb)) {
					return binary_buffer_error(&ctx.bb,
								   "stray operations in DW_AT_frame_base expression");
				} else {
					return NULL;
				}
			}
			default:
				return binary_buffer_error(&ctx.bb,
							   "invalid opcode %#" PRIx8 " for DW_AT_frame_base expression",
							   opcode);
			}
		} else if (!uint64_vector_empty(&stack)) {
			*ret = *uint64_vector_last(&stack);
			return NULL;
		} else {
			return &drgn_not_found;
		}
	}
}

/*
 * Type and object parsing.
 */

/**
 * Return whether a DWARF DIE is little-endian.
 *
 * @param[in] check_attr Whether to check the DW_AT_endianity attribute. If @c
 * false, only the ELF header is checked and this function cannot fail.
 * @return @c NULL on success, non-@c NULL on error.
 */
static struct drgn_error *dwarf_die_is_little_endian(Dwarf_Die *die,
						     bool check_attr, bool *ret)
{
	Dwarf_Attribute endianity_attr_mem, *endianity_attr;
	Dwarf_Word endianity;
	if (check_attr &&
	    (endianity_attr = dwarf_attr_integrate(die, DW_AT_endianity,
						   &endianity_attr_mem))) {
		if (dwarf_formudata(endianity_attr, &endianity)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid DW_AT_endianity");
		}
	} else {
		endianity = DW_END_default;
	}
	switch (endianity) {
	case DW_END_default: {
		Elf *elf = dwarf_getelf(dwarf_cu_getdwarf(die->cu));
		*ret = elf_getident(elf, NULL)[EI_DATA] == ELFDATA2LSB;
		return NULL;
	}
	case DW_END_little:
		*ret = true;
		return NULL;
	case DW_END_big:
		*ret = false;
		return NULL;
	default:
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "unknown DW_AT_endianity");
	}
}

/** Like dwarf_die_is_little_endian(), but returns a @ref drgn_byte_order. */
static struct drgn_error *dwarf_die_byte_order(Dwarf_Die *die, bool check_attr,
					       enum drgn_byte_order *ret)
{
	bool little_endian;
	struct drgn_error *err = dwarf_die_is_little_endian(die, check_attr,
							    &little_endian);
	/*
	 * dwarf_die_is_little_endian() can't fail if check_attr is false, so
	 * the !check_attr test suppresses maybe-uninitialized warnings.
	 */
	if (!err || !check_attr)
		*ret = drgn_byte_order_from_little_endian(little_endian);
	return err;
}

static int dwarf_type(Dwarf_Die *die, Dwarf_Die *ret)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;

	if (!(attr = dwarf_attr_integrate(die, DW_AT_type, &attr_mem)))
		return 1;

	return dwarf_formref_die(attr, ret) ? 0 : -1;
}

static int dwarf_flag(Dwarf_Die *die, unsigned int name, bool *ret)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;

	if (!(attr = dwarf_attr(die, name, &attr_mem))) {
		*ret = false;
		return 0;
	}
	return dwarf_formflag(attr, ret);
}

static int dwarf_flag_integrate(Dwarf_Die *die, unsigned int name, bool *ret)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;

	if (!(attr = dwarf_attr_integrate(die, name, &attr_mem))) {
		*ret = false;
		return 0;
	}
	return dwarf_formflag(attr, ret);
}

/**
 * Parse a type from a DWARF debugging information entry.
 *
 * This is the same as @ref drgn_type_from_dwarf() except that it can be used to
 * work around a bug in GCC < 9.0 that zero length array types are encoded the
 * same as incomplete array types. There are a few places where GCC allows
 * zero-length arrays but not incomplete arrays:
 *
 * - As the type of a member of a structure with only one member.
 * - As the type of a structure member other than the last member.
 * - As the type of a union member.
 * - As the element type of an array.
 *
 * In these cases, we know that what appears to be an incomplete array type must
 * actually have a length of zero. In other cases, a subrange DIE without
 * DW_AT_count or DW_AT_upper_bound is ambiguous; we return an incomplete array
 * type.
 *
 * @param[in] dbinfo Debugging information.
 * @param[in] file File containing @p die.
 * @param[in] die DIE to parse.
 * @param[in] can_be_incomplete_array Whether the type can be an incomplete
 * array type. If this is @c false and the type appears to be an incomplete
 * array type, its length is set to zero instead.
 * @param[out] is_incomplete_array_ret Whether the encoded type is an incomplete
 * array type or a typedef of an incomplete array type (regardless of @p
 * can_be_incomplete_array).
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static struct drgn_error *
drgn_type_from_dwarf_internal(struct drgn_debug_info *dbinfo,
			      struct drgn_elf_file *file, Dwarf_Die *die,
			      bool can_be_incomplete_array,
			      bool *is_incomplete_array_ret,
			      struct drgn_qualified_type *ret);

/**
 * Parse a type from a DWARF debugging information entry.
 *
 * @param[in] dbinfo Debugging information.
 * @param[in] file File containing @p die.
 * @param[in] die DIE to parse.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_type_from_dwarf(struct drgn_debug_info *dbinfo, struct drgn_elf_file *file,
		     Dwarf_Die *die, struct drgn_qualified_type *ret)
{
	return drgn_type_from_dwarf_internal(dbinfo, file, die, true, NULL,
					     ret);
}

/**
 * Parse a type from the @c DW_AT_type attribute of a DWARF debugging
 * information entry.
 *
 * @param[in] dbinfo Debugging information.
 * @param[in] file File containing @p die.
 * @param[in] die DIE with @c DW_AT_type attribute.
 * @param[in] lang Language of @p die if it is already known, @c NULL if it
 * should be determined from @p die.
 * @param[in] can_be_void Whether the @c DW_AT_type attribute may be missing,
 * which is interpreted as a void type. If this is false and the @c DW_AT_type
 * attribute is missing, an error is returned.
 * @param[in] can_be_incomplete_array See @ref drgn_type_from_dwarf_internal().
 * @param[in] is_incomplete_array_ret See @ref drgn_type_from_dwarf_internal().
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static struct drgn_error *
drgn_type_from_dwarf_attr(struct drgn_debug_info *dbinfo,
			  struct drgn_elf_file *file, Dwarf_Die *die,
			  const struct drgn_language *lang,
			  bool can_be_void, bool can_be_incomplete_array,
			  bool *is_incomplete_array_ret,
			  struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	char tag_buf[DW_TAG_STR_BUF_LEN];

	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	if (!(attr = dwarf_attr_integrate(die, DW_AT_type, &attr_mem))) {
		if (can_be_void) {
			if (!lang) {
				err = drgn_language_from_die(die, true, &lang);
				if (err)
					return err;
			}
			ret->type = drgn_void_type(dbinfo->prog, lang);
			ret->qualifiers = 0;
			return NULL;
		} else {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "%s is missing DW_AT_type",
						 dwarf_tag_str(die, tag_buf));
		}
	}

	Dwarf_Die type_die;
	if (!dwarf_formref_die(attr, &type_die)) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has invalid DW_AT_type",
					 dwarf_tag_str(die, tag_buf));
	}

	return drgn_type_from_dwarf_internal(dbinfo, file, &type_die,
					     can_be_incomplete_array,
					     is_incomplete_array_ret, ret);
}

static struct drgn_error *
drgn_object_from_dwarf_enumerator(struct drgn_debug_info *dbinfo,
				  struct drgn_elf_file *file, Dwarf_Die *die,
				  const char *name, struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_type_from_dwarf(dbinfo, file, die, &qualified_type);
	if (err)
		return err;
	const struct drgn_type_enumerator *enumerators =
		drgn_type_enumerators(qualified_type.type);
	size_t num_enumerators = drgn_type_num_enumerators(qualified_type.type);
	for (size_t i = 0; i < num_enumerators; i++) {
		if (strcmp(enumerators[i].name, name) != 0)
			continue;

		if (drgn_enum_type_is_signed(qualified_type.type)) {
			return drgn_object_set_signed(ret, qualified_type,
						      enumerators[i].svalue, 0);
		} else {
			return drgn_object_set_unsigned(ret, qualified_type,
							enumerators[i].uvalue,
							0);
		}
	}
	UNREACHABLE();
}

static struct drgn_error *
drgn_object_from_dwarf_subprogram(struct drgn_debug_info *dbinfo,
				  struct drgn_elf_file *file, Dwarf_Die *die,
				  struct drgn_object *ret)
{
	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_type_from_dwarf(dbinfo, file, die,
						      &qualified_type);
	if (err)
		return err;
	Dwarf_Addr low_pc;
	if (dwarf_lowpc(die, &low_pc) == -1)
		return drgn_object_set_absent(ret, qualified_type, 0);
	return drgn_object_set_reference(ret, qualified_type,
					 low_pc + file->module->debug_file_bias,
					 0, 0);
}

static struct drgn_error *read_bits(struct drgn_program *prog, void *dst,
				    unsigned int dst_bit_offset, uint64_t src,
				    unsigned int src_bit_offset,
				    uint64_t bit_size, bool lsb0)
{
	struct drgn_error *err;

	assert(dst_bit_offset < 8);
	assert(src_bit_offset < 8);

	if (bit_size == 0)
		return NULL;

	if (dst_bit_offset == src_bit_offset) {
		/*
		 * We can read directly into the the destination buffer, but we
		 * may have to preserve some bits at the start and/or end.
		 */
		uint8_t *d = dst;
		uint64_t last_bit = dst_bit_offset + bit_size - 1;
		uint8_t first_byte = d[0];
		uint8_t last_byte = d[last_bit / 8];
		err = drgn_program_read_memory(prog, d, src, last_bit / 8 + 1,
					       false);
		if (err)
			return err;
		if (dst_bit_offset != 0) {
			uint8_t mask =
				copy_bits_first_mask(dst_bit_offset, lsb0);
			d[0] = (first_byte & ~mask) | (d[0] & mask);
		}
		if (last_bit % 8 != 7) {
			uint8_t mask = copy_bits_last_mask(last_bit, lsb0);
			d[last_bit / 8] = ((last_byte & ~mask)
					   | (d[last_bit / 8] & mask));
		}
		return NULL;
	} else {
		/*
		 * If the source and destination have different offsets, then
		 * depending on the size and source offset, we may have to read
		 * one more byte than is available in the destination. To keep
		 * things simple, we always read into a temporary buffer (rather
		 * than adding a special case for reading directly into the
		 * destination and shifting bits around).
		 */
		uint64_t src_bytes = (src_bit_offset + bit_size - 1) / 8 + 1;
		char stack_tmp[16], *tmp;
		if (src_bytes <= sizeof(stack_tmp)) {
			tmp = stack_tmp;
		} else {
			tmp = malloc64(src_bytes);
			if (!tmp)
				return &drgn_enomem;
		}
		err = drgn_program_read_memory(prog, tmp, src, src_bytes,
					       false);
		if (!err) {
			copy_bits(dst, dst_bit_offset, tmp, src_bit_offset,
				  bit_size, lsb0);
		}
		if (src_bytes > sizeof(stack_tmp))
			free(tmp);
		return err;
	}
}

static struct drgn_error *
drgn_object_from_dwarf_location(struct drgn_program *prog,
				struct drgn_elf_file *file, Dwarf_Die *die,
				struct drgn_qualified_type qualified_type,
				const char *expr, size_t expr_size,
				Dwarf_Die *function_die,
				const struct drgn_register_state *regs,
				struct drgn_object *ret)
{
	struct drgn_error *err;
	bool little_endian = drgn_elf_file_is_little_endian(file);
	uint64_t address_mask = drgn_elf_file_address_mask(file);
	const struct drgn_register_layout *register_layout =
		file->platform.arch->register_layout;
	drgn_register_number (*dwarf_regno_to_internal)(uint64_t) =
		file->platform.arch->dwarf_regno_to_internal;

	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, 0, &type);
	if (err)
		return err;

	union drgn_value value;
	char *value_buf = NULL;

	uint64_t address = 0; /* GCC thinks this may be used uninitialized. */
	int bit_offset = -1; /* -1 means that we don't have an address. */

	uint64_t bit_pos = 0;

	int remaining_ops = MAX_DWARF_EXPR_OPS;
	struct drgn_dwarf_expression_context ctx;
	if ((err = drgn_dwarf_expression_context_init(&ctx, prog, file, die->cu,
						      function_die, regs, expr,
						      expr_size)))
		return err;
	struct uint64_vector stack = VECTOR_INIT;
	do {
		uint64_vector_clear(&stack);
		err = drgn_eval_dwarf_expression(&ctx, &stack, &remaining_ops);
		if (err == &drgn_not_found)
			goto absent;
		else if (err)
			goto out;

		const void *src = NULL;
		size_t src_size;

		if (binary_buffer_has_next(&ctx.bb)) {
			uint8_t opcode;
			if ((err = binary_buffer_next_u8(&ctx.bb, &opcode)))
				goto out;

			uint64_t uvalue;
			uint64_t dwarf_regno;
			drgn_register_number regno;
			switch (opcode) {
			case DW_OP_reg0 ... DW_OP_reg31:
				dwarf_regno = opcode - DW_OP_reg0;
				goto reg;
			case DW_OP_regx:
				if ((err = binary_buffer_next_uleb128(&ctx.bb,
								      &dwarf_regno)))
					goto out;
reg:
				if (!regs)
					goto absent;
				regno = dwarf_regno_to_internal(dwarf_regno);
				if (!drgn_register_state_has_register(regs,
								      regno))
					goto absent;
				const struct drgn_register_layout *layout =
					&register_layout[regno];
				src = &regs->buf[layout->offset];
				src_size = layout->size;
				break;
			case DW_OP_implicit_value:
				if ((err = binary_buffer_next_uleb128(&ctx.bb,
								      &uvalue)))
					goto out;
				if (uvalue > ctx.bb.end - ctx.bb.pos) {
					err = binary_buffer_error(&ctx.bb,
								  "DW_OP_implicit_value size is out of bounds");
					goto out;
				}
				src = ctx.bb.pos;
				src_size = uvalue;
				ctx.bb.pos += uvalue;
				break;
			case DW_OP_stack_value:
				if (uint64_vector_empty(&stack))
					goto absent;
				if (little_endian != HOST_LITTLE_ENDIAN) {
					*uint64_vector_last(&stack) =
						bswap_64(*uint64_vector_last(&stack));
				}
				src = uint64_vector_last(&stack);
				src_size = sizeof(uint64_t);
				break;
			default:
				ctx.bb.pos = ctx.bb.prev;
				break;
			}
		}

		uint64_t piece_bit_size;
		uint64_t piece_bit_offset;
		if (binary_buffer_has_next(&ctx.bb)) {
			uint8_t opcode;
			if ((err = binary_buffer_next_u8(&ctx.bb, &opcode)))
				goto out;

			switch (opcode) {
			case DW_OP_piece:
				if ((err = binary_buffer_next_uleb128(&ctx.bb,
								      &piece_bit_size)))
					goto out;
				/*
				 * It's probably bogus for the piece size to be
				 * larger than the remaining value size, but
				 * that's not explicitly stated in the DWARF 5
				 * specification, so clamp it instead.
				 */
				if (__builtin_mul_overflow(piece_bit_size, 8U,
							   &piece_bit_size) ||
				    piece_bit_size > type.bit_size - bit_pos)
					piece_bit_size = type.bit_size - bit_pos;
				piece_bit_offset = 0;
				break;
			case DW_OP_bit_piece:
				if ((err = binary_buffer_next_uleb128(&ctx.bb,
								      &piece_bit_size)) ||
				    (err = binary_buffer_next_uleb128(&ctx.bb,
								      &piece_bit_offset)))
					goto out;
				if (piece_bit_size > type.bit_size - bit_pos)
					piece_bit_size = type.bit_size - bit_pos;
				break;
			default:
				err = binary_buffer_error(&ctx.bb,
							  "unknown DWARF expression opcode %#" PRIx8 " after simple location description",
							  opcode);
				goto out;
			}
		} else {
			piece_bit_size = type.bit_size - bit_pos;
			piece_bit_offset = 0;
		}

		/*
		 * TODO: there are a few cases that a DWARF location can
		 * describe that can't be represented in drgn's object model:
		 *
		 * 1. An object that is partially known and partially unknown.
		 * 2. An object that is partially in memory and partially a
		 *    value.
		 * 3. An object that is in memory at non-contiguous addresses.
		 * 4. A pointer object whose pointer value is not known but
		 *    whose referenced value is known (DW_OP_implicit_pointer).
		 *
		 * For case 1, we consider the whole object as absent. For cases
		 * 2 and 3, we convert the whole object to a value. Case 4 is
		 * not supported at all. We should add a way to represent all of
		 * these situations precisely.
		 */
		if (src && piece_bit_size == 0) {
			/* Ignore empty value. */
		} else if (src) {
			if (!value_buf &&
			    !drgn_value_zalloc(drgn_value_size(type.bit_size),
					       &value, &value_buf)) {
				err = &drgn_enomem;
				goto out;
			}
			if (bit_offset >= 0) {
				/*
				 * We previously had an address. Read it into
				 * the value.
				 */
				err = read_bits(prog, value_buf, 0, address,
						bit_offset, bit_pos,
						little_endian);
				if (err)
					goto out;
				bit_offset = -1;
			}
			/*
			 * It's probably safe to assume that we don't have an
			 * implicit value larger than 2 exabytes.
			 */
			assert(src_size <= UINT64_MAX / 8);
			uint64_t src_bit_size = UINT64_C(8) * src_size;
			if (piece_bit_offset > src_bit_size)
				piece_bit_offset = src_bit_size;
			uint64_t copy_bit_size =
				min(piece_bit_size,
				    src_bit_size - piece_bit_offset);
			uint64_t copy_bit_offset = bit_pos;
			if (!little_endian) {
				copy_bit_offset += piece_bit_size - copy_bit_size;
				piece_bit_offset = (src_bit_size
						    - copy_bit_size
						    - piece_bit_offset);
			}
			copy_bits(&value_buf[copy_bit_offset / 8],
				  copy_bit_offset % 8,
				  (const char *)src + (piece_bit_offset / 8),
				  piece_bit_offset % 8, copy_bit_size,
				  little_endian);
		} else if (!uint64_vector_empty(&stack)) {
			uint64_t piece_address =
				((*uint64_vector_last(&stack)
				  + piece_bit_offset / 8)
				 & address_mask);
			piece_bit_offset %= 8;
			if (bit_pos > 0 && bit_offset >= 0) {
				/*
				 * We already had an address. Merge the pieces
				 * if the addresses are contiguous, otherwise
				 * convert to a value.
				 *
				 * The obvious way to write this is
				 * (address + (bit_pos + bit_offset) / 8), but
				 * (bit_pos + bit_offset) can overflow uint64_t.
				 */
				uint64_t end_address =
					((address
					  + bit_pos / 8
					  + (bit_pos % 8 + bit_offset) / 8)
					 & address_mask);
				unsigned int end_bit_offset =
					(bit_offset + bit_pos) % 8;
				if (piece_bit_size == 0 ||
				    (piece_address == end_address &&
				     piece_bit_offset == end_bit_offset)) {
					/* Piece is contiguous. */
					piece_address = address;
					piece_bit_offset = bit_offset;
				} else {
					if (!drgn_value_zalloc(drgn_value_size(type.bit_size),
							       &value,
							       &value_buf)) {
						err = &drgn_enomem;
						goto out;
					}
					err = read_bits(prog, value_buf, 0,
							address, bit_offset,
							bit_pos, little_endian);
					if (err)
						goto out;
					bit_offset = -1;
				}
			}
			if (value_buf) {
				/* We already have a value. Read into it. */
				err = read_bits(prog, &value_buf[bit_pos / 8],
						bit_pos % 8, piece_address,
						piece_bit_offset,
						piece_bit_size, little_endian);
				if (err)
					goto out;
			} else {
				address = piece_address;
				bit_offset = piece_bit_offset;
			}
		} else if (piece_bit_size > 0) {
			goto absent;
		}
		bit_pos += piece_bit_size;
	} while (binary_buffer_has_next(&ctx.bb));

	if (bit_pos < type.bit_size || (bit_offset < 0 && !value_buf)) {
absent:
		if (dwarf_tag(die) == DW_TAG_template_value_parameter) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_AT_template_value_parameter is missing value");
		}
		drgn_object_reinit(ret, &type, DRGN_OBJECT_ABSENT);
		err = NULL;
	} else if (bit_offset >= 0) {
		Dwarf_Addr start, end, bias;
		dwfl_module_info(file->module->dwfl_module, NULL, &start, &end,
				 &bias, NULL, NULL, NULL);
		/*
		 * If the address is not in the module's address range, then
		 * it's probably something special like a Linux per-CPU variable
		 * (which isn't actually a variable address but an offset).
		 * Don't apply the bias in that case.
		 */
		if (start <= address + bias && address + bias < end)
			address += bias;
		err = drgn_object_set_reference_internal(ret, &type, address,
							 bit_offset);
	} else if (type.encoding == DRGN_OBJECT_ENCODING_BUFFER) {
		drgn_object_reinit(ret, &type, DRGN_OBJECT_VALUE);
		ret->value = value;
		value_buf = NULL;
		err = NULL;
	} else {
		err = drgn_object_set_from_buffer_internal(ret, &type,
							   value_buf, 0);
	}

out:
	if (value_buf != value.ibuf)
		free(value_buf);
	uint64_vector_deinit(&stack);
	return err;
}

static struct drgn_error *
drgn_object_from_dwarf_constant(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
				struct drgn_qualified_type qualified_type,
				Dwarf_Attribute *attr, struct drgn_object *ret)
{
	struct drgn_object_type type;
	struct drgn_error *err = drgn_object_type(qualified_type, 0, &type);
	if (err)
		return err;
	Dwarf_Block block;
	if (dwarf_formblock(attr, &block) == 0) {
		if (block.length < drgn_value_size(type.bit_size)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_AT_const_value block is too small");
		}
		return drgn_object_set_from_buffer_internal(ret, &type,
							    block.data, 0);
	} else if (type.encoding == DRGN_OBJECT_ENCODING_SIGNED) {
		Dwarf_Sword svalue;
		if (dwarf_formsdata(attr, &svalue)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid DW_AT_const_value");
		}
		return drgn_object_set_signed_internal(ret, &type, svalue);
	} else if (type.encoding == DRGN_OBJECT_ENCODING_UNSIGNED) {
		Dwarf_Word uvalue;
		if (dwarf_formudata(attr, &uvalue)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid DW_AT_const_value");
		}
		return drgn_object_set_unsigned_internal(ret, &type, uvalue);
	} else {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "unknown DW_AT_const_value form");
	}
}

struct drgn_error *
drgn_object_from_dwarf(struct drgn_debug_info *dbinfo,
		       struct drgn_elf_file *file, Dwarf_Die *die,
		       Dwarf_Die *type_die, Dwarf_Die *function_die,
		       const struct drgn_register_state *regs,
		       struct drgn_object *ret)
{
	struct drgn_error *err;
	if (dwarf_tag(die) == DW_TAG_subprogram) {
		return drgn_object_from_dwarf_subprogram(dbinfo, file, die,
							 ret);
	}
	/*
	 * The DWARF 5 specifications mentions that data object entries can have
	 * DW_AT_endianity, but that doesn't seem to be used in practice. It
	 * would be inconvenient to support, so ignore it for now.
	 */
	struct drgn_qualified_type qualified_type;
	if (type_die) {
		err = drgn_type_from_dwarf(dbinfo, file, type_die,
					   &qualified_type);
	} else {
		err = drgn_type_from_dwarf_attr(dbinfo, file, die, NULL, true,
						true, NULL, &qualified_type);
	}
	if (err)
		return err;
	Dwarf_Attribute attr_mem, *attr;
	const char *expr;
	size_t expr_size;
	if ((attr = dwarf_attr_integrate(die, DW_AT_location, &attr_mem))) {
		err = drgn_dwarf_location(file, attr, regs, &expr, &expr_size);
		if (err)
			return err;
	} else if ((attr = dwarf_attr_integrate(die, DW_AT_const_value,
						&attr_mem))) {
		return drgn_object_from_dwarf_constant(dbinfo, die,
						       qualified_type, attr,
						       ret);
	} else {
		expr = NULL;
		expr_size = 0;
	}
	return drgn_object_from_dwarf_location(dbinfo->prog, file, die,
					       qualified_type, expr, expr_size,
					       function_die, regs, ret);
}

DEFINE_VECTOR(const_char_p_vector, const char *);

static struct drgn_error *add_dwarf_enumerators(Dwarf_Die *enumeration_type,
						struct const_char_p_vector *vec)
{
	Dwarf_Die child;
	int r = dwarf_child(enumeration_type, &child);
	while (r == 0) {
		if (dwarf_tag(&child) == DW_TAG_enumerator) {
			const char *die_name = dwarf_diename(&child);
			if (!die_name)
				continue;
			if (!const_char_p_vector_append(vec, &die_name))
				return &drgn_enomem;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r < 0)
		return drgn_error_libdw();
	return NULL;
}

struct drgn_error *drgn_dwarf_scopes_names(Dwarf_Die *scopes,
					   size_t num_scopes,
					   const char ***names_ret,
					   size_t *count_ret)
{
	struct drgn_error *err;
	Dwarf_Die die;
	_cleanup_(const_char_p_vector_deinit)
		struct const_char_p_vector vec = VECTOR_INIT;
	for (size_t scope = 0; scope < num_scopes; scope++) {
		if (dwarf_child(&scopes[scope], &die) != 0)
			continue;
		do {
			switch (dwarf_tag(&die)) {
			case DW_TAG_variable:
			case DW_TAG_formal_parameter:
			case DW_TAG_subprogram: {
				const char *die_name = dwarf_diename(&die);
				if (!die_name)
					continue;
				if (!const_char_p_vector_append(&vec,
								&die_name))
					return &drgn_enomem;
				break;
			}
			case DW_TAG_enumeration_type: {
				bool enum_class;
				if (dwarf_flag_integrate(&die, DW_AT_enum_class,
							 &enum_class))
					return drgn_error_libdw();
				if (!enum_class) {
					err = add_dwarf_enumerators(&die, &vec);
					if (err)
						return err;
				}
				break;
			}
			default:
				continue;
			}
		} while (dwarf_siblingof(&die, &die) == 0);
	}
	const_char_p_vector_shrink_to_fit(&vec);
	const_char_p_vector_steal(&vec, names_ret, count_ret);
	return NULL;
}

static struct drgn_error *find_dwarf_enumerator(Dwarf_Die *enumeration_type,
						const char *name,
						Dwarf_Die *ret)
{
	int r = dwarf_child(enumeration_type, ret);
	while (r == 0) {
		if (dwarf_tag(ret) == DW_TAG_enumerator) {
			const char *die_name = dwarf_diename(ret);
			if (die_name && strcmp(die_name, name) == 0)
				return NULL;
		}
		r = dwarf_siblingof(ret, ret);
	}
	if (r < 0)
		return drgn_error_libdw();
	ret->addr = NULL;
	return NULL;
}

struct drgn_error *drgn_find_in_dwarf_scopes(Dwarf_Die *scopes,
					     size_t num_scopes,
					     const char *name,
					     Dwarf_Die *die_ret,
					     Dwarf_Die *type_ret)
{
	struct drgn_error *err;
	Dwarf_Die die;
	for (size_t scope = num_scopes; scope--;) {
		bool have_declaration = false;
		if (dwarf_child(&scopes[scope], &die) != 0)
			continue;
		do {
			switch (dwarf_tag(&die)) {
			case DW_TAG_variable:
			case DW_TAG_formal_parameter:
			case DW_TAG_subprogram: {
				const char *die_name = dwarf_diename(&die);
				if (die_name && strcmp(die_name, name) == 0) {
					*die_ret = die;
					bool declaration;
					if (dwarf_flag(&die, DW_AT_declaration,
						       &declaration))
						return drgn_error_libdw();
					if (declaration)
						have_declaration = true;
					else
						return NULL;
				}
				break;
			}
			case DW_TAG_enumeration_type: {
				bool enum_class;
				if (dwarf_flag_integrate(&die, DW_AT_enum_class,
							 &enum_class))
					return drgn_error_libdw();
				if (!enum_class) {
					Dwarf_Die enumerator;
					err = find_dwarf_enumerator(&die, name,
								    &enumerator);
					if (err)
						return err;
					if (enumerator.addr) {
						*die_ret = enumerator;
						*type_ret = die;
						return NULL;
					}
				}
				break;
			}
			default:
				continue;
			}
		} while (dwarf_siblingof(&die, &die) == 0);
		if (have_declaration)
			return NULL;
	}
	die_ret->addr = NULL;
	return NULL;
}

static struct drgn_error *
drgn_base_type_from_dwarf(struct drgn_debug_info *dbinfo,
			  struct drgn_elf_file *file, Dwarf_Die *die,
			  const struct drgn_language *lang,
			  struct drgn_type **ret)
{
	struct drgn_error *err;

	const char *name = dwarf_diename(die);
	if (!name) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_TAG_base_type has missing or invalid DW_AT_name");
	}

	Dwarf_Attribute attr;
	Dwarf_Word encoding;
	if (!dwarf_attr_integrate(die, DW_AT_encoding, &attr) ||
	    dwarf_formudata(&attr, &encoding)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_TAG_base_type has missing or invalid DW_AT_encoding");
	}
	int size = dwarf_bytesize(die);
	if (size == -1) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_TAG_base_type has missing or invalid DW_AT_byte_size");
	}

	enum drgn_byte_order byte_order;
	err = dwarf_die_byte_order(die, true, &byte_order);
	if (err)
		return err;

	switch (encoding) {
	case DW_ATE_boolean:
		return drgn_bool_type_create(dbinfo->prog, name, size,
					     byte_order, lang, ret);
	case DW_ATE_float:
		return drgn_float_type_create(dbinfo->prog, name, size,
					      byte_order, lang, ret);
	case DW_ATE_signed:
	case DW_ATE_signed_char:
		return drgn_int_type_create(dbinfo->prog, name, size, true,
					    byte_order, lang, ret);
	case DW_ATE_unsigned:
	case DW_ATE_unsigned_char:
	case DW_ATE_UTF:
		return drgn_int_type_create(dbinfo->prog, name, size, false,
					    byte_order, lang, ret);
	/* We don't support complex types yet. */
	case DW_ATE_complex_float:
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "DW_TAG_base_type has unknown DWARF encoding 0x%llx",
					 (unsigned long long)encoding);
	}
}

static struct drgn_error *
find_namespace_containing_die(struct drgn_debug_info *dbinfo,
			      Dwarf_Die *die, const struct drgn_language *lang,
			      struct drgn_namespace_dwarf_index **ret)
{
	struct drgn_error *err;

	struct drgn_namespace_dwarf_index *ns = &dbinfo->dwarf.global;
	if (!lang->has_namespaces) {
		*ret = ns;
		return NULL;
	}

	Dwarf_Die *ancestors;
	size_t num_ancestors;
	err = drgn_find_die_ancestors(die, &ancestors, &num_ancestors);
	if (err)
		return err;

	for (size_t i = 0; i < num_ancestors; i++) {
		switch (dwarf_tag(&ancestors[i])) {
#define X(name) case DW_TAG_##name: break;
		DRGN_DWARF_INDEX_NAMESPACE_TAGS
#undef X
		default:
			continue;
		}

		Dwarf_Attribute attr_mem, *attr;
		if (!(attr = dwarf_attr_integrate(&ancestors[i], DW_AT_name,
						  &attr_mem)))
			continue;
		const char *name = dwarf_formstring(attr);
		if (!name) {
			err = drgn_error_libdw();
			goto out;
		}

		err = drgn_namespace_find_child(ns, name, strlen(name), &ns);
		if (err)
			goto out;
	}
	*ret = ns;
out:
	free(ancestors);
	return err;
}

/*
 * DW_TAG_structure_type, DW_TAG_union_type, DW_TAG_class_type, and
 * DW_TAG_enumeration_type can be incomplete (i.e., have a DW_AT_declaration of
 * true). This tries to find the complete type. If it succeeds, it returns NULL.
 * If it can't find a complete type, it returns &drgn_not_found. Otherwise, it
 * returns an error.
 */
static struct drgn_error *
drgn_debug_info_find_complete(struct drgn_debug_info *dbinfo, int tag,
			      const char *name, Dwarf_Die *incomplete_die,
			      const struct drgn_language *lang,
			      struct drgn_type **ret)
{
	struct drgn_error *err;

	struct drgn_namespace_dwarf_index *ns;
	err = find_namespace_containing_die(dbinfo, incomplete_die, lang, &ns);
	if (err)
		return err;

	enum drgn_dwarf_index_tag dwarf_index_tag;
	switch (tag) {
#define X(name) case DW_TAG_##name: dwarf_index_tag = DRGN_DWARF_INDEX_##name; break;
	DRGN_DWARF_INDEX_TAGS
#undef X
	default:
		return NULL;
	}
	struct drgn_dwarf_index_iterator it;
	err = drgn_dwarf_index_iterator_init(&it, ns, name, strlen(name),
					     &dwarf_index_tag, 1);
	if (err)
		return err;

	/*
	 * Find a matching DIE. Note that drgn_namespace_dwarf_index does not
	 * contain DIEs with DW_AT_declaration, so this will always be a
	 * complete type.
	 */
	Dwarf_Die die;
	struct drgn_elf_file *file;
	if (!drgn_dwarf_index_iterator_next(&it, &die, &file))
		return &drgn_not_found;

	struct drgn_qualified_type qualified_type;
	err = drgn_type_from_dwarf(dbinfo, file, &die, &qualified_type);
	if (err)
		return err;
	*ret = qualified_type.type;
	return NULL;
}

struct drgn_dwarf_member_thunk_arg {
	struct drgn_elf_file *file;
	Dwarf_Die die;
	bool can_be_incomplete_array;
};

static struct drgn_error *
drgn_dwarf_member_thunk_fn(struct drgn_object *res, void *arg_)
{
	struct drgn_error *err;
	struct drgn_dwarf_member_thunk_arg *arg = arg_;
	if (res) {
		struct drgn_qualified_type qualified_type;
		err = drgn_type_from_dwarf_attr(&drgn_object_program(res)->dbinfo,
						arg->file, &arg->die, NULL,
						false,
						arg->can_be_incomplete_array,
						NULL, &qualified_type);
		if (err)
			return err;

		Dwarf_Attribute attr_mem, *attr;
		uint64_t bit_field_size;
		if ((attr = dwarf_attr_integrate(&arg->die, DW_AT_bit_size,
						 &attr_mem))) {
			Dwarf_Word bit_size;
			if (dwarf_formudata(attr, &bit_size)) {
				return drgn_error_create(DRGN_ERROR_OTHER,
							 "DW_TAG_member has invalid DW_AT_bit_size");
			}
			bit_field_size = bit_size;
		} else {
			bit_field_size = 0;
		}

		err = drgn_object_set_absent(res, qualified_type,
					     bit_field_size);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static inline bool drgn_dwarf_attribute_is_block(Dwarf_Attribute *attr)
{
	switch (attr->form) {
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_block:
		return true;
	default:
		return false;
	}
}

static inline bool drgn_dwarf_attribute_is_ptr(Dwarf_Attribute *attr)
{
	switch (attr->form) {
	case DW_FORM_sec_offset:
		return true;
	case DW_FORM_data4:
	case DW_FORM_data8: {
		/*
		 * dwarf_cu_die() always returns the DIE. We should use
		 * dwarf_cu_info(), but that requires elfutils >= 0.171.
		 */
		Dwarf_Die unused;
		Dwarf_Half cu_version;
		dwarf_cu_die(attr->cu, &unused, &cu_version, NULL, NULL, NULL,
			     NULL, NULL);
		return cu_version <= 3;
	}
	default:
		return false;
	}
}

static struct drgn_error *invalid_data_member_location(struct binary_buffer *bb,
						       const char *pos,
						       const char *message)
{
	return drgn_error_create(DRGN_ERROR_OTHER,
				 "DW_TAG_member has invalid DW_AT_data_member_location");
}

static struct drgn_error *
drgn_parse_dwarf_data_member_location(Dwarf_Attribute *attr, uint64_t *ret)
{
	struct drgn_error *err;

	if (drgn_dwarf_attribute_is_block(attr)) {
		Dwarf_Block block;
		if (dwarf_formblock(attr, &block))
			return drgn_error_libdw();
		/*
		 * In DWARF 2, DW_AT_data_member_location is always a location
		 * description. We can translate a DW_OP_plus_uconst expression
		 * into a constant offset; other expressions aren't supported
		 * yet.
		 */
		struct binary_buffer bb;
		/*
		 * Right now we only parse u8 and ULEB128, so the byte order
		 * doesn't matter.
		 */
		binary_buffer_init(&bb, block.data, block.length,
				   HOST_LITTLE_ENDIAN,
				   invalid_data_member_location);
		uint8_t opcode;
		err = binary_buffer_next_u8(&bb, &opcode);
		if (err)
			return err;
		if (opcode != DW_OP_plus_uconst) {
unsupported:
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_member has unsupported DW_AT_data_member_location");
		}
		err = binary_buffer_next_uleb128(&bb, ret);
		if (err)
			return err;
		if (binary_buffer_has_next(&bb))
			goto unsupported;
	} else if (drgn_dwarf_attribute_is_ptr(attr)) {
		goto unsupported;
	} else {

		Dwarf_Word word;
		if (dwarf_formudata(attr, &word))
			return invalid_data_member_location(NULL, NULL, NULL);
		*ret = word;
	}
	return NULL;
}

static struct drgn_error *
parse_member_offset(Dwarf_Die *die, union drgn_lazy_object *member_object,
		    bool little_endian, uint64_t *ret)
{
	struct drgn_error *err;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;

	/*
	 * The simplest case is when we have DW_AT_data_bit_offset, which is
	 * already the offset in bits from the beginning of the containing
	 * object to the beginning of the member (which may be a bit field).
	 */
	attr = dwarf_attr_integrate(die, DW_AT_data_bit_offset, &attr_mem);
	if (attr) {
		Dwarf_Word bit_offset;
		if (dwarf_formudata(attr, &bit_offset)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_member has invalid DW_AT_data_bit_offset");
		}
		*ret = bit_offset;
		return NULL;
	}

	/*
	 * Otherwise, we might have DW_AT_data_member_location, which is the
	 * offset in bytes from the beginning of the containing object.
	 */
	attr = dwarf_attr_integrate(die, DW_AT_data_member_location, &attr_mem);
	if (attr) {
		err = drgn_parse_dwarf_data_member_location(attr, ret);
		if (err)
			return err;
		*ret *= 8;
	} else {
		*ret = 0;
	}

	/*
	 * In addition to DW_AT_data_member_location, a bit field might have
	 * DW_AT_bit_offset, which is the offset in bits of the most significant
	 * bit of the bit field from the most significant bit of the containing
	 * object.
	 */
	attr = dwarf_attr_integrate(die, DW_AT_bit_offset, &attr_mem);
	if (attr) {
		Dwarf_Word bit_offset;
		if (dwarf_formudata(attr, &bit_offset)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_member has invalid DW_AT_bit_offset");
		}

		/*
		 * If the architecture is little-endian, then we must compute
		 * the location of the most significant bit from the size of the
		 * member, then subtract the bit offset and bit size to get the
		 * location of the beginning of the bit field.
		 *
		 * If the architecture is big-endian, then the most significant
		 * bit of the bit field is the beginning.
		 */
		if (little_endian) {
			err = drgn_lazy_object_evaluate(member_object);
			if (err)
				return err;

			attr = dwarf_attr_integrate(die, DW_AT_byte_size,
						    &attr_mem);
			/*
			 * If the member has an explicit byte size, we can use
			 * that. Otherwise, we have to get it from the member
			 * type.
			 */
			uint64_t byte_size;
			if (attr) {
				Dwarf_Word word;
				if (dwarf_formudata(attr, &word)) {
					return drgn_error_create(DRGN_ERROR_OTHER,
								 "DW_TAG_member has invalid DW_AT_byte_size");
				}
				byte_size = word;
			} else {
				if (!drgn_type_has_size(member_object->obj.type)) {
					return drgn_error_create(DRGN_ERROR_OTHER,
								 "DW_TAG_member bit field type does not have size");
				}
				err = drgn_type_sizeof(member_object->obj.type,
						       &byte_size);
				if (err)
					return err;
			}
			*ret += 8 * byte_size - bit_offset - member_object->obj.bit_size;
		} else {
			*ret += bit_offset;
		}
	}

	return NULL;
}

static struct drgn_error *
parse_member(struct drgn_debug_info *dbinfo, struct drgn_elf_file *file,
	     Dwarf_Die *die, bool little_endian, bool can_be_incomplete_array,
	     struct drgn_compound_type_builder *builder)
{
	struct drgn_error *err;

	Dwarf_Attribute attr_mem, *attr;
	const char *name;
	if ((attr = dwarf_attr_integrate(die, DW_AT_name, &attr_mem))) {
		name = dwarf_formstring(attr);
		if (!name) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_member has invalid DW_AT_name");
		}
	} else {
		name = NULL;
	}

	struct drgn_dwarf_member_thunk_arg *thunk_arg =
		malloc(sizeof(*thunk_arg));
	if (!thunk_arg)
		return &drgn_enomem;
	thunk_arg->file = file;
	thunk_arg->die = *die;
	thunk_arg->can_be_incomplete_array = can_be_incomplete_array;

	union drgn_lazy_object member_object;
	drgn_lazy_object_init_thunk(&member_object, dbinfo->prog,
				    drgn_dwarf_member_thunk_fn, thunk_arg);

	uint64_t bit_offset;
	err = parse_member_offset(die, &member_object, little_endian,
				  &bit_offset);
	if (err)
		goto err;

	err = drgn_compound_type_builder_add_member(builder, &member_object,
						    name, bit_offset);
	if (err)
		goto err;
	return NULL;

err:
	drgn_lazy_object_deinit(&member_object);
	return err;
}

struct drgn_dwarf_die_thunk_arg {
	struct drgn_elf_file *file;
	Dwarf_Die die;
};

static struct drgn_error *
drgn_dwarf_template_type_parameter_thunk_fn(struct drgn_object *res, void *arg_)
{
	struct drgn_error *err;
	struct drgn_dwarf_die_thunk_arg *arg = arg_;
	if (res) {
		struct drgn_qualified_type qualified_type;
		err = drgn_type_from_dwarf_attr(&drgn_object_program(res)->dbinfo,
						arg->file, &arg->die, NULL,
						true, true, NULL,
						&qualified_type);
		if (err)
			return err;

		err = drgn_object_set_absent(res, qualified_type, 0);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static struct drgn_error *
drgn_dwarf_template_value_parameter_thunk_fn(struct drgn_object *res,
					     void *arg_)
{
	struct drgn_error *err;
	struct drgn_dwarf_die_thunk_arg *arg = arg_;
	if (res) {
		err = drgn_object_from_dwarf(&drgn_object_program(res)->dbinfo,
					     arg->file, &arg->die, NULL, NULL,
					     NULL, res);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static struct drgn_error *
maybe_parse_template_parameter(struct drgn_debug_info *dbinfo,
			       struct drgn_elf_file *file, Dwarf_Die *die,
			       struct drgn_template_parameters_builder *builder)
{
	drgn_object_thunk_fn *thunk_fn;
	switch (dwarf_tag(die)) {
	case DW_TAG_template_type_parameter:
		thunk_fn = drgn_dwarf_template_type_parameter_thunk_fn;
		break;
	case DW_TAG_template_value_parameter:
		thunk_fn = drgn_dwarf_template_value_parameter_thunk_fn;
		break;
	default:
		return NULL;
	}

	char tag_buf[DW_TAG_STR_BUF_LEN];

	Dwarf_Attribute attr_mem, *attr;
	const char *name;
	if ((attr = dwarf_attr_integrate(die, DW_AT_name, &attr_mem))) {
		name = dwarf_formstring(attr);
		if (!name) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "%s has invalid DW_AT_name",
						 dwarf_tag_str(die, tag_buf));
		}
	} else {
		name = NULL;
	}

	bool defaulted;
	if (dwarf_flag_integrate(die, DW_AT_default_value, &defaulted)) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has invalid DW_AT_default_value",
					 dwarf_tag_str(die, tag_buf));
	}

	struct drgn_dwarf_die_thunk_arg *thunk_arg =
		malloc(sizeof(*thunk_arg));
	if (!thunk_arg)
		return &drgn_enomem;
	thunk_arg->file = file;
	thunk_arg->die = *die;

	union drgn_lazy_object argument;
	drgn_lazy_object_init_thunk(&argument, dbinfo->prog, thunk_fn,
				    thunk_arg);

	struct drgn_error *err =
		drgn_template_parameters_builder_add(builder, &argument, name,
						     defaulted);
	if (err)
		drgn_lazy_object_deinit(&argument);
	return err;
}

static struct drgn_error *
drgn_parse_template_parameter_pack(struct drgn_debug_info *dbinfo,
				   struct drgn_elf_file *file, Dwarf_Die *die,
				   struct drgn_template_parameters_builder *builder)
{
	struct drgn_error *err;
	Dwarf_Die child;
	int r = dwarf_child(die, &child);
	while (r == 0) {
		err = maybe_parse_template_parameter(dbinfo, file, &child, builder);
		if (err)
			return err;
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "libdw could not parse DIE children");
	}
	return NULL;
}

static struct drgn_error *
drgn_compound_type_from_dwarf(struct drgn_debug_info *dbinfo,
			      struct drgn_elf_file *file, Dwarf_Die *die,
			      const struct drgn_language *lang,
			      enum drgn_type_kind kind, struct drgn_type **ret)
{
	struct drgn_error *err;
	char tag_buf[DW_TAG_STR_BUF_LEN];

	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr = dwarf_attr_integrate(die, DW_AT_name,
						     &attr_mem);
	const char *tag;
	if (attr) {
		tag = dwarf_formstring(attr);
		if (!tag) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "%s has invalid DW_AT_name",
						 dwarf_tag_str(die, tag_buf));
		}
	} else {
		tag = NULL;
	}

	bool declaration;
	if (dwarf_flag(die, DW_AT_declaration, &declaration)) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has invalid DW_AT_declaration",
					 dwarf_tag_str(die, tag_buf));
	}
	if (declaration && tag) {
		err = drgn_debug_info_find_complete(dbinfo, dwarf_tag(die), tag,
						    die, lang, ret);
		if (err != &drgn_not_found)
			return err;
	}

	struct drgn_compound_type_builder builder;
	drgn_compound_type_builder_init(&builder, dbinfo->prog, kind);

	int size;
	bool little_endian;
	if (declaration) {
		size = 0;
	} else {
		size = dwarf_bytesize(die);
		if (size == -1) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "%s has missing or invalid DW_AT_byte_size",
						 dwarf_tag_str(die, tag_buf));
		}
		dwarf_die_is_little_endian(die, false, &little_endian);
	}

	Dwarf_Die member = {}, child;
	bool first_member = true;
	int r = dwarf_child(die, &child);
	while (r == 0) {
		switch (dwarf_tag(&child)) {
		case DW_TAG_member:
			if (!declaration) {
				if (member.addr) {
					err = parse_member(dbinfo, file,
							   &member,
							   little_endian, false,
							   &builder);
					if (err)
						goto err;
					first_member = false;
				}
				member = child;
			}
			break;
		case DW_TAG_template_type_parameter:
		case DW_TAG_template_value_parameter:
			err = maybe_parse_template_parameter(dbinfo, file, &child,
							     &builder.template_builder);
			if (err)
				goto err;
			break;
		case DW_TAG_GNU_template_parameter_pack:
			err = drgn_parse_template_parameter_pack(dbinfo, file, &child,
								 &builder.template_builder);
			if (err)
				goto err;
			break;
		default:
			break;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"libdw could not parse DIE children");
		goto err;
	}
	/*
	 * Flexible array members are only allowed as the last member of a
	 * structure with at least one other member.
	 */
	if (member.addr) {
		err = parse_member(dbinfo, file, &member, little_endian,
				   kind != DRGN_TYPE_UNION && !first_member,
				   &builder);
		if (err)
			goto err;
	}

	err = drgn_compound_type_create(&builder, tag, size, !declaration, lang,
					ret);
	if (err)
		goto err;
	return NULL;

err:
	drgn_compound_type_builder_deinit(&builder);
	return err;
}

static struct drgn_error *
parse_enumerator(Dwarf_Die *die, struct drgn_enum_type_builder *builder,
		 bool *is_signed)
{
	const char *name = dwarf_diename(die);
	if (!name) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_TAG_enumerator has missing or invalid DW_AT_name");
	}

	Dwarf_Attribute attr_mem, *attr;
	if (!(attr = dwarf_attr_integrate(die, DW_AT_const_value, &attr_mem))) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_TAG_enumerator is missing DW_AT_const_value");
	}
	struct drgn_error *err;
	if (attr->form == DW_FORM_sdata ||
	    attr->form == DW_FORM_implicit_const) {
		Dwarf_Sword svalue;
		if (dwarf_formsdata(attr, &svalue))
			goto invalid;
		err = drgn_enum_type_builder_add_signed(builder, name,
							svalue);
		/*
		 * GCC before 7.1 didn't include DW_AT_encoding for
		 * DW_TAG_enumeration_type DIEs, so we have to guess the sign
		 * for enum_compatible_type_fallback().
		 */
		if (!err && svalue < 0)
			*is_signed = true;
	} else {
		Dwarf_Word uvalue;
		if (dwarf_formudata(attr, &uvalue))
			goto invalid;
		err = drgn_enum_type_builder_add_unsigned(builder, name,
							  uvalue);
	}
	return err;

invalid:
	return drgn_error_create(DRGN_ERROR_OTHER,
				 "DW_TAG_enumerator has invalid DW_AT_const_value");
}

/*
 * GCC before 5.1 did not include DW_AT_type for DW_TAG_enumeration_type DIEs,
 * so we have to fabricate the compatible type.
 */
static struct drgn_error *
enum_compatible_type_fallback(struct drgn_debug_info *dbinfo,
			      Dwarf_Die *die, bool is_signed,
			      const struct drgn_language *lang,
			      struct drgn_type **ret)
{
	int size = dwarf_bytesize(die);
	if (size == -1) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_TAG_enumeration_type has missing or invalid DW_AT_byte_size");
	}
	enum drgn_byte_order byte_order;
	dwarf_die_byte_order(die, false, &byte_order);
	return drgn_int_type_create(dbinfo->prog, "<unknown>", size, is_signed,
				    byte_order, lang, ret);
}

static struct drgn_error *
drgn_enum_type_from_dwarf(struct drgn_debug_info *dbinfo,
			  struct drgn_elf_file *file, Dwarf_Die *die,
			  const struct drgn_language *lang,
			  struct drgn_type **ret)
{
	struct drgn_error *err;

	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr = dwarf_attr_integrate(die, DW_AT_name,
						     &attr_mem);
	const char *tag;
	if (attr) {
		tag = dwarf_formstring(attr);
		if (!tag)
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_enumeration_type has invalid DW_AT_name");
	} else {
		tag = NULL;
	}

	bool declaration;
	if (dwarf_flag(die, DW_AT_declaration, &declaration)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_TAG_enumeration_type has invalid DW_AT_declaration");
	}
	if (declaration && tag) {
		err = drgn_debug_info_find_complete(dbinfo,
						    DW_TAG_enumeration_type,
						    tag, die, lang, ret);
		if (err != &drgn_not_found)
			return err;
	}

	if (declaration) {
		return drgn_incomplete_enum_type_create(dbinfo->prog, tag, lang,
							ret);
	}

	struct drgn_enum_type_builder builder;
	drgn_enum_type_builder_init(&builder, dbinfo->prog);
	bool is_signed = false;
	Dwarf_Die child;
	int r = dwarf_child(die, &child);
	while (r == 0) {
		if (dwarf_tag(&child) == DW_TAG_enumerator) {
			err = parse_enumerator(&child, &builder, &is_signed);
			if (err)
				goto err;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"libdw could not parse DIE children");
		goto err;
	}

	struct drgn_type *compatible_type;
	r = dwarf_type(die, &child);
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"DW_TAG_enumeration_type has invalid DW_AT_type");
		goto err;
	} else if (r) {
		err = enum_compatible_type_fallback(dbinfo, die, is_signed,
						    lang, &compatible_type);
		if (err)
			goto err;
	} else {
		struct drgn_qualified_type qualified_compatible_type;
		err = drgn_type_from_dwarf(dbinfo, file, &child,
					   &qualified_compatible_type);
		if (err)
			goto err;
		compatible_type =
			drgn_underlying_type(qualified_compatible_type.type);
		if (drgn_type_kind(compatible_type) != DRGN_TYPE_INT) {
			err = drgn_error_create(DRGN_ERROR_OTHER,
						"DW_AT_type of DW_TAG_enumeration_type is not an integer type");
			goto err;
		}
	}

	err = drgn_enum_type_create(&builder, tag, compatible_type, lang, ret);
	if (err)
		goto err;
	return NULL;

err:
	drgn_enum_type_builder_deinit(&builder);
	return err;
}

static struct drgn_error *
drgn_typedef_type_from_dwarf(struct drgn_debug_info *dbinfo,
			     struct drgn_elf_file *file, Dwarf_Die *die,
			     const struct drgn_language *lang,
			     bool can_be_incomplete_array,
			     bool *is_incomplete_array_ret,
			     struct drgn_type **ret)
{
	const char *name = dwarf_diename(die);
	if (!name) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DW_TAG_typedef has missing or invalid DW_AT_name");
	}

	struct drgn_qualified_type aliased_type;
	struct drgn_error *err = drgn_type_from_dwarf_attr(dbinfo, file, die,
							   lang, true,
							   can_be_incomplete_array,
							   is_incomplete_array_ret,
							   &aliased_type);
	if (err)
		return err;

	return drgn_typedef_type_create(dbinfo->prog, name, aliased_type, lang,
					ret);
}

static struct drgn_error *
drgn_pointer_type_from_dwarf(struct drgn_debug_info *dbinfo,
			     struct drgn_elf_file *file, Dwarf_Die *die,
			     const struct drgn_language *lang,
			     struct drgn_type **ret)
{
	struct drgn_qualified_type referenced_type;
	struct drgn_error *err = drgn_type_from_dwarf_attr(dbinfo, file, die,
							   lang, true, true,
							   NULL,
							   &referenced_type);
	if (err)
		return err;

	Dwarf_Attribute attr_mem, *attr;
	uint64_t size;
	if ((attr = dwarf_attr_integrate(die, DW_AT_byte_size, &attr_mem))) {
		Dwarf_Word word;
		if (dwarf_formudata(attr, &word)) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "DW_TAG_pointer_type has invalid DW_AT_byte_size");
		}
		size = word;
	} else {
		// dwarf_diecu() always returns the DIE. We should use
		// dwarf_cu_info(), but that requires elfutils >= 0.171.
		Dwarf_Die unused;
		uint8_t address_size;
		dwarf_diecu(die, &unused, &address_size, NULL);
		size = address_size;
	}

	/*
	 * The DWARF 5 specification doesn't mention DW_AT_endianity for
	 * DW_TAG_pointer_type DIEs, and GCC as of version 10.2 doesn't emit it
	 * even for pointers stored in the opposite byte order (e.g., when using
	 * scalar_storage_order), but it probably should.
	 */
	enum drgn_byte_order byte_order;
	dwarf_die_byte_order(die, false, &byte_order);
	return drgn_pointer_type_create(dbinfo->prog, referenced_type, size,
					byte_order, lang, ret);
}

struct array_dimension {
	uint64_t length;
	bool is_complete;
};

DEFINE_VECTOR(array_dimension_vector, struct array_dimension);

static struct drgn_error *subrange_length(Dwarf_Die *die,
					  struct array_dimension *dimension)
{
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	Dwarf_Word word;

	if (!(attr = dwarf_attr_integrate(die, DW_AT_upper_bound, &attr_mem)) &&
	    !(attr = dwarf_attr_integrate(die, DW_AT_count, &attr_mem))) {
		dimension->is_complete = false;
		return NULL;
	}

	if (dwarf_formudata(attr, &word)) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "DW_TAG_subrange_type has invalid %s",
					 attr->code == DW_AT_upper_bound ?
					 "DW_AT_upper_bound" :
					 "DW_AT_count");
	}

	dimension->is_complete = true;
	/*
	 * GCC emits a DW_FORM_sdata or DW_FORM_data8 DW_AT_upper_bound of -1
	 * for empty array variables without an explicit size
	 * (e.g., `int arr[] = {};`).
	 */
	if (attr->code == DW_AT_upper_bound && word == (Dwarf_Word)-1) {
		dimension->length = 0;
	} else if (attr->code == DW_AT_upper_bound) {
		if (word >= UINT64_MAX) {
			return drgn_error_create(DRGN_ERROR_OVERFLOW,
						 "DW_AT_upper_bound is too large");
		}
		dimension->length = (uint64_t)word + 1;
	} else {
		if (word > UINT64_MAX) {
			return drgn_error_create(DRGN_ERROR_OVERFLOW,
						 "DW_AT_count is too large");
		}
		dimension->length = word;
	}
	return NULL;
}

static struct drgn_error *
drgn_array_type_from_dwarf(struct drgn_debug_info *dbinfo,
			   struct drgn_elf_file *file, Dwarf_Die *die,
			   const struct drgn_language *lang,
			   bool can_be_incomplete_array,
			   bool *is_incomplete_array_ret,
			   struct drgn_type **ret)
{
	struct drgn_error *err;
	_cleanup_(array_dimension_vector_deinit)
		struct array_dimension_vector dimensions = VECTOR_INIT;
	struct array_dimension *dimension;
	Dwarf_Die child;
	int r = dwarf_child(die, &child);
	while (r == 0) {
		if (dwarf_tag(&child) == DW_TAG_subrange_type) {
			dimension = array_dimension_vector_append_entry(&dimensions);
			if (!dimension)
				return &drgn_enomem;
			err = subrange_length(&child, dimension);
			if (err)
				return err;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "libdw could not parse DIE children");
	}
	if (array_dimension_vector_empty(&dimensions)) {
		dimension = array_dimension_vector_append_entry(&dimensions);
		if (!dimension)
			return &drgn_enomem;
		dimension->is_complete = false;
	}

	struct drgn_qualified_type element_type;
	err = drgn_type_from_dwarf_attr(dbinfo, file, die, lang, false, false,
					NULL, &element_type);
	if (err)
		return err;

	*is_incomplete_array_ret =
		!array_dimension_vector_first(&dimensions)->is_complete;
	struct drgn_type *type;
	do {
		dimension = array_dimension_vector_pop(&dimensions);
		if (dimension->is_complete) {
			err = drgn_array_type_create(dbinfo->prog, element_type,
						     dimension->length, lang,
						     &type);
		} else if (!array_dimension_vector_empty(&dimensions)
			   || !can_be_incomplete_array) {
			err = drgn_array_type_create(dbinfo->prog, element_type,
						     0, lang, &type);
		} else {
			err = drgn_incomplete_array_type_create(dbinfo->prog,
								element_type,
								lang, &type);
		}
		if (err)
			return err;

		element_type.type = type;
		element_type.qualifiers = 0;
	} while (!array_dimension_vector_empty(&dimensions));

	*ret = type;
	return NULL;
}

static struct drgn_error *
drgn_dwarf_formal_parameter_thunk_fn(struct drgn_object *res, void *arg_)
{
	struct drgn_error *err;
	struct drgn_dwarf_die_thunk_arg *arg = arg_;
	if (res) {
		struct drgn_qualified_type qualified_type;
		err = drgn_type_from_dwarf_attr(&drgn_object_program(res)->dbinfo,
						arg->file, &arg->die, NULL,
						false, true, NULL,
						&qualified_type);
		if (err)
			return err;

		err = drgn_object_set_absent(res, qualified_type, 0);
		if (err)
			return err;
	}
	free(arg);
	return NULL;
}

static struct drgn_error *
parse_formal_parameter(struct drgn_debug_info *dbinfo,
		       struct drgn_elf_file *file, Dwarf_Die *die,
		       struct drgn_function_type_builder *builder)
{
	Dwarf_Attribute attr_mem, *attr;
	const char *name;
	if ((attr = dwarf_attr_integrate(die, DW_AT_name, &attr_mem))) {
		name = dwarf_formstring(attr);
		if (!name) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_formal_parameter has invalid DW_AT_name");
		}
	} else {
		name = NULL;
	}

	struct drgn_dwarf_die_thunk_arg *thunk_arg =
		malloc(sizeof(*thunk_arg));
	if (!thunk_arg)
		return &drgn_enomem;
	thunk_arg->file = file;
	thunk_arg->die = *die;

	union drgn_lazy_object default_argument;
	drgn_lazy_object_init_thunk(&default_argument, dbinfo->prog,
				    drgn_dwarf_formal_parameter_thunk_fn,
				    thunk_arg);

	struct drgn_error *err =
		drgn_function_type_builder_add_parameter(builder,
							 &default_argument,
							 name);
	if (err)
		drgn_lazy_object_deinit(&default_argument);
	return err;
}

static struct drgn_error *
drgn_function_type_from_dwarf(struct drgn_debug_info *dbinfo,
			      struct drgn_elf_file *file, Dwarf_Die *die,
			      const struct drgn_language *lang,
			      struct drgn_type **ret)
{
	struct drgn_error *err;
	char tag_buf[DW_TAG_STR_BUF_LEN];

	struct drgn_function_type_builder builder;
	drgn_function_type_builder_init(&builder, dbinfo->prog);
	bool is_variadic = false;
	Dwarf_Die child;
	int r = dwarf_child(die, &child);
	while (r == 0) {
		switch (dwarf_tag(&child)) {
		case DW_TAG_formal_parameter:
			if (is_variadic) {
				err = drgn_error_format(DRGN_ERROR_OTHER,
							"%s has DW_TAG_formal_parameter child after DW_TAG_unspecified_parameters child",
							dwarf_tag_str(die,
								      tag_buf));
				goto err;
			}
			err = parse_formal_parameter(dbinfo, file, &child,
						     &builder);
			if (err)
				goto err;
			break;
		case DW_TAG_unspecified_parameters:
			if (is_variadic) {
				err = drgn_error_format(DRGN_ERROR_OTHER,
							"%s has multiple DW_TAG_unspecified_parameters children",
							dwarf_tag_str(die,
								      tag_buf));
				goto err;
			}
			is_variadic = true;
			break;
		case DW_TAG_template_type_parameter:
		case DW_TAG_template_value_parameter:
			err = maybe_parse_template_parameter(dbinfo, file, &child,
							     &builder.template_builder);
			if (err)
				goto err;
			break;
		case DW_TAG_GNU_template_parameter_pack:
			err = drgn_parse_template_parameter_pack(dbinfo, file, &child,
								 &builder.template_builder);
			if (err)
				goto err;
			break;
		default:
			break;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"libdw could not parse DIE children");
		goto err;
	}

	struct drgn_qualified_type return_type;
	err = drgn_type_from_dwarf_attr(dbinfo, file, die, lang, true, true,
					NULL, &return_type);
	if (err)
		goto err;

	err = drgn_function_type_create(&builder, return_type, is_variadic,
					lang, ret);
	if (err)
		goto err;
	return NULL;

err:
	drgn_function_type_builder_deinit(&builder);
	return err;
}

static struct drgn_error *
drgn_type_from_dwarf_internal(struct drgn_debug_info *dbinfo,
			      struct drgn_elf_file *file, Dwarf_Die *die,
			      bool can_be_incomplete_array,
			      bool *is_incomplete_array_ret,
			      struct drgn_qualified_type *ret)
{
	if (dbinfo->dwarf.depth >= 1000) {
		return drgn_error_create(DRGN_ERROR_RECURSION,
					 "maximum DWARF type parsing depth exceeded");
	}

	/* If the DIE has a type unit signature, follow it. */
	Dwarf_Die definition_die;
	{
		Dwarf_Attribute attr_mem, *attr;
		if ((attr = dwarf_attr_integrate(die, DW_AT_signature,
						 &attr_mem))) {
			if (!dwarf_formref_die(attr, &definition_die))
				return drgn_error_libdw();
			die = &definition_die;
		}
	}

	/* If we got a declaration, try to find the definition. */
	bool declaration;
	if (dwarf_flag(die, DW_AT_declaration, &declaration))
		return drgn_error_libdw();
	if (declaration) {
		uintptr_t die_addr;
		if (drgn_dwarf_find_definition(dbinfo, (uintptr_t)die->addr,
					       &die_addr)) {
			struct drgn_dwarf_index_cu *cu =
				drgn_dwarf_index_find_cu(dbinfo, die_addr);
			definition_die = (Dwarf_Die){
				.addr = (void *)die_addr,
				.cu = cu->libdw_cu,
			};
			die = &definition_die;
			file = cu->file;
		}
	}

	struct drgn_dwarf_type_map_entry entry = {
		.key = die->addr,
	};
	struct hash_pair hp = drgn_dwarf_type_map_hash(&entry.key);
	struct drgn_dwarf_type_map_iterator it =
		drgn_dwarf_type_map_search_hashed(&dbinfo->dwarf.types,
						  &entry.key, hp);
	if (it.entry) {
		if (!can_be_incomplete_array &&
		    it.entry->value.is_incomplete_array) {
			it = drgn_dwarf_type_map_search_hashed(&dbinfo->dwarf.cant_be_incomplete_array_types,
							       &entry.key, hp);
		}
		if (it.entry) {
			ret->type = it.entry->value.type;
			ret->qualifiers = it.entry->value.qualifiers;
			return NULL;
		}
	}

	const struct drgn_language *lang;
	struct drgn_error *err = drgn_language_from_die(die, true, &lang);
	if (err)
		return err;

	ret->qualifiers = 0;
	dbinfo->dwarf.depth++;
	entry.value.is_incomplete_array = false;
	switch (dwarf_tag(die)) {
	case DW_TAG_const_type:
		err = drgn_type_from_dwarf_attr(dbinfo, file, die, lang, true,
						can_be_incomplete_array,
						&entry.value.is_incomplete_array,
						ret);
		ret->qualifiers |= DRGN_QUALIFIER_CONST;
		break;
	case DW_TAG_restrict_type:
		err = drgn_type_from_dwarf_attr(dbinfo, file, die, lang, true,
						can_be_incomplete_array,
						&entry.value.is_incomplete_array,
						ret);
		ret->qualifiers |= DRGN_QUALIFIER_RESTRICT;
		break;
	case DW_TAG_volatile_type:
		err = drgn_type_from_dwarf_attr(dbinfo, file, die, lang, true,
						can_be_incomplete_array,
						&entry.value.is_incomplete_array,
						ret);
		ret->qualifiers |= DRGN_QUALIFIER_VOLATILE;
		break;
	case DW_TAG_atomic_type:
		err = drgn_type_from_dwarf_attr(dbinfo, file, die, lang, true,
						can_be_incomplete_array,
						&entry.value.is_incomplete_array,
						ret);
		ret->qualifiers |= DRGN_QUALIFIER_ATOMIC;
		break;
	case DW_TAG_base_type:
		err = drgn_base_type_from_dwarf(dbinfo, file, die, lang,
						&ret->type);
		break;
	case DW_TAG_structure_type:
		err = drgn_compound_type_from_dwarf(dbinfo, file, die, lang,
						    DRGN_TYPE_STRUCT,
						    &ret->type);
		break;
	case DW_TAG_union_type:
		err = drgn_compound_type_from_dwarf(dbinfo, file, die, lang,
						    DRGN_TYPE_UNION,
						    &ret->type);
		break;
	case DW_TAG_class_type:
		err = drgn_compound_type_from_dwarf(dbinfo, file, die, lang,
						    DRGN_TYPE_CLASS,
						    &ret->type);
		break;
	case DW_TAG_enumeration_type:
		err = drgn_enum_type_from_dwarf(dbinfo, file, die, lang,
						&ret->type);
		break;
	case DW_TAG_typedef:
		err = drgn_typedef_type_from_dwarf(dbinfo, file, die, lang,
						   can_be_incomplete_array,
						   &entry.value.is_incomplete_array,
						   &ret->type);
		break;
	case DW_TAG_pointer_type:
		err = drgn_pointer_type_from_dwarf(dbinfo, file, die, lang,
						   &ret->type);
		break;
	case DW_TAG_array_type:
		err = drgn_array_type_from_dwarf(dbinfo, file, die, lang,
						 can_be_incomplete_array,
						 &entry.value.is_incomplete_array,
						 &ret->type);
		break;
	case DW_TAG_subroutine_type:
	case DW_TAG_subprogram:
		err = drgn_function_type_from_dwarf(dbinfo, file, die, lang,
						    &ret->type);
		break;
	default:
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"unknown DWARF type tag 0x%x",
					dwarf_tag(die));
		break;
	}
	dbinfo->dwarf.depth--;
	if (err)
		return err;

	entry.value.type = ret->type;
	entry.value.qualifiers = ret->qualifiers;
	struct drgn_dwarf_type_map *map;
	if (!can_be_incomplete_array && entry.value.is_incomplete_array)
		map = &dbinfo->dwarf.cant_be_incomplete_array_types;
	else
		map = &dbinfo->dwarf.types;
	if (drgn_dwarf_type_map_insert_searched(map, &entry, hp, NULL) == -1) {
		/*
		 * This will "leak" the type we created, but it'll still be
		 * cleaned up when the program is freed.
		 */
		return &drgn_enomem;
	}
	if (is_incomplete_array_ret)
		*is_incomplete_array_ret = entry.value.is_incomplete_array;
	return NULL;
}

static struct drgn_error *
find_enclosing_namespace(struct drgn_namespace_dwarf_index *global_namespace,
			 const char **name, size_t *name_len,
			 struct drgn_namespace_dwarf_index **namespace_ret)
{
	struct drgn_error *err;

	*namespace_ret = global_namespace;
	if (*name_len >= 2 && memcmp(*name, "::", 2) == 0) {
		/* Explicit global namespace. */
		*name_len -= 2;
		*name += 2;
	}

	const char *template_parameters_start = memchr(*name, '<', *name_len);
	ptrdiff_t searchable_len =
		template_parameters_start ?
				  template_parameters_start - *name:
				  *name_len;
	const char *colons;
	while ((colons = memmem(*name, searchable_len, "::", 2))) {
		err = drgn_namespace_find_child(*namespace_ret, *name,
						colons - *name, namespace_ret);
		if (err)
			return err;

		size_t chars_consumed = colons + 2 - *name;
		searchable_len -= chars_consumed;
		*name_len -= chars_consumed;
		*name = colons + 2;
	}

	return NULL;
}

struct drgn_error *drgn_debug_info_find_type(uint64_t kinds, const char *name,
					     size_t name_len,
					     const char *filename, void *arg,
					     struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	struct drgn_debug_info *dbinfo = arg;

	enum drgn_dwarf_index_tag tags[6];
	size_t num_tags = 0;
	if (kinds & ((1 << DRGN_TYPE_INT)
		     | (1 << DRGN_TYPE_BOOL)
		     | (1 << DRGN_TYPE_FLOAT)))
		tags[num_tags++] = DRGN_DWARF_INDEX_base_type;
	if (kinds & (1 << DRGN_TYPE_STRUCT))
		tags[num_tags++] = DRGN_DWARF_INDEX_structure_type;
	if (kinds & (1 << DRGN_TYPE_UNION))
		tags[num_tags++] = DRGN_DWARF_INDEX_union_type;
	if (kinds & (1 << DRGN_TYPE_CLASS))
		tags[num_tags++] = DRGN_DWARF_INDEX_class_type;
	if (kinds & (1 << DRGN_TYPE_ENUM))
		tags[num_tags++] = DRGN_DWARF_INDEX_enumeration_type;
	if (kinds & (1 << DRGN_TYPE_TYPEDEF))
		tags[num_tags++] = DRGN_DWARF_INDEX_typedef;

	struct drgn_namespace_dwarf_index *namespace;
	err = find_enclosing_namespace(&dbinfo->dwarf.global,
				       &name, &name_len, &namespace);
	if (err)
		return err;
	struct drgn_dwarf_index_iterator it;
	err = drgn_dwarf_index_iterator_init(&it, namespace, name, name_len,
					     tags, num_tags);
	if (err)
		return err;
	Dwarf_Die die;
	struct drgn_elf_file *file;
	while (drgn_dwarf_index_iterator_next(&it, &die, &file)) {
		if (die_matches_filename(&die, filename)) {
			err = drgn_type_from_dwarf(dbinfo, file, &die, ret);
			if (err)
				return err;
			/*
			 * For base_type, we need to check that the type we
			 * found was the right kind.
			 */
			if (kinds & (UINT64_C(1) << drgn_type_kind(ret->type)))
				return NULL;
		}
	}
	return &drgn_not_found;
}

struct drgn_error *
drgn_debug_info_find_object(const char *name, size_t name_len,
			    const char *filename,
			    enum drgn_find_object_flags flags, void *arg,
			    struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_debug_info *dbinfo = arg;

	struct drgn_namespace_dwarf_index *ns;
	err = find_enclosing_namespace(&dbinfo->dwarf.global,
				       &name, &name_len, &ns);
	if (err)
		return err;

	enum drgn_dwarf_index_tag tags[3];
	size_t num_tags = 0;
	if (flags & DRGN_FIND_OBJECT_CONSTANT)
		tags[num_tags++] = DRGN_DWARF_INDEX_enumerator;
	if (flags & DRGN_FIND_OBJECT_FUNCTION)
		tags[num_tags++] = DRGN_DWARF_INDEX_subprogram;
	if (flags & DRGN_FIND_OBJECT_VARIABLE)
		tags[num_tags++] = DRGN_DWARF_INDEX_variable;

	struct drgn_dwarf_index_iterator it;
	err = drgn_dwarf_index_iterator_init(&it, ns, name, name_len, tags,
					     num_tags);
	if (err)
		return err;
	Dwarf_Die die;
	struct drgn_elf_file *file;
	while (drgn_dwarf_index_iterator_next(&it, &die, &file)) {
		if (!die_matches_filename(&die, filename))
			continue;
		if (dwarf_tag(&die) == DW_TAG_enumeration_type) {
			return drgn_object_from_dwarf_enumerator(dbinfo, file,
								 &die, name,
								 ret);
		} else {
			return drgn_object_from_dwarf(dbinfo, file, &die, NULL,
						      NULL, NULL, ret);
		}
	}
	return &drgn_not_found;
}

/*
 * Call frame information.
 */

struct drgn_dwarf_cie {
	/* Size of an address in this CIE in bytes. */
	uint8_t address_size;
	/* DW_EH_PE_* encoding of addresses in this CIE. */
	uint8_t address_encoding;
	/* Whether this CIE has a 'z' augmentation. */
	bool have_augmentation_length;
	/* Whether this CIE is for a signal handler ('S' augmentation). */
	bool signal_frame;
	drgn_register_number return_address_register;
	uint64_t code_alignment_factor;
	int64_t data_alignment_factor;
	const char *initial_instructions;
	size_t initial_instructions_size;
};

DEFINE_VECTOR(drgn_dwarf_fde_vector, struct drgn_dwarf_fde);
DEFINE_VECTOR(drgn_dwarf_cie_vector, struct drgn_dwarf_cie);
DEFINE_HASH_MAP(drgn_dwarf_cie_map, size_t, size_t, int_key_hash_pair,
		scalar_key_eq);

static struct drgn_error *
drgn_dwarf_cfi_next_encoded(struct drgn_elf_file_section_buffer *buffer,
			    uint8_t address_size, uint8_t encoding,
			    uint64_t func_addr, uint64_t *ret)
{
	struct drgn_error *err;

	/* Not currently used for CFI. */
	if (encoding & DW_EH_PE_indirect) {
unknown_fde_encoding:
		return binary_buffer_error(&buffer->bb,
					   "unknown EH encoding %#" PRIx8,
					   encoding);
	}

	size_t pos = buffer->bb.pos - (char *)buffer->data->d_buf;
	uint64_t base;
	switch (encoding & 0x70) {
	case DW_EH_PE_absptr:
		base = 0;
		break;
	case DW_EH_PE_pcrel:
		base = buffer->file->module->dwarf.pcrel_base + pos;
		break;
	case DW_EH_PE_textrel:
		base = buffer->file->module->dwarf.textrel_base;
		break;
	case DW_EH_PE_datarel:
		base = buffer->file->module->dwarf.datarel_base;
		break;
	case DW_EH_PE_funcrel:
		/* Relative to the FDE's initial location. */
		base = func_addr;
		break;
	case DW_EH_PE_aligned:
		base = 0;
		if (pos % address_size != 0 &&
		    (err = binary_buffer_skip(&buffer->bb,
					      address_size - pos % address_size)))
			return err;
		break;
	default:
		goto unknown_fde_encoding;
	}

	uint64_t offset;
	switch (encoding & 0xf) {
	case DW_EH_PE_absptr:
		if ((err = binary_buffer_next_uint(&buffer->bb, address_size,
						   &offset)))
			return err;
		break;
	case DW_EH_PE_uleb128:
		if ((err = binary_buffer_next_uleb128(&buffer->bb, &offset)))
			return err;
		break;
	case DW_EH_PE_udata2:
		if ((err = binary_buffer_next_u16_into_u64(&buffer->bb,
							   &offset)))
			return err;
		break;
	case DW_EH_PE_udata4:
		if ((err = binary_buffer_next_u32_into_u64(&buffer->bb,
							   &offset)))
			return err;
		break;
	case DW_EH_PE_udata8:
		if ((err = binary_buffer_next_u64(&buffer->bb, &offset)))
			return err;
		break;
	case DW_EH_PE_sleb128:
		if ((err = binary_buffer_next_sleb128_into_u64(&buffer->bb,
							       &offset)))
			return err;
		break;
	case DW_EH_PE_sdata2:
		if ((err = binary_buffer_next_s16_into_u64(&buffer->bb,
							   &offset)))
			return err;
		break;
	case DW_EH_PE_sdata4:
		if ((err = binary_buffer_next_s32_into_u64(&buffer->bb,
							   &offset)))
			return err;
		break;
	case DW_EH_PE_sdata8:
		if ((err = binary_buffer_next_s64_into_u64(&buffer->bb,
							   &offset)))
			return err;
		break;
	default:
		goto unknown_fde_encoding;
	}
	*ret = (base + offset) & uint_max(address_size);

	return NULL;
}

static struct drgn_error *drgn_parse_dwarf_cie(struct drgn_elf_file *file,
					       enum drgn_section_index scn,
					       size_t cie_pointer,
					       struct drgn_dwarf_cie *cie)
{
	bool is_eh = scn == DRGN_SCN_EH_FRAME;
	struct drgn_error *err;

	struct drgn_elf_file_section_buffer buffer;
	drgn_elf_file_section_buffer_init_index(&buffer, file, scn);
	buffer.bb.pos += cie_pointer;

	uint32_t tmp;
	if ((err = binary_buffer_next_u32(&buffer.bb, &tmp)))
		return err;
	bool is_64_bit = tmp == UINT32_C(0xffffffff);
	uint64_t length;
	if (is_64_bit) {
		if ((err = binary_buffer_next_u64(&buffer.bb, &length)))
			return err;
	} else {
		length = tmp;
	}
	if (length > buffer.bb.end - buffer.bb.pos) {
		return binary_buffer_error(&buffer.bb,
					   "entry length is out of bounds");
	}
	buffer.bb.end = buffer.bb.pos + length;

	uint64_t cie_id, expected_cie_id;
	if (is_64_bit) {
		if ((err = binary_buffer_next_u64(&buffer.bb, &cie_id)))
			return err;
		expected_cie_id = is_eh ? 0 : UINT64_C(0xffffffffffffffff);
	} else {
		if ((err = binary_buffer_next_u32_into_u64(&buffer.bb,
							   &cie_id)))
			return err;
		expected_cie_id = is_eh ? 0 : UINT64_C(0xffffffff);
	}
	if (cie_id != expected_cie_id)
		return binary_buffer_error(&buffer.bb, "invalid CIE ID");

	uint8_t version;
	if ((err = binary_buffer_next_u8(&buffer.bb, &version)))
		return err;
	if (version < 1 || version == 2 || version > 4) {
		return binary_buffer_error(&buffer.bb,
					   "unknown CIE version %" PRIu8,
					   version);
	}

	const char *augmentation;
	size_t augmentation_len;
	if ((err = binary_buffer_next_string(&buffer.bb, &augmentation,
					     &augmentation_len)))
		return err;
	cie->have_augmentation_length = augmentation[0] == 'z';
	cie->signal_frame = false;
	for (size_t i = 0; i < augmentation_len; i++) {
		switch (augmentation[i]) {
		case 'z':
			if (i != 0)
				goto unknown_augmentation;
			break;
		case 'L':
		case 'P':
		case 'R':
			if (augmentation[0] != 'z' || !is_eh)
				goto unknown_augmentation;
			break;
		case 'S':
			cie->signal_frame = true;
			break;
		default:
unknown_augmentation:
			/*
			 * We could ignore this CIE and all FDEs that reference
			 * it or skip the augmentation if we have its length,
			 * but let's fail loudly so that we find out about
			 * missing support.
			 */
			return binary_buffer_error_at(&buffer.bb,
						      &augmentation[i],
						      "unknown CFI augmentation %s",
						      augmentation);
		}
	}

	if (version >= 4) {
		if ((err = binary_buffer_next_u8(&buffer.bb,
						 &cie->address_size)))
			return err;
		if (cie->address_size < 1 || cie->address_size > 8) {
			return binary_buffer_error(&buffer.bb,
						   "unsupported address size %" PRIu8,
						   cie->address_size);
		}
		uint8_t segment_selector_size;
		if ((err = binary_buffer_next_u8(&buffer.bb,
						 &segment_selector_size)))
			return err;
		if (segment_selector_size) {
			return binary_buffer_error(&buffer.bb,
						   "unsupported segment selector size %" PRIu8,
						   segment_selector_size);
		}
	} else {
		cie->address_size = drgn_elf_file_address_size(file);
	}
	if ((err = binary_buffer_next_uleb128(&buffer.bb,
					      &cie->code_alignment_factor)) ||
	    (err = binary_buffer_next_sleb128(&buffer.bb,
					      &cie->data_alignment_factor)))
		return err;
	uint64_t return_address_register;
	if (version >= 3) {
		if ((err = binary_buffer_next_uleb128(&buffer.bb,
						      &return_address_register)))
			return err;
	} else {
		if ((err = binary_buffer_next_u8_into_u64(&buffer.bb,
							  &return_address_register)))
			return err;
	}
	cie->return_address_register =
		file->platform.arch->dwarf_regno_to_internal(return_address_register);
	if (cie->return_address_register == DRGN_REGISTER_NUMBER_UNKNOWN) {
		return binary_buffer_error(&buffer.bb,
					   "unknown return address register");
	}
	cie->address_encoding = DW_EH_PE_absptr;
	if (augmentation[0] == 'z') {
		for (size_t i = 0; i < augmentation_len; i++) {
			switch (augmentation[i]) {
			case 'z':
				if ((err = binary_buffer_skip_leb128(&buffer.bb)))
					return err;
				break;
			case 'L':
				if ((err = binary_buffer_skip(&buffer.bb, 1)))
					return err;
				break;
			case 'P': {
				uint8_t encoding;
				if ((err = binary_buffer_next_u8(&buffer.bb, &encoding)))
					return err;
				/*
				 * We don't need the result, so don't bother
				 * dereferencing.
				 */
				encoding &= ~DW_EH_PE_indirect;
				uint64_t unused;
				if ((err = drgn_dwarf_cfi_next_encoded(&buffer,
								       cie->address_size,
								       encoding,
								       0,
								       &unused)))
					return err;
				break;
			}
			case 'R':
				if ((err = binary_buffer_next_u8(&buffer.bb,
								 &cie->address_encoding)))
					return err;
				break;
			}
		}
	}
	cie->initial_instructions = buffer.bb.pos;
	cie->initial_instructions_size = buffer.bb.end - buffer.bb.pos;
	return NULL;
}

static void drgn_debug_info_cache_sh_addr(struct drgn_elf_file *file,
					  enum drgn_section_index scn,
					  uint64_t *addr)
{
	if (file->scns[scn]) {
		GElf_Shdr shdr_mem;
		GElf_Shdr *shdr = gelf_getshdr(file->scns[scn], &shdr_mem);
		if (shdr)
			*addr = shdr->sh_addr;
	}
}

static int drgn_dwarf_fde_compar(const void *_a, const void *_b)
{
	const struct drgn_dwarf_fde *a = _a;
	const struct drgn_dwarf_fde *b = _b;
	if (a->initial_location < b->initial_location)
		return -1;
	else if (a->initial_location > b->initial_location)
		return 1;
	else
		return 0;
}

static struct drgn_error *drgn_parse_dwarf_cfi(struct drgn_dwarf_cfi *cfi,
					       struct drgn_elf_file *file,
					       enum drgn_section_index scn)
{
	const bool is_eh = scn == DRGN_SCN_EH_FRAME;
	struct drgn_error *err;

	if (!file->scns[scn])
		return NULL;

	if (is_eh) {
		drgn_debug_info_cache_sh_addr(file, DRGN_SCN_EH_FRAME,
					      &file->module->dwarf.pcrel_base);
		drgn_debug_info_cache_sh_addr(file, DRGN_SCN_TEXT,
					      &file->module->dwarf.textrel_base);
		drgn_debug_info_cache_sh_addr(file, DRGN_SCN_GOT,
					      &file->module->dwarf.datarel_base);
	}

	err = drgn_elf_file_cache_section(file, scn);
	if (err)
		return err;

	_cleanup_(drgn_dwarf_cie_vector_deinit)
		struct drgn_dwarf_cie_vector cies = VECTOR_INIT;
	_cleanup_(drgn_dwarf_fde_vector_deinit)
		struct drgn_dwarf_fde_vector fdes = VECTOR_INIT;
	_cleanup_(drgn_dwarf_cie_map_deinit)
		struct drgn_dwarf_cie_map cie_map = HASH_TABLE_INIT;

	Elf_Data *data = file->scn_data[scn];
	struct drgn_elf_file_section_buffer buffer;
	drgn_elf_file_section_buffer_init_index(&buffer, file, scn);
	while (binary_buffer_has_next(&buffer.bb)) {
		uint32_t tmp;
		if ((err = binary_buffer_next_u32(&buffer.bb, &tmp)))
			return err;
		bool is_64_bit = tmp == UINT32_C(0xffffffff);
		uint64_t length;
		if (is_64_bit) {
			if ((err = binary_buffer_next_u64(&buffer.bb, &length)))
				return err;
		} else {
			length = tmp;
		}
		/*
		 * Technically, a length of zero is only a terminator in
		 * .eh_frame, but other consumers (binutils, elfutils, GDB)
		 * handle it the same way in .debug_frame.
		 */
		if (length == 0)
			break;
		if (length > buffer.bb.end - buffer.bb.pos) {
			return binary_buffer_error(&buffer.bb,
						   "entry length is out of bounds");
		}
		buffer.bb.end = buffer.bb.pos + length;

		/*
		 * The Linux Standard Base Core Specification [1] states that
		 * the CIE ID in .eh_frame is always 4 bytes. However, other
		 * consumers handle it the same as in .debug_frame (8 bytes for
		 * the 64-bit format).
		 *
		 * 1: https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
		 */
		uint64_t cie_pointer, cie_id;
		if (is_64_bit) {
			if ((err = binary_buffer_next_u64(&buffer.bb,
							  &cie_pointer)))
				return err;
			cie_id = is_eh ? 0 : UINT64_C(0xffffffffffffffff);
		} else {
			if ((err = binary_buffer_next_u32_into_u64(&buffer.bb,
								   &cie_pointer)))
				return err;
			cie_id = is_eh ? 0 : UINT64_C(0xffffffff);
		}

		if (cie_pointer != cie_id) {
			if (is_eh) {
				size_t pointer_offset =
					(buffer.bb.pos
					 - (is_64_bit ? 8 : 4)
					 - (char *)data->d_buf);
				if (cie_pointer > pointer_offset) {
					return binary_buffer_error(&buffer.bb,
								   "CIE pointer is out of bounds");
				}
				cie_pointer = pointer_offset - cie_pointer;
			} else if (cie_pointer > data->d_size) {
				return binary_buffer_error(&buffer.bb,
							   "CIE pointer is out of bounds");
			}
			struct drgn_dwarf_fde *fde =
				drgn_dwarf_fde_vector_append_entry(&fdes);
			if (!fde)
				return &drgn_enomem;
			struct drgn_dwarf_cie_map_entry entry = {
				.key = cie_pointer,
				.value = drgn_dwarf_cie_vector_size(&cies),
			};
			struct drgn_dwarf_cie_map_iterator it;
			int r = drgn_dwarf_cie_map_insert(&cie_map, &entry,
							  &it);
			struct drgn_dwarf_cie *cie;
			if (r > 0) {
				cie = drgn_dwarf_cie_vector_append_entry(&cies);
				if (!cie)
					return &drgn_enomem;
				err = drgn_parse_dwarf_cie(file, scn,
							   cie_pointer, cie);
				if (err)
					return err;
			} else if (r == 0) {
				cie = drgn_dwarf_cie_vector_at(&cies,
							       it.entry->value);
			} else {
				return &drgn_enomem;
			}
			if ((err = drgn_dwarf_cfi_next_encoded(&buffer,
							       cie->address_size,
							       cie->address_encoding,
							       0,
							       &fde->initial_location)) ||
			    (err = drgn_dwarf_cfi_next_encoded(&buffer,
							       cie->address_size,
							       cie->address_encoding & 0xf,
							       0,
							       &fde->address_range)))
				return err;
			if (cie->have_augmentation_length) {
				uint64_t augmentation_length;
				if ((err = binary_buffer_next_uleb128(&buffer.bb,
								      &augmentation_length)))
					return err;
				if (augmentation_length >
				    buffer.bb.end - buffer.bb.pos) {
					return binary_buffer_error(&buffer.bb,
								   "augmentation length is out of bounds");
				}
				buffer.bb.pos += augmentation_length;
			}
			fde->cie = it.entry->value;
			fde->instructions = buffer.bb.pos;
			fde->instructions_size = buffer.bb.end - buffer.bb.pos;
		}

		buffer.bb.pos = buffer.bb.end;
		buffer.bb.end = (const char *)data->d_buf + data->d_size;
	}

	drgn_dwarf_cie_vector_shrink_to_fit(&cies);
	drgn_dwarf_fde_vector_shrink_to_fit(&fdes);
	qsort(drgn_dwarf_fde_vector_begin(&fdes),
	      drgn_dwarf_fde_vector_size(&fdes), sizeof(struct drgn_dwarf_fde),
	      drgn_dwarf_fde_compar);
	drgn_dwarf_cie_vector_steal(&cies, &cfi->cies, NULL);
	drgn_dwarf_fde_vector_steal(&fdes, &cfi->fdes, &cfi->num_fdes);
	return NULL;
}

static struct drgn_dwarf_fde *drgn_find_dwarf_fde(struct drgn_dwarf_cfi *cfi,
						  uint64_t unbiased_pc)
{
	/* Binary search for the containing FDE. */
	size_t lo = 0, hi = cfi->num_fdes;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		struct drgn_dwarf_fde *fde = &cfi->fdes[mid];
		if (unbiased_pc < fde->initial_location)
			hi = mid;
		else if (unbiased_pc - fde->initial_location >=
			 fde->address_range)
			lo = mid + 1;
		else
			return fde;
	}
	return NULL;
}

static struct drgn_error *
drgn_dwarf_cfi_next_offset(struct drgn_elf_file_section_buffer *buffer,
			   int64_t *ret)
{
	struct drgn_error *err;
	uint64_t offset;
	if ((err = binary_buffer_next_uleb128(&buffer->bb, &offset)))
		return err;
	if (offset > INT64_MAX)
		return binary_buffer_error(&buffer->bb, "offset is too large");
	*ret = offset;
	return NULL;
}

static struct drgn_error *
drgn_dwarf_cfi_next_offset_sf(struct drgn_elf_file_section_buffer *buffer,
			      struct drgn_dwarf_cie *cie, int64_t *ret)
{
	struct drgn_error *err;
	int64_t factored;
	if ((err = binary_buffer_next_sleb128(&buffer->bb, &factored)))
		return err;
	if (__builtin_mul_overflow(factored, cie->data_alignment_factor, ret))
		return binary_buffer_error(&buffer->bb, "offset is too large");
	return NULL;
}

static struct drgn_error *
drgn_dwarf_cfi_next_offset_f(struct drgn_elf_file_section_buffer *buffer,
			     struct drgn_dwarf_cie *cie, int64_t *ret)
{
	struct drgn_error *err;
	uint64_t factored;
	if ((err = binary_buffer_next_uleb128(&buffer->bb, &factored)))
		return err;
	if (__builtin_mul_overflow(factored, cie->data_alignment_factor, ret))
		return binary_buffer_error(&buffer->bb, "offset is too large");
	return NULL;
}

static struct drgn_error *
drgn_dwarf_cfi_next_block(struct drgn_elf_file_section_buffer *buffer,
			  const char **buf_ret, size_t *size_ret)
{
	struct drgn_error *err;
	uint64_t size;
	if ((err = binary_buffer_next_uleb128(&buffer->bb, &size)))
		return err;
	if (size > buffer->bb.end - buffer->bb.pos) {
		return binary_buffer_error(&buffer->bb,
					   "block is out of bounds");
	}
	*buf_ret = buffer->bb.pos;
	buffer->bb.pos += size;
	*size_ret = size;
	return NULL;
}

DEFINE_VECTOR(drgn_cfi_row_vector, struct drgn_cfi_row *);

static struct drgn_error *
drgn_eval_dwarf_cfi(struct drgn_elf_file *file, enum drgn_section_index scn,
		    struct drgn_dwarf_cie *cie, struct drgn_dwarf_fde *fde,
		    const struct drgn_cfi_row *initial_row, uint64_t target,
		    const char *instructions, size_t instructions_size,
		    struct drgn_cfi_row **row)
{
	struct drgn_error *err;
	drgn_register_number (*dwarf_regno_to_internal)(uint64_t) =
		file->platform.arch->dwarf_regno_to_internal;
	uint64_t pc = fde->initial_location;

	struct drgn_cfi_row_vector state_stack = VECTOR_INIT;
	struct drgn_elf_file_section_buffer buffer;
	drgn_elf_file_section_buffer_init_index(&buffer, file, scn);
	buffer.bb.pos = instructions;
	buffer.bb.end = instructions + instructions_size;
	while (binary_buffer_has_next(&buffer.bb)) {
		uint8_t opcode;
		if ((err = binary_buffer_next_u8(&buffer.bb, &opcode)))
			goto out;

		uint64_t dwarf_regno;
		drgn_register_number regno;
		struct drgn_cfi_rule rule;
		uint64_t tmp;
		switch ((opcode & 0xc0) ? (opcode & 0xc0) : opcode) {
		case DW_CFA_set_loc:
			if (!initial_row)
				goto invalid_for_initial;
			if ((err = drgn_dwarf_cfi_next_encoded(&buffer,
							       cie->address_size,
							       cie->address_encoding,
							       fde->initial_location,
							       &tmp)))
				goto out;
			if (tmp <= pc) {
				err = binary_buffer_error(&buffer.bb,
							  "DW_CFA_set_loc location is not greater than current location");
				goto out;
			}
			pc = tmp;
			if (pc > target)
				goto found;
			break;
		case DW_CFA_advance_loc:
			if (!initial_row)
				goto invalid_for_initial;
			tmp = opcode & 0x3f;
			goto advance_loc;
		case DW_CFA_advance_loc1:
			if (!initial_row)
				goto invalid_for_initial;
			if ((err = binary_buffer_next_u8_into_u64(&buffer.bb,
								  &tmp)))
				goto out;
			goto advance_loc;
		case DW_CFA_advance_loc2:
			if (!initial_row)
				goto invalid_for_initial;
			if ((err = binary_buffer_next_u16_into_u64(&buffer.bb,
								   &tmp)))
				goto out;
			goto advance_loc;
		case DW_CFA_advance_loc4:
			if (!initial_row)
				goto invalid_for_initial;
			if ((err = binary_buffer_next_u32_into_u64(&buffer.bb,
								   &tmp)))
				goto out;
advance_loc:
			if (__builtin_mul_overflow(tmp,
						   cie->code_alignment_factor,
						   &tmp) ||
			    __builtin_add_overflow(pc, tmp, &pc) ||
			    pc > uint_max(cie->address_size)) {
				err = drgn_error_create(DRGN_ERROR_OTHER,
							"DW_CFA_advance_loc* overflows location");
				goto out;
			}
			if (pc > target)
				goto found;
			break;
		case DW_CFA_def_cfa:
			rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)) ||
			    (err = drgn_dwarf_cfi_next_offset(&buffer, &rule.offset)))
				goto out;
			if ((rule.regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				rule.kind = DRGN_CFI_RULE_UNDEFINED;
			goto set_cfa;
		case DW_CFA_def_cfa_sf:
			rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)) ||
			    (err = drgn_dwarf_cfi_next_offset_sf(&buffer, cie,
								 &rule.offset)))
				goto out;
			if ((rule.regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				rule.kind = DRGN_CFI_RULE_UNDEFINED;
			goto set_cfa;
		case DW_CFA_def_cfa_register:
			drgn_cfi_row_get_cfa(*row, &rule);
			if (rule.kind != DRGN_CFI_RULE_REGISTER_PLUS_OFFSET) {
				err = binary_buffer_error(&buffer.bb,
							  "DW_CFA_def_cfa_register with incompatible CFA rule");
				goto out;
			}
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)))
				goto out;
			if ((rule.regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				rule.kind = DRGN_CFI_RULE_UNDEFINED;
			goto set_cfa;
		case DW_CFA_def_cfa_offset:
			drgn_cfi_row_get_cfa(*row, &rule);
			if (rule.kind != DRGN_CFI_RULE_REGISTER_PLUS_OFFSET) {
				err = binary_buffer_error(&buffer.bb,
							  "DW_CFA_def_cfa_offset with incompatible CFA rule");
				goto out;
			}
			if ((err = drgn_dwarf_cfi_next_offset(&buffer,
							      &rule.offset)))
				goto out;
			goto set_cfa;
		case DW_CFA_def_cfa_offset_sf:
			drgn_cfi_row_get_cfa(*row, &rule);
			if (rule.kind != DRGN_CFI_RULE_REGISTER_PLUS_OFFSET) {
				err = binary_buffer_error(&buffer.bb,
							  "DW_CFA_def_cfa_offset_sf with incompatible CFA rule");
				goto out;
			}
			if ((err = drgn_dwarf_cfi_next_offset_sf(&buffer, cie,
								 &rule.offset)))
				goto out;
			goto set_cfa;
		case DW_CFA_def_cfa_expression:
			rule.kind = DRGN_CFI_RULE_DWARF_EXPRESSION;
			rule.push_cfa = false;
			if ((err = drgn_dwarf_cfi_next_block(&buffer,
							     &rule.expr,
							     &rule.expr_size)))
				goto out;
set_cfa:
			if (!drgn_cfi_row_set_cfa(row, &rule)) {
				err = &drgn_enomem;
				goto out;
			}
			break;
		case DW_CFA_undefined:
			rule.kind = DRGN_CFI_RULE_UNDEFINED;
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)))
				goto out;
			if ((regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				break;
			goto set_reg;
		case DW_CFA_same_value:
			rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
			rule.offset = 0;
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)))
				goto out;
			if ((regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				break;
			rule.regno = regno;
			goto set_reg;
		case DW_CFA_offset:
			rule.kind = DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET;
			if ((err = drgn_dwarf_cfi_next_offset_f(&buffer, cie,
								&rule.offset)))
				goto out;
			if ((regno = dwarf_regno_to_internal(opcode & 0x3f)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				break;
			goto set_reg;
		case DW_CFA_offset_extended:
			rule.kind = DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET;
			goto reg_offset_f;
		case DW_CFA_offset_extended_sf:
			rule.kind = DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET;
			goto reg_offset_sf;
		case DW_CFA_val_offset:
			rule.kind = DRGN_CFI_RULE_CFA_PLUS_OFFSET;
reg_offset_f:
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)) ||
			    (err = drgn_dwarf_cfi_next_offset_f(&buffer, cie,
								&rule.offset)))
				goto out;
			if ((regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				break;
			goto set_reg;
		case DW_CFA_val_offset_sf:
			rule.kind = DRGN_CFI_RULE_CFA_PLUS_OFFSET;
reg_offset_sf:
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)) ||
			    (err = drgn_dwarf_cfi_next_offset_sf(&buffer, cie,
								 &rule.offset)))
				goto out;
			if ((regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				break;
			goto set_reg;
		case DW_CFA_register: {
			rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
			rule.offset = 0;
			uint64_t dwarf_regno2;
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)) ||
			    (err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno2)))
				goto out;
			if ((regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				break;
			if ((rule.regno = dwarf_regno_to_internal(dwarf_regno2)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				rule.kind = DRGN_CFI_RULE_UNDEFINED;
			goto set_reg;
		}
		case DW_CFA_expression:
			rule.kind = DRGN_CFI_RULE_AT_DWARF_EXPRESSION;
			goto reg_expression;
		case DW_CFA_val_expression:
			rule.kind = DRGN_CFI_RULE_DWARF_EXPRESSION;
reg_expression:
			rule.push_cfa = true;
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)) ||
			    (err = drgn_dwarf_cfi_next_block(&buffer,
							     &rule.expr,
							     &rule.expr_size)))
				goto out;
			if ((regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				break;
			goto set_reg;
		case DW_CFA_restore:
			if (!initial_row)
				goto invalid_for_initial;
			dwarf_regno = opcode & 0x3f;
			goto restore;
		case DW_CFA_restore_extended:
			if (!initial_row) {
invalid_for_initial:
				err = binary_buffer_error(&buffer.bb,
							  "invalid initial DWARF CFI opcode %#" PRIx8,
							  opcode);
				goto out;
			}
			if ((err = binary_buffer_next_uleb128(&buffer.bb,
							      &dwarf_regno)))
				goto out;
restore:
			if ((regno = dwarf_regno_to_internal(dwarf_regno)) ==
			    DRGN_REGISTER_NUMBER_UNKNOWN)
				break;
			drgn_cfi_row_get_register(initial_row, regno, &rule);
set_reg:
			if (!drgn_cfi_row_set_register(row, regno, &rule)) {
				err = &drgn_enomem;
				goto out;
			}
			break;
		case DW_CFA_remember_state: {
			struct drgn_cfi_row **state =
				drgn_cfi_row_vector_append_entry(&state_stack);
			if (!state) {
				err = &drgn_enomem;
				goto out;
			}
			*state = drgn_empty_cfi_row;
			if (!drgn_cfi_row_copy(state, *row)) {
				err = &drgn_enomem;
				goto out;
			}
			break;
		}
		case DW_CFA_restore_state:
			if (drgn_cfi_row_vector_empty(&state_stack)) {
				err = binary_buffer_error(&buffer.bb,
							  "DW_CFA_restore_state with empty state stack");
				goto out;
			}
			drgn_cfi_row_destroy(*row);
			*row = *drgn_cfi_row_vector_pop(&state_stack);
			break;
		case DW_CFA_nop:
			break;
		// Note that this is the same opcode as DW_CFA_GNU_window_save,
		// which is used on Sparc.
		case DW_CFA_AARCH64_negate_ra_state:
			if (drgn_platform_arch(&file->platform)
			    == DRGN_ARCH_AARCH64) {
				regno = DRGN_AARCH64_RA_SIGN_STATE_REGNO;
				drgn_cfi_row_get_register(*row, regno, &rule);
				if (rule.kind != DRGN_CFI_RULE_CONSTANT) {
					err = binary_buffer_error(&buffer.bb,
								  "DW_CFA_AARCH64_negate_ra_state mixed with another rule");
					goto out;
				}
				rule.constant ^= 1;
				goto set_reg;
			}
			fallthrough;
		default:
			err = binary_buffer_error(&buffer.bb,
						  "unknown DWARF CFI opcode %#" PRIx8,
						  opcode);
			goto out;
		}
	}
found:
	err = NULL;
out:
	vector_for_each(drgn_cfi_row_vector, it, &state_stack)
		drgn_cfi_row_destroy(*it);
	drgn_cfi_row_vector_deinit(&state_stack);
	return err;
}

static struct drgn_error *
drgn_find_cfi_row_in_dwarf_fde(struct drgn_dwarf_cfi *cfi,
			       struct drgn_elf_file *file,
			       enum drgn_section_index scn,
			       struct drgn_dwarf_fde *fde, uint64_t unbiased_pc,
			       struct drgn_cfi_row **ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_cie *cie = &cfi->cies[fde->cie];
	struct drgn_cfi_row *initial_row =
		(struct drgn_cfi_row *)file->platform.arch->default_dwarf_cfi_row;
	err = drgn_eval_dwarf_cfi(file, scn, cie, fde, NULL, unbiased_pc,
				  cie->initial_instructions,
				  cie->initial_instructions_size, &initial_row);
	if (err)
		goto out;
	if (!drgn_cfi_row_copy(ret, initial_row)) {
		err = &drgn_enomem;
		goto out;
	}
	err = drgn_eval_dwarf_cfi(file, scn, cie, fde, initial_row, unbiased_pc,
				  fde->instructions, fde->instructions_size,
				  ret);
out:
	drgn_cfi_row_destroy(initial_row);
	return err;
}

static struct drgn_error *
drgn_find_dwarf_cfi(struct drgn_dwarf_cfi *cfi, bool *parsed,
		    struct drgn_elf_file *file, enum drgn_section_index scn,
		    uint64_t unbiased_pc, struct drgn_cfi_row **row_ret,
		    bool *interrupted_ret,
		    drgn_register_number *ret_addr_regno_ret)
{
	struct drgn_error *err;

	if (!*parsed) {
		err = drgn_parse_dwarf_cfi(cfi, file, scn);
		if (err)
			return err;
		*parsed = true;
	}

	struct drgn_dwarf_fde *fde = drgn_find_dwarf_fde(cfi, unbiased_pc);
	if (!fde)
		return &drgn_not_found;
	err = drgn_find_cfi_row_in_dwarf_fde(cfi, file, scn, fde, unbiased_pc,
					     row_ret);
	if (err)
		return err;
	*interrupted_ret = cfi->cies[fde->cie].signal_frame;
	*ret_addr_regno_ret = cfi->cies[fde->cie].return_address_register;
	return NULL;
}

struct drgn_error *
drgn_module_find_dwarf_cfi(struct drgn_module *module, uint64_t pc,
			   struct drgn_cfi_row **row_ret, bool *interrupted_ret,
			   drgn_register_number *ret_addr_regno_ret)
{
	return drgn_find_dwarf_cfi(&module->dwarf.debug_frame,
				   &module->parsed_debug_frame,
				   module->debug_file, DRGN_SCN_DEBUG_FRAME,
				   pc - module->debug_file_bias, row_ret,
				   interrupted_ret, ret_addr_regno_ret);
}

struct drgn_error *
drgn_module_find_eh_cfi(struct drgn_module *module, uint64_t pc,
			struct drgn_cfi_row **row_ret, bool *interrupted_ret,
			drgn_register_number *ret_addr_regno_ret)
{
	return drgn_find_dwarf_cfi(&module->dwarf.eh_frame,
				   &module->parsed_eh_frame,
				   module->loaded_file, DRGN_SCN_EH_FRAME,
				   pc - module->loaded_file_bias, row_ret,
				   interrupted_ret, ret_addr_regno_ret);
}

struct drgn_error *
drgn_eval_cfi_dwarf_expression(struct drgn_program *prog,
			       struct drgn_elf_file *file,
			       const struct drgn_cfi_rule *rule,
			       const struct drgn_register_state *regs,
			       void *buf, size_t size)
{
	struct drgn_error *err;
	_cleanup_(uint64_vector_deinit) struct uint64_vector stack =
		VECTOR_INIT;

	if (rule->push_cfa) {
		struct optional_uint64 cfa = drgn_register_state_get_cfa(regs);
		if (!cfa.has_value)
			return &drgn_not_found;
		if (!uint64_vector_append(&stack, &cfa.value))
			return &drgn_enomem;
	}

	int remaining_ops = MAX_DWARF_EXPR_OPS;
	struct drgn_dwarf_expression_context ctx;
	drgn_dwarf_expression_context_init(&ctx, prog, file, NULL, NULL, regs,
					   rule->expr, rule->expr_size);
	err = drgn_eval_dwarf_expression(&ctx, &stack, &remaining_ops);
	if (err)
		return err;
	if (binary_buffer_has_next(&ctx.bb)) {
		uint8_t opcode;
		err = binary_buffer_next_u8(&ctx.bb, &opcode);
		if (!err) {
			err = binary_buffer_error(&ctx.bb,
						  "invalid opcode %#" PRIx8 " for CFI expression",
						  opcode);
		}
		return err;
	}
	if (uint64_vector_empty(&stack)) {
		return &drgn_not_found;
	} else if (rule->kind == DRGN_CFI_RULE_AT_DWARF_EXPRESSION) {
		return drgn_program_read_memory(prog, buf,
						*uint64_vector_last(&stack),
						size, false);
	} else {
		copy_lsbytes(buf, size, drgn_elf_file_is_little_endian(file),
			     uint64_vector_last(&stack), sizeof(uint64_t),
			     HOST_LITTLE_ENDIAN);
		return NULL;
	}
}
