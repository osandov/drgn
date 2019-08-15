// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <assert.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
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
#include "read.h"
#include "siphash.h"
#include "string_builder.h"
#include "vector.h"

struct drgn_dwfl_module_userdata *drgn_dwfl_module_userdata_create(void)
{
	struct drgn_dwfl_module_userdata *userdata;

	userdata = calloc(1, sizeof(*userdata));
	if (userdata)
		userdata->fd = -1;
	return userdata;
}

void
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

void
drgn_dwfl_module_userdata_set_error(struct drgn_dwfl_module_userdata *userdata,
				    const char *message, struct drgn_error *err)
{
	if (userdata->err)
		drgn_error_destroy(userdata->err);
	if (message && err) {
		struct string_builder sb = {};

		if (!string_builder_appendf(&sb, "%s: ", message) ||
		    !string_builder_append_error(&sb, err)) {
			drgn_error_destroy(err);
			free(sb.str);
			userdata->err = &drgn_enomem;
			return;
		}
		drgn_error_destroy(err);
		userdata->err = drgn_error_from_string_builder(DRGN_ERROR_MISSING_DEBUG_INFO,
							       &sb);
	} else if (message) {
		userdata->err = drgn_error_create(DRGN_ERROR_MISSING_DEBUG_INFO,
						  message);
	} else {
		userdata->err = err;
	}
}

/**
 * @c Dwfl_Callbacks::find_elf() implementation.
 *
 * Ideally we'd use @c dwfl_report_elf() instead, but that doesn't work for a
 * couple of reasons:
 *
 * - vmlinux is usually an @c ET_EXEC ELF file, but when KASLR is enabled, it
 *   needs to be handled like an @c ET_DYN file. libdwfl has a hack for this
 *   when @c dwfl_report_module() is used, but @ref dwfl_report_elf() doesn't
 *   support this hack.
 * - For kernel modules, we want to set the section addresses in the @c Elf
 *   handle ourselves instead of using @c Dwfl_Callbacks::section_address(), but
 *   @c dwfl_report_elf() doesn't take an @c Elf handle.
 *
 * So, we're stuck with using @c dwfl_report_module() and this dummy callback.
 */
static int drgn_dwfl_find_elf(Dwfl_Module *module, void **userdatap,
			      const char *name, Dwarf_Addr base,
			      char **file_name, Elf **elfp)
{
	struct drgn_dwfl_module_userdata *userdata = *userdatap;
	int fd;

	if (userdata->err) {
		*file_name = NULL;
		*elfp = NULL;
		return -1;
	}

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

enum {
	SECTION_DEBUG_ABBREV,
	SECTION_DEBUG_INFO,
	SECTION_DEBUG_LINE,
	SECTION_DEBUG_STR,
	DRGN_DWARF_INDEX_NUM_SECTIONS,
};

static const char * const section_name[DRGN_DWARF_INDEX_NUM_SECTIONS] = {
	[SECTION_DEBUG_ABBREV] = ".debug_abbrev",
	[SECTION_DEBUG_INFO] = ".debug_info",
	[SECTION_DEBUG_LINE] = ".debug_line",
	[SECTION_DEBUG_STR] = ".debug_str",
};

/*
 * The DWARF abbreviation table gets translated into a series of instructions.
 * An instruction <= INSN_MAX_SKIP indicates a number of bytes to be skipped
 * over. The next few instructions mean that the corresponding attribute can be
 * skipped over. The remaining instructions indicate that the corresponding
 * attribute should be parsed. Finally, every sequence of instructions
 * corresponding to a DIE is terminated by a zero byte followed by a bitmask of
 * TAG_FLAG_* bits combined with the DWARF tag (which may be set to zero if the
 * tag is not of interest).
 */
enum {
	INSN_MAX_SKIP = 229,
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
	ATTRIB_SPECIFICATION_REF1,
	ATTRIB_SPECIFICATION_REF2,
	ATTRIB_SPECIFICATION_REF4,
	ATTRIB_SPECIFICATION_REF8,
	ATTRIB_SPECIFICATION_REF_UDATA,
	ATTRIB_MAX_INSN = ATTRIB_SPECIFICATION_REF_UDATA,
};

enum {
	/* Maximum number of bits used by the tags we care about. */
	TAG_BITS = 6,
	TAG_MASK = (1 << TAG_BITS) - 1,
	/* The remaining bits can be used for other purposes. */
	TAG_FLAG_DECLARATION = 0x40,
	TAG_FLAG_CHILDREN = 0x80,
};

DEFINE_VECTOR(uint8_vector, uint8_t)
DEFINE_VECTOR(uint32_vector, uint32_t)
DEFINE_VECTOR(uint64_vector, uint64_t)

struct abbrev_table {
	/*
	 * This is indexed on the DWARF abbreviation code minus one. It maps the
	 * abbreviation code to an index in insns where the instruction stream
	 * for that code begins.
	 *
	 * Technically, abbreviation codes don't have to be sequential. In
	 * practice, GCC seems to always generate sequential codes starting at
	 * one, so we can get away with a flat array.
	 */
	struct uint32_vector decls;
	struct uint8_vector insns;
};

static void abbrev_table_init(struct abbrev_table *abbrev)
{
	uint32_vector_init(&abbrev->decls);
	uint8_vector_init(&abbrev->insns);
}

static void abbrev_table_deinit(struct abbrev_table *abbrev)
{
	uint8_vector_deinit(&abbrev->insns);
	uint32_vector_deinit(&abbrev->decls);
}

struct compilation_unit {
	Dwfl_Module *module;
	Elf_Data *sections[DRGN_DWARF_INDEX_NUM_SECTIONS];
	const char *ptr;
	uint64_t unit_length;
	uint64_t debug_abbrev_offset;
	uint8_t address_size;
	bool is_64_bit;
	bool bswap;
};

static inline const char *section_ptr(Elf_Data *data, size_t offset)
{
	return &((char *)data->d_buf)[offset];
}

static inline const char *section_end(Elf_Data *data)
{
	return section_ptr(data, data->d_size);
}

/*
 * An indexed DIE.
 *
 * DIEs with the same name but different tags or files are considered distinct.
 * We only compare the hash of the file name, not the string value, because a
 * 64-bit collision is unlikely enough, especially when also considering the
 * name and tag.
 */
struct drgn_dwarf_index_die {
	uint64_t tag;
	uint64_t file_name_hash;
	/*
	 * The next DIE with the same name (as an index into
	 * drgn_dwarf_index_shard::dies), or SIZE_MAX if this is the last DIE.
	 */
	size_t next;
	Dwfl_Module *module;
	uint64_t offset;
};

/*
 * The key is the DIE name. The value is the first DIE with that name (as an
 * index into drgn_dwarf_index_shard::dies).
 */
DEFINE_HASH_TABLE_FUNCTIONS(drgn_dwarf_index_die_map, string_hash, string_eq)
DEFINE_VECTOR_FUNCTIONS(drgn_dwarf_index_die_vector)

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

static inline bool skip_leb128(const char **ptr, const char *end)
{
	for (;;) {
		if (*ptr >= end)
			return false;
		if (!(*(const uint8_t *)(*ptr)++ & 0x80))
			return true;
	}
}

static inline struct drgn_error *read_uleb128(const char **ptr, const char *end,
					      uint64_t *value)
{
	int shift = 0;
	uint8_t byte;

	*value = 0;
	for (;;) {
		if (*ptr >= end)
			return drgn_eof();
		byte = *(const uint8_t *)*ptr;
		(*ptr)++;
		if (shift == 63 && byte > 1) {
			return drgn_error_create(DRGN_ERROR_OVERFLOW,
						 "ULEB128 overflowed unsigned 64-bit integer");
		}
		*value |= (uint64_t)(byte & 0x7f) << shift;
		shift += 7;
		if (!(byte & 0x80))
			break;
	}
	return NULL;
}

static inline struct drgn_error *read_uleb128_into_size_t(const char **ptr,
							  const char *end,
							  size_t *value)
{
	struct drgn_error *err;
	uint64_t tmp;

	if ((err = read_uleb128(ptr, end, &tmp)))
		return err;

	if (tmp > SIZE_MAX)
		return drgn_eof();
	*value = tmp;
	return NULL;
}

static void free_shards(struct drgn_dwarf_index *dindex, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		drgn_dwarf_index_die_vector_deinit(&dindex->shards[i].dies);
		drgn_dwarf_index_die_map_deinit(&dindex->shards[i].map);
		omp_destroy_lock(&dindex->shards[i].lock);
	}
}

void drgn_dwarf_index_init(struct drgn_dwarf_index *dindex)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(dindex->shards); i++) {
		struct drgn_dwarf_index_shard *shard = &dindex->shards[i];

		omp_init_lock(&shard->lock);
		drgn_dwarf_index_die_map_init(&shard->map);
		drgn_dwarf_index_die_vector_init(&shard->dies);
	}
}

void drgn_dwarf_index_deinit(struct drgn_dwarf_index *dindex)
{
	if (dindex)
		free_shards(dindex, ARRAY_SIZE(dindex->shards));
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

		if (strncmp(scnname, ".rela.debug_", 12) == 0) {
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

static struct drgn_error *get_debug_sections(Elf *elf, Elf_Data **sections)
{
	struct drgn_error *err;
	size_t shstrndx;
	Elf_Scn *scn = NULL;
	size_t i;
	Elf_Data *debug_str;

	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr *shdr, shdr_mem;
		const char *scnname;

		shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return drgn_error_libelf();

		if (shdr->sh_type == SHT_NOBITS || (shdr->sh_flags & SHF_GROUP))
			continue;

		scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname)
			continue;

		for (i = 0; i < DRGN_DWARF_INDEX_NUM_SECTIONS; i++) {
			if (sections[i])
				continue;

			if (strcmp(scnname, section_name[i]) != 0)
				continue;

			err = read_elf_section(scn, &sections[i]);
			if (err)
				return err;
		}
	}

	for (i = 0; i < DRGN_DWARF_INDEX_NUM_SECTIONS; i++) {
		if (i != SECTION_DEBUG_LINE && !sections[i]) {
			return drgn_error_format(DRGN_ERROR_MISSING_DEBUG_INFO,
						 "ELF file has no %s section",
						 section_name[i]);
		}
	}

	debug_str = sections[SECTION_DEBUG_STR];
	if (debug_str->d_size == 0 ||
	    ((char *)debug_str->d_buf)[debug_str->d_size - 1] != '\0') {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 ".debug_str is not null terminated");
	}
	return NULL;
}

static struct drgn_error *read_compilation_unit_header(const char *ptr,
						       const char *end,
						       struct compilation_unit *cu)
{
	uint32_t tmp;
	uint16_t version;

	if (!read_u32(&ptr, end, cu->bswap, &tmp))
		return drgn_eof();
	cu->is_64_bit = tmp == UINT32_C(0xffffffff);
	if (cu->is_64_bit) {
		if (!read_u64(&ptr, end, cu->bswap, &cu->unit_length))
			return drgn_eof();
	} else {
		cu->unit_length = tmp;
	}

	if (!read_u16(&ptr, end, cu->bswap, &version))
		return drgn_eof();
	if (version != 2 && version != 3 && version != 4) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown DWARF CU version %" PRIu16,
					 version);
	}

	if (cu->is_64_bit) {
		if (!read_u64(&ptr, end, cu->bswap, &cu->debug_abbrev_offset))
			return drgn_eof();
	} else {
		if (!read_u32_into_u64(&ptr, end, cu->bswap,
				       &cu->debug_abbrev_offset))
			return drgn_eof();
	}

	if (!read_u8(&ptr, end, &cu->address_size))
		return drgn_eof();

	return NULL;
}

DEFINE_VECTOR(compilation_unit_vector, struct compilation_unit)

static struct drgn_error *read_cus(struct drgn_dwarf_index *dindex,
				   Dwfl_Module **modules, size_t num_modules,
				   struct compilation_unit_vector *all_cus)
{
	struct drgn_error *err = NULL;

	#pragma omp parallel
	{
		struct compilation_unit_vector cus;
		size_t i;

		compilation_unit_vector_init(&cus);
		#pragma omp for schedule(dynamic)
		for (i = 0; i < num_modules; i++) {
			struct drgn_error *err2;
			struct drgn_dwfl_module_userdata *userdata;
			Dwarf *dwarf;
			Dwarf_Addr bias;
			Elf *elf;
			bool bswap;
			Elf_Data *sections[DRGN_DWARF_INDEX_NUM_SECTIONS] = {};
			const char *ptr, *end;

			if (err)
				continue;

			userdata = drgn_dwfl_module_userdata(modules[i]);
			if (userdata->err)
				continue;

			if (userdata->elf) {
				err2 = apply_elf_relocations(userdata->elf);
				if (err2) {
					drgn_dwfl_module_userdata_set_error(userdata,
									    NULL,
									    err2);
					continue;
				}
			}

			/*
			 * Note: not dwfl_module_getelf(), because then libdwfl
			 * applies ELF relocations to all sections, not just
			 * debug sections.
			 */
			dwarf = dwfl_module_getdwarf(modules[i], &bias);
			if (!dwarf) {
				drgn_dwfl_module_userdata_set_error(userdata,
								    NULL,
								    drgn_error_libdwfl());
				continue;
			}
			elf = dwarf_getelf(dwarf);
			if (!elf) {
				drgn_dwfl_module_userdata_set_error(userdata,
								    NULL,
								    drgn_error_libdw());
				continue;
			}

			err2 = get_debug_sections(elf, sections);
			if (err2) {
				drgn_dwfl_module_userdata_set_error(userdata,
								    NULL, err2);
				continue;
			}

			bswap = (elf_getident(elf, NULL)[EI_DATA] !=
				 (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ?
				  ELFDATA2LSB : ELFDATA2MSB));

			ptr = section_ptr(sections[SECTION_DEBUG_INFO], 0);
			end = section_end(sections[SECTION_DEBUG_INFO]);
			while (ptr < end) {
				struct compilation_unit *cu;

				cu = compilation_unit_vector_append_entry(&cus);
				if (!cu) {
					#pragma omp critical(drgn_read_cus)
					{
						if (!err)
							err = &drgn_enomem;
					}
					break;
				}
				cu->module = modules[i];
				memcpy(cu->sections, sections, sizeof(cu->sections));
				cu->ptr = ptr;
				cu->bswap = bswap;
				err2 = read_compilation_unit_header(ptr, end, cu);
				if (err2) {
					#pragma omp critical(drgn_read_cus)
					{
						if (err)
							drgn_error_destroy(err2);
						else
							err = err2;
					}
					break;
				}

				ptr += (cu->is_64_bit ? 12 : 4) + cu->unit_length;
			}
		}

		if (cus.size) {
			#pragma omp critical(drgn_read_cus)
			if (!err) {
				if (compilation_unit_vector_reserve(all_cus,
								    all_cus->size + cus.size)) {
					memcpy(all_cus->data + all_cus->size,
					       cus.data,
					       cus.size * sizeof(*cus.data));
					all_cus->size += cus.size;
				} else {
					err = &drgn_enomem;
				}
			}
		}

		compilation_unit_vector_deinit(&cus);
	}
	return err;
}

static struct drgn_error *read_abbrev_decl(const char **ptr, const char *end,
					   const struct compilation_unit *cu,
					   struct abbrev_table *abbrev)
{
	struct drgn_error *err;
	uint64_t code;
	uint32_t insn_index;
	uint64_t tag;
	uint8_t children;
	uint8_t die_flags;
	bool should_index;
	bool first = true;
	uint8_t insn;

	static_assert(ATTRIB_MAX_INSN == UINT8_MAX,
		      "maximum DWARF attribute instruction is invalid");

	if ((err = read_uleb128(ptr, end, &code)))
		return err;
	if (code == 0)
		return &drgn_stop;
	if (code != abbrev->decls.size + 1) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "DWARF abbreviation table is not sequential");
	}

	insn_index = abbrev->insns.size;
	if (!uint32_vector_append(&abbrev->decls, &insn_index))
		return &drgn_enomem;

	if ((err = read_uleb128(ptr, end, &tag)))
		return err;

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
		should_index = true;
		break;
	default:
		should_index = false;
		break;
	}

	if (should_index || tag == DW_TAG_compile_unit)
		die_flags = tag;
	else
		die_flags = 0;

	if (!read_u8(ptr, end, &children))
		return drgn_eof();
	if (children)
		die_flags |= TAG_FLAG_CHILDREN;

	for (;;) {
		uint64_t name, form;

		if ((err = read_uleb128(ptr, end, &name)))
			return err;
		if ((err = read_uleb128(ptr, end, &form)))
			return err;
		if (name == 0 && form == 0)
			break;

		if (name == DW_AT_sibling && tag != DW_TAG_enumeration_type) {
			/*
			 * If we are indexing enumerators, we must descend into
			 * DW_TAG_enumeration_type to find the DW_TAG_enumerator
			 * children instead of skipping to the sibling DIE.
			 */
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
			   tag == DW_TAG_compile_unit &&
			   cu->sections[SECTION_DEBUG_LINE]) {
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
		} else if (name == DW_AT_decl_file && should_index) {
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
		} else if (name == DW_AT_declaration) {
			/*
			 * In theory, this could be DW_FORM_flag with a value of
			 * zero, but in practice, GCC always uses
			 * DW_FORM_flag_present.
			 */
			die_flags |= TAG_FLAG_DECLARATION;
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
			default:
				break;
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
			uint8_t last_insn;

			last_insn = abbrev->insns.data[abbrev->insns.size - 1];
			if (last_insn + insn <= INSN_MAX_SKIP) {
				abbrev->insns.data[abbrev->insns.size - 1] += insn;
				continue;
			} else if (last_insn < INSN_MAX_SKIP) {
				insn = last_insn + insn - INSN_MAX_SKIP;
				abbrev->insns.data[abbrev->insns.size - 1] =
					INSN_MAX_SKIP;
			}
		}

append_insn:
		first = false;
		if (!uint8_vector_append(&abbrev->insns, &insn))
			return &drgn_enomem;
	}
	insn = 0;
	if (!uint8_vector_append(&abbrev->insns, &insn) ||
	    !uint8_vector_append(&abbrev->insns, &die_flags))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *read_abbrev_table(const char *ptr, const char *end,
					    const struct compilation_unit *cu,
					    struct abbrev_table *abbrev)
{
	struct drgn_error *err;

	for (;;) {
		err = read_abbrev_decl(&ptr, end, cu, abbrev);
		if (err && err->code == DRGN_ERROR_STOP)
			break;
		else if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *skip_lnp_header(struct compilation_unit *cu,
					  const char **ptr, const char *end)
{
	uint32_t tmp;
	bool is_64_bit;
	uint16_t version;
	uint8_t opcode_base;

	if (!read_u32(ptr, end, cu->bswap, &tmp))
		return drgn_eof();
	is_64_bit = tmp == UINT32_C(0xffffffff);
	if (is_64_bit)
		*ptr += sizeof(uint64_t);

	if (!read_u16(ptr, end, cu->bswap, &version))
		return drgn_eof();
	if (version != 2 && version != 3 && version != 4) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown DWARF LNP version %" PRIu16,
					 version);
	}

	/*
	 * header_length
	 * minimum_instruction_length
	 * maximum_operations_per_instruction (DWARF 4 only)
	 * default_is_stmt
	 * line_base
	 * line_range
	 */
	*ptr += (is_64_bit ? 8 : 4) + 4 + (version >= 4);

	if (!read_u8(ptr, end, &opcode_base))
		return drgn_eof();
	/* standard_opcode_lengths */
	*ptr += opcode_base - 1;

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
		     struct compilation_unit *cu, size_t stmt_list,
		     struct uint64_vector *file_name_table)
{
	/*
	 * We don't care about hash flooding attacks, so don't bother with the
	 * random key.
	 */
	static const uint64_t siphash_key[2];
	struct drgn_error *err;
	Elf_Data *debug_line = cu->sections[SECTION_DEBUG_LINE];
	const char *ptr = section_ptr(debug_line, stmt_list);
	const char *end = section_end(debug_line);
	struct siphash_vector directories;

	siphash_vector_init(&directories);

	err = skip_lnp_header(cu, &ptr, end);
	if (err)
		return err;

	for (;;) {
		struct siphash *hash;
		const char *path;
		size_t path_len;

		if (!read_string(&ptr, end, &path, &path_len))
			return drgn_eof();
		if (!path_len)
			break;

		hash = siphash_vector_append_entry(&directories);
		if (!hash) {
			err = &drgn_enomem;
			goto out;
		}
		siphash_init(hash, siphash_key);
		hash_directory(hash, path, path_len);
	}

	for (;;) {
		const char *path;
		size_t path_len;
		uint64_t directory_index;
		struct siphash hash;
		uint64_t file_name_hash;

		if (!read_string(&ptr, end, &path, &path_len)) {
			err = drgn_eof();
			goto out;
		}
		if (!path_len)
			break;

		if ((err = read_uleb128(&ptr, end, &directory_index)))
			goto out;
		/* mtime, size */
		if (!skip_leb128(&ptr, end) || !skip_leb128(&ptr, end)) {
			err = drgn_eof();
			goto out;
		}

		if (directory_index > directories.size) {
			err = drgn_error_format(DRGN_ERROR_OTHER,
						"directory index %" PRIu64 " is invalid",
						directory_index);
			goto out;
		}

		if (directory_index)
			hash = directories.data[directory_index - 1];
		else
			siphash_init(&hash, siphash_key);
		siphash_update(&hash, path, path_len);

		file_name_hash = siphash_final(&hash);
		if (!uint64_vector_append(file_name_table, &file_name_hash)) {
			err = &drgn_enomem;
			goto out;
		}
	}

	err = NULL;
out:
	siphash_vector_deinit(&directories);
	return err;
}

static bool append_die_entry(struct drgn_dwarf_index_shard *shard, uint64_t tag,
			     uint64_t file_name_hash, Dwfl_Module *module,
			     uint64_t offset)
{
	struct drgn_dwarf_index_die *die;

	die = drgn_dwarf_index_die_vector_append_entry(&shard->dies);
	if (!die)
		return false;
	die->tag = tag;
	die->file_name_hash = file_name_hash;
	die->module = module;
	die->offset = offset;
	die->next = SIZE_MAX;
	return true;
}

static struct drgn_error *index_die(struct drgn_dwarf_index *dindex,
				    const char *name, uint64_t tag,
				    uint64_t file_name_hash,
				    Dwfl_Module *module, uint64_t offset)
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
	shard = &dindex->shards[hash_pair_to_shard(hp)];
	omp_set_lock(&shard->lock);
	it = drgn_dwarf_index_die_map_search_hashed(&shard->map, &entry.key,
						    hp);
	if (!it.entry) {
		if (!append_die_entry(shard, tag, file_name_hash, module,
				      offset)) {
			err = &drgn_enomem;
			goto out;
		}
		entry.value = shard->dies.size - 1;
		if (drgn_dwarf_index_die_map_insert_searched(&shard->map,
							     &entry, hp,
							     NULL) == 1)
			err = NULL;
		else
			err = &drgn_enomem;
		goto out;
	}

	die = &shard->dies.data[it.entry->value];
	for (;;) {
		if (die->tag == tag &&
		    die->file_name_hash == file_name_hash) {
			err = NULL;
			goto out;
		}

		if (die->next == SIZE_MAX)
			break;
		die = &shard->dies.data[die->next];
	}

	index = die - shard->dies.data;
	if (!append_die_entry(shard, tag, file_name_hash, module, offset)) {
		err = &drgn_enomem;
		goto out;
	}
	shard->dies.data[index].next = shard->dies.size - 1;
	err = NULL;
out:
	omp_unset_lock(&shard->lock);
	return err;
}

struct die {
	const char *sibling;
	const char *name;
	size_t stmt_list;
	size_t decl_file;
	const char *specification;
	uint8_t flags;
};

static struct drgn_error *read_die(struct compilation_unit *cu,
				   const struct abbrev_table *abbrev,
				   const char **ptr, const char *end,
				   const char *debug_str_buffer,
				   const char *debug_str_end, struct die *die)
{
	struct drgn_error *err;
	uint64_t code;
	uint8_t *insnp;
	uint8_t insn;

	if ((err = read_uleb128(ptr, end, &code)))
		return err;
	if (code == 0)
		return &drgn_stop;

	if (code < 1 || code > abbrev->decls.size) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown abbreviation code %" PRIu64,
					 code);
	}
	insnp = &abbrev->insns.data[abbrev->decls.data[code - 1]];

	while ((insn = *insnp++)) {
		size_t skip, tmp;

		switch (insn) {
		case ATTRIB_BLOCK1:
			if (!read_u8_into_size_t(ptr, end, &skip))
				return drgn_eof();
			goto skip;
		case ATTRIB_BLOCK2:
			if (!read_u16_into_size_t(ptr, end, cu->bswap, &skip))
				return drgn_eof();
			goto skip;
		case ATTRIB_BLOCK4:
			if (!read_u32_into_size_t(ptr, end, cu->bswap, &skip))
				return drgn_eof();
			goto skip;
		case ATTRIB_EXPRLOC:
			if ((err = read_uleb128_into_size_t(ptr, end, &skip)))
				return err;
			goto skip;
		case ATTRIB_LEB128:
			if (!skip_leb128(ptr, end))
				return drgn_eof();
			break;
		case ATTRIB_NAME_STRING:
			die->name = *ptr;
			/* fallthrough */
		case ATTRIB_STRING:
			if (!skip_string(ptr, end))
				return drgn_eof();
			break;
		case ATTRIB_SIBLING_REF1:
			if (!read_u8_into_size_t(ptr, end, &tmp))
				return drgn_eof();
			goto sibling;
		case ATTRIB_SIBLING_REF2:
			if (!read_u16_into_size_t(ptr, end, cu->bswap, &tmp))
				return drgn_eof();
			goto sibling;
		case ATTRIB_SIBLING_REF4:
			if (!read_u32_into_size_t(ptr, end, cu->bswap, &tmp))
				return drgn_eof();
			goto sibling;
		case ATTRIB_SIBLING_REF8:
			if (!read_u64_into_size_t(ptr, end, cu->bswap, &tmp))
				return drgn_eof();
			goto sibling;
		case ATTRIB_SIBLING_REF_UDATA:
			if ((err = read_uleb128_into_size_t(ptr, end, &tmp)))
				return err;
sibling:
			if (!read_in_bounds(cu->ptr, end, tmp))
				return drgn_eof();
			die->sibling = &cu->ptr[tmp];
			__builtin_prefetch(die->sibling);
			break;
		case ATTRIB_NAME_STRP4:
			if (!read_u32_into_size_t(ptr, end, cu->bswap, &tmp))
				return drgn_eof();
			goto strp;
		case ATTRIB_NAME_STRP8:
			if (!read_u64_into_size_t(ptr, end, cu->bswap, &tmp))
				return drgn_eof();
strp:
			if (!read_in_bounds(debug_str_buffer, debug_str_end,
					    tmp))
				return drgn_eof();
			die->name = &debug_str_buffer[tmp];
			__builtin_prefetch(die->name);
			break;
		case ATTRIB_STMT_LIST_LINEPTR4:
			if (!read_u32_into_size_t(ptr, end, cu->bswap,
						  &die->stmt_list))
				return drgn_eof();
			break;
		case ATTRIB_STMT_LIST_LINEPTR8:
			if (!read_u64_into_size_t(ptr, end, cu->bswap,
						  &die->stmt_list))
				return drgn_eof();
			break;
		case ATTRIB_DECL_FILE_DATA1:
			if (!read_u8_into_size_t(ptr, end, &die->decl_file))
				return drgn_eof();
			break;
		case ATTRIB_DECL_FILE_DATA2:
			if (!read_u16_into_size_t(ptr, end, cu->bswap,
						  &die->decl_file))
				return drgn_eof();
			break;
		case ATTRIB_DECL_FILE_DATA4:
			if (!read_u32_into_size_t(ptr, end, cu->bswap,
						  &die->decl_file))
				return drgn_eof();
			break;
		case ATTRIB_DECL_FILE_DATA8:
			if (!read_u64_into_size_t(ptr, end, cu->bswap,
						  &die->decl_file))
				return drgn_eof();
			break;
		case ATTRIB_DECL_FILE_UDATA:
			if ((err = read_uleb128_into_size_t(ptr, end,
							    &die->decl_file)))
				return err;
			break;
		case ATTRIB_SPECIFICATION_REF1:
			if (!read_u8_into_size_t(ptr, end, &tmp))
				return drgn_eof();
			goto specification;
		case ATTRIB_SPECIFICATION_REF2:
			if (!read_u16_into_size_t(ptr, end, cu->bswap, &tmp))
				return drgn_eof();
			goto specification;
		case ATTRIB_SPECIFICATION_REF4:
			if (!read_u32_into_size_t(ptr, end, cu->bswap, &tmp))
				return drgn_eof();
			goto specification;
		case ATTRIB_SPECIFICATION_REF8:
			if (!read_u64_into_size_t(ptr, end, cu->bswap, &tmp))
				return drgn_eof();
			goto specification;
		case ATTRIB_SPECIFICATION_REF_UDATA:
			if ((err = read_uleb128_into_size_t(ptr, end, &tmp)))
				return err;
specification:
			if (!read_in_bounds(cu->ptr, end, tmp))
				return drgn_eof();
			die->specification = &cu->ptr[tmp];
			__builtin_prefetch(die->specification);
			break;
		default:
			skip = insn;
skip:
			if (!read_in_bounds(*ptr, end, skip))
				return drgn_eof();
			*ptr += skip;
			break;
		}
	}

	die->flags = *insnp;

	return NULL;
}

static struct drgn_error *index_cu(struct drgn_dwarf_index *dindex,
				   struct compilation_unit *cu)
{
	struct drgn_error *err;
	struct abbrev_table abbrev;
	struct uint64_vector file_name_table;
	Elf_Data *debug_abbrev = cu->sections[SECTION_DEBUG_ABBREV];
	const char *debug_abbrev_end = section_end(debug_abbrev);
	const char *ptr = &cu->ptr[cu->is_64_bit ? 23 : 11];
	const char *end = &cu->ptr[(cu->is_64_bit ? 12 : 4) + cu->unit_length];
	Elf_Data *debug_info = cu->sections[SECTION_DEBUG_INFO];
	const char *debug_info_buffer = section_ptr(debug_info, 0);
	Elf_Data *debug_str = cu->sections[SECTION_DEBUG_STR];
	const char *debug_str_buffer = section_ptr(debug_str, 0);
	const char *debug_str_end = section_end(debug_str);
	unsigned int depth = 0;
	uint64_t enum_die_offset = 0;

	abbrev_table_init(&abbrev);
	uint64_vector_init(&file_name_table);

	if ((err = read_abbrev_table(section_ptr(debug_abbrev,
						 cu->debug_abbrev_offset),
				     debug_abbrev_end, cu, &abbrev)))
		goto out;

	for (;;) {
		struct die die = {
			.stmt_list = SIZE_MAX,
		};
		uint64_t die_offset = ptr - debug_info_buffer;
		uint64_t tag;

		err = read_die(cu, &abbrev, &ptr, end, debug_str_buffer,
			       debug_str_end, &die);
		if (err && err->code == DRGN_ERROR_STOP) {
			depth--;
			if (depth == 1)
				enum_die_offset = 0;
			else if (depth == 0)
				break;
			continue;
		} else if (err) {
			goto out;
		}

		tag = die.flags & TAG_MASK;
		if (tag == DW_TAG_compile_unit) {
			if (depth == 0 && die.stmt_list != SIZE_MAX &&
			    (err = read_file_name_table(dindex, cu,
							die.stmt_list,
							&file_name_table)))
				goto out;
		} else if (tag && !(die.flags & TAG_FLAG_DECLARATION)) {
			uint64_t file_name_hash;

			/*
			 * NB: the enumerator name points to the
			 * enumeration_type DIE instead of the enumerator DIE.
			 */
			if (depth == 1 && tag == DW_TAG_enumeration_type)
				enum_die_offset = die_offset;
			else if (depth == 2 && tag == DW_TAG_enumerator &&
				 enum_die_offset)
				die_offset = enum_die_offset;
			else if (depth != 1)
				goto next;

			if (die.specification && (!die.name || !die.decl_file)) {
				struct die decl = {};
				const char *decl_ptr = die.specification;

				if ((err = read_die(cu, &abbrev, &decl_ptr, end,
						    debug_str_buffer,
						    debug_str_end, &decl)))
					goto out;
				if (!die.name && decl.name)
					die.name = decl.name;
				if (!die.decl_file && decl.decl_file)
					die.decl_file = decl.decl_file;
			}

			if (die.name) {
				if (die.decl_file > file_name_table.size) {
					err = drgn_error_format(DRGN_ERROR_OTHER,
								"invalid DW_AT_decl_file %zu",
								die.decl_file);
					goto out;
				}
				if (die.decl_file)
					file_name_hash = file_name_table.data[die.decl_file - 1];
				else
					file_name_hash = 0;
				if ((err = index_die(dindex, die.name, tag,
						     file_name_hash, cu->module,
						     die_offset)))
					goto out;
			}
		}

next:
		if (die.flags & TAG_FLAG_CHILDREN) {
			if (die.sibling)
				ptr = die.sibling;
			else
				depth++;
		} else if (depth == 0) {
			break;
		}
	}

	err = NULL;
out:
	uint64_vector_deinit(&file_name_table);
	abbrev_table_deinit(&abbrev);
	return err;
}

static struct drgn_error *index_cus(struct drgn_dwarf_index *dindex,
				    struct compilation_unit *cus,
				    size_t num_cus)
{
	struct drgn_error *err = NULL;
	size_t i;

	#pragma omp parallel for schedule(dynamic)
	for (i = 0; i < num_cus; i++) {
		struct drgn_error *err2;

		if (err)
			continue;

		err2 = index_cu(dindex, &cus[i]);
		if (err2) {
			#pragma omp critical(drgn_index_cus)
			{
				if (err)
					drgn_error_destroy(err2);
				else
					err = err2;
			}
		}
	}

	/* If we have an error while indexing, delete all new entries. */
	if (err) {
		for (i = 0; i < ARRAY_SIZE(dindex->shards); i++) {
			struct drgn_dwarf_index_shard *shard;
			struct drgn_dwarf_index_die *die;
			struct drgn_dwarf_index_die_map_iterator it;
			size_t index;

			shard = &dindex->shards[i];

			/*
			 * Because we're deleting everything that was added
			 * since the last update, we can just shrink the dies
			 * array to the first entry that was added for this
			 * update.
			 */
			while (shard->dies.size) {
				die = &shard->dies.data[shard->dies.size - 1];
				if (drgn_dwfl_module_userdata(die->module)->indexed)
					break;
				else
					shard->dies.size--;
			}

			/*
			 * The new entries may be chained off of existing
			 * entries; unchain them. Note that any entries chained
			 * off of the new entries must also be new, so there's
			 * no need to preserve them.
			 */
			for (index = 0; index < shard->dies.size; i++) {
				die = &shard->dies.data[index];
				if (die->next != SIZE_MAX &&
				    die->next >= shard->dies.size)
					die->next = SIZE_MAX;
			}

			/* Finally, delete the new entries in the map. */
			for (it = drgn_dwarf_index_die_map_first(&shard->map);
			     it.entry; ) {
				if (it.entry->value >= shard->dies.size) {
					it = drgn_dwarf_index_die_map_delete_iterator(&shard->map,
										      it);
				} else {
					it = drgn_dwarf_index_die_map_next(it);
				}
			}
		}
	}
	return err;
}

DEFINE_VECTOR(dwfl_module_vector, Dwfl_Module *)

static int drgn_append_dwfl_module(Dwfl_Module *module, void **userdatap,
				   const char *name, Dwarf_Addr base, void *arg)
{
	struct drgn_dwfl_module_userdata *userdata = *userdatap;
	struct dwfl_module_vector *modules = arg;

	if (userdata && userdata->indexed)
		return DWARF_CB_OK;
	if (!userdata) {
		userdata = drgn_dwfl_module_userdata_create();
		if (!userdata)
			return DWARF_CB_ABORT;
		*userdatap = userdata;
	}
	if (!dwfl_module_vector_append(modules, &module))
		return DWARF_CB_ABORT;
	return DWARF_CB_OK;
}

struct drgn_error *drgn_dwarf_index_update(struct drgn_dwarf_index *dindex,
					   Dwfl *dwfl)
{
	struct drgn_error *err = NULL;
	struct dwfl_module_vector modules;
	struct compilation_unit_vector cus;
	struct string_builder missing = {};
	size_t num_missing = 0;
	static const size_t max_missing = 5;
	size_t i;

	dwfl_module_vector_init(&modules);
	compilation_unit_vector_init(&cus);
	if (dwfl_getmodules(dwfl, drgn_append_dwfl_module, &modules, 0)) {
		err = &drgn_enomem;
		goto out;
	}
	err = read_cus(dindex, modules.data, modules.size, &cus);
	if (err)
		goto out;
	err = index_cus(dindex, cus.data, cus.size);
	if (err)
		goto out;

	for (i = 0; i < modules.size; i++) {
		const char *name;
		void **userdatap;
		struct drgn_dwfl_module_userdata *userdata;

		name = dwfl_module_info(modules.data[i], &userdatap, NULL, NULL,
					NULL, NULL, NULL, NULL);
		userdata = *userdatap;
		if (!userdata->err) {
			userdata->indexed = true;
			continue;
		}
		if (num_missing == 0 &&
		    !string_builder_append(&missing,
					   "could not get debugging information for:")) {
			err = &drgn_enomem;
			goto out;
		}
		if (num_missing < max_missing) {
		    if (!string_builder_line_break(&missing) ||
			!string_builder_appendf(&missing, "%s (", name) ||
			!string_builder_append_error(&missing, userdata->err) ||
			!string_builder_appendc(&missing, ')')) {
			    err = &drgn_enomem;
			    goto out;
		    }
		}
		num_missing++;
	}
	if (num_missing > max_missing &&
	    (!string_builder_line_break(&missing) ||
	     !string_builder_appendf(&missing, "... %zu more",
				     num_missing - max_missing))) {
		err = &drgn_enomem;
		goto out;
	}
	if (missing.len) {
		err = drgn_error_from_string_builder(DRGN_ERROR_MISSING_DEBUG_INFO,
						     &missing);
		missing.str = NULL;
	} else {
		err = NULL;
	}
out:
	free(missing.str);
	compilation_unit_vector_deinit(&cus);
	dwfl_module_vector_deinit(&modules);
	return err;
}

static int drgn_dwfl_module_removed(Dwfl_Module *module, void *userdatap,
				    const char *name, Dwarf_Addr base,
				    void *arg)
{
	/*
	 * userdatap is actually a void ** like for the other libdwfl callbacks,
	 * but dwfl_report_end() has the wrong signature for the removed
	 * callback.
	 */
	struct drgn_dwfl_module_userdata *userdata = *(void **)userdatap;
	Dwarf_Addr end;

	if (arg && userdata && userdata->indexed) {
		/*
		 * The file is already indexed and drgn_remove_dwfl_modules()
		 * was called with unindexed == true; report the module again so
		 * libdwfl doesn't remove it.
		 */
		dwfl_module_info(module, NULL, NULL, &end, NULL, NULL, NULL,
				 NULL);
		dwfl_report_module(arg, name, base, end);
	} else {
		drgn_dwfl_module_userdata_destroy(userdata);
	}
	return DWARF_CB_OK;
}

static void drgn_remove_dwfl_modules(Dwfl *dwfl, bool unindexed)
{
	int fd;

	/*
	 * Work around a libdwfl bug that causes it to close stdin when it frees
	 * some modules which are reported by dwfl_core_file_report().
	 */
	fd = dup(0);
	dwfl_report_begin(dwfl);
	dwfl_report_end(dwfl, drgn_dwfl_module_removed,
			unindexed ? dwfl : NULL);
	if (fd != -1) {
		dup2(fd, 0);
		close(fd);
	}
}

void drgn_remove_unindexed_dwfl_modules(Dwfl *dwfl)
{
	drgn_remove_dwfl_modules(dwfl, true);
}

void drgn_remove_all_dwfl_modules(Dwfl *dwfl)
{
	drgn_remove_dwfl_modules(dwfl, false);
}

void drgn_dwarf_index_iterator_init(struct drgn_dwarf_index_iterator *it,
				    struct drgn_dwarf_index *dindex,
				    const char *name, size_t name_len,
				    const uint64_t *tags, size_t num_tags)
{
	it->dindex = dindex;
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
		shard = &dindex->shards[it->shard];
		map_it = drgn_dwarf_index_die_map_search_hashed(&shard->map,
								&key, hp);
		it->index = map_it.entry ? map_it.entry->value : SIZE_MAX;
		it->any_name = false;
	} else {
		it->index = 0;
		for (it->shard = 0; it->shard < ARRAY_SIZE(dindex->shards);
		     it->shard++) {
			if (dindex->shards[it->shard].dies.size)
				break;
		}
		it->any_name = true;
	}
	it->tags = tags;
	it->num_tags = num_tags;
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

struct drgn_error *
drgn_dwarf_index_iterator_next(struct drgn_dwarf_index_iterator *it,
			       Dwarf_Die *die_ret, uint64_t *bias_ret)
{
	struct drgn_dwarf_index *dindex = it->dindex;
	struct drgn_dwarf_index_die *die;
	Dwarf *dwarf;
	Dwarf_Addr bias;

	if (it->any_name) {
		for (;;) {
			struct drgn_dwarf_index_shard *shard;

			if (it->shard >= ARRAY_SIZE(dindex->shards))
				return &drgn_stop;

			shard = &dindex->shards[it->shard];
			die = &shard->dies.data[it->index];

			if (++it->index >= shard->dies.size) {
				it->index = 0;
				while (++it->shard < ARRAY_SIZE(dindex->shards)) {
					if (dindex->shards[it->shard].dies.size)
						break;
				}
			}

			if (drgn_dwarf_index_iterator_matches_tag(it, die))
				break;
		}
	} else {
		for (;;) {
			struct drgn_dwarf_index_shard *shard;

			if (it->index == SIZE_MAX)
				return &drgn_stop;

			shard = &dindex->shards[it->shard];
			die = &shard->dies.data[it->index];

			it->index = die->next;

			if (drgn_dwarf_index_iterator_matches_tag(it, die))
				break;
		}
	}

	dwarf = dwfl_module_getdwarf(die->module, &bias);
	if (!dwarf)
		return drgn_error_libdwfl();
	if (!dwarf_offdie(dwarf, die->offset, die_ret))
		return drgn_error_libdw();
	if (bias_ret)
		*bias_ret = bias;
	return NULL;
}
