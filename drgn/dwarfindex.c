#include <dwarf.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <Python.h>
#include "structmember.h"

static PyObject *DwarfFile;
static PyObject *DwarfFormatError;
static PyObject *ElfFormatError;

#define DIE_HASH_SHIFT 17
#define DIE_HASH_SIZE (1 << DIE_HASH_SHIFT)
#define DIE_HASH_MASK ((1 << DIE_HASH_SHIFT) - 1)

/*
 * XXX: hacky way to make sure everywhere we raise an exception does so with the
 * GIL held.
 */
#define PyErr_Format(...) ({				\
	PyGILState_STATE _state = PyGILState_Ensure();	\
	PyErr_Format(__VA_ARGS__);			\
	PyGILState_Release(_state);			\
	NULL;						\
})

#define PyErr_NoMemory(...) ({				\
	PyGILState_STATE _state = PyGILState_Ensure();	\
	PyErr_NoMemory(__VA_ARGS__);			\
	PyGILState_Release(_state);			\
	NULL;						\
})

#define PyErr_SetFromErrnoWithFilenameObject(...) ({		\
	PyGILState_STATE _state = PyGILState_Ensure();		\
	PyErr_SetFromErrnoWithFilenameObject(__VA_ARGS__);	\
	PyGILState_Release(_state);				\
	NULL;							\
})

#define PyErr_SetNone(...) ({				\
	PyGILState_STATE _state = PyGILState_Ensure();	\
	PyErr_SetNone(__VA_ARGS__);			\
	PyGILState_Release(_state);			\
	NULL;						\
})

#define PyErr_SetString(...) ({				\
	PyGILState_STATE _state = PyGILState_Ensure();	\
	PyErr_SetString(__VA_ARGS__);			\
	PyGILState_Release(_state);			\
	NULL;						\
})

enum {
	DEBUG_ABBREV,
	DEBUG_INFO,
	DEBUG_STR,
	NUM_DEBUG_SECTIONS,
};

static const char *section_names[NUM_DEBUG_SECTIONS] = {
	[DEBUG_ABBREV] = ".debug_abbrev",
	[DEBUG_INFO] = ".debug_info",
	[DEBUG_STR] = ".debug_str",
};

static inline bool in_bounds(const char *ptr, const char *end, size_t size)
{
	return ptr <= end && (size_t)(end - ptr) >= size;
}

#define DEFINE_READ(size)						\
static inline int read_u##size(const char **ptr, const char *end,	\
			       uint##size##_t *value)			\
{									\
	if (!in_bounds(*ptr, end, sizeof(uint##size##_t))) {		\
		PyErr_SetNone(PyExc_EOFError);				\
		return -1;						\
	}								\
	*value = *(const uint##size##_t *)*ptr;				\
	*ptr += sizeof(uint##size##_t);					\
	return 0;							\
}									\
									\
static inline int read_u##size##_into_bool(const char **ptr,		\
					   const char *end,		\
					   bool *value)			\
{									\
	if (!in_bounds(*ptr, end, sizeof(uint##size##_t))) {		\
		PyErr_SetNone(PyExc_EOFError);				\
		return -1;						\
	}								\
	*value = !!*(const uint##size##_t *)*ptr;			\
	*ptr += sizeof(uint##size##_t);					\
	return 0;							\
}									\
									\
static inline int read_u##size##_into_u64(const char **ptr,		\
					  const char *end,		\
					  uint64_t *value)		\
{									\
	if (!in_bounds(*ptr, end, sizeof(uint##size##_t))) {		\
		PyErr_SetNone(PyExc_EOFError);				\
		return -1;						\
	}								\
	*value = *(const uint##size##_t *)*ptr;				\
	*ptr += sizeof(uint##size##_t);					\
	return 0;							\
}									\
									\
static inline int read_u##size##_into_size_t(const char **ptr,		\
					     const char *end,		\
					     size_t *value)		\
{									\
	uint##size##_t tmp;						\
									\
	if (read_u##size(ptr, end, &tmp) == -1)				\
		return -1;						\
									\
	if (tmp > SIZE_MAX) {						\
		PyErr_SetNone(PyExc_EOFError);				\
		return -1;						\
	}								\
	*value = tmp;							\
	return 0;							\
}

DEFINE_READ(8);
DEFINE_READ(16);
DEFINE_READ(32);
DEFINE_READ(64);

static inline int read_uleb128(const char **ptr, const char *end,
			       uint64_t *value)
{
	int shift = 0;
	uint8_t byte;

	*value = 0;
	for (;;) {
		if (*ptr >= end) {
			PyErr_SetNone(PyExc_EOFError);
			return -1;
		}
		byte = *(const uint8_t *)*ptr;
		(*ptr)++;
		if (shift == 63 && byte > 1) {
			PyErr_SetString(PyExc_OverflowError,
					"ULEB128 overflowed unsigned 64-bit integer");
			return -1;
		}
		*value |= (uint64_t)(byte & 0x7f) << shift;
		shift += 7;
		if (!(byte & 0x80))
			break;
	}
	return 0;
}

static inline int read_uleb128_into_size_t(const char **ptr, const char *end,
					   size_t *value)
{
	uint64_t tmp;

	if (read_uleb128(ptr, end, &tmp) == -1)
		return -1;

	if (tmp > SIZE_MAX) {
		PyErr_SetNone(PyExc_EOFError);
		return -1;
	}
	*value = tmp;
	return 0;
}

enum {
	ATTRIB_BLOCK1 = 242,
	ATTRIB_BLOCK2 = 243,
	ATTRIB_BLOCK4 = 244,
	ATTRIB_EXPRLOC = 245,
	ATTRIB_LEB128 = 246,
	ATTRIB_STRING = 247,
	ATTRIB_SIBLING_REF1 = 248,
	ATTRIB_SIBLING_REF2 = 249,
	ATTRIB_SIBLING_REF4 = 250,
	ATTRIB_SIBLING_REF8 = 251,
	ATTRIB_SIBLING_REF_UDATA = 252,
	ATTRIB_NAME_STRP4 = 253,
	ATTRIB_NAME_STRP8 = 254,
	ATTRIB_NAME_STRING = 255,
	ATTRIB_MIN_CMD = ATTRIB_BLOCK1,
};

struct abbrev_table {
	/*
	 * Technically, abbreviation codes don't have to be sequential. In
	 * practice, GCC seems to always generate sequential codes starting at
	 * one, so we can get away with a flat array.
	 */
	uint32_t *decls;
	size_t num_decls;
	uint8_t *cmds;
};

struct compilation_unit {
	const char *ptr;
	uint64_t unit_length;
	uint16_t version;
	uint64_t debug_abbrev_offset;
	uint8_t address_size;
	bool is_64_bit;
	struct file *file;
};

struct section {
	uint16_t shdr_index;
	char *buffer;
	uint64_t size;
};

struct file {
	char *map;
	size_t size;
	struct section symtab;
	struct section debug_sections[NUM_DEBUG_SECTIONS];
	struct section rela_sections[NUM_DEBUG_SECTIONS];
	/* DwarfFile object or NULL if it has not been initialized yet. */
	PyObject *obj;
	/* dict mapping cu offsets to CUs */
	PyObject *cu_objs;
};

struct die_hash_entry {
	const char *name;
	uint64_t tag;
	struct compilation_unit *cu;
	const char *ptr;
};

typedef struct {
	PyObject_HEAD
	struct file *files;
	size_t num_files;
	struct compilation_unit *cus;
	size_t num_cus;
	struct die_hash_entry die_hash[DIE_HASH_SIZE];
	int address_size;
} DwarfIndex;

static int open_file(struct file *file, const char *path)
{
	int saved_errno;
	struct stat st;
	void *map;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;

	if (fstat(fd, &st) == -1)
		return -1;

	map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	file->map = map;
	file->size = st.st_size;

	close(fd);
	return 0;
}

static int validate_ehdr(struct file *file, const Elf64_Ehdr *ehdr)
{
	if (file->size < EI_NIDENT ||
	    ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3) {
		PyErr_SetString(ElfFormatError, "not an ELF file");
		return -1;
	}

	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
		PyErr_Format(ElfFormatError, "ELF version %u is not EV_CURRENT",
			     (unsigned int)ehdr->e_ident[EI_VERSION]);
		return -1;
	}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
#else
	if (ehdr->e_ident[EI_DATA] != ELFDATA2MSB) {
#endif
		PyErr_SetString(PyExc_NotImplementedError,
				"ELF file endianness does not match machine");
		return -1;
	}

	if (ehdr->e_ident[EI_CLASS] == ELFCLASS32) {
		PyErr_SetString(PyExc_NotImplementedError,
				"32-bit ELF is not implemented");
		return -1;
	} else if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		PyErr_Format(ElfFormatError, "unknown ELF class %u",
			     (unsigned int)ehdr->e_ident[EI_CLASS]);
		return -1;
	}

	if (file->size < sizeof(Elf64_Ehdr)) {
		PyErr_SetString(ElfFormatError, "ELF header is truncated");
		return -1;
	}

	if (ehdr->e_shnum == 0) {
		PyErr_SetString(ElfFormatError, "ELF file has no sections");
		return -1;
	}

	if (ehdr->e_shoff > SIZE_MAX - sizeof(Elf64_Shdr) * (size_t)ehdr->e_shnum ||
	    ehdr->e_shoff + sizeof(Elf64_Shdr) * (size_t)ehdr->e_shnum > file->size) {
		PyErr_SetString(ElfFormatError,
				"ELF section header table is beyond EOF");
		return -1;
	}

	return 0;
}

static int validate_shdr(struct file *file, const Elf64_Shdr *shdr)
{
	if (shdr->sh_offset > SIZE_MAX - shdr->sh_size ||
	    shdr->sh_offset + shdr->sh_size > file->size) {
		PyErr_SetString(ElfFormatError, "ELF section is beyond EOF");
		return -1;
	}
	return 0;
}

static int read_sections(struct file *file)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdrs;
	uint16_t shstrndx;
	const Elf64_Shdr *shstrtab_shdr;
	const char *shstrtab;
	uint16_t i;

	ehdr = (Elf64_Ehdr *)file->map;
	if (validate_ehdr(file, ehdr) == -1)
		return -1;


	shdrs = (Elf64_Shdr *)(file->map + ehdr->e_shoff);

	shstrndx = ehdr->e_shstrndx;
	if (shstrndx == SHN_XINDEX)
		shstrndx = shdrs[0].sh_link;
	if (shstrndx == SHN_UNDEF || shstrndx >= ehdr->e_shnum) {
		PyErr_SetString(ElfFormatError,
				"invalid ELF section header string table index");
		return -1;
	}
	shstrtab_shdr = &shdrs[shstrndx];
	if (validate_shdr(file, shstrtab_shdr) == -1)
		return -1;

	shstrtab = file->map + shstrtab_shdr->sh_offset;

	for (i = 0; i < ehdr->e_shnum; i++) {
		struct section *section;
		const char *name;
		size_t max_name_len;

		if (shdrs[i].sh_type == SHT_PROGBITS) {
			if (shdrs[i].sh_name == 0 ||
			    shdrs[i].sh_name >= shstrtab_shdr->sh_size)
				continue;
			max_name_len = shstrtab_shdr->sh_size - shdrs[i].sh_name;
			name = &shstrtab[shdrs[i].sh_name];
			/* Must be greater than to account for the NUL byte. */
			if (max_name_len > strlen(".debug_abbrev") &&
			    strcmp(name, ".debug_abbrev") == 0)
				section = &file->debug_sections[DEBUG_ABBREV];
			else if (max_name_len > strlen(".debug_info") &&
				 strcmp(name, ".debug_info") == 0)
				section = &file->debug_sections[DEBUG_INFO];
			else if (max_name_len > strlen(".debug_str") &&
				 strcmp(name, ".debug_str") == 0)
				section = &file->debug_sections[DEBUG_STR];
			else
				continue;
		} else if (shdrs[i].sh_type == SHT_SYMTAB) {
			section = &file->symtab;
		} else {
			continue;
		}
		if (validate_shdr(file, &shdrs[i]) == -1)
			return -1;
		section->shdr_index = i;
		section->buffer = file->map + shdrs[i].sh_offset;
		section->size = shdrs[i].sh_size;
	}

	if (!file->symtab.buffer) {
		PyErr_SetString(DwarfFormatError, "missing .symtab");
		return -1;
	}
	for (i = 0; i < NUM_DEBUG_SECTIONS; i++) {
		if (!file->debug_sections[i].buffer) {
			PyErr_Format(DwarfFormatError, "missing %s",
				     section_names[i]);
			return -1;
		}
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		struct section *section;
		int j;

		if (shdrs[i].sh_type != SHT_RELA)
			continue;
		for (j = 0; j < NUM_DEBUG_SECTIONS; j++) {
			if (shdrs[i].sh_info == file->debug_sections[j].shdr_index) {
				section = &file->rela_sections[j];
				break;
			}
		}
		if (j == NUM_DEBUG_SECTIONS)
			continue;
		if (shdrs[i].sh_link != file->symtab.shdr_index) {
			PyErr_SetString(ElfFormatError,
					"relocation symbol table section is not .symtab");
			return -1;
		}
		if (validate_shdr(file, &shdrs[i]) == -1)
			return -1;
		section->shdr_index = i;
		section->buffer = file->map + shdrs[i].sh_offset;
		section->size = shdrs[i].sh_size;
	}
	return 0;
}

static int apply_relocation(struct section *section,
			    struct section *rela_section,
			    struct section *symtab, size_t i)
{
	const Elf64_Rela *reloc;
	const Elf64_Sym *syms;
	size_t num_syms;
	uint32_t r_sym;
	uint32_t r_type;
	char *p;

	reloc = &((Elf64_Rela *)rela_section->buffer)[i];
	syms = (Elf64_Sym *)symtab->buffer;
	num_syms = symtab->size / sizeof(Elf64_Rela);

	p = section->buffer + reloc->r_offset;
	r_sym = reloc->r_info >> 32;
	r_type = reloc->r_info & UINT32_C(0xffffffff);
	switch (r_type) {
	case R_X86_64_NONE:
		break;
	case R_X86_64_32:
		if (r_sym >= num_syms) {
			PyErr_Format(ElfFormatError,
				     "invalid relocation symbol");
			return -1;
		}
		if (reloc->r_offset > SIZE_MAX - sizeof(uint32_t) ||
		    reloc->r_offset + sizeof(uint32_t) > section->size) {
			PyErr_Format(ElfFormatError,
				     "invalid relocation offset");
			return -1;
		}
		*(uint32_t *)p = syms[r_sym].st_value + reloc->r_addend;
		break;
	case R_X86_64_64:
		if (r_sym >= num_syms) {
			PyErr_Format(ElfFormatError,
				     "invalid relocation symbol");
			return -1;
		}
		if (reloc->r_offset > SIZE_MAX - sizeof(uint64_t) ||
		    reloc->r_offset + sizeof(uint64_t) > section->size) {
			PyErr_Format(ElfFormatError,
				     "invalid relocation offset");
			return -1;
		}
		*(uint64_t *)p = syms[r_sym].st_value + reloc->r_addend;
		break;
	default:
		PyErr_Format(PyExc_NotImplementedError,
			     "unimplemented relocation type %" PRIu32,
			     r_type);
		return -1;
	}
	return 0;
}

static int realloc_cus(struct compilation_unit **cus, size_t n)
{
	struct compilation_unit *tmp;

	if (n > SIZE_MAX / sizeof(**cus)) {
		PyErr_NoMemory();
		return -1;
	}

	tmp = realloc(*cus, n * sizeof(**cus));
	if (!tmp) {
		PyErr_NoMemory();
		return -1;
	}

	*cus = tmp;
	return 0;
}

static int read_compilation_unit_header(const char *ptr, const char *end,
					struct compilation_unit *cu)
{
	uint32_t tmp;

	if (read_u32(&ptr, end, &tmp) == -1)
		return -1;
	cu->is_64_bit = tmp == UINT32_C(0xffffffff);
	if (cu->is_64_bit) {
		if (read_u64(&ptr, end, &cu->unit_length) == -1)
			return -1;
	} else {
		cu->unit_length = tmp;
	}

	if (read_u16(&ptr, end, &cu->version) == -1)
		return -1;
	if (cu->version != 2 && cu->version != 3 && cu->version != 4) {
		PyErr_Format(DwarfFormatError, "unknown DWARF version %" PRIu16,
			     cu->version);
		return -1;
	}

	if (cu->is_64_bit) {
		if (read_u64(&ptr, end, &cu->debug_abbrev_offset) == -1)
			return -1;
	} else {
		if (read_u32_into_u64(&ptr, end, &cu->debug_abbrev_offset) == -1)
			return -1;
	}

	return read_u8(&ptr, end, &cu->address_size);
}

static int read_cus(DwarfIndex *self, struct file *file, size_t *cus_capacity)
{
	const struct section *debug_info = &file->debug_sections[DEBUG_INFO];
	const char *ptr = debug_info->buffer;
	const char *debug_info_end = &ptr[debug_info->size];

	while (ptr < debug_info_end) {
		struct compilation_unit *cu;

		if (self->num_cus >= *cus_capacity) {
			if (*cus_capacity == 0)
				*cus_capacity = 1;
			else
				*cus_capacity *= 2;
			if (realloc_cus(&self->cus, *cus_capacity) == -1)
				return -1;
		}

		cu = &self->cus[self->num_cus++];

		if (read_compilation_unit_header(ptr, debug_info_end, cu) == -1)
			return -1;
		cu->ptr = ptr;
		cu->file = file;
		self->address_size = cu->address_size;

		ptr += (cu->is_64_bit ? 12 : 4) + cu->unit_length;
	}
	return 0;
}

static int read_abbrev_decl(const char **ptr, const char *end,
			    const struct compilation_unit *cu,
			    struct abbrev_table *table, size_t *decls_capacity,
			    size_t *num_cmds, size_t *cmds_capacity)
{
	uint8_t children;
	uint64_t code;
	uint64_t tag;
	bool first = true;

	if (read_uleb128(ptr, end, &code) == -1)
		return -1;
	if (code == 0)
		return 0;
	if (code != table->num_decls + 1) {
		PyErr_SetString(PyExc_NotImplementedError,
				"abbreviation table is not sequential");
		return -1;
	}

	if (table->num_decls >= *decls_capacity) {
		uint32_t *tmp;

		if (*decls_capacity == 0)
			*decls_capacity = 1;
		else
			*decls_capacity *= 2;
		tmp = realloc(table->decls, *decls_capacity * sizeof(uint32_t));
		if (!tmp) {
			PyErr_NoMemory();
			return -1;
		}
		table->decls = tmp;
	}

	table->decls[table->num_decls++] = *num_cmds;

	if (read_uleb128(ptr, end, &tag) == -1)
		return -1;
	if (tag != DW_TAG_base_type &&
	    tag != DW_TAG_class_type &&
	    tag != DW_TAG_enumeration_type &&
	    tag != DW_TAG_structure_type &&
	    tag != DW_TAG_typedef &&
	    tag != DW_TAG_union_type &&
	    tag != DW_TAG_variable)
		tag = 0;
	if (read_u8(ptr, end, &children) == -1)
		return -1;

	for (;;) {
		uint64_t name, form;
		uint8_t cmd;

		if (read_uleb128(ptr, end, &name) == -1)
			return -1;
		if (read_uleb128(ptr, end, &form) == -1)
			return -1;
		if (name == 0 && form == 0)
			break;

		if (name == DW_AT_sibling) {
			switch (form) {
			case DW_FORM_ref1:
				cmd = ATTRIB_SIBLING_REF1;
				goto append_cmd;
			case DW_FORM_ref2:
				cmd = ATTRIB_SIBLING_REF2;
				goto append_cmd;
			case DW_FORM_ref4:
				cmd = ATTRIB_SIBLING_REF4;
				goto append_cmd;
			case DW_FORM_ref8:
				cmd = ATTRIB_SIBLING_REF8;
				goto append_cmd;
			case DW_FORM_ref_udata:
				cmd = ATTRIB_SIBLING_REF_UDATA;
				goto append_cmd;
			default:
				break;
			}
		} else if (name == DW_AT_name && tag) {
			switch (form) {
			case DW_FORM_strp:
				if (cu->is_64_bit)
					cmd = ATTRIB_NAME_STRP8;
				else
					cmd = ATTRIB_NAME_STRP4;
				goto append_cmd;
			case DW_FORM_string:
				cmd = ATTRIB_NAME_STRING;
				goto append_cmd;
			default:
				break;
			}
		} else if (name == DW_AT_declaration &&
			   tag != DW_TAG_variable) {
			/*
			 * Ignore type declarations. In theory, this could be
			 * DW_FORM_flag with a value of zero, but in practice,
			 * GCC always uses DW_FORM_flag_present.
			 */
			tag = 0;
		}

		switch (form) {
		case DW_FORM_addr:
			cmd = cu->address_size;
			break;
		case DW_FORM_data1:
		case DW_FORM_ref1:
		case DW_FORM_flag:
			cmd = 1;
			break;
		case DW_FORM_data2:
		case DW_FORM_ref2:
			cmd = 2;
			break;
		case DW_FORM_data4:
		case DW_FORM_ref4:
			cmd = 4;
			break;
		case DW_FORM_data8:
		case DW_FORM_ref8:
		case DW_FORM_ref_sig8:
			cmd = 8;
			break;
		case DW_FORM_block1:
			cmd = ATTRIB_BLOCK1;
			goto append_cmd;
		case DW_FORM_block2:
			cmd = ATTRIB_BLOCK2;
			goto append_cmd;
		case DW_FORM_block4:
			cmd = ATTRIB_BLOCK4;
			goto append_cmd;
		case DW_FORM_exprloc:
			cmd = ATTRIB_EXPRLOC;
			goto append_cmd;
		case DW_FORM_sdata:
		case DW_FORM_udata:
		case DW_FORM_ref_udata:
			cmd = ATTRIB_LEB128;
			goto append_cmd;
		case DW_FORM_ref_addr:
		case DW_FORM_sec_offset:
		case DW_FORM_strp:
			cmd = cu->is_64_bit ? 8 : 4;
			break;
		case DW_FORM_string:
			cmd = ATTRIB_STRING;
			goto append_cmd;
		case DW_FORM_flag_present:
			continue;
		case DW_FORM_indirect:
			PyErr_SetString(PyExc_NotImplementedError,
					"DW_FORM_indirect is not implemented");
			return -1;
		default:
			PyErr_Format(DwarfFormatError,
				     "unknown attribute form %" PRIu64, form);
			return -1;
		}

		if (!first && table->cmds[*num_cmds - 1] < ATTRIB_MIN_CMD) {
			if ((uint16_t)table->cmds[*num_cmds - 1] + cmd < ATTRIB_MIN_CMD) {
				table->cmds[*num_cmds - 1] += cmd;
				continue;
			} else {
				cmd = (uint16_t)table->cmds[*num_cmds - 1] + cmd - ATTRIB_MIN_CMD + 1;
				table->cmds[*num_cmds - 1] = ATTRIB_MIN_CMD - 1;
			}
		}

append_cmd:
		first = false;
		if (*num_cmds + 2 >= *cmds_capacity) {
			uint8_t *tmp;

			if (*cmds_capacity == 0)
				*cmds_capacity = 32;
			else
				*cmds_capacity *= 2;
			tmp = realloc(table->cmds,
				      *cmds_capacity * sizeof(uint8_t));
			if (!tmp) {
				PyErr_NoMemory();
				return -1;
			}
			table->cmds = tmp;
		}
		table->cmds[(*num_cmds)++] = cmd;
	}
	table->cmds[(*num_cmds)++] = 0;
	/* Low bits are the tag, high bit is the children flag. */
	table->cmds[(*num_cmds)++] = tag | ((!!children) << 7);

	return 1;
}

static int read_abbrev_table(const char *ptr, const char *end,
			     const struct compilation_unit *cu,
			     struct abbrev_table *table)
{
	size_t decls_capacity = 0;
	size_t num_cmds = 0;
	size_t cmds_capacity = 0;

	table->decls = NULL;
	table->num_decls = 0;
	table->cmds = NULL;

	for (;;) {
		int ret;

		ret = read_abbrev_decl(&ptr, end, cu, table, &decls_capacity,
				       &num_cmds, &cmds_capacity);
		if (ret != 1)
			return ret;
	}
}

/* DJBX33A hash function */
static inline uint32_t name_hash(const char *name)
{
	uint32_t hash = 5381;
	const uint8_t *p = (const uint8_t *)name;

	while (*p)
		hash = ((hash << 5) + hash) + *p++;
	return hash;
}

static int add_die_hash_entry(DwarfIndex *self, const char *name, uint64_t tag,
			      struct compilation_unit *cu, const char *ptr)
{
	struct die_hash_entry *entry;
	uint32_t i, orig_i;

	i = orig_i = name_hash(name) & DIE_HASH_MASK;
	for (;;) {
		const char *entry_name;
		uint64_t entry_tag;

		entry = &self->die_hash[i];
		entry_name = __atomic_load_n(&entry->name, __ATOMIC_SEQ_CST);
		if (!entry_name &&
		    __atomic_compare_exchange_n(&entry->name, &entry_name, name,
						false, __ATOMIC_SEQ_CST,
						__ATOMIC_SEQ_CST)) {
			__atomic_store_n(&entry->tag, tag, __ATOMIC_SEQ_CST);
			entry->cu = cu;
			entry->ptr = ptr;
			return 0;
		}
		do {
			entry_tag = __atomic_load_n(&entry->tag,
						    __ATOMIC_SEQ_CST);
		} while (!entry_tag);
		if (tag == entry_tag && strcmp(name, entry_name) == 0)
			return 0;
		i = (i + 1) & DIE_HASH_MASK;
		if (i == orig_i) {
			PyErr_NoMemory();
			return -1;
		}
	}
}

static int index_cu(DwarfIndex *self, struct compilation_unit *cu)
{
	struct abbrev_table abbrev_table;
	const struct section *debug_abbrev = &cu->file->debug_sections[DEBUG_ABBREV];
	const char *debug_abbrev_end = &debug_abbrev->buffer[debug_abbrev->size];
	const char *ptr = &cu->ptr[cu->is_64_bit ? 23 : 11];
	const char *end = &cu->ptr[(cu->is_64_bit ? 12 : 4) + cu->unit_length];
	const struct section *debug_str = &cu->file->debug_sections[DEBUG_STR];
	const char *debug_str_buffer = debug_str->buffer;
	const char *debug_str_end = &debug_str_buffer[debug_str->size];
	unsigned int depth = 0;

	if (read_abbrev_table(&debug_abbrev->buffer[cu->debug_abbrev_offset],
			      debug_abbrev_end, cu, &abbrev_table) == -1)
		goto err;

	for (;;) {
		const char *die_ptr = ptr;
		const char *sibling = NULL;
		const char *name = NULL;
		uint64_t code;
		uint8_t *cmdp;
		uint8_t cmd;
		uint64_t tag;

		if (read_uleb128(&ptr, end, &code) == -1)
			goto err;
		if (code == 0) {
			if (!--depth)
				break;
			continue;
		}

		if (code < 1 || code > abbrev_table.num_decls) {
			PyErr_Format(DwarfFormatError,
				     "unknown abbreviation code %" PRIu64,
				     code);
			goto err;
		}
		cmdp = &abbrev_table.cmds[abbrev_table.decls[code - 1]];

		while ((cmd = *cmdp++)) {
			uint64_t skip;
			uint64_t tmp;

			switch (cmd) {
			case ATTRIB_BLOCK1:
				if (read_u8_into_size_t(&ptr, end, &skip) == -1)
					goto err;
				goto skip;
			case ATTRIB_BLOCK2:
				if (read_u16_into_size_t(&ptr, end, &skip) == -1)
					goto err;
				goto skip;
			case ATTRIB_BLOCK4:
				if (read_u32_into_size_t(&ptr, end, &skip) == -1)
					goto err;
				goto skip;
			case ATTRIB_EXPRLOC:
				if (read_uleb128_into_size_t(&ptr, end, &skip) == -1)
					goto err;
				goto skip;
			case ATTRIB_LEB128:
				for (;;) {
					if (ptr >= end) {
						PyErr_SetNone(PyExc_EOFError);
						goto err;
					}
					if (!(*(const uint8_t *)ptr++ & 0x80))
						break;
				}
				break;
			case ATTRIB_NAME_STRING:
				name = ptr;
				/* fallthrough */
			case ATTRIB_STRING:
				{
					const char *nul;

					if (ptr >= end) {
						PyErr_SetNone(PyExc_EOFError);
						goto err;
					}
					nul = memchr(ptr, 0, end - ptr);
					if (!nul) {
						PyErr_SetNone(PyExc_EOFError);
						goto err;
					}
					ptr = nul + 1;
				}
				break;
			case ATTRIB_SIBLING_REF1:
				if (read_u8_into_size_t(&ptr, end, &tmp) == -1)
					goto err;
				goto sibling;
			case ATTRIB_SIBLING_REF2:
				if (read_u16_into_size_t(&ptr, end, &tmp) == -1)
					goto err;
				goto sibling;
			case ATTRIB_SIBLING_REF4:
				if (read_u32_into_size_t(&ptr, end, &tmp) == -1)
					goto err;
				goto sibling;
			case ATTRIB_SIBLING_REF8:
				if (read_u64_into_size_t(&ptr, end, &tmp) == -1)
					goto err;
				goto sibling;
			case ATTRIB_SIBLING_REF_UDATA:
				if (read_uleb128_into_size_t(&ptr, end, &tmp) == -1)
					goto err;
sibling:
				if (!in_bounds(cu->ptr, end, tmp)) {
					PyErr_SetNone(PyExc_EOFError);
					goto err;
				}
				sibling = &cu->ptr[tmp];
				__builtin_prefetch(sibling);
				break;
			case ATTRIB_NAME_STRP4:
				if (read_u32_into_size_t(&ptr, end, &tmp) == -1)
					goto err;
				goto strp;
			case ATTRIB_NAME_STRP8:
				if (read_u64_into_size_t(&ptr, end, &tmp) == -1)
					goto err;
strp:
				if (!in_bounds(debug_str_buffer, debug_str_end, tmp)) {
					PyErr_SetNone(PyExc_EOFError);
					goto err;
				}
				name = &debug_str_buffer[tmp];
				__builtin_prefetch(name);
				break;
			default:
				skip = cmd;
skip:
				if (!in_bounds(ptr, end, skip)) {
					PyErr_SetNone(PyExc_EOFError);
					goto err;
				}
				ptr += skip;
				break;
			}
		}

		tag = *cmdp & 0x7f;
		if (depth == 1 && name && tag) {
			if (add_die_hash_entry(self, name, tag, cu, die_ptr) == -1)
				goto err;
		}

		/* High bit set means this DIE has children. */
		if (*cmdp & 0x80) {
			if (sibling)
				ptr = sibling;
			else
				depth++;
		} else if (depth == 0) {
			break;
		}
	}

	free(abbrev_table.decls);
	free(abbrev_table.cmds);
	return 0;

err:
	free(abbrev_table.decls);
	free(abbrev_table.cmds);
	return -1;
}

static void DwarfIndex_dealloc(DwarfIndex *self)
{
	size_t i;

	for (i = 0; i < self->num_files; i++) {
		munmap(self->files[i].map, self->files[i].size);
		Py_XDECREF(self->files[i].obj);
		Py_XDECREF(self->files[i].cu_objs);
	}
	free(self->files);
	free(self->cus);

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int apply_all_relocations(DwarfIndex *self)
{
	PyObject *type = NULL, *value = NULL, *traceback = NULL;
	size_t total_num_relocs;
	size_t i;

	Py_BEGIN_ALLOW_THREADS

	total_num_relocs = 0;
	for (i = 0; i < self->num_files; i++) {
		size_t j;

		for (j = 0; j < NUM_DEBUG_SECTIONS; j++) {
			total_num_relocs += (self->files[i].rela_sections[j].size /
					     sizeof(Elf64_Rela));
		}
	}

#pragma omp parallel
	{
		PyGILState_STATE state = PyGILState_Ensure();
		size_t file_idx, section_idx = 0, reloc_idx = 0;
		size_t i;
		bool first = true;
		size_t num_relocs = 0;

		Py_BEGIN_ALLOW_THREADS

#pragma omp for
		for (i = 0; i < total_num_relocs; i++) {
			if (type)
				continue;
			if (first) {
				size_t cur = 0;

				for (file_idx = 0; file_idx < self->num_files; file_idx++) {
					for (section_idx = 0; section_idx < NUM_DEBUG_SECTIONS; section_idx++) {
						num_relocs = (self->files[file_idx].rela_sections[section_idx].size /
							      sizeof(Elf64_Rela));
						if (cur + num_relocs > i) {
							reloc_idx = i - cur;
							goto done;
						} else {
							cur += num_relocs;
						}
					}
				}
done:
				first = false;
			}

			if (apply_relocation(&self->files[file_idx].debug_sections[section_idx],
					     &self->files[file_idx].rela_sections[section_idx],
					     &self->files[file_idx].symtab, reloc_idx) == -1) {
				Py_BLOCK_THREADS
				if (type)
					PyErr_Clear();
				else
					PyErr_Fetch(&type, &value, &traceback);
				Py_UNBLOCK_THREADS
				continue;
			}

			if (file_idx < self->num_files) {
				reloc_idx++;
				while (reloc_idx >= num_relocs) {
					reloc_idx = 0;
					if (++section_idx >= NUM_DEBUG_SECTIONS) {
						section_idx = 0;
						if (++file_idx >= self->num_files)
							break;
					}
					num_relocs = (self->files[file_idx].rela_sections[section_idx].size /
						      sizeof(Elf64_Rela));
				}
			}
		}

		Py_END_ALLOW_THREADS

		PyGILState_Release(state);
	}

	Py_END_ALLOW_THREADS

	if (type) {
		PyErr_Restore(type, value, traceback);
		return -1;
	}
	return 0;
}

static int index_cus(DwarfIndex *self)
{
	PyObject *type = NULL, *value = NULL, *traceback = NULL;

	Py_BEGIN_ALLOW_THREADS

#pragma omp parallel
	{
		PyGILState_STATE state = PyGILState_Ensure();
		size_t i;

		Py_BEGIN_ALLOW_THREADS

#pragma omp for schedule(dynamic)
		for (i = 0; i < self->num_cus; i++) {
			if (type)
				continue;
			if (index_cu(self, &self->cus[i]) == -1) {
				Py_BLOCK_THREADS
				if (type)
					PyErr_Clear();
				else
					PyErr_Fetch(&type, &value, &traceback);
				Py_UNBLOCK_THREADS
			}
		}

		Py_END_ALLOW_THREADS

		PyGILState_Release(state);
	}

	Py_END_ALLOW_THREADS

	if (type) {
		PyErr_Restore(type, value, traceback);
		return -1;
	}
	return 0;
}

static int DwarfIndex_init(DwarfIndex *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"paths", NULL};
	PyObject *paths;
	size_t cus_capacity = 0;
	size_t i;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:DwarfIndex",
					 keywords, &PyList_Type, &paths))
		return -1;

	self->num_files = PyList_GET_SIZE(paths);
	self->files = calloc(self->num_files, sizeof(self->files[0]));
	if (!self->files) {
		self->num_files = 0;
		PyErr_NoMemory();
		return -1;
	}

	for (i = 0; i < self->num_files; i++) {
		PyObject *path;

		self->files[i].cu_objs = PyDict_New();
		if (!self->files[i].cu_objs)
			return -1;

		path = PyUnicode_EncodeFSDefault(PyList_GET_ITEM(paths, i));
		if (!path)
			return -1;
		if (open_file(&self->files[i], PyBytes_AS_STRING(path))) {
			PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,
							     PyList_GET_ITEM(paths, i));
			Py_DECREF(path);
			return -1;
		}
		Py_DECREF(path);

		if (read_sections(&self->files[i]) == -1)
			return -1;
	}

	if (apply_all_relocations(self) == -1)
		return -1;


	for (i = 0; i < self->num_files; i++) {
		const struct section *debug_str;

		debug_str = &self->files[i].debug_sections[DEBUG_STR];
		if (debug_str->size == 0 ||
		    debug_str->buffer[debug_str->size - 1] != '\0') {
			PyErr_SetString(DwarfFormatError,
					".debug_str is not null terminated");
			return -1;
		}

		if (read_cus(self, &self->files[i], &cus_capacity) == -1)
			return -1;
	}

	return index_cus(self);
}

static PyObject *create_file_object(DwarfIndex *self, struct file *file)
{
	PyObject *file_obj = NULL;
	PyObject *sections;
	int i;

	sections = PyDict_New();
	if (!sections)
		return NULL;

	for (i = 0; i < NUM_DEBUG_SECTIONS; i++) {
		PyObject *mview;

		/* XXX: need to reference count self */
		mview = PyMemoryView_FromMemory(file->debug_sections[i].buffer,
						file->debug_sections[i].size,
						PyBUF_READ);
		if (!mview)
			goto out;

		if (PyDict_SetItemString(sections, section_names[i],
					 mview) == -1) {
			Py_DECREF(mview);
			goto out;
		}
		Py_DECREF(mview);
	}

	file_obj = PyObject_CallFunctionObjArgs(DwarfFile, sections, NULL);
out:
	Py_DECREF(sections);
	return file_obj;
}

static PyObject *DwarfIndex_find(DwarfIndex *self, PyObject *args, PyObject
				 *kwds)
{
	static char *keywords[] = {"name", "tag", NULL};
	struct die_hash_entry *entry;
	const char *name;
	PyObject *method_name;
	PyObject *cu_offset;
	PyObject *cu_obj;
	PyObject *die_offset;
	PyObject *die_obj;
	unsigned long long tag;
	uint32_t i, orig_i;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "sK:find", keywords, &name,
					 &tag))
		return NULL;

	i = orig_i = name_hash(name) & DIE_HASH_MASK;
	for (;;) {
		entry = &self->die_hash[i];
		if (!entry->name) {
			entry = NULL;
			break;
		}
		if (entry->tag == tag && strcmp(entry->name, name) == 0)
			break;
		i = (i + 1) & DIE_HASH_MASK;
		if (i == orig_i) {
			entry = NULL;
			break;
		}
	}
	if (!entry) {
		PyErr_SetString(PyExc_ValueError, "DIE not found");
		return NULL;
	}

	cu_offset = PyLong_FromUnsignedLongLong(entry->cu->ptr -
						entry->cu->file->debug_sections[DEBUG_INFO].buffer);
	if (!cu_offset)
		return NULL;
	cu_obj = PyDict_GetItem(entry->cu->file->cu_objs, cu_offset);
	if (!cu_obj) {
		if (!entry->cu->file->obj) {
			entry->cu->file->obj = create_file_object(self,
								  entry->cu->file);
			if (!entry->cu->file->obj)
				return NULL;
		}

		method_name = PyUnicode_FromString("compilation_unit");
		cu_obj = PyObject_CallMethodObjArgs(entry->cu->file->obj,
						    method_name, cu_offset,
						    NULL);
		Py_DECREF(method_name);
		if (!cu_obj) {
			Py_DECREF(cu_offset);
			return NULL;
		}

		if (PyDict_SetItem(entry->cu->file->cu_objs, cu_offset,
				   cu_obj) == -1) {
			Py_DECREF(cu_offset);
			Py_DECREF(cu_obj);
			return NULL;
		}
		Py_DECREF(cu_obj);
	}
	Py_DECREF(cu_offset);

	die_offset = PyLong_FromUnsignedLongLong(entry->ptr - entry->cu->ptr);
	if (!die_offset)
		return NULL;

	method_name = PyUnicode_FromString("die");
	if (!method_name) {
		Py_DECREF(die_offset);
		return NULL;
	}
	die_obj = PyObject_CallMethodObjArgs(cu_obj, method_name, die_offset,
					     NULL);
	Py_DECREF(method_name);
	Py_DECREF(die_offset);
	return die_obj;
}

#define DwarfIndex_DOC	\
	"DwarfIndex(paths) -> new DWARF debugging information index"

static PyMethodDef DwarfIndex_methods[] = {
	{"find", (PyCFunction)DwarfIndex_find,
	 METH_VARARGS | METH_KEYWORDS,
	 "find(name, tag)\n\n"
	 "Find an indexed DWARF DIE.\n\n"
	 "Arguments:\n"
	 "name -- string name of the DIE\n"
	 "tag -- int tag of the DIE"},
	{},
};

static PyMemberDef DwarfIndex_members[] = {
	{"address_size", T_INT, offsetof(DwarfIndex, address_size),
	 READONLY, "size in bytes of a pointer"},
	{},
};

static PyTypeObject DwarfIndex_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.dwarfindex.DwarfIndex",	/* tp_name */
	sizeof(DwarfIndex),		/* tp_basicsize */
	0,				/* tp_itemsize */
	(destructor)DwarfIndex_dealloc,	/* tp_dealloc */
	NULL,				/* tp_print */
	NULL,				/* tp_getattr */
	NULL,				/* tp_setattr */
	NULL,				/* tp_as_async */
	NULL,				/* tp_repr */
	NULL,				/* tp_as_number */
	NULL,				/* tp_as_sequence */
	NULL,				/* tp_as_mapping */
	NULL,				/* tp_hash  */
	NULL,				/* tp_call */
	NULL,				/* tp_str */
	NULL,				/* tp_getattro */
	NULL,				/* tp_setattro */
	NULL,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */
	DwarfIndex_DOC,			/* tp_doc */
	NULL,				/* tp_traverse */
	NULL,				/* tp_clear */
	NULL,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	NULL,				/* tp_iter */
	NULL,				/* tp_iternext */
	DwarfIndex_methods,		/* tp_methods */
	DwarfIndex_members,		/* tp_members */
	NULL,				/* tp_getset */
	NULL,				/* tp_base */
	NULL,				/* tp_dict */
	NULL,				/* tp_descr_get */
	NULL,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc)DwarfIndex_init,	/* tp_init */
};

static struct PyModuleDef dwarfindexmodule = {
	PyModuleDef_HEAD_INIT,
	"dwarfindex",
	"Fast DWARF debugging information index",
	-1,
};

PyMODINIT_FUNC
PyInit_dwarfindex(void)
{
	PyObject *name;
	PyObject *m;

	PyEval_InitThreads();

	name = PyUnicode_FromString("drgn.dwarf");
	if (!name)
		return NULL;

	m = PyImport_Import(name);
	Py_DECREF(name);
	if (!m)
		return NULL;

	DwarfFile = PyObject_GetAttrString(m, "DwarfFile");
	if (!DwarfFile) {
		Py_DECREF(m);
		return NULL;
	}
	DwarfFormatError = PyObject_GetAttrString(m, "DwarfFormatError");
	if (!DwarfFormatError) {
		Py_DECREF(m);
		return NULL;
	}
	Py_DECREF(m);

	name = PyUnicode_FromString("drgn.elf");
	if (!name)
		return NULL;

	m = PyImport_Import(name);
	Py_DECREF(name);
	if (!m)
		return NULL;

	ElfFormatError = PyObject_GetAttrString(m, "ElfFormatError");
	if (!ElfFormatError) {
		Py_DECREF(m);
		return NULL;
	}
	Py_DECREF(m);

	m = PyModule_Create(&dwarfindexmodule);
	if (!m)
		return NULL;

	DwarfIndex_type.tp_new = PyType_GenericNew;
	if (PyType_Ready(&DwarfIndex_type) < 0)
		return NULL;
	Py_INCREF(&DwarfIndex_type);
	PyModule_AddObject(m, "DwarfIndex", (PyObject *)&DwarfIndex_type);

	return m;
}
