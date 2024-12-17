// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <byteswap.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <gelf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "array.h"
#include "debug_info.h"
#include "drgn_internal.h"
#include "elf_file.h"
#include "error.h"
#include "minmax.h"
#include "util.h"

struct drgn_error *read_elf_section(Elf_Scn *scn, Elf_Data **ret)
{
	GElf_Shdr shdr_mem, *shdr;
	shdr = gelf_getshdr(scn, &shdr_mem);
	if (!shdr)
		return drgn_error_libelf();
	if (shdr->sh_type == SHT_NOBITS) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "section has no data");
	}
	if ((shdr->sh_flags & SHF_COMPRESSED) && elf_compress(scn, 0, 0) < 0)
		return drgn_error_libelf();
	Elf_Data *data = elf_rawdata(scn, NULL);
	if (!data)
		return drgn_error_libelf();
	*ret = data;
	return NULL;
}

void truncate_elf_string_data(Elf_Data *data)
{
	const char *buf = data->d_buf;
	const char *nul = memrchr(buf, '\0', data->d_size);
	if (nul)
		data->d_size = nul - buf + 1;
	else
		data->d_size = 0;
}

#include "drgn_section_name_to_index.inc"

enum drgn_dwarf_file_type {
	DRGN_DWARF_FILE_NONE,
	DRGN_DWARF_FILE_GNU_LTO,
	DRGN_DWARF_FILE_DWO,
	DRGN_DWARF_FILE_PLAIN,
};

struct drgn_error *drgn_elf_file_create(struct drgn_module *module,
					const char *path, int fd, char *image,
					Elf *elf, struct drgn_elf_file **ret)
{
	if (elf_kind(elf) != ELF_K_ELF)
		return drgn_error_create(DRGN_ERROR_OTHER, "not an ELF file");

	GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr)
		return drgn_error_libelf();

	_cleanup_free_ struct drgn_elf_file *file = calloc(1, sizeof(*file));
	if (!file)
		return &drgn_enomem;

	if (ehdr->e_type == ET_EXEC ||
	    ehdr->e_type == ET_DYN ||
	    ehdr->e_type == ET_REL) {
		size_t shstrndx;
		if (elf_getshdrstrndx(elf, &shstrndx))
			return drgn_error_libelf();

		bool has_sections = false;
		bool has_alloc_section = false;
		// We mimic libdw's logic for choosing debug sections: we either
		// use all .debug_* or .zdebug_* sections
		// (DRGN_DWARF_FILE_PLAIN), all .debug_*.dwo or .zdebug_*.dwo
		// sections (DRGN_DWARF_FILE_DWO), or all .gnu.debuglto_.debug_*
		// sections (DRGN_DWARF_FILE_GNU_LTO), in that order of
		// preference.
		enum drgn_dwarf_file_type dwarf_file_type = DRGN_DWARF_FILE_NONE;
		Elf_Scn *scn = NULL;
		while ((scn = elf_nextscn(elf, scn))) {
			GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
			if (!shdr)
				return drgn_error_libelf();

			has_sections = true;
			if (shdr->sh_type != SHT_NOBITS &&
			    shdr->sh_type != SHT_NOTE &&
			    (shdr->sh_flags & SHF_ALLOC))
				has_alloc_section = true;

			const char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
			if (!scnname)
				return drgn_error_libelf();

			enum drgn_dwarf_file_type dwarf_section_type;
			if (strcmp(scnname, ".debug_cu_index") == 0 ||
			    strcmp(scnname, ".debug_tu_index") == 0) {
				dwarf_section_type = DRGN_DWARF_FILE_DWO;
			} else if (strstartswith(scnname, ".debug_") ||
				   strstartswith(scnname, ".zdebug_")) {
				if (strcmp(scnname + strlen(scnname) - 4, ".dwo") == 0)
					dwarf_section_type = DRGN_DWARF_FILE_DWO;
				else
					dwarf_section_type = DRGN_DWARF_FILE_PLAIN;
			} else if (strstartswith(scnname, ".gnu.debuglto_.debug")) {
				dwarf_section_type = DRGN_DWARF_FILE_GNU_LTO;
			} else {
				dwarf_section_type = DRGN_DWARF_FILE_NONE;
			}
			dwarf_file_type = max(dwarf_file_type, dwarf_section_type);
		}

		scn = NULL;
		while ((scn = elf_nextscn(elf, scn))) {
			GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
			if (!shdr)
				return drgn_error_libelf();

			if (shdr->sh_type != SHT_PROGBITS)
				continue;

			const char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
			if (!scnname)
				return drgn_error_libelf();

			enum drgn_section_index index;
			if (strstartswith(scnname, ".debug_") ||
			    strstartswith(scnname, ".zdebug_")) {
				const char *subname;
				if (strstartswith(scnname, ".zdebug_"))
					subname = scnname + sizeof(".zdebug_") - 1;
				else
					subname = scnname + sizeof(".debug_") - 1;
				size_t len = strlen(subname);
				if (len >= 4
				    && strcmp(subname + len - 4, ".dwo") == 0) {
					if (dwarf_file_type != DRGN_DWARF_FILE_DWO)
						continue;
					len -= 4;
				} else if (dwarf_file_type != DRGN_DWARF_FILE_PLAIN) {
					continue;
				}
				index = drgn_debug_section_name_to_index(subname, len);
			} else if (strstartswith(scnname, ".gnu.debuglto_.debug_")) {
				if (dwarf_file_type != DRGN_DWARF_FILE_GNU_LTO)
					continue;
				const char *subname =
					scnname + sizeof(".gnu.debuglto_.debug_") - 1;
				index = drgn_debug_section_name_to_index(subname,
									 strlen(subname));
			} else if (strcmp(scnname, ".init.text") == 0) {
				// We consider a file to be vmlinux if it has an
				// .init.text section and is not relocatable
				// (which excludes kernel modules).
				file->is_vmlinux = ehdr->e_type != ET_REL;
				index = DRGN_SECTION_INDEX_NUM;
			} else {
				index = drgn_non_debug_section_name_to_index(scnname);
			}
			if (index < DRGN_SECTION_INDEX_NUM && !file->scns[index])
				file->scns[index] = scn;
		}

		if (ehdr->e_type == ET_REL) {
			// We consider a relocatable file "loadable" if it has
			// any allocated sections.
			file->is_loadable = has_alloc_section;
			file->is_relocatable = file->needs_relocation = true;
		} else {
			// We consider executable and shared object files
			// loadable if they have any loadable segments, and
			// either no sections or at least one allocated section.
			bool has_loadable_segment = false;
			size_t phnum;
			if (elf_getphdrnum(elf, &phnum) != 0)
				return drgn_error_libelf();
			for (size_t i = 0; i < phnum; i++) {
				GElf_Phdr phdr_mem, *phdr =
					gelf_getphdr(elf, i, &phdr_mem);
				if (!phdr)
					return drgn_error_libelf();
				if (phdr->p_type == PT_LOAD) {
					has_loadable_segment = true;
					break;
				}
			}
			file->is_loadable =
				has_loadable_segment &&
				(!has_sections || has_alloc_section);
		}
	}

	file->module = module;
	file->path = strdup(path);
	if (!file->path)
		return &drgn_enomem;
	file->image = image;
	file->fd = fd;
	file->elf = elf;
	drgn_platform_from_elf(ehdr, &file->platform);
	*ret = no_cleanup_ptr(file);
	return NULL;
}

void drgn_elf_file_destroy(struct drgn_elf_file *file)
{
	if (file) {
		dwarf_end(file->_dwarf);
		elf_end(file->elf);
		if (file->fd >= 0)
			close(file->fd);
		free(file->image);
		free(file->path);
		free(file);
	}
}

static int should_apply_relocation_section(Elf *elf, size_t shstrndx,
					   const GElf_Shdr *shdr)
{
	if (shdr->sh_type != SHT_RELA && shdr->sh_type != SHT_REL)
		return 0;

	const char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
	if (!scnname)
		return -1;
	if (shdr->sh_type == SHT_RELA) {
		if (!strstartswith(scnname, ".rela."))
			return 0;
		scnname += sizeof(".rela.") - 1;
	} else {
		if (!strstartswith(scnname, ".rel."))
			return 0;
		scnname += sizeof(".rel.") - 1;
	}
	return (strstartswith(scnname, "debug_")
		|| strstartswith(scnname, "orc_"));
}

static inline struct drgn_error *get_reloc_sym_value(const void *syms,
						     size_t num_syms,
						     const uint64_t *sh_addrs,
						     size_t shdrnum,
						     bool is_64_bit,
						     bool bswap,
						     uint32_t r_sym,
						     uint64_t *ret)
{
	if (r_sym >= num_syms) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "invalid ELF relocation symbol");
	}
	uint16_t st_shndx;
	uint64_t st_value;
	if (is_64_bit) {
		const Elf64_Sym *sym = (Elf64_Sym *)syms + r_sym;
		memcpy(&st_shndx, &sym->st_shndx, sizeof(st_shndx));
		memcpy(&st_value, &sym->st_value, sizeof(st_value));
		if (bswap) {
			st_shndx = bswap_16(st_shndx);
			st_value = bswap_64(st_value);
		}
	} else {
		const Elf32_Sym *sym = (Elf32_Sym *)syms + r_sym;
		memcpy(&st_shndx, &sym->st_shndx, sizeof(st_shndx));
		uint32_t st_value32;
		memcpy(&st_value32, &sym->st_value, sizeof(st_value32));
		if (bswap) {
			st_shndx = bswap_16(st_shndx);
			st_value32 = bswap_32(st_value32);
		}
		st_value = st_value32;
	}
	if (st_shndx >= shdrnum) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "invalid ELF symbol section index");
	}
	*ret = sh_addrs[st_shndx] + st_value;
	return NULL;
}

static struct drgn_error *
apply_elf_relas(const struct drgn_relocating_section *relocating,
		Elf_Data *reloc_data, Elf_Data *symtab_data,
		const uint64_t *sh_addrs, size_t shdrnum,
		const struct drgn_platform *platform)
{
	struct drgn_error *err;

	bool is_64_bit = drgn_platform_is_64_bit(platform);
	bool bswap = drgn_platform_bswap(platform);
	apply_elf_reloc_fn *apply_elf_reloc = platform->arch->apply_elf_reloc;

	const void *relocs = reloc_data->d_buf;
	size_t reloc_size = is_64_bit ? sizeof(Elf64_Rela) : sizeof(Elf32_Rela);
	size_t num_relocs = reloc_data->d_size / reloc_size;

	const void *syms = symtab_data->d_buf;
	size_t sym_size = is_64_bit ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
	size_t num_syms = symtab_data->d_size / sym_size;

	for (size_t i = 0; i < num_relocs; i++) {
		uint64_t r_offset;
		uint32_t r_sym;
		uint32_t r_type;
		int64_t r_addend;
		if (is_64_bit) {
			const Elf64_Rela *rela = (Elf64_Rela *)relocs + i;
			uint64_t r_info;
			memcpy(&r_offset, &rela->r_offset, sizeof(r_offset));
			memcpy(&r_info, &rela->r_info, sizeof(r_info));
			memcpy(&r_addend, &rela->r_addend, sizeof(r_addend));
			if (bswap) {
				r_offset = bswap_64(r_offset);
				r_info = bswap_64(r_info);
				r_addend = bswap_64(r_addend);
			}
			r_sym = ELF64_R_SYM(r_info);
			r_type = ELF64_R_TYPE(r_info);
		} else {
			const Elf32_Rela *rela32 = (Elf32_Rela *)relocs + i;
			uint32_t r_offset32;
			uint32_t r_info32;
			int32_t r_addend32;
			memcpy(&r_offset32, &rela32->r_offset, sizeof(r_offset32));
			memcpy(&r_info32, &rela32->r_info, sizeof(r_info32));
			memcpy(&r_addend32, &rela32->r_addend, sizeof(r_addend32));
			if (bswap) {
				r_offset32 = bswap_32(r_offset32);
				r_info32 = bswap_32(r_info32);
				r_addend32 = bswap_32(r_addend32);
			}
			r_offset = r_offset32;
			r_sym = ELF32_R_SYM(r_info32);
			r_type = ELF32_R_TYPE(r_info32);
			r_addend = r_addend32;
		}
		uint64_t sym_value;
		err = get_reloc_sym_value(syms, num_syms, sh_addrs, shdrnum,
					  is_64_bit, bswap, r_sym, &sym_value);
		if (err)
			return err;

		err = apply_elf_reloc(relocating, r_offset, r_type, &r_addend,
				      sym_value);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
apply_elf_rels(const struct drgn_relocating_section *relocating,
	       Elf_Data *reloc_data, Elf_Data *symtab_data,
	       const uint64_t *sh_addrs, size_t shdrnum,
	       const struct drgn_platform *platform)
{
	struct drgn_error *err;

	bool is_64_bit = drgn_platform_is_64_bit(platform);
	bool bswap = drgn_platform_bswap(platform);
	apply_elf_reloc_fn *apply_elf_reloc = platform->arch->apply_elf_reloc;

	const void *relocs = reloc_data->d_buf;
	size_t reloc_size = is_64_bit ? sizeof(Elf64_Rel) : sizeof(Elf32_Rel);
	size_t num_relocs = reloc_data->d_size / reloc_size;

	const void *syms = symtab_data->d_buf;
	size_t sym_size = is_64_bit ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
	size_t num_syms = symtab_data->d_size / sym_size;

	for (size_t i = 0; i < num_relocs; i++) {
		uint64_t r_offset;
		uint32_t r_sym;
		uint32_t r_type;
		if (is_64_bit) {
			const Elf64_Rel *rel = (Elf64_Rel *)relocs + i;
			uint64_t r_info;
			memcpy(&r_offset, &rel->r_offset, sizeof(r_offset));
			memcpy(&r_info, &rel->r_info, sizeof(r_info));
			if (bswap) {
				r_offset = bswap_64(r_offset);
				r_info = bswap_64(r_info);
			}
			r_sym = ELF64_R_SYM(r_info);
			r_type = ELF64_R_TYPE(r_info);
		} else {
			const Elf32_Rel *rel32 = (Elf32_Rel *)relocs + i;
			uint32_t r_offset32;
			uint32_t r_info32;
			memcpy(&r_offset32, &rel32->r_offset, sizeof(r_offset32));
			memcpy(&r_info32, &rel32->r_info, sizeof(r_info32));
			if (bswap) {
				r_offset32 = bswap_32(r_offset32);
				r_info32 = bswap_32(r_info32);
			}
			r_offset = r_offset32;
			r_sym = ELF32_R_SYM(r_info32);
			r_type = ELF32_R_TYPE(r_info32);
		}
		uint64_t sym_value;
		err = get_reloc_sym_value(syms, num_syms, sh_addrs, shdrnum,
					  is_64_bit, bswap, r_sym, &sym_value);
		if (err)
			return err;

		err = apply_elf_reloc(relocating, r_offset, r_type, NULL,
				      sym_value);
		if (err)
			return err;
	}
	return NULL;
}

struct drgn_error *
drgn_elf_file_apply_relocations(struct drgn_elf_file *file)
{
	struct drgn_error *err;

	if (!file->needs_relocation)
		return NULL;

	if (!file->platform.arch->apply_elf_reloc) {
		return drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED,
					 "relocation support is not implemented for %s architecture",
					 file->platform.arch->name);
	}

	Elf *elf = file->elf;
	size_t shdrnum;
	if (elf_getshdrnum(elf, &shdrnum))
		return drgn_error_libelf();
	_cleanup_free_ uint64_t *sh_addrs =
		calloc(shdrnum, sizeof(sh_addrs[0]));
	if (!sh_addrs && shdrnum > 0)
		return &drgn_enomem;

	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr *shdr, shdr_mem;
		shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return drgn_error_libelf();
		sh_addrs[elf_ndxscn(scn)] = shdr->sh_addr;
	}

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	Elf_Scn *reloc_scn = NULL;
	while ((reloc_scn = elf_nextscn(elf, reloc_scn))) {
		GElf_Shdr *reloc_shdr, reloc_shdr_mem;
		reloc_shdr = gelf_getshdr(reloc_scn, &reloc_shdr_mem);
		if (!reloc_shdr)
			return drgn_error_libelf();

		int r = should_apply_relocation_section(elf, shstrndx,
							reloc_shdr);
		if (r < 0)
			return drgn_error_libelf();
		if (r) {
			scn = elf_getscn(elf, reloc_shdr->sh_info);
			if (!scn)
				return drgn_error_libelf();
			GElf_Shdr *shdr, shdr_mem;
			shdr = gelf_getshdr(scn, &shdr_mem);
			if (!shdr)
				return drgn_error_libelf();
			if (shdr->sh_type == SHT_NOBITS)
				continue;

			Elf_Scn *symtab_scn = elf_getscn(elf,
							 reloc_shdr->sh_link);
			if (!symtab_scn)
				return drgn_error_libelf();
			shdr = gelf_getshdr(symtab_scn, &shdr_mem);
			if (!shdr)
				return drgn_error_libelf();
			if (shdr->sh_type == SHT_NOBITS) {
				return drgn_error_create(DRGN_ERROR_OTHER,
							 "relocation symbol table has no data");
			}

			Elf_Data *data, *reloc_data, *symtab_data;
			if ((err = read_elf_section(scn, &data))
			    || (err = read_elf_section(reloc_scn, &reloc_data))
			    || (err = read_elf_section(symtab_scn, &symtab_data)))
				return err;

			struct drgn_relocating_section relocating = {
				.buf = data->d_buf,
				.buf_size = data->d_size,
				.addr = sh_addrs[elf_ndxscn(scn)],
				.bswap = drgn_platform_bswap(&file->platform),
			};

			if (reloc_shdr->sh_type == SHT_RELA) {
				err = apply_elf_relas(&relocating, reloc_data,
						      symtab_data, sh_addrs,
						      shdrnum, &file->platform);
			} else {
				err = apply_elf_rels(&relocating, reloc_data,
						     symtab_data, sh_addrs,
						     shdrnum, &file->platform);
			}
			if (err)
				return err;
		}
	}
	file->needs_relocation = false;
	return NULL;
}

struct drgn_error *drgn_elf_file_read_section(struct drgn_elf_file *file,
					      enum drgn_section_index scn,
					      Elf_Data **ret)
{
	struct drgn_error *err;
	if (!file->scn_data[scn]) {
		err = drgn_elf_file_apply_relocations(file);
		if (err)
			return err;
		err = read_elf_section(file->scns[scn], &file->scn_data[scn]);
		if (err)
			return err;
		if (scn == DRGN_SCN_DEBUG_STR)
			truncate_elf_string_data(file->scn_data[scn]);
	}
	*ret = file->scn_data[scn];
	return NULL;
}

struct drgn_error *drgn_elf_file_get_dwarf(struct drgn_elf_file *file,
					   Dwarf **ret)
{
	struct drgn_error *err;
	if (!file->_dwarf) {
		struct drgn_elf_file *supplementary_file =
			file->module->supplementary_debug_file;
		if (supplementary_file) {
			supplementary_file->_dwarf =
				dwarf_begin_elf(supplementary_file->elf,
						DWARF_C_READ, NULL);
			if (!supplementary_file->_dwarf)
				return drgn_error_libdw();
		}

		err = drgn_elf_file_apply_relocations(file);
		if (err)
			return err;

		file->_dwarf = dwarf_begin_elf(file->elf, DWARF_C_READ, NULL);
		if (!file->_dwarf)
			return drgn_error_libdw();

		if (supplementary_file)
			dwarf_setalt(file->_dwarf, supplementary_file->_dwarf);
	}
	*ret = file->_dwarf;
	return NULL;
}

struct drgn_error *
drgn_elf_file_section_error(struct drgn_elf_file *file, Elf_Scn *scn,
			    Elf_Data *data, const char *ptr,
			    const char *message)
{
	// If we don't know what section the pointer came from, try to find it
	// in the cached sections.
	if (!scn) {
		uintptr_t p = (uintptr_t)ptr;
		for (size_t i = 0; i < array_size(file->scn_data); i++) {
			if (!file->scn_data[i])
				continue;
			uintptr_t start = (uintptr_t)file->scn_data[i]->d_buf;
			uintptr_t end = start + file->scn_data[i]->d_size;
			if (start <= p) {
				// If the pointer matches the end of a section,
				// remember the section but try to find a better
				// match.
				if (p <= end) {
					scn = file->scns[i];
					data = file->scn_data[i];
				}
				// If the pointer lies inside of the section,
				// we're done.
				if (p < end)
					break;
			}
		}
	}
	const char *scnname = NULL;
	size_t shstrndx;
	GElf_Shdr shdr_mem, *shdr;
	if (!elf_getshdrstrndx(file->elf, &shstrndx) &&
	    (shdr = gelf_getshdr(scn, &shdr_mem)))
		scnname = elf_strptr(file->elf, shstrndx, shdr->sh_name);

	if (scnname && data) {
		return drgn_error_format(DRGN_ERROR_OTHER, "%s: %s+%#tx: %s",
					 file->path, scnname,
					 ptr - (const char *)data->d_buf,
					 message);
	} else if (scnname) {
		return drgn_error_format(DRGN_ERROR_OTHER, "%s: %s: %s",
					 file->path, scnname, message);
	} else {
		return drgn_error_format(DRGN_ERROR_OTHER, "%s: %s", file->path,
					 message);
	}
}

struct drgn_error *
drgn_elf_file_section_errorf(struct drgn_elf_file *file, Elf_Scn *scn,
			     Elf_Data *data, const char *ptr,
			     const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	char *message;
	int ret = vasprintf(&message, format, ap);
	va_end(ap);
	if (ret < 0)
		return &drgn_enomem;
	struct drgn_error *err = drgn_elf_file_section_error(file, scn, data,
							     ptr, message);
	free(message);
	return err;
}

struct drgn_error *drgn_elf_file_section_buffer_error(struct binary_buffer *bb,
						      const char *ptr,
						      const char *message)
{
	struct drgn_elf_file_section_buffer *buffer =
		container_of(bb, struct drgn_elf_file_section_buffer, bb);
	return drgn_elf_file_section_error(buffer->file, buffer->scn,
					   buffer->data, ptr, message);
}

static bool elf_address_range_from_first_and_last_segment(Elf *elf,
							  uint64_t *start_ret,
							  uint64_t *end_ret)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum))
		return false;

	uint64_t start;
	GElf_Phdr phdr_mem, *phdr;
	size_t i;
	for (i = 0; i < phnum; i++) {
		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return false;
		if (phdr->p_type == PT_LOAD) {
			start = phdr->p_vaddr;
			break;
		}
	}
	if (i >= phnum) {
		*start_ret = *end_ret = 0;
		return true;
	}

	for (i = phnum; i-- > 0;) {
		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return false;

		if (phdr->p_type == PT_LOAD) {
			uint64_t end = phdr->p_vaddr + phdr->p_memsz;
			if (start < end) {
				*start_ret = start;
				*end_ret = end;
				return true;
			}
			break;
		}
	}
	*start_ret = *end_ret = 0;
	return true;
}

static bool elf_address_range_from_min_and_max_segment(Elf *elf,
						       uint64_t *start_ret,
						       uint64_t *end_ret)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum))
		return false;

	uint64_t start = UINT64_MAX, end = 0;
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return false;
		if (phdr->p_type == PT_LOAD) {
			start = min(start, phdr->p_vaddr);
			end = max(end, phdr->p_vaddr + phdr->p_memsz);
		}
	}
	if (start < end) {
		*start_ret = start;
		*end_ret = end;
	} else {
		*start_ret = *end_ret = 0;
	}
	return true;
}

bool drgn_elf_file_address_range(struct drgn_elf_file *file,
				 uint64_t *start_ret, uint64_t *end_ret)
{
	// The ELF specification says that "loadable segment entries in the
	// program header table appear in ascending order, sorted on the p_vaddr
	// member." However, this is not the case in practice.
	//
	// vmlinux on some architectures contains special segments whose
	// addresses are not meaningful and break the sorted order (e.g.,
	// segments corresponding to the .data..percpu section on x86-64 and the
	// .vectors and .stubs sections on Arm). It appears that segments in
	// vmlinux are sorted other than those special segments, and the special
	// segments are never the first or last segment.
	//
	// Userspace ELF loaders disagree about whether to assume sorted order:
	//
	// - As of Linux kernel commit 10b19249192a ("ELF: fix overflow in total
	//   mapping size calculation") (in v5.18), the Linux kernel DOES NOT
	//   assume sorting. Before that, it DOES.
	// - glibc as of v2.40 DOES assume sorting; see _dl_map_object_from_fd()
	//   in elf/dl-load.c and _dl_map_segments() in elf/dl-map-segments.h.
	// - musl as of v1.2.5 DOES NOT assume sorting; see map_library() in
	//   ldso/dynlink.c.
	//
	// So, we use a heuristic: if the file has an .init.text section, then
	// it is probably a vmlinux file, so we assume the sorted order, which
	// allows us to ignore the special segments in the middle.
	//
	// Otherwise, we don't assume the sorted order.
	if (file->is_vmlinux) {
		return elf_address_range_from_first_and_last_segment(file->elf,
								     start_ret,
								     end_ret);
	} else {
		return elf_address_range_from_min_and_max_segment(file->elf,
								  start_ret,
								  end_ret);
	}
}
