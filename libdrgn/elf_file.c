// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <elf.h>
#include <gelf.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "drgn.h"
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
	if ((shdr->sh_flags & SHF_COMPRESSED) && elf_compress(scn, 0, 0) < 0)
		return drgn_error_libelf();
	Elf_Data *data = elf_rawdata(scn, NULL);
	if (!data)
		return drgn_error_libelf();
	*ret = data;
	return NULL;
}

#include "drgn_section_name_to_index.inc"

enum drgn_dwarf_file_type {
	DRGN_DWARF_FILE_NONE,
	DRGN_DWARF_FILE_GNU_LTO,
	DRGN_DWARF_FILE_DWO,
	DRGN_DWARF_FILE_PLAIN,
};

struct drgn_error *drgn_elf_file_create(struct drgn_module *module,
					const char *path, Elf *elf,
					struct drgn_elf_file **ret)
{
	struct drgn_error *err;
	GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr)
		return drgn_error_libelf();
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	struct drgn_elf_file *file = calloc(1, sizeof(*file));
	if (!file)
		return &drgn_enomem;
	file->module = module;
	file->path = path;
	file->elf = elf;
	drgn_platform_from_elf(ehdr, &file->platform);

	// We mimic libdw's logic for choosing debug sections: we either use all
	// .debug_* or .zdebug_* sections (DRGN_DWARF_FILE_PLAIN), all
	// .debug_*.dwo or .zdebug_*.dwo sections (DRGN_DWARF_FILE_DWO), or all
	// .gnu.debuglto_.debug_* sections (DRGN_DWARF_FILE_GNU_LTO), in that
	// order of preference.
	enum drgn_dwarf_file_type dwarf_file_type = DRGN_DWARF_FILE_NONE;
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr) {
			err = drgn_error_libelf();
			goto err;
		}
		const char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname) {
			err = drgn_error_libelf();
			goto err;
		}

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
		if (!shdr) {
			err = drgn_error_libelf();
			goto err;
		}

		if (shdr->sh_type != SHT_PROGBITS)
			continue;

		const char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname) {
			err = drgn_error_libelf();
			goto err;
		}

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
		} else {
			index = drgn_non_debug_section_name_to_index(scnname);
		}
		if (index < DRGN_SECTION_INDEX_NUM && !file->scns[index])
			file->scns[index] = scn;
	}
	*ret = file;
	return NULL;

err:
	free(file);
	return err;
}

void drgn_elf_file_destroy(struct drgn_elf_file *file)
{
	free(file);
}

static void truncate_null_terminated_section(Elf_Data *data)
{
	if (data) {
		const char *buf = data->d_buf;
		const char *nul = memrchr(buf, '\0', data->d_size);
		if (nul)
			data->d_size = nul - buf + 1;
		else
			data->d_size = 0;
	}
}

struct drgn_error *drgn_elf_file_precache_sections(struct drgn_elf_file *file)
{
	struct drgn_error *err;

	for (size_t i = 0; i < DRGN_SECTION_INDEX_NUM_PRECACHE; i++) {
		if (file->scns[i]) {
			err = read_elf_section(file->scns[i],
					       &file->scn_data[i]);
			if (err)
				return err;
		}
	}

	/*
	 * Truncate any extraneous bytes so that we can assume that a pointer
	 * within .debug_{,line_}str is always null-terminated.
	 */
	truncate_null_terminated_section(file->scn_data[DRGN_SCN_DEBUG_STR]);
	truncate_null_terminated_section(file->alt_debug_str_data);
	return NULL;
}

struct drgn_error *
drgn_elf_file_cache_section(struct drgn_elf_file *file, enum drgn_section_index scn)
{
	if (file->scn_data[scn])
		return NULL;
	return read_elf_section(file->scns[scn], &file->scn_data[scn]);
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

bool next_elf_note(const void **p, size_t *size, unsigned int align, bool bswap,
		   Elf32_Nhdr *nhdr_ret, const char **name_ret,
		   const void **desc_ret)
{
	uint64_t align_mask = align - 1;

	if (*size < sizeof(*nhdr_ret))
		return false;
	memcpy(nhdr_ret, *p, sizeof(*nhdr_ret));
	if (bswap) {
		nhdr_ret->n_namesz = bswap_32(nhdr_ret->n_namesz);
		nhdr_ret->n_descsz = bswap_32(nhdr_ret->n_descsz);
		nhdr_ret->n_type = bswap_32(nhdr_ret->n_type);
	}

	if (nhdr_ret->n_namesz > *size - sizeof(*nhdr_ret))
		return false;
	uint64_t aligned_namesz = (nhdr_ret->n_namesz + align_mask) & ~align_mask;
	if (nhdr_ret->n_descsz > 0
	    && (aligned_namesz > *size - sizeof(*nhdr_ret)
		|| nhdr_ret->n_descsz > *size - sizeof(*nhdr_ret) - aligned_namesz))
	    return false;

	*p = (const char *)*p + sizeof(*nhdr_ret);
	*size -= sizeof(*nhdr_ret);

	*name_ret = *p;
	if (aligned_namesz > *size) {
		*p = (const char *)*p + *size;
		*size = 0;
	} else {
		*p = (const char *)*p + aligned_namesz;
		*size -= aligned_namesz;
	}

	*desc_ret = *p;
	uint64_t aligned_descsz = (nhdr_ret->n_descsz + align_mask) & ~align_mask;
	if (aligned_descsz > *size) {
		*p = (const char *)*p + *size;
		*size = 0;
	} else {
		*p = (const char *)*p + aligned_descsz;
		*size -= aligned_descsz;
	}

	return true;
}
