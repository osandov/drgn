// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <elf.h>
#include <gelf.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "drgn.h"
#include "elf_file.h"
#include "error.h"
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

	Elf_Scn *scn = NULL;
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
		enum drgn_section_index index =
			drgn_section_name_to_index(scnname);
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
	truncate_null_terminated_section(file->scn_data[DRGN_SCN_DEBUG_LINE_STR]);
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

struct drgn_error *drgn_elf_file_section_buffer_error(struct binary_buffer *bb,
						      const char *ptr,
						      const char *message)
{
	struct drgn_elf_file_section_buffer *buffer =
		container_of(bb, struct drgn_elf_file_section_buffer, bb);
	return drgn_elf_file_section_error(buffer->file, buffer->scn,
					   buffer->data, ptr, message);
}
