// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <byteswap.h>
#include <string.h>

#include "elf_notes.h"
#include "util.h"

bool next_elf_note(const void **p, size_t *size, unsigned int align, bool bswap,
		   GElf_Nhdr *nhdr_ret, const char **name_ret,
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

size_t parse_gnu_build_id_from_notes(const void *buf, size_t size,
				     unsigned int align, bool bswap,
				     const void **ret)
{
	GElf_Nhdr nhdr;
	const char *name;
	const void *desc;
	while (next_elf_note(&buf, &size, align, bswap, &nhdr, &name, &desc)) {
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

#if _ELFUTILS_PREREQ(0, 175)
ssize_t drgn_elf_gnu_build_id(Elf *elf, const void **ret)
{
	GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr)
		return -1;
	bool bswap =
		(ehdr->e_ident[EI_DATA] == ELFDATA2LSB) != HOST_LITTLE_ENDIAN;

	Elf_Data *nhdr8_data = NULL;
	size_t num_note_sections = 0;

	Elf_Scn *scn = elf_nextscn(elf, NULL);
	if (scn) {
		do {
			GElf_Shdr shdr_mem, *shdr = gelf_getshdr(scn, &shdr_mem);
			if (!shdr || shdr->sh_type != SHT_NOTE)
				continue;
			num_note_sections++;

			Elf_Data *data = elf_rawdata(scn, NULL);
			if (!data)
				continue;

			if (data->d_type == ELF_T_NHDR8)
				nhdr8_data = data;

			unsigned int align = data->d_type == ELF_T_NHDR8 ? 8 : 4;
			const void *build_id;
			size_t size = parse_gnu_build_id_from_notes(data->d_buf,
								    data->d_size,
								    align,
								    bswap,
								    &build_id);
			if (size) {
				*ret = build_id;
				return size;
			}
		} while ((scn = elf_nextscn(elf, scn)));
	} else {
		size_t phnum;
		if (elf_getphdrnum(elf, &phnum))
			return -1;
		for (size_t i = 0; i < phnum; i++) {
			GElf_Phdr phdr_mem, *phdr =
				gelf_getphdr(elf, i, &phdr_mem);
			if (!phdr || phdr->p_type != PT_NOTE)
				continue;
			num_note_sections++;

			Elf_Data *data =
				elf_getdata_rawchunk(elf, phdr->p_offset,
						     phdr->p_filesz,
						     note_header_type(phdr->p_align));
			if (!data)
				continue;

			if (data->d_type == ELF_T_NHDR8)
				nhdr8_data = data;

			unsigned int align = data->d_type == ELF_T_NHDR8 ? 8 : 4;
			const void *build_id;
			size_t size = parse_gnu_build_id_from_notes(data->d_buf,
								    data->d_size,
								    align,
								    bswap,
								    &build_id);
			if (size) {
				*ret = build_id;
				return size;
			}
		}
	}

	// Before Linux kernel commit f7ba52f302fd ("vmlinux.lds.h: Discard
	// .note.gnu.property section") (in v6.4), the vmlinux .notes section
	// may specify an 8-byte alignment even though it is actually 4-byte
	// aligned. This fix was backported to several stable and longterm
	// kernels, but it never made it to the 4.14 and 4.19 longterm branches.
	// So, we try to work around this bug here.
	//
	// If there is only one note section (or segment) and it specifies
	// 8-byte alignment, then it might be affected by this bug, so we retry
	// with 4-byte alignment.
	//
	// Whenever we drop Linux 4.14 and 4.19 support, we can probably drop
	// this workaround and just use dwelf_elf_gnu_build_id().
	if (nhdr8_data && num_note_sections == 1) {
		return parse_gnu_build_id_from_notes(nhdr8_data->d_buf,
						     nhdr8_data->d_size, 4,
						     bswap, ret);
	}

	*ret = NULL;
	return 0;
}
#endif
