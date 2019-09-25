// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "internal.h"

/*
 * glibc added reallocarray() in 2.26, but since it's so trivial, it's easier to
 * duplicate it here than it is to do feature detection.
 */
void *realloc_array(void *ptr, size_t nmemb, size_t size)
{
	size_t bytes;

	if (__builtin_mul_overflow(nmemb, size, &bytes)) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(ptr, bytes);
}

void *malloc_array(size_t nmemb, size_t size)
{
	size_t bytes;

	if (__builtin_mul_overflow(nmemb, size, &bytes)) {
		errno = ENOMEM;
		return NULL;
	}
	return malloc(bytes);
}

struct drgn_error *read_elf_section(Elf_Scn *scn, Elf_Data **ret)
{
	GElf_Shdr shdr_mem, *shdr;
	Elf_Data *data;

	shdr = gelf_getshdr(scn, &shdr_mem);
	if (!shdr)
		return drgn_error_libelf();
	if ((shdr->sh_flags & SHF_COMPRESSED) && elf_compress(scn, 0, 0) < 0)
		return drgn_error_libelf();
	data = elf_getdata(scn, NULL);
	if (!data)
		return drgn_error_libelf();
	*ret = data;
	return NULL;
}
