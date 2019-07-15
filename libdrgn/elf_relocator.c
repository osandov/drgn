// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <inttypes.h>
#include <string.h>

#include "internal.h"
#include "elf_relocator.h"

DEFINE_VECTOR_FUNCTIONS(elf_vector)

void drgn_elf_relocator_init(struct drgn_elf_relocator *relocator)
{
	elf_vector_init(&relocator->elfs);
}

void drgn_elf_relocator_deinit(struct drgn_elf_relocator *relocator)
{
	elf_vector_deinit(&relocator->elfs);
}

struct drgn_error *
drgn_elf_relocator_add_elf(struct drgn_elf_relocator *relocator, Elf *elf)
{
	GElf_Ehdr ehdr_mem, *ehdr;

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr)
		return drgn_error_libelf();

	if (ehdr->e_type != ET_REL ||
	    ehdr->e_machine != EM_X86_64 ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] !=
	    (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ?
	     ELFDATA2LSB : ELFDATA2MSB))
		return NULL;

	if (!elf_vector_append(&relocator->elfs, &elf))
		return &drgn_enomem;
	return NULL;
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
			return drgn_error_create(DRGN_ERROR_ELF_FORMAT,
						 "invalid relocation offset");
		}
		*(uint32_t *)p = st_value + r_addend;
		break;
	case R_X86_64_64:
		if (r_offset > SIZE_MAX - sizeof(uint64_t) ||
		    r_offset + sizeof(uint64_t) > data->d_size) {
			return drgn_error_create(DRGN_ERROR_ELF_FORMAT,
						 "invalid relocation offset");
		}
		*(uint64_t *)p = st_value + r_addend;
		break;
	default:
		return drgn_error_format(DRGN_ERROR_ELF_FORMAT,
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
			return drgn_error_create(DRGN_ERROR_ELF_FORMAT,
						 "invalid relocation symbol");
		}
		st_shndx = syms[r_sym].st_shndx;
		if (st_shndx == 0) {
			sh_addr = 0;
		} else if (st_shndx < shdrnum) {
			sh_addr = sh_addrs[st_shndx - 1];
		} else {
			return drgn_error_create(DRGN_ERROR_ELF_FORMAT,
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

static struct drgn_error *relocate_elf(Elf *elf)
{
	struct drgn_error *err;
	size_t shdrnum, shstrndx;
	uint64_t *sh_addrs;
	Elf_Scn *scn;

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

struct drgn_error *
drgn_elf_relocator_apply(struct drgn_elf_relocator *relocator)
{
	struct drgn_error *err = NULL;
	Elf **elfs = relocator->elfs.data;
	size_t num_elfs = relocator->elfs.size;

	#pragma omp parallel for schedule(dynamic)
	for (size_t i = 0; i < num_elfs; i++) {
		struct drgn_error *err2;

		if (err)
			continue;

		err2 = relocate_elf(elfs[i]);
		if (err2) {
			#pragma omp critical(relocators_err)
			{
				if (err)
					drgn_error_destroy(err2);
				else
					err = err2;
			}
			continue;
		}
	}
	return err;
}
