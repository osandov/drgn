// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <assert.h>
#include <dwarf.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwelf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "debug_info.h"
#include "error.h"
#include "hash_table.h"
#include "language.h"
#include "linux_kernel.h"
#include "object.h"
#include "path.h"
#include "program.h"
#include "type.h"
#include "util.h"
#include "vector.h"

DEFINE_VECTOR_FUNCTIONS(drgn_debug_info_module_vector)

static inline struct hash_pair
drgn_debug_info_module_key_hash_pair(const struct drgn_debug_info_module_key *key)
{
	size_t hash = hash_bytes(key->build_id, key->build_id_len);
	hash = hash_combine(hash, key->start);
	hash = hash_combine(hash, key->end);
	return hash_pair_from_avalanching_hash(hash);
}
static inline bool
drgn_debug_info_module_key_eq(const struct drgn_debug_info_module_key *a,
			      const struct drgn_debug_info_module_key *b)
{
	return (a->build_id_len == b->build_id_len &&
		memcmp(a->build_id, b->build_id, a->build_id_len) == 0 &&
		a->start == b->start && a->end == b->end);
}
DEFINE_HASH_TABLE_FUNCTIONS(drgn_debug_info_module_table,
			    drgn_debug_info_module_key_hash_pair,
			    drgn_debug_info_module_key_eq)

DEFINE_HASH_TABLE_FUNCTIONS(c_string_set, c_string_key_hash_pair,
			    c_string_key_eq)

/**
 * @c Dwfl_Callbacks::find_elf() implementation.
 *
 * Ideally we'd use @c dwfl_report_elf() instead, but that doesn't take an @c
 * Elf handle, which we need for a couple of reasons:
 *
 * - We usually already have the @c Elf handle open in order to identify the
 *   file.
 * - For kernel modules, we set the section addresses in the @c Elf handle
 *   ourselves instead of using @c Dwfl_Callbacks::section_address().
 *
 * Additionally, there's a special case for vmlinux. It is usually an @c ET_EXEC
 * ELF file, but when KASLR is enabled, it needs to be handled like an @c ET_DYN
 * file. libdwfl has a hack for this when @c dwfl_report_module() is used, but
 * @ref dwfl_report_elf() bypasses this hack.
 *
 * So, we're stuck using @c dwfl_report_module() and this dummy callback.
 */
static int drgn_dwfl_find_elf(Dwfl_Module *dwfl_module, void **userdatap,
			      const char *name, Dwarf_Addr base,
			      char **file_name, Elf **elfp)
{
	struct drgn_debug_info_module *module = *userdatap;
	/*
	 * libdwfl consumes the returned path, file descriptor, and ELF handle,
	 * so clear the fields.
	 */
	*file_name = module->path;
	int fd = module->fd;
	*elfp = module->elf;
	module->path = NULL;
	module->fd = -1;
	module->elf = NULL;
	return fd;
}

/*
 * Uses drgn_dwfl_find_elf() if the ELF file was reported directly and falls
 * back to dwfl_linux_proc_find_elf() otherwise.
 */
static int drgn_dwfl_linux_proc_find_elf(Dwfl_Module *dwfl_module,
					 void **userdatap, const char *name,
					 Dwarf_Addr base, char **file_name,
					 Elf **elfp)
{
	struct drgn_debug_info_module *module = *userdatap;
	if (module->elf) {
		return drgn_dwfl_find_elf(dwfl_module, userdatap, name, base,
					  file_name, elfp);
	}
	return dwfl_linux_proc_find_elf(dwfl_module, userdatap, name, base,
					file_name, elfp);
}

/*
 * Uses drgn_dwfl_find_elf() if the ELF file was reported directly and falls
 * back to dwfl_build_id_find_elf() otherwise.
 */
static int drgn_dwfl_build_id_find_elf(Dwfl_Module *dwfl_module,
				       void **userdatap, const char *name,
				       Dwarf_Addr base, char **file_name,
				       Elf **elfp)
{
	struct drgn_debug_info_module *module = *userdatap;
	if (module->elf) {
		return drgn_dwfl_find_elf(dwfl_module, userdatap, name, base,
					  file_name, elfp);
	}
	return dwfl_build_id_find_elf(dwfl_module, userdatap, name, base,
				      file_name, elfp);
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

static const Dwfl_Callbacks drgn_dwfl_callbacks = {
	.find_elf = drgn_dwfl_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
	.section_address = drgn_dwfl_section_address,
};

static const Dwfl_Callbacks drgn_linux_proc_dwfl_callbacks = {
	.find_elf = drgn_dwfl_linux_proc_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
	.section_address = drgn_dwfl_section_address,
};

static const Dwfl_Callbacks drgn_userspace_core_dump_dwfl_callbacks = {
	.find_elf = drgn_dwfl_build_id_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
	.section_address = drgn_dwfl_section_address,
};

static void
drgn_debug_info_module_destroy(struct drgn_debug_info_module *module)
{
	if (module) {
		drgn_error_destroy(module->err);
		elf_end(module->elf);
		if (module->fd != -1)
			close(module->fd);
		free(module->path);
		free(module->name);
		free(module);
	}
}

static void
drgn_debug_info_module_finish_indexing(struct drgn_debug_info *dbinfo,
				       struct drgn_debug_info_module *module)
{
	module->state = DRGN_DEBUG_INFO_MODULE_INDEXED;
	if (module->name) {
		int ret = c_string_set_insert(&dbinfo->module_names,
					      (const char **)&module->name,
					      NULL);
		/* drgn_debug_info_update_index() should've reserved enough. */
		assert(ret != -1);
	}
}

struct drgn_dwfl_module_removed_arg {
	struct drgn_debug_info *dbinfo;
	bool finish_indexing;
	bool free_all;
};

static int drgn_dwfl_module_removed(Dwfl_Module *dwfl_module, void *userdatap,
				    const char *name, Dwarf_Addr base,
				    void *_arg)
{
	struct drgn_dwfl_module_removed_arg *arg = _arg;
	/*
	 * userdatap is actually a void ** like for the other libdwfl callbacks,
	 * but dwfl_report_end() has the wrong signature for the removed
	 * callback.
	 */
	struct drgn_debug_info_module *module = *(void **)userdatap;
	if (arg->finish_indexing && module &&
	    module->state == DRGN_DEBUG_INFO_MODULE_INDEXING)
		drgn_debug_info_module_finish_indexing(arg->dbinfo, module);
	if (arg->free_all || !module ||
	    module->state != DRGN_DEBUG_INFO_MODULE_INDEXED) {
		drgn_debug_info_module_destroy(module);
	} else {
		/*
		 * The module was already indexed. Report it again so libdwfl
		 * doesn't remove it.
		 */
		Dwarf_Addr end;
		dwfl_module_info(dwfl_module, NULL, NULL, &end, NULL, NULL,
				 NULL, NULL);
		dwfl_report_module(arg->dbinfo->dwfl, name, base, end);
	}
	return DWARF_CB_OK;
}

static void drgn_debug_info_free_modules(struct drgn_debug_info *dbinfo,
					 bool finish_indexing, bool free_all)
{
	for (struct drgn_debug_info_module_table_iterator it =
	     drgn_debug_info_module_table_first(&dbinfo->modules); it.entry; ) {
		struct drgn_debug_info_module *module = *it.entry;
		struct drgn_debug_info_module **nextp = it.entry;
		do {
			struct drgn_debug_info_module *next = module->next;
			if (finish_indexing &&
			    module->state == DRGN_DEBUG_INFO_MODULE_INDEXING) {
				drgn_debug_info_module_finish_indexing(dbinfo,
								       module);
			}
			if (free_all ||
			    module->state != DRGN_DEBUG_INFO_MODULE_INDEXED) {
				if (module == *nextp) {
					if (nextp == it.entry && !next) {
						it = drgn_debug_info_module_table_delete_iterator(&dbinfo->modules,
												  it);
					} else {
						if (!next)
							it = drgn_debug_info_module_table_next(it);
						*nextp = next;
					}
				}
				void **userdatap;
				dwfl_module_info(module->dwfl_module,
						 &userdatap, NULL, NULL, NULL,
						 NULL, NULL, NULL);
				*userdatap = NULL;
				drgn_debug_info_module_destroy(module);
			} else {
				if (!next)
					it = drgn_debug_info_module_table_next(it);
				nextp = &module->next;
			}
			module = next;
		} while (module);
	}

	dwfl_report_begin(dbinfo->dwfl);
	struct drgn_dwfl_module_removed_arg arg = {
		.dbinfo = dbinfo,
		.finish_indexing = finish_indexing,
		.free_all = free_all,
	};
	dwfl_report_end(dbinfo->dwfl, drgn_dwfl_module_removed, &arg);
}

struct drgn_error *
drgn_debug_info_report_error(struct drgn_debug_info_load_state *load,
			     const char *name, const char *message,
			     struct drgn_error *err)
{
	if (err && err->code == DRGN_ERROR_NO_MEMORY) {
		/* Always fail hard if we're out of memory. */
		goto err;
	}
	if (load->num_errors == 0 &&
	    !string_builder_append(&load->errors,
				   "could not get debugging information for:"))
		goto err;
	if (load->num_errors < load->max_errors) {
		if (!string_builder_line_break(&load->errors))
			goto err;
		if (name && !string_builder_append(&load->errors, name))
			goto err;
		if (name && (message || err) &&
		    !string_builder_append(&load->errors, " ("))
			goto err;
		if (message && !string_builder_append(&load->errors, message))
			goto err;
		if (message && err &&
		    !string_builder_append(&load->errors, ": "))
			goto err;
		if (err && !string_builder_append_error(&load->errors, err))
			goto err;
		if (name && (message || err) &&
		    !string_builder_appendc(&load->errors, ')'))
			goto err;
	}
	load->num_errors++;
	drgn_error_destroy(err);
	return NULL;

err:
	drgn_error_destroy(err);
	return &drgn_enomem;
}

static struct drgn_error *
drgn_debug_info_report_module(struct drgn_debug_info_load_state *load,
			      const void *build_id, size_t build_id_len,
			      uint64_t start, uint64_t end, const char *name,
			      Dwfl_Module *dwfl_module, const char *path,
			      int fd, Elf *elf, bool *new_ret)
{
	struct drgn_debug_info *dbinfo = load->dbinfo;
	struct drgn_error *err;
	char *path_key = NULL;

	if (new_ret)
		*new_ret = false;

	struct hash_pair hp;
	struct drgn_debug_info_module_table_iterator it;
	if (build_id_len) {
		struct drgn_debug_info_module_key key = {
			.build_id = build_id,
			.build_id_len = build_id_len,
			.start = start,
			.end = end,
		};
		hp = drgn_debug_info_module_table_hash(&key);
		it = drgn_debug_info_module_table_search_hashed(&dbinfo->modules,
								&key, hp);
		if (it.entry &&
		    (*it.entry)->state == DRGN_DEBUG_INFO_MODULE_INDEXED) {
			/* We've already indexed this module. */
			err = NULL;
			goto free;
		}
	}

	if (!dwfl_module) {
		path_key = realpath(path, NULL);
		if (!path_key) {
			path_key = strdup(path);
			if (!path_key) {
				err = &drgn_enomem;
				goto free;
			}
		}

		dwfl_module = dwfl_report_module(dbinfo->dwfl, path_key, start,
						 end);
		if (!dwfl_module) {
			err = drgn_error_libdwfl();
			goto free;
		}
	}

	void **userdatap;
	dwfl_module_info(dwfl_module, &userdatap, NULL, NULL, NULL, NULL, NULL,
			 NULL);
	if (*userdatap) {
		/* We've already reported this file at this offset. */
		err = NULL;
		goto free;
	}
	if (new_ret)
		*new_ret = true;

	struct drgn_debug_info_module *module = malloc(sizeof(*module));
	if (!module) {
		err = &drgn_enomem;
		goto free;
	}
	module->state = DRGN_DEBUG_INFO_MODULE_NEW;
	module->build_id = build_id;
	module->build_id_len = build_id_len;
	module->start = start;
	module->end = end;
	if (name) {
		module->name = strdup(name);
		if (!module->name) {
			err = &drgn_enomem;
			free(module);
			goto free;
		}
	} else {
		module->name = NULL;
	}
	module->dwfl_module = dwfl_module;
	module->path = path_key;
	module->fd = fd;
	module->elf = elf;
	module->err = NULL;
	module->next = NULL;

	/* path_key, fd and elf are owned by the module now. */

	if (!drgn_debug_info_module_vector_append(&load->new_modules,
						  &module)) {
		drgn_debug_info_module_destroy(module);
		return &drgn_enomem;
	}
	if (build_id_len) {
		if (it.entry) {
			/*
			 * The first module with this build ID is in
			 * new_modules, so insert it after in the list, not
			 * before.
			 */
			module->next = (*it.entry)->next;
			(*it.entry)->next = module;
		} else if (drgn_debug_info_module_table_insert_searched(&dbinfo->modules,
									&module,
									hp,
									NULL) < 0) {
			load->new_modules.size--;
			drgn_debug_info_module_destroy(module);
			return &drgn_enomem;
		}
	}
	*userdatap = module;
	return NULL;

free:
	elf_end(elf);
	if (fd != -1)
		close(fd);
	free(path_key);
	return err;
}

struct drgn_error *
drgn_debug_info_report_elf(struct drgn_debug_info_load_state *load,
			   const char *path, int fd, Elf *elf, uint64_t start,
			   uint64_t end, const char *name, bool *new_ret)
{

	struct drgn_error *err;
	const void *build_id;
	ssize_t build_id_len = dwelf_elf_gnu_build_id(elf, &build_id);
	if (build_id_len < 0) {
		err = drgn_debug_info_report_error(load, path, NULL,
						   drgn_error_libdwfl());
		close(fd);
		elf_end(elf);
		return err;
	} else if (build_id_len == 0) {
		build_id = NULL;
	}
	return drgn_debug_info_report_module(load, build_id, build_id_len,
					     start, end, name, NULL, path, fd,
					     elf, new_ret);
}

static int drgn_debug_info_report_dwfl_module(Dwfl_Module *dwfl_module,
					      void **userdatap,
					      const char *name, Dwarf_Addr base,
					      void *arg)
{
	struct drgn_debug_info_load_state *load = arg;
	struct drgn_error *err;

	if (*userdatap) {
		/*
		 * This was either reported from drgn_debug_info_report_elf() or
		 * already indexed.
		 */
		return DWARF_CB_OK;
	}

	const unsigned char *build_id;
	GElf_Addr build_id_vaddr;
	int build_id_len = dwfl_module_build_id(dwfl_module, &build_id,
						&build_id_vaddr);
	if (build_id_len < 0) {
		err = drgn_debug_info_report_error(load, name, NULL,
						   drgn_error_libdwfl());
		if (err)
			goto err;
	} else if (build_id_len == 0) {
		build_id = NULL;
	}
	Dwarf_Addr end;
	dwfl_module_info(dwfl_module, NULL, NULL, &end, NULL, NULL, NULL, NULL);
	err = drgn_debug_info_report_module(load, build_id, build_id_len, base,
					    end, NULL, dwfl_module, name, -1,
					    NULL, NULL);
	if (err)
		goto err;
	return DWARF_CB_OK;

err:
	drgn_error_destroy(err);
	return DWARF_CB_ABORT;
}

static struct drgn_error *
userspace_report_debug_info(struct drgn_debug_info_load_state *load)
{
	struct drgn_error *err;

	for (size_t i = 0; i < load->num_paths; i++) {
		int fd;
		Elf *elf;
		err = open_elf_file(load->paths[i], &fd, &elf);
		if (err) {
			err = drgn_debug_info_report_error(load, load->paths[i],
							   NULL, err);
			if (err)
				return err;
			continue;
		}
		/*
		 * We haven't implemented a way to get the load address for
		 * anything reported here, so for now we report it as unloaded.
		 */
		err = drgn_debug_info_report_elf(load, load->paths[i], fd, elf,
						 0, 0, NULL, NULL);
		if (err)
			return err;
	}

	if (load->load_default) {
		Dwfl *dwfl = load->dbinfo->dwfl;
		struct drgn_program *prog = load->dbinfo->prog;
		if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
			int ret = dwfl_linux_proc_report(dwfl, prog->pid);
			if (ret == -1) {
				return drgn_error_libdwfl();
			} else if (ret) {
				return drgn_error_create_os("dwfl_linux_proc_report",
							    ret, NULL);
			}
		} else if (dwfl_core_file_report(dwfl, prog->core,
						 NULL) == -1) {
			return drgn_error_libdwfl();
		}
	}
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

		if (strstartswith(scnname, ".rela.debug_")) {
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

static struct drgn_error *
drgn_get_debug_sections(struct drgn_debug_info_module *module)
{
	struct drgn_error *err;

	if (module->elf) {
		err = apply_elf_relocations(module->elf);
		if (err)
			return err;
	}

	/*
	 * Note: not dwfl_module_getelf(), because then libdwfl applies
	 * ELF relocations to all sections, not just debug sections.
	 */
	Dwarf_Addr bias;
	Dwarf *dwarf = dwfl_module_getdwarf(module->dwfl_module, &bias);
	if (!dwarf)
		return drgn_error_libdwfl();
	Elf *elf = dwarf_getelf(dwarf);
	if (!elf)
		return drgn_error_libdw();

	module->bswap = (elf_getident(elf, NULL)[EI_DATA] !=
			 (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ?
			  ELFDATA2LSB : ELFDATA2MSB));

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	module->debug_info = NULL;
	module->debug_abbrev = NULL;
	module->debug_str = NULL;
	module->debug_line = NULL;
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr_mem;
		GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			return drgn_error_libelf();

		if (shdr->sh_type == SHT_NOBITS || (shdr->sh_flags & SHF_GROUP))
			continue;

		const char *scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname)
			continue;

		Elf_Data **sectionp;
		if (!module->debug_info && strcmp(scnname, ".debug_info") == 0)
			sectionp = &module->debug_info;
		else if (!module->debug_abbrev && strcmp(scnname, ".debug_abbrev") == 0)
			sectionp = &module->debug_abbrev;
		else if (!module->debug_str && strcmp(scnname, ".debug_str") == 0)
			sectionp = &module->debug_str;
		else if (!module->debug_line && strcmp(scnname, ".debug_line") == 0)
			sectionp = &module->debug_line;
		else
			continue;
		err = read_elf_section(scn, sectionp);
		if (err)
			return err;
	}

	/*
	 * Truncate any extraneous bytes so that we can assume that a pointer
	 * within .debug_str is always null-terminated.
	 */
	if (module->debug_str) {
		const char *buf = module->debug_str->d_buf;
		const char *nul = memrchr(buf, '\0', module->debug_str->d_size);
		if (nul)
			module->debug_str->d_size = nul - buf + 1;
		else
			module->debug_str->d_size = 0;

	}
	return NULL;
}

static struct drgn_error *
drgn_debug_info_read_module(struct drgn_debug_info_load_state *load,
			    struct drgn_dwarf_index_update_state *dindex_state,
			    struct drgn_debug_info_module *head)
{
	struct drgn_error *err;
	struct drgn_debug_info_module *module;
	for (module = head; module; module = module->next) {
		err = drgn_get_debug_sections(module);
		if (err) {
			module->err = err;
			continue;
		}
		if (module->debug_info && module->debug_abbrev) {
			module->state = DRGN_DEBUG_INFO_MODULE_INDEXING;
			drgn_dwarf_index_read_module(dindex_state, module);
			return NULL;
		}
	}
	/*
	 * We checked all of the files and didn't find debugging information.
	 * Report why for each one.
	 *
	 * (If we did find debugging information, we discard errors on the
	 * unused files.)
	 */
	err = NULL;
	#pragma omp critical(drgn_debug_info_read_module_error)
	for (module = head; module; module = module->next) {
		const char *name =
			dwfl_module_info(module->dwfl_module, NULL, NULL, NULL,
					 NULL, NULL, NULL, NULL);
		if (module->err) {
			err = drgn_debug_info_report_error(load, name, NULL,
							   module->err);
			module->err = NULL;
		} else {
			err = drgn_debug_info_report_error(load, name,
							   "no debugging information",
							   NULL);
		}
		if (err)
			break;
	}
	return err;
}

static struct drgn_error *
drgn_debug_info_update_index(struct drgn_debug_info_load_state *load)
{
	if (!load->new_modules.size)
		return NULL;
	struct drgn_debug_info *dbinfo = load->dbinfo;
	if (!c_string_set_reserve(&dbinfo->module_names,
				  c_string_set_size(&dbinfo->module_names) +
				  load->new_modules.size))
		return &drgn_enomem;
	struct drgn_dwarf_index_update_state dindex_state;
	drgn_dwarf_index_update_begin(&dindex_state, &dbinfo->dindex);
	/*
	 * In OpenMP 5.0, this could be "#pragma omp parallel master taskloop"
	 * (added in GCC 9 and Clang 10).
	 */
	#pragma omp parallel
	#pragma omp master
	#pragma omp taskloop
	for (size_t i = 0; i < load->new_modules.size; i++) {
		if (drgn_dwarf_index_update_cancelled(&dindex_state))
			continue;
		struct drgn_error *module_err =
			drgn_debug_info_read_module(load, &dindex_state,
						    load->new_modules.data[i]);
		if (module_err)
			drgn_dwarf_index_update_cancel(&dindex_state, module_err);
	}
	struct drgn_error *err = drgn_dwarf_index_update_end(&dindex_state);
	if (err)
		return err;
	drgn_debug_info_free_modules(dbinfo, true, false);
	return NULL;
}

struct drgn_error *
drgn_debug_info_report_flush(struct drgn_debug_info_load_state *load)
{
	struct drgn_debug_info *dbinfo = load->dbinfo;
	dwfl_report_end(dbinfo->dwfl, NULL, NULL);
	struct drgn_error *err = drgn_debug_info_update_index(load);
	dwfl_report_begin_add(dbinfo->dwfl);
	if (err)
		return err;
	load->new_modules.size = 0;
	return NULL;
}

static struct drgn_error *
drgn_debug_info_report_finalize_errors(struct drgn_debug_info_load_state *load)
{
	if (load->num_errors > load->max_errors &&
	    (!string_builder_line_break(&load->errors) ||
	     !string_builder_appendf(&load->errors, "... %u more",
				     load->num_errors - load->max_errors))) {
		free(load->errors.str);
		return &drgn_enomem;
	}
	if (load->num_errors) {
		return drgn_error_from_string_builder(DRGN_ERROR_MISSING_DEBUG_INFO,
						      &load->errors);
	} else {
		return NULL;
	}
}

struct drgn_error *drgn_debug_info_load(struct drgn_debug_info *dbinfo,
					const char **paths, size_t n,
					bool load_default, bool load_main)
{
	struct drgn_program *prog = dbinfo->prog;
	struct drgn_error *err;

	if (load_default)
		load_main = true;

	const char *max_errors = getenv("DRGN_MAX_DEBUG_INFO_ERRORS");
	struct drgn_debug_info_load_state load = {
		.dbinfo = dbinfo,
		.paths = paths,
		.num_paths = n,
		.load_default = load_default,
		.load_main = load_main,
		.new_modules = VECTOR_INIT,
		.max_errors = max_errors ? atoi(max_errors) : 5,
	};
	dwfl_report_begin_add(dbinfo->dwfl);
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		err = linux_kernel_report_debug_info(&load);
	else
		err = userspace_report_debug_info(&load);
	dwfl_report_end(dbinfo->dwfl, NULL, NULL);
	if (err)
		goto err;

	/*
	 * userspace_report_debug_info() reports the main debugging information
	 * directly with libdwfl, so we need to report it to dbinfo.
	 */
	if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) && load_main &&
	    dwfl_getmodules(dbinfo->dwfl, drgn_debug_info_report_dwfl_module,
			    &load, 0)) {
		err = &drgn_enomem;
		goto err;
	}

	err = drgn_debug_info_update_index(&load);
	if (err)
		goto err;

	/*
	 * If this fails, it's too late to roll back. This can only fail with
	 * enomem, so it's not a big deal.
	 */
	err = drgn_debug_info_report_finalize_errors(&load);
out:
	drgn_debug_info_module_vector_deinit(&load.new_modules);
	return err;

err:
	drgn_debug_info_free_modules(dbinfo, false, false);
	free(load.errors.str);
	goto out;
}

bool drgn_debug_info_is_indexed(struct drgn_debug_info *dbinfo,
				const char *name)
{
	return c_string_set_search(&dbinfo->module_names, &name).entry != NULL;
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_dwarf_type_map, ptr_key_hash_pair,
			    scalar_key_eq)

struct drgn_type_from_dwarf_thunk {
	struct drgn_type_thunk thunk;
	Dwarf_Die die;
	bool can_be_incomplete_array;
};

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
static struct drgn_error *dwarf_die_byte_order(Dwarf_Die *die,
					       bool check_attr,
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
		*ret = little_endian ? DRGN_LITTLE_ENDIAN : DRGN_BIG_ENDIAN;
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
drgn_type_from_dwarf_internal(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
			      bool can_be_incomplete_array,
			      bool *is_incomplete_array_ret,
			      struct drgn_qualified_type *ret);

/**
 * Parse a type from a DWARF debugging information entry.
 *
 * @param[in] dbinfo Debugging information.
 * @param[in] die DIE to parse.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
static inline struct drgn_error *
drgn_type_from_dwarf(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
		     struct drgn_qualified_type *ret)
{
	return drgn_type_from_dwarf_internal(dbinfo, die, true, NULL, ret);
}

static struct drgn_error *
drgn_type_from_dwarf_thunk_evaluate_fn(struct drgn_type_thunk *thunk,
				       struct drgn_qualified_type *ret)
{
	struct drgn_type_from_dwarf_thunk *t =
		container_of(thunk, struct drgn_type_from_dwarf_thunk, thunk);
	return drgn_type_from_dwarf_internal(thunk->prog->_dbinfo, &t->die,
					     t->can_be_incomplete_array, NULL,
					     ret);
}

static void drgn_type_from_dwarf_thunk_free_fn(struct drgn_type_thunk *thunk)
{
	free(container_of(thunk, struct drgn_type_from_dwarf_thunk, thunk));
}

static struct drgn_error *
drgn_lazy_type_from_dwarf(struct drgn_debug_info *dbinfo, Dwarf_Die *parent_die,
			  bool can_be_incomplete_array, const char *tag_name,
			  struct drgn_lazy_type *ret)
{
	Dwarf_Attribute attr_mem, *attr;
	if (!(attr = dwarf_attr_integrate(parent_die, DW_AT_type, &attr_mem))) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s is missing DW_AT_type",
					 tag_name);
	}

	Dwarf_Die type_die;
	if (!dwarf_formref_die(attr, &type_die)) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has invalid DW_AT_type", tag_name);
	}

	struct drgn_type_from_dwarf_thunk *thunk = malloc(sizeof(*thunk));
	if (!thunk)
		return &drgn_enomem;

	thunk->thunk.prog = dbinfo->prog;
	thunk->thunk.evaluate_fn = drgn_type_from_dwarf_thunk_evaluate_fn;
	thunk->thunk.free_fn = drgn_type_from_dwarf_thunk_free_fn;
	thunk->die = type_die;
	thunk->can_be_incomplete_array = can_be_incomplete_array;
	drgn_lazy_type_init_thunk(ret, &thunk->thunk);
	return NULL;
}

/**
 * Parse a type from the @c DW_AT_type attribute of a DWARF debugging
 * information entry.
 *
 * @param[in] dbinfo Debugging information.
 * @param[in] parent_die Parent DIE.
 * @param[in] parent_lang Language of the parent DIE if it is already known, @c
 * NULL if it should be determined from @p parent_die.
 * @param[in] tag_name Spelling of the DWARF tag of @p parent_die. Used for
 * error messages.
 * @param[in] can_be_void Whether the @c DW_AT_type attribute may be missing,
 * which is interpreted as a void type. If this is false and the @c DW_AT_type
 * attribute is missing, an error is returned.
 * @param[in] can_be_incomplete_array See @ref drgn_type_from_dwarf_internal().
 * @param[in] is_incomplete_array_ret See @ref drgn_type_from_dwarf_internal().
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_type_from_dwarf_child(struct drgn_debug_info *dbinfo,
			   Dwarf_Die *parent_die,
			   const struct drgn_language *parent_lang,
			   const char *tag_name,
			   bool can_be_void, bool can_be_incomplete_array,
			   bool *is_incomplete_array_ret,
			   struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr;
	Dwarf_Die type_die;

	if (!(attr = dwarf_attr_integrate(parent_die, DW_AT_type, &attr_mem))) {
		if (can_be_void) {
			if (!parent_lang) {
				err = drgn_language_from_die(parent_die,
							     &parent_lang);
				if (err)
					return err;
			}
			ret->type = drgn_void_type(dbinfo->prog, parent_lang);
			ret->qualifiers = 0;
			return NULL;
		} else {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "%s is missing DW_AT_type",
						 tag_name);
		}
	}

	if (!dwarf_formref_die(attr, &type_die)) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has invalid DW_AT_type", tag_name);
	}

	return drgn_type_from_dwarf_internal(dbinfo, &type_die,
					     can_be_incomplete_array,
					     is_incomplete_array_ret, ret);
}

static struct drgn_error *
drgn_base_type_from_dwarf(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
			  const struct drgn_language *lang,
			  struct drgn_type **ret)
{
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

	switch (encoding) {
	case DW_ATE_boolean:
		return drgn_bool_type_create(dbinfo->prog, name, size, lang,
					     ret);
	case DW_ATE_float:
		return drgn_float_type_create(dbinfo->prog, name, size, lang,
					      ret);
	case DW_ATE_signed:
	case DW_ATE_signed_char:
		return drgn_int_type_create(dbinfo->prog, name, size, true,
					    lang, ret);
	case DW_ATE_unsigned:
	case DW_ATE_unsigned_char:
		return drgn_int_type_create(dbinfo->prog, name, size, false,
					    lang, ret);
	/*
	 * GCC also supports complex integer types, but DWARF 4 doesn't have an
	 * encoding for that. GCC as of 8.2 emits DW_ATE_lo_user, but that's
	 * ambiguous because it also emits that in other cases. For now, we
	 * don't support it.
	 */
	case DW_ATE_complex_float: {
		Dwarf_Die child;
		if (dwarf_type(die, &child)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_base_type has missing or invalid DW_AT_type");
		}
		struct drgn_qualified_type real_type;
		struct drgn_error *err = drgn_type_from_dwarf(dbinfo, &child,
							      &real_type);
		if (err)
			return err;
		if (drgn_type_kind(real_type.type) != DRGN_TYPE_FLOAT &&
		    drgn_type_kind(real_type.type) != DRGN_TYPE_INT) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_AT_type of DW_ATE_complex_float is not a floating-point or integer type");
		}
		return drgn_complex_type_create(dbinfo->prog, name, size,
						real_type.type, lang, ret);
	}
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "DW_TAG_base_type has unknown DWARF encoding 0x%llx",
					 (unsigned long long)encoding);
	}
}

/*
 * DW_TAG_structure_type, DW_TAG_union_type, DW_TAG_class_type, and
 * DW_TAG_enumeration_type can be incomplete (i.e., have a DW_AT_declaration of
 * true). This tries to find the complete type. If it succeeds, it returns NULL.
 * If it can't find a complete type, it returns a DRGN_ERROR_STOP error.
 * Otherwise, it returns an error.
 */
static struct drgn_error *
drgn_debug_info_find_complete(struct drgn_debug_info *dbinfo, uint64_t tag,
			      const char *name, struct drgn_type **ret)
{
	struct drgn_error *err;

	struct drgn_dwarf_index_iterator it;
	err = drgn_dwarf_index_iterator_init(&it, &dbinfo->dindex.global, name,
					     strlen(name), &tag, 1);
	if (err)
		return err;

	/*
	 * Find a matching DIE. Note that drgn_dwarf_index does not contain DIEs
	 * with DW_AT_declaration, so this will always be a complete type.
	 */
	struct drgn_dwarf_index_die *index_die =
		drgn_dwarf_index_iterator_next(&it);
	if (!index_die)
		return &drgn_stop;
	/*
	 * Look for another matching DIE. If there is one, then we can't be sure
	 * which type this is, so leave it incomplete rather than guessing.
	 */
	if (drgn_dwarf_index_iterator_next(&it))
		return &drgn_stop;

	Dwarf_Die die;
	err = drgn_dwarf_index_get_die(index_die, &die, NULL);
	if (err)
		return err;
	struct drgn_qualified_type qualified_type;
	err = drgn_type_from_dwarf(dbinfo, &die, &qualified_type);
	if (err)
		return err;
	*ret = qualified_type.type;
	return NULL;
}

static struct drgn_error *
parse_member_offset(Dwarf_Die *die, struct drgn_lazy_type *member_type,
		    uint64_t bit_field_size, bool little_endian, uint64_t *ret)
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
		Dwarf_Word byte_offset;

		if (dwarf_formudata(attr, &byte_offset)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_member has invalid DW_AT_data_member_location");
		}
		*ret = 8 * byte_offset;
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
			uint64_t byte_size;

			attr = dwarf_attr_integrate(die, DW_AT_byte_size,
						    &attr_mem);
			/*
			 * If the member has an explicit byte size, we can use
			 * that. Otherwise, we have to get it from the member
			 * type.
			 */
			if (attr) {
				Dwarf_Word word;

				if (dwarf_formudata(attr, &word)) {
					return drgn_error_create(DRGN_ERROR_OTHER,
								 "DW_TAG_member has invalid DW_AT_byte_size");
				}
				byte_size = word;
			} else {
				struct drgn_qualified_type containing_type;

				err = drgn_lazy_type_evaluate(member_type,
							      &containing_type);
				if (err)
					return err;
				if (!drgn_type_has_size(containing_type.type)) {
					return drgn_error_create(DRGN_ERROR_OTHER,
								 "DW_TAG_member bit field type does not have size");
				}
				byte_size = drgn_type_size(containing_type.type);
			}
			*ret += 8 * byte_size - bit_offset - bit_field_size;
		} else {
			*ret += bit_offset;
		}
	}

	return NULL;
}

static struct drgn_error *
parse_member(struct drgn_debug_info *dbinfo, Dwarf_Die *die, bool little_endian,
	     bool can_be_incomplete_array,
	     struct drgn_compound_type_builder *builder)
{
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

	uint64_t bit_field_size;
	if ((attr = dwarf_attr_integrate(die, DW_AT_bit_size, &attr_mem))) {
		Dwarf_Word bit_size;
		if (dwarf_formudata(attr, &bit_size)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_TAG_member has invalid DW_AT_bit_size");
		}
		bit_field_size = bit_size;
	} else {
		bit_field_size = 0;
	}

	struct drgn_lazy_type member_type;
	struct drgn_error *err = drgn_lazy_type_from_dwarf(dbinfo, die,
							   can_be_incomplete_array,
							   "DW_TAG_member",
							   &member_type);
	if (err)
		return err;

	uint64_t bit_offset;
	err = parse_member_offset(die, &member_type, bit_field_size,
				  little_endian, &bit_offset);
	if (err)
		goto err;

	err = drgn_compound_type_builder_add_member(builder, member_type, name,
						    bit_offset, bit_field_size);
	if (err)
		goto err;
	return NULL;

err:
	drgn_lazy_type_deinit(&member_type);
	return err;
}

static struct drgn_error *
drgn_compound_type_from_dwarf(struct drgn_debug_info *dbinfo,
			      Dwarf_Die *die, const struct drgn_language *lang,
			      enum drgn_type_kind kind, struct drgn_type **ret)
{
	struct drgn_error *err;

	const char *dw_tag_str;
	uint64_t dw_tag;
	switch (kind) {
	case DRGN_TYPE_STRUCT:
		dw_tag_str = "DW_TAG_structure_type";
		dw_tag = DW_TAG_structure_type;
		break;
	case DRGN_TYPE_UNION:
		dw_tag_str = "DW_TAG_union_type";
		dw_tag = DW_TAG_union_type;
		break;
	case DRGN_TYPE_CLASS:
		dw_tag_str = "DW_TAG_class_type";
		dw_tag = DW_TAG_class_type;
		break;
	default:
		UNREACHABLE();
	}

	Dwarf_Attribute attr_mem;
	Dwarf_Attribute *attr = dwarf_attr_integrate(die, DW_AT_name,
						     &attr_mem);
	const char *tag;
	if (attr) {
		tag = dwarf_formstring(attr);
		if (!tag) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "%s has invalid DW_AT_name",
						 dw_tag_str);
		}
	} else {
		tag = NULL;
	}

	bool declaration;
	if (dwarf_flag(die, DW_AT_declaration, &declaration)) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has invalid DW_AT_declaration",
					 dw_tag_str);
	}
	if (declaration && tag) {
		err = drgn_debug_info_find_complete(dbinfo, dw_tag, tag, ret);
		if (!err || err->code != DRGN_ERROR_STOP)
			return err;
	}

	if (declaration) {
		return drgn_incomplete_compound_type_create(dbinfo->prog, kind,
							    tag, lang, ret);
	}

	int size = dwarf_bytesize(die);
	if (size == -1) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has missing or invalid DW_AT_byte_size",
					 dw_tag_str);
	}

	struct drgn_compound_type_builder builder;
	drgn_compound_type_builder_init(&builder, dbinfo->prog, kind);
	bool little_endian;
	dwarf_die_is_little_endian(die, false, &little_endian);
	Dwarf_Die member = {}, child;
	int r = dwarf_child(die, &child);
	while (r == 0) {
		if (dwarf_tag(&child) == DW_TAG_member) {
			if (member.addr) {
				err = parse_member(dbinfo, &member,
						   little_endian, false,
						   &builder);
				if (err)
					goto err;
			}
			member = child;
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
		err = parse_member(dbinfo, &member, little_endian,
				   kind != DRGN_TYPE_UNION &&
				   builder.members.size > 0,
				   &builder);
		if (err)
			goto err;
	}

	err = drgn_compound_type_create(&builder, tag, size, lang, ret);
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
	return drgn_int_type_create(dbinfo->prog, "<unknown>", size, is_signed,
				    lang, ret);
}

static struct drgn_error *
drgn_enum_type_from_dwarf(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
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
						    tag, ret);
		if (!err || err->code != DRGN_ERROR_STOP)
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
		err = drgn_type_from_dwarf(dbinfo, &child,
					   &qualified_compatible_type);
		if (err)
			goto err;
		compatible_type = qualified_compatible_type.type;
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
drgn_typedef_type_from_dwarf(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
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
	struct drgn_error *err = drgn_type_from_dwarf_child(dbinfo, die,
							    drgn_language_or_default(lang),
							    "DW_TAG_typedef",
							    true,
							    can_be_incomplete_array,
							    is_incomplete_array_ret,
							    &aliased_type);
	if (err)
		return err;

	return drgn_typedef_type_create(dbinfo->prog, name, aliased_type, lang,
					ret);
}

static struct drgn_error *
drgn_pointer_type_from_dwarf(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
			     const struct drgn_language *lang,
			     struct drgn_type **ret)
{
	struct drgn_qualified_type referenced_type;
	struct drgn_error *err = drgn_type_from_dwarf_child(dbinfo, die,
							    drgn_language_or_default(lang),
							    "DW_TAG_pointer_type",
							    true, true, NULL,
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
		uint8_t word_size;
		err = drgn_program_word_size(dbinfo->prog, &word_size);
		if (err)
			return err;
		size = word_size;
	}

	return drgn_pointer_type_create(dbinfo->prog, referenced_type, size,
					lang, ret);
}

struct array_dimension {
	uint64_t length;
	bool is_complete;
};

DEFINE_VECTOR(array_dimension_vector, struct array_dimension)

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
	 * GCC emits a DW_FORM_sdata DW_AT_upper_bound of -1 for empty array
	 * variables without an explicit size (e.g., `int arr[] = {};`).
	 */
	if (attr->code == DW_AT_upper_bound && attr->form == DW_FORM_sdata &&
	    word == (Dwarf_Word)-1) {
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
drgn_array_type_from_dwarf(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
			   const struct drgn_language *lang,
			   bool can_be_incomplete_array,
			   bool *is_incomplete_array_ret,
			   struct drgn_type **ret)
{
	struct drgn_error *err;
	struct array_dimension_vector dimensions = VECTOR_INIT;
	struct array_dimension *dimension;
	Dwarf_Die child;
	int r = dwarf_child(die, &child);
	while (r == 0) {
		if (dwarf_tag(&child) == DW_TAG_subrange_type) {
			dimension = array_dimension_vector_append_entry(&dimensions);
			if (!dimension)
				goto out;
			err = subrange_length(&child, dimension);
			if (err)
				goto out;
		}
		r = dwarf_siblingof(&child, &child);
	}
	if (r == -1) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"libdw could not parse DIE children");
		goto out;
	}
	if (!dimensions.size) {
		dimension = array_dimension_vector_append_entry(&dimensions);
		if (!dimension)
			goto out;
		dimension->is_complete = false;
	}

	struct drgn_qualified_type element_type;
	err = drgn_type_from_dwarf_child(dbinfo, die,
					 drgn_language_or_default(lang),
					 "DW_TAG_array_type", false, false,
					 NULL, &element_type);
	if (err)
		goto out;

	*is_incomplete_array_ret = !dimensions.data[0].is_complete;
	struct drgn_type *type;
	do {
		dimension = array_dimension_vector_pop(&dimensions);
		if (dimension->is_complete) {
			err = drgn_array_type_create(dbinfo->prog, element_type,
						     dimension->length, lang,
						     &type);
		} else if (dimensions.size || !can_be_incomplete_array) {
			err = drgn_array_type_create(dbinfo->prog, element_type,
						     0, lang, &type);
		} else {
			err = drgn_incomplete_array_type_create(dbinfo->prog,
								element_type,
								lang, &type);
		}
		if (err)
			goto out;

		element_type.type = type;
		element_type.qualifiers = 0;
	} while (dimensions.size);

	*ret = type;
	err = NULL;
out:
	array_dimension_vector_deinit(&dimensions);
	return err;
}

static struct drgn_error *
parse_formal_parameter(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
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

	struct drgn_lazy_type parameter_type;
	struct drgn_error *err = drgn_lazy_type_from_dwarf(dbinfo, die, true,
							   "DW_TAG_formal_parameter",
							   &parameter_type);
	if (err)
		return err;

	err = drgn_function_type_builder_add_parameter(builder, parameter_type,
						       name);
	if (err)
		drgn_lazy_type_deinit(&parameter_type);
	return err;
}

static struct drgn_error *
drgn_function_type_from_dwarf(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
			      const struct drgn_language *lang,
			      struct drgn_type **ret)
{
	struct drgn_error *err;

	const char *tag_name =
		dwarf_tag(die) == DW_TAG_subroutine_type ?
		"DW_TAG_subroutine_type" : "DW_TAG_subprogram";
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
							tag_name);
				goto err;
			}
			err = parse_formal_parameter(dbinfo, &child, &builder);
			if (err)
				goto err;
			break;
		case DW_TAG_unspecified_parameters:
			if (is_variadic) {
				err = drgn_error_format(DRGN_ERROR_OTHER,
							"%s has multiple DW_TAG_unspecified_parameters children",
							tag_name);
				goto err;
			}
			is_variadic = true;
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
	err = drgn_type_from_dwarf_child(dbinfo, die,
					 drgn_language_or_default(lang),
					 tag_name, true, true, NULL,
					 &return_type);
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
drgn_type_from_dwarf_internal(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
			      bool can_be_incomplete_array,
			      bool *is_incomplete_array_ret,
			      struct drgn_qualified_type *ret)
{
	if (dbinfo->depth >= 1000) {
		return drgn_error_create(DRGN_ERROR_RECURSION,
					 "maximum DWARF type parsing depth exceeded");
	}

	struct drgn_dwarf_type_map_entry entry = {
		.key = die->addr,
	};
	struct hash_pair hp = drgn_dwarf_type_map_hash(&entry.key);
	struct drgn_dwarf_type_map_iterator it =
		drgn_dwarf_type_map_search_hashed(&dbinfo->types, &entry.key,
						  hp);
	if (it.entry) {
		if (!can_be_incomplete_array &&
		    it.entry->value.is_incomplete_array) {
			it = drgn_dwarf_type_map_search_hashed(&dbinfo->cant_be_incomplete_array_types,
							       &entry.key, hp);
		}
		if (it.entry) {
			ret->type = it.entry->value.type;
			ret->qualifiers = it.entry->value.qualifiers;
			return NULL;
		}
	}

	const struct drgn_language *lang;
	struct drgn_error *err = drgn_language_from_die(die, &lang);
	if (err)
		return err;

	ret->qualifiers = 0;
	dbinfo->depth++;
	entry.value.is_incomplete_array = false;
	switch (dwarf_tag(die)) {
	case DW_TAG_const_type:
		err = drgn_type_from_dwarf_child(dbinfo, die,
						 drgn_language_or_default(lang),
						 "DW_TAG_const_type", true,
						 true, NULL, ret);
		ret->qualifiers |= DRGN_QUALIFIER_CONST;
		break;
	case DW_TAG_restrict_type:
		err = drgn_type_from_dwarf_child(dbinfo, die,
						 drgn_language_or_default(lang),
						 "DW_TAG_restrict_type", true,
						 true, NULL, ret);
		ret->qualifiers |= DRGN_QUALIFIER_RESTRICT;
		break;
	case DW_TAG_volatile_type:
		err = drgn_type_from_dwarf_child(dbinfo, die,
						 drgn_language_or_default(lang),
						 "DW_TAG_volatile_type", true,
						 true, NULL, ret);
		ret->qualifiers |= DRGN_QUALIFIER_VOLATILE;
		break;
	case DW_TAG_atomic_type:
		err = drgn_type_from_dwarf_child(dbinfo, die,
						 drgn_language_or_default(lang),
						 "DW_TAG_atomic_type", true,
						 true, NULL, ret);
		ret->qualifiers |= DRGN_QUALIFIER_ATOMIC;
		break;
	case DW_TAG_base_type:
		err = drgn_base_type_from_dwarf(dbinfo, die, lang, &ret->type);
		break;
	case DW_TAG_structure_type:
		err = drgn_compound_type_from_dwarf(dbinfo, die, lang,
						    DRGN_TYPE_STRUCT,
						    &ret->type);
		break;
	case DW_TAG_union_type:
		err = drgn_compound_type_from_dwarf(dbinfo, die, lang,
						    DRGN_TYPE_UNION,
						    &ret->type);
		break;
	case DW_TAG_class_type:
		err = drgn_compound_type_from_dwarf(dbinfo, die, lang,
						    DRGN_TYPE_CLASS,
						    &ret->type);
		break;
	case DW_TAG_enumeration_type:
		err = drgn_enum_type_from_dwarf(dbinfo, die, lang, &ret->type);
		break;
	case DW_TAG_typedef:
		err = drgn_typedef_type_from_dwarf(dbinfo, die, lang,
						   can_be_incomplete_array,
						   &entry.value.is_incomplete_array,
						   &ret->type);
		break;
	case DW_TAG_pointer_type:
		err = drgn_pointer_type_from_dwarf(dbinfo, die, lang,
						   &ret->type);
		break;
	case DW_TAG_array_type:
		err = drgn_array_type_from_dwarf(dbinfo, die, lang,
						 can_be_incomplete_array,
						 &entry.value.is_incomplete_array,
						 &ret->type);
		break;
	case DW_TAG_subroutine_type:
	case DW_TAG_subprogram:
		err = drgn_function_type_from_dwarf(dbinfo, die, lang,
						    &ret->type);
		break;
	default:
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"unknown DWARF type tag 0x%x",
					dwarf_tag(die));
		break;
	}
	dbinfo->depth--;
	if (err)
		return err;

	entry.value.type = ret->type;
	entry.value.qualifiers = ret->qualifiers;
	struct drgn_dwarf_type_map *map;
	if (!can_be_incomplete_array && entry.value.is_incomplete_array)
		map = &dbinfo->cant_be_incomplete_array_types;
	else
		map = &dbinfo->types;
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

struct drgn_error *drgn_debug_info_find_type(enum drgn_type_kind kind,
					     const char *name, size_t name_len,
					     const char *filename, void *arg,
					     struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	struct drgn_debug_info *dbinfo = arg;

	uint64_t tag;
	switch (kind) {
	case DRGN_TYPE_INT:
	case DRGN_TYPE_BOOL:
	case DRGN_TYPE_FLOAT:
		tag = DW_TAG_base_type;
		break;
	case DRGN_TYPE_STRUCT:
		tag = DW_TAG_structure_type;
		break;
	case DRGN_TYPE_UNION:
		tag = DW_TAG_union_type;
		break;
	case DRGN_TYPE_CLASS:
		tag = DW_TAG_class_type;
		break;
	case DRGN_TYPE_ENUM:
		tag = DW_TAG_enumeration_type;
		break;
	case DRGN_TYPE_TYPEDEF:
		tag = DW_TAG_typedef;
		break;
	default:
		UNREACHABLE();
	}

	struct drgn_dwarf_index_iterator it;
	err = drgn_dwarf_index_iterator_init(&it, &dbinfo->dindex.global, name,
					     name_len, &tag, 1);
	if (err)
		return err;
	struct drgn_dwarf_index_die *index_die;
	while ((index_die = drgn_dwarf_index_iterator_next(&it))) {
		Dwarf_Die die;
		err = drgn_dwarf_index_get_die(index_die, &die, NULL);
		if (err)
			return err;
		if (die_matches_filename(&die, filename)) {
			err = drgn_type_from_dwarf(dbinfo, &die, ret);
			if (err)
				return err;
			/*
			 * For DW_TAG_base_type, we need to check that the type
			 * we found was the right kind.
			 */
			if (drgn_type_kind(ret->type) == kind)
				return NULL;
		}
	}
	return &drgn_not_found;
}

static struct drgn_error *
drgn_object_from_dwarf_enumerator(struct drgn_debug_info *dbinfo,
				  Dwarf_Die *die, const char *name,
				  struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	const struct drgn_type_enumerator *enumerators;
	size_t num_enumerators, i;

	err = drgn_type_from_dwarf(dbinfo, die, &qualified_type);
	if (err)
		return err;
	enumerators = drgn_type_enumerators(qualified_type.type);
	num_enumerators = drgn_type_num_enumerators(qualified_type.type);
	for (i = 0; i < num_enumerators; i++) {
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
				  Dwarf_Die *die, uint64_t bias,
				  const char *name, struct drgn_object *ret)
{
	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_type_from_dwarf(dbinfo, die,
						      &qualified_type);
	if (err)
		return err;
	Dwarf_Addr low_pc;
	if (dwarf_lowpc(die, &low_pc) == -1) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find address of '%s'",
					 name);
	}
	enum drgn_byte_order byte_order;
	dwarf_die_byte_order(die, false, &byte_order);
	return drgn_object_set_reference(ret, qualified_type, low_pc + bias, 0,
					 0, byte_order);
}

static struct drgn_error *
drgn_object_from_dwarf_constant(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
				struct drgn_qualified_type qualified_type,
				Dwarf_Attribute *attr, struct drgn_object *ret)
{
	struct drgn_object_type type;
	enum drgn_object_kind kind;
	uint64_t bit_size;
	struct drgn_error *err = drgn_object_set_common(qualified_type, 0,
							&type, &kind,
							&bit_size);
	if (err)
		return err;
	Dwarf_Block block;
	if (dwarf_formblock(attr, &block) == 0) {
		bool little_endian;
		err = dwarf_die_is_little_endian(die, true, &little_endian);
		if (err)
			return err;
		if (block.length < drgn_value_size(bit_size, 0)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_AT_const_value block is too small");
		}
		return drgn_object_set_buffer_internal(ret, &type, kind,
						       bit_size, block.data, 0,
						       little_endian);
	} else if (kind == DRGN_OBJECT_SIGNED) {
		Dwarf_Sword svalue;
		if (dwarf_formsdata(attr, &svalue)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid DW_AT_const_value");
		}
		return drgn_object_set_signed_internal(ret, &type, bit_size,
						       svalue);
	} else if (kind == DRGN_OBJECT_UNSIGNED) {
		Dwarf_Word uvalue;
		if (dwarf_formudata(attr, &uvalue)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "invalid DW_AT_const_value");
		}
		return drgn_object_set_unsigned_internal(ret, &type, bit_size,
							 uvalue);
	} else {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "unknown DW_AT_const_value form");
	}
}

static struct drgn_error *
drgn_object_from_dwarf_variable(struct drgn_debug_info *dbinfo, Dwarf_Die *die,
				uint64_t bias, const char *name,
				struct drgn_object *ret)
{
	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_type_from_dwarf_child(dbinfo, die, NULL,
							    "DW_TAG_variable",
							    true, true, NULL,
							    &qualified_type);
	if (err)
		return err;
	Dwarf_Attribute attr_mem, *attr;
	if ((attr = dwarf_attr_integrate(die, DW_AT_location, &attr_mem))) {
		Dwarf_Op *loc;
		size_t nloc;
		if (dwarf_getlocation(attr, &loc, &nloc))
			return drgn_error_libdw();
		if (nloc != 1 || loc[0].atom != DW_OP_addr) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "DW_AT_location has unimplemented operation");
		}
		enum drgn_byte_order byte_order;
		err = dwarf_die_byte_order(die, true, &byte_order);
		if (err)
			return err;
		return drgn_object_set_reference(ret, qualified_type,
						 loc[0].number + bias, 0, 0,
						 byte_order);
	} else if ((attr = dwarf_attr_integrate(die, DW_AT_const_value,
						&attr_mem))) {
		return drgn_object_from_dwarf_constant(dbinfo, die,
						       qualified_type, attr,
						       ret);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find address or value of '%s'",
					 name);
	}
}

struct drgn_error *
drgn_debug_info_find_object(const char *name, size_t name_len,
			    const char *filename,
			    enum drgn_find_object_flags flags, void *arg,
			    struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_debug_info *dbinfo = arg;

	struct drgn_dwarf_index_namespace *ns = &dbinfo->dindex.global;
	if (name_len >= 2 && memcmp(name, "::", 2) == 0) {
		/* Explicit global namespace. */
		name_len -= 2;
		name += 2;
	}
	const char *colons;
	while ((colons = memmem(name, name_len, "::", 2))) {
		struct drgn_dwarf_index_iterator it;
		uint64_t ns_tag = DW_TAG_namespace;
		err = drgn_dwarf_index_iterator_init(&it, ns, name,
						     colons - name, &ns_tag, 1);
		if (err)
			return err;
		struct drgn_dwarf_index_die *index_die =
			drgn_dwarf_index_iterator_next(&it);
		if (!index_die)
			return &drgn_not_found;
		ns = index_die->namespace;
		name_len -= colons + 2 - name;
		name = colons + 2;
	}

	uint64_t tags[3];
	size_t num_tags = 0;
	if (flags & DRGN_FIND_OBJECT_CONSTANT)
		tags[num_tags++] = DW_TAG_enumerator;
	if (flags & DRGN_FIND_OBJECT_FUNCTION)
		tags[num_tags++] = DW_TAG_subprogram;
	if (flags & DRGN_FIND_OBJECT_VARIABLE)
		tags[num_tags++] = DW_TAG_variable;

	struct drgn_dwarf_index_iterator it;
	err = drgn_dwarf_index_iterator_init(&it, ns, name, strlen(name), tags,
					     num_tags);
	if (err)
		return err;
	struct drgn_dwarf_index_die *index_die;
	while ((index_die = drgn_dwarf_index_iterator_next(&it))) {
		Dwarf_Die die;
		uint64_t bias;
		err = drgn_dwarf_index_get_die(index_die, &die, &bias);
		if (err)
			return err;
		if (!die_matches_filename(&die, filename))
			continue;
		switch (dwarf_tag(&die)) {
		case DW_TAG_enumeration_type:
			return drgn_object_from_dwarf_enumerator(dbinfo, &die,
								 name, ret);
		case DW_TAG_subprogram:
			return drgn_object_from_dwarf_subprogram(dbinfo, &die,
								 bias, name,
								 ret);
		case DW_TAG_variable:
			return drgn_object_from_dwarf_variable(dbinfo, &die,
							       bias, name, ret);
		default:
			UNREACHABLE();
		}
	}
	return &drgn_not_found;
}

struct drgn_error *drgn_debug_info_create(struct drgn_program *prog,
					  struct drgn_debug_info **ret)
{
	struct drgn_debug_info *dbinfo = malloc(sizeof(*dbinfo));
	if (!dbinfo)
		return &drgn_enomem;
	dbinfo->prog = prog;
	const Dwfl_Callbacks *dwfl_callbacks;
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		dwfl_callbacks = &drgn_dwfl_callbacks;
	else if (prog->flags & DRGN_PROGRAM_IS_LIVE)
		dwfl_callbacks = &drgn_linux_proc_dwfl_callbacks;
	else
		dwfl_callbacks = &drgn_userspace_core_dump_dwfl_callbacks;
	dbinfo->dwfl = dwfl_begin(dwfl_callbacks);
	if (!dbinfo->dwfl) {
		free(dbinfo);
		return drgn_error_libdwfl();
	}
	drgn_debug_info_module_table_init(&dbinfo->modules);
	c_string_set_init(&dbinfo->module_names);
	drgn_dwarf_index_init(&dbinfo->dindex);
	drgn_dwarf_type_map_init(&dbinfo->types);
	drgn_dwarf_type_map_init(&dbinfo->cant_be_incomplete_array_types);
	dbinfo->depth = 0;
	*ret = dbinfo;
	return NULL;
}

void drgn_debug_info_destroy(struct drgn_debug_info *dbinfo)
{
	if (!dbinfo)
		return;
	drgn_dwarf_type_map_deinit(&dbinfo->cant_be_incomplete_array_types);
	drgn_dwarf_type_map_deinit(&dbinfo->types);
	drgn_dwarf_index_deinit(&dbinfo->dindex);
	c_string_set_deinit(&dbinfo->module_names);
	drgn_debug_info_free_modules(dbinfo, false, true);
	assert(drgn_debug_info_module_table_empty(&dbinfo->modules));
	drgn_debug_info_module_table_deinit(&dbinfo->modules);
	dwfl_end(dbinfo->dwfl);
	free(dbinfo);
}

struct drgn_error *open_elf_file(const char *path, int *fd_ret, Elf **elf_ret)
{
	struct drgn_error *err;

	*fd_ret = open(path, O_RDONLY);
	if (*fd_ret == -1)
		return drgn_error_create_os("open", errno, path);
	*elf_ret = dwelf_elf_begin(*fd_ret);
	if (!*elf_ret) {
		err = drgn_error_libelf();
		goto err_fd;
	}
	if (elf_kind(*elf_ret) != ELF_K_ELF) {
		err = drgn_error_create(DRGN_ERROR_OTHER, "not an ELF file");
		goto err_elf;
	}
	return NULL;

err_elf:
	elf_end(*elf_ret);
err_fd:
	close(*fd_ret);
	return err;
}

struct drgn_error *find_elf_file(char **path_ret, int *fd_ret, Elf **elf_ret,
				 const char * const *path_formats, ...)
{
	struct drgn_error *err;
	size_t i;

	for (i = 0; path_formats[i]; i++) {
		va_list ap;
		int ret;
		char *path;
		int fd;
		Elf *elf;

		va_start(ap, path_formats);
		ret = vasprintf(&path, path_formats[i], ap);
		va_end(ap);
		if (ret == -1)
			return &drgn_enomem;
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			free(path);
			continue;
		}
		elf = dwelf_elf_begin(fd);
		if (!elf) {
			close(fd);
			free(path);
			continue;
		}
		if (elf_kind(elf) != ELF_K_ELF) {
			err = drgn_error_format(DRGN_ERROR_OTHER,
						"%s: not an ELF file", path);
			elf_end(elf);
			close(fd);
			free(path);
			return err;
		}
		*path_ret = path;
		*fd_ret = fd;
		*elf_ret = elf;
		return NULL;
	}
	*path_ret = NULL;
	*fd_ret = -1;
	*elf_ret = NULL;
	return NULL;
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

struct drgn_error *elf_address_range(Elf *elf, uint64_t bias,
				     uint64_t *start_ret, uint64_t *end_ret)
{
	uint64_t start = UINT64_MAX, end = 0;
	size_t phnum, i;

	/*
	 * Get the minimum and maximum addresses from the PT_LOAD segments. We
	 * ignore memory ranges that start beyond UINT64_MAX, and we truncate
	 * ranges that end beyond UINT64_MAX.
	 */
	if (elf_getphdrnum(elf, &phnum) != 0)
		return drgn_error_libelf();
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;
		uint64_t segment_start, segment_end;

		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return drgn_error_libelf();
		if (phdr->p_type != PT_LOAD || !phdr->p_vaddr)
			continue;
		if (__builtin_add_overflow(phdr->p_vaddr, bias,
					   &segment_start))
			continue;
		if (__builtin_add_overflow(segment_start, phdr->p_memsz,
					   &segment_end))
			segment_end = UINT64_MAX;
		if (segment_start < segment_end) {
			if (segment_start < start)
				start = segment_start;
			if (segment_end > end)
				end = segment_end;
		}
	}
	if (start >= end) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "ELF file has no loadable segments");
	}
	*start_ret = start;
	*end_ret = end;
	return NULL;
}
