// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <byteswap.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwelf.h>
#include <elfutils/version.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "binary_buffer.h"
#include "cleanup.h"
#include "debug_info.h"
#include "elf_file.h"
#include "error.h"
#include "linux_kernel.h"
#include "openmp.h"
#include "platform.h"
#include "program.h"
#include "util.h"

static inline Dwarf *drgn_elf_file_dwarf_key(struct drgn_elf_file * const *entry)
{
	return (*entry)->dwarf;
}
DEFINE_HASH_TABLE_FUNCTIONS(drgn_elf_file_dwarf_table, drgn_elf_file_dwarf_key,
			    ptr_key_hash_pair, scalar_key_eq);
DEFINE_VECTOR_FUNCTIONS(drgn_module_vector);

struct drgn_module_key {
	const void *build_id;
	size_t build_id_len;
	uint64_t start, end;
};

static inline struct drgn_module_key
drgn_module_key(struct drgn_module * const *entry)
{
	return (struct drgn_module_key){
		.build_id = (*entry)->build_id,
		.build_id_len = (*entry)->build_id_len,
		.start = (*entry)->start,
		.end = (*entry)->end,
	};
}

static inline struct hash_pair
drgn_module_key_hash_pair(const struct drgn_module_key *key)
{
	size_t hash = hash_bytes(key->build_id, key->build_id_len);
	hash = hash_combine(hash, key->start);
	hash = hash_combine(hash, key->end);
	return hash_pair_from_avalanching_hash(hash);
}
static inline bool drgn_module_key_eq(const struct drgn_module_key *a,
				      const struct drgn_module_key *b)
{
	return (a->build_id_len == b->build_id_len &&
		memcmp(a->build_id, b->build_id, a->build_id_len) == 0 &&
		a->start == b->start && a->end == b->end);
}
DEFINE_HASH_TABLE_FUNCTIONS(drgn_module_table, drgn_module_key,
			    drgn_module_key_hash_pair, drgn_module_key_eq);

DEFINE_HASH_SET_FUNCTIONS(c_string_set, c_string_key_hash_pair,
			  c_string_key_eq);

/**
 * @c Dwfl_Callbacks::find_elf() implementation.
 *
 * If the ELF file was reported directly, this returns it. Otherwise, it falls
 * back to an appropriate callback.
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
	struct drgn_module *module = *userdatap;
	if (module->elf) {
		*file_name = module->path;
		int fd = module->fd;
		*elfp = module->elf;
		// libdwfl consumes the returned path, file descriptor, and ELF
		// handle, so clear the fields.
		module->path = NULL;
		module->fd = -1;
		module->elf = NULL;
		return fd;
	}
	if (module->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		*elfp = NULL;
		return -1;
	} else if (module->prog->flags & DRGN_PROGRAM_IS_LIVE) {
		return dwfl_linux_proc_find_elf(dwfl_module, userdatap, name,
						base, file_name, elfp);
	} else {
		return dwfl_build_id_find_elf(dwfl_module, userdatap, name,
					      base, file_name, elfp);
	}
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

static void drgn_module_destroy(struct drgn_module *module)
{
	if (module) {
		drgn_error_destroy(module->err);
		drgn_module_orc_info_deinit(module);
		drgn_module_dwarf_info_deinit(module);
		elf_end(module->elf);
		if (module->fd != -1)
			close(module->fd);
		free(module->path);
		for (struct drgn_elf_file_dwarf_table_iterator it =
		     drgn_elf_file_dwarf_table_first(&module->split_dwarf_files);
		     it.entry;
		     it = drgn_elf_file_dwarf_table_next(it))
			drgn_elf_file_destroy(*it.entry);
		drgn_elf_file_dwarf_table_deinit(&module->split_dwarf_files);
		if (module->debug_file != module->loaded_file)
			drgn_elf_file_destroy(module->debug_file);
		drgn_elf_file_destroy(module->loaded_file);
		free(module->name);
		free(module);
	}
}

static void drgn_module_finish_indexing(struct drgn_debug_info *dbinfo,
					struct drgn_module *module)
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

/*
 * Wrapper around dwfl_report_end() that works around a libdwfl bug which causes
 * it to close stdin when it frees some modules that were reported by
 * dwfl_core_file_report(). This was fixed in elfutils 0.177 by commit
 * d37f6ea7e3e5 ("libdwfl: Fix fd leak/closing wrong fd after
 * dwfl_core_file_report()"), but we support older versions.
 */
static int my_dwfl_report_end(struct drgn_debug_info *dbinfo,
			      int (*removed)(Dwfl_Module *, void *,
					     const char *, Dwarf_Addr, void *),
			      void *arg)
{
	int fd = -1;
	if ((dbinfo->prog->flags
	     & (DRGN_PROGRAM_IS_LINUX_KERNEL | DRGN_PROGRAM_IS_LIVE)) == 0)
		fd = dup(0);
	int ret = dwfl_report_end(dbinfo->dwfl, removed, arg);
	if (fd != -1) {
		dup2(fd, 0);
		close(fd);
	}
	return ret;
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
	struct drgn_module *module = *(void **)userdatap;
	if (arg->finish_indexing && module &&
	    module->state == DRGN_DEBUG_INFO_MODULE_INDEXING)
		drgn_module_finish_indexing(arg->dbinfo, module);
	if (arg->free_all || !module ||
	    module->state != DRGN_DEBUG_INFO_MODULE_INDEXED) {
		drgn_module_destroy(module);
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
	for (struct drgn_module_table_iterator it =
	     drgn_module_table_first(&dbinfo->modules); it.entry; ) {
		struct drgn_module *module = *it.entry;
		struct drgn_module **nextp = it.entry;
		do {
			struct drgn_module *next = module->next;
			if (finish_indexing &&
			    module->state == DRGN_DEBUG_INFO_MODULE_INDEXING)
				drgn_module_finish_indexing(dbinfo, module);
			if (free_all ||
			    module->state != DRGN_DEBUG_INFO_MODULE_INDEXED) {
				if (module == *nextp) {
					if (nextp == it.entry && !next) {
						it = drgn_module_table_delete_iterator(&dbinfo->modules,
										       it);
					} else {
						if (!next)
							it = drgn_module_table_next(it);
						*nextp = next;
					}
				}
				void **userdatap;
				dwfl_module_info(module->dwfl_module,
						 &userdatap, NULL, NULL, NULL,
						 NULL, NULL, NULL);
				*userdatap = NULL;
				drgn_module_destroy(module);
			} else {
				if (!next)
					it = drgn_module_table_next(it);
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
	my_dwfl_report_end(dbinfo, drgn_dwfl_module_removed, &arg);
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
				   "missing some debugging symbols (see https://drgn.readthedocs.io/en/latest/getting_debugging_symbols.html):"))
		goto err;
	if (load->num_errors < load->max_errors) {
		if (!string_builder_line_break(&load->errors))
			goto err;
		if (!string_builder_append(&load->errors, "  "))
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
	// Silence -Wmaybe-uninitialized false positive last seen with GCC 12 on
	// i386 and Arm.
	struct drgn_module_table_iterator it = {};
	if (build_id_len) {
		struct drgn_module_key key = {
			.build_id = build_id,
			.build_id_len = build_id_len,
			.start = start,
			.end = end,
		};
		hp = drgn_module_table_hash(&key);
		it = drgn_module_table_search_hashed(&dbinfo->modules, &key,
						     hp);
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

	struct drgn_module *module = calloc(1, sizeof(*module));
	if (!module) {
		err = &drgn_enomem;
		goto free;
	}
	module->prog = load->dbinfo->prog;
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
	}
	module->dwfl_module = dwfl_module;
	module->path = path_key;
	module->fd = fd;
	module->elf = elf;
	drgn_elf_file_dwarf_table_init(&module->split_dwarf_files);

	/* path_key, fd and elf are owned by the module now. */

	if (!drgn_module_vector_append(&load->new_modules, &module)) {
		drgn_module_destroy(module);
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
		} else if (drgn_module_table_insert_searched(&dbinfo->modules,
							     &module, hp,
							     NULL) < 0) {
			drgn_module_vector_pop(&load->new_modules);
			drgn_module_destroy(module);
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
						   drgn_error_libelf());
		elf_end(elf);
		close(fd);
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

static struct drgn_error *drgn_get_nt_file(Elf *elf, const char **ret,
					   size_t *len_ret)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum) != 0)
		return drgn_error_libelf();
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return drgn_error_libelf();
		if (phdr->p_type == PT_NOTE) {
			Elf_Data *data = elf_getdata_rawchunk(elf,
							      phdr->p_offset,
							      phdr->p_filesz,
							      note_header_type(phdr->p_align));
			if (!data)
				return drgn_error_libelf();
			GElf_Nhdr nhdr;
			size_t offset = 0, name_offset, desc_offset;
			while (offset < data->d_size &&
			       (offset = gelf_getnote(data, offset, &nhdr,
						      &name_offset,
						      &desc_offset))) {
				const char *name =
					(char *)data->d_buf + name_offset;
				if (nhdr.n_namesz == sizeof("CORE") &&
				    memcmp(name, "CORE", sizeof("CORE")) == 0 &&
				    nhdr.n_type == NT_FILE) {
					*ret = (char *)data->d_buf + desc_offset;
					*len_ret = nhdr.n_descsz;
					return NULL;
				}
			}
		}
	}
	*ret = NULL;
	*len_ret = 0;
	return NULL;
}

struct drgn_mapped_file_segment {
	uint64_t start;
	uint64_t end;
	uint64_t file_offset;
};

DEFINE_VECTOR(drgn_mapped_file_segment_vector, struct drgn_mapped_file_segment);

DEFINE_HASH_MAP(drgn_mapped_files, const char *,
		struct drgn_mapped_file_segment_vector, c_string_key_hash_pair,
		c_string_key_eq);

struct userspace_core_report_state {
	struct drgn_mapped_files files;
	void *phdr_buf;
	size_t phdr_buf_capacity;
	void *segment_buf;
	size_t segment_buf_capacity;
};

static struct drgn_error *parse_nt_file_error(struct binary_buffer *bb,
					      const char *pos,
					      const char *message)
{
	return drgn_error_create(DRGN_ERROR_OTHER, "couldn't parse NT_FILE");
}

static bool
drgn_mapped_file_segments_contiguous(const struct drgn_mapped_file_segment *segment1,
				     const struct drgn_mapped_file_segment *segment2)
{
	if (segment1->end != segment2->start)
		return false;
	uint64_t size = segment1->end - segment1->start;
	return segment1->file_offset + size == segment2->file_offset;
}

static struct drgn_error *
userspace_core_get_mapped_files(struct drgn_debug_info_load_state *load,
				struct userspace_core_report_state *core,
				const char *nt_file, size_t nt_file_len)
{
	struct drgn_error *err;

	GElf_Ehdr ehdr_mem, *ehdr = gelf_getehdr(load->dbinfo->prog->core,
						 &ehdr_mem);
	if (!ehdr)
		return drgn_error_libelf();
	bool is_64_bit = ehdr->e_ident[EI_CLASS] == ELFCLASS64;
	bool little_endian = ehdr->e_ident[EI_DATA] == ELFDATA2LSB;

	struct binary_buffer bb;
	binary_buffer_init(&bb, nt_file, nt_file_len, little_endian,
			   parse_nt_file_error);

	/*
	 * fs/binfmt_elf.c in the Linux kernel source code documents the format
	 * of NT_FILE as:
	 *
	 * long count     -- how many files are mapped
	 * long page_size -- units for file_ofs
	 * array of [COUNT] elements of
	 *   long start
	 *   long end
	 *   long file_ofs
	 * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
	 */
	uint64_t count, page_size;
	if (is_64_bit) {
		if ((err = binary_buffer_next_u64(&bb, &count)))
			return err;
		if (count > UINT64_MAX / 24)
			return binary_buffer_error(&bb, "count is too large");
		if ((err = binary_buffer_next_u64(&bb, &page_size)) ||
		    (err = binary_buffer_skip(&bb, count * 24)))
			return err;
	} else {
		if ((err = binary_buffer_next_u32_into_u64(&bb, &count)))
			return err;
		if (count > UINT64_MAX / 12)
			return binary_buffer_error(&bb, "count is too large");
		if ((err = binary_buffer_next_u32_into_u64(&bb, &page_size)) ||
		    (err = binary_buffer_skip(&bb, count * 12)))
			return err;
	}

	for (uint64_t i = 0; i < count; i++) {
		struct drgn_mapped_file_segment segment;
		if (is_64_bit) {
			memcpy(&segment, nt_file + 16 + i * 24, 24);
			if (bb.bswap) {
				segment.start = bswap_64(segment.start);
				segment.end = bswap_64(segment.end);
				segment.file_offset = bswap_64(segment.file_offset);
			}
		} else {
			struct {
				uint32_t start;
				uint32_t end;
				uint32_t file_offset;
			} segment32;
			memcpy(&segment32, nt_file + 8 + i * 12, 12);
			if (bb.bswap) {
				segment.start = bswap_32(segment32.start);
				segment.end = bswap_32(segment32.end);
				segment.file_offset = bswap_32(segment32.file_offset);
			} else {
				segment.start = segment32.start;
				segment.end = segment32.end;
				segment.file_offset = segment32.file_offset;
			}
		}
		segment.file_offset *= page_size;

		struct drgn_mapped_files_entry entry = {
			.key = bb.pos,
		};
		if ((err = binary_buffer_skip_string(&bb)))
			return err;
		struct drgn_mapped_files_iterator it;
		int r = drgn_mapped_files_insert(&core->files, &entry, &it);
		if (r < 0)
			return &drgn_enomem;
		if (r == 1)
			drgn_mapped_file_segment_vector_init(&it.entry->value);

		/*
		 * The Linux kernel creates separate entries for contiguous
		 * mappings with different memory protections even though the
		 * protection is not included in NT_FILE. Merge them if we can.
		 */
		if (!drgn_mapped_file_segment_vector_empty(&it.entry->value)
		    && drgn_mapped_file_segments_contiguous(drgn_mapped_file_segment_vector_last(&it.entry->value),
							    &segment))
			drgn_mapped_file_segment_vector_last(&it.entry->value)->end = segment.end;
		else if (!drgn_mapped_file_segment_vector_append(&it.entry->value,
								 &segment))
			return &drgn_enomem;
	}
	return NULL;
}

static bool build_id_matches(Elf *elf, const void *build_id,
			     size_t build_id_len)
{
	const void *elf_build_id;
	ssize_t elf_build_id_len = dwelf_elf_gnu_build_id(elf, &elf_build_id);
	if (elf_build_id_len < 0)
		return false;
	return (elf_build_id_len == build_id_len &&
		memcmp(elf_build_id, build_id, build_id_len) == 0);
}

static struct drgn_error *
userspace_core_elf_address_range(uint16_t e_type, size_t phnum,
				 struct drgn_error *(*get_phdr)(void *, size_t, GElf_Phdr *),
				 void *arg,
				 const struct drgn_mapped_file_segment *segments,
				 size_t num_segments,
				 const struct drgn_mapped_file_segment *ehdr_segment,
				 uint64_t *bias_ret, uint64_t *start_ret,
				 uint64_t *end_ret)
{
	struct drgn_error *err;

	/*
	 * First, find the virtual address of the ELF header so that we can
	 * calculate the bias.
	 */
	uint64_t ehdr_vaddr;
	size_t i;
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr;
		err = get_phdr(arg, i, &phdr);
		if (err)
			return err;
		if (phdr.p_type == PT_LOAD) {
			uint64_t align = phdr.p_align ? phdr.p_align : 1;
			if ((phdr.p_offset & -align) == 0) {
				ehdr_vaddr = phdr.p_vaddr & -align;
				break;
			}
		}
	}
	if (i >= phnum) {
		/*
		 * No loadable segments contain the ELF header. This can't be
		 * our file.
		 */
		*bias_ret = 0;
not_loaded:
		*start_ret = *end_ret = 0;
		return NULL;
	}
	*bias_ret = ehdr_segment->start - ehdr_vaddr;
	if (*bias_ret != 0 && e_type == ET_EXEC) {
		/* The executable is not loaded at the correct address. */
		goto not_loaded;
	}

	/*
	 * Now check all of the program headers to (1) get the module address
	 * range and (2) make sure that they are mapped as expected. If we're
	 * lucky, this can detect a file that was mmap'd and not actually loaded
	 * by the kernel or dynamic loader. This could also be the wrong file.
	 */
	const struct drgn_mapped_file_segment *segment = segments;
	const struct drgn_mapped_file_segment *end_segment =
		segments + num_segments;
	uint64_t start = 0, end = 0;
	bool first = true;
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr;
		err = get_phdr(arg, i, &phdr);
		if (err)
			return err;
		if (phdr.p_type != PT_LOAD)
			continue;
		uint64_t vaddr = phdr.p_vaddr + *bias_ret;
		if (phdr.p_filesz != 0) {
			/*
			 * Advance to the mapped segment containing the start
			 * address.
			 */
			while (vaddr >= segment->end) {
				if (++segment == end_segment)
					goto not_loaded;
				if (vaddr < segment->start)
					goto not_loaded;
			}
			if (segment->file_offset + (vaddr - segment->start) !=
			    phdr.p_offset) {
				/*
				 * The address in the core dump does not map to
				 * the segment's file offset.
				 */
				goto not_loaded;
			}
			if (phdr.p_filesz > segment->end - vaddr) {
				/* Part of the segment is not mapped. */
				goto not_loaded;
			}
		}
		if (first) {
			uint64_t align = phdr.p_align ? phdr.p_align : 1;
			start = vaddr & -align;
			first = false;
		}
		end = vaddr + phdr.p_memsz;
	}
	if (start >= end)
		goto not_loaded;
	*start_ret = start;
	*end_ret = end;
	return NULL;
}

/* ehdr_buf must be aligned as Elf64_Ehdr. */
static void read_ehdr(const void *ehdr_buf, GElf_Ehdr *ret, bool *is_64_bit_ret,
		      bool *bswap_ret)
{
	*is_64_bit_ret = ((unsigned char *)ehdr_buf)[EI_CLASS] == ELFCLASS64;
	bool little_endian =
		((unsigned char *)ehdr_buf)[EI_DATA] == ELFDATA2LSB;
	*bswap_ret = little_endian != HOST_LITTLE_ENDIAN;
	if (*is_64_bit_ret) {
		const Elf64_Ehdr *ehdr64 = ehdr_buf;
		if (*bswap_ret) {
			memcpy(ret->e_ident, ehdr64->e_ident, EI_NIDENT);
			ret->e_type = bswap_16(ehdr64->e_type);
			ret->e_machine = bswap_16(ehdr64->e_machine);
			ret->e_version = bswap_32(ehdr64->e_version);
			ret->e_entry = bswap_64(ehdr64->e_entry);
			ret->e_phoff = bswap_64(ehdr64->e_phoff);
			ret->e_shoff = bswap_64(ehdr64->e_shoff);
			ret->e_flags = bswap_32(ehdr64->e_flags);
			ret->e_ehsize = bswap_16(ehdr64->e_ehsize);
			ret->e_phentsize = bswap_16(ehdr64->e_phentsize);
			ret->e_phnum = bswap_16(ehdr64->e_phnum);
			ret->e_shentsize = bswap_16(ehdr64->e_shentsize);
			ret->e_shnum = bswap_16(ehdr64->e_shnum);
			ret->e_shstrndx = bswap_16(ehdr64->e_shstrndx);
		} else {
			*ret = *ehdr64;
		}
	} else {
		const Elf32_Ehdr *ehdr32 = ehdr_buf;
		memcpy(ret->e_ident, ehdr32->e_ident, EI_NIDENT);
		if (*bswap_ret) {
			ret->e_type = bswap_16(ehdr32->e_type);
			ret->e_machine = bswap_16(ehdr32->e_machine);
			ret->e_version = bswap_32(ehdr32->e_version);
			ret->e_entry = bswap_32(ehdr32->e_entry);
			ret->e_phoff = bswap_32(ehdr32->e_phoff);
			ret->e_shoff = bswap_32(ehdr32->e_shoff);
			ret->e_flags = bswap_32(ehdr32->e_flags);
			ret->e_ehsize = bswap_16(ehdr32->e_ehsize);
			ret->e_phentsize = bswap_16(ehdr32->e_phentsize);
			ret->e_phnum = bswap_16(ehdr32->e_phnum);
			ret->e_shentsize = bswap_16(ehdr32->e_shentsize);
			ret->e_shnum = bswap_16(ehdr32->e_shnum);
			ret->e_shstrndx = bswap_16(ehdr32->e_shstrndx);
		} else {
			ret->e_type = ehdr32->e_type;
			ret->e_machine = ehdr32->e_machine;
			ret->e_version = ehdr32->e_version;
			ret->e_entry = ehdr32->e_entry;
			ret->e_phoff = ehdr32->e_phoff;
			ret->e_shoff = ehdr32->e_shoff;
			ret->e_flags = ehdr32->e_flags;
			ret->e_ehsize = ehdr32->e_ehsize;
			ret->e_phentsize = ehdr32->e_phentsize;
			ret->e_phnum = ehdr32->e_phnum;
			ret->e_shentsize = ehdr32->e_shentsize;
			ret->e_shnum = ehdr32->e_shnum;
			ret->e_shstrndx = ehdr32->e_shstrndx;
		}
	}
}

/* phdr_buf must be aligned as Elf64_Phdr. */
static void read_phdr(const void *phdr_buf, size_t i, bool is_64_bit,
		      bool bswap, GElf_Phdr *ret)
{
	if (is_64_bit) {
		const Elf64_Phdr *phdr64 = (Elf64_Phdr *)phdr_buf + i;
		if (bswap) {
			ret->p_type = bswap_32(phdr64->p_type);
			ret->p_flags = bswap_32(phdr64->p_flags);
			ret->p_offset = bswap_64(phdr64->p_offset);
			ret->p_vaddr = bswap_64(phdr64->p_vaddr);
			ret->p_paddr = bswap_64(phdr64->p_paddr);
			ret->p_filesz = bswap_64(phdr64->p_filesz);
			ret->p_memsz = bswap_64(phdr64->p_memsz);
			ret->p_align = bswap_64(phdr64->p_align);
		} else {
			*ret = *phdr64;
		}
	} else {
		const Elf32_Phdr *phdr32 = (Elf32_Phdr *)phdr_buf + i;
		if (bswap) {
			ret->p_type = bswap_32(phdr32->p_type);
			ret->p_offset = bswap_32(phdr32->p_offset);
			ret->p_vaddr = bswap_32(phdr32->p_vaddr);
			ret->p_paddr = bswap_32(phdr32->p_paddr);
			ret->p_filesz = bswap_32(phdr32->p_filesz);
			ret->p_memsz = bswap_32(phdr32->p_memsz);
			ret->p_flags = bswap_32(phdr32->p_flags);
			ret->p_align = bswap_32(phdr32->p_align);
		} else {
			ret->p_type = phdr32->p_type;
			ret->p_offset = phdr32->p_offset;
			ret->p_vaddr = phdr32->p_vaddr;
			ret->p_paddr = phdr32->p_paddr;
			ret->p_filesz = phdr32->p_filesz;
			ret->p_memsz = phdr32->p_memsz;
			ret->p_flags = phdr32->p_flags;
			ret->p_align = phdr32->p_align;
		}
	}
}

static const char *read_build_id(const char *buf, size_t buf_len,
				 uint64_t align, bool bswap,
				 size_t *len_ret)
{
	/*
	 * Build IDs are usually 16 or 20 bytes (MD5 or SHA-1, respectively), so
	 * these arbitrary limits are generous.
	 */
	static const uint32_t build_id_min_size = 2;
	static const uint32_t build_id_max_size = 1024;
	/* Elf32_Nhdr is the same as Elf64_Nhdr. */
	Elf64_Nhdr nhdr;
	const char *p = buf;
	while (buf + buf_len - p >= sizeof(nhdr)) {
		memcpy(&nhdr, p, sizeof(nhdr));
		if (bswap) {
			nhdr.n_namesz = bswap_32(nhdr.n_namesz);
			nhdr.n_descsz = bswap_32(nhdr.n_descsz);
			nhdr.n_type = bswap_32(nhdr.n_type);
		}
		p += sizeof(nhdr);

		uint64_t namesz = (nhdr.n_namesz + align - 1) & ~(align - 1);
		if (namesz > buf + buf_len - p)
			return NULL;
		const char *name = p;
		p += namesz;

		if (nhdr.n_namesz == sizeof("GNU") &&
		    memcmp(name, "GNU", sizeof("GNU")) == 0 &&
		    nhdr.n_type == NT_GNU_BUILD_ID &&
		    nhdr.n_descsz >= build_id_min_size &&
		    nhdr.n_descsz <= build_id_max_size) {
			if (nhdr.n_descsz > buf + buf_len - p)
				return NULL;
			*len_ret = nhdr.n_descsz;
			return p;
		}

		uint64_t descsz = (nhdr.n_descsz + align - 1) & ~(align - 1);
		if (descsz > buf + buf_len - p)
			return NULL;
		p += descsz;
	}
	return NULL;
}

struct core_get_phdr_arg {
	const void *phdr_buf;
	bool is_64_bit;
	bool bswap;
};

static struct drgn_error *
core_get_phdr(void *arg_, size_t i, GElf_Phdr *ret)
{
	struct core_get_phdr_arg *arg = arg_;
	read_phdr(arg->phdr_buf, i, arg->is_64_bit, arg->bswap, ret);
	return NULL;
}

struct userspace_core_identified_file {
	const void *build_id;
	size_t build_id_len;
	uint64_t start, end;
	bool ignore;
	bool have_address_range;
};

static struct drgn_error *
userspace_core_identify_file(struct drgn_program *prog,
			     struct userspace_core_report_state *core,
			     const struct drgn_mapped_file_segment *segments,
			     size_t num_segments,
			     const struct drgn_mapped_file_segment *ehdr_segment,
			     struct userspace_core_identified_file *ret)
{
	struct drgn_error *err;

	Elf64_Ehdr ehdr_buf;
	err = drgn_program_read_memory(prog, &ehdr_buf, ehdr_segment->start,
				       sizeof(ehdr_buf), false);
	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}
	if (memcmp(&ehdr_buf, ELFMAG, SELFMAG) != 0) {
		ret->ignore = true;
		return NULL;
	}

	GElf_Ehdr ehdr;
	struct core_get_phdr_arg arg;
	read_ehdr(&ehdr_buf, &ehdr, &arg.is_64_bit, &arg.bswap);
	if (ehdr.e_type == ET_CORE ||
	    ehdr.e_phnum == 0 ||
	    ehdr.e_phentsize !=
	    (arg.is_64_bit ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr))) {
		ret->ignore = true;
		return NULL;
	}

	if (ehdr.e_phnum > SIZE_MAX / ehdr.e_phentsize ||
	    !alloc_or_reuse(&core->phdr_buf, &core->phdr_buf_capacity,
			    ehdr.e_phnum * ehdr.e_phentsize))
		return &drgn_enomem;

	/*
	 * Check whether the mapped segment containing the file header also
	 * contains the program headers. This seems to be the case in practice.
	 */
	uint64_t ehdr_segment_file_end =
		(ehdr_segment->file_offset +
		 (ehdr_segment->end - ehdr_segment->start));
	if (ehdr_segment_file_end < ehdr.e_phoff ||
	    ehdr_segment_file_end - ehdr.e_phoff <
	    ehdr.e_phnum * ehdr.e_phentsize)
		return NULL;

	err = drgn_program_read_memory(prog, core->phdr_buf,
				       ehdr_segment->start + ehdr.e_phoff,
				       ehdr.e_phnum * ehdr.e_phentsize, false);
	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			drgn_error_destroy(err);
			err = NULL;
		}
		return err;
	}
	arg.phdr_buf = core->phdr_buf;

	/*
	 * In theory, if the program has a huge number of program headers, they
	 * may not all be dumped. However, the largest binary I was able to find
	 * still had all program headers within 1k.
	 *
	 * It'd be more reliable to determine the bias based on the headers that
	 * were saved, use that to read the build ID, use that to find the ELF
	 * file, and then determine the address range directly from the ELF
	 * file. However, we need the address range to report the build ID to
	 * libdwfl, so we do it this way.
	 */
	uint64_t bias;
	err = userspace_core_elf_address_range(ehdr.e_type, ehdr.e_phnum,
					       core_get_phdr, &arg, segments,
					       num_segments, ehdr_segment,
					       &bias, &ret->start, &ret->end);
	if (err)
		return err;
	if (ret->start >= ret->end) {
		ret->ignore = true;
		return NULL;
	}
	ret->have_address_range = true;

	for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
		GElf_Phdr phdr;
		core_get_phdr(&arg, i, &phdr);
		if (phdr.p_type == PT_NOTE) {
			if (phdr.p_filesz > SIZE_MAX ||
			    !alloc_or_reuse(&core->segment_buf,
					    &core->segment_buf_capacity,
					    phdr.p_filesz))
				return &drgn_enomem;
			err = drgn_program_read_memory(prog, core->segment_buf,
						       phdr.p_vaddr + bias,
						       phdr.p_filesz, false);
			if (err) {
				if (err->code == DRGN_ERROR_FAULT) {
					drgn_error_destroy(err);
					continue;
				} else {
					return err;
				}
			}
			ret->build_id = read_build_id(core->segment_buf,
						      phdr.p_filesz,
						      phdr.p_align, arg.bswap,
						      &ret->build_id_len);
			if (ret->build_id)
				break;
		}
	}
	return NULL;
}

static struct drgn_error *elf_file_get_phdr(void *arg, size_t i,
					    GElf_Phdr *phdr)
{
	if (!gelf_getphdr(arg, i, phdr))
		return drgn_error_libelf();
	return NULL;
}

static struct drgn_error *
userspace_core_maybe_report_file(struct drgn_debug_info_load_state *load,
				 struct userspace_core_report_state *core,
				 const char *path,
				 const struct drgn_mapped_file_segment *segments,
				 size_t num_segments)
{
	struct drgn_error *err;
	struct drgn_program *prog = load->dbinfo->prog;
	for (size_t ehdr_idx = 0; ehdr_idx < num_segments; ehdr_idx++) {
		const struct drgn_mapped_file_segment *ehdr_segment =
			&segments[ehdr_idx];
		/*
		 * There should always be a full page mapped, so even if it's a
		 * 32-bit file, we can read the 64-bit size.
		 */
		if (ehdr_segment->file_offset != 0 ||
		    ehdr_segment->end - ehdr_segment->start < sizeof(Elf64_Ehdr))
			continue;

		/*
		 * This logic is complicated because we're dealing with two data
		 * sources that we can't completely trust: the memory in the
		 * core dump and the file at the path found in the core dump.
		 *
		 * First, we try to identify the mapped file contents in the
		 * core dump. Ideally, this will find a build ID. However, this
		 * can fail for a few reasons:
		 *
		 * 1. The file is not an ELF file.
		 * 2. The ELF file is not an executable or library.
		 * 3. The ELF file does not have a build ID.
		 * 4. The file header was not dumped to the core dump, in which
		 *    case we can't tell whether this is an ELF file. Dumping
		 *    the first page of an executable file has been the default
		 *    behavior since Linux kernel commit 895021552d6f
		 *    ("coredump: default
		 *    CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS=y") (in v2.6.37), but
		 *    it can be disabled at kernel build time or toggled at
		 *    runtime.
		 * 5. The build ID or the necessary ELF metadata were not dumped
		 *    in the core dump. This can happen if the necessary program
		 *    headers or note segment were not in the first page of the
		 *    file.
		 * 6. The file is mapped but not actually loaded into the
		 *    program (e.g., if the program is a tool like a profiler or
		 *    a debugger that mmaps binaries [like drgn itself!]).
		 *
		 * In cases 1 and 2, we can simply ignore the file. In cases
		 * 3-5, we blindly trust the path in the core dump. We can
		 * sometimes detect case 6 in
		 * userspace_core_elf_address_range().
		 *
		 * There is also the possibility that the program modified or
		 * corrupted the ELF metadata in memory (more likely if the file
		 * was explicitly mmap'd, since the metadata will usually be
		 * read-only if it was loaded properly). We don't deal with that
		 * yet.
		 */
		struct userspace_core_identified_file identity = {};
		err = userspace_core_identify_file(prog, core, segments,
						   num_segments, ehdr_segment,
						   &identity);
		if (err)
			return err;
		if (identity.ignore)
			continue;

#define CLEAR_ELF() do {	\
	elf = NULL;		\
	fd = -1;		\
} while (0)
#define CLOSE_ELF() do {	\
	elf_end(elf);		\
	close(fd);		\
	CLEAR_ELF();		\
} while (0)
		int fd;
		Elf *elf;
		/*
		 * There are a few things that can go wrong here:
		 *
		 * 1. The path no longer exists.
		 * 2. The path refers to a different ELF file than was in the
		 *    core dump.
		 * 3. The path refers to something which isn't a valid ELF file.
		 */
		err = open_elf_file(path, &fd, &elf);
		if (err) {
			drgn_error_destroy(err);
			CLEAR_ELF();
		} else if (identity.build_id_len > 0) {
			if (!build_id_matches(elf, identity.build_id,
					      identity.build_id_len))
				CLOSE_ELF();
		}

		if (elf && !identity.have_address_range) {
			GElf_Ehdr ehdr_mem, *ehdr;
			size_t phnum;
			if ((ehdr = gelf_getehdr(elf, &ehdr_mem)) &&
			    (elf_getphdrnum(elf, &phnum) == 0)) {
				uint64_t bias;
				err = userspace_core_elf_address_range(ehdr->e_type,
								       phnum,
								       elf_file_get_phdr,
								       elf,
								       segments,
								       num_segments,
								       ehdr_segment,
								       &bias,
								       &identity.start,
								       &identity.end);
				if (err || identity.start >= identity.end) {
					drgn_error_destroy(err);
					CLOSE_ELF();
				} else {
					identity.have_address_range = true;
				}
			} else {
				CLOSE_ELF();
			}
		}

		if (elf) {
			err = drgn_debug_info_report_elf(load, path, fd, elf,
							 identity.start,
							 identity.end, NULL,
							 NULL);
			if (err)
				return err;
		} else {
			if (!identity.have_address_range)
				identity.start = identity.end = 0;
			Dwfl_Module *dwfl_module =
				dwfl_report_module(load->dbinfo->dwfl, path,
						   identity.start,
						   identity.end);
			if (!dwfl_module)
				return drgn_error_libdwfl();
			if (identity.build_id_len > 0 &&
			    dwfl_module_report_build_id(dwfl_module,
							identity.build_id,
							identity.build_id_len,
							0))
				return drgn_error_libdwfl();
		}
#undef CLOSE_ELF
#undef CLEAR_ELF
	}
	return NULL;
}

static struct drgn_error *
userspace_core_report_mapped_files(struct drgn_debug_info_load_state *load,
				   struct userspace_core_report_state *core)
{

	struct drgn_error *err;
	for (struct drgn_mapped_files_iterator it =
	     drgn_mapped_files_first(&core->files);
	     it.entry; it = drgn_mapped_files_next(it)) {
		err = userspace_core_maybe_report_file(load, core,
						       it.entry->key,
						       drgn_mapped_file_segment_vector_begin(&it.entry->value),
						       drgn_mapped_file_segment_vector_size(&it.entry->value));
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
userspace_core_report_debug_info(struct drgn_debug_info_load_state *load,
				 const char *nt_file, size_t nt_file_len)
{
	struct drgn_error *err;

	struct userspace_core_report_state core = {
		.files = HASH_TABLE_INIT,
	};
	err = userspace_core_get_mapped_files(load, &core, nt_file,
					      nt_file_len);
	if (err)
		goto out;
	err = userspace_core_report_mapped_files(load, &core);
out:
	free(core.segment_buf);
	free(core.phdr_buf);
	for (struct drgn_mapped_files_iterator it =
	     drgn_mapped_files_first(&core.files);
	     it.entry; it = drgn_mapped_files_next(it))
		drgn_mapped_file_segment_vector_deinit(&it.entry->value);
	drgn_mapped_files_deinit(&core.files);
	return err;
}

static struct drgn_error *
userspace_report_elf_file(struct drgn_debug_info_load_state *load,
			  const char *path)
{
	struct drgn_error *err;

	int fd;
	Elf *elf;
	err = open_elf_file(path, &fd, &elf);
	if (err)
		goto err;

	GElf_Ehdr ehdr_mem, *ehdr;
	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr) {
		err = drgn_error_libelf();
		goto err_close;
	}
	/*
	 * We haven't implemented a way to get the load address for dynamically
	 * loaded or relocatable files, so for now we report those as unloaded.
	 */
	uint64_t start = 0, end = 0;
	if (ehdr->e_type == ET_EXEC || ehdr->e_type == ET_CORE) {
		err = elf_address_range(elf, 0, &start, &end);
		if (err)
			goto err_close;
	}

	return drgn_debug_info_report_elf(load, path, fd, elf, start, end, NULL,
					  NULL);

err_close:
	elf_end(elf);
	close(fd);
err:
	return drgn_debug_info_report_error(load, path, NULL, err);
}

static struct drgn_error *
userspace_report_debug_info(struct drgn_debug_info_load_state *load)
{
	struct drgn_error *err;

	for (size_t i = 0; i < load->num_paths; i++) {
		err = userspace_report_elf_file(load, load->paths[i]);
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
		} else {
			const char *nt_file;
			size_t nt_file_len;
			char *env = getenv("DRGN_USE_LIBDWFL_REPORT");
			if (env && atoi(env)) {
				nt_file = NULL;
				nt_file_len = 0;
			} else {
				err = drgn_get_nt_file(prog->core, &nt_file,
						       &nt_file_len);
				if (err)
					return err;
			}
			if (nt_file) {
				err = userspace_core_report_debug_info(load,
								       nt_file,
								       nt_file_len);
				if (err)
					return err;
			} else if (dwfl_core_file_report(dwfl, prog->core,
							 NULL) == -1) {
				return drgn_error_libdwfl();
			}
		}
	}
	return NULL;
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
	return (strstartswith(scnname, "debug_") ||
		strstartswith(scnname, "orc_"));
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

/*
 * Before the debugging information in a relocatable ELF file (e.g., Linux
 * kernel module) can be used, it must have ELF relocations applied. This is
 * usually done by libdwfl. However, libdwfl is relatively slow at it. This is a
 * much faster implementation.
 */
static struct drgn_error *relocate_elf_file(Elf *elf)
{
	struct drgn_error *err;

	GElf_Ehdr ehdr_mem, *ehdr;
	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr)
		return drgn_error_libelf();

	if (ehdr->e_type != ET_REL) {
		/* Not a relocatable file. */
		return NULL;
	}

	struct drgn_platform platform;
	drgn_platform_from_elf(ehdr, &platform);
	if (!platform.arch->apply_elf_reloc) {
		/* Unsupported; fall back to libdwfl. */
		return NULL;
	}

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
			Elf_Scn *scn = elf_getscn(elf, reloc_shdr->sh_info);
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
			if ((err = read_elf_section(scn, &data)) ||
			    (err = read_elf_section(reloc_scn, &reloc_data)) ||
			    (err = read_elf_section(symtab_scn, &symtab_data)))
				return err;

			struct drgn_relocating_section relocating = {
				.buf = data->d_buf,
				.buf_size = data->d_size,
				.addr = sh_addrs[elf_ndxscn(scn)],
				.bswap = drgn_platform_bswap(&platform),
			};

			if (reloc_shdr->sh_type == SHT_RELA) {
				err = apply_elf_relas(&relocating, reloc_data,
						      symtab_data, sh_addrs,
						      shdrnum, &platform);
			} else {
				err = apply_elf_rels(&relocating, reloc_data,
						     symtab_data, sh_addrs,
						     shdrnum, &platform);
			}
			if (err)
				return err;

			/*
			 * Mark the relocation section as empty so that libdwfl
			 * doesn't try to apply it again.
			 */
			reloc_shdr->sh_size = 0;
			if (!gelf_update_shdr(reloc_scn, reloc_shdr))
				return drgn_error_libelf();
			reloc_data->d_size = 0;
		}
	}
	return NULL;
}

static struct drgn_error *
drgn_module_find_files(struct drgn_debug_info_load_state *load,
		       struct drgn_module *module)
{
	struct drgn_error *err;

	if (module->elf) {
		err = relocate_elf_file(module->elf);
		if (err)
			return err;
	}

	GElf_Addr loaded_file_bias;
	Elf *loaded_elf = NULL;
	Dwarf_Addr debug_file_bias;
	Dwarf *dwarf;
	err = NULL;
	#pragma omp critical(drgn_module_find_files)
	{
		// We don't need the loaded file for the Linux kernel, and we
		// always report the debug file as the main file to libdwfl.
		if (!(load->dbinfo->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
			loaded_elf = dwfl_module_getelf(module->dwfl_module,
							&loaded_file_bias);
			if (!loaded_elf)
				err = drgn_error_libdwfl();
		}
		if (!err) {
			dwarf = dwfl_module_getdwarf(module->dwfl_module,
						     &debug_file_bias);
			if (!dwarf)
				err = drgn_error_libdwfl();
		}
	}
	if (err)
		return err;

	const char *loaded_file_path;
	const char *debug_file_path;
	dwfl_module_info(module->dwfl_module, NULL, NULL, NULL, NULL, NULL,
			 &loaded_file_path, &debug_file_path);
	// If the loaded file also has debugging information, debug_file_path is
	// NULL. (debug_file_path is also NULL if libdwfl got the debug file
	// from debuginfod, so this isn't 100% correct, but it'll at least
	// identify the module.)
	if (!debug_file_path)
		debug_file_path = loaded_file_path;

	module->debug_file_bias = debug_file_bias;
	err = drgn_elf_file_create(module, debug_file_path, dwarf_getelf(dwarf),
				   &module->debug_file);
	if (err) {
		module->debug_file = NULL;
		return err;
	}
	module->debug_file->dwarf = dwarf;
	if (!module->debug_file->scns[DRGN_SCN_DEBUG_INFO] ||
	    !module->debug_file->scns[DRGN_SCN_DEBUG_ABBREV]) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "missing debugging information sections");
	}

	Dwarf *altdwarf = dwarf_getalt(dwarf);
	if (altdwarf) {
		Elf *altelf = dwarf_getelf(altdwarf);
		if (!altelf)
			return drgn_error_libdw();
		size_t shstrndx;
		if (elf_getshdrstrndx(altelf, &shstrndx))
			return drgn_error_libelf();

		Elf_Scn *scn = NULL;
		while ((scn = elf_nextscn(altelf, scn))) {
			GElf_Shdr shdr_mem;
			GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
			if (!shdr)
				return drgn_error_libelf();

			if (shdr->sh_type != SHT_PROGBITS)
				continue;
			const char *scnname = elf_strptr(altelf, shstrndx,
							 shdr->sh_name);
			if (!scnname)
				return drgn_error_libelf();

			/*
			 * TODO: save more sections and support imported units.
			 */
			if (strcmp(scnname, ".debug_info") == 0 &&
			    !module->debug_file->alt_debug_info_data) {
				err = read_elf_section(scn,
						       &module->debug_file->alt_debug_info_data);
				if (err)
					return err;
			} else if (strcmp(scnname, ".debug_str") == 0 &&
				   !module->debug_file->alt_debug_str_data) {
				err = read_elf_section(scn,
						       &module->debug_file->alt_debug_str_data);
				if (err)
					return err;
			}
		}
	}
	err = drgn_elf_file_precache_sections(module->debug_file);
	if (err)
		return err;

	if (loaded_elf) {
		module->loaded_file_bias = loaded_file_bias;
		if (loaded_elf == module->debug_file->elf) {
			module->loaded_file = module->debug_file;
		} else {
			err = drgn_elf_file_create(module, loaded_file_path,
						   loaded_elf,
						   &module->loaded_file);
			if (err) {
				module->loaded_file = NULL;
				return err;
			}
		}
	}
	return NULL;
}

static struct drgn_error *
drgn_debug_info_read_module(struct drgn_debug_info_load_state *load,
			    struct drgn_dwarf_index_state *index,
			    struct drgn_module *head)
{
	struct drgn_error *err;
	struct drgn_module *module;
	for (module = head; module; module = module->next) {
		err = drgn_module_find_files(load, module);
		if (err) {
			module->err = err;
			continue;
		}
		module->state = DRGN_DEBUG_INFO_MODULE_INDEXING;
		return drgn_dwarf_index_read_file(index, module->debug_file);
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
	if (drgn_module_vector_empty(&load->new_modules))
		return NULL;
	struct drgn_debug_info *dbinfo = load->dbinfo;
	if (!c_string_set_reserve(&dbinfo->module_names,
				  c_string_set_size(&dbinfo->module_names)
				  + drgn_module_vector_size(&load->new_modules)))
		return &drgn_enomem;

	struct drgn_dwarf_index_state index;
	if (!drgn_dwarf_index_state_init(&index, dbinfo))
		return &drgn_enomem;
	struct drgn_error *err = NULL;
	#pragma omp parallel for schedule(dynamic) num_threads(drgn_num_threads)
	for (size_t i = 0; i < drgn_module_vector_size(&load->new_modules); i++) {
		if (err)
			continue;
		struct drgn_module *module =
			*drgn_module_vector_at(&load->new_modules, i);
		struct drgn_error *module_err =
			drgn_debug_info_read_module(load, &index, module);
		if (module_err) {
			#pragma omp critical(drgn_debug_info_update_index_error)
			if (err)
				drgn_error_destroy(module_err);
			else
				err = module_err;
		}
	}
	if (!err) {
		drgn_debug_info_free_modules(dbinfo, true, false);
		err = drgn_dwarf_info_update_index(&index);
	}
	drgn_dwarf_index_state_deinit(&index);
	return err;
}

struct drgn_error *
drgn_debug_info_report_flush(struct drgn_debug_info_load_state *load)
{
	struct drgn_debug_info *dbinfo = load->dbinfo;
	my_dwfl_report_end(dbinfo, NULL, NULL);
	struct drgn_error *err = drgn_debug_info_update_index(load);
	dwfl_report_begin_add(dbinfo->dwfl);
	if (err)
		return err;
	drgn_module_vector_clear(&load->new_modules);
	return NULL;
}

static struct drgn_error *
drgn_debug_info_report_finalize_errors(struct drgn_debug_info_load_state *load)
{
	if (load->num_errors > load->max_errors &&
	    (!string_builder_line_break(&load->errors) ||
	     !string_builder_appendf(&load->errors, "... %u more",
				     load->num_errors - load->max_errors))) {
		string_builder_deinit(&load->errors);
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
		.errors = STRING_BUILDER_INIT,
		.max_errors = max_errors ? atoi(max_errors) : 5,
	};
	dwfl_report_begin_add(dbinfo->dwfl);
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		err = linux_kernel_report_debug_info(&load);
	else
		err = userspace_report_debug_info(&load);
	my_dwfl_report_end(dbinfo, NULL, NULL);
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
	 * TODO: for core dumps, we need to add memory reader segments for
	 * read-only segments of the loaded binaries since those aren't saved in
	 * the core dump.
	 */

	err = drgn_debug_info_report_finalize_errors(&load);
out:
	drgn_module_vector_deinit(&load.new_modules);
	return err;

err:
	drgn_debug_info_free_modules(dbinfo, false, false);
	string_builder_deinit(&load.errors);
	goto out;
}

struct elf_symbols_search_arg {
	const char *name;
	uint64_t address;
	enum drgn_find_symbol_flags flags;
	struct drgn_error *err;
	struct drgn_symbol_result_builder *builder;
};

static bool elf_symbol_match(struct elf_symbols_search_arg *arg, GElf_Addr addr,
			 const GElf_Sym *sym, const char *name)
{
	if ((arg->flags & DRGN_FIND_SYMBOL_NAME) && strcmp(name, arg->name) != 0)
		return false;
	if ((arg->flags & DRGN_FIND_SYMBOL_ADDR) &&
	    (arg->address < addr || arg->address >= addr + sym->st_size))
		return false;
	return true;
}

static bool elf_symbol_store_match(struct elf_symbols_search_arg *arg,
				   GElf_Sym *elf_sym, GElf_Addr addr,
				   const char *name)
{
	struct drgn_symbol *sym;
	if (arg->flags == (DRGN_FIND_SYMBOL_ONE | DRGN_FIND_SYMBOL_NAME)) {
		int binding = GELF_ST_BIND(elf_sym->st_info);
		/*
		 * The order of precedence is
		 * GLOBAL = UNIQUE > WEAK > LOCAL = everything else
		 *
		 * If we found a global or unique symbol, return it
		 * immediately. If we found a weak symbol, then save it,
		 * which may overwrite a previously found weak or local
		 * symbol. Otherwise, save the symbol only if we haven't
		 * found another symbol.
		 */
		if (binding != STB_GLOBAL
		    && binding != STB_GNU_UNIQUE
		    && binding != STB_WEAK
		    && drgn_symbol_result_builder_count(arg->builder) > 0)
			return false;
		sym = malloc(sizeof(*sym));
		if (!sym) {
			arg->err = &drgn_enomem;
			return true;
		}
		drgn_symbol_from_elf(name, addr, elf_sym, sym);
		if (!drgn_symbol_result_builder_add(arg->builder, sym)) {
			arg->err = &drgn_enomem;
			drgn_symbol_destroy(sym);
		}

		/* Abort on error, or short-circuit if we found a global or
		 * unique symbol */
		return (arg->err || sym->binding == DRGN_SYMBOL_BINDING_GLOBAL
			|| sym->binding == DRGN_SYMBOL_BINDING_UNIQUE);
	} else {
		sym = malloc(sizeof(*sym));
		if (!sym) {
			arg->err = &drgn_enomem;
			return true;
		}
		drgn_symbol_from_elf(name, addr, elf_sym, sym);
		if (!drgn_symbol_result_builder_add(arg->builder, sym)) {
			arg->err = &drgn_enomem;
			drgn_symbol_destroy(sym);
		}
		/* Abort on error, or short-circuit for single lookup */
		return (arg->err || (arg->flags & DRGN_FIND_SYMBOL_ONE));
	}
}

static int elf_symbols_search_cb(Dwfl_Module *dwfl_module, void **userdatap,
			     const char *module_name, Dwarf_Addr base,
			     void *cb_arg)
{
	struct elf_symbols_search_arg *arg = cb_arg;

	int symtab_len = dwfl_module_getsymtab(dwfl_module);
	if (symtab_len == -1)
		return DWARF_CB_OK;

	/* Ignore the zeroth null symbol */
	for (int i = 1; i < symtab_len; i++) {
		GElf_Sym elf_sym;
		GElf_Addr elf_addr;
		const char *name = dwfl_module_getsym_info(dwfl_module, i,
							   &elf_sym, &elf_addr,
							   NULL, NULL, NULL);
		if (!name || !elf_symbol_match(arg, elf_addr, &elf_sym, name))
			continue;
		if (elf_symbol_store_match(arg, &elf_sym, elf_addr, name))
			return DWARF_CB_ABORT;
	}
	return DWARF_CB_OK;
}

static struct drgn_error *
elf_symbols_search(const char *name, uint64_t addr, enum drgn_find_symbol_flags flags,
		   void *data, struct drgn_symbol_result_builder *builder)
{
	Dwfl_Module *dwfl_module = NULL;
	struct drgn_program *prog = data;
	struct elf_symbols_search_arg arg = {
		.name = name,
		.address = addr,
		.flags = flags,
		.err = NULL,
		.builder = builder,
	};

	if (arg.flags & DRGN_FIND_SYMBOL_ADDR) {
		dwfl_module = dwfl_addrmodule(prog->dbinfo.dwfl, arg.address);
		if (!dwfl_module)
			return NULL;
	}

	if ((arg.flags & (DRGN_FIND_SYMBOL_ADDR | DRGN_FIND_SYMBOL_ONE))
	    == (DRGN_FIND_SYMBOL_ADDR | DRGN_FIND_SYMBOL_ONE)) {
		GElf_Off offset;
		GElf_Sym elf_sym;
		const char *name = dwfl_module_addrinfo(
			dwfl_module, addr, &offset,
			&elf_sym, NULL, NULL, NULL);
		if (!name)
			return NULL;
		struct drgn_symbol *sym = malloc(sizeof(*sym));
		if (!sym)
			return &drgn_enomem;
		drgn_symbol_from_elf(name, addr - offset, &elf_sym, sym);
		if (!drgn_symbol_result_builder_add(builder, sym)) {
			arg.err = &drgn_enomem;
			drgn_symbol_destroy(sym);
		}
	} else if (dwfl_module) {
		elf_symbols_search_cb(dwfl_module, NULL, NULL, 0, &arg);
	} else {
		dwfl_getmodules(prog->dbinfo.dwfl, elf_symbols_search_cb, &arg, 0);
	}
	return arg.err;
}

bool drgn_debug_info_is_indexed(struct drgn_debug_info *dbinfo,
				const char *name)
{
	return c_string_set_search(&dbinfo->module_names, &name).entry != NULL;
}

void drgn_debug_info_init(struct drgn_debug_info *dbinfo,
			  struct drgn_program *prog)
{
	dbinfo->prog = prog;
	dbinfo->dwfl = dwfl_begin(&drgn_dwfl_callbacks);
	// This is temporary until we stop using libdwfl, and is extremely
	// unlikely to fail anwyays, so don't bother propagating an error up.
	if (!dbinfo->dwfl)
		abort();
	drgn_program_add_type_finder_impl(prog, &dbinfo->type_finder,
					  drgn_debug_info_find_type, dbinfo);
	drgn_program_add_object_finder_impl(prog, &dbinfo->object_finder,
					    drgn_debug_info_find_object,
					    dbinfo);
	const struct drgn_symbol_finder_ops symbol_finder_ops = {
		.find = elf_symbols_search,
	};
	drgn_program_register_symbol_finder_impl(prog, &dbinfo->symbol_finder,
						 "elf", &symbol_finder_ops,
						 prog, 0);
	drgn_module_table_init(&dbinfo->modules);
	c_string_set_init(&dbinfo->module_names);
	drgn_dwarf_info_init(dbinfo);
}

void drgn_debug_info_deinit(struct drgn_debug_info *dbinfo)
{
	drgn_dwarf_info_deinit(dbinfo);
	c_string_set_deinit(&dbinfo->module_names);
	drgn_debug_info_free_modules(dbinfo, false, true);
	assert(drgn_module_table_empty(&dbinfo->modules));
	drgn_module_table_deinit(&dbinfo->modules);
	dwfl_end(dbinfo->dwfl);
}

struct drgn_elf_file *drgn_module_find_dwarf_file(struct drgn_module *module,
						  Dwarf *dwarf)
{
	if (!module->debug_file)
		return NULL;
	if (dwarf == module->debug_file->dwarf)
		return module->debug_file;
	struct drgn_elf_file_dwarf_table_iterator it =
		drgn_elf_file_dwarf_table_search(&module->split_dwarf_files,
						 &dwarf);
	return it.entry ? *it.entry : NULL;
}

struct drgn_error *
drgn_module_create_split_dwarf_file(struct drgn_module *module,
				    const char *name, Dwarf *dwarf,
				    struct drgn_elf_file **ret)
{
	struct drgn_error *err;
	err = drgn_elf_file_create(module, name, dwarf_getelf(dwarf), ret);
	if (err)
		return err;
	err = drgn_elf_file_precache_sections(*ret);
	if (err) {
		drgn_elf_file_destroy(*ret);
		return err;
	}
	(*ret)->dwarf = dwarf;
	int r = drgn_elf_file_dwarf_table_insert(&module->split_dwarf_files,
						 ret, NULL);
	if (r < 0) {
		drgn_elf_file_destroy(*ret);
		return &drgn_enomem;
	}
	assert(r > 0);
	return NULL;
}

struct drgn_error *
drgn_module_find_cfi(struct drgn_program *prog, struct drgn_module *module,
		     uint64_t pc, struct drgn_elf_file **file_ret,
		     struct drgn_cfi_row **row_ret, bool *interrupted_ret,
		     drgn_register_number *ret_addr_regno_ret)
{
	struct drgn_error *err;

	// If the file's platform doesn't match the program's, we can't use its
	// CFI.
	const bool can_use_loaded_file =
		(module->loaded_file &&
		 drgn_platforms_equal(&module->loaded_file->platform,
				      &prog->platform));
	const bool can_use_debug_file =
		(module->debug_file &&
		 drgn_platforms_equal(&module->debug_file->platform,
				      &prog->platform));

	if (prog->prefer_orc_unwinder) {
		if (can_use_debug_file) {
			*file_ret = module->debug_file;
			err = drgn_module_find_orc_cfi(module, pc, row_ret,
						       interrupted_ret,
						       ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
			err = drgn_module_find_dwarf_cfi(module, pc, row_ret,
							 interrupted_ret,
							 ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
		}
		if (can_use_loaded_file) {
			*file_ret = module->loaded_file;
			return drgn_module_find_eh_cfi(module, pc, row_ret,
						       interrupted_ret,
						       ret_addr_regno_ret);
		}
	} else {
		if (can_use_debug_file) {
			*file_ret = module->debug_file;
			err = drgn_module_find_dwarf_cfi(module, pc, row_ret,
							 interrupted_ret,
							 ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
		}
		if (can_use_loaded_file) {
			*file_ret = module->loaded_file;
			err = drgn_module_find_eh_cfi(module, pc, row_ret,
						      interrupted_ret,
						      ret_addr_regno_ret);
			if (err != &drgn_not_found)
				return err;
		}
		if (can_use_debug_file) {
			*file_ret = module->debug_file;
			return drgn_module_find_orc_cfi(module, pc, row_ret,
							interrupted_ret,
							ret_addr_regno_ret);
		}
	}
	return &drgn_not_found;
}

#if !_ELFUTILS_PREREQ(0, 175)
static Elf *dwelf_elf_begin(int fd)
{
	return elf_begin(fd, ELF_C_READ_MMAP_PRIVATE, NULL);
}
#endif

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

/*
 * Get the start address from the first loadable segment and the end address
 * from the last loadable segment.
 *
 * The ELF specification states that loadable segments are sorted on p_vaddr.
 * However, vmlinux on x86-64 has an out of order segment for .data..percpu, and
 * Arm has a couple for .vector and .stubs. Thankfully, those are placed in the
 * middle by the vmlinux linker script, so we can still rely on the first and
 * last loadable segments.
 */
struct drgn_error *elf_address_range(Elf *elf, uint64_t bias,
				     uint64_t *start_ret, uint64_t *end_ret)
{
	size_t phnum;
	if (elf_getphdrnum(elf, &phnum) != 0)
		return drgn_error_libelf();

	GElf_Phdr phdr_mem, *phdr;
	size_t i;
	for (i = 0; i < phnum; i++) {
		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return drgn_error_libelf();
		if (phdr->p_type == PT_LOAD) {
			uint64_t align = phdr->p_align ? phdr->p_align : 1;
			*start_ret = (phdr->p_vaddr & -align) + bias;
			break;
		}
	}
	if (i >= phnum) {
		/* There were no loadable segments. */
		*start_ret = *end_ret = 0;
		return NULL;
	}

	for (i = phnum; i-- > 0;) {
		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return drgn_error_libelf();
		if (phdr->p_type == PT_LOAD) {
			*end_ret = (phdr->p_vaddr + phdr->p_memsz) + bias;
			if (*start_ret >= *end_ret)
				*start_ret = *end_ret = 0;
			return NULL;
		}
	}
	/* We found a loadable segment earlier, so this shouldn't happen. */
	assert(!"PT_LOAD segment disappeared");
	*end_ret = 0;
	return NULL;
}
