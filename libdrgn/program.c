// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <byteswap.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "internal.h"
#include "dwarf_index.h"
#include "dwarf_info_cache.h"
#include "language.h"
#include "linux_kernel.h"
#include "memory_reader.h"
#include "object_index.h"
#include "program.h"
#include "read.h"
#include "string_builder.h"
#include "symbol.h"
#include "type_index.h"
#include "vector.h"

/* This definition was added to elf.h in glibc 2.18. */
#ifndef NT_FILE
#define NT_FILE 0x46494c45
#endif

static Elf_Type note_header_type(GElf_Phdr *phdr)
{
#if _ELFUTILS_PREREQ(0, 175)
	if (phdr->p_align == 8)
		return ELF_T_NHDR8;
#endif
	return ELF_T_NHDR;
}

LIBDRGN_PUBLIC enum drgn_program_flags
drgn_program_flags(struct drgn_program *prog)
{
	return prog->flags;
}

LIBDRGN_PUBLIC const struct drgn_platform *
drgn_program_platform(struct drgn_program *prog)
{
	return prog->has_platform ? &prog->platform : NULL;
}

static void drgn_program_set_platform(struct drgn_program *prog,
				      const struct drgn_platform *platform)
{
	if (!prog->has_platform) {
		prog->platform = *platform;
		prog->has_platform = true;
		prog->tindex.word_size =
			platform->flags & DRGN_PLATFORM_IS_64_BIT ? 8 : 4;
	}
}

void drgn_program_init(struct drgn_program *prog,
		       const struct drgn_platform *platform)
{
	memset(prog, 0, sizeof(*prog));
	drgn_memory_reader_init(&prog->reader);
	drgn_type_index_init(&prog->tindex);
	drgn_object_index_init(&prog->oindex);
	prog->core_fd = -1;
	if (platform)
		drgn_program_set_platform(prog, platform);
}

void drgn_program_deinit(struct drgn_program *prog)
{
	drgn_object_index_deinit(&prog->oindex);
	drgn_type_index_deinit(&prog->tindex);
	drgn_memory_reader_deinit(&prog->reader);

	free(prog->file_segments);

	if (prog->core_fd != -1)
		close(prog->core_fd);

	drgn_dwarf_info_cache_destroy(prog->_dicache);
	if (prog->_dwfl) {
		drgn_remove_all_dwfl_modules(prog->_dwfl);
		dwfl_end(prog->_dwfl);
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_create(const struct drgn_platform *platform,
		    struct drgn_program **ret)
{
	struct drgn_program *prog;

	prog = malloc(sizeof(*prog));
	if (!prog)
		return &drgn_enomem;
	drgn_program_init(prog, platform);
	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC void drgn_program_destroy(struct drgn_program *prog)
{
	if (prog) {
		drgn_program_deinit(prog);
		free(prog);
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_add_memory_segment(struct drgn_program *prog, uint64_t address,
				uint64_t size, drgn_memory_read_fn read_fn,
				void *arg, bool physical)
{
	return drgn_memory_reader_add_segment(&prog->reader, address, size,
					      read_fn, arg, physical);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_add_type_finder(struct drgn_program *prog, drgn_type_find_fn fn,
			     void *arg)
{
	return drgn_type_index_add_finder(&prog->tindex, fn, arg);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_add_object_finder(struct drgn_program *prog,
			       drgn_object_find_fn fn, void *arg)
{
	return drgn_object_index_add_finder(&prog->oindex, fn, arg);
}

static struct drgn_error *
drgn_program_check_initialized(struct drgn_program *prog)
{
	if (prog->core_fd != -1 || !drgn_memory_reader_empty(&prog->reader)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program memory was already initialized");
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_core_dump(struct drgn_program *prog, const char *path)
{
	struct drgn_error *err;
	Elf *elf;
	GElf_Ehdr ehdr_mem, *ehdr;
	struct drgn_platform platform;
	bool is_64_bit;
	size_t phnum, i;
	bool have_non_zero_phys_addr = false;
	struct drgn_memory_file_segment *current_file_segment;
	bool have_nt_taskstruct = false, have_vmcoreinfo = false, is_proc_kcore;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	prog->core_fd = open(path, O_RDONLY);
	if (prog->core_fd == -1)
		return drgn_error_create_os("open", errno, path);

	elf_version(EV_CURRENT);

	elf = elf_begin(prog->core_fd, ELF_C_READ, NULL);
	if (!elf) {
		err = drgn_error_libelf();
		goto out_fd;
	}

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr || ehdr->e_type != ET_CORE) {
		err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					"not an ELF core file");
		goto out_elf;
	}

	drgn_platform_from_elf(ehdr, &platform);
	is_64_bit = ehdr->e_ident[EI_CLASS] == ELFCLASS64;

	if (elf_getphdrnum(elf, &phnum) != 0) {
		err = drgn_error_libelf();
		goto out_elf;
	}

	/*
	 * First pass: count the number of loadable segments and check if p_addr
	 * is valid.
	 */
	prog->num_file_segments = 0;
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;

		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr) {
			err = drgn_error_libelf();
			goto out_segments;
		}

		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_paddr)
				have_non_zero_phys_addr = true;
			prog->num_file_segments++;
		}
	}

	prog->file_segments = malloc_array(prog->num_file_segments,
					   sizeof(*prog->file_segments));
	if (!prog->file_segments) {
		err = &drgn_enomem;
		goto out_segments;
	}
	current_file_segment = prog->file_segments;

	/* Second pass: add the segments and parse notes. */
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;

		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr) {
			err = drgn_error_libelf();
			goto out_segments;
		}

		if (phdr->p_type == PT_LOAD) {
			/*
			 * If this happens, then the number of segments changed
			 * since the first pass. That's probably impossible, but
			 * skip it just in case.
			 */
			if (current_file_segment ==
			    prog->file_segments + prog->num_file_segments)
				continue;
			current_file_segment->file_offset = phdr->p_offset;
			current_file_segment->file_size = phdr->p_filesz;
			current_file_segment->fd = prog->core_fd;
			err = drgn_program_add_memory_segment(prog,
							      phdr->p_vaddr,
							      phdr->p_memsz,
							      drgn_read_memory_file,
							      current_file_segment,
							      false);
			if (err)
				goto out_segments;
			if (have_non_zero_phys_addr &&
			    phdr->p_paddr !=
			    (is_64_bit ? UINT64_MAX : UINT32_MAX)) {
				err = drgn_program_add_memory_segment(prog,
								      phdr->p_paddr,
								      phdr->p_memsz,
								      drgn_read_memory_file,
								      current_file_segment,
								      true);
				if (err)
					goto out_segments;
			}
			current_file_segment++;
		} else if (phdr->p_type == PT_NOTE) {
			Elf_Data *data;
			size_t offset;
			GElf_Nhdr nhdr;
			size_t name_offset, desc_offset;

			data = elf_getdata_rawchunk(elf, phdr->p_offset,
						    phdr->p_filesz,
						    note_header_type(phdr));
			if (!data) {
				err = drgn_error_libelf();
				goto out_segments;
			}

			offset = 0;
			while (offset < data->d_size &&
			       (offset = gelf_getnote(data, offset, &nhdr,
						      &name_offset,
						      &desc_offset))) {
				const char *name, *desc;

				name = (char *)data->d_buf + name_offset;
				desc = (char *)data->d_buf + desc_offset;
				if (strncmp(name, "CORE", nhdr.n_namesz) == 0) {
					if (nhdr.n_type == NT_TASKSTRUCT)
						have_nt_taskstruct = true;
				} else if (strncmp(name, "VMCOREINFO",
						   nhdr.n_namesz) == 0) {
					err = parse_vmcoreinfo(desc,
							       nhdr.n_descsz,
							       &prog->vmcoreinfo);
					if (err)
						goto out_segments;
					have_vmcoreinfo = true;
				}
			}
		}
	}
	elf_end(elf);
	elf = NULL;

	if (have_nt_taskstruct) {
		/*
		 * If the core file has an NT_TASKSTRUCT note and is in /proc,
		 * then it's probably /proc/kcore.
		 */
		struct statfs fs;

		if (fstatfs(prog->core_fd, &fs) == -1) {
			err = drgn_error_create_os("fstatfs", errno, path);
			if (err)
				goto out_segments;
		}
		is_proc_kcore = fs.f_type == 0x9fa0; /* PROC_SUPER_MAGIC */
	} else {
		is_proc_kcore = false;
	}

	if (!have_vmcoreinfo && is_proc_kcore) {
		err = read_vmcoreinfo_fallback(&prog->reader,
					       have_non_zero_phys_addr,
					       &prog->vmcoreinfo);
		if (err)
			goto out_segments;
		have_vmcoreinfo = true;
	}

	if (have_vmcoreinfo)
		prog->flags |= DRGN_PROGRAM_IS_LINUX_KERNEL;
	if (is_proc_kcore)
		prog->flags |= DRGN_PROGRAM_IS_LIVE;
	drgn_program_set_platform(prog, &platform);
	return NULL;

out_segments:
	drgn_memory_reader_deinit(&prog->reader);
	drgn_memory_reader_init(&prog->reader);
	free(prog->file_segments);
	prog->file_segments = NULL;
	prog->num_file_segments = 0;
out_elf:
	elf_end(elf);
out_fd:
	close(prog->core_fd);
	prog->core_fd = -1;
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_kernel(struct drgn_program *prog)
{
	return drgn_program_set_core_dump(prog, "/proc/kcore");
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_pid(struct drgn_program *prog, pid_t pid)
{
	struct drgn_error *err;
	char buf[64];

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	sprintf(buf, "/proc/%ld/mem", (long)pid);
	prog->core_fd = open(buf, O_RDONLY);
	if (prog->core_fd == -1)
		return drgn_error_create_os("open", errno, buf);

	prog->file_segments = malloc(sizeof(*prog->file_segments));
	if (!prog->file_segments) {
		err = &drgn_enomem;
		goto out_fd;
	}
	prog->file_segments[0].file_offset = 0;
	prog->file_segments[0].file_size = UINT64_MAX;
	prog->file_segments[0].fd = prog->core_fd;
	prog->num_file_segments = 1;
	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_read_memory_file,
					      prog->file_segments, false);
	if (err)
		goto out_segments;

	prog->pid = pid;
	prog->flags |= DRGN_PROGRAM_IS_LIVE;
	drgn_program_set_platform(prog, &drgn_host_platform);
	return NULL;

out_segments:
	drgn_memory_reader_deinit(&prog->reader);
	drgn_memory_reader_init(&prog->reader);
	free(prog->file_segments);
	prog->file_segments = NULL;
	prog->num_file_segments = 0;
out_fd:
	close(prog->core_fd);
	prog->core_fd = -1;
	return err;
}

static const Dwfl_Callbacks linux_proc_dwfl_callbacks = {
	.find_elf = dwfl_linux_proc_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
};

static const Dwfl_Callbacks userspace_core_dump_dwfl_callbacks = {
	.find_elf = dwfl_build_id_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
};

struct drgn_error *drgn_program_get_dwfl(struct drgn_program *prog, Dwfl **ret)
{
	const Dwfl_Callbacks *dwfl_callbacks;

	if (!prog->_dwfl) {
		if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
			dwfl_callbacks = &drgn_dwfl_callbacks;
		else if (prog->flags & DRGN_PROGRAM_IS_LIVE)
			dwfl_callbacks = &linux_proc_dwfl_callbacks;
		else
			dwfl_callbacks = &userspace_core_dump_dwfl_callbacks;
		prog->_dwfl = dwfl_begin(dwfl_callbacks);
		if (!prog->_dwfl)
			return drgn_error_libdwfl();
	}
	*ret = prog->_dwfl;
	return NULL;
}

static int drgn_set_platform_from_dwarf(Dwfl_Module *module, void **userdatap,
					const char *name, Dwarf_Addr base,
					Dwarf *dwarf, Dwarf_Addr bias,
					void *arg)
{
	Elf *elf;
	GElf_Ehdr ehdr_mem, *ehdr;
	struct drgn_platform platform;

	elf = dwarf_getelf(dwarf);
	if (!elf)
		return DWARF_CB_OK;
	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr)
		return DWARF_CB_OK;
	drgn_platform_from_elf(ehdr, &platform);
	drgn_program_set_platform(arg, &platform);
	return DWARF_CB_ABORT;
}

struct drgn_error *drgn_program_update_dwarf_index(struct drgn_program *prog)
{
	struct drgn_error *err;

	/* If we don't have a Dwfl handle yet, there's nothing to index. */
	if (!prog->_dwfl)
		return NULL;
	if (!prog->_dicache) {
		struct drgn_dwarf_info_cache *dicache;

		err = drgn_dwarf_info_cache_create(&prog->tindex, &dicache);
		if (err)
			return err;
		err = drgn_program_add_type_finder(prog, drgn_dwarf_type_find,
						   dicache);
		if (err) {
			drgn_dwarf_info_cache_destroy(dicache);
			return err;
		}
		err = drgn_program_add_object_finder(prog,
						     drgn_dwarf_object_find,
						     dicache);
		if (err) {
			drgn_type_index_remove_finder(&prog->tindex);
			drgn_dwarf_info_cache_destroy(dicache);
			return err;
		}
		prog->_dicache = dicache;
	}
	err = drgn_dwarf_index_update(&prog->_dicache->dindex, prog->_dwfl);
	if (err)
		return err;
	if (!prog->has_platform) {
		dwfl_getdwarf(prog->_dwfl, drgn_set_platform_from_dwarf, prog,
			      0);
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_debug_info(struct drgn_program *prog, const char **paths,
			     size_t n)
{
	struct drgn_error *err;
	Dwfl *dwfl;
	size_t i;

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return linux_kernel_load_debug_info(prog, paths, n);

	err = drgn_program_get_dwfl(prog, &dwfl);
	if (err)
		return err;
	for (i = 0; i < n; i++) {
		if (!dwfl_report_elf(dwfl, paths[i], paths[i], -1, 0, true)) {
			err = drgn_error_libdwfl();
			goto out;
		}
	}
	err = drgn_program_update_dwarf_index(prog);
out:
	if (err)
		drgn_remove_unindexed_dwfl_modules(dwfl);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_default_debug_info(struct drgn_program *prog)
{
	struct drgn_error *err;
	Dwfl *dwfl;

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return linux_kernel_load_default_debug_info(prog);

	err = drgn_program_get_dwfl(prog, &dwfl);
	if (err)
		return err;
	dwfl_report_begin_add(dwfl);
	if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
		int ret;

		ret = dwfl_linux_proc_report(dwfl, prog->pid);
		if (ret == -1) {
			err = drgn_error_libdwfl();
		} else if (ret) {
			err = drgn_error_create_os("dwfl_linux_proc_report",
						   ret, NULL);
		} else {
			err = NULL;
		}
	} else {
		Elf *elf;

		elf = elf_begin(prog->core_fd, ELF_C_READ, NULL);
		if (elf) {
			if (dwfl_core_file_report(dwfl, elf, NULL) == -1)
				err = drgn_error_libdwfl();
			else
				err = NULL;
			elf_end(elf);
		} else {
			err = drgn_error_libelf();
		}
	}
	dwfl_report_end(dwfl, NULL, NULL);
	if (err)
		goto out;

	err = drgn_program_update_dwarf_index(prog);
out:
	if (err)
		drgn_remove_unindexed_dwfl_modules(dwfl);
	return err;
}

struct drgn_error *drgn_program_init_core_dump(struct drgn_program *prog,
					       const char *path)
{
	struct drgn_error *err;

	err = drgn_program_set_core_dump(prog, path);
	if (err)
		return err;
	err = drgn_program_load_default_debug_info(prog);
	if (err && err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
		drgn_error_destroy(err);
		err = NULL;
	}
	return err;
}

struct drgn_error *drgn_program_init_kernel(struct drgn_program *prog)
{
	struct drgn_error *err;

	err = drgn_program_set_kernel(prog);
	if (err)
		return err;
	err = drgn_program_load_default_debug_info(prog);
	if (err && err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
		drgn_error_destroy(err);
		err = NULL;
	}
	return err;
}

struct drgn_error *drgn_program_init_pid(struct drgn_program *prog, pid_t pid)
{
	struct drgn_error *err;

	err = drgn_program_set_pid(prog, pid);
	if (err)
		return err;
	err = drgn_program_load_default_debug_info(prog);
	if (err && err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
		drgn_error_destroy(err);
		err = NULL;
	}
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_from_core_dump(const char *path, struct drgn_program **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog;

	prog = malloc(sizeof(*prog));
	if (!prog)
		return &drgn_enomem;

	drgn_program_init(prog, NULL);
	err = drgn_program_init_core_dump(prog, path);
	if (err) {
		drgn_program_deinit(prog);
		free(prog);
		return err;
	}

	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_from_kernel(struct drgn_program **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog;

	prog = malloc(sizeof(*prog));
	if (!prog)
		return &drgn_enomem;

	drgn_program_init(prog, NULL);
	err = drgn_program_init_kernel(prog);
	if (err) {
		drgn_program_deinit(prog);
		free(prog);
		return err;
	}

	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_from_pid(pid_t pid, struct drgn_program **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog;

	prog = malloc(sizeof(*prog));
	if (!prog)
		return &drgn_enomem;

	drgn_program_init(prog, NULL);
	err = drgn_program_init_pid(prog, pid);
	if (err) {
		drgn_program_deinit(prog);
		free(prog);
		return err;
	}

	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_memory(struct drgn_program *prog, void *buf, uint64_t address,
			 size_t count, bool physical)
{
	return drgn_memory_reader_read(&prog->reader, buf, address, count,
				       physical);
}

DEFINE_VECTOR(char_vector, char)

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_c_string(struct drgn_program *prog, uint64_t address,
			   bool physical, size_t max_size, char **ret)
{
	struct drgn_error *err;
	struct char_vector str;

	char_vector_init(&str);
	for (;;) {
		char *c;

		c = char_vector_append_entry(&str);
		if (!c) {
			char_vector_deinit(&str);
			return &drgn_enomem;
		}
		if (str.size <= max_size) {
			err = drgn_memory_reader_read(&prog->reader, c, address,
						      1, physical);
			if (err) {
				char_vector_deinit(&str);
				return err;
			}
			if (!*c)
				break;
		} else {
			*c = '\0';
			break;
		}
		address++;
	}
	char_vector_shrink_to_fit(&str);
	*ret = str.data;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_type(struct drgn_program *prog, const char *name,
		       const char *filename, struct drgn_qualified_type *ret)
{
	return drgn_type_index_find(&prog->tindex, name, filename,
				    &drgn_language_c, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_object(struct drgn_program *prog, const char *name,
			 const char *filename,
			 enum drgn_find_object_flags flags,
			 struct drgn_object *ret)
{
	if (ret && ret->prog != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "object is from wrong program");
	}
	return drgn_object_index_find(&prog->oindex, name, filename, flags,
				      ret);
}

struct drgn_error *drgn_program_find_symbol_internal(struct drgn_program *prog,
						     uint64_t address,
						     struct drgn_symbol *sym)
{
	Dwfl_Module *module;
	const char *name;
	GElf_Off offset;
	GElf_Sym elf_sym;

	if (!prog->_dwfl)
		return &drgn_not_found;

	module = dwfl_addrmodule(prog->_dwfl, address);
	if (!module)
		return &drgn_not_found;
	name = dwfl_module_addrinfo(module, address, &offset, &elf_sym, NULL,
				    NULL, NULL);
	if (!name)
		return &drgn_not_found;

	sym->name = name;
	sym->address = address - offset;
	sym->size = elf_sym.st_size;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbol(struct drgn_program *prog, uint64_t address,
			 struct drgn_symbol **ret)
{
	struct drgn_error *err;
	struct drgn_symbol *sym;

	sym = malloc(sizeof(*sym));
	if (!sym)
		return &drgn_enomem;
	err = drgn_program_find_symbol_internal(prog, address, sym);
	if (err) {
		free(sym);
		if (err == &drgn_not_found) {
			err = drgn_error_format(DRGN_ERROR_LOOKUP,
						"could not find symbol containing 0x%" PRIx64,
						address);
		}
		return err;
	}
	*ret = sym;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_element_info(struct drgn_program *prog, struct drgn_type *type,
			  struct drgn_element_info *ret)
{
	struct drgn_type *underlying_type;
	bool is_pointer, is_array;

	underlying_type = drgn_underlying_type(type);
	is_pointer = drgn_type_kind(underlying_type) == DRGN_TYPE_POINTER;
	is_array = drgn_type_kind(underlying_type) == DRGN_TYPE_ARRAY;
	if (!is_pointer && !is_array)
		return drgn_type_error("'%s' is not an array or pointer", type);

	ret->qualified_type = drgn_type_type(underlying_type);
	return drgn_type_bit_size(ret->qualified_type.type, &ret->bit_size);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_member_info(struct drgn_program *prog, struct drgn_type *type,
			 const char *member_name, struct drgn_member_info *ret)
{
	struct drgn_error *err;
	struct drgn_member_value *member;

	err = drgn_type_index_find_member(&prog->tindex, type, member_name,
					  strlen(member_name), &member);
	if (err)
		return err;

	err = drgn_lazy_type_evaluate(member->type, &ret->qualified_type);
	if (err)
		return err;
	ret->bit_offset = member->bit_offset;
	ret->bit_field_size = member->bit_field_size;
	return NULL;
}
