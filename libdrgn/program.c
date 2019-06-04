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
#include "program.h"
#include "read.h"
#include "string_builder.h"
#include "symbol_index.h"
#include "type_index.h"

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

LIBDRGN_PUBLIC enum drgn_architecture_flags
drgn_program_architecture(struct drgn_program *prog)
{
	return prog->arch;
}

static void drgn_program_update_arch(struct drgn_program *prog,
				     enum drgn_architecture_flags arch)
{
	if (prog->arch == DRGN_ARCH_AUTO) {
		prog->arch = arch;
		prog->tindex.word_size =
			prog->arch & DRGN_ARCH_IS_64_BIT ? 8 : 4;
	}
}

void drgn_program_init(struct drgn_program *prog,
		       enum drgn_architecture_flags arch)
{
	drgn_memory_reader_init(&prog->reader);
	drgn_type_index_init(&prog->tindex);
	drgn_symbol_index_init(&prog->sindex);
	prog->file_segments = NULL;
	prog->num_file_segments = 0;
	prog->mappings = NULL;
	prog->num_mappings = 0;
	memset(&prog->vmcoreinfo, 0, sizeof(prog->vmcoreinfo));
	prog->dicache = NULL;
	prog->core_fd = -1;
	prog->flags = 0;
	prog->arch = DRGN_ARCH_AUTO;
	if (arch != DRGN_ARCH_AUTO)
		drgn_program_update_arch(prog, arch);
	prog->added_vmcoreinfo_symbol_finder = false;
}

void drgn_program_deinit(struct drgn_program *prog)
{
	size_t i;

	drgn_symbol_index_deinit(&prog->sindex);
	drgn_type_index_deinit(&prog->tindex);
	drgn_memory_reader_deinit(&prog->reader);

	free(prog->file_segments);

	for (i = 0; i < prog->num_mappings; i++)
		free(prog->mappings[i].path);
	free(prog->mappings);

	if (prog->core_fd != -1)
		close(prog->core_fd);

	drgn_dwarf_info_cache_destroy(prog->dicache);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_create(enum drgn_architecture_flags arch,
		    struct drgn_program **ret)
{
	struct drgn_program *prog;

	if (arch & ~DRGN_ALL_ARCH_FLAGS) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid architecture flags");
	}
	prog = malloc(sizeof(*prog));
	if (!prog)
		return &drgn_enomem;
	drgn_program_init(prog, arch);
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
drgn_program_add_symbol_finder(struct drgn_program *prog,
			       drgn_symbol_find_fn fn, void *arg)
{
	return drgn_symbol_index_add_finder(&prog->sindex, fn, arg);
}

/*
 * Returns NULL if a mapping was appended, &drgn_stop if the mapping was merged,
 * non-NULL on error.
 */
static struct drgn_error *append_file_mapping(uint64_t start, uint64_t end,
					      uint64_t file_offset, char *path,
					      struct file_mapping **mappings,
					      size_t *num_mappings,
					      size_t *capacity)
{
	struct file_mapping *mapping;

	if (start > end) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "file memory mapping has negative length");
	} else if (start == end) {
		return NULL;
	}

	/*
	 * There may be separate mappings for adjacent areas of a file (e.g., if
	 * the mappings have different permissions). Make sure to merge those.
	 */
	if (*num_mappings) {
		uint64_t length;

		mapping = &(*mappings)[*num_mappings - 1];
		length = mapping->end - mapping->start;
		if (mapping->end == start &&
		    mapping->file_offset + length == file_offset &&
		    strcmp(mapping->path, path) == 0) {
			mapping->end = end;
			return &drgn_stop;
		}
	}

	if (*num_mappings >= *capacity) {
		size_t new_capacity;

		if (*capacity == 0)
			new_capacity = 1;
		else
			new_capacity = *capacity * 2;
		if (!resize_array(mappings, new_capacity))
			return &drgn_enomem;
		*capacity = new_capacity;
	}

	mapping = &(*mappings)[(*num_mappings)++];
	mapping->start = start;
	mapping->end = end;
	mapping->file_offset = file_offset;
	mapping->path = path;
	mapping->elf = NULL;
	return NULL;
}

static struct drgn_error *parse_nt_file(const char *desc, size_t descsz,
					bool is_64_bit,
					struct file_mapping **mappings,
					size_t *num_mappings,
					size_t *mappings_capacity)
{
	struct drgn_error *err;
	uint64_t count, page_size, i;
	const char *p = desc, *q, *end = &desc[descsz];
	size_t paths_offset;
	bool bswap = false;

	if (is_64_bit) {
		if (!read_u64(&p, end, bswap, &count) ||
		    !read_u64(&p, end, bswap, &page_size) ||
		    __builtin_mul_overflow(count, 24U, &paths_offset))
			goto invalid;
	} else {
		if (!read_u32_into_u64(&p, end, bswap, &count) ||
		    !read_u32_into_u64(&p, end, bswap, &page_size) ||
		    __builtin_mul_overflow(count, 12U, &paths_offset))
			goto invalid;
	}

	if (!read_in_bounds(p, end, paths_offset))
		goto invalid;
	q = p + paths_offset;
	for (i = 0; i < count; i++) {
		uint64_t mapping_start, mapping_end, file_offset;
		const char *path;
		size_t len;

		/* We already did the bounds check above. */
		if (is_64_bit) {
			read_u64_nocheck(&p, bswap, &mapping_start);
			read_u64_nocheck(&p, bswap, &mapping_end);
			read_u64_nocheck(&p, bswap, &file_offset);
		} else {
			read_u32_into_u64_nocheck(&p, bswap, &mapping_start);
			read_u32_into_u64_nocheck(&p, bswap, &mapping_end);
			read_u32_into_u64_nocheck(&p, bswap, &file_offset);
		}
		file_offset *= page_size;

		if (!read_string(&q, end, &path, &len))
			goto invalid;
		err = append_file_mapping(mapping_start, mapping_end, file_offset,
					  (char *)path, mappings, num_mappings,
					  mappings_capacity);
		if (!err) {
			struct file_mapping *mapping;

			/*
			 * The mapping wasn't merged, so actually allocate the
			 * path now.
			 */
			mapping = &(*mappings)[*num_mappings - 1];
			mapping->path = malloc(len + 1);
			if (!mapping->path)
				return &drgn_enomem;
			memcpy(mapping->path, path, len + 1);
		} else if (err->code != DRGN_ERROR_STOP) {
			return err;
		}
	}

	return NULL;

invalid:
	return drgn_error_create(DRGN_ERROR_ELF_FORMAT, "invalid NT_FILE note");
}

static enum drgn_architecture_flags drgn_architecture_from_elf(Elf *elf)
{
	char *e_ident = elf_getident(elf, NULL);
	enum drgn_architecture_flags arch = 0;

	if (e_ident[EI_CLASS] == ELFCLASS64)
		arch |= DRGN_ARCH_IS_64_BIT;
	if (e_ident[EI_DATA] == ELFDATA2LSB)
		arch |= DRGN_ARCH_IS_LITTLE_ENDIAN;
	return arch;
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
	enum drgn_architecture_flags arch;
	bool is_64_bit;
	size_t phnum, i, mappings_capacity = 0;
	bool have_non_zero_phys_addr = false;
	struct drgn_memory_file_segment *current_file_segment;
	bool have_nt_taskstruct = false, have_vmcoreinfo = false, is_proc_kcore;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	prog->core_fd = open(path, O_RDONLY);
	if (prog->core_fd == -1)
		return drgn_error_create_os(errno, path, "open");

	elf_version(EV_CURRENT);

	elf = elf_begin(prog->core_fd, ELF_C_READ, NULL);
	if (!elf) {
		err = drgn_error_libelf();
		goto out_fd;
	}

	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr) {
		err = &drgn_not_elf;
		goto out_elf;
	}

	if (ehdr->e_type != ET_CORE) {
		err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					"not an ELF core file");
		goto out_elf;
	}

	arch = drgn_architecture_from_elf(elf);
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
			goto out_mappings;
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
				goto out_mappings;
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
					goto out_mappings;
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
				goto out_mappings;
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
					if (nhdr.n_type == NT_FILE) {
						err = parse_nt_file(desc,
								    nhdr.n_descsz,
								    is_64_bit,
								    &prog->mappings,
								    &prog->num_mappings,
								    &mappings_capacity);
						if (err)
							goto out_mappings;
					} else if (nhdr.n_type == NT_TASKSTRUCT) {
						have_nt_taskstruct = true;
					}
				} else if (strncmp(name, "VMCOREINFO",
						   nhdr.n_namesz) == 0) {
					err = parse_vmcoreinfo(desc,
							       nhdr.n_descsz,
							       &prog->vmcoreinfo);
					if (err)
						goto out_mappings;
					have_vmcoreinfo = true;
				}
			}
		}
	}
	elf_end(elf);
	elf = NULL;

	if (mappings_capacity > prog->num_mappings) {
		/* We don't care if this fails. */
		resize_array(&prog->mappings, prog->num_mappings);
	}

	if (have_nt_taskstruct) {
		/*
		 * If the core file has an NT_TASKSTRUCT note and is in /proc,
		 * then it's probably /proc/kcore.
		 */
		struct statfs fs;

		if (fstatfs(prog->core_fd, &fs) == -1) {
			err = drgn_error_create_os(errno, path, "fstatfs");
			if (err)
				goto out_mappings;
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
			goto out_mappings;
		have_vmcoreinfo = true;
	}

	if (have_vmcoreinfo)
		prog->flags |= DRGN_PROGRAM_IS_LINUX_KERNEL;
	if (is_proc_kcore)
		prog->flags |= DRGN_PROGRAM_IS_RUNNING_KERNEL;
	drgn_program_update_arch(prog, arch);
	return NULL;

out_mappings:
	free(prog->mappings);
	prog->mappings = NULL;
	prog->num_mappings = 0;
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

static struct drgn_error *parse_proc_maps(const char *maps_path,
					  struct file_mapping **mappings,
					  size_t *num_mappings)
{
	struct drgn_error *err;
	FILE *file;
	size_t capacity = 0;

	file = fopen(maps_path, "r");
	if (!file)
		return drgn_error_create_os(errno, maps_path, "fopen");

	for (;;) {
		unsigned long mapping_start, mapping_end;
		uint64_t file_offset;
		char *path;
		int ret;

		ret = fscanf(file, "%lx-%lx %*c%*c%*c%*c %" SCNx64 " "
			     "%*x:%*x %*d%*[ ]%m[^\n]", &mapping_start,
			     &mapping_end, &file_offset, &path);
		if (ret == EOF) {
			break;
		} else if (ret == 3) {
			/* This is an anonymous mapping; skip it. */
			continue;
		} else if (ret != 4) {
			err = drgn_error_format(DRGN_ERROR_OTHER,
						"could not parse %s", maps_path);
			goto out;
		}
		err = append_file_mapping(mapping_start, mapping_end,
					  file_offset, path, mappings,
					  num_mappings, &capacity);
		if (err && err->code == DRGN_ERROR_STOP) {
			/* The mapping was merged, so free the path. */
			free(path);
		} else if (err) {
			goto out;
		}
	}

	if (capacity > *num_mappings) {
		/* We don't care if this fails. */
		resize_array(mappings, *num_mappings);
	}

	err = NULL;
out:
	fclose(file);
	return err;
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
		return drgn_error_create_os(errno, buf, "open");

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

	sprintf(buf, "/proc/%ld/maps", (long)pid);
	err = parse_proc_maps(buf, &prog->mappings, &prog->num_mappings);
	if (err)
		goto out_mappings;

	drgn_program_update_arch(prog, DRGN_ARCH_HOST);
	return NULL;

out_mappings:
	free(prog->mappings);
	prog->mappings = NULL;
	prog->num_mappings = 0;
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


static struct drgn_error *
userspace_relocation_hook(struct drgn_program *prog, const char *name,
			  Dwarf_Die *die, struct drgn_symbol *sym)
{
	Elf *elf;
	size_t phnum, i;
	uint64_t file_offset;

	elf = dwarf_getelf(dwarf_cu_getdwarf(die->cu));
	if (elf_getphdrnum(elf, &phnum) != 0)
		return drgn_error_libelf();

	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;

		phdr = gelf_getphdr(elf, i, &phdr_mem);
		if (!phdr)
			return drgn_error_libelf();

		if (phdr->p_type == PT_LOAD &&
		    phdr->p_vaddr <= sym->address &&
		    sym->address < phdr->p_vaddr + phdr->p_memsz) {
			file_offset = (phdr->p_offset + sym->address -
				       phdr->p_vaddr);
			break;
		}
	}
	if (i >= phnum) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find segment containing %s",
					 name);
	}

	for (i = 0; i < prog->num_mappings; i++) {
		struct file_mapping *mapping = &prog->mappings[i];
		uint64_t mapping_size;

		mapping_size = mapping->end - mapping->start;
		if (mapping->elf == elf &&
		    mapping->file_offset <= file_offset &&
		    file_offset < mapping->file_offset + mapping_size) {
			sym->address = (mapping->start + file_offset -
					mapping->file_offset);
			return NULL;
		}
	}
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "could not find file mapping containing %s",
				 name);
}

static struct drgn_error *drgn_program_relocation_hook(const char *name,
						       Dwarf_Die *die,
						       struct drgn_symbol *sym,
						       void *arg)
{
	struct drgn_program *prog = arg;

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return kernel_relocation_hook(prog, name, die, sym);
	else if (prog->num_mappings)
		return userspace_relocation_hook(prog, name, die, sym);
	else
		return NULL;
}

struct drgn_error *drgn_program_open_debug_info(struct drgn_program *prog,
						const char *path, Elf **elf_ret)
{
	struct drgn_error *err;
	Elf *elf;

	if (!prog->dicache) {
		struct drgn_dwarf_info_cache *dicache;

		err = drgn_dwarf_info_cache_create(&prog->tindex,
						   &dicache);
		if (err)
			return err;
		err = drgn_program_add_type_finder(prog, drgn_dwarf_type_find,
						   dicache);
		if (err) {
			drgn_dwarf_info_cache_destroy(dicache);
			return err;
		}
		err = drgn_program_add_symbol_finder(prog,
						     drgn_dwarf_symbol_find,
						     dicache);
		if (err) {
			drgn_type_index_remove_finder(&prog->tindex);
			drgn_dwarf_info_cache_destroy(dicache);
			return err;
		}
		prog->dicache = dicache;
		dicache->relocation_hook = drgn_program_relocation_hook;
		dicache->relocation_arg = prog;
	}

	err = drgn_dwarf_index_open(&prog->dicache->dindex, path, &elf);
	if (err)
		return err;
	drgn_program_update_arch(prog, drgn_architecture_from_elf(elf));
	if (elf_ret)
		*elf_ret = elf;
	return NULL;
}

void drgn_program_close_unindexed_debug_info(struct drgn_program *prog)
{
	if (prog->dicache)
		drgn_dwarf_index_close_unindexed(&prog->dicache->dindex);
}

struct drgn_error *drgn_program_update_debug_info(struct drgn_program *prog)
{
	if (!prog->dicache)
		return NULL;
	return drgn_dwarf_index_update(&prog->dicache->dindex);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_debug_info(struct drgn_program *prog, const char **paths,
			     size_t n)
{
	struct drgn_error *err;
	size_t i;

	for (i = 0; i < n; i++) {
		err = drgn_program_open_debug_info(prog, paths[i], NULL);
		if (err) {
			drgn_program_close_unindexed_debug_info(prog);
			return err;
		}
	}
	return drgn_program_update_debug_info(prog);
}

static struct drgn_error *load_userspace_debug_info(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct file_mapping *mappings;
	size_t i, num_mappings;
	bool success = false;

	mappings = prog->mappings;
	num_mappings = prog->num_mappings;
	for (i = 0; i < num_mappings; i++) {
		if (prog->mappings[i].elf)
			continue;
		err = drgn_program_open_debug_info(prog, mappings[i].path,
						   &mappings[i].elf);
		if (err) {
			mappings[i].elf = NULL;
			if ((err->code == DRGN_ERROR_OS &&
			     err->errnum == ENOENT) ||
			    err == &drgn_not_elf ||
			    err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
				drgn_error_destroy(err);
				continue;
			}
			drgn_dwarf_index_close_unindexed(&prog->dicache->dindex);
			return err;
		}
		success = true;
	}
	if (!success) {
		return drgn_error_create(DRGN_ERROR_MISSING_DEBUG_INFO,
					 "no debug information found");
	}
	return drgn_program_update_debug_info(prog);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_default_debug_info(struct drgn_program *prog)
{
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return load_kernel_debug_info(prog);
	else
		return load_userspace_debug_info(prog);
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

	drgn_program_init(prog, DRGN_ARCH_AUTO);
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

	drgn_program_init(prog, DRGN_ARCH_AUTO);
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

	drgn_program_init(prog, DRGN_ARCH_AUTO);
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

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_c_string(struct drgn_program *prog, uint64_t address,
			   bool physical, size_t max_size, char **ret)
{
	struct drgn_error *err;
	char *str;
	size_t size = 0, capacity = 1;

	str = malloc(capacity);
	if (!str)
		return &drgn_enomem;

	for (;;) {
		if (size >= capacity) {
			capacity *= 2;
			if (!resize_array(&str, capacity)) {
				free(str);
				return &drgn_enomem;
			}
		}

		if (size < max_size) {
			err = drgn_memory_reader_read(&prog->reader, &str[size],
						      address, 1, physical);
			if (err) {
				free(str);
				return err;
			}
			if (!str[size++])
				break;
		} else {
			str[size++] = '\0';
			break;
		}
		address++;
	}
	/* We don't care if this fails. */
	resize_array(&str, size);
	*ret = str;
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
	struct drgn_error *err;
	struct drgn_symbol sym;
	struct drgn_qualified_type qualified_type;

	if (ret && ret->prog != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "object is from wrong program");
	}

	err = drgn_symbol_index_find(&prog->sindex, name, filename, flags,
				     &sym);
	if (err || !ret)
		return err;
	qualified_type.type = sym.type;
	qualified_type.qualifiers = sym.qualifiers;
	if (sym.kind == DRGN_SYMBOL_CONSTANT) {
		switch (drgn_type_object_kind(sym.type)) {
		case DRGN_OBJECT_SIGNED:
			return drgn_object_set_signed(ret, qualified_type,
						      sym.svalue, 0);
		case DRGN_OBJECT_UNSIGNED:
			return drgn_object_set_unsigned(ret, qualified_type,
							sym.uvalue, 0);
		case DRGN_OBJECT_FLOAT:
			return drgn_object_set_float(ret, qualified_type,
						     sym.fvalue);
		default:
			return drgn_type_error("cannot create '%s' constant",
					       sym.type);
		}
	} else {
		assert(sym.kind == DRGN_SYMBOL_ADDRESS);
		return drgn_object_set_reference(ret, qualified_type,
						 sym.address, 0, 0,
						 sym.little_endian);
	}
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
