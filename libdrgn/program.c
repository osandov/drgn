// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>
#include <byteswap.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "debug_info.h"
#include "error.h"
#include "language.h"
#include "linux_kernel.h"
#include "memory_reader.h"
#include "minmax.h"
#include "object_index.h"
#include "program.h"
#include "symbol.h"
#include "vector.h"
#include "util.h"

DEFINE_VECTOR_FUNCTIONS(drgn_prstatus_vector)
DEFINE_HASH_MAP_FUNCTIONS(drgn_prstatus_map, int_key_hash_pair, scalar_key_eq)

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

LIBDRGN_PUBLIC const struct drgn_language *
drgn_program_language(struct drgn_program *prog)
{
	return prog->lang ? prog->lang : &drgn_default_language;
}

void drgn_program_set_platform(struct drgn_program *prog,
			       const struct drgn_platform *platform)
{
	if (!prog->has_platform) {
		prog->platform = *platform;
		prog->has_platform = true;
	}
}

void drgn_program_init(struct drgn_program *prog,
		       const struct drgn_platform *platform)
{
	memset(prog, 0, sizeof(*prog));
	drgn_memory_reader_init(&prog->reader);
	drgn_program_init_types(prog);
	drgn_object_index_init(&prog->oindex);
	prog->core_fd = -1;
	if (platform)
		drgn_program_set_platform(prog, platform);
	char *env = getenv("DRGN_PREFER_ORC_UNWINDER");
	prog->prefer_orc_unwinder = env && atoi(env);
	drgn_object_init(&prog->page_offset, prog);
	drgn_object_init(&prog->vmemmap, prog);
}

void drgn_program_deinit(struct drgn_program *prog)
{
	if (prog->prstatus_cached) {
		if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
			drgn_prstatus_vector_deinit(&prog->prstatus_vector);
		else
			drgn_prstatus_map_deinit(&prog->prstatus_map);
	}
	free(prog->pgtable_it);

	drgn_object_deinit(&prog->vmemmap);
	drgn_object_deinit(&prog->page_offset);

	drgn_object_index_deinit(&prog->oindex);
	drgn_program_deinit_types(prog);
	drgn_memory_reader_deinit(&prog->reader);

	free(prog->file_segments);

#ifdef WITH_LIBKDUMPFILE
	if (prog->kdump_ctx)
		kdump_free(prog->kdump_ctx);
#endif
	elf_end(prog->core);
	if (prog->core_fd != -1)
		close(prog->core_fd);

	drgn_debug_info_destroy(prog->dbinfo);
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
	uint64_t address_mask;
	struct drgn_error *err = drgn_program_address_mask(prog, &address_mask);
	if (err)
		return err;
	if (size == 0 || address > address_mask)
		return NULL;
	uint64_t max_address = address + min(size - 1, address_mask - address);
	return drgn_memory_reader_add_segment(&prog->reader, address,
					      max_address, read_fn, arg,
					      physical);
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

static struct drgn_error *has_kdump_signature(const char *path, int fd,
					      bool *ret)
{
	char signature[KDUMP_SIG_LEN];
	size_t n = 0;

	while (n < sizeof(signature)) {
		ssize_t sret;

		sret = pread(fd, signature + n, sizeof(signature) - n, n);
		if (sret == -1) {
			if (errno == EINTR)
				continue;
			return drgn_error_create_os("pread", errno, path);
		} else if (sret == 0) {
			*ret = false;
			return NULL;
		}
		n += sret;
	}
	*ret = memcmp(signature, KDUMP_SIGNATURE, sizeof(signature)) == 0;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_core_dump(struct drgn_program *prog, const char *path)
{
	struct drgn_error *err;
	GElf_Ehdr ehdr_mem, *ehdr;
	bool had_platform;
	bool is_64_bit, is_kdump;
	size_t phnum, i;
	size_t num_file_segments, j;
	bool have_phys_addrs = false;
	const char *vmcoreinfo_note = NULL;
	size_t vmcoreinfo_size = 0;
	bool have_nt_taskstruct = false, is_proc_kcore;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	prog->core_fd = open(path, O_RDONLY);
	if (prog->core_fd == -1)
		return drgn_error_create_os("open", errno, path);

	err = has_kdump_signature(path, prog->core_fd, &is_kdump);
	if (err)
		goto out_fd;
	if (is_kdump) {
		err = drgn_program_set_kdump(prog);
		if (err)
			goto out_fd;
		return NULL;
	}

	elf_version(EV_CURRENT);

	prog->core = elf_begin(prog->core_fd, ELF_C_READ, NULL);
	if (!prog->core) {
		err = drgn_error_libelf();
		goto out_fd;
	}

	ehdr = gelf_getehdr(prog->core, &ehdr_mem);
	if (!ehdr || ehdr->e_type != ET_CORE) {
		err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					"not an ELF core file");
		goto out_elf;
	}
	had_platform = prog->has_platform;
	if (!had_platform) {
		struct drgn_platform platform;
		drgn_platform_from_elf(ehdr, &platform);
		drgn_program_set_platform(prog, &platform);
	}
	is_64_bit = ehdr->e_ident[EI_CLASS] == ELFCLASS64;

	if (elf_getphdrnum(prog->core, &phnum) != 0) {
		err = drgn_error_libelf();
		goto out_platform;
	}

	/*
	 * First pass: count the number of loadable segments, check if p_paddr
	 * is valid, and check for notes.
	 */
	num_file_segments = 0;
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;

		phdr = gelf_getphdr(prog->core, i, &phdr_mem);
		if (!phdr) {
			err = drgn_error_libelf();
			goto out_platform;
		}

		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_paddr)
				have_phys_addrs = true;
			num_file_segments++;
		} else if (phdr->p_type == PT_NOTE) {
			Elf_Data *data;
			size_t offset;
			GElf_Nhdr nhdr;
			size_t name_offset, desc_offset;

			data = elf_getdata_rawchunk(prog->core, phdr->p_offset,
						    phdr->p_filesz,
						    note_header_type(phdr->p_align));
			if (!data) {
				err = drgn_error_libelf();
				goto out_platform;
			}

			offset = 0;
			while (offset < data->d_size &&
			       (offset = gelf_getnote(data, offset, &nhdr,
						      &name_offset,
						      &desc_offset))) {
				const char *name, *desc;

				name = (char *)data->d_buf + name_offset;
				desc = (char *)data->d_buf + desc_offset;
				if (nhdr.n_namesz == sizeof("CORE") &&
				    memcmp(name, "CORE", sizeof("CORE")) == 0) {
					if (nhdr.n_type == NT_TASKSTRUCT)
						have_nt_taskstruct = true;
				} else if (nhdr.n_namesz == sizeof("VMCOREINFO") &&
					   memcmp(name, "VMCOREINFO",
						  sizeof("VMCOREINFO")) == 0) {
					vmcoreinfo_note = desc;
					vmcoreinfo_size = nhdr.n_descsz;
					/*
					 * This is either a vmcore or
					 * /proc/kcore, so even a p_paddr of 0
					 * may be valid.
					 */
					have_phys_addrs = true;
				}
			}
		}
	}

	if (have_nt_taskstruct) {
		/*
		 * If the core file has an NT_TASKSTRUCT note and is in /proc,
		 * then it's probably /proc/kcore.
		 */
		struct statfs fs;

		if (fstatfs(prog->core_fd, &fs) == -1) {
			err = drgn_error_create_os("fstatfs", errno, path);
			if (err)
				goto out_platform;
		}
		is_proc_kcore = fs.f_type == 0x9fa0; /* PROC_SUPER_MAGIC */
	} else {
		is_proc_kcore = false;
	}

	if (vmcoreinfo_note && !is_proc_kcore) {
		char *env;

		/* Use libkdumpfile for ELF vmcores if it was requested. */
		env = getenv("DRGN_USE_LIBKDUMPFILE_FOR_ELF");
		if (env && atoi(env)) {
			err = drgn_program_set_kdump(prog);
			if (err)
				goto out_platform;
			return NULL;
		}
	}

	prog->file_segments = malloc_array(num_file_segments,
					   sizeof(*prog->file_segments));
	if (!prog->file_segments) {
		err = &drgn_enomem;
		goto out_platform;
	}

	bool pgtable_reader =
		(is_proc_kcore || vmcoreinfo_note) &&
		prog->platform.arch->linux_kernel_pgtable_iterator_next;
	if (pgtable_reader) {
		/*
		 * Try to read any memory that isn't in the core dump via the
		 * page table.
		 */
		err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
						      read_memory_via_pgtable,
						      prog, false);
		if (err)
			goto out_segments;
	}

	/* Second pass: add the segments. */
	for (i = 0, j = 0; i < phnum && j < num_file_segments; i++) {
		GElf_Phdr phdr_mem, *phdr;

		phdr = gelf_getphdr(prog->core, i, &phdr_mem);
		if (!phdr) {
			err = drgn_error_libelf();
			goto out_segments;
		}

		if (phdr->p_type != PT_LOAD)
			continue;

		prog->file_segments[j].file_offset = phdr->p_offset;
		prog->file_segments[j].file_size = phdr->p_filesz;
		prog->file_segments[j].fd = prog->core_fd;
		prog->file_segments[j].eio_is_fault = false;
		err = drgn_program_add_memory_segment(prog, phdr->p_vaddr,
						      /*
						       * Don't override the page
						       * table reader for
						       * unsaved regions.
						       */
						      pgtable_reader ?
						      phdr->p_filesz :
						      phdr->p_memsz,
						      drgn_read_memory_file,
						      &prog->file_segments[j],
						      false);
		if (err)
			goto out_segments;
		if (have_phys_addrs &&
		    phdr->p_paddr != (is_64_bit ? UINT64_MAX : UINT32_MAX)) {
			err = drgn_program_add_memory_segment(prog,
							      phdr->p_paddr,
							      pgtable_reader ?
							      phdr->p_filesz :
							      phdr->p_memsz,
							      drgn_read_memory_file,
							      &prog->file_segments[j],
							      true);
			if (err)
				goto out_segments;
		}
		j++;
	}
	/*
	 * Before Linux kernel commit 464920104bf7 ("/proc/kcore: update
	 * physical address for kcore ram and text") (in v4.11), p_paddr in
	 * /proc/kcore is always zero. If we know the address of the direct
	 * mapping, we can still add physical segments. This needs to be a third
	 * pass, as we may need to read virtual memory to determine the mapping.
	 */
	if (is_proc_kcore && !have_phys_addrs &&
	    prog->platform.arch->linux_kernel_live_direct_mapping_fallback) {
		uint64_t direct_mapping, direct_mapping_size;
		err = prog->platform.arch->linux_kernel_live_direct_mapping_fallback(prog,
										     &direct_mapping,
										     &direct_mapping_size);
		if (err)
			goto out_segments;

		for (i = 0, j = 0; i < phnum && j < num_file_segments; i++) {
			GElf_Phdr phdr_mem, *phdr;

			phdr = gelf_getphdr(prog->core, i, &phdr_mem);
			if (!phdr) {
				err = drgn_error_libelf();
				goto out_segments;
			}

			if (phdr->p_type != PT_LOAD)
				continue;

			if (phdr->p_vaddr >= direct_mapping &&
			    phdr->p_vaddr - direct_mapping + phdr->p_memsz <=
			    direct_mapping_size) {
				uint64_t phys_addr;

				phys_addr = phdr->p_vaddr - direct_mapping;
				err = drgn_program_add_memory_segment(prog,
								      phys_addr,
								      pgtable_reader ?
								      phdr->p_filesz :
								      phdr->p_memsz,
								      drgn_read_memory_file,
								      &prog->file_segments[j],
								      true);
				if (err)
					goto out_segments;
			}
			j++;
		}
	}
	if (vmcoreinfo_note) {
		err = parse_vmcoreinfo(vmcoreinfo_note, vmcoreinfo_size,
				       &prog->vmcoreinfo);
		if (err)
			goto out_segments;
	}

	if (is_proc_kcore) {
		if (!vmcoreinfo_note) {
			err = read_vmcoreinfo_fallback(prog);
			if (err)
				goto out_segments;
		}
		prog->flags |= (DRGN_PROGRAM_IS_LINUX_KERNEL |
				DRGN_PROGRAM_IS_LIVE);
		elf_end(prog->core);
		prog->core = NULL;
	} else if (vmcoreinfo_note) {
		prog->flags |= DRGN_PROGRAM_IS_LINUX_KERNEL;
	}
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		err = drgn_program_add_object_finder(prog,
						     linux_kernel_object_find,
						     prog);
		if (err)
			goto out_segments;
		if (!prog->lang)
			prog->lang = &drgn_language_c;
	}

	return NULL;

out_segments:
	drgn_memory_reader_deinit(&prog->reader);
	drgn_memory_reader_init(&prog->reader);
	free(prog->file_segments);
	prog->file_segments = NULL;
out_platform:
	prog->has_platform = had_platform;
out_elf:
	elf_end(prog->core);
	prog->core = NULL;
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

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	char buf[64];
	sprintf(buf, "/proc/%ld/mem", (long)pid);
	prog->core_fd = open(buf, O_RDONLY);
	if (prog->core_fd == -1)
		return drgn_error_create_os("open", errno, buf);

	bool had_platform = prog->has_platform;
	drgn_program_set_platform(prog, &drgn_host_platform);

	prog->file_segments = malloc(sizeof(*prog->file_segments));
	if (!prog->file_segments) {
		err = &drgn_enomem;
		goto out_fd;
	}
	prog->file_segments[0].file_offset = 0;
	prog->file_segments[0].file_size = UINT64_MAX;
	prog->file_segments[0].fd = prog->core_fd;
	prog->file_segments[0].eio_is_fault = true;
	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_read_memory_file,
					      prog->file_segments, false);
	if (err)
		goto out_segments;

	prog->pid = pid;
	prog->flags |= DRGN_PROGRAM_IS_LIVE;
	return NULL;

out_segments:
	drgn_memory_reader_deinit(&prog->reader);
	drgn_memory_reader_init(&prog->reader);
	free(prog->file_segments);
	prog->file_segments = NULL;
out_fd:
	prog->has_platform = had_platform;
	close(prog->core_fd);
	prog->core_fd = -1;
	return err;
}

/* Set the default language from the language of "main". */
static void drgn_program_set_language_from_main(struct drgn_program *prog)
{
	struct drgn_error *err;

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return;
	const struct drgn_language *lang;
	err = drgn_debug_info_main_language(prog->dbinfo, &lang);
	if (err)
		drgn_error_destroy(err);
	if (lang)
		prog->lang = lang;
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

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_debug_info(struct drgn_program *prog, const char **paths,
			     size_t n, bool load_default, bool load_main)
{
	struct drgn_error *err;

	if (!n && !load_default && !load_main)
		return NULL;

	struct drgn_debug_info *dbinfo = prog->dbinfo;
	if (!dbinfo) {
		err = drgn_debug_info_create(prog, &dbinfo);
		if (err)
			return err;
		err = drgn_program_add_object_finder(prog,
						     drgn_debug_info_find_object,
						     dbinfo);
		if (err) {
			drgn_debug_info_destroy(dbinfo);
			return err;
		}
		err = drgn_program_add_type_finder(prog,
						   drgn_debug_info_find_type,
						   dbinfo);
		if (err) {
			drgn_object_index_remove_finder(&prog->oindex);
			drgn_debug_info_destroy(dbinfo);
			return err;
		}
		prog->dbinfo = dbinfo;
	}

	err = drgn_debug_info_load(dbinfo, paths, n, load_default, load_main);
	if ((!err || err->code == DRGN_ERROR_MISSING_DEBUG_INFO)) {
		if (!prog->lang)
			drgn_program_set_language_from_main(prog);
		if (!prog->has_platform) {
			dwfl_getdwarf(dbinfo->dwfl,
				      drgn_set_platform_from_dwarf, prog, 0);
		}
	}
	return err;
}

static struct drgn_error *get_prstatus_pid(struct drgn_program *prog, const char *data,
					   size_t size, uint32_t *ret)
{
	bool is_64_bit, bswap;
	struct drgn_error *err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;

	size_t offset = is_64_bit ? 32 : 24;
	uint32_t pr_pid;
	if (size < offset + sizeof(pr_pid)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "NT_PRSTATUS is truncated");
	}
	memcpy(&pr_pid, data + offset, sizeof(pr_pid));
	if (bswap)
		pr_pid = bswap_32(pr_pid);
	*ret = pr_pid;
	return NULL;
}

struct drgn_error *drgn_program_cache_prstatus_entry(struct drgn_program *prog,
						     const char *data,
						     size_t size)
{
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		struct nstring *entry =
			drgn_prstatus_vector_append_entry(&prog->prstatus_vector);
		if (!entry)
			return &drgn_enomem;
		entry->str = data;
		entry->len = size;
	} else {
		struct drgn_prstatus_map_entry entry = {
			.value = { data, size },
		};
		struct drgn_error *err = get_prstatus_pid(prog, data, size,
							  &entry.key);
		if (err)
			return err;
		if (drgn_prstatus_map_insert(&prog->prstatus_map, &entry,
					     NULL) == -1)
			return &drgn_enomem;
	}
	return NULL;
}

static struct drgn_error *drgn_program_cache_prstatus(struct drgn_program *prog)
{
	struct drgn_error *err;
	size_t phnum, i;

	if (prog->prstatus_cached)
		return NULL;

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		drgn_prstatus_vector_init(&prog->prstatus_vector);
	else
		drgn_prstatus_map_init(&prog->prstatus_map);

#ifdef WITH_LIBKDUMPFILE
	if (prog->kdump_ctx) {
		err = drgn_program_cache_prstatus_kdump(prog);
		goto out;
	}
#endif
	if (!prog->core) {
		err = NULL;
		goto out;
	}
	if (elf_getphdrnum(prog->core, &phnum) != 0) {
		err = drgn_error_libelf();
		goto out;
	}
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;
		Elf_Data *data;
		size_t offset;
		GElf_Nhdr nhdr;
		size_t name_offset, desc_offset;

		phdr = gelf_getphdr(prog->core, i, &phdr_mem);
		if (!phdr) {
			err = drgn_error_libelf();
			goto out;
		}
		if (phdr->p_type != PT_NOTE)
			continue;

		data = elf_getdata_rawchunk(prog->core, phdr->p_offset,
					    phdr->p_filesz,
					    note_header_type(phdr->p_align));
		if (!data) {
			err = drgn_error_libelf();
			goto out;
		}

		offset = 0;
		while (offset < data->d_size &&
		       (offset = gelf_getnote(data, offset, &nhdr, &name_offset,
					      &desc_offset))) {
			const char *name;

			name = (char *)data->d_buf + name_offset;
			if (strncmp(name, "CORE", nhdr.n_namesz) != 0 ||
			    nhdr.n_type != NT_PRSTATUS)
				continue;

			err = drgn_program_cache_prstatus_entry(prog,
								(char *)data->d_buf + desc_offset,
								nhdr.n_descsz);
			if (err)
				goto out;
		}
	}

	err = NULL;
out:
	if (err) {
		if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
			drgn_prstatus_vector_deinit(&prog->prstatus_vector);
		else
			drgn_prstatus_map_deinit(&prog->prstatus_map);
	} else {
		prog->prstatus_cached = true;
	}
	return err;
}

struct drgn_error *drgn_program_find_prstatus_by_cpu(struct drgn_program *prog,
						     uint32_t cpu,
						     struct nstring *ret,
						     uint32_t *tid_ret)
{
	assert(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL);
	struct drgn_error *err = drgn_program_cache_prstatus(prog);
	if (err)
		return err;

	if (cpu < prog->prstatus_vector.size) {
		*ret = prog->prstatus_vector.data[cpu];
		return get_prstatus_pid(prog, ret->str, ret->len, tid_ret);
	} else {
		ret->str = NULL;
		ret->len = 0;
		return NULL;
	}
}

struct drgn_error *drgn_program_find_prstatus_by_tid(struct drgn_program *prog,
						     uint32_t tid,
						     struct nstring *ret)
{
	struct drgn_error *err;
	struct drgn_prstatus_map_iterator it;

	assert(!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL));
	err = drgn_program_cache_prstatus(prog);
	if (err)
		return err;

	it = drgn_prstatus_map_search(&prog->prstatus_map, &tid);
	if (!it.entry) {
		ret->str = NULL;
		ret->len = 0;
		return NULL;
	}
	*ret = it.entry->value;
	return NULL;
}

struct drgn_error *drgn_program_init_core_dump(struct drgn_program *prog,
					       const char *path)
{
	struct drgn_error *err;

	err = drgn_program_set_core_dump(prog, path);
	if (err)
		return err;
	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);
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
	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);
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
	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);
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
	uint64_t address_mask;
	struct drgn_error *err = drgn_program_address_mask(prog, &address_mask);
	if (err)
		return err;
	char *p = buf;
	address &= address_mask;
	while (count > 0) {
		size_t n = min((uint64_t)(count - 1), address_mask - address) + 1;
		err = drgn_memory_reader_read(&prog->reader, p, address, n,
					      physical);
		if (err)
			return err;
		p += n;
		address = 0;
		count -= n;
	}
	return NULL;
}

DEFINE_VECTOR(char_vector, char)

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_c_string(struct drgn_program *prog, uint64_t address,
			   bool physical, size_t max_size, char **ret)
{
	uint64_t address_mask;
	struct drgn_error *err = drgn_program_address_mask(prog, &address_mask);
	if (err)
		return err;
	struct char_vector str = VECTOR_INIT;
	for (;;) {
		address &= address_mask;
		char *c = char_vector_append_entry(&str);
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
drgn_program_read_u8(struct drgn_program *prog, uint64_t address, bool physical,
		     uint8_t *ret)
{
	return drgn_program_read_memory(prog, ret, address, sizeof(*ret),
					physical);
}

#define DEFINE_PROGRAM_READ_U(n)						\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_read_u##n(struct drgn_program *prog, uint64_t address,		\
		       bool physical, uint##n##_t *ret)				\
{										\
	bool bswap;								\
	struct drgn_error *err = drgn_program_bswap(prog, &bswap);		\
	if (err)								\
		return err;							\
	uint##n##_t tmp;							\
	err = drgn_program_read_memory(prog, &tmp, address, sizeof(tmp),	\
				       physical);				\
	if (err)								\
		return err;							\
	if (bswap)								\
		tmp = bswap_##n(tmp);						\
	*ret = tmp;								\
	return NULL;								\
}

DEFINE_PROGRAM_READ_U(16)
DEFINE_PROGRAM_READ_U(32)
DEFINE_PROGRAM_READ_U(64)
#undef DEFINE_PROGRAM_READ_U

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_word(struct drgn_program *prog, uint64_t address,
		       bool physical, uint64_t *ret)
{
	bool is_64_bit, bswap;
	struct drgn_error *err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;
	if (is_64_bit) {
		uint64_t tmp;
		err = drgn_program_read_memory(prog, &tmp, address, sizeof(tmp),
					       physical);
		if (err)
			return err;
		if (bswap)
			tmp = bswap_64(tmp);
		*ret = tmp;
	} else {
		uint32_t tmp;
		err = drgn_program_read_memory(prog, &tmp, address, sizeof(tmp),
					       physical);
		if (err)
			return err;
		if (bswap)
			tmp = bswap_32(tmp);
		*ret = tmp;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_object(struct drgn_program *prog, const char *name,
			 const char *filename,
			 enum drgn_find_object_flags flags,
			 struct drgn_object *ret)
{
	if (ret && drgn_object_program(ret) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "object is from wrong program");
	}
	return drgn_object_index_find(&prog->oindex, name, filename, flags,
				      ret);
}

bool drgn_program_find_symbol_by_address_internal(struct drgn_program *prog,
						  uint64_t address,
						  Dwfl_Module *module,
						  struct drgn_symbol *ret)
{
	if (!module) {
		if (prog->dbinfo) {
			module = dwfl_addrmodule(prog->dbinfo->dwfl, address);
			if (!module)
				return false;
		} else {
			return false;
		}
	}

	GElf_Off offset;
	GElf_Sym elf_sym;
	const char *name = dwfl_module_addrinfo(module, address, &offset,
						&elf_sym, NULL, NULL, NULL);
	if (!name)
		return false;
	drgn_symbol_from_elf(name, address - offset, &elf_sym, ret);
	return true;
}

struct drgn_error *drgn_error_symbol_not_found(uint64_t address)
{
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "could not find symbol containing 0x%" PRIx64,
				 address);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbol_by_address(struct drgn_program *prog, uint64_t address,
				    struct drgn_symbol **ret)
{
	struct drgn_symbol *sym;

	sym = malloc(sizeof(*sym));
	if (!sym)
		return &drgn_enomem;
	if (!drgn_program_find_symbol_by_address_internal(prog, address, NULL,
							  sym)) {
		free(sym);
		return drgn_error_symbol_not_found(address);
	}
	*ret = sym;
	return NULL;
}

struct find_symbol_by_name_arg {
	const char *name;
	GElf_Sym sym;
	GElf_Addr addr;
	bool found;
	bool bad_symtabs;
};

static int find_symbol_by_name_cb(Dwfl_Module *dwfl_module, void **userdatap,
				  const char *module_name, Dwarf_Addr base,
				  void *cb_arg)
{
	struct find_symbol_by_name_arg *arg = cb_arg;
	int symtab_len = dwfl_module_getsymtab(dwfl_module);
	if (symtab_len == -1) {
		arg->bad_symtabs = true;
		return DWARF_CB_OK;
	}
	/*
	 * Global symbols are after local symbols, so by iterating backwards we
	 * might find a global symbol faster. Ignore the zeroth null symbol.
	 */
	for (int i = symtab_len - 1; i > 0; i--) {
		GElf_Sym sym;
		GElf_Addr addr;
		const char *name = dwfl_module_getsym_info(dwfl_module, i, &sym,
							   &addr, NULL, NULL,
							   NULL);
		if (name && strcmp(arg->name, name) == 0) {
			/*
			 * The order of precedence is
			 * GLOBAL = GNU_UNIQUE > WEAK > LOCAL = everything else
			 *
			 * If we found a global or unique symbol, return it
			 * immediately. If we found a weak symbol, then save it,
			 * which may overwrite a previously found weak or local
			 * symbol. Otherwise, save the symbol only if we haven't
			 * found another symbol.
			 */
			if (GELF_ST_BIND(sym.st_info) == STB_GLOBAL ||
			    GELF_ST_BIND(sym.st_info) == STB_GNU_UNIQUE ||
			    GELF_ST_BIND(sym.st_info) == STB_WEAK ||
			    !arg->found) {
				arg->sym = sym;
				arg->addr = addr;
				arg->found = true;
			}
			if (GELF_ST_BIND(sym.st_info) == STB_GLOBAL ||
			    GELF_ST_BIND(sym.st_info) == STB_GNU_UNIQUE)
				return DWARF_CB_ABORT;
		}
	}
	return DWARF_CB_OK;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbol_by_name(struct drgn_program *prog,
			const char *name, struct drgn_symbol **ret)
{
	struct find_symbol_by_name_arg arg = {
		.name = name,
	};
	if (prog->dbinfo) {
		dwfl_getmodules(prog->dbinfo->dwfl, find_symbol_by_name_cb,
				&arg, 0);
		if (arg.found) {
			struct drgn_symbol *sym = malloc(sizeof(*sym));
			if (!sym)
				return &drgn_enomem;
			drgn_symbol_from_elf(name, arg.addr, &arg.sym, sym);
			*ret = sym;
			return NULL;
		}
	}
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "could not find symbol with name '%s'%s", name,
				 arg.bad_symtabs ?
				 " (could not get some symbol tables)" : "");
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
