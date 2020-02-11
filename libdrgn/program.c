// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <byteswap.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
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

DEFINE_HASH_TABLE_FUNCTIONS(drgn_prstatus_map, hash_pair_int_type,
			    hash_table_scalar_eq)

static Elf_Type note_header_type(GElf_Phdr *phdr)
{
	if (phdr->p_align == 8)
		return ELF_T_NHDR8;
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

LIBDRGN_PUBLIC const struct drgn_language *
drgn_program_language(struct drgn_program *prog)
{
	return drgn_language_or_default(prog->lang);
}

void drgn_program_set_platform(struct drgn_program *prog,
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
	drgn_prstatus_map_init(&prog->prstatus_cache);
	if (platform)
		drgn_program_set_platform(prog, platform);
}

void drgn_program_deinit(struct drgn_program *prog)
{
	free(prog->task_state_chars);
	drgn_prstatus_map_deinit(&prog->prstatus_cache);

	drgn_object_index_deinit(&prog->oindex);
	drgn_type_index_deinit(&prog->tindex);
	drgn_memory_reader_deinit(&prog->reader);

	free(prog->file_segments);

#ifdef WITH_LIBKDUMPFILE
	if (prog->kdump_ctx)
		kdump_free(prog->kdump_ctx);
#endif
	elf_end(prog->core);
	if (prog->core_fd != -1)
		close(prog->core_fd);

	drgn_dwarf_info_cache_destroy(prog->_dicache);
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
	struct drgn_platform platform;
	bool is_64_bit, is_kdump;
	size_t phnum, i;
	size_t num_file_segments;
	bool have_non_zero_phys_addr = false;
	struct drgn_memory_file_segment *current_file_segment;
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

	drgn_platform_from_elf(ehdr, &platform);
	is_64_bit = ehdr->e_ident[EI_CLASS] == ELFCLASS64;

	if (elf_getphdrnum(prog->core, &phnum) != 0) {
		err = drgn_error_libelf();
		goto out_elf;
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
			goto out_elf;
		}

		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_paddr)
				have_non_zero_phys_addr = true;
			num_file_segments++;
		} else if (phdr->p_type == PT_NOTE) {
			Elf_Data *data;
			size_t offset;
			GElf_Nhdr nhdr;
			size_t name_offset, desc_offset;

			data = elf_getdata_rawchunk(prog->core, phdr->p_offset,
						    phdr->p_filesz,
						    note_header_type(phdr));
			if (!data) {
				err = drgn_error_libelf();
				goto out_elf;
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
					vmcoreinfo_note = desc;
					vmcoreinfo_size = nhdr.n_descsz;
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
				goto out_elf;
		}
		is_proc_kcore = fs.f_type == 0x9fa0; /* PROC_SUPER_MAGIC */
	} else {
		is_proc_kcore = false;
	}

	if (vmcoreinfo_note && !is_proc_kcore) {
		char *env;
		bool use_libkdumpfile;

		/*
		 * Use libkdumpfile for ELF vmcores if we were compiled with
		 * libkdumpfile support unless specified otherwise.
		 */
		env = getenv("DRGN_USE_LIBKDUMPFILE_FOR_ELF");
		if (env) {
			use_libkdumpfile = atoi(env);
		} else {
#ifdef WITH_LIBKDUMPFILE
			use_libkdumpfile = true;
#else
			use_libkdumpfile = false;
#endif
		}
		if (use_libkdumpfile) {
			err = drgn_program_set_kdump(prog);
			if (err)
				goto out_elf;
			return NULL;
		}
	}

	prog->file_segments = malloc_array(num_file_segments,
					   sizeof(*prog->file_segments));
	if (!prog->file_segments) {
		err = &drgn_enomem;
		goto out_elf;
	}
	prog->num_file_segments = num_file_segments;
	current_file_segment = prog->file_segments;

	/* Second pass: add the segments. */
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;

		phdr = gelf_getphdr(prog->core, i, &phdr_mem);
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
			current_file_segment->eio_is_fault = false;
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
			err = read_vmcoreinfo_fallback(&prog->reader,
						       have_non_zero_phys_addr,
						       &prog->vmcoreinfo);
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
						     vmcoreinfo_object_find,
						     prog);
		if (err)
			goto out_segments;
		if (!prog->lang)
			prog->lang = &drgn_language_c;
	}

	drgn_program_set_platform(prog, &platform);
	return NULL;

out_segments:
	drgn_memory_reader_deinit(&prog->reader);
	drgn_memory_reader_init(&prog->reader);
	free(prog->file_segments);
	prog->file_segments = NULL;
	prog->num_file_segments = 0;
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
	prog->file_segments[0].eio_is_fault = true;
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

static struct drgn_error *drgn_program_get_dindex(struct drgn_program *prog,
						  struct drgn_dwarf_index **ret)
{
	struct drgn_error *err;

	if (!prog->_dicache) {
		const Dwfl_Callbacks *dwfl_callbacks;
		struct drgn_dwarf_info_cache *dicache;

		if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
			dwfl_callbacks = &drgn_dwfl_callbacks;
		else if (prog->flags & DRGN_PROGRAM_IS_LIVE)
			dwfl_callbacks = &drgn_linux_proc_dwfl_callbacks;
		else
			dwfl_callbacks = &drgn_userspace_core_dump_dwfl_callbacks;

		err = drgn_dwarf_info_cache_create(&prog->tindex,
						   dwfl_callbacks, &dicache);
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
	*ret = &prog->_dicache->dindex;
	return NULL;
}

struct drgn_error *drgn_program_get_dwfl(struct drgn_program *prog, Dwfl **ret)
{
	struct drgn_error *err;
	struct drgn_dwarf_index *dindex;

	err = drgn_program_get_dindex(prog, &dindex);
	if (err)
		return err;
	*ret = dindex->dwfl;
	return NULL;
}

/* Set the default language from the language of "main". */
static struct drgn_error *
drgn_program_set_language_from_main(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct drgn_object res;

	drgn_object_init(&res, prog);
	err = drgn_program_find_object(prog, "main", NULL, DRGN_FIND_OBJECT_ANY,
				       &res);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			/* We couldn't find "main". Don't set the language. */
			drgn_error_destroy(err);
			err = NULL;
		}
	} else {
		prog->lang = drgn_type_language(res.type);
	}
	drgn_object_deinit(&res);
	return err;
}

static struct drgn_error *
userspace_report_debug_info(struct drgn_program *prog,
			    struct drgn_dwarf_index *dindex,
			    const char **paths, size_t n,
			    bool report_default)
{
	struct drgn_error *err;
	size_t i;

	for (i = 0; i < n; i++) {
		int fd;
		Elf *elf;

		err = open_elf_file(paths[i], &fd, &elf);
		if (err) {
			err = drgn_dwarf_index_report_error(dindex, paths[i],
							    NULL, err);
			if (err)
				return err;
			continue;
		}
		/*
		 * We haven't implemented a way to get the load address for
		 * anything reported here, so for now we report it as unloaded.
		 */
		err = drgn_dwarf_index_report_elf(dindex, paths[i], fd, elf, 0,
						  0, NULL, NULL);
		if (err)
			return err;
	}

	if (report_default) {
		if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
			int ret;

			ret = dwfl_linux_proc_report(dindex->dwfl, prog->pid);
			if (ret == -1) {
				return drgn_error_libdwfl();
			} else if (ret) {
				return drgn_error_create_os("dwfl_linux_proc_report",
							    ret, NULL);
			}
		} else if (dwfl_core_file_report(dindex->dwfl, prog->core,
						 NULL) == -1) {
			return drgn_error_libdwfl();
		}
	}

	if (!prog->lang) {
		err = drgn_program_set_language_from_main(prog);
		if (err)
			return err;
	}
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

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_load_debug_info(struct drgn_program *prog, const char **paths,
			     size_t n, bool load_default, bool load_main)
{
	struct drgn_error *err;
	struct drgn_dwarf_index *dindex;
	bool report_from_dwfl;

	if (!n && !load_default && !load_main)
		return NULL;

	if (load_default)
		load_main = true;

	err = drgn_program_get_dindex(prog, &dindex);
	if (err)
		return err;

	drgn_dwarf_index_report_begin(dindex);
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		err = linux_kernel_report_debug_info(prog, dindex, paths, n,
						     load_default, load_main);
	} else {
		err = userspace_report_debug_info(prog, dindex, paths, n,
						  load_default);
	}
	if (err) {
		drgn_dwarf_index_report_abort(dindex);
		return err;
	}
	report_from_dwfl = (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
			    load_main);
	err = drgn_dwarf_index_report_end(dindex, report_from_dwfl);
	if ((!err || err->code == DRGN_ERROR_MISSING_DEBUG_INFO) &&
	    !prog->has_platform) {
		dwfl_getdwarf(prog->_dicache->dindex.dwfl,
			      drgn_set_platform_from_dwarf, prog, 0);
	}
	return err;
}

struct drgn_error *drgn_program_cache_prstatus_entry(struct drgn_program *prog,
						     char *data, size_t size)
{
	struct drgn_prstatus_map_entry entry;
	size_t pr_pid_offset;
	uint32_t pr_pid;
	bool bswap;

	pr_pid_offset = drgn_program_is_64_bit(prog) ? 32 : 24;
	bswap = (drgn_program_is_little_endian(prog) !=
		 (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__));

	if (size < pr_pid_offset + sizeof(pr_pid))
		return NULL;

	memcpy(&pr_pid, data + pr_pid_offset, sizeof(pr_pid));
	if (bswap)
		pr_pid = bswap_32(pr_pid);
	if (!pr_pid)
		return NULL;

	entry.key = pr_pid;
	entry.value.str = data;
	entry.value.len = size;
	if (drgn_prstatus_map_insert(&prog->prstatus_cache, &entry,
				     NULL) == -1) {
		return &drgn_enomem;
	}
	return NULL;
}

static struct drgn_error *drgn_program_cache_prstatus(struct drgn_program *prog)
{
	size_t phnum, i;

#ifdef WITH_LIBKDUMPFILE
	if (prog->kdump_ctx)
		return drgn_program_cache_prstatus_kdump(prog);
#endif
	if (elf_getphdrnum(prog->core, &phnum) != 0)
		return drgn_error_libelf();
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;
		Elf_Data *data;
		size_t offset;
		GElf_Nhdr nhdr;
		size_t name_offset, desc_offset;

		phdr = gelf_getphdr(prog->core, i, &phdr_mem);
		if (!phdr)
			return drgn_error_libelf();
		if (phdr->p_type != PT_NOTE)
			continue;

		data = elf_getdata_rawchunk(prog->core, phdr->p_offset,
					    phdr->p_filesz,
					    note_header_type(phdr));
		if (!data)
			return drgn_error_libelf();

		offset = 0;
		while (offset < data->d_size &&
		       (offset = gelf_getnote(data, offset, &nhdr, &name_offset,
					      &desc_offset))) {
			const char *name;
			struct drgn_error *err;

			name = (char *)data->d_buf + name_offset;
			if (strncmp(name, "CORE", nhdr.n_namesz) != 0 ||
			    nhdr.n_type != NT_PRSTATUS)
				continue;

			err = drgn_program_cache_prstatus_entry(prog,
								(char *)data->d_buf + desc_offset,
								nhdr.n_descsz);
			if (err)
				return err;
		}
	}
	return NULL;
}

struct drgn_error *drgn_program_find_prstatus(struct drgn_program *prog,
					      uint32_t tid, struct string *ret)
{
	struct drgn_error *err;
	struct drgn_prstatus_map_iterator it;

	if (!prog->prstatus_cached) {
		err = drgn_program_cache_prstatus(prog);
		if (err)
			return err;
		prog->prstatus_cached = true;
	}

	it = drgn_prstatus_map_search(&prog->prstatus_cache, &tid);
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
				    drgn_program_language(prog), ret);
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

bool drgn_program_find_symbol_by_address_internal(struct drgn_program *prog,
						  uint64_t address,
						  Dwfl_Module *module,
						  struct drgn_symbol *ret)
{
	const char *name;
	GElf_Off offset;
	GElf_Sym elf_sym;

	if (!module) {
		if (prog->_dicache) {
			module = dwfl_addrmodule(prog->_dicache->dindex.dwfl,
						 address);
			if (!module)
				return false;
		} else {
			return false;
		}
	}

	name = dwfl_module_addrinfo(module, address, &offset, &elf_sym, NULL,
				    NULL, NULL);
	if (!name)
		return false;
	ret->name = name;
	ret->address = address - offset;
	ret->size = elf_sym.st_size;
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
	struct drgn_symbol **ret;
	struct drgn_error *err;
	bool bad_symtabs;
};

static int find_symbol_by_name_cb(Dwfl_Module *dwfl_module, void **userdatap,
				  const char *module_name, Dwarf_Addr base,
				  void *cb_arg)
{
	struct find_symbol_by_name_arg *arg = cb_arg;
	int symtab_len, i;

	symtab_len = dwfl_module_getsymtab(dwfl_module);
	i = dwfl_module_getsymtab_first_global(dwfl_module);
	if (symtab_len == -1 || i == -1) {
		arg->bad_symtabs = true;
		return DWARF_CB_OK;
	}
	for (; i < symtab_len; i++) {
		GElf_Sym elf_sym;
		GElf_Addr elf_addr;
		const char *name;

		name = dwfl_module_getsym_info(dwfl_module, i, &elf_sym,
					       &elf_addr, NULL, NULL, NULL);
		if (name && strcmp(arg->name, name) == 0) {
			struct drgn_symbol *sym;

			sym = malloc(sizeof(*sym));
			if (sym) {
				sym->name = name;
				sym->address = elf_addr;
				sym->size = elf_sym.st_size;
				*arg->ret = sym;
			} else {
				arg->err = &drgn_enomem;
			}
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
		.ret = ret,
	};

	if (prog->_dicache &&
	    dwfl_getmodules(prog->_dicache->dindex.dwfl, find_symbol_by_name_cb,
			    &arg, 0))
		return arg.err;
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
