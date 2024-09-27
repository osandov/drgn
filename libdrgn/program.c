// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <byteswap.h>
#include <dirent.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "cleanup.h"
#include "debug_info.h"
#include "error.h"
#include "helpers.h"
#include "io.h"
#include "language.h"
#include "log.h"
#include "linux_kernel.h"
#include "memory_reader.h"
#include "minmax.h"
#include "object.h"
#include "program.h"
#include "symbol.h"
#include "util.h"
#include "vector.h"

static inline uint32_t drgn_thread_to_key(const struct drgn_thread *entry)
{
	return entry->tid;
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_thread_set, drgn_thread_to_key,
			    int_key_hash_pair, scalar_key_eq);

struct drgn_thread_iterator {
	struct drgn_program *prog;
	union {
		/* For userspace core dumps. */
		struct drgn_thread_set_iterator iterator;
		struct {
			union {
				/* For live processes. */
				DIR *tasks_dir;
				/* For the Linux kernel. */
				struct linux_helper_task_iterator task_iter;
			};
			/* For both live processes and the Linux kernel. */
			struct drgn_thread entry;
		};
	};
};

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

LIBDRGN_PUBLIC void drgn_program_set_language(struct drgn_program *prog,
					      const struct drgn_language *lang)
{
	prog->lang = lang;
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
	drgn_debug_info_init(&prog->dbinfo, prog);
	prog->core_fd = -1;
	if (platform)
		drgn_program_set_platform(prog, platform);
	drgn_thread_set_init(&prog->thread_set);
	char *env = getenv("DRGN_PREFER_ORC_UNWINDER");
	prog->prefer_orc_unwinder = env && atoi(env);
	drgn_program_set_log_level(prog, DRGN_LOG_NONE);
	drgn_program_set_log_file(prog, stderr);
	drgn_object_init(&prog->vmemmap, prog);
}

void drgn_program_deinit(struct drgn_program *prog)
{
	drgn_thread_set_deinit(&prog->thread_set);
	/*
	 * For userspace core dumps, main_thread and crashed_thread are in
	 * prog->thread_set and thus freed by the above call to
	 * drgn_thread_set_deinit().
	 */
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		drgn_thread_destroy(prog->crashed_thread);
	else if (prog->flags & DRGN_PROGRAM_IS_LIVE)
		drgn_thread_destroy(prog->main_thread);
	if (prog->pgtable_it)
		prog->platform.arch->linux_kernel_pgtable_iterator_destroy(prog->pgtable_it);

	drgn_object_deinit(&prog->vmemmap);

	drgn_handler_list_deinit(struct drgn_symbol_finder, finder,
				 &prog->symbol_finders,
		if (finder->ops.destroy)
			finder->ops.destroy(finder->arg);
	);
	drgn_handler_list_deinit(struct drgn_object_finder, finder,
				 &prog->object_finders,
		if (finder->ops.destroy)
			finder->ops.destroy(finder->arg);
	);
	drgn_program_deinit_types(prog);
	drgn_memory_reader_deinit(&prog->reader);

	free(prog->file_segments);
	free(prog->vmcoreinfo.raw);

#ifdef WITH_LIBKDUMPFILE
	if (prog->kdump_ctx)
		kdump_free(prog->kdump_ctx);
#endif
	elf_end(prog->core);
	if (prog->core_fd != -1)
		close(prog->core_fd);

	drgn_debug_info_deinit(&prog->dbinfo);
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

#define DRGN_PROGRAM_FINDER(which)						\
struct drgn_error *								\
drgn_program_register_##which##_finder_impl(struct drgn_program *prog,		\
					    struct drgn_##which##_finder *finder,\
					    const char *name,			\
					    const struct drgn_##which##_finder_ops *ops,\
					    void *arg, size_t enable_index)	\
{										\
	struct drgn_error *err;							\
	if (finder) {								\
		finder->handler.name = name;					\
		finder->handler.free = false;					\
	} else {								\
		finder = malloc(sizeof(*finder));				\
		if (!finder)							\
			return &drgn_enomem;					\
		finder->handler.name = strdup(name);				\
		if (!finder->handler.name) {					\
			free(finder);						\
			return &drgn_enomem;					\
		}								\
		finder->handler.free = true;					\
	}									\
	memcpy(&finder->ops, ops, sizeof(finder->ops));				\
	finder->arg = arg;							\
	err = drgn_handler_list_register(&prog->which##_finders,		\
					 &finder->handler, enable_index,	\
					 #which " finder");			\
	if (err && finder->handler.free) {					\
		free((char *)finder->handler.name);				\
		free(finder);							\
	}									\
	return err;								\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_register_##which##_finder(struct drgn_program *prog, const char *name,\
				       const struct drgn_##which##_finder_ops *ops,\
				       void *arg, size_t enable_index)		\
{										\
	return drgn_program_register_##which##_finder_impl(prog, NULL, name,	\
							   ops, arg,		\
							   enable_index);	\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_registered_##which##_finders(struct drgn_program *prog,		\
					  const char ***names_ret,		\
					  size_t *count_ret)			\
{										\
	return drgn_handler_list_registered(&prog->which##_finders, names_ret,	\
					    count_ret);				\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_set_enabled_##which##_finders(struct drgn_program *prog,		\
					   const char * const *names,		\
					   size_t count)			\
{										\
	return drgn_handler_list_set_enabled(&prog->which##_finders, names,	\
					     count, #which "finder");		\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_enabled_##which##_finders(struct drgn_program *prog,		\
				       const char ***names_ret,			\
				       size_t *count_ret)			\
{										\
	return drgn_handler_list_enabled(&prog->which##_finders, names_ret,	\
					 count_ret);				\
}

DRGN_PROGRAM_FINDER(type)
DRGN_PROGRAM_FINDER(object)
DRGN_PROGRAM_FINDER(symbol)
#undef DRGN_PROGRAM_FINDER

static struct drgn_error *
drgn_program_check_initialized(struct drgn_program *prog)
{
	if (prog->core_fd != -1 || !drgn_memory_reader_empty(&prog->reader)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program memory was already initialized");
	}
	return NULL;
}

static struct drgn_error *
has_kdump_signature(struct drgn_program *prog, const char *path, bool *ret)
{
	char signature[max_iconst(KDUMP_SIG_LEN, FLATTENED_SIG_LEN)];
	ssize_t r = pread_all(prog->core_fd, signature, sizeof(signature), 0);
	if (r < 0)
		return drgn_error_create_os("pread", errno, path);
	*ret = false;
	if (r >= FLATTENED_SIG_LEN
	    && memcmp(signature, FLATTENED_SIGNATURE, FLATTENED_SIG_LEN) == 0) {
		drgn_log_warning(prog,
				 "the given file is in the makedumpfile flattened "
				 "format; if open fails or is too slow, reassemble "
				 "it with 'makedumpfile -R newfile <oldfile'");
		*ret = true;
	} else if (r >= KDUMP_SIG_LEN
		   && memcmp(signature, KDUMP_SIGNATURE, KDUMP_SIG_LEN) == 0)
		*ret = true;
	return NULL;
}

static struct drgn_error *
drgn_program_set_core_dump_fd_internal(struct drgn_program *prog, int fd,
				       const char *path)
{
	struct drgn_error *err;
	GElf_Ehdr ehdr_mem, *ehdr;
	bool had_platform;
	bool is_64_bit, little_endian, is_kdump;
	size_t phnum, i;
	size_t num_file_segments, j;
	bool have_phys_addrs = false;
	bool have_qemu_note = false;
	const char *vmcoreinfo_note = NULL;
	size_t vmcoreinfo_size = 0;
	bool have_nt_taskstruct = false, is_proc_kcore;
	bool have_vmcoreinfo = prog->vmcoreinfo.raw;
	bool had_vmcoreinfo = have_vmcoreinfo;

	prog->core_fd = fd;
	err = has_kdump_signature(prog, path, &is_kdump);
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
	little_endian = ehdr->e_ident[EI_DATA] == ELFDATA2LSB;

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
			goto out_notes;
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
				goto out_notes;
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
				} else if (nhdr.n_namesz == sizeof("LINUX") &&
					   memcmp(name, "LINUX",
						  sizeof("LINUX")) == 0) {
					if (nhdr.n_type == NT_ARM_PAC_MASK &&
					    nhdr.n_descsz >=
					    2 * sizeof(uint64_t)) {
						memcpy(&prog->aarch64_insn_pac_mask,
						       (uint64_t *)desc + 1,
						       sizeof(uint64_t));
						if (little_endian !=
						    HOST_LITTLE_ENDIAN)
							bswap_64(prog->aarch64_insn_pac_mask);
					}
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
					have_vmcoreinfo = true;
				} else if (nhdr.n_namesz == sizeof("QEMU") &&
					   memcmp(name, "QEMU",
						  sizeof("QEMU")) == 0) {
					have_qemu_note = true;
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
				goto out_notes;
		}
		is_proc_kcore = fs.f_type == 0x9fa0; /* PROC_SUPER_MAGIC */
	} else {
		is_proc_kcore = false;
	}

	if (have_vmcoreinfo && !is_proc_kcore) {
		char *env;

		/* Use libkdumpfile for ELF vmcores if it was requested. */
		env = getenv("DRGN_USE_LIBKDUMPFILE_FOR_ELF");
		if (env && atoi(env)) {
			err = drgn_program_set_kdump(prog);
			if (err)
				goto out_notes;
			return NULL;
		}
	}

	prog->file_segments = malloc_array(num_file_segments,
					   sizeof(*prog->file_segments));
	if (!prog->file_segments) {
		err = &drgn_enomem;
		goto out_notes;
	}

	bool pgtable_reader =
		(is_proc_kcore || have_vmcoreinfo) &&
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
		/*
		 * p_filesz < p_memsz is ambiguous for core dumps. The ELF
		 * specification says that "if the segment's memory size p_memsz
		 * is larger than the file size p_filesz, the 'extra' bytes are
		 * defined to hold the value 0 and to follow the segment's
		 * initialized area."
		 *
		 * However, the Linux kernel generates userspace core dumps with
		 * segments with p_filesz < p_memsz to indicate that the range
		 * between p_filesz and p_memsz was filtered out (see
		 * coredump_filter in core(5)). These bytes were not necessarily
		 * zeroes in the process's memory, which contradicts the ELF
		 * specification in a way.
		 *
		 * As of Linux 5.19, /proc/kcore and /proc/vmcore never have
		 * segments with p_filesz < p_memsz. However, makedumpfile
		 * creates segments with p_filesz < p_memsz to indicate ranges
		 * that were excluded. This is similar to Linux userspace core
		 * dumps, except that makedumpfile can also exclude ranges that
		 * were all zeroes.
		 *
		 * So, for userspace core dumps, we want to fault for ranges
		 * between p_filesz and p_memsz to indicate that the memory was
		 * not saved rather than lying and returning zeroes. For
		 * /proc/kcore, we don't expect to see p_filesz < p_memsz but we
		 * fault to be safe. For Linux kernel core dumps, we can't
		 * distinguish between memory that was excluded because it was
		 * all zeroes and memory that was excluded by makedumpfile for
		 * another reason, so we're forced to always return zeroes.
		 */
		prog->file_segments[j].zerofill = have_vmcoreinfo && !is_proc_kcore;
		err = drgn_program_add_memory_segment(prog, phdr->p_vaddr,
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
	if (vmcoreinfo_note && !prog->vmcoreinfo.raw) {
		err = drgn_program_parse_vmcoreinfo(prog, vmcoreinfo_note,
						    vmcoreinfo_size);
		if (err)
			goto out_segments;
	}

	if (is_proc_kcore) {
		if (!have_vmcoreinfo) {
			err = read_vmcoreinfo_fallback(prog);
			if (err)
				goto out_segments;
		}
		prog->flags |= (DRGN_PROGRAM_IS_LINUX_KERNEL |
				DRGN_PROGRAM_IS_LIVE |
		                DRGN_PROGRAM_IS_LOCAL);
		elf_end(prog->core);
		prog->core = NULL;
	} else if (have_vmcoreinfo) {
		prog->flags |= DRGN_PROGRAM_IS_LINUX_KERNEL;
	} else if (have_qemu_note) {
		err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					"unrecognized QEMU memory dump; "
					"for Linux guests, run QEMU with '-device vmcoreinfo', "
					"compile the kernel with CONFIG_FW_CFG_SYSFS and CONFIG_KEXEC, "
					"and load the qemu_fw_cfg kernel module "
					"before dumping the guest memory "
					"(requires Linux >= 4.17 and QEMU >= 2.11)");
		goto out_segments;
	}
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		err = drgn_program_finish_set_kernel(prog);
		if (err)
			goto out_segments;
	}

	return NULL;

out_segments:
	drgn_memory_reader_deinit(&prog->reader);
	drgn_memory_reader_init(&prog->reader);
	free(prog->file_segments);
	prog->file_segments = NULL;
out_notes:
	// Reset anything we parsed from ELF notes.
	prog->aarch64_insn_pac_mask = 0;
	// Free vmcoreinfo buffer if it was not provided by the caller
	if (!had_vmcoreinfo) {
		free(prog->vmcoreinfo.raw);
		memset(&prog->vmcoreinfo, 0, sizeof(prog->vmcoreinfo));
	}
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
drgn_program_set_core_dump_fd(struct drgn_program *prog, int fd)
{
	struct drgn_error *err;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	#define FORMAT "/proc/self/fd/%d"
	char path[sizeof(FORMAT) - sizeof("%d") + max_decimal_length(int) + 1];
	snprintf(path, sizeof(path), FORMAT, fd);
	#undef FORMAT

	return drgn_program_set_core_dump_fd_internal(prog, fd, path);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_core_dump(struct drgn_program *prog, const char *path)
{
	struct drgn_error *err;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	int fd = open(path, O_RDONLY);
	if (fd == -1)
		return drgn_error_create_os("open", errno, path);

	return drgn_program_set_core_dump_fd_internal(prog, fd, path);
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

#define FORMAT "/proc/%ld/mem"
	char buf[sizeof(FORMAT) - sizeof("%ld") + max_decimal_length(long) + 1];
	snprintf(buf, sizeof(buf), FORMAT, (long)pid);
#undef FORMAT
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
	prog->file_segments[0].zerofill = false;
	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_read_memory_file,
					      prog->file_segments, false);
	if (err)
		goto out_segments;

	prog->pid = pid;
	prog->flags |= DRGN_PROGRAM_IS_LIVE | DRGN_PROGRAM_IS_LOCAL;
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
	err = drgn_debug_info_main_language(&prog->dbinfo, &lang);
	if (err) {
		drgn_error_destroy(err);
		return;
	}
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

	drgn_blocking_guard(prog);
	err = drgn_debug_info_load(&prog->dbinfo, paths, n, load_default, load_main);
	if ((!err || err->code == DRGN_ERROR_MISSING_DEBUG_INFO)) {
		if (!prog->lang)
			drgn_program_set_language_from_main(prog);
		if (!prog->has_platform) {
			dwfl_getdwarf(prog->dbinfo.dwfl,
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

static struct drgn_error *get_prpsinfo_pid(struct drgn_program *prog,
					   const char *data, size_t size,
					   uint32_t *ret)
{
	bool is_64_bit, bswap;
	struct drgn_error *err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;

	size_t offset = is_64_bit ? 24 : 12;
	uint32_t pr_pid;
	if (size < offset + sizeof(pr_pid)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "NT_PRPSINFO is truncated");
	}
	memcpy(&pr_pid, data + offset, sizeof(pr_pid));
	if (bswap)
		pr_pid = bswap_32(pr_pid);
	*ret = pr_pid;
	return NULL;
}

static struct drgn_error *get_prpsinfo_fname(struct drgn_program *prog,
					   const char *data, size_t size,
					   const char **ret)
{
	bool is_64_bit;
	struct drgn_error *err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	size_t offset = is_64_bit ? 40 : 28;
	// pr_fname is defined as 16 byte buffer in elf_prpsinfo
	// https://github.com/torvalds/linux/blob/075dbe9f6e3c21596c5245826a4ee1f1c1676eb8/include/linux/elfcore.h#L73
#define PR_FNAME_LEN 16
	if (size < offset + PR_FNAME_LEN) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "NT_PRPSINFO is truncated");
	}
	// No need to make a copy: the data returned by elf_getdata_rawchunk()
	// is valid for the lifetime of the Elf handle, and prog->core is valid for
	// the lifetime of prog.
	const char *tmp = data + offset;
	size_t len = strnlen(tmp, PR_FNAME_LEN);
	if (len == PR_FNAME_LEN)
#undef PR_FNAME_LEN
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "pr_fname is not null terminated");
	*ret = tmp;
	return NULL;
}

struct drgn_error *drgn_thread_dup_internal(const struct drgn_thread *thread,
					    struct drgn_thread *ret)
{
	struct drgn_error *err = NULL;
	ret->prog = thread->prog;
	ret->tid = thread->tid;
	/* Don't need a deep copy here since the PRSTATUS notes are cached. */
	ret->prstatus = thread->prstatus;
	if (thread->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		drgn_object_init(&ret->object, thread->prog);
		err = drgn_object_copy(&ret->object, &thread->object);
		if (err)
			drgn_object_deinit(&ret->object);
	}
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_dup(const struct drgn_thread *thread, struct drgn_thread **ret)
{
	if (!(thread->prog->flags &
	      (DRGN_PROGRAM_IS_LINUX_KERNEL | DRGN_PROGRAM_IS_LIVE))) {
		/*
		 * For userspace core dumps, all threads are cached and
		 * immutable, so we can return the same handle.
		 */
		*ret = (struct drgn_thread *)thread;
		return NULL;
	}

	*ret = malloc(sizeof(**ret));
	if (!*ret)
		return &drgn_enomem;
	struct drgn_error *err = drgn_thread_dup_internal(thread, *ret);
	if (err)
		free(*ret);
	return err;
}

void drgn_thread_deinit(struct drgn_thread *thread) {
	if (thread->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		drgn_object_deinit(&thread->object);
}

LIBDRGN_PUBLIC void drgn_thread_destroy(struct drgn_thread *thread)
{
	if (thread) {
		drgn_thread_deinit(thread);
		if (thread->prog->flags &
		    (DRGN_PROGRAM_IS_LINUX_KERNEL | DRGN_PROGRAM_IS_LIVE))
			free(thread);
	}
}

struct drgn_error *drgn_program_cache_prstatus_entry(struct drgn_program *prog,
						     const char *data,
						     size_t size, uint32_t *ret)
{
	struct drgn_thread thread = {
		.prog = prog,
		.prstatus = { data, size },
	};
	struct drgn_error *err = get_prstatus_pid(prog, data, size,
						  &thread.tid);
	if (err)
		return err;
	*ret = thread.tid;
	if (drgn_thread_set_insert(&prog->thread_set, &thread, NULL) == -1)
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
drgn_program_cache_core_dump_notes(struct drgn_program *prog)
{
	struct drgn_error *err;
	size_t phnum, i;
	bool found_prstatus = false;
	uint32_t first_prstatus_tid;
	bool found_prpsinfo = false;
	uint32_t prpsinfo_pid;
	const char *prpsinfo_fname = NULL;

	if (prog->core_dump_notes_cached)
		return NULL;

	assert(!(prog->flags & DRGN_PROGRAM_IS_LIVE));

#ifdef WITH_LIBKDUMPFILE
	if (prog->kdump_ctx) {
		err = drgn_program_cache_kdump_notes(prog);
		if (err)
			goto err;
		goto out;
	}
#endif
	if (!prog->core) {
		err = NULL;
		goto out;
	}
	if (elf_getphdrnum(prog->core, &phnum) != 0) {
		err = drgn_error_libelf();
		goto err;
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
			goto err;
		}
		if (phdr->p_type != PT_NOTE)
			continue;

		data = elf_getdata_rawchunk(prog->core, phdr->p_offset,
					    phdr->p_filesz,
					    note_header_type(phdr->p_align));
		if (!data) {
			err = drgn_error_libelf();
			goto err;
		}

		offset = 0;
		while (offset < data->d_size &&
		       (offset = gelf_getnote(data, offset, &nhdr, &name_offset,
					      &desc_offset))) {
			const char *name;

			name = (char *)data->d_buf + name_offset;
			if (strncmp(name, "CORE", nhdr.n_namesz) != 0)
				continue;

			if (nhdr.n_type == NT_PRPSINFO) {
				err = get_prpsinfo_pid(prog,
						       (char *)data->d_buf + desc_offset,
						       nhdr.n_descsz,
						       &prpsinfo_pid);
				if (err)
					goto err;
				err = get_prpsinfo_fname(prog,
						       (char *)data->d_buf + desc_offset,
						       nhdr.n_descsz,
						       &prpsinfo_fname);
				if (err)
					goto err;
				found_prpsinfo = true;
			} else if (nhdr.n_type == NT_PRSTATUS) {
				uint32_t tid;
				err = drgn_program_cache_prstatus_entry(prog,
						(char *)data->d_buf + desc_offset,
						nhdr.n_descsz,
						&tid);
				if (err)
					goto err;
				/*
				 * The first PRSTATUS note is the crashed thread. See
				 * fs/binfmt_elf.c:fill_note_info in the Linux kernel
				 * and bfd/elf.c:elfcore_grok_prstatus in BFD.
				 */
				if (!found_prstatus) {
					found_prstatus = true;
					first_prstatus_tid = tid;
				}
			}
		}
	}

out:
	prog->core_dump_notes_cached = true;
	if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		if (found_prpsinfo) {
			struct drgn_thread_set_iterator it =
				drgn_thread_set_search(&prog->thread_set,
						       &prpsinfo_pid);
			/* If the PID isn't found, then this is NULL. */
			prog->main_thread = it.entry;
			prog->core_dump_fname_cached = prpsinfo_fname;
		}
		if (found_prstatus) {
			/*
			 * Now that thread_set won't be modified, look up the crashed
			 * thread entry.
			 */
			struct drgn_thread_set_iterator it =
				drgn_thread_set_search(&prog->thread_set,
						       &first_prstatus_tid);
			assert(it.entry);
			prog->crashed_thread = it.entry;
		}
	}
	return NULL;

err:
	drgn_thread_set_deinit(&prog->thread_set);
	drgn_thread_set_init(&prog->thread_set);
	return err;
}

static struct drgn_error *
drgn_thread_iterator_init_linux_kernel(struct drgn_thread_iterator *it)
{
	struct drgn_error *err = linux_helper_task_iterator_init(&it->task_iter,
								 it->prog);
	if (err)
		return err;
	drgn_object_init(&it->entry.object, it->prog);
	it->entry.prstatus = (struct nstring){};
	return NULL;
}

static struct drgn_error *
drgn_thread_iterator_init_userspace_live(struct drgn_thread_iterator *it)
{
#define FORMAT "/proc/%ld/task"
	char path[sizeof(FORMAT)
		- sizeof("%ld")
		+ max_decimal_length(long)
		+ 1];
	snprintf(path, sizeof(path), FORMAT, (long)it->prog->pid);
#undef FORMAT
	it->tasks_dir = opendir(path);
	if (!it->tasks_dir)
		return drgn_error_create_os("opendir", errno, path);
	it->entry.prog = it->prog;
	it->entry.prstatus = (struct nstring){};
	return NULL;
}

static struct drgn_error *
drgn_thread_iterator_init_userspace_core(struct drgn_thread_iterator *it)
{
	struct drgn_error *err = drgn_program_cache_core_dump_notes(it->prog);
	if (err)
		return err;
	it->iterator = drgn_thread_set_first(&it->prog->thread_set);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_iterator_create(struct drgn_program *prog,
			    struct drgn_thread_iterator **ret)
{
	struct drgn_error *err;

	*ret = malloc(sizeof(**ret));
	if (!*ret)
		return &drgn_enomem;
	(*ret)->prog = prog;
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		err = drgn_thread_iterator_init_linux_kernel(*ret);
	else if (prog->flags & DRGN_PROGRAM_IS_LIVE)
		err = drgn_thread_iterator_init_userspace_live(*ret);
	else
		err = drgn_thread_iterator_init_userspace_core(*ret);
	if (err)
		free(*ret);
	return err;
}

LIBDRGN_PUBLIC void
drgn_thread_iterator_destroy(struct drgn_thread_iterator *it)
{
	if (it) {
		if (it->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
			drgn_object_deinit(&it->entry.object);
			linux_helper_task_iterator_deinit(&it->task_iter);
		} else if (it->prog->flags & DRGN_PROGRAM_IS_LIVE) {
			closedir(it->tasks_dir);
		}
		free(it);
	}
}

static struct drgn_error *
drgn_thread_iterator_next_linux_kernel(struct drgn_thread_iterator *it,
				       struct drgn_thread **ret)
{
	struct drgn_error *err;
	err = linux_helper_task_iterator_next(&it->task_iter,
					      &it->entry.object);
	if (err == &drgn_stop) {
		*ret = NULL;
		return NULL;
	} else if (err) {
		return err;
	}
	it->entry.prog = drgn_object_program(&it->entry.object);
	union drgn_value tid_value;
	DRGN_OBJECT(tid, drgn_object_program(&it->entry.object));
	err = drgn_object_member_dereference(&tid, &it->entry.object, "pid");
	if (!err)
		err = drgn_object_read_integer(&tid, &tid_value);
	if (err)
		return err;
	it->entry.tid = tid_value.uvalue;
	*ret = &it->entry;
	return NULL;
}

static struct drgn_error *
drgn_thread_iterator_next_userspace_live(struct drgn_thread_iterator *it,
					 struct drgn_thread **ret)
{
	struct dirent *task;
	unsigned long tid;
	char *end;
	do {
		errno = 0;
		task = readdir(it->tasks_dir);
		if (!task) {
			if (errno) {
				return drgn_error_create_os("readdir", errno,
							    NULL);
			}
			*ret = NULL;
			return NULL;
		}

		errno = 0;
		tid = strtoul(task->d_name, &end, 10);
		/*
		 * Skip anything that isn't a number (like "." and "..") or
		 * overflows (which is impossible normally).
		 */
	} while (*end != '\0' || (tid == ULONG_MAX && errno == ERANGE));
	it->entry.tid = tid;
	*ret = &it->entry;
	return NULL;
}

static void
drgn_thread_iterator_next_userspace_core(struct drgn_thread_iterator *it,
					 struct drgn_thread **ret)
{
	*ret = it->iterator.entry;
	if (it->iterator.entry)
		it->iterator = drgn_thread_set_next(it->iterator);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_iterator_next(struct drgn_thread_iterator *it,
			  struct drgn_thread **ret)
{
	if (it->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		return drgn_thread_iterator_next_linux_kernel(it, ret);
	} else if (it->prog->flags & DRGN_PROGRAM_IS_LIVE) {
		return drgn_thread_iterator_next_userspace_live(it, ret);
	} else {
		drgn_thread_iterator_next_userspace_core(it, ret);
		return NULL;
	}
}

static struct drgn_error *
drgn_program_find_thread_linux_kernel(struct drgn_program *prog, uint32_t tid,
				      struct drgn_thread **ret)
{
	struct drgn_error *err;

	*ret = malloc(sizeof(**ret));
	if (!*ret)
		return &drgn_enomem;
	(*ret)->prog = prog;
	(*ret)->tid = tid;
	(*ret)->prstatus = (struct nstring){};

	struct drgn_object *object = &(*ret)->object;
	drgn_object_init(object, prog);
	err = drgn_program_find_object(prog, "init_pid_ns", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, object);
	if (err)
		goto err;
	err = drgn_object_address_of(object, object);
	if (err)
		goto err;
	err = linux_helper_find_task(object, object, tid);
	if (err)
		goto err;
	bool truthy;
	err = drgn_object_bool(object, &truthy);
	if (err)
		goto err;
	if (!truthy) {
		drgn_thread_destroy(*ret);
		*ret = NULL;
	}
	return NULL;

err:
	drgn_thread_destroy(*ret);
	return err;
}

static struct drgn_error *
drgn_program_find_thread_userspace_live(struct drgn_program *prog, uint32_t tid,
					struct drgn_thread **ret)
{
#define FORMAT "/proc/%ld/task/%" PRIu32
	char path[sizeof(FORMAT)
		- sizeof("%ld%" PRIu32)
		+ max_decimal_length(long)
		+ max_decimal_length(uint32_t)
		+ 1];
	snprintf(path, sizeof(path), FORMAT, (long)prog->pid, tid);
#undef FORMAT
	int r = access(path, F_OK);
	if (r == 0) {
		*ret = malloc(sizeof(**ret));
		if (!*ret)
			return &drgn_enomem;
		(*ret)->prog = prog;
		(*ret)->tid = tid;
		(*ret)->prstatus = (struct nstring){};
		return NULL;
	} else if (errno == ENOENT) {
		*ret = NULL;
		return NULL;
	} else {
		return drgn_error_create_os("access", errno, path);
	}
}

static struct drgn_error *
drgn_program_find_thread_userspace_core(struct drgn_program *prog, uint32_t tid,
					struct drgn_thread **ret)
{
	struct drgn_error *err = drgn_program_cache_core_dump_notes(prog);
	if (err)
		return err;
	*ret = drgn_thread_set_search(&prog->thread_set, &tid).entry;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_thread(struct drgn_program *prog, uint32_t tid,
			 struct drgn_thread **ret)
{
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return drgn_program_find_thread_linux_kernel(prog, tid, ret);
	else if (prog->flags & DRGN_PROGRAM_IS_LIVE)
		return drgn_program_find_thread_userspace_live(prog, tid, ret);
	else
		return drgn_program_find_thread_userspace_core(prog, tid, ret);
}

// Get the CPU that crashed in a Linux kernel core dump.
static struct drgn_error *
drgn_program_kernel_get_crashed_cpu(struct drgn_program *prog, uint64_t *ret)
{
	struct drgn_error *err;
	DRGN_OBJECT(cpu, prog);
	union drgn_value cpu_value;

	// Since Linux kernel commit 1717f2096b54 ("panic, x86: Fix re-entrance
	// problem due to panic on NMI") (in v4.5), the crashed CPU is stored in
	// an atomic_t panic_cpu on all architectures.
	err = drgn_program_find_object(prog, "panic_cpu", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &cpu);
	if (!err) {
		err = drgn_object_member(&cpu, &cpu, "counter");
		if (err)
			return err;
		err = drgn_object_read_integer(&cpu, &cpu_value);
		if (!err)
			*ret = cpu_value.uvalue;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		// On x86 and x86-64 only, the crashed CPU is also in an int
		// crashing_cpu. Use this as a fallback for kernels before
		// commit 1717f2096b54 ("panic, x86: Fix re-entrance problem due
		// to panic on NMI") (in v4.5).
		drgn_error_destroy(err);
		err = drgn_program_find_object(prog, "crashing_cpu", NULL,
					       DRGN_FIND_OBJECT_VARIABLE, &cpu);
		if (!err) {
			err = drgn_object_read_integer(&cpu, &cpu_value);
			if (err)
				return err;
			// Since Linux kernel commit 5bc329503e81 ("x86/mce:
			// Handle broadcasted MCE gracefully with kexec") (in
			// v4.12), crashing_cpu is defined in !SMP kernels, but
			// it's always -1.
			if (cpu_value.svalue == -1)
				*ret = 0;
			else
				*ret = cpu_value.uvalue;
		} else if (err->code == DRGN_ERROR_LOOKUP) {
			// Before Linux kernel commit 5bc329503e81 ("x86/mce:
			// Handle broadcasted MCE gracefully with kexec") (in
			// v4.12), crashing_cpu is only defined in SMP kernels.
			drgn_error_destroy(err);
			err = NULL;
			*ret = 0;
		}
	}
	return err;
}

static struct drgn_error *
drgn_program_find_thread_kernel_cpu_curr(struct drgn_program *prog,
					 uint64_t cpu,
					 struct drgn_thread **ret)
{
	struct drgn_error *err;
	struct drgn_thread *thread = malloc(sizeof(*thread));
	if (!thread)
		return &drgn_enomem;
	thread->prog = prog;

	DRGN_OBJECT(tmp, prog);
	drgn_object_init(&thread->object, prog);

	err = linux_helper_cpu_curr(&thread->object, cpu);
	if (err)
		goto out;

	err = drgn_object_member_dereference(&tmp, &thread->object, "pid");
	if (err)
		goto out;
	union drgn_value tid;
	err = drgn_object_read_integer(&tmp, &tid);
	if (err)
		goto out;
	thread->tid = tid.uvalue;
	thread->prstatus = (struct nstring){};

	*ret = thread;

out:
	if (err) {
		drgn_object_deinit(&thread->object);
		free(thread);
	}
	return err;
}

static struct drgn_error *
drgn_program_kernel_core_dump_cache_crashed_thread(struct drgn_program *prog)
{
	struct drgn_error *err;

	assert((prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
	       !(prog->flags & DRGN_PROGRAM_IS_LIVE));
	if (prog->crashed_thread)
		return NULL;

	uint64_t crashed_cpu;
	err = drgn_program_kernel_get_crashed_cpu(prog, &crashed_cpu);
	if (err)
		return err;

	err = drgn_program_find_thread_kernel_cpu_curr(prog, crashed_cpu,
						       &prog->crashed_thread);
	if (err) {
		prog->crashed_thread = NULL;
		return err;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_main_thread(struct drgn_program *prog, struct drgn_thread **ret)
{
	struct drgn_error *err;

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "main thread is not defined for the Linux kernel");
	}
	if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
		if (!prog->main_thread) {
			err = drgn_program_find_thread(prog, prog->pid,
						       &prog->main_thread);
			if (err) {
				prog->main_thread = NULL;
				return err;
			}
		}
	} else {
		err = drgn_program_cache_core_dump_notes(prog);
		if (err)
			return err;
	}
	if (!prog->main_thread) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "main thread not found");
	}
	*ret = prog->main_thread;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_crashed_thread(struct drgn_program *prog, struct drgn_thread **ret)
{
	struct drgn_error *err;

	if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "crashed thread is only defined for core dumps");
	}
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		err = drgn_program_kernel_core_dump_cache_crashed_thread(prog);
	else
		err = drgn_program_cache_core_dump_notes(prog);
	if (err)
		return err;
	if (!prog->crashed_thread) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "crashed thread not found");
	}
	*ret = prog->crashed_thread;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_object(struct drgn_thread *thread, const struct drgn_object **ret)
{
	if (!(thread->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "thread object is currently only defined for the Linux kernel");
	}
	*ret = &thread->object;
	return NULL;
}

static struct drgn_error *
drgn_thread_name_linux_kernel(struct drgn_thread *thread, char **ret)
{
	struct drgn_error *err;
	DRGN_OBJECT(comm, drgn_object_program(&thread->object));
	err = drgn_object_member_dereference(&comm, &thread->object, "comm");
	if (!err)
		err = drgn_object_read_c_string(&comm, ret);
	return err;
}

static struct drgn_error *
drgn_thread_name_userspace_live(struct drgn_thread *thread, char **ret)
{
#define FORMAT "/proc/%" PRIu32 "/comm"
	char path[sizeof(FORMAT)
		- sizeof("%" PRIu32)
		+ max_decimal_length(uint32_t)
		+ 1];
	snprintf(path, sizeof(path), FORMAT, thread->tid);
#undef FORMAT
	_cleanup_close_ int fd = open(path, O_RDONLY);
	if (fd < 0)
		return drgn_error_create_os("open", errno, path);
	// While userspace threads use 16 byte buffer, kernel threads use a 64 byte buffer
	// https://github.com/torvalds/linux/blob/075dbe9f6e3c21596c5245826a4ee1f1c1676eb8/fs/proc/array.c#L101
	char buf[64];
	ssize_t bytes_read = read_all(fd, buf, sizeof(buf));
	if (bytes_read < 0)
		return drgn_error_create_os("read", errno, path);

	if (bytes_read > 0 && buf[bytes_read - 1] == '\n')
		bytes_read--;
	char *tmp = strndup(buf, bytes_read);
	if (!tmp)
		return &drgn_enomem;
	*ret = tmp;
	return NULL;
}

static struct drgn_error *
drgn_thread_name_userspace_core(struct drgn_thread *thread, char **ret)
{
	struct drgn_error *err = drgn_program_cache_core_dump_notes(thread->prog);
	if (err)
		return err;
	// Core dumps only contain the main thread name so check if this is the main thread.
	// Otherwise, set ret to NULL which will return None in Python.
	bool is_main_thread = thread->prog->main_thread && thread->prog->main_thread->tid == thread->tid;
	if (is_main_thread && thread->prog->core_dump_fname_cached) {
		char *tmp = strdup(thread->prog->core_dump_fname_cached);
		if (!tmp)
			return &drgn_enomem;
		*ret = tmp;
	} else {
		*ret = NULL;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_name(struct drgn_thread *thread, char **ret)
{
	if (thread->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return drgn_thread_name_linux_kernel(thread, ret);
	else if (thread->prog->flags & DRGN_PROGRAM_IS_LIVE)
		return drgn_thread_name_userspace_live(thread, ret);
	else
		return drgn_thread_name_userspace_core(thread, ret);
}

struct drgn_error *drgn_program_find_prstatus(struct drgn_program *prog,
					      uint32_t tid, struct nstring *ret)
{
	struct drgn_error *err = drgn_program_cache_core_dump_notes(prog);
	if (err)
		return err;
	struct drgn_thread *thread =
		drgn_thread_set_search(&prog->thread_set, &tid).entry;
	if (!thread) {
		ret->str = NULL;
		ret->len = 0;
		return NULL;
	}
	*ret = thread->prstatus;
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

struct drgn_error *drgn_program_init_core_dump_fd(struct drgn_program *prog, int fd)
{
	struct drgn_error *err;

	err = drgn_program_set_core_dump_fd(prog, fd);
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
drgn_program_from_core_dump_fd(int fd, struct drgn_program **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog;

	prog = malloc(sizeof(*prog));
	if (!prog)
		return &drgn_enomem;

	drgn_program_init(prog, NULL);
	err = drgn_program_init_core_dump_fd(prog, fd);
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
	err = drgn_program_untagged_addr(prog, &address);
	if (err)
		return err;
	char *p = buf;
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

DEFINE_VECTOR(char_vector, char);

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_c_string(struct drgn_program *prog, uint64_t address,
			   bool physical, size_t max_size, char **ret)
{
	_cleanup_(char_vector_deinit) struct char_vector str = VECTOR_INIT;
	for (;;) {
		struct drgn_error *err = drgn_program_untagged_addr(prog, &address);
		if (err)
			return err;
		char *c = char_vector_append_entry(&str);
		if (!c)
			return &drgn_enomem;
		if (char_vector_size(&str) <= max_size) {
			err = drgn_memory_reader_read(&prog->reader, c, address,
						      1, physical);
			if (err)
				return err;
			if (!*c)
				break;
		} else {
			*c = '\0';
			break;
		}
		address++;
	}
	char_vector_shrink_to_fit(&str);
	char_vector_steal(&str, ret, NULL);
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
	struct drgn_error *err;

	if ((flags & ~DRGN_FIND_OBJECT_ANY) || !flags) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid find object flags");
	}
	if (ret && drgn_object_program(ret) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "object is from wrong program");
	}

	size_t name_len = strlen(name);
	drgn_handler_list_for_each_enabled(struct drgn_object_finder, finder,
					   &prog->object_finders) {
		err = finder->ops.find(name, name_len, filename, flags,
				       finder->arg, ret);
		if (err != &drgn_not_found)
			return err;
	}

	const char *kind_str;
	switch (flags) {
	case DRGN_FIND_OBJECT_CONSTANT:
		kind_str = "constant ";
		break;
	case DRGN_FIND_OBJECT_FUNCTION:
		kind_str = "function ";
		break;
	case DRGN_FIND_OBJECT_VARIABLE:
		kind_str = "variable ";
		break;
	default:
		kind_str = "";
		break;
	}
	if (filename) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s' in '%s'",
					 kind_str, name, filename);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s'", kind_str,
					 name);
	}
}

struct drgn_error *drgn_error_symbol_not_found(uint64_t address)
{
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "could not find symbol containing 0x%" PRIx64,
				 address);
}

static struct drgn_error *
drgn_program_symbols_search(struct drgn_program *prog, const char *name,
			    uint64_t addr, enum drgn_find_symbol_flags flags,
			    struct drgn_symbol_result_builder *builder)
{
	struct drgn_error *err = NULL;
	drgn_handler_list_for_each_enabled(struct drgn_symbol_finder, finder,
					   &prog->symbol_finders) {
		err = finder->ops.find(name, addr, flags, finder->arg, builder);
		if (err ||
		    ((flags & DRGN_FIND_SYMBOL_ONE)
		     && drgn_symbol_result_builder_count(builder) > 0))
			break;
	}
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbols_by_name(struct drgn_program *prog, const char *name,
				  struct drgn_symbol ***syms_ret,
				  size_t *count_ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = name ? DRGN_FIND_SYMBOL_NAME : 0;

	drgn_symbol_result_builder_init(&builder, false);
	struct drgn_error *err = drgn_program_symbols_search(prog, name, 0,
							     flags, &builder);
	if (err)
		drgn_symbol_result_builder_abort(&builder);
	else
		drgn_symbol_result_builder_array(&builder, syms_ret, count_ret);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbols_by_address(struct drgn_program *prog,
				     uint64_t address,
				     struct drgn_symbol ***syms_ret,
				     size_t *count_ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = DRGN_FIND_SYMBOL_ADDR;

	drgn_symbol_result_builder_init(&builder, false);
	struct drgn_error *err = drgn_program_symbols_search(prog, NULL, address,
							     flags, &builder);
	if (err)
		drgn_symbol_result_builder_abort(&builder);
	else
		drgn_symbol_result_builder_array(&builder, syms_ret, count_ret);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbol_by_name(struct drgn_program *prog,
				 const char *name, struct drgn_symbol **ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = DRGN_FIND_SYMBOL_NAME | DRGN_FIND_SYMBOL_ONE;

	drgn_symbol_result_builder_init(&builder, true);
	struct drgn_error *err = drgn_program_symbols_search(prog, name, 0,
							     flags, &builder);
	if (err) {
		drgn_symbol_result_builder_abort(&builder);
		return err;
	}

	if (!drgn_symbol_result_builder_count(&builder))
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find symbol with name '%s'", name);

	*ret = drgn_symbol_result_builder_single(&builder);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbol_by_address(struct drgn_program *prog, uint64_t address,
				    struct drgn_symbol **ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = DRGN_FIND_SYMBOL_ADDR | DRGN_FIND_SYMBOL_ONE;

	drgn_symbol_result_builder_init(&builder, true);
	struct drgn_error *err = drgn_program_symbols_search(prog, NULL, address,
							     flags, &builder);

	if (err) {
		drgn_symbol_result_builder_abort(&builder);
		return err;
	}

	if (!drgn_symbol_result_builder_count(&builder))
		return drgn_error_symbol_not_found(address);

	*ret = drgn_symbol_result_builder_single(&builder);
	return err;
}

struct drgn_error *
drgn_program_find_symbol_by_address_internal(struct drgn_program *prog,
					     uint64_t address,
					     struct drgn_symbol **ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = DRGN_FIND_SYMBOL_ADDR | DRGN_FIND_SYMBOL_ONE;

	drgn_symbol_result_builder_init(&builder, true);
	struct drgn_error *err = drgn_program_symbols_search(prog, NULL, address,
							     flags, &builder);
	if (err)
		drgn_symbol_result_builder_abort(&builder);
	else
		*ret = drgn_symbol_result_builder_single(&builder);
	return err;
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

LIBDRGN_PUBLIC void
drgn_program_set_blocking_callback(struct drgn_program *prog,
				   drgn_program_begin_blocking_fn *begin_callback,
				   drgn_program_end_blocking_fn *end_callback,
				   void *callback_arg)
{
	prog->begin_blocking_fn = begin_callback;
	prog->end_blocking_fn = end_callback;
	prog->blocking_arg = callback_arg;
}

LIBDRGN_PUBLIC void
drgn_program_get_blocking_callback(struct drgn_program *prog,
				   drgn_program_begin_blocking_fn **begin_callback_ret,
				   drgn_program_end_blocking_fn **end_callback_ret,
				   void **callback_arg_ret)
{
	*begin_callback_ret = prog->begin_blocking_fn;
	*end_callback_ret = prog->end_blocking_fn;
	*callback_arg_ret = prog->blocking_arg;
}

void *drgn_program_begin_blocking(struct drgn_program *prog)
{
	if (!prog->begin_blocking_fn)
		return NULL;
	return prog->begin_blocking_fn(prog, prog->blocking_arg);
}

void drgn_program_end_blocking(struct drgn_program *prog, void *state)
{
	if (prog->end_blocking_fn)
		prog->end_blocking_fn(prog, prog->blocking_arg, state);
}
