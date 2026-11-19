// Copyright (c) 2026, Oracle and/or its affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * Reading a live Linux kernel's memory with BPF.
 *
 * drgn normally reads a live kernel through /proc/kcore. Some kernels don't
 * have it (for example, Android GKI kernels and other kernels built without
 * CONFIG_PROC_KCORE). For those, we read memory with a tiny BPF program
 * instead:
 *
 * - The program is a BPF_PROG_TYPE_SYSCALL program (Linux 5.14+) that we run
 *   on demand with BPF_PROG_TEST_RUN. Its context holds an address and a
 *   length, and it copies that many bytes with bpf_probe_read_kernel() into
 *   the value of a one-element array map. bpf_probe_read_kernel() returns an
 *   error for a bad address instead of faulting.
 * - The map is created with BPF_F_MMAPABLE (Linux 5.5+) and mapped into our
 *   address space, so each read is a single bpf() system call.
 * - The program doesn't use any kernel types, so it needs neither BTF nor a
 *   compiler: it is a handful of instructions assembled below, and nothing
 *   beyond the bpf() system call is needed to load it.
 *
 * Kernel virtual addresses are read directly. Physical addresses are read
 * through the kernel's direct mapping, which is found with the architecture's
 * linux_kernel_live_direct_mapping_fallback() hook. User virtual addresses are
 * translated by drgn's page table walker, which reads physical memory.
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "array.h"
#include "cleanup.h"
#include "error.h"
#include "linux_kernel.h"
#include "log.h"
#include "memory_reader.h"
#include "minmax.h"
#include "platform.h"
#include "plugins.h"
#include "program.h"

#ifndef __NR_bpf
#if defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__powerpc64__)
#define __NR_bpf 361
#elif defined(__s390x__)
#define __NR_bpf 351
#endif
#endif

// The subset of the bpf(2) ABI used here, defined locally so that drgn
// builds against kernel headers too old to have it.
enum {
	DRGN_BPF_MAP_CREATE = 0,
	DRGN_BPF_PROG_LOAD = 5,
	DRGN_BPF_PROG_TEST_RUN = 10,
	DRGN_BPF_MAP_TYPE_ARRAY = 2,
	DRGN_BPF_PROG_TYPE_SYSCALL = 31,
	DRGN_BPF_F_SLEEPABLE = 1 << 4,
	DRGN_BPF_F_MMAPABLE = 1 << 10,
	DRGN_BPF_FUNC_probe_read_kernel = 113,
	DRGN_BPF_PSEUDO_MAP_VALUE = 2,
};

struct drgn_bpf_insn {
	uint8_t code;
	uint8_t dst_reg : 4;
	uint8_t src_reg : 4;
	int16_t off;
	int32_t imm;
};

union drgn_bpf_attr {
	struct {
		uint32_t map_type;
		uint32_t key_size;
		uint32_t value_size;
		uint32_t max_entries;
		uint32_t map_flags;
	} map_create;
	struct {
		uint32_t prog_type;
		uint32_t insn_cnt;
		uint64_t insns __attribute__((__aligned__(8)));
		uint64_t license __attribute__((__aligned__(8)));
		uint32_t log_level;
		uint32_t log_size;
		uint64_t log_buf __attribute__((__aligned__(8)));
		uint32_t kern_version;
		uint32_t prog_flags;
		char prog_name[16];
	} prog_load;
	struct {
		uint32_t prog_fd;
		uint32_t retval;
		uint32_t data_size_in;
		uint32_t data_size_out;
		uint64_t data_in __attribute__((__aligned__(8)));
		uint64_t data_out __attribute__((__aligned__(8)));
		uint32_t repeat;
		uint32_t duration;
		uint32_t ctx_size_in;
		uint32_t ctx_size_out;
		uint64_t ctx_in __attribute__((__aligned__(8)));
		uint64_t ctx_out __attribute__((__aligned__(8)));
	} test;
	char pad[128];
};

// Instruction classes, sizes, modes, and operations.
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_JMP 0x05
#define BPF_ALU64 0x07
#define BPF_W 0x00
#define BPF_DW 0x18
#define BPF_IMM 0x00
#define BPF_MEM 0x60
#define BPF_K 0x00
#define BPF_X 0x08
#define BPF_MOV 0xb0
#define BPF_JLE 0xb0
#define BPF_CALL 0x80
#define BPF_EXIT 0x90

// The most bytes that one program run reads.
#define BPF_READ_MAX 32768

// The program's context.
struct bpf_read_args {
	uint64_t address;
	uint32_t count;
	uint32_t pad;
};

struct drgn_bpf_memory {
	pthread_mutex_t lock;
	int map_fd;
	int prog_fd;
	// The map's value, mapped into our address space.
	void *buf;
	size_t page_size;
	// Virtual address of physical address 0 in the direct mapping.
	uint64_t direct_mapping;
};

static long bpf_syscall(int cmd, union drgn_bpf_attr *attr)
{
#ifdef __NR_bpf
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
#else
	errno = ENOSYS;
	return -1;
#endif
}

void drgn_bpf_memory_destroy(struct drgn_bpf_memory *mem)
{
	if (!mem)
		return;
	if (mem->buf)
		munmap(mem->buf, BPF_READ_MAX);
	if (mem->prog_fd >= 0)
		close(mem->prog_fd);
	if (mem->map_fd >= 0)
		close(mem->map_fd);
	pthread_mutex_destroy(&mem->lock);
	free(mem);
}

static struct drgn_error *bpf_os_error(const char *what, int errnum)
{
	if (errnum == EPERM || errnum == EACCES) {
		return drgn_error_create_os("reading kernel memory with BPF requires root, or CAP_BPF and CAP_PERFMON",
					    errnum, NULL);
	}
	return drgn_error_create_os(what, errnum, NULL);
}

static struct drgn_error *bpf_load_program(struct drgn_bpf_memory *mem)
{
	const struct drgn_bpf_insn insns[] = {
		// r6 = ctx
		{ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = 6, .src_reg = 1 },
		// r2 = ctx->count, at most BPF_READ_MAX
		{ .code = BPF_LDX | BPF_MEM | BPF_W, .dst_reg = 2, .src_reg = 6,
		  .off = offsetof(struct bpf_read_args, count) },
		{ .code = BPF_JMP | BPF_JLE | BPF_K, .dst_reg = 2, .off = 1,
		  .imm = BPF_READ_MAX },
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 2,
		  .imm = BPF_READ_MAX },
		// r3 = ctx->address
		{ .code = BPF_LDX | BPF_MEM | BPF_DW, .dst_reg = 3, .src_reg = 6,
		  .off = offsetof(struct bpf_read_args, address) },
		// r1 = &map value
		{ .code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = 1,
		  .src_reg = DRGN_BPF_PSEUDO_MAP_VALUE, .imm = mem->map_fd },
		{ .imm = 0 },
		// return bpf_probe_read_kernel(r1, r2, r3)
		{ .code = BPF_JMP | BPF_CALL,
		  .imm = DRGN_BPF_FUNC_probe_read_kernel },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	union drgn_bpf_attr attr = {
		.prog_load = {
			.prog_type = DRGN_BPF_PROG_TYPE_SYSCALL,
			.insn_cnt = array_size(insns),
			.insns = (uintptr_t)insns,
			// bpf_probe_read_kernel() is only available to
			// GPL-compatible programs. This program is part of
			// drgn, which is LGPL-2.1-or-later, and so it may be
			// used under the GPL.
			.license = (uintptr_t)"GPL",
			// Syscall programs must be sleepable.
			.prog_flags = DRGN_BPF_F_SLEEPABLE,
			.prog_name = "drgn_read",
		},
	};
	mem->prog_fd = bpf_syscall(DRGN_BPF_PROG_LOAD, &attr);
	if (mem->prog_fd >= 0)
		return NULL;
	int errnum = errno;
	if (errnum == EINVAL) {
		// Probably a kernel without BPF_PROG_TYPE_SYSCALL. Retry with
		// the verifier log, which explains other causes.
		_cleanup_free_ char *log = calloc(1, 4096);
		if (log) {
			attr.prog_load.log_level = 1;
			attr.prog_load.log_size = 4096;
			attr.prog_load.log_buf = (uintptr_t)log;
			int fd = bpf_syscall(DRGN_BPF_PROG_LOAD, &attr);
			if (fd >= 0) {
				mem->prog_fd = fd;
				return NULL;
			}
			if (log[0]) {
				return drgn_error_format(DRGN_ERROR_OTHER,
							 "could not load BPF program to read kernel memory (requires Linux 5.14 or newer): %s",
							 log);
			}
		}
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "could not load BPF program to read kernel memory (requires Linux 5.14 or newer)");
	}
	return bpf_os_error("BPF_PROG_LOAD", errnum);
}

static struct drgn_error *bpf_memory_create(struct drgn_bpf_memory **ret)
{
	struct drgn_error *err;

	struct drgn_bpf_memory *mem = calloc(1, sizeof(*mem));
	if (!mem)
		return &drgn_enomem;
	pthread_mutex_init(&mem->lock, NULL);
	mem->map_fd = mem->prog_fd = -1;
	long page_size = sysconf(_SC_PAGESIZE);
	mem->page_size = page_size > 0 ? page_size : 4096;

	union drgn_bpf_attr attr = {
		.map_create = {
			.map_type = DRGN_BPF_MAP_TYPE_ARRAY,
			.key_size = sizeof(uint32_t),
			.value_size = BPF_READ_MAX,
			.max_entries = 1,
			.map_flags = DRGN_BPF_F_MMAPABLE,
		},
	};
	mem->map_fd = bpf_syscall(DRGN_BPF_MAP_CREATE, &attr);
	if (mem->map_fd < 0) {
		err = bpf_os_error("BPF_MAP_CREATE", errno);
		goto err;
	}
	mem->buf = mmap(NULL, BPF_READ_MAX, PROT_READ, MAP_SHARED, mem->map_fd,
			0);
	if (mem->buf == MAP_FAILED) {
		mem->buf = NULL;
		err = drgn_error_create_os("mmap", errno, NULL);
		goto err;
	}
	err = bpf_load_program(mem);
	if (err)
		goto err;
	*ret = mem;
	return NULL;

err:
	drgn_bpf_memory_destroy(mem);
	return err;
}

// Read up to BPF_READ_MAX bytes with one program run. Returns 0, or -errno
// from bpf_probe_read_kernel(). The caller must hold mem->lock.
static struct drgn_error *bpf_read_once(struct drgn_bpf_memory *mem,
					void *buf, uint64_t address,
					size_t count, int *ret)
{
	struct bpf_read_args args = { .address = address, .count = count };
	union drgn_bpf_attr attr = {
		.test = {
			.prog_fd = mem->prog_fd,
			.ctx_in = (uintptr_t)&args,
			.ctx_size_in = sizeof(args),
		},
	};
	if (bpf_syscall(DRGN_BPF_PROG_TEST_RUN, &attr) < 0)
		return bpf_os_error("BPF_PROG_TEST_RUN", errno);
	*ret = (int32_t)attr.test.retval;
	if (*ret == 0)
		memcpy(buf, mem->buf, count);
	return NULL;
}

// Read count bytes at the kernel virtual address. On a fault, the error is
// for the first unreadable page, reported at fault_base + its offset, unless
// zero_fill is true, in which case unreadable pages read as zeroes.
static struct drgn_error *bpf_read(struct drgn_bpf_memory *mem, void *buf,
				   uint64_t address, size_t count,
				   uint64_t fault_base, bool zero_fill)
{
	struct drgn_error *err = NULL;
	char *p = buf;
	size_t done = 0;

	pthread_mutex_lock(&mem->lock);
	while (done < count) {
		size_t n = min(count - done, (size_t)BPF_READ_MAX);
		int ret;
		err = bpf_read_once(mem, p + done, address + done, n, &ret);
		if (err)
			goto out;
		if (ret) {
			// Find the first page that can't be read.
			while (n > 0) {
				uint64_t a = address + done;
				size_t m = min(n, mem->page_size
					       - (size_t)(a & (mem->page_size - 1)));
				err = bpf_read_once(mem, p + done, a, m, &ret);
				if (err)
					goto out;
				if (ret && zero_fill) {
					memset(p + done, 0, m);
				} else if (ret) {
					err = drgn_error_create_fault("could not read memory",
								      fault_base + done);
					goto out;
				}
				done += m;
				n -= m;
			}
			continue;
		}
		done += n;
	}
out:
	pthread_mutex_unlock(&mem->lock);
	return err;
}

static struct drgn_error *bpf_read_virtual(void *buf, uint64_t address,
					   size_t count, uint64_t offset,
					   void *arg, bool physical)
{
	return bpf_read(arg, buf, address, count, address, false);
}

static struct drgn_error *bpf_read_physical(void *buf, uint64_t address,
					    size_t count, uint64_t offset,
					    void *arg, bool physical)
{
	struct drgn_bpf_memory *mem = arg;
	return bpf_read(mem, buf, mem->direct_mapping + address, count,
			address, false);
}

// Some System RAM isn't in the direct mapping (e.g., memory reserved with
// "no-map"). Like /proc/kcore, read it as zeroes.
static struct drgn_error *bpf_read_physical_ram(void *buf, uint64_t address,
						size_t count, uint64_t offset,
						void *arg, bool physical)
{
	struct drgn_bpf_memory *mem = arg;
	return bpf_read(mem, buf, mem->direct_mapping + address, count,
			address, true);
}

// Read the VMCOREINFO text from the kernel's vmcoreinfo_data buffer.
static struct drgn_error *bpf_read_vmcoreinfo(struct drgn_program *prog)
{
	struct drgn_error *err;

	unsigned long data_address, size_address;
	err = proc_kallsyms_symbol_addr("vmcoreinfo_data", &data_address);
	if (err)
		return err;
	err = proc_kallsyms_symbol_addr("vmcoreinfo_size", &size_address);
	if (err)
		return err;

	uint64_t data, size;
	err = drgn_program_read_word(prog, data_address, false, &data);
	if (err)
		return err;
	err = drgn_program_read_word(prog, size_address, false, &size);
	if (err)
		return err;
	if (!data || !size || size > 1024 * 1024) {
		return drgn_error_create(DRGN_ERROR_BAD_DATA,
					 "VMCOREINFO is invalid");
	}

	_cleanup_free_ char *buf = malloc(size);
	if (!buf)
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, buf, data, size, false);
	if (err)
		return err;
	return drgn_program_parse_vmcoreinfo(prog, buf, size);
}

static struct drgn_error *bpf_add_physical_segment(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct drgn_bpf_memory *mem = prog->bpf_memory;

	uint64_t size;
	err = prog->platform.arch->linux_kernel_live_direct_mapping_fallback(prog,
									     &mem->direct_mapping,
									     &size);
	if (err)
		return err;
	drgn_log_debug(prog, "reading physical memory through the direct mapping at 0x%" PRIx64,
		       mem->direct_mapping);

	// Like /proc/kcore, only add the System RAM ranges, so that searches of
	// physical memory (which is how searches of all kernel memory are done)
	// don't run into holes. /proc/iomem shows the addresses as 0 without
	// CAP_SYS_ADMIN; then, add the whole direct mapping.
	bool found = false;
	_cleanup_fclose_ FILE *file = fopen("/proc/iomem", "r");
	if (file) {
		_cleanup_free_ char *line = NULL;
		size_t n = 0;
		while (getline(&line, &n, file) != -1) {
			uint64_t start, end;
			int name_offset;
			// Top-level ranges only; nested ones are indented.
			if (line[0] == ' '
			    || sscanf(line, "%" SCNx64 "-%" SCNx64 " : %n", &start,
				   &end, &name_offset) != 2
			    || strcmp(line + name_offset, "System RAM\n") != 0
			    || end < start || end == 0 || start >= size)
				continue;
			end = min(end, size - 1);
			err = drgn_program_add_memory_segment(prog, start,
							      end - start + 1,
							      bpf_read_physical_ram,
							      mem, true);
			if (err)
				return err;
			found = true;
		}
	}
	if (found)
		return NULL;
	drgn_log_debug(prog, "no System RAM ranges in /proc/iomem; adding the whole direct mapping");
	return drgn_program_add_memory_segment(prog, 0, size, bpf_read_physical,
					       mem, true);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_kernel_bpf(struct drgn_program *prog)
{
	struct drgn_error *err;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	bool had_platform = prog->has_platform;
	if (!had_platform)
		drgn_program_set_platform(prog, &drgn_host_platform);
	if (!(prog->platform.flags & DRGN_PLATFORM_IS_64_BIT)
	    || !prog->platform.arch->linux_kernel_live_direct_mapping_fallback) {
		err = drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED,
					"reading kernel memory with BPF is not supported on %s",
					prog->platform.arch->name);
		goto out_platform;
	}
	bool had_vmcoreinfo = prog->vmcoreinfo.raw;

	err = bpf_memory_create(&prog->bpf_memory);
	if (err)
		goto out_platform;

	// User addresses are translated with the page tables. Kernel addresses
	// are read directly; this segment takes precedence because it is added
	// later.
	if (prog->platform.arch->linux_kernel_pgtable_iterator_next) {
		err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
						      read_memory_via_pgtable,
						      prog, false);
		if (err)
			goto out_segments;
	}
	err = drgn_program_add_memory_segment(prog, UINT64_C(1) << 63,
					      UINT64_C(1) << 63,
					      bpf_read_virtual,
					      prog->bpf_memory, false);
	if (err)
		goto out_segments;

	bool have_physical = false;
	if (!had_vmcoreinfo) {
		err = bpf_read_vmcoreinfo(prog);
		if (err == &drgn_not_found) {
			// No vmcoreinfo_data symbol (e.g., the kernel was built
			// without CONFIG_KALLSYMS_ALL). Read the VMCOREINFO
			// note at the physical address in sysfs instead, if
			// the architecture can find the direct mapping without
			// it.
			err = bpf_add_physical_segment(prog);
			if (err)
				goto out_vmcoreinfo;
			have_physical = true;
			err = read_vmcoreinfo_fallback(prog);
		}
		if (err)
			goto out_vmcoreinfo;
	}
	if (!have_physical) {
		err = bpf_add_physical_segment(prog);
		if (err)
			goto out_vmcoreinfo;
	}

	prog->flags |= (DRGN_PROGRAM_IS_LINUX_KERNEL |
			DRGN_PROGRAM_IS_LIVE |
			DRGN_PROGRAM_IS_LOCAL);
	err = drgn_program_finish_set_kernel(prog);
	if (err) {
		prog->flags &= ~(DRGN_PROGRAM_IS_LINUX_KERNEL |
				 DRGN_PROGRAM_IS_LIVE |
				 DRGN_PROGRAM_IS_LOCAL);
		goto out_vmcoreinfo;
	}
	drgn_log_info(prog, "reading kernel memory with BPF");
	drgn_call_plugins_prog("drgn_prog_set", prog);
	return NULL;

out_vmcoreinfo:
	if (!had_vmcoreinfo) {
		free(prog->vmcoreinfo.raw);
		memset(&prog->vmcoreinfo, 0, sizeof(prog->vmcoreinfo));
	}
out_segments:
	drgn_memory_reader_clear(&prog->reader);
	drgn_bpf_memory_destroy(prog->bpf_memory);
	prog->bpf_memory = NULL;
out_platform:
	prog->has_platform = had_platform;
	return err;
}
