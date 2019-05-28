// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Program internals.
 *
 * See @ref ProgramInternals.
 */

#ifndef DRGN_PROGRAM_H
#define DRGN_PROGRAM_H

#include "memory_reader.h"
#include "symbol_index.h"
#include "type_index.h"

/**
 * @ingroup Internals
 *
 * @defgroup ProgramInternals Programs
 *
 * Program internals.
 *
 * @{
 */

/** The important parts of the VMCOREINFO note of a Linux kernel core. */
struct vmcoreinfo {
	/** <tt>uname -r</tt> */
	char osrelease[128];
	/** PAGE_SIZE of the kernel. */
	uint64_t page_size;
	/**
	 * The offset from the compiled address of the kernel image to its
	 * actual address in memory.
	 *
	 * This is non-zero if kernel address space layout randomization (KASLR)
	 * is enabled.
	 */
	uint64_t kaslr_offset;
};

/**
 * An ELF file which is mapped into a program.
 *
 * This is parsed from the @c NT_FILE note of a crash dump or
 * <tt>/proc/$pid/maps</tt> of a running program.
 */
struct file_mapping {
	/** Path of the file. */
	char *path;
	/** ELF handle. */
	Elf *elf;
	/** Starting virtual address in the program's address space. */
	uint64_t start;
	/**
	 * One byte after the last virtual address in the program's address
	 * space.
	 */
	uint64_t end;
	/** Starting offset in the file. */
	uint64_t file_offset;
};

struct drgn_dwarf_info_cache;

struct drgn_program {
	/** @privatesection */
	struct drgn_memory_reader reader;
	struct drgn_type_index tindex;
	struct drgn_symbol_index sindex;
	struct drgn_memory_file_segment *file_segments;
	size_t num_file_segments;
	struct file_mapping *mappings;
	size_t num_mappings;
	struct vmcoreinfo vmcoreinfo;
	struct drgn_dwarf_info_cache *dicache;
	int core_fd;
	enum drgn_program_flags flags;
	enum drgn_architecture_flags arch;
	bool added_vmcoreinfo_symbol_finder;
};

/** Initialize a @ref drgn_program. */
void drgn_program_init(struct drgn_program *prog,
		       enum drgn_architecture_flags arch);

/** Deinitialize a @ref drgn_program. */
void drgn_program_deinit(struct drgn_program *prog);

/**
 * Implement @ref drgn_program_from_core_dump() on an initialized @ref
 * drgn_program.
 */
struct drgn_error *drgn_program_init_core_dump(struct drgn_program *prog,
					       const char *path);

/**
 * Implement @ref drgn_program_from_kernel() on an initialized @ref
 * drgn_program.
 */
struct drgn_error *drgn_program_init_kernel(struct drgn_program *prog);

/**
 * Implement @ref drgn_program_from_pid() on an initialized @ref drgn_program.
 */
struct drgn_error *drgn_program_init_pid(struct drgn_program *prog, pid_t pid);

/** Return the maximum word value for a program. */
static inline uint64_t drgn_program_word_mask(struct drgn_program *prog)
{
	return prog->arch & DRGN_ARCH_IS_64_BIT ? UINT64_MAX : UINT32_MAX;
}

/** @} */

#endif /* DRGN_PROGRAM_H */
