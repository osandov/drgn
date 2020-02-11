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

#include <elfutils/libdwfl.h>
#ifdef WITH_LIBKDUMPFILE
#include <libkdumpfile/kdumpfile.h>
#endif

#include "hash_table.h"
#include "memory_reader.h"
#include "object_index.h"
#include "platform.h"
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

DEFINE_HASH_MAP_TYPE(drgn_prstatus_map, uint32_t, struct string)

struct drgn_dwarf_info_cache;
struct drgn_dwarf_index;

struct drgn_program {
	/** @privatesection */
	struct drgn_memory_reader reader;
	struct drgn_type_index tindex;
	struct drgn_object_index oindex;
	struct drgn_memory_file_segment *file_segments;
	size_t num_file_segments;
	/* Default language of the program. */
	const struct drgn_language *lang;
	/*
	 * Valid iff <tt>flags & DRGN_PROGRAM_IS_LINUX_KERNEL</tt>.
	 */
	struct vmcoreinfo vmcoreinfo;
#ifdef WITH_LIBKDUMPFILE
	kdump_ctx_t *kdump_ctx;
#endif
	/*
	 * Valid iff <tt>!(flags & DRGN_PROGRAM_IS_LIVE)</tt>, unless the file
	 * was a kdump file.
	 */
	Elf *core;
	int core_fd;
	 /*
	  * Valid iff
	  * <tt>(flags & (DRGN_PROGRAM_IS_LINUX_KERNEL | DRGN_PROGRAM_IS_LIVE)) ==
	  * DRGN_PROGRAM_IS_LIVE</tt>.
	  */
	pid_t pid;
	struct drgn_dwarf_info_cache *_dicache;
	struct drgn_prstatus_map prstatus_cache;
	/* See @ref drgn_object_stack_trace(). */
	struct drgn_error *stack_trace_err;
	/* See @ref drgn_object_stack_trace_next_thread(). */
	const struct drgn_object *stack_trace_obj;
	uint32_t stack_trace_tid;
	enum drgn_program_flags flags;
	struct drgn_platform platform;
	bool has_platform;
	bool attached_dwfl_state;
	bool prstatus_cached;

	/* Cache for @ref linux_helper_task_state_to_char(). */
	char *task_state_chars;
	uint64_t task_report;
};

/** Initialize a @ref drgn_program. */
void drgn_program_init(struct drgn_program *prog,
		       const struct drgn_platform *platform);

/** Deinitialize a @ref drgn_program. */
void drgn_program_deinit(struct drgn_program *prog);

/**
 * Set the @ref drgn_platform of a @ref drgn_program if it hasn't been set
 * yet.
 */
void drgn_program_set_platform(struct drgn_program *prog,
			       const struct drgn_platform *platform);

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

static inline bool drgn_program_is_little_endian(struct drgn_program *prog)
{
	assert(prog->has_platform);
	return prog->platform.flags & DRGN_PLATFORM_IS_LITTLE_ENDIAN;
}

static inline bool drgn_program_is_64_bit(struct drgn_program *prog)
{
	assert(prog->has_platform);
	return prog->platform.flags & DRGN_PLATFORM_IS_64_BIT;
}

struct drgn_error *drgn_program_get_dwfl(struct drgn_program *prog, Dwfl **ret);

/**
 * Find the @c NT_PRSTATUS note for the given thread ID.
 *
 * This assumes that <tt>prog->core</tt> is not @c NULL.
 *
 * @param[out] ret Returned note data. If not found, <tt>ret->str</tt> is set to
 * @c NULL and <tt>ret->len</tt> is set to zero.
 */
struct drgn_error *drgn_program_find_prstatus(struct drgn_program *prog,
					      uint32_t tid, struct string *ret);

/**
 * Cache the @c NT_PRSTATUS note provided by @p data in @p prog.
 *
 * @param[in] data The pointer to the note data.
 * @param[in] size Size of data in note.
 */
struct drgn_error *drgn_program_cache_prstatus_entry(struct drgn_program *prog,
                                                     char *data, size_t size);

/*
 * Like @ref drgn_program_find_symbol_by_address(), but @p ret is already
 * allocated, we may already know the module, and doesn't return a @ref
 * drgn_error.
 *
 * @param[in] module Module containing the address. May be @c NULL, in which
 * case this will look it up.
 * @return Whether the symbol was found.
 */
bool drgn_program_find_symbol_by_address_internal(struct drgn_program *prog,
						  uint64_t address,
						  Dwfl_Module *module,
						  struct drgn_symbol *ret);

/** @} */

#endif /* DRGN_PROGRAM_H */
