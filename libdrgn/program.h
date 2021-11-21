// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

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
#include <libelf.h>
#include <sys/types.h>
#ifdef WITH_LIBKDUMPFILE
#include <libkdumpfile/kdumpfile.h>
#endif

#include "drgn.h"
#include "hash_table.h"
#include "language.h"
#include "memory_reader.h"
#include "object_index.h"
#include "platform.h"
#include "type.h"
#include "vector.h"

struct drgn_symbol;

/**
 * @defgroup Internals Internals
 *
 * Internal implementation
 *
 * @{
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
	/** Kernel page table. */
	uint64_t swapper_pg_dir;
	/** Whether 5-level paging was enabled. */
	bool pgtable_l5_enabled;
};

DEFINE_VECTOR_TYPE(drgn_typep_vector, struct drgn_type *)
DEFINE_VECTOR_TYPE(drgn_prstatus_vector, struct nstring)
DEFINE_HASH_MAP_TYPE(drgn_prstatus_map, uint32_t, struct nstring)

struct drgn_program {
	/** @privatesection */

	/*
	 * Memory/core dump.
	 */
	struct drgn_memory_reader reader;
	/* Elf core dump or /proc/pid/mem file segments. */
	struct drgn_memory_file_segment *file_segments;
	/* Elf core dump. Not valid for live programs or kdump files. */
	Elf *core;
	/* File descriptor for ELF core dump, kdump file, or /proc/pid/mem. */
	int core_fd;
	/* PID of live userspace program. */
	pid_t pid;
#ifdef WITH_LIBKDUMPFILE
	kdump_ctx_t *kdump_ctx;
#endif

	/*
	 * Types.
	 */
	/** Callbacks for finding types. */
	struct drgn_type_finder *type_finders;
	/** Void type for each language. */
	struct drgn_type void_types[DRGN_NUM_LANGUAGES];
	/** Cache of primitive types. */
	struct drgn_type *primitive_types[DRGN_PRIMITIVE_TYPE_NUM];
	/** Cache of deduplicated types. */
	struct drgn_dedupe_type_set dedupe_types;
	/**
	 * List of created types that are not deduplicated: types with non-empty
	 * lists of members, parameters, template parameters, or enumerators.
	 *
	 * Members, parameters, and template parameters contain lazily-evaluated
	 * objects, so they cannot be easily deduplicated.
	 *
	 * Enumerators could be deduplicated, but it's probably not worth the
	 * effort to hash and compare them.
	 */
	struct drgn_typep_vector created_types;
	/** Cache for @ref drgn_program_find_member(). */
	struct drgn_member_map members;
	/**
	 * Set of types which have been already cached in @ref
	 * drgn_program::members.
	 */
	struct drgn_type_set members_cached;

	/*
	 * Debugging information.
	 */
	struct drgn_object_index oindex;
	struct drgn_debug_info *dbinfo;

	/*
	 * Program information.
	 */
	/* Default language of the program. */
	const struct drgn_language *lang;
	struct drgn_platform platform;
	bool has_platform;
	enum drgn_program_flags flags;

	/*
	 * Stack traces.
	 */
	union {
		/*
		 * For the Linux kernel, PRSTATUS notes indexed by CPU. See
		 * drgn_get_initial_registers() for why we don't use the PID
		 * map.
		 */
		struct drgn_prstatus_vector prstatus_vector;
		/* For userspace programs, PRSTATUS notes indexed by PID. */
		struct drgn_prstatus_map prstatus_map;
	};
	bool prstatus_cached;
	bool prefer_orc_unwinder;

	/*
	 * Linux kernel-specific.
	 */
	struct vmcoreinfo vmcoreinfo;
	/* Cached PAGE_OFFSET. */
	struct drgn_object page_offset;
	/* Cached vmemmap. */
	struct drgn_object vmemmap;
	/* Page table iterator for linux_helper_read_vm(). */
	struct pgtable_iterator *pgtable_it;
	/*
	 * Whether @ref drgn_program::pgtable_it is currently being used. Used
	 * to prevent address translation from recursing.
	 */
	bool pgtable_it_in_use;
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

static inline struct drgn_error *
drgn_program_is_little_endian(struct drgn_program *prog, bool *ret)
{
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program byte order is not known");
	}
	*ret = drgn_platform_is_little_endian(&prog->platform);
	return NULL;
}

/**
 * Return whether a @ref drgn_program has a different endianness than the host
 * system.
 */
static inline struct drgn_error *
drgn_program_bswap(struct drgn_program *prog, bool *ret)
{
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program byte order is not known");
	}
	*ret = drgn_platform_bswap(&prog->platform);
	return NULL;
}

static inline struct drgn_error *
drgn_program_is_64_bit(struct drgn_program *prog, bool *ret)
{
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program word size is not known");
	}
	*ret = drgn_platform_is_64_bit(&prog->platform);
	return NULL;
}

static inline struct drgn_error *
drgn_program_address_size(struct drgn_program *prog, uint8_t *ret)
{
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program address size is not known");
	}
	*ret = drgn_platform_address_size(&prog->platform);
	return NULL;
}

static inline struct drgn_error *
drgn_program_address_mask(const struct drgn_program *prog, uint64_t *ret)
{
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program address size is not known");
	}
	*ret = drgn_platform_address_mask(&prog->platform);
	return NULL;
}

/**
 * Find the @c NT_PRSTATUS note for the given CPU.
 *
 * This is only valid for the Linux kernel.
 *
 * @param[out] ret Returned note data. If not found, <tt>ret->str</tt> is set to
 * @c NULL and <tt>ret->len</tt> is set to zero.
 * @param[out] tid_ret Returned thread ID of note.
 */
struct drgn_error *drgn_program_find_prstatus_by_cpu(struct drgn_program *prog,
						     uint32_t cpu,
						     struct nstring *ret,
						     uint32_t *tid_ret);

/**
 * Find the @c NT_PRSTATUS note for the given thread ID.
 *
 * This is only valid for userspace programs.
 *
 * @param[out] ret Returned note data. If not found, <tt>ret->str</tt> is set to
 * @c NULL and <tt>ret->len</tt> is set to zero.
 */
struct drgn_error *drgn_program_find_prstatus_by_tid(struct drgn_program *prog,
						     uint32_t tid,
						     struct nstring *ret);

/**
 * Cache the @c NT_PRSTATUS note provided by @p data in @p prog.
 *
 * @param[in] data The pointer to the note data.
 * @param[in] size Size of data in note.
 */
struct drgn_error *drgn_program_cache_prstatus_entry(struct drgn_program *prog,
                                                     const char *data,
						     size_t size);

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

/**
 * @}
 * @}
 */

#endif /* DRGN_PROGRAM_H */
