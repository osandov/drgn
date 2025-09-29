// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Program internals.
 *
 * See @ref ProgramInternals.
 */

#ifndef DRGN_PROGRAM_H
#define DRGN_PROGRAM_H

#include <libelf.h>
#include <sys/types.h>
#ifdef WITH_LIBKDUMPFILE
#include <libkdumpfile/kdumpfile.h>
#endif

#include "debug_info.h"
#include "drgn_internal.h"
#include "handler.h"
#include "hash_table.h"
#include "language.h"
#include "memory_reader.h"
#include "platform.h"
#include "pp.h"
#include "type.h"
#include "vector.h"

struct drgn_object_finder;
struct drgn_symbol;
struct drgn_symbol_finder;
struct drgn_type_finder;

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

struct drgn_thread {
	struct drgn_program *prog;
	uint32_t tid;
	struct nstring prstatus;
	struct drgn_object object;
};

DEFINE_VECTOR_TYPE(drgn_typep_vector, struct drgn_type *);
DEFINE_HASH_TABLE_TYPE(drgn_thread_set, struct drgn_thread);

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
	/* Path of core dump. */
	char *core_path;
	/* PID of live userspace program. */
	pid_t pid;
#ifdef WITH_LIBKDUMPFILE
	kdump_ctx_t *kdump_ctx;
#endif

	/*
	 * Types.
	 */
	/** Callbacks for finding types. */
	struct drgn_handler_list type_finders;
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
	struct drgn_handler_list object_finders;
	struct drgn_debug_info dbinfo;
	struct drgn_handler_list symbol_finders;

	/*
	 * Program information.
	 */
	/* Default language of the program. */
	const struct drgn_language *lang;
	struct drgn_platform platform;
	/**
	 * Whether we have tried determining the default language from "main"
	 * since the last time that debug info was added.
	 */
	bool tried_main_language;
	bool has_platform;
	enum drgn_program_flags flags;

	/*
	 * Threads/stack traces.
	 */
	/*
	 * Threads indexed by TID.
	 *
	 * For the Linux kernel, this is only used to index @c PRSTATUS notes.
	 * See @ref drgn_program_find_prstatus().
	 */
	struct drgn_thread_set thread_set;
	struct drgn_thread *main_thread;
	struct drgn_thread *crashed_thread;
	/*
	 * AArch64 instruction pointer authentication code mask, parsed either
	 * from NT_ARM_PAC_MASK or VMCOREINFO.
	 */
	uint64_t aarch64_insn_pac_mask;
	bool core_dump_threads_cached;

	union {
		/*
		 * Userspace-specific.
		 */
		struct {
			/** Cached `pr_fname` from `NT_PRPSINFO` note. */
			char *core_dump_fname_cached;
			/** Cache of important parts of auxiliary vector. */
			struct {
				uint64_t at_phdr;
				uint64_t at_phnum;
				uint64_t at_sysinfo_ehdr;
			} auxv;
			bool auxv_cached;
		};

		/*
		 * Linux kernel-specific.
		 */
		struct {
			/*
			 * Important parts of the VMCOREINFO note of a Linux
			 * kernel core.
			 */
			struct {
				/** `uname -r` */
				char osrelease[128];
				/** Build ID. */
				char build_id[128];
				/** `PAGE_SIZE` of the kernel. */
				uint64_t page_size;
				/**
				 * The offset from the compiled address of the
				 * kernel image to its actual address in memory.
				 *
				 * This is non-zero if kernel address space
				 * layout randomization (KASLR) is enabled.
				 * XXX unused
				 */
				uint64_t kaslr_offset;
				/** Kernel page table. */
				uint64_t swapper_pg_dir;
				/**
				 * Length of mem_section array (i.e.,
				 * `NR_SECTION_ROOTS`).
				 */
				uint64_t mem_section_length;
				/**
				 * `SECTION_SIZE_BITS` of the kernel. Initially
				 * 0 if not found in VMCOREINFO, but may be
				 * determined by other means and cached later.
				 */
				int section_size_bits;
				/**
				 * `MAX_PHYSMEM_BITS` of the kernel. Initially 0
				 * if not found in VMCOREINFO, but may be
				 * determined by other means and cached later.
				 */
				int max_physmem_bits;
				/** `VA_BITS` on AArch64. */
				uint64_t va_bits;
				/** `TCR_EL1_T1SZ` on AArch64. */
				uint64_t tcr_el1_t1sz;
				/** `phys_base` on x86_64 */
				uint64_t phys_base;
				/**
				 * Whether 5-level paging was enabled on x86-64.
				 */
				bool pgtable_l5_enabled;
				/** Whether LPAE was enabled on Arm. */
				bool arm_lpae;
				/** Whether `CRASHTIME` was in the VMCOREINFO. */
				bool have_crashtime;
				/** Whether `phys_base` was in the VMCOREINFO. */
				bool have_phys_base;
				/** Length of build ID. */
				unsigned int build_id_len;
				/**
				 * `PAGE_SHIFT` of the kernel (derived from
				 * `PAGE_SIZE`).
				 */
				int page_shift;

				/** The original vmcoreinfo data, to expose as an object */
				char *raw;
				size_t raw_size;
			} vmcoreinfo;
			/**
			 * Value of `THREAD_SIZE` in the kernel, or 0 if not
			 * cached yet.
			 */
			uint64_t thread_size_cached;
			/**
			 * Value of `SECTIONS_PER_ROOT` in the kernel, or 0 if
			 * not cached yet.
			 */
			uint64_t cached_sections_per_root;
			/*
			 * Difference between a virtual address in the direct
			 * mapping and the physical address it maps to.
			 */
			uint64_t direct_mapping_offset;
			/** Cached value of `MOD_TEXT` in the kernel. */
			uint64_t mod_text;
			/*
			 * Whether @ref drgn_program::direct_mapping_offset has
			 * been cached.
			 */
			bool direct_mapping_offset_cached;
			/**
			 * Whether @ref drgn_program::mod_text has been cached.
			 */
			bool mod_text_cached;
			/**
			 * The offset from the compiled address of the
			 * kernel image to its actual address in memory.
			 *
			 * This is non-zero if kernel address space
			 * layout randomization (KASLR) is enabled.
			 */
			uint64_t ktext_offset;
			/**
			 * ktext_mapped = &_text + ktext_offset
			 * where
			 *   &_text is ELF before loading
			 *   ktext_mapped is from vmcore's mapping probing
			 */
			uint64_t ktext_mapped;
			/*
			 * Whether we are currently in address translation. Used
			 * to prevent address translation from recursing.
			 */
			bool in_address_translation;
		};
	};
	/*
	 * Linux kernel-specific, but simplifies init/deinit to have them
	 * outside of the union above.
	 */
	/* Cached vmemmap. */
	struct drgn_object vmemmap;
	/* Page table iterator. */
	struct pgtable_iterator *pgtable_it;

	/*
	 * Logging.
	 */
	drgn_log_fn *log_fn;
	void *log_arg;
	FILE *progress_file;
	enum drgn_log_level log_level;
	bool default_progress_file;
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
 * Implement @ref drgn_program_from_core_dump_fd() on an initialized @ref
 * drgn_program.
 */
struct drgn_error *drgn_program_init_core_dump_fd(struct drgn_program *prog,
						  int fd);

/**
 * Implement @ref drgn_program_from_kernel() on an initialized @ref
 * drgn_program.
 */
struct drgn_error *drgn_program_init_kernel(struct drgn_program *prog);

/**
 * Implement @ref drgn_program_from_pid() on an initialized @ref drgn_program.
 */
struct drgn_error *drgn_program_init_pid(struct drgn_program *prog, pid_t pid);

struct drgn_error *drgn_program_cache_auxv(struct drgn_program *prog);

/**
 * Return whether a @ref drgn_program is a userspace process running on the
 * local machine.
 */
static inline bool
drgn_program_is_userspace_process(struct drgn_program *prog)
{
	return (prog->flags & (DRGN_PROGRAM_IS_LINUX_KERNEL
			       | DRGN_PROGRAM_IS_LIVE
			       | DRGN_PROGRAM_IS_LOCAL))
	       == (DRGN_PROGRAM_IS_LIVE | DRGN_PROGRAM_IS_LOCAL);
}

/** Return whether a @ref drgn_program is a core dump of a userspace process. */
static inline bool
drgn_program_is_userspace_core(struct drgn_program *prog)
{
	return (prog->flags &
		(DRGN_PROGRAM_IS_LINUX_KERNEL | DRGN_PROGRAM_IS_LIVE)) == 0
	       && prog->core;
}

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

static inline struct drgn_error *
drgn_program_untagged_addr(const struct drgn_program *prog, uint64_t *address)
{
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program address size is not known");
	}
	*address &= drgn_platform_address_mask(&prog->platform);
	if (prog->platform.arch->untagged_addr)
		*address = prog->platform.arch->untagged_addr(*address);
	return NULL;
}

struct drgn_error *drgn_thread_dup_internal(const struct drgn_thread *thread,
					    struct drgn_thread *ret);

void drgn_thread_deinit(struct drgn_thread *thread);

/**
 * Find the @c NT_PRSTATUS note with the given "PID".
 *
 * For userspace, the PID is the thread ID. For the kernel, it's complicated;
 * see drgn_get_initial_registers_from_kernel_core_dump().
 *
 * @param[out] ret Returned note data. If not found, <tt>ret->str</tt> is set to
 * @c NULL and <tt>ret->len</tt> is set to zero.
 */
struct drgn_error *drgn_program_find_prstatus(struct drgn_program *prog,
					      uint32_t tid,
					      struct nstring *ret);

/**
 * Cache the @c NT_PRSTATUS note provided by @p data in @p prog.
 *
 * @param[in] data The pointer to the note data.
 * @param[in] size Size of data in note.
 * @param[out] ret Thread ID from note.
 */
struct drgn_error *drgn_program_cache_prstatus_entry(struct drgn_program *prog,
						     const char *data,
						     size_t size,
						     uint32_t *ret);

/*
 * Like @ref drgn_program_find_symbol_by_address(), but returns @c NULL rather
 * than a lookup error if the symbol was not found.
 *
 * @param[in] address Address to search for.
 * @param [out] ret The symbol found by the lookup (if found)
 * @return @c NULL unless an error (unrelated to a lookup error) was encountered
 */
struct drgn_error *
drgn_program_find_symbol_by_address_internal(struct drgn_program *prog,
					     uint64_t address,
					     struct drgn_symbol **ret);

struct drgn_error *
drgn_program_register_type_finder_impl(struct drgn_program *prog,
				       struct drgn_type_finder *finder,
				       const char *name,
				       const struct drgn_type_finder_ops *ops,
				       void *arg, size_t enable_index);

struct drgn_error *
drgn_program_register_object_finder_impl(struct drgn_program *prog,
					 struct drgn_object_finder *finder,
					 const char *name,
					 const struct drgn_object_finder_ops *ops,
					 void *arg, size_t enable_index);

struct drgn_error *
drgn_program_register_symbol_finder_impl(struct drgn_program *prog,
					 struct drgn_symbol_finder *finder,
					 const char *name,
					 const struct drgn_symbol_finder_ops *ops,
					 void *arg, size_t enable_index);

/**
 * Call before a blocking (I/O or long-running) operation.
 *
 * Must be paired with @ref drgn_end_blocking().
 *
 * @return Opaque pointer to pass to @ref drgn_end_blocking().
 */
void *drgn_begin_blocking(void);

/**
 * Call after a blocking (I/O or long-running) operation.
 *
 * @param[in] state Return value of @ref drgn_begin_blocking().
 */
void drgn_end_blocking(void *state);

static inline void drgn_blocking_guard_cleanup(void **statep)
{
	drgn_end_blocking(*statep);
}

/**
 * Scope guard that wraps @ref drgn_begin_blocking() and @ref
 * drgn_end_blocking().
 */
#define drgn_blocking_guard()							\
	void *PP_UNIQUE(guard)							\
	__attribute__((__cleanup__(drgn_blocking_guard_cleanup), __unused__)) =	\
		drgn_begin_blocking()

/**
 * @}
 * @}
 */

#endif /* DRGN_PROGRAM_H */
