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

#include "hash_table.h"
#include "memory_reader.h"
#include "object_index.h"
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

/** <tt>(type, member name)</tt> pair. */
struct drgn_member_key {
	struct drgn_type *type;
	const char *name;
	size_t name_len;
};

/** Type, offset, and bit field size of a type member. */
struct drgn_member_value {
	struct drgn_lazy_type *type;
	uint64_t bit_offset, bit_field_size;
};

#ifdef DOXYGEN
/**
 * @struct drgn_member_map
 *
 * Map of compound type members.
 *
 * The key is a @ref drgn_member_key, and the value is a @ref drgn_member_value.
 *
 * @struct drgn_type_set
 *
 * Set of types compared by address.
 */
#else
DEFINE_HASH_MAP_TYPES(drgn_member_map, struct drgn_member_key,
		      struct drgn_member_value)
DEFINE_HASH_SET_TYPES(drgn_type_set, struct drgn_type *)
#endif

/** The important parts of the VMCOREINFO note of a Linux kernel core. */
struct vmcoreinfo {
	/** <tt>uname -r</tt> */
	char osrelease[128];
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

struct drgn_program {
	/** @privatesection */
	struct drgn_memory_reader *reader;
	struct drgn_type_index *tindex;
	struct drgn_object_index *oindex;
	/** Cache for @ref drgn_program_find_member(). */
	struct drgn_member_map members;
	/**
	 * Set of types which have been already cached in @ref
	 * drgn_program::members.
	 */
	struct drgn_type_set members_cached;
	union {
		struct vmcoreinfo vmcoreinfo;
		struct {
			struct file_mapping *mappings;
			size_t num_mappings;
		};
	};
	/** Destructor. See @ref drgn_program_init(). */
	void (*deinit_fn)(struct drgn_program *);
	enum drgn_program_flags flags;
};

/**
 * Initialize the common part of a @ref drgn_program.
 *
 * This should only be called by @ref drgn_program initializers.
 *
 * @param[in] prog Program to initialize.
 * @param[in] reader Memory reader to use.
 * @param[in] tindex Type index to use.
 * @param[in] oindex Object index to use.
 * @param[in] deinit_fn Destructor called by @ref drgn_program_deinit() before
 * anything else is deinitialized.
 */
void drgn_program_init(struct drgn_program *prog,
		       struct drgn_memory_reader *reader,
		       struct drgn_type_index *tindex,
		       struct drgn_object_index *oindex,
		       void (*deinit_fn)(struct drgn_program *));

/**
 * Implement @ref drgn_program_from_core_dump() on an allocated @ref
 * drgn_program.
 */
struct drgn_error *drgn_program_init_core_dump(struct drgn_program *prog,
					       const char *path, bool verbose);

/**
 * Implement @ref drgn_program_from_kernel() on an allocated @ref drgn_program.
 */
struct drgn_error *drgn_program_init_kernel(struct drgn_program *prog,
					    bool verbose);

/**
 * Implement @ref drgn_program_from_pid() on an allocated @ref drgn_program.
 */
struct drgn_error *drgn_program_init_pid(struct drgn_program *prog, pid_t pid);

/**
 * Initialize a @ref drgn_program from manually-created memory segments, types,
 * and objects.
 *
 * This is mostly useful for testing.
 *
 * @param[in] prog Program to initialize.
 * @param[in] word_size See @ref drgn_program_word_size().
 * @param[in] little_endian See @ref drgn_program_is_little_endian().
 * @param[in] segments See @ref drgn_mock_memory_reader_create().
 * @param[in] num_segments See @ref drgn_mock_memory_reader_create().
 * @param[in] types See @ref drgn_mock_type_index_create().
 * @param[in] num_types See @ref drgn_mock_type_index_create().
 * @param[in] objects See @ref drgn_mock_object_index_create().
 * @param[in] num_objects See @ref drgn_mock_object_index_create().
 * @param[in] deinit_fn See @ref drgn_program_init().
 */
struct drgn_error *
drgn_program_init_mock(struct drgn_program *prog, uint8_t word_size,
		       bool little_endian,
		       struct drgn_mock_memory_segment *segments,
		       size_t num_segments, struct drgn_mock_type *types,
		       size_t num_types, struct drgn_mock_object *objects,
		       size_t num_objects,
		       void (*deinit_fn)(struct drgn_program *));

/**
 * Deinitialize a @ref drgn_program.
 *
 * This should only be used if the program was created directly with
 * <tt>drgn_program_init_*</tt>. If the program was created with
 * <tt>drgn_program_from_*</tt>, this shouldn't be used, as it is called by @ref
 * drgn_program_destroy().
 *
 * @param[in] prog Program to deinitialize.
 */
void drgn_program_deinit(struct drgn_program *prog);

/** Return the maximum word value for a program. */
static inline uint64_t drgn_program_word_mask(struct drgn_program *prog)
{
	return drgn_program_word_size(prog) == 8 ? UINT64_MAX : UINT32_MAX;
}

/**
 * Find the type, offset, and bit field size of a type member.
 *
 * This matches the members of the type itself as well as the members of any
 * unnamed members of the type.
 *
 * This caches all members of @p type for subsequent calls. Therefore, @p type
 * must remain valid until @p prog is destroyed.
 *
 * @param[in] prog Program containing the type.
 * @param[in] type Compound type to search in.
 * @param[in] member_name Name of member.
 * @param[in] member_name_len Length of @p member_name
 * @param[out] ret Returned member information.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_find_member(struct drgn_program *prog,
					    struct drgn_type *type,
					    const char *member_name,
					    size_t member_name_len,
					    struct drgn_member_value **ret);

/** @} */

#endif /* DRGN_PROGRAM_H */
