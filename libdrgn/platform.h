// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Platform internals
 *
 * See @ref PlatformInternals.
 */

#ifndef DRGN_PLATFORM_H
#define DRGN_PLATFORM_H

#include <gelf.h>
#include <inttypes.h>

#include "cfi.h"
#include "drgn.h"
#include "util.h"

struct drgn_orc_entry;
struct drgn_register_state;

/**
 * @ingroup Internals
 *
 * @defgroup PlatformInternals Platforms
 *
 * Platform internals.
 *
 * drgn's external representation of a platform is @ref drgn_platform.
 * Internally, architecture-specific handling is mainly in @ref
 * drgn_architecture_info. See @ref drgn_architecture_info for instructions on
 * adding support for a new architecture.
 *
 * @{
 */

struct drgn_register {
	/** Human-readable names of this register. */
	const char * const *names;
	/** Number of names in @ref names. */
	size_t num_names;
	/** Internal register number. */
	drgn_register_number regno;
};

/** Offset and size of a register in @ref drgn_register_state::buf. */
struct drgn_register_layout {
	uint32_t offset;
	uint32_t size;
};

// This is an ugly layering violation needed for DW_CFA_AARCH64_negate_ra_state.
// We enforce that it stays up to date with a static_assert() in arch_aarch64.c.
#define DRGN_AARCH64_RA_SIGN_STATE_REGNO 0

/** ELF section to apply relocations to. */
struct drgn_relocating_section {
	char *buf;
	size_t buf_size;
	uint64_t addr;
	bool bswap;
};

extern struct drgn_error drgn_invalid_relocation_offset;

#ifdef DOXYGEN
/**
 * Apply an ELF relocation as:
 *
 * - `*dst = addend + *r_addend` if `r_addend` is not `NULL` (for `ElfN_Rela`)
 * - `*dst += addend` if `r_addend` is `NULL` (for `ElfN_Rel`)
 *
 * Where `dst = (uintN_t *)(relocating->buf + r_offset)`.
 *
 * This checks bounds and handles unaligned destinations and byte swapping. It
 * does not check for overflow.
 *
 * This is defined for N of 8, 16, 32, and 64.
 */
struct drgn_error *
drgn_reloc_addN(const struct drgn_relocating_section *relocating,
		uint64_t r_offset, const int64_t *r_addend, uintN_t addend);
#endif

struct drgn_error *
drgn_reloc_add64(const struct drgn_relocating_section *relocating,
		 uint64_t r_offset, const int64_t *r_addend, uint64_t addend);
struct drgn_error *
drgn_reloc_add32(const struct drgn_relocating_section *relocating,
		 uint64_t r_offset, const int64_t *r_addend, uint32_t addend);
struct drgn_error *
drgn_reloc_add16(const struct drgn_relocating_section *relocating,
		 uint64_t r_offset, const int64_t *r_addend, uint16_t addend);
struct drgn_error *
drgn_reloc_add8(const struct drgn_relocating_section *relocating,
		uint64_t r_offset, const int64_t *r_addend, uint8_t addend);

/** Create an error for an unknown ELF relocation type. */
#define DRGN_UNKNOWN_RELOCATION_TYPE(r_type)				\
	drgn_error_format(DRGN_ERROR_OTHER,				\
			  "unknown relocation type %" PRIu32 " in %s; "	\
			  "please report this to %s",			\
			  (r_type), __func__, PACKAGE_BUGREPORT)

/**
 * Apply an ELF relocation. If @p r_addend is `NULL`, then this is an `ElfN_Rel`
 * relocation. Otherwise, this is an `ElfN_Rela` relocation.
 */
typedef struct drgn_error *
apply_elf_reloc_fn(const struct drgn_relocating_section *relocating,
		   uint64_t r_offset, uint32_t r_type, const int64_t *r_addend,
		   uint64_t sym_value);

/** Page table iterator. */
struct pgtable_iterator {
	/** Address of the top-level page table to iterate. */
	uint64_t pgtable;
	/** Current virtual address to translate. */
	uint64_t virt_addr;
};

/**
 * Translate the current virtual address from a page table iterator.
 *
 * Abstractly, a virtual address lies in a range of addresses in the address
 * space. A range may be a mapped page, a page table gap, or a range of invalid
 * addresses (e.g., non-canonical addresses on x86-64). This finds the range
 * containing the current virtual address (`it->virt_addr`), returns the first
 * virtual address of that range and the physical address it maps to (if any),
 * and updates `it->virt_addr` to the end of the range.
 *
 * This does not merge contiguous ranges. For example, if two adjacent mapped
 * pages have adjacent physical addresses, this returns each page separately.
 * This makes it possible to distinguish between contiguous pages and "huge
 * pages" on architectures that support different page sizes. Similarly, if two
 * adjacent entries at level 2 of the page table are empty, this returns each
 * gap separately.
 *
 * @param[in] it Iterator.
 * @param[out] virt_addr_ret Returned first virtual address in the range
 * containing the current virtual address.
 * @param[out] phys_addr_ret Returned physical address that @p virt_addr_ret
 * maps to, or @c UINT64_MAX if it is not mapped.
 */
typedef struct drgn_error *
(pgtable_iterator_next_fn)(struct drgn_program *prog,
			   struct pgtable_iterator *it, uint64_t *virt_addr_ret,
			   uint64_t *phys_addr_ret);

/**
 * Architecture-specific information and callbacks.
 *
 * To add the bare minimum support for recognizing a new architecture:
 *
 * - Add a `DRGN_ARCH_FOO` enumerator to @ref drgn_architecture.
 * - Add the constant to `class Architecture` in `_drgn.pyi`.
 * - Create a new `libdrgn/arch_foo.c` file and add it to `libdrgn/Makefile.am`.
 * - Define `struct drgn_architecture_info arch_info_foo` in
 *   `libdrgn/arch_foo.c` with the following members:
 *     - @ref name
 *     - @ref arch
 *     - @ref default_flags
 *     - @ref register_by_name
 * - Add an `extern` declaration of `arch_info_foo` to `libdrgn/platform.h`.
 * - Handle the architecture in @ref drgn_platform_from_kdump(), @ref
 *   drgn_host_platform, @ref drgn_platform_create(), and @ref
 *   drgn_platform_from_elf().
 *
 * To support Linux kernel loadable modules:
 *
 * - Define @ref apply_elf_reloc.
 *
 * To support stack unwinding:
 *
 * - Create a new `libdrgn/arch_foo_defs.py` file. See
 *   `libdrgn/build-aux/gen_arch_inc_strswitch.py`.
 * - Add `#include "arch_foo_defs.inc"` to `libdrgn/arch_foo.c`.
 * - Add `DRGN_ARCHITECTURE_REGISTERS` to `arch_info_foo` (and remove @ref
 *   register_by_name).
 * - Define the following @ref drgn_architecture_info members:
 *     - @ref default_dwarf_cfi_row (use @ref DRGN_CFI_ROW)
 *     - @ref fallback_unwind
 *     - @ref pt_regs_get_initial_registers
 *     - @ref prstatus_get_initial_registers
 *     - @ref linux_kernel_get_initial_registers
 *     - @ref demangle_cfi_registers (only if needed)
 *
 * To support virtual address translation:
 *
 * - Define the @ref drgn_architecture_info page table iterator members:
 *   - @ref linux_kernel_pgtable_iterator_create
 *   - @ref linux_kernel_pgtable_iterator_destroy
 *   - @ref linux_kernel_pgtable_iterator_init
 *   - @ref linux_kernel_pgtable_iterator_next
 *
 * This is an example of how the page table iterator members may be used
 * (ignoring error handling):
 *
 * ```
 * // Create the iterator.
 * struct pgtable_iterator *it;
 * arch->linux_kernel_pgtable_iterator_create(prog, &it);
 *
 * // Initialize the iterator to translate virtual address 0x80000000 using
 * // the page table "pgtable".
 * it->pgtable = pgtable;
 * it->virt_addr = 0x80000000;
 * arch->linux_kernel_pgtable_iterator_init(prog, it);
 * // Iterate up to virtual address 0x90000000.
 * while (it->virt_addr < 0x90000000) {
 *         uint64_t virt_addr, phys_addr;
 *         arch->linux_kernel_pgtable_iterator_next(prog, it, &virt_addr,
 *                                                  &phys_addr);
 *         if (phys_addr == UINT64_MAX) {
 *                 printf("Virtual address range 0x%" PRIx64 "-0x%" PRIx64
 *                        " is not mapped\n",
 *                        virt_addr, it->virt_addr);
 *         } else {
 *                 printf("Virtual address range 0x%" PRIx64 "-0x%" PRIx64
 *                        " maps to physical address 0x%" PRIx64 "\n",
 *                        virt_addr, phys_addr);
 *         }
 * }
 *
 * // Reuse the iterator to translate a different address using a different page
 * // table.
 * it->pgtable = another_pgtable;
 * it->virt_addr = 0x11110000;
 * uint64_t virt_addr, phys_addr;
 * arch->linux_kernel_pgtable_iterator_next(prog, it, &virt_addr, &phys_addr);
 * if (phys_addr != UINT64_MAX) {
 *         printf("Virtual address 0x11110000 maps to physical address 0x%" PRIx64 "\n",
 *                phys_addr + (0x11110000 - virt_addr));
 * }
 *
 * // Free the iterator now that we're done with it.
 * arch->linux_kernel_pgtable_iterator_destroy(prog, &it);
 * ```
 */
struct drgn_architecture_info {
	/** Human-readable name of this architecture. */
	const char *name;
	/** Architecture identifier. */
	enum drgn_architecture arch;
	/**
	 * Flags to set for the platform if we're not getting them from
	 * elsewhere (like from an ELF file).
	 */
	enum drgn_platform_flags default_flags;
	/**
	 * Registers visible to the public API.
	 *
	 * This is set by `DRGN_ARCHITECTURE_REGISTERS`.
	 */
	const struct drgn_register *registers;
	/**
	 * Number of registers in @ref registers.
	 *
	 * This is set by `DRGN_ARCHITECTURE_REGISTERS`.
	 */
	size_t num_registers;
	/**
	 * Internal register number of stack pointer.
	 *
	 * This is set by `DRGN_ARCHITECTURE_REGISTERS`.
	 */
	drgn_register_number stack_pointer_regno;
	/**
	 * Return the API-visible register with the given name, or @c NULL if it
	 * is not recognized.
	 *
	 * This is set by `DRGN_ARCHITECTURE_REGISTERS`. It cannot be `NULL`.
	 * Set it to @ref drgn_register_by_name_unknown if not using
	 * `DRGN_ARCHITECTURE_REGISTERS`.
	 */
	const struct drgn_register *(*register_by_name)(const char *name);
	/**
	 * Internal register layouts indexed by internal register number.
	 *
	 * This is set by `DRGN_ARCHITECTURE_REGISTERS`.
	 */
	const struct drgn_register_layout *register_layout;
	/**
	 * Return the internal register number for the given DWARF register
	 * number, or @ref DRGN_REGISTER_NUMBER_UNKNOWN if it is not recognized.
	 *
	 * This is set by `DRGN_ARCHITECTURE_REGISTERS`.
	 */
	drgn_register_number (*dwarf_regno_to_internal)(uint64_t);
	/** CFI row containing default rules for DWARF CFI. */
	const struct drgn_cfi_row *default_dwarf_cfi_row;
	/**
	 * Translate an ORC entry to a @ref drgn_cfi_row.
	 *
	 * This should be `NULL` if the architecture doesn't use ORC.
	 */
	struct drgn_error *(*orc_to_cfi)(const struct drgn_orc_entry *,
					 struct drgn_cfi_row **, bool *,
					 drgn_register_number *);
	/**
	 * Replace mangled registers unwound by CFI with their actual values.
	 *
	 * This should be `NULL` if not needed.
	 */
	void (*demangle_cfi_registers)(struct drgn_program *,
				       struct drgn_register_state *);
	/**
	 * Try to unwind a stack frame if CFI wasn't found. Returns &@ref
	 * drgn_stop if we couldn't.
	 *
	 * This typically uses something like frame pointers. If this has to
	 * read memory, translate @ref DRGN_ERROR_FAULT errors to &@ref
	 * drgn_stop.
	 */
	struct drgn_error *(*fallback_unwind)(struct drgn_program *,
					      struct drgn_register_state *,
					      struct drgn_register_state **);
	/**
	 * Create a @ref drgn_register_state from a Linux `struct pt_regs`.
	 *
	 * This should check that the object is sufficiently large with @ref
	 * drgn_object_size(), call @ref drgn_register_state_create() with
	 * `interrupted = true`, and initialize it from the contents of @ref
	 * drgn_object_buffer().
	 *
	 * @param[in] obj `struct pt_regs` as a value buffer object.
	 * @param[out] ret Returned registers.
	 */
	struct drgn_error *(*pt_regs_get_initial_registers)(const struct drgn_object *obj,
							    struct drgn_register_state **ret);
	/**
	 * Create a @ref drgn_register_state from the contents of an ELF
	 * `NT_PRSTATUS` note.
	 *
	 * This should check that @p size is sufficiently large, call @ref
	 * drgn_register_state_create() with `interrupted = true`, and
	 * initialize it from @p prstatus.
	 *
	 * Refer to `struct elf_prstatus_common` in the Linux kernel source for
	 * the format, and in particular, the `elf_gregset_t pr_reg` member.
	 * `elf_gregset_t` has an architecture-specific layout; on many
	 * architectures, it is identical to or a prefix of `struct pt_regs`.
	 * `pr_reg` is typically at offset 112 on 64-bit platforms and 72 on
	 * 32-bit platforms.
	 *
	 * @param[in] prstatus Buffer of `NT_PRSTATUS` contents.
	 * @param[in] size Size of @p prstatus in bytes.
	 * @param[out] ret Returned registers.
	 */
	struct drgn_error *(*prstatus_get_initial_registers)(struct drgn_program *prog,
							     const void *prstatus,
							     size_t size,
							     struct drgn_register_state **ret);
	/**
	 * Create a @ref drgn_register_state from the `struct task_struct` of a
	 * scheduled-out Linux kernel thread.
	 *
	 * This should should call @ref drgn_register_state_create() with
	 * `interrupted = false` and initialize it from the saved thread
	 * context.
	 *
	 * The context can usually be found in `struct task_struct::thread`
	 * and/or the thread stack. Refer to this architecture's implementation
	 * of `switch_to()` in the Linux kernel.
	 *
	 * @param[in] task_obj `struct task_struct` object.
	 * @param[out] ret Returned registers.
	 */
	struct drgn_error *(*linux_kernel_get_initial_registers)(const struct drgn_object *task_obj,
								 struct drgn_register_state **ret);
	/**
	 * Apply an ELF relocation.
	 *
	 * This should use the pre-defined @ref drgn_reloc_addN() functions
	 * whenever possible. Note that this is only used to relocate debugging
	 * information sections, so typically only simple absolute and
	 * PC-relative relocations need to be implemented.
	 */
	apply_elf_reloc_fn *apply_elf_reloc;
	/**
	 * Return the address and size of the direct mapping virtual address
	 * range.
	 *
	 * This is a hack which is only called when debugging a live Linux
	 * kernel older than v4.11.
	 */
	struct drgn_error *(*linux_kernel_live_direct_mapping_fallback)(struct drgn_program *prog,
									uint64_t *address_ret,
									uint64_t *size_ret);
	/** Allocate a Linux kernel page table iterator. */
	struct drgn_error *(*linux_kernel_pgtable_iterator_create)(struct drgn_program *,
								   struct pgtable_iterator **);
	/** Free a Linux kernel page table iterator. */
	void (*linux_kernel_pgtable_iterator_destroy)(struct pgtable_iterator *);
	/**
	 * (Re)initialize a Linux kernel page table iterator.
	 *
	 * This is called each time that the iterator will be used to translate
	 * a contiguous range of virtual addresses from a single page table. It
	 * is called with @ref pgtable_iterator::pgtable set to the address of
	 * the page table to use and @ref pgtable_iterator::virt_addr set to the
	 * starting virtual address to translate.
	 */
	void (*linux_kernel_pgtable_iterator_init)(struct drgn_program *,
						   struct pgtable_iterator *);
	/**
	 * Iterate a (user or kernel) page table in the Linux kernel.
	 *
	 * This is called after @ref linux_kernel_pgtable_iterator_init() to
	 * translate the starting address and may be called again without
	 * reinitializing the iterator to translate subsequent adjacent
	 * addresses in the same page table.
	 *
	 * If the caller needs to translate from a different page table or
	 * virtual address, it will call @ref
	 * linux_kernel_pgtable_iterator_init() before calling this function
	 * again.
	 *
	 * @see pgtable_iterator_next_fn
	 */
	pgtable_iterator_next_fn *linux_kernel_pgtable_iterator_next;
	/**
	 * Return the canonical form of a virtual address, i.e. apply any
	 * transformations that the CPU applies to the address before page
	 * table walking.
	 */
	uint64_t (*untagged_addr)(uint64_t addr);
};

/**
 * Implementation of @ref drgn_architecture_info::register_by_name that always
 * returns `NULL`.
 */
const struct drgn_register *drgn_register_by_name_unknown(const char *name);

extern const struct drgn_architecture_info arch_info_unknown;
extern const struct drgn_architecture_info arch_info_x86_64;
extern const struct drgn_architecture_info arch_info_i386;
extern const struct drgn_architecture_info arch_info_aarch64;
extern const struct drgn_architecture_info arch_info_arm;
extern const struct drgn_architecture_info arch_info_ppc64;
extern const struct drgn_architecture_info arch_info_riscv64;
extern const struct drgn_architecture_info arch_info_riscv32;
extern const struct drgn_architecture_info arch_info_s390x;
extern const struct drgn_architecture_info arch_info_s390;

struct drgn_platform {
	const struct drgn_architecture_info *arch;
	enum drgn_platform_flags flags;
};

static inline bool drgn_platforms_equal(const struct drgn_platform *a,
					const struct drgn_platform *b)
{
	return a->arch == b->arch && a->flags == b->flags;
}

static inline bool
drgn_platform_is_little_endian(const struct drgn_platform *platform)
{
	return platform->flags & DRGN_PLATFORM_IS_LITTLE_ENDIAN;
}

static inline bool drgn_platform_bswap(const struct drgn_platform *platform)
{
	return drgn_platform_is_little_endian(platform) != HOST_LITTLE_ENDIAN;
}

static inline bool drgn_platform_is_64_bit(const struct drgn_platform *platform)
{
	return platform->flags & DRGN_PLATFORM_IS_64_BIT;
}

static inline uint8_t
drgn_platform_address_size(const struct drgn_platform *platform)
{
	return drgn_platform_is_64_bit(platform) ? 8 : 4;
}

static inline uint64_t
drgn_platform_address_mask(const struct drgn_platform *platform)
{
	return drgn_platform_is_64_bit(platform) ? UINT64_MAX : UINT32_MAX;
}

/**
 * Initialize a @ref drgn_platform from an architecture, word size, and
 * endianness.
 *
 * The default flags for the architecture are used other than the word size and
 * endianness.
 */
void drgn_platform_from_arch(const struct drgn_architecture_info *arch,
			     bool is_64_bit, bool is_little_endian,
			     struct drgn_platform *ret);

/** Initialize a @ref drgn_platform from an ELF header. */
void drgn_platform_from_elf(GElf_Ehdr *ehdr, struct drgn_platform *ret);

/** @} */

#endif /* DRGN_PLATFORM_H */
