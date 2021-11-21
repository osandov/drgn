// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef DRGN_PLATFORM_H
#define DRGN_PLATFORM_H

#include <gelf.h>

#include "cfi.h"
#include "drgn.h"
#include "util.h"

struct drgn_orc_entry;
struct drgn_register_state;

struct drgn_register {
	const char * const *names;
	size_t num_names;
	drgn_register_number regno;
	uint64_t dwarf_number;
};

struct drgn_register_layout {
	uint32_t offset;
	uint32_t size;
};

/* ELF section to apply relocations to. */
struct drgn_relocating_section {
	char *buf;
	size_t buf_size;
	uint64_t addr;
	bool bswap;
};

typedef struct drgn_error *
apply_elf_rela_fn(const struct drgn_relocating_section *relocating,
		  uint64_t r_offset, uint32_t r_type, int64_t r_addend,
		  uint64_t sym_value);

/* Page table iterator. */
struct pgtable_iterator {
	struct drgn_program *prog;
	/* Address of the top-level page table to iterate. */
	uint64_t pgtable;
	/* Current virtual address to translate. */
	uint64_t virt_addr;
	/* Architecture-specific data. */
	char arch[];
};

/*
 * Translate the current virtual address from a page table iterator.
 *
 * Abstractly, a virtual address lies in a range of addresses in the address
 * space. A range may be a mapped page, a page table gap, or a range of invalid
 * addresses (e.g., non-canonical addresses on x86-64). This finds the range
 * containing the current virtual address, returns the first virtual address of
 * that range and the physical address it maps to (if any), and updates the
 * current virtual address to the end of the range.
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
(pgtable_iterator_next_fn)(struct pgtable_iterator *it, uint64_t *virt_addr_ret,
			   uint64_t *phys_addr_ret);

struct drgn_architecture_info {
	const char *name;
	enum drgn_architecture arch;
	enum drgn_platform_flags default_flags;
	const struct drgn_register *registers;
	size_t num_registers;
	const struct drgn_register *(*register_by_name)(const char *name);
	const struct drgn_register_layout *register_layout;
	drgn_register_number (*dwarf_regno_to_internal)(uint64_t);
	/* CFI row containing default rules for DWARF CFI. */
	const struct drgn_cfi_row *default_dwarf_cfi_row;
	struct drgn_error *(*orc_to_cfi)(const struct drgn_orc_entry *,
					 struct drgn_cfi_row **, bool *,
					 drgn_register_number *);
	/*
	 * Try to unwind a stack frame if CFI wasn't found. Returns &drgn_stop
	 * if we couldn't.
	 */
	struct drgn_error *(*fallback_unwind)(struct drgn_program *,
					      struct drgn_register_state *,
					      struct drgn_register_state **);
	/* Given pt_regs as a value buffer object. */
	struct drgn_error *(*pt_regs_get_initial_registers)(const struct drgn_object *,
							    struct drgn_register_state **);
	struct drgn_error *(*prstatus_get_initial_registers)(struct drgn_program *,
							     const void *,
							     size_t,
							     struct drgn_register_state **);
	struct drgn_error *(*linux_kernel_get_initial_registers)(const struct drgn_object *,
								 struct drgn_register_state **);
	apply_elf_rela_fn *apply_elf_rela;
	struct drgn_error *(*linux_kernel_get_page_offset)(struct drgn_object *);
	struct drgn_error *(*linux_kernel_get_vmemmap)(struct drgn_object *);
	struct drgn_error *(*linux_kernel_live_direct_mapping_fallback)(struct drgn_program *,
									uint64_t *,
									uint64_t *);
	/* Size to allocate for pgtable_iterator::arch. */
	size_t pgtable_iterator_arch_size;
	/* Initialize pgtable_iterator::arch. */
	void (*pgtable_iterator_arch_init)(void *buf);
	/* Iterate a (user or kernel) page table in the Linux kernel. */
	pgtable_iterator_next_fn *linux_kernel_pgtable_iterator_next;
};

extern const struct drgn_architecture_info arch_info_unknown;
extern const struct drgn_architecture_info arch_info_x86_64;
extern const struct drgn_architecture_info arch_info_ppc64;

struct drgn_platform {
	const struct drgn_architecture_info *arch;
	enum drgn_platform_flags flags;
};

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

#endif /* DRGN_PLATFORM_H */
