// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGN_PLATFORM_H
#define DRGN_PLATFORM_H

#include <elfutils/libdwfl.h>

#include "drgn.h"

struct drgn_register {
	const char *name;
	enum drgn_register_number number;
};

/* Page table iterator. */
struct pgtable_iterator {
	struct drgn_program *prog;
	/* Address of the top-level page table to iterate. */
	uint64_t pgtable;
	/* Current virtual address to translate. */
	uint64_t virt_addr;
	/* Architecture-specific data. */
	char arch[0];
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
	/* Given pt_regs as a value buffer object. */
	struct drgn_error *(*pt_regs_set_initial_registers)(Dwfl_Thread *,
							    const struct drgn_object *);
	struct drgn_error *(*prstatus_set_initial_registers)(struct drgn_program *,
							     Dwfl_Thread *,
							     const void *,
							     size_t);
	/*
	 * Get a task's registers from the task_struct or PRSTATUS note as
	 * appropriate.
	 *
	 * The given PRSTATUS note is for the CPU that the task is assigned to,
	 * which may or may not be for the given task. This callback must
	 * determine that (typically by checking whether the stack pointer in
	 * PRSTATUS lies within the task's stack).
	 *
	 * We find the PRSTATUS note by CPU rather than by PID for two reasons:
	 *
	 * 1. The PID is populated by the kernel from "current" (the current
	 *    task) via a non-maskable interrupt (NMI). During a context switch,
	 *    the stack pointer and current are not updated atomically, so if
	 *    the NMI arrives in the middle of a context switch, the stack
	 *    pointer may not actually be that of current. Therefore, the stack
	 *    pointer in PRSTATUS may not actually be for the PID in PRSTATUS.
	 *
	 *    We go through all of this trouble because blindly trusting the PID
	 *    could result in a stack trace for the wrong task, which we want to
	 *    avoid at all costs.
	 *
	 * 2. There is an idle task with PID 0 for each CPU, so for an idle task
	 *    we have no choice but to find the note by CPU.
	 */
	struct drgn_error *(*linux_kernel_set_initial_registers)(Dwfl_Thread *,
								 const struct drgn_object *,
								 const void *prstatus,
								 size_t prstatus_size);
	struct drgn_error *(*linux_kernel_get_page_offset)(struct drgn_program *,
							   uint64_t *);
	struct drgn_error *(*linux_kernel_get_vmemmap)(struct drgn_program *,
						       uint64_t *);
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

static inline const struct drgn_register *
drgn_architecture_register_by_name(const struct drgn_architecture_info *arch,
				   const char *name)
{
	if (!arch->register_by_name)
		return NULL;
	return arch->register_by_name(name);
}

extern const struct drgn_architecture_info arch_info_unknown;
extern const struct drgn_architecture_info arch_info_x86_64;

struct drgn_platform {
	const struct drgn_architecture_info *arch;
	enum drgn_platform_flags flags;
};

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
