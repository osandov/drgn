// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <elf.h>

#include "cfi.h"
#include "error.h"
#include "helpers.h"
#include "platform.h" // IWYU pragma: associated
#include "program.h"
#include "register_state.h"

/*
 * The ABI specification can be found at:
 * https://developer.arm.com/architectures/system-architectures/software-standards/abi
 * https://github.com/ARM-software/abi-aa/releases
 */

#include "arch_arm_defs.inc"

static const struct drgn_cfi_row default_dwarf_cfi_row_arm = DRGN_CFI_ROW(
	// The psABI defines the CFA as the value of the stack pointer in the
	// calling frame.
	[DRGN_REGISTER_NUMBER(r13)] = { DRGN_CFI_RULE_CFA_PLUS_OFFSET },
	// The psABI defines that callee-saved registers default to
	// DW_CFA_same_value.
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r4)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r5)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r6)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r7)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r8)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r9)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r10)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r11)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r14)),
);

static struct drgn_error *fallback_unwind_arm(struct drgn_program *prog,
					      struct drgn_register_state *regs,
					      struct drgn_register_state **ret)
{
	// GCC and Clang generate different frame pointer layouts. See "GCC/LLVM
	// frame pointer incompatibility on ARM" [1] and Linux kernel commit
	// b4d5ec9b39f8 ("ARM: 8992/1: Fix unwind_frame for clang-built
	// kernels"). For now, let's not bother with it.
	//
	// 1: https://discourse.llvm.org/t/gcc-llvm-frame-pointer-incompatibility-on-arm/32906
	return &drgn_stop;
}

// elf_gregset_t (in PRSTATUS) and struct pt_regs are identical.
static struct drgn_error *
get_initial_registers_from_struct_arm(struct drgn_program *prog,
				      const void *buf, size_t size,
				      struct drgn_register_state **ret)
{
	if (size < 68) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "registers are truncated");
	}

	struct drgn_register_state *regs =
		drgn_register_state_create(cpsr, true);
	if (!regs)
		return &drgn_enomem;

	drgn_register_state_set_range_from_buffer(regs, r13, r14,
						  (uint32_t *)buf + 13);
	drgn_register_state_set_range_from_buffer(regs, r4, r11,
						  (uint32_t *)buf + 4);
	drgn_register_state_set_range_from_buffer(regs, r0, r3, buf);
	drgn_register_state_set_from_buffer(regs, r12, (uint32_t *)buf + 12);
	drgn_register_state_set_range_from_buffer(regs, r15, cpsr,
						  (uint32_t *)buf + 15);
	drgn_register_state_set_pc_from_register(prog, regs, r15);

	*ret = regs;
	return NULL;
}

static struct drgn_error *
pt_regs_get_initial_registers_arm(const struct drgn_object *obj,
				  struct drgn_register_state **ret)
{
	return get_initial_registers_from_struct_arm(drgn_object_program(obj),
						     drgn_object_buffer(obj),
						     drgn_object_size(obj),
						     ret);
}

static struct drgn_error *
prstatus_get_initial_registers_arm(struct drgn_program *prog,
				   const void *prstatus, size_t size,
				   struct drgn_register_state **ret)
{
	// offsetof(struct elf_prstatus, pr_reg)
	static const size_t pr_reg_offset = 72;
	if (size < pr_reg_offset) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "NT_PRSTATUS is truncated");
	}
	return get_initial_registers_from_struct_arm(prog,
						     (char *)prstatus + pr_reg_offset,
						     size - pr_reg_offset, ret);
}

// The Linux kernel saves the callee-saved registers in
// task_thread_info(task)->cpu_context (with type struct cpu_context_save). See
// __switch_to() in arch/arm/kernel/entry-armv.S (as of Linux v6.12).
static struct drgn_error *
linux_kernel_get_initial_registers_arm(const struct drgn_object *task_obj,
				       struct drgn_register_state **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(task_obj);

	DRGN_OBJECT(cpu_context_obj, prog);
	err = linux_helper_task_thread_info(&cpu_context_obj, task_obj);
	if (err)
		return err;
	err = drgn_object_member_dereference(&cpu_context_obj, &cpu_context_obj,
					     "cpu_context");
	if (err)
		return err;
	if (cpu_context_obj.encoding != DRGN_OBJECT_ENCODING_BUFFER ||
	    drgn_object_size(&cpu_context_obj) < 40) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cpu_context is truncated");
	}
	err = drgn_object_read(&cpu_context_obj, &cpu_context_obj);
	if (err)
		return err;

	const void *buf = drgn_object_buffer(&cpu_context_obj);
	struct drgn_register_state *regs =
		drgn_register_state_create(r15, false);
	if (!regs)
		return &drgn_enomem;

	drgn_register_state_set_range_from_buffer(regs, r13, r14,
						  (uint32_t *)buf + 8);
	drgn_register_state_set_range_from_buffer(regs, r4, r11, buf);
	drgn_register_state_set_pc_from_register(prog, regs, r14);
	*ret = regs;
	return NULL;
}

static struct drgn_error *
apply_elf_reloc_arm(const struct drgn_relocating_section *relocating,
		    uint64_t r_offset, uint32_t r_type, const int64_t *r_addend,
		    uint64_t sym_value)
{
	switch (r_type) {
	case R_ARM_NONE:
		return NULL;
	case R_ARM_ABS32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	case R_ARM_REL32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	default:
		return DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
	}
}

struct pgtable_iterator_arm {
	struct pgtable_iterator it;
	union {
		// For LPAE.
		struct {
			uint64_t cached_entries[3];
			uint32_t cached_virt_addr;
		};
		// For non-LPAE.
		struct {
			uint32_t cached_entry;
			uint32_t cached_index;
		};
	};
};

static struct drgn_error *
linux_kernel_pgtable_iterator_create_arm(struct drgn_program *prog,
					 struct pgtable_iterator **ret)
{
	struct pgtable_iterator_arm *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;
	*ret = &it->it;
	return NULL;
}

static void linux_kernel_pgtable_iterator_destroy_arm(struct pgtable_iterator *it)
{
	free(container_of(it, struct pgtable_iterator_arm, it));
}

static void linux_kernel_pgtable_iterator_init_arm(struct drgn_program *prog,
						   struct pgtable_iterator *_it)
{
	struct pgtable_iterator_arm *it =
		container_of(_it, struct pgtable_iterator_arm, it);
	memset(it->cached_entries, 0, sizeof(it->cached_entries));
	it->cached_virt_addr = 0;
}

static struct drgn_error *
linux_kernel_pgtable_iterator_next_arm_lpae(struct drgn_program *prog,
					    struct pgtable_iterator_arm *it,
					    uint64_t *virt_addr_ret,
					    uint64_t *phys_addr_ret)
{
	struct drgn_error *err;
	const uint32_t virt_addr = it->it.virt_addr;

	const uint64_t phys_addr_mask = 0xfffffff000;
	uint32_t index_mask = 0x3;
	uint64_t table = it->it.pgtable;
	bool table_physical = false;
	for (int level = 2;; level--) {
		int level_shift = 12 + 9 * level;
		uint32_t index = (virt_addr >> level_shift) & index_mask;
		uint32_t cached_index =
			(it->cached_virt_addr >> level_shift) & index_mask;
		uint64_t *entry_ptr = &it->cached_entries[2 - level];
		if (index != cached_index)
			memset(entry_ptr, 0, (level + 1) * 8);
		if (!*entry_ptr) {
			err = drgn_program_read_u64(prog, table + index * 8,
						    table_physical, entry_ptr);
			if (err)
				return err;
		}
		uint64_t entry = *entry_ptr;

		index_mask = 0x1ff;
		table = entry & phys_addr_mask;
		table_physical = true;

		if (level == 0 || (entry & 0x3) != 0x3) {
			uint64_t mask = (UINT64_C(1) << level_shift) - 1;
			*virt_addr_ret = virt_addr & ~mask;
			if ((entry & 0x3) == (level == 0 ? 0x3 : 0x1))
				*phys_addr_ret = table & ~mask;
			else
				*phys_addr_ret = UINT64_MAX;
			it->cached_virt_addr = virt_addr;
			it->it.virt_addr = (virt_addr | mask) + 1;
			return NULL;
		}
	}
}

static struct drgn_error *
linux_kernel_pgtable_iterator_next_arm(struct drgn_program *prog,
				       struct pgtable_iterator *_it,
				       uint64_t *virt_addr_ret,
				       uint64_t *phys_addr_ret)
{
	struct drgn_error *err;
	struct pgtable_iterator_arm *it =
		container_of(_it, struct pgtable_iterator_arm, it);

	if (prog->vmcoreinfo.arm_lpae) {
		return linux_kernel_pgtable_iterator_next_arm_lpae(prog, it,
								   virt_addr_ret,
								   phys_addr_ret);
	}

	const uint32_t virt_addr = it->it.virt_addr;

	uint32_t index = virt_addr >> 20;
	if (it->cached_index != index || !it->cached_entry) {
		err = drgn_program_read_u32(prog, it->it.pgtable + index * 4,
					    false, &it->cached_entry);
		if (err)
			return err;
		it->cached_index = index;
	}
	uint32_t entry = it->cached_entry;

	if ((entry & 0x3) != 0x1) {
		uint32_t mask = (UINT32_C(1) << 20) - 1;
		if ((entry & 0x40002) == 0x40002) {
			// Supersection (16MB)
			mask = (UINT32_C(1) << 24) - 1;
			*phys_addr_ret = (entry & ~mask)
					 | ((uint64_t)(entry & 0xf00000) << 12);
		} else if ((entry & 0x40002) == 0x2) {
			// Section (1MB)
			*phys_addr_ret = entry & ~mask;
		} else {
			// Invalid
			*phys_addr_ret = UINT64_MAX;
		}
		*virt_addr_ret = virt_addr & ~mask;
		it->it.virt_addr = (virt_addr | mask) + 1;
		return NULL;
	}

	uint32_t table = entry & ~((UINT32_C(1) << 10) - 1);
	index = (virt_addr >> 12) & 0xff;
	err = drgn_program_read_u32(prog, table + index * 4, true, &entry);
	if (err)
		return err;

	uint32_t mask = (UINT32_C(1) << 12) - 1;
	if ((entry & 0x2)) {
		// Small page (4KB)
		*phys_addr_ret = entry & ~mask;
	} else if ((entry & 0x3) == 0x1) {
		// Large page (16KB)
		mask = (UINT32_C(1) << 16) - 1;
		*phys_addr_ret = entry & ~mask;
	} else {
		*phys_addr_ret = UINT64_MAX;
	}
	*virt_addr_ret = virt_addr & ~mask;
	it->it.virt_addr = (virt_addr | mask) + 1;
	return NULL;
}

const struct drgn_architecture_info arch_info_arm = {
	.name = "Arm",
	.arch = DRGN_ARCH_ARM,
	.default_flags = DRGN_PLATFORM_IS_LITTLE_ENDIAN,
	.scalar_alignment = { 1, 2, 4, 8, 8 },
	DRGN_ARCHITECTURE_REGISTERS,
	.default_dwarf_cfi_row = &default_dwarf_cfi_row_arm,
	.fallback_unwind = fallback_unwind_arm,
	.pt_regs_get_initial_registers = pt_regs_get_initial_registers_arm,
	.prstatus_get_initial_registers = prstatus_get_initial_registers_arm,
	.linux_kernel_get_initial_registers =
		linux_kernel_get_initial_registers_arm,
	.apply_elf_reloc = apply_elf_reloc_arm,
	.linux_kernel_pgtable_iterator_create =
		linux_kernel_pgtable_iterator_create_arm,
	.linux_kernel_pgtable_iterator_destroy =
		linux_kernel_pgtable_iterator_destroy_arm,
	.linux_kernel_pgtable_iterator_init =
		linux_kernel_pgtable_iterator_init_arm,
	.linux_kernel_pgtable_iterator_next =
		linux_kernel_pgtable_iterator_next_arm,
};
