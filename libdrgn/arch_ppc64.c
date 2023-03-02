// (C) Copyright IBM Corp. 2020
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <byteswap.h>
#include <elf.h>
#include <endian.h>
#include <string.h>

#include "drgn.h"
#include "error.h"
#include "platform.h" // IWYU pragma: associated
#include "program.h"
#include "register_state.h"

#include "arch_ppc64_defs.inc"

static const struct drgn_cfi_row default_dwarf_cfi_row_ppc64 = DRGN_CFI_ROW(
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(lr)),
	[DRGN_REGISTER_NUMBER(r1)] = { DRGN_CFI_RULE_CFA_PLUS_OFFSET },
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r14)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r15)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r16)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r17)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r18)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r19)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r20)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r21)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r22)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r23)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r24)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r25)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r26)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r27)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r28)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r29)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r30)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r31)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(cr2)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(cr3)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(cr4)),
);

// Unwind using the stack frame back chain. Note that leaf functions may not
// allocate a stack frame, so this may skip the caller of a leaf function. I
// don't know of a good way around that.
static struct drgn_error *
fallback_unwind_ppc64(struct drgn_program *prog,
		      struct drgn_register_state *regs,
		      struct drgn_register_state **ret)
{
	struct drgn_error *err;

	struct optional_uint64 r1 = drgn_register_state_get_u64(prog, regs, r1);
	if (!r1.has_value)
		return &drgn_stop;

	// The stack pointer (r1) points to the lowest address of the stack
	// frame (the stack grows downwards from high addresses to low
	// addresses), which contains the caller's stack pointer.
	uint64_t unwound_r1;
	err = drgn_program_read_u64(prog, r1.value, false, &unwound_r1);
	uint64_t saved_lr;
	if (!err) {
		if (unwound_r1 <= r1.value) {
			// The unwound stack pointer is either 0, indicating the
			// first stack frame, or invalid.
			return &drgn_stop;
		}
		// The return address (the saved lr) is stored 16 bytes into the
		// caller's stack frame.
		err = drgn_program_read_memory(prog, &saved_lr, unwound_r1 + 16,
					       sizeof(saved_lr), false);
	}
	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			drgn_error_destroy(err);
			err = &drgn_stop;
		}
		return err;
	}

	struct drgn_register_state *unwound =
		drgn_register_state_create(r1, false);
	if (!unwound)
		return &drgn_enomem;
	drgn_register_state_set_from_buffer(unwound, lr, &saved_lr);
	drgn_register_state_set_from_u64(prog, unwound, r1, unwound_r1);
	drgn_register_state_set_pc_from_register(prog, unwound, lr);
	*ret = unwound;
	drgn_register_state_set_cfa(prog, regs, unwound_r1);
	return NULL;
}

static struct drgn_error *
get_initial_registers_from_struct_ppc64(struct drgn_program *prog,
					const void *buf, size_t size,
					bool linux_kernel_prstatus,
					bool linux_kernel_switched_out,
					struct drgn_register_state **ret)
{
	if (size < 312) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "registers are truncated");
	}

	bool bswap = drgn_platform_bswap(&prog->platform);

	struct drgn_register_state *regs =
		drgn_register_state_create(cr7, true);
	if (!regs)
		return &drgn_enomem;

	/*
	 * In most cases, nip (word 32) contains the program counter. But, the
	 * NT_PRSTATUS note in Linux kernel vmcores is odd, and the saved stack
	 * pointer (r1) is for the program counter in the link register (word
	 * 36).
	 */
	uint64_t pc;
	memcpy(&pc, (uint64_t *)buf + (linux_kernel_prstatus ? 36 : 32),
	       sizeof(pc));
	if (bswap)
		pc = bswap_64(pc);
	drgn_register_state_set_pc(prog, regs, pc);

	// Switched out tasks in the Linux kernel only save r14-r31, nip, and
	// ccr.
	if (!linux_kernel_switched_out) {
		if (!linux_kernel_prstatus) {
			drgn_register_state_set_from_buffer(regs, lr,
							    (uint64_t *)buf + 36);
		}
		drgn_register_state_set_range_from_buffer(regs, r0, r13, buf);
	}
	drgn_register_state_set_range_from_buffer(regs, r14, r31,
						  (uint64_t *)buf + 14);

	uint64_t ccr;
	memcpy(&ccr, (uint64_t *)regs + 38, sizeof(ccr));
	uint64_t cr[8];
	if (bswap) {
		for (int i = 0; i < 8; i += 2) {
			cr[i] = ccr & (UINT64_C(0xf) << (36 + 4 * i));
			cr[i + 1] = ccr & (UINT64_C(0xf) << (32 + 4 * i));
		}
	} else {
		for (int i = 0; i < 8; i++)
			cr[i] = ccr & (UINT64_C(0xf) << (28 - 4 * i));
	}
	drgn_register_state_set_range_from_buffer(regs, cr0, cr7, cr);

	*ret = regs;
	return NULL;
}

static struct drgn_error *
pt_regs_get_initial_registers_ppc64(const struct drgn_object *obj,
				    struct drgn_register_state **ret)
{
	return get_initial_registers_from_struct_ppc64(drgn_object_program(obj),
						       drgn_object_buffer(obj),
						       drgn_object_size(obj),
						       false, false, ret);
}

static struct drgn_error *
prstatus_get_initial_registers_ppc64(struct drgn_program *prog,
				     const void *prstatus, size_t size,
				     struct drgn_register_state **ret)
{
	if (size < 112) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "NT_PRSTATUS is truncated");
	}
	bool is_linux_kernel = prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL;
	return get_initial_registers_from_struct_ppc64(prog,
						       (char *)prstatus + 112,
						       size - 112,
						       is_linux_kernel, false,
						       ret);
}

// The Linux kernel saves the callee-saved registers in a struct pt_regs on the
// thread's kernel stack. See _switch() in arch/powerpc/kernel/entry_64.S (as of
// Linux v5.19).
static struct drgn_error *
linux_kernel_get_initial_registers_ppc64(const struct drgn_object *task_obj,
					 struct drgn_register_state **ret)

{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(task_obj);

	struct drgn_object sp_obj;
	drgn_object_init(&sp_obj, prog);

	// The top of the stack is saved in task->thread.ksp.
	err = drgn_object_member_dereference(&sp_obj, task_obj, "thread");
	if (err)
		goto out;
	err = drgn_object_member(&sp_obj, &sp_obj, "ksp");
	if (err)
		goto out;
	uint64_t ksp;
	err = drgn_object_read_unsigned(&sp_obj, &ksp);
	if (err)
		goto out;
	// The previous stack pointer is stored at the top of the stack.
	uint64_t r1;
	err = drgn_program_read_u64(prog, ksp, false, &r1);
	if (err)
		goto out;

	// The struct pt_regs is stored above the previous stack pointer.
	struct drgn_qualified_type pt_regs_type;
	err = drgn_program_find_type(prog, "struct pt_regs", NULL,
				     &pt_regs_type);
	if (err)
		goto out;
	uint64_t sizeof_pt_regs;
	err = drgn_type_sizeof(pt_regs_type.type, &sizeof_pt_regs);
	if (err)
		goto out;

	char buf[312];
	err = drgn_program_read_memory(prog, buf, r1 - sizeof_pt_regs,
				       sizeof(buf), false);
	if (err)
		goto out;

	err = get_initial_registers_from_struct_ppc64(prog, buf, sizeof(buf),
						      false, true, ret);
	if (err)
		goto out;

	drgn_register_state_set_from_u64(prog, *ret, r1, r1);

	err = NULL;
out:
	drgn_object_deinit(&sp_obj);
	return err;
}

static struct drgn_error *
apply_elf_reloc_ppc64(const struct drgn_relocating_section *relocating,
		      uint64_t r_offset, uint32_t r_type,
		      const int64_t *r_addend, uint64_t sym_value)
{
	switch (r_type) {
	case R_PPC64_NONE:
		return NULL;
	case R_PPC64_ADDR32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	case R_PPC64_REL32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	case R_PPC64_ADDR64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value);
	case R_PPC64_REL64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	default:
		return DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
	}
}

struct pt_level {
	uint16_t bits;
	uint16_t shift;
	uint64_t entries;
};

struct pgtable_iterator_ppc64 {
	struct pgtable_iterator it;
	const struct pt_level *pt_levels;
};

static const struct pt_level pt_levels_radix_4k[] = {
	{ .bits = 9,  .shift = 12, .entries = 512  }, // PTE
	{ .bits = 9,  .shift = 21, .entries = 512  }, // PMD
	{ .bits = 9,  .shift = 30, .entries = 512  }, // PUD
	{ .bits = 13, .shift = 39, .entries = 8192 }, // PGD
};

static const struct pt_level pt_levels_radix_64k[] = {
	{ .bits = 5,  .shift = 16, .entries = 32   }, // PTE
	{ .bits = 9,  .shift = 21, .entries = 512  }, // PMD
	{ .bits = 9,  .shift = 30, .entries = 512  }, // PUD
	{ .bits = 13, .shift = 39, .entries = 8192 }, // PGD
};

static inline uint64_t
get_page_mask(struct pgtable_iterator_ppc64 *it, int level)
{
	return (((UINT64_C(1) << 53) - 1)
		& ~((UINT64_C(1) << it->pt_levels[level].shift) - 1));
}

static uint16_t
get_index(struct pgtable_iterator_ppc64 *it, uint64_t va, uint16_t level)
{
	uint64_t mask = it->pt_levels[level - 1].entries - 1;
	return (va >> it->pt_levels[level - 1].shift) & mask;
}

static struct drgn_error *
linux_kernel_pgtable_iterator_create_ppc64(struct drgn_program * prog,
					   struct pgtable_iterator **ret)
{
	uint64_t mmu_features;
	struct drgn_error *err = NULL;
	const uint64_t page_shift = prog->vmcoreinfo.page_shift;
	struct drgn_object book3s, cur_cpu_spec, mmu_features_obj;

	struct pgtable_iterator_ppc64 *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;

	drgn_object_init(&book3s, prog);
	drgn_object_init(&cur_cpu_spec, prog);
	drgn_object_init(&mmu_features_obj, prog);

	if (page_shift == 16) {
		it->pt_levels = pt_levels_radix_64k;
	} else if (page_shift == 12) {
		it->pt_levels = pt_levels_radix_4k;
	} else {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"Unknown page size.");
		goto out;
	}

	// Only BOOK3S CPU family is supported, not BOOK3E.
	err = drgn_program_find_object(prog, "interrupt_base_book3e", NULL,
				       DRGN_FIND_OBJECT_ANY, &book3s);
	if (!err) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"virtual address translation is not available for BOOK3E CPU family");
		goto out;
	}

	// Identify the MMU type.
	err = drgn_program_find_object(prog, "cur_cpu_spec", NULL,
				       DRGN_FIND_OBJECT_ANY, &cur_cpu_spec);
	if (err)
		goto out;
	err = drgn_object_member_dereference(&mmu_features_obj, &cur_cpu_spec,
					     "mmu_features");
	if (err)
		goto out;

	err = drgn_object_read_unsigned(&mmu_features_obj, &mmu_features);

	if (err)
		goto out;

	if (!(mmu_features & 0x40)) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"virtual address translation is only supported for Radix MMU");
		goto out;
	}

	*ret = &it->it;

out:
	drgn_object_deinit(&book3s);
	drgn_object_deinit(&cur_cpu_spec);
	drgn_object_deinit(&mmu_features_obj);
	if (err)
		free(it);
	return err;
}

static void
linux_kernel_pgtable_iterator_destroy_ppc64(struct pgtable_iterator *_it)
{
	struct pgtable_iterator_ppc64 *it =
		container_of(_it, struct pgtable_iterator_ppc64, it);
	free(it);
}

static void
linux_kernel_pgtable_iterator_init_ppc64(struct drgn_program *prog,
					 struct pgtable_iterator *_it)
{
	return;
}

static struct drgn_error *
linux_kernel_pgtable_iterator_next_ppc64(struct drgn_program *prog,
					 struct pgtable_iterator *_it,
					 uint64_t *virt_addr_ret,
					 uint64_t *phys_addr_ret)
{
	// Page table entry status bits since Linux kernel commits 849f86a630e9
	// ("powerpc/mm/book3s-64: Move _PAGE_PRESENT to the most significant
	// bit") and 84c957560a7a ("powerpc/mm/book3s-64: Move _PAGE_PTE to 2nd
	// most significant bit") (in v4.6).
	static const uint64_t PAGE_PRESENT = UINT64_C(1) << 63;
	static const uint64_t PAGE_PTE = UINT64_C(1) << 62;
	static const uint64_t PT_MASK = UINT64_C(0xc0000000000000ff);
	static const uint16_t levels = 4;
	struct drgn_error *err;
	struct pgtable_iterator_ppc64 *it =
		container_of(_it, struct pgtable_iterator_ppc64, it);
	uint64_t virt_addr = it->it.virt_addr;

	uint64_t entry;
	for (uint16_t level = levels;; level--) {
		uint64_t table;
		bool table_physical;
		if (level == levels) {
			table = it->it.pgtable;
			table_physical = false;
		} else {
			// PAGE_PTE bit represents huge page.
			if (!(entry & PAGE_PRESENT) || (entry & PAGE_PTE) || level == 0) {
				uint64_t mask = (UINT64_C(1) << it->pt_levels[level].shift) - 1;
				*virt_addr_ret = virt_addr & ~mask;
				if (entry & PAGE_PRESENT)
					*phys_addr_ret = entry & get_page_mask(it, level);
				else
					*phys_addr_ret = UINT64_MAX;

				it->it.virt_addr = (virt_addr | mask) + 1;
				return NULL;
			}
			table = entry & ~PT_MASK;
			table_physical = true;
		}

		uint64_t index = get_index(it, virt_addr, level);
		err = drgn_program_read_memory(prog, &entry,
					       table + (8 * index), 8,
					       table_physical);
		if (err)
			return err;

		// Page table entries are always big-endian, even on ppc64le.
		entry = be64toh(entry);
	}
}

const struct drgn_architecture_info arch_info_ppc64 = {
	.name = "ppc64",
	.arch = DRGN_ARCH_PPC64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	DRGN_ARCHITECTURE_REGISTERS,
	.default_dwarf_cfi_row = &default_dwarf_cfi_row_ppc64,
	.fallback_unwind = fallback_unwind_ppc64,
	.pt_regs_get_initial_registers = pt_regs_get_initial_registers_ppc64,
	.prstatus_get_initial_registers = prstatus_get_initial_registers_ppc64,
	.linux_kernel_get_initial_registers =
		linux_kernel_get_initial_registers_ppc64,
	.apply_elf_reloc = apply_elf_reloc_ppc64,
	.linux_kernel_pgtable_iterator_create =
		linux_kernel_pgtable_iterator_create_ppc64,
	.linux_kernel_pgtable_iterator_destroy =
		linux_kernel_pgtable_iterator_destroy_ppc64,
	.linux_kernel_pgtable_iterator_init =
		linux_kernel_pgtable_iterator_init_ppc64,
	.linux_kernel_pgtable_iterator_next =
		linux_kernel_pgtable_iterator_next_ppc64,
};
