// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <elf.h>

#include "platform.h" // IWYU pragma: associated
#include "program.h"

/*
 * The ABI specification can be found at:
 * https://developer.arm.com/architectures/system-architectures/software-standards/abi
 * https://github.com/ARM-software/abi-aa/releases
 */

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

#define LEVEL1_NUM_ENTRIES 4096
#define LEVEL2_NUM_ENTRIES 256

struct pgtable_iterator_arm {
	struct pgtable_iterator it;
	uint16_t index1;
	uint16_t index2;
	uint32_t level1[LEVEL1_NUM_ENTRIES];
	uint32_t level2[LEVEL2_NUM_ENTRIES];
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

static void linux_kernel_pgtable_iterator_destroy_arm(struct pgtable_iterator *_it)
{
	free(container_of(_it, struct pgtable_iterator_arm, it));
}

static void linux_kernel_pgtable_iterator_init_arm(struct drgn_program *prog,
						   struct pgtable_iterator *_it)
{
	struct pgtable_iterator_arm *it =
		container_of(_it, struct pgtable_iterator_arm, it);
	it->index1 = 0xffff;
	it->index2 = 0xffff;
}

static struct drgn_error *
mmu_mapped_entry(struct pgtable_iterator *_it, uint32_t entry, uint32_t mask,
		 uint64_t *virt_addr_ret, uint64_t *phys_addr_ret)
{
	*virt_addr_ret = _it->virt_addr & ~mask;
	*phys_addr_ret = entry & ~mask;
	_it->virt_addr = (_it->virt_addr | mask) + 1;
	return NULL;
}

static struct drgn_error *
mmu_unmapped_entry(struct pgtable_iterator *_it, uint32_t mask,
		   uint64_t *virt_addr_ret, uint64_t *phys_addr_ret)
{
	*virt_addr_ret = _it->virt_addr & ~mask;
	*phys_addr_ret = UINT64_MAX;
	_it->virt_addr = (_it->virt_addr | mask) + 1;
	return NULL;
}

static struct drgn_error *
mmu_read_table(struct drgn_program *prog, uint32_t *level, uint32_t table,
	       uint16_t index, uint32_t num_entries, bool physical)
{
	return drgn_program_read_memory(prog, &level[index], table + 4 * index,
					4 * (num_entries - index), physical);
}

static struct drgn_error *
linux_kernel_pgtable_iterator_next_arm(struct drgn_program *prog,
				       struct pgtable_iterator *_it,
				       uint64_t *virt_addr_ret,
				       uint64_t *phys_addr_ret)
{
	struct drgn_error *err;
	const bool bswap = drgn_platform_bswap(&prog->platform);
	struct pgtable_iterator_arm *it =
		container_of(_it, struct pgtable_iterator_arm, it);
	const uint64_t virt_addr = it->it.virt_addr;

	uint16_t index;
	uint32_t table;
	uint32_t entry;
	
	if (it->index2 >= LEVEL2_NUM_ENTRIES) {
		if (it->index1 >= LEVEL1_NUM_ENTRIES) {
			// Refill level1 table
			table = it->it.pgtable;
			index = (virt_addr >> 20) & 0xfff;
			err = mmu_read_table(prog, it->level1, table, index,
					     LEVEL1_NUM_ENTRIES, false);
			if (err)
				return err;
			it->index1 = index;
		}

		// MMU level 1
		entry = it->level1[it->index1++];
		if (bswap)
			entry = bswap_32(entry);
		
		if ((entry & 0x3) == 0) {
			// Fault
			return mmu_unmapped_entry(_it, 0x000fffff,
						  virt_addr_ret, phys_addr_ret);
		} else if (((entry & 0x3) == 2) && ((entry & 0x40000) == 0)) {
			// Section
			return mmu_mapped_entry(_it, entry, 0x000fffff,
						virt_addr_ret, phys_addr_ret);
		} else if ((entry & 0x3) == 1) {
			// Pointer to 2nd level
			// Refill level2 table
			table = entry & 0xfffffc00;
			index = (virt_addr >> 12) & 0xff;
			err = mmu_read_table(prog, it->level2, table, index,
					     LEVEL2_NUM_ENTRIES, true);
			if (err)
				return err;

			it->index2 = index;
		} else {
			return drgn_error_format(DRGN_ERROR_OTHER,
				"unsupported ARM level 1 entry: 0x%08x", entry);
		}
	}

	// MMU level 2
	entry = it->level2[it->index2++];
	if (bswap)
		entry = bswap_32(entry);

	if ((entry & 0x3) == 0) {
		// Fault
		return mmu_unmapped_entry(_it, 0x00000fff,
					  virt_addr_ret, phys_addr_ret);
	} else if ((entry & 0x2) == 2) {
		// Small page
		return mmu_mapped_entry(_it, entry, 0x00000fff,
					virt_addr_ret, phys_addr_ret);
	} else {
		return drgn_error_format(DRGN_ERROR_OTHER,
				"unsupported ARM level 2 entry: 0x%08x", entry);
	}
}

const struct drgn_architecture_info arch_info_arm = {
	.name = "Arm",
	.arch = DRGN_ARCH_ARM,
	.default_flags = DRGN_PLATFORM_IS_LITTLE_ENDIAN,
	.register_by_name = drgn_register_by_name_unknown,
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
