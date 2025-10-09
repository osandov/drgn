// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <byteswap.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "error.h"
#include "linux_kernel.h"
#include "log.h"
#include "platform.h" // IWYU pragma: associated
#include "program.h"
#include "register_state.h"
#include "util.h"

/*
 * The ABI specification can be found at:
 * https://developer.arm.com/architectures/system-architectures/software-standards/abi
 * https://github.com/ARM-software/abi-aa/releases
 */

#include "arch_aarch64_defs.inc"

static_assert(DRGN_AARCH64_RA_SIGN_STATE_REGNO ==
	      DRGN_REGISTER_NUMBER(ra_sign_state),
	      "RA_SIGN_STATE register number is out of sync");

static const struct drgn_cfi_row default_dwarf_cfi_row_aarch64 = DRGN_CFI_ROW(
	[DRGN_REGISTER_NUMBER(ra_sign_state)] = {
		DRGN_CFI_RULE_CONSTANT, .constant = 0
	},
	// The psABI defines the CFA as the value of the stack pointer in the
	// calling frame.
	[DRGN_REGISTER_NUMBER(sp)] = { DRGN_CFI_RULE_CFA_PLUS_OFFSET },
	// The psABI defines that callee-saved registers default to
	// DW_CFA_same_value.
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x19)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x20)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x21)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x22)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x23)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x24)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x25)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x26)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x27)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x28)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x29)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x30)),
);

// Mask out the pointer authentication code from x30/lr.
static void demangle_cfi_registers_aarch64(struct drgn_program *prog,
					   struct drgn_register_state *regs)
{
	struct optional_uint64 ra_sign_state =
		drgn_register_state_get_u64(prog, regs, ra_sign_state);
	if (!ra_sign_state.has_value || !(ra_sign_state.value & 1))
		return;
	struct optional_uint64 ra =
		drgn_register_state_get_u64(prog, regs, x30);
	if (!ra.has_value)
		return;
	if (ra.value & (UINT64_C(1) << 55))
		ra.value |= prog->aarch64_insn_pac_mask;
	else
		ra.value &= ~prog->aarch64_insn_pac_mask;
	drgn_register_state_set_from_u64(prog, regs, x30, ra.value);
}

// elf_gregset_t (in PRSTATUS) and struct user_pt_regs have the same layout.
// This layout is a prefix of the in-kernel struct pt_regs (but we don't care
// about any of the extra fields).
static struct drgn_error *
get_initial_registers_from_struct_aarch64(struct drgn_program *prog,
					  const void *buf, size_t size,
					  struct drgn_register_state **ret)
{
	if (size < 272) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "registers are truncated");
	}

	struct drgn_register_state *regs =
		drgn_register_state_create(pstate, true);
	if (!regs)
		return &drgn_enomem;

	drgn_register_state_set_from_buffer(regs, pc, (uint64_t *)buf + 32);
	drgn_register_state_set_from_buffer(regs, sp, (uint64_t *)buf + 31);
	drgn_register_state_set_range_from_buffer(regs, x19, x30,
						  (uint64_t *)buf + 19);
	drgn_register_state_set_range_from_buffer(regs, x0, x18, buf);
	drgn_register_state_set_from_buffer(regs, pstate, (uint64_t *)buf + 33);
	drgn_register_state_set_pc_from_register(prog, regs, pc);

	*ret = regs;
	return NULL;
}


static struct drgn_error *
get_stackframe_offset(struct drgn_program *prog, uint64_t *ret)
{
	if (!prog->aarch64_stackframe_offset_cached) {
		struct drgn_error *err;
		struct drgn_qualified_type pt_regs_type;

		err = drgn_program_find_type(prog, "struct pt_regs", NULL, &pt_regs_type);
		if (err)
			return err;

		struct drgn_type_member *stackframe_member;
		uint64_t bit_offset;
		err = drgn_type_find_member(pt_regs_type.type, "stackframe",
					    &stackframe_member, &bit_offset);
		if (err)
			return err;

		prog->aarch64_stackframe_offset_cached = bit_offset / 8;
	}

	*ret = prog->aarch64_stackframe_offset_cached;
	return NULL;
}


static struct drgn_error *
fallback_unwind_try_pt_regs(struct drgn_program *prog, uint64_t fp,
			    uint64_t frame[2],
			    struct drgn_register_state *regs,
			    struct drgn_register_state **regs_ret,
			    bool *found_ret)
{
	struct drgn_error *err;
	uint64_t stackframe_offset;
	const char *method;

	err = get_stackframe_offset(prog, &stackframe_offset);
	if (err)
		return err;

	uint64_t pt_regs_addr = fp - stackframe_offset;

	if (!frame[0] && !frame[1]) {
		// Since c2c6b27b5aa14 ("arm64: stacktrace: unwind exception
		// boundaries") - v6.13, a frame record with fp and lr both zero
		// indicates that we can read the next word on the stack for
		// "metadata" which tells us whether a pt_regs is pushed to the
		// stack.
		uint64_t frame_meta_type;
		err = drgn_program_read_u64(prog, fp + 16, false, &frame_meta_type);
		if (err)
			return err;

		// FRAME_META_TYPE_PT_REGS == 2 indicates a pt_regs
		if (frame_meta_type != 2) {
			*found_ret = false;
			return NULL;
		}
		method = "frame metadata";
	} else {
		// Before this, it's still possible that this stack frame is
		// embedded within a pt_regs. However, there's no reliable way
		// to detect it. We can guess what that pt_regs pointer would
		// be, and check whether any CPU has a __irq_regs value matching
		// it. If so, we're guaranteed to be in the pt_regs for an IRQ.
		// If not, it's still possible that this is a pt_regs, but the
		// __irq_regs accounting has not yet happened (or has been
		// cleaned up already). So this heuristic shouldn't have any
		// false positives, but could have some false negatives.
		bool is_irq_regs;
		err = drgn_program_is_irq_regs(prog, pt_regs_addr, &is_irq_regs);
		if (err)
			return err;

		if (!is_irq_regs) {
			*found_ret = false;
			return NULL;
		}
		method = "__irq_regs";
	}

	// Now that we're reasonably confident that there's a pt_regs here, read
	// it and use it.
	char pt_regs[272];
	err = drgn_program_read_memory(prog, &pt_regs, pt_regs_addr,
				       sizeof(pt_regs), false);
	if (err)
		return err;
	err = get_initial_registers_from_struct_aarch64(prog, &pt_regs,
							sizeof(pt_regs), regs_ret);
	if (err)
		return err;

	drgn_log_debug(prog, "aarch64 fallback: discovered pt_regs 0x%"PRIx64" via %s",
		       pt_regs_addr, method);
	*found_ret = true;
	return NULL;
}

// Unwind using the frame pointer. Note that leaf functions may not allocate a
// stack frame, so this may skip the caller of a leaf function. I don't know of
// a good way around that.
static struct drgn_error *
fallback_unwind_aarch64(struct drgn_program *prog,
		       struct drgn_register_state *regs,
		       struct drgn_register_state **ret)
{

	struct drgn_error *err;

	struct optional_uint64 fp =
		drgn_register_state_get_u64(prog, regs, x29);
	if (!fp.has_value)
		return &drgn_stop;

	// The frame pointer points to a frame record of two 64-bit values. The
	// first (lowest addressed) is the address of the caller's frame record.
	// The second (highest addressed) is the saved lr.
	uint64_t frame[2];
	err = drgn_program_read_memory(prog, frame, fp.value, sizeof(frame),
				       false);
	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			drgn_error_destroy(err);
			err = &drgn_stop;
		}
		return err;
	}

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		bool found;
		err = fallback_unwind_try_pt_regs(prog, fp.value, frame, regs, ret, &found);
		if (err) {
			// If we encounter any error trying the pt_regs
			// approach, log it at the debug level and continue.
			// It's likely an expected error, but could be useful
			// debugging information.
			drgn_error_log_debug(prog, err, "encountered error in linux fallback unwinder:");
			drgn_error_destroy(err);
			err = NULL;
		} else if (found) {
			// We have set the register state based on a pt_regs
			// frame we found, return!
			return NULL;
		}
	}

	uint64_t unwound_fp =
		drgn_platform_bswap(&prog->platform) ?
		bswap_64(frame[0]) : frame[0];
	if (unwound_fp <= fp.value) {
		// The unwound stack pointer is either 0, indicating the first
		// stack frame, or invalid.
		return &drgn_stop;
	}

	struct drgn_register_state *unwound =
		drgn_register_state_create(x30, false);
	if (!unwound)
		return &drgn_enomem;
	drgn_register_state_set_from_buffer(unwound, x30, &frame[1]);
	drgn_register_state_set_from_buffer(unwound, x29, &frame[0]);
	// We don't know whether the return address is signed, so just assume
	// that it is if pointer authentication is enabled. If we're wrong, the
	// worst that can happen is that we'll "correct" incorrect sign
	// extension bits or clear an address tag.
	if (prog->aarch64_insn_pac_mask) {
		drgn_register_state_set_from_u64(prog, unwound, ra_sign_state,
						 1);
		demangle_cfi_registers_aarch64(prog, unwound);
	}
	drgn_register_state_set_pc_from_register(prog, unwound, x30);
	// The location of the frame record within the stack frame is not
	// specified, so we can't determine the stack pointer.
	*ret = unwound;
	return NULL;
}

// Unwind a single bl or blr instruction.
static struct drgn_error *
bad_call_unwind_aarch64(struct drgn_program *prog,
			struct drgn_register_state *regs,
			struct drgn_register_state **ret)
{
	struct optional_uint64 lr =
		drgn_register_state_get_u64(prog, regs, x30);
	if (!lr.has_value)
		return &drgn_stop;

	struct drgn_register_state *tmp = drgn_register_state_dup(regs);
	if (!tmp)
		return &drgn_enomem;

	// lr contains the the old pc + 4.
	drgn_register_state_set_pc(prog, tmp, lr.value - 4);
	// We don't know the old lr.
	drgn_register_state_unset_has_register(tmp, DRGN_REGISTER_NUMBER(x30));
	// The interrupted pc is no longer applicable.
	drgn_register_state_unset_has_register(tmp, DRGN_REGISTER_NUMBER(pc));
	*ret = tmp;
	return NULL;
}

static struct drgn_error *
pt_regs_get_initial_registers_aarch64(const struct drgn_object *obj,
				      struct drgn_register_state **ret)
{
	return get_initial_registers_from_struct_aarch64(drgn_object_program(obj),
							 drgn_object_buffer(obj),
							 drgn_object_size(obj),
							 ret);
}

static struct drgn_error *
prstatus_get_initial_registers_aarch64(struct drgn_program *prog,
				       const void *prstatus, size_t size,
				       struct drgn_register_state **ret)
{
	// offsetof(struct elf_prstatus, pr_reg)
	static const size_t pr_reg_offset = 112;
	if (size < pr_reg_offset) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "NT_PRSTATUS is truncated");
	}
	return get_initial_registers_from_struct_aarch64(prog,
							 (char *)prstatus + pr_reg_offset,
							 size - pr_reg_offset,
							 ret);
}

// The Linux kernel saves the callee-saved registers in
// struct task_struct.thread.cpu_context (with type struct cpu_context). See
// cpu_switch_to() in arch/arm64/kernel/entry.S (as of Linux v5.19).
static struct drgn_error *
linux_kernel_get_initial_registers_aarch64(const struct drgn_object *task_obj,
					   struct drgn_register_state **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(task_obj);

	DRGN_OBJECT(cpu_context_obj, prog);

	err = drgn_object_member_dereference(&cpu_context_obj, task_obj,
					     "thread");
	if (err)
		return err;
	err = drgn_object_member(&cpu_context_obj, &cpu_context_obj,
				 "cpu_context");
	if (err)
		return err;
	if (cpu_context_obj.encoding != DRGN_OBJECT_ENCODING_BUFFER ||
	    drgn_object_size(&cpu_context_obj) < 104) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cpu_context is truncated");
	}
	err = drgn_object_read(&cpu_context_obj, &cpu_context_obj);
	if (err)
		return err;

	const void *buf = drgn_object_buffer(&cpu_context_obj);
	struct drgn_register_state *regs =
		drgn_register_state_create(x30, false);
	if (!regs)
		return &drgn_enomem;

	drgn_register_state_set_from_buffer(regs, x30, (uint64_t *)buf + 12);
	drgn_register_state_set_from_buffer(regs, sp, (uint64_t *)buf + 11);
	drgn_register_state_set_range_from_buffer(regs, x19, x29, buf);
	drgn_register_state_set_pc_from_register(prog, regs, x30);
	*ret = regs;
	return NULL;
}

static struct drgn_error *
apply_elf_reloc_aarch64(const struct drgn_relocating_section *relocating,
			uint64_t r_offset, uint32_t r_type, const int64_t *r_addend,
			uint64_t sym_value)
{
	switch (r_type) {
	case R_AARCH64_NONE:
		return NULL;
	case R_AARCH64_ABS64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value);
	case R_AARCH64_ABS32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	case R_AARCH64_ABS16:
		return drgn_reloc_add16(relocating, r_offset, r_addend,
					sym_value);
	case R_AARCH64_PREL64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	case R_AARCH64_PREL32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	case R_AARCH64_PREL16:
		return drgn_reloc_add16(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	default:
		return DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
	}
}

struct pgtable_iterator_aarch64 {
	struct pgtable_iterator it;
	uint64_t va_bits;
	// Inclusive range of valid virtual addresses.
	uint64_t va_range_min, va_range_max;
	int levels;
	uint16_t entries_per_level;
	uint16_t last_level_num_entries;
	uint64_t cached_virt_addr;
	uint64_t table[5];
	uint64_t pa_low_mask;
	uint64_t pa_high_mask;
	int pa_high_shift;
};

static struct drgn_error *
linux_kernel_pgtable_iterator_create_aarch64(struct drgn_program *prog,
					     struct pgtable_iterator **ret)
{
	const uint64_t page_shift = prog->vmcoreinfo.page_shift;
	if (page_shift != 12 && page_shift != 14 && page_shift != 16) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "unknown page size for virtual address translation");
	}
	const uint64_t pgtable_shift = page_shift - 3;

	// VA_BITS in VMCOREINFO, added in Linux kernel commit 20a166243328
	// ("arm64: kdump: add VMCOREINFO's for user-space tools") (in v4.12),
	// is the configured virtual address size. Since Linux kernel commit
	// b6d00d47e81a ("arm64: mm: Introduce 52-bit Kernel VAs") (in v5.4), it
	// may be greater than the actual size used at runtime if the kernel is
	// configured with 52-bit virtual addresses but the hardware does not
	// support it. 64 - TCR_EL1_T1SZ, added in Linux kernel commit
	// bbdbc11804ff ("arm64/crash_core: Export TCR_EL1.T1SZ in vmcoreinfo")
	// (in v5.9), is the size used at runtime.
	//
	// With 64k pages, if 52-bit virtual addresses are not supported
	// (Armv8.2 FEAT_LVA), then the kernel falls back to 48-bit virtual
	// addresses. Note that the page table has 3 levels with either size. In
	// this case, swapper_pg_dir is still set up for 52-bit virtual
	// addresses (an offset is applied when loading swapper_pg_dir into
	// TTBR1; see Linux kernel commit c812026c54cf ("arm64: mm: Logic to
	// make offset_ttbr1 conditional") (in v5.4)). So, with 64k pages, we
	// need to treat kernel addresses as if they have size VA_BITS for the
	// purposes of translating using swapper_pg_dir. We can also treat user
	// addresses as if they have size VA_BITS. In the 52- to 48-bit fallback
	// case, the additional user virtual address bits [51:48] are zero, so
	// the page table is accessed identically.
	//
	// With 4k or 16k pages, if 52-bit virtual addresses are not supported
	// (Armv8.7 FEAT_LPA2), then the kernel falls back to 48-bit virtual
	// addresses with 4k pages or 47-bit virtual addresses with 16k pages;
	// see Linux kernel commit 0dd4f60a2c76 ("arm64: mm: Add support for
	// folding PUDs at runtime") (in v6.9). This decreases the number of
	// page table levels (from 5 to 4 for 4k pages and from 4 to 3 for 16k
	// pages). In this case, we need to use the actual size for both kernel
	// and user addresses, 64 - TCR_EL1_T1SZ.
	uint64_t va_bits;
	if (page_shift == 16 || !prog->vmcoreinfo.tcr_el1_t1sz)
		va_bits = prog->vmcoreinfo.va_bits;
	else
		va_bits = 64 - prog->vmcoreinfo.tcr_el1_t1sz;
	if (va_bits <= page_shift || va_bits > 52) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "VMCOREINFO does not contain valid TCR_EL1_T1SZ or VA_BITS");
	}

	struct pgtable_iterator_aarch64 *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;

	it->va_bits = va_bits;
	it->levels = ((va_bits - page_shift + pgtable_shift - 1) /
		      pgtable_shift);
	assert(it->levels <= array_size(it->table));
	it->entries_per_level = 1 << pgtable_shift;
	it->last_level_num_entries =
		1 << ((va_bits - page_shift - 1) % pgtable_shift + 1);

	// Descriptor bits [47:PAGE_SHIFT] contain physical address bits
	// [47:PAGE_SHIFT].
	//
	// For 52-bit physical addresses, physical address bits [51:48] come
	// from elsewhere.
	//
	// With 64k pages and 52-bit physical addresses (Armv8.2 FEAT_LPA),
	// descriptor bits [15:12] contain physical address bits [51:48]. With
	// 64k pages and 48-bit physical addresses, descriptor bits [15:12] must
	// be 0. So, if we're using 64k pages, we can always get those bits
	// without knowing the physical address size.
	//
	// With 4k or 16k pages and 52-bit physical addresses (Armv8.7
	// FEAT_LPA2), descriptor bits [49:48] contain physical address bits
	// [49:48] and descriptor bits [9:8] contain physical address bits
	// [51:50]. However, with 4k or 16k pages and 48-bit physical addresses,
	// descriptor bits [9:8] are used for other purposes. We need to know
	// the physical address size, but it is not reported in VMCOREINFO.
	// However, we can check the virtual address size, as with 4k or 16k
	// pages, the kernel requires that it is equal to the physical address
	// size; see Linux kernel commit 352b0395b505 ("arm64: Enable 52-bit
	// virtual addressing for 4k and 16k granule configs") (in v6.9).
	it->pa_low_mask = (UINT64_C(0x0000ffffffffffff)
			   & ~(prog->vmcoreinfo.page_size - 1));
	if (page_shift == 16) {
		it->pa_high_mask = 0xf000;
		it->pa_high_shift = 36;
	} else if (va_bits == 52) {
		it->pa_low_mask |= UINT64_C(0x0003000000000000);
		it->pa_high_mask = 0x300;
		it->pa_high_shift = 42;
	} else {
		it->pa_high_mask = 0x0;
		it->pa_high_shift = 0;
	}

	*ret = &it->it;
	return NULL;
}

static void linux_kernel_pgtable_iterator_destroy_aarch64(struct pgtable_iterator *_it)
{
	struct pgtable_iterator_aarch64 *it =
		container_of(_it, struct pgtable_iterator_aarch64, it);
	free(it);
}

static void linux_kernel_pgtable_iterator_init_aarch64(struct drgn_program *prog,
						       struct pgtable_iterator *_it)
{
	struct pgtable_iterator_aarch64 *it =
		container_of(_it, struct pgtable_iterator_aarch64, it);
	if (it->it.pgtable == prog->vmcoreinfo.swapper_pg_dir) {
		it->va_range_min = UINT64_MAX << it->va_bits;
		it->va_range_max = UINT64_MAX;
	} else {
		it->va_range_min = 0;
		it->va_range_max = (UINT64_C(1) << it->va_bits) - 1;
	}

	it->cached_virt_addr = 0;
	memset(it->table, 0, sizeof(it->table));
}

static struct drgn_error *
linux_kernel_pgtable_iterator_next_aarch64(struct drgn_program *prog,
					   struct pgtable_iterator *_it,
					   uint64_t *virt_addr_ret,
					   uint64_t *phys_addr_ret)
{
	struct drgn_error *err;
	const uint64_t page_shift = prog->vmcoreinfo.page_shift;
	const uint64_t pgtable_shift = page_shift - 3;
	const bool bswap = drgn_platform_bswap(&prog->platform);
	struct pgtable_iterator_aarch64 *it =
		container_of(_it, struct pgtable_iterator_aarch64, it);
	const uint64_t virt_addr = it->it.virt_addr;

	if (virt_addr < it->va_range_min || virt_addr > it->va_range_max) {
		*virt_addr_ret = it->va_range_min;
		*phys_addr_ret = UINT64_MAX;
		it->it.virt_addr = it->va_range_max + 1;
		return NULL;
	}

	uint16_t num_entries = it->last_level_num_entries;
	uint64_t table = it->it.pgtable;
	bool table_physical = false;
	for (int level = it->levels;; level--) {
		uint8_t level_shift = page_shift + pgtable_shift * (level - 1);
		uint16_t index = (virt_addr >> level_shift) & (num_entries - 1);
		uint16_t cached_index = (it->cached_virt_addr >> level_shift) &
					(num_entries - 1);
		if (index != cached_index)
			memset(it->table, 0, 8 * level);
		uint64_t *entry_ptr = &it->table[level - 1];
		if (!*entry_ptr) {
			err = drgn_program_read_memory(prog, entry_ptr,
						       table + 8 * index, 8,
						       table_physical);
			if (err)
				return err;
			if (bswap)
				*entry_ptr = bswap_64(*entry_ptr);
		}
		uint64_t entry = *entry_ptr;

		num_entries = it->entries_per_level;
		table = ((entry & it->pa_low_mask) |
			 (entry & it->pa_high_mask) << it->pa_high_shift);

		// Descriptor bits [1:0] identify the descriptor type:
		//
		// 0x0, 0x2: invalid
		// 0x1: lowest level: reserved, invalid
		//      higher levels: block
		// 0x3: lowest level: page
		//      higher levels: table
		if ((entry & 0x3) != 0x3 || level == 1) {
			uint64_t mask = (UINT64_C(1) << level_shift) - 1;
			*virt_addr_ret = virt_addr & ~mask;
			if ((entry & 0x3) == (level == 1 ? 0x3 : 0x1))
				*phys_addr_ret = table & ~mask;
			else
				*phys_addr_ret = UINT64_MAX;
			it->cached_virt_addr = virt_addr;
			it->it.virt_addr = (virt_addr | mask) + 1;
			return NULL;
		}
		table_physical = true;
	}
}

static int
linux_kernel_section_size_bits_fallback_aarch64(struct drgn_program *prog)
{
	// Since Linux kernel commit f0b13ee23241 ("arm64/sparsemem: reduce
	// SECTION_SIZE_BITS") (in v5.12), SECTION_SIZE_BITS is 29 with 64k
	// pages and 27 otherwise. Linux kernel stable commit 70fd2a63fc1c
	// ("crash_core, vmcoreinfo: append 'SECTION_SIZE_BITS' to vmcoreinfo")
	// (in v5.12.13) addresses this, but before that there's no good way to
	// detect it other than the kernel version.
	char *p = (char *)prog->vmcoreinfo.osrelease;
	long major = strtol(p, &p, 10), minor = 0;
	if (*p == '.')
		minor = strtol(p + 1, &p, 10);
	if (major > 5 || (major == 5 && minor >= 12))
		return prog->vmcoreinfo.page_shift == 16 ? 29 : 27;
	// Before that, it didn't change since Linux kernel commit 4f04d8f00545
	// ("arm64: MMU definitions") (in v3.7).
	return 30;
}

static uint64_t untagged_addr_aarch64(uint64_t addr)
{
	/* Apply TBI by sign extending bit 55 into bits 56-63. */
	return (((int64_t)addr) << 8) >> 8;
}

const struct drgn_architecture_info arch_info_aarch64 = {
	.name = "AArch64",
	.arch = DRGN_ARCH_AARCH64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	.scalar_alignment = { 1, 2, 4, 8, 16 },
	DRGN_ARCHITECTURE_REGISTERS,
	.default_dwarf_cfi_row = &default_dwarf_cfi_row_aarch64,
	.demangle_cfi_registers = demangle_cfi_registers_aarch64,
	.fallback_unwind = fallback_unwind_aarch64,
	.bad_call_unwind = bad_call_unwind_aarch64,
	.pt_regs_get_initial_registers = pt_regs_get_initial_registers_aarch64,
	.prstatus_get_initial_registers = prstatus_get_initial_registers_aarch64,
	.linux_kernel_get_initial_registers =
		linux_kernel_get_initial_registers_aarch64,
	.apply_elf_reloc = apply_elf_reloc_aarch64,
	.linux_kernel_pgtable_iterator_create =
		linux_kernel_pgtable_iterator_create_aarch64,
	.linux_kernel_pgtable_iterator_destroy =
		linux_kernel_pgtable_iterator_destroy_aarch64,
	.linux_kernel_pgtable_iterator_init =
		linux_kernel_pgtable_iterator_init_aarch64,
	.linux_kernel_pgtable_iterator_next =
		linux_kernel_pgtable_iterator_next_aarch64,
	.linux_kernel_section_size_bits_fallback =
		linux_kernel_section_size_bits_fallback_aarch64,
	// MAX_PHYSMEM_BITS depends on CONFIG_ARM64_PA_BITS. Use the default
	// fallback.
	.untagged_addr = untagged_addr_aarch64,
};
