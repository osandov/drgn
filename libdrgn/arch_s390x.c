// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "error.h"
#include "platform.h" // IWYU pragma: associated
#include "register_state.h"

// The ABI specification can be found at https://github.com/IBM/s390x-abi.

#include "arch_s390x_defs.inc"

static const struct drgn_cfi_row default_dwarf_cfi_row_s390x = DRGN_CFI_ROW(
	// Callee-saved registers default to DW_CFA_same_value. This isn't
	// explicitly documented in the psABI, but it seems to be the consensus.
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r6)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r7)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r8)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r9)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r10)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r11)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r12)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r13)),
	// r14 is the return address, which also defaults to DW_CFA_same_value
	// by consensus.
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r14)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r15)),
);

static struct drgn_error *
apply_elf_reloc_s390(const struct drgn_relocating_section *relocating,
		     uint64_t r_offset, uint32_t r_type,
		     const int64_t *r_addend, uint64_t sym_value)
{
	switch (r_type) {
	case R_390_NONE:
		return NULL;
	case R_390_8:
		return drgn_reloc_add8(relocating, r_offset, r_addend,
				       sym_value);
	case R_390_16:
		return drgn_reloc_add16(relocating, r_offset, r_addend,
					sym_value);
	case R_390_32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	case R_390_PC32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	case R_390_PC16:
		return drgn_reloc_add16(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	case R_390_64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value);
	case R_390_PC64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value
					- (relocating->addr + r_offset));
	default:
		return DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
	}
}

static struct drgn_error *
pt_regs_get_initial_registers_s390x_impl(struct drgn_program *prog,
					 const void *buf,
					 struct drgn_register_state **ret)
{
	struct drgn_register_state *regs =
		drgn_register_state_create(pswa, true);
	if (!regs)
		return &drgn_enomem;
	drgn_register_state_set_range_from_buffer(regs, r6, r15,
						  (uint64_t *)buf + 9);
	drgn_register_state_set_range_from_buffer(regs, r0, r5,
						  (uint64_t *)buf + 3);
	drgn_register_state_set_range_from_buffer(regs, pswm, pswa,
						  (uint64_t *)buf + 1);
	drgn_register_state_set_pc_from_register(prog, regs, pswa);
	*ret = regs;
	return NULL;
}

static struct drgn_error *
fallback_unwind_s390x(struct drgn_program *prog,
		      struct drgn_register_state *regs,
		      struct drgn_register_state **ret)
{
	struct drgn_error *err;

	// For userspace, we can't rely on the backchain entry because it is
	// normally compiled without -mbackchain.
	if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL))
		return &drgn_stop;

	// For the Linux kernel, we assume -mpacked-stack.

	struct optional_uint64 r15 = drgn_register_state_get_u64(prog, regs,
								 r15);
	if (!r15.has_value)
		return &drgn_stop;

	static const size_t stack_frame_backchain_offset = 152;
	uint64_t backchain;
	err = drgn_program_read_u64(prog,
				    r15.value + stack_frame_backchain_offset,
				    false, &backchain);
	if (err)
		goto err;

	if (!backchain) {
		// The Linux kernel saves a struct stack_frame with back_chain =
		// 0 and a struct pt_regs on the stack when entering program
		// check handler, irq handlers, or the system call handler.
		uint64_t buf[19];
		err = drgn_program_read_memory(prog, buf, r15.value + 160,
					       sizeof(buf), false);
		if (err)
			goto err;
		return pt_regs_get_initial_registers_s390x_impl(prog, buf, ret);
	}

	// r14 and r15.
	uint64_t buf[2];
	static const size_t stack_frame_r14_offset = 136;
	err = drgn_program_read_memory(prog, buf,
				       backchain + stack_frame_r14_offset,
				       sizeof(buf), false);
	if (err)
		goto err;

	struct drgn_register_state *unwound =
		drgn_register_state_create(r15, false);
	if (!unwound)
		return &drgn_enomem;
	drgn_register_state_set_range_from_buffer(unwound, r14, r15, buf);
	drgn_register_state_set_pc_from_register(prog, unwound, r14);
	*ret = unwound;
	return NULL;

err:
	if (err->code == DRGN_ERROR_FAULT) {
		drgn_error_destroy(err);
		return &drgn_stop;
	}
	return err;
}

static struct drgn_error *
pt_regs_get_initial_registers_s390x(const struct drgn_object *obj,
				    struct drgn_register_state **ret)
{
	if (drgn_object_size(obj) < 152) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "registers are truncated");
	}
	return pt_regs_get_initial_registers_s390x_impl(drgn_object_program(obj),
							drgn_object_buffer(obj),
							ret);
}

// On s390x, elf_gregset_t (a.k.a. s390_regs) is different from struct pt_regs.
static struct drgn_error *
prstatus_get_initial_registers_s390x(struct drgn_program *prog,
				      const void *prstatus, size_t size,
				      struct drgn_register_state **ret)
{
	if (size < 208) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "registers are truncated");
	}

	// offsetof(struct elf_prstatus, pr_reg)
	static const size_t pr_reg_offset = 112;
	const uint64_t *buf =
		(const uint64_t *)((const char *)prstatus + pr_reg_offset);

	struct drgn_register_state *regs =
		drgn_register_state_create(a15, true);
	if (!regs)
		return &drgn_enomem;
	drgn_register_state_set_range_from_buffer(regs, r0, r5, buf + 2);
	drgn_register_state_set_range_from_buffer(regs, r6, r15, buf + 8);
	drgn_register_state_set_range_from_buffer(regs, pswm, pswa, buf);
	drgn_register_state_set_range_from_buffer(regs, a0, a15, buf + 18);
	drgn_register_state_set_pc_from_register(prog, regs, pswa);
	*ret = regs;
	return NULL;
}

// The Linux kernel saves the callee-saved registers in a struct stack_frame and
// saves this address to struct task_struct.thread.ksp. See __switch_to() in
// arch/s390/kernel/entry.S.
static struct drgn_error *
linux_kernel_get_initial_registers_s390x(const struct drgn_object *task_obj,
					 struct drgn_register_state **ret)
{
	struct drgn_program *prog = drgn_object_program(task_obj);
	struct drgn_error *err;

	struct drgn_object ctx;
	drgn_object_init(&ctx, prog);

	err = drgn_object_member_dereference(&ctx, task_obj, "thread");
	if (err)
		goto out;
	err = drgn_object_member(&ctx, &ctx, "ksp");
	if (err)
		goto out;
	uint64_t ksp;
	err = drgn_object_read_unsigned(&ctx, &ksp);
	if (err)
		goto out;

	// r6-r15
	uint64_t buf[10];
	static const size_t stack_frame_gprs_offset = 72;
	err = drgn_program_read_memory(prog, buf, ksp + stack_frame_gprs_offset,
				       sizeof(buf), false);
	if (err)
		goto out;

	struct drgn_register_state *regs =
		drgn_register_state_create(r15, false);
	if (!regs) {
		err = &drgn_enomem;
		goto out;
	}
	drgn_register_state_set_range_from_buffer(regs, r6, r15, buf);
	drgn_register_state_set_pc_from_register(prog, regs, r14);
	*ret = regs;
	err = NULL;
out:
	drgn_object_deinit(&ctx);
	return err;
}

const struct drgn_architecture_info arch_info_s390x = {
	.name = "s390x",
	.arch = DRGN_ARCH_S390X,
	.default_flags = DRGN_PLATFORM_IS_64_BIT,
	DRGN_ARCHITECTURE_REGISTERS,
	.default_dwarf_cfi_row = &default_dwarf_cfi_row_s390x,
	.fallback_unwind = fallback_unwind_s390x,
	.pt_regs_get_initial_registers = pt_regs_get_initial_registers_s390x,
	.prstatus_get_initial_registers = prstatus_get_initial_registers_s390x,
	.linux_kernel_get_initial_registers =
		linux_kernel_get_initial_registers_s390x,
	.apply_elf_reloc = apply_elf_reloc_s390,

};

const struct drgn_architecture_info arch_info_s390 = {
	.name = "s390",
	.arch = DRGN_ARCH_S390,
	.default_flags = 0,
	.register_by_name = drgn_register_by_name_unknown,
	.apply_elf_reloc = apply_elf_reloc_s390,
};
