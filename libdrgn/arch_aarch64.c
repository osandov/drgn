// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "error.h"
#include "register_state.h"
#include "platform.h" // IWYU pragma: associated

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

// Mask out the pointer authentication code if the return address is signed.
static void demangle_return_address_aarch64(struct drgn_program *prog,
					    struct drgn_register_state *regs,
					    drgn_register_number regno)
{
	struct optional_uint64 ra_sign_state =
		drgn_register_state_get_u64(prog, regs, ra_sign_state);
	if (!ra_sign_state.has_value || !(ra_sign_state.value & 1))
		return;
	struct optional_uint64 ra =
		drgn_register_state_get_u64_impl(prog, regs, regno,
						 register_layout[regno].offset,
						 register_layout[regno].size);
	assert(ra.has_value);
	if (ra.value & (UINT64_C(1) << 55))
		ra.value |= prog->aarch64_insn_pac_mask;
	else
		ra.value &= ~prog->aarch64_insn_pac_mask;
	drgn_register_state_set_from_u64_impl(prog, regs, regno,
					      register_layout[regno].offset,
					      register_layout[regno].size,
					      ra.value);
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
		demangle_return_address_aarch64(prog, unwound,
						DRGN_REGISTER_NUMBER(x30));
	}
	drgn_register_state_set_pc_from_register(prog, unwound, x30);
	// The location of the frame record within the stack frame is not
	// specified, so we can't determine the stack pointer.
	*ret = unwound;
	return NULL;
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

	struct drgn_object cpu_context_obj;
	drgn_object_init(&cpu_context_obj, prog);

	err = drgn_object_member_dereference(&cpu_context_obj, task_obj,
					     "thread");
	if (err)
		goto out;
	err = drgn_object_member(&cpu_context_obj, &cpu_context_obj,
				 "cpu_context");
	if (err)
		goto out;
	if (cpu_context_obj.encoding != DRGN_OBJECT_ENCODING_BUFFER ||
	    drgn_object_size(&cpu_context_obj) < 104) {
		err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					"cpu_context is truncated");
		goto out;
	}
	err = drgn_object_read(&cpu_context_obj, &cpu_context_obj);
	if (err)
		goto out;

	const void *buf = drgn_object_buffer(&cpu_context_obj);
	struct drgn_register_state *regs =
		drgn_register_state_create(x30, false);
	if (!regs) {
		err = &drgn_enomem;
		goto out;
	}

	drgn_register_state_set_from_buffer(regs, x30, (uint64_t *)buf + 12);
	drgn_register_state_set_from_buffer(regs, sp, (uint64_t *)buf + 11);
	drgn_register_state_set_range_from_buffer(regs, x19, x29, buf);
	drgn_register_state_set_pc_from_register(prog, regs, x30);
	*ret = regs;
out:
	drgn_object_deinit(&cpu_context_obj);
	return err;
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

const struct drgn_architecture_info arch_info_aarch64 = {
	.name = "AArch64",
	.arch = DRGN_ARCH_AARCH64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	DRGN_ARCHITECTURE_REGISTERS,
	.default_dwarf_cfi_row = &default_dwarf_cfi_row_aarch64,
	.fallback_unwind = fallback_unwind_aarch64,
	.demangle_return_address = demangle_return_address_aarch64,
	.pt_regs_get_initial_registers = pt_regs_get_initial_registers_aarch64,
	.prstatus_get_initial_registers = prstatus_get_initial_registers_aarch64,
	.linux_kernel_get_initial_registers =
		linux_kernel_get_initial_registers_aarch64,
	.apply_elf_reloc = apply_elf_reloc_aarch64,
};
