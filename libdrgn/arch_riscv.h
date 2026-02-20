// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_ARCH_RISCV_H
#define DRGN_ARCH_RISCV_H

#include <byteswap.h>
#include <elf.h>
#include <string.h>

#include "cfi.h"
#include "error.h"
#include "platform.h" // IWYU pragma: associated
#include "program.h"
#include "register_state.h"

/*
 * The ABI specification can be found at:
 * https://github.com/riscv-non-isa/riscv-elf-psabi-doc
 */

static const struct drgn_cfi_row default_dwarf_cfi_row_riscv = DRGN_CFI_ROW(
	// The psABI defines the CFA as the value of sp in the calling frame.
	[DRGN_REGISTER_NUMBER(x2)] = { DRGN_CFI_RULE_CFA_PLUS_OFFSET },
	// Callee-saved registers default to DW_CFA_same_value. This isn't
	// explicitly documented in the psABI, but it seems to be the consensus.
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x8)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x9)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x18)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x19)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x20)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x21)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x22)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x23)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x24)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x25)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x26)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(x27)),
);

// elf_gregset_t (in PRSTATUS) and struct user_pt_regs have the same layout.
// This layout is a prefix of the in-kernel struct pt_regs (but we don't care
// about any of the extra fields).
static struct drgn_error *
get_initial_registers_from_struct_riscv(struct drgn_program *prog,
					const void *buf, size_t size,
					struct drgn_register_state **ret)
{
	size_t reg_size = DRGN_REGISTER_SIZE(pc);
	if (size < 32 * reg_size) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "registers are truncated");
	}

	struct drgn_register_state *regs =
		drgn_register_state_create(pc, true);
	if (!regs)
		return &drgn_enomem;

	drgn_register_state_set_from_buffer(regs, pc, buf);
	drgn_register_state_set_from_buffer(regs, x2,
					    (const char *)buf + 2 * reg_size);
	drgn_register_state_set_range_from_buffer(regs, x5, x31,
						  (const char *)buf + 5 * reg_size);
	drgn_register_state_set_pc_from_register(prog, regs, pc);

	*ret = regs;
	return NULL;
}

static struct drgn_error *
fallback_unwind_riscv(struct drgn_program *prog,
		      struct drgn_register_state *regs,
		      struct drgn_register_state **ret)
{
	struct drgn_error *err;
	size_t reg_size = DRGN_REGISTER_SIZE(x8);

	// The frame pointer is not required by the psABI, but is used in practice.
	struct optional_uint64 fp =
		drgn_register_state_get_u64(prog, regs, x8);
	if (!fp.has_value)
		return &drgn_stop;

	// The frame pointer points to a frame record of two values (sized by
	// register width). The first (lowest addressed) is the address of the
	// caller's frame record. The second (highest addressed) is the saved
	// return address.
	char frame[16]; // Large enough for two 64-bit values
	err = drgn_program_read_memory(prog, frame, fp.value, 2 * reg_size,
				       false);

	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			drgn_error_destroy(err);
			err = &drgn_stop;
		}
		return err;
	}

	uint64_t unwound_fp;
	if (reg_size == 8) {
		unwound_fp = drgn_platform_bswap(&prog->platform) ?
			bswap_64(*(uint64_t *)frame) : *(uint64_t *)frame;
	} else {
		unwound_fp = drgn_platform_bswap(&prog->platform) ?
			bswap_32(*(uint32_t *)frame) : *(uint32_t *)frame;
	}

	if (unwound_fp <= fp.value) {
		// The unwound stack pointer is either 0, indicating the first
		// stack frame, or invalid.
		return &drgn_stop;
	}

	struct drgn_register_state *unwound =
		drgn_register_state_create(x8, false);
	if (!unwound)
		return &drgn_enomem;

	drgn_register_state_set_from_buffer(unwound, x1, frame + reg_size);
	drgn_register_state_set_from_buffer(unwound, x8, frame);
	drgn_register_state_set_pc_from_register(prog, unwound, x1);
	// The psABI says the frame pointer points to the CFA, which is the
	// stack pointer value on entry to the current procedure. So the
	// caller's stack pointer at the call site is the current frame's fp.
	drgn_register_state_set_from_u64(prog, unwound, x2, fp.value);
	*ret = unwound;
	return NULL;
}

// Unwind a single jal or jalr instruction.
static struct drgn_error *
bad_call_unwind_riscv(struct drgn_program *prog,
		      struct drgn_register_state *regs,
		      struct drgn_register_state **ret)
{
	struct drgn_error *err;

	// The ABI does not require the return address to be in x1, but it generally
	// is by convention.
	struct optional_uint64 ra = drgn_register_state_get_u64(prog, regs, x1);
	if (!ra.has_value)
		return &drgn_stop;

	struct drgn_register_state *tmp = drgn_register_state_dup(regs);
	if (!tmp)
		return &drgn_enomem;

	// Get size of previous instruction by reading the instruction packet (previous 2 bytes)
	// before ra.
	uint16_t inst_packet;
	err = drgn_program_read_memory(prog, &inst_packet, ra.value - 2, sizeof(inst_packet),
				 false);
	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			drgn_error_destroy(err);
			err = &drgn_stop;
		}
		return err;
	}

	// Instruction is 4 bytes if opcode ends in 0b11 and 2 bytes otherwise
	uint32_t inst_size = (inst_packet & 0b11) == 0b11 ? 4 : 2;
	// ra contains the old pc + size of instruction at old pc.
	drgn_register_state_set_pc(prog, tmp, ra.value - inst_size);
	// We don't know the old ra.
	drgn_register_state_unset_has_register(tmp, DRGN_REGISTER_NUMBER(x1));
	// The interrupted pc is no longer applicable.
	drgn_register_state_unset_has_register(tmp, DRGN_REGISTER_NUMBER(pc));
	*ret = tmp;
	return NULL;
}

static struct drgn_error *
pt_regs_get_initial_registers_riscv(const struct drgn_object *obj,
				    struct drgn_register_state **ret)
{
	return get_initial_registers_from_struct_riscv(drgn_object_program(obj),
						       drgn_object_buffer(obj),
						       drgn_object_size(obj),
						       ret);
}

static struct drgn_error *
prstatus_get_initial_registers_riscv(struct drgn_program *prog,
				     const void *prstatus, size_t size,
				     struct drgn_register_state **ret)
{
	// offsetof(struct elf_prstatus, pr_reg)
	static const size_t pr_reg_offset = 112;
	if (size < pr_reg_offset) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "NT_PRSTATUS is truncated");
	}
	return get_initial_registers_from_struct_riscv(prog,
						       (const char *)prstatus + pr_reg_offset,
						       size - pr_reg_offset,
						       ret);
}

// The Linux kernel saves the callee-saved registers in
// struct task_struct.thread.
static struct drgn_error *
linux_kernel_get_initial_registers_riscv(const struct drgn_object *task_obj,
					 struct drgn_register_state **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(task_obj);
	size_t reg_size = DRGN_REGISTER_SIZE(x1);

	DRGN_OBJECT(thread_obj, prog);

	err = drgn_object_member_dereference(&thread_obj, task_obj,
					     "thread");
	if (err)
		return err;

	if (thread_obj.encoding != DRGN_OBJECT_ENCODING_BUFFER ||
	    drgn_object_size(&thread_obj) < 14 * reg_size) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "thread is truncated");
	}
	err = drgn_object_read(&thread_obj, &thread_obj);
	if (err)
		return err;

	const char *buf = drgn_object_buffer(&thread_obj);
	struct drgn_register_state *regs =
		drgn_register_state_create(x27, false);
	if (!regs)
		return &drgn_enomem;

	drgn_register_state_set_from_buffer(regs, x1, buf);
	drgn_register_state_set_from_buffer(regs, x2, buf + reg_size);
	drgn_register_state_set_range_from_buffer(regs, x8, x9, buf + 2 * reg_size);
	drgn_register_state_set_range_from_buffer(regs, x18, x27, buf + 4 * reg_size);
	drgn_register_state_set_pc_from_register(prog, regs, x1);
	*ret = regs;
	return NULL;
}

static struct drgn_error drgn_invalid_rel = {
	.code = DRGN_ERROR_OTHER,
	.message = "invalid relocation type for SHT_REL",
};

static struct drgn_error *
apply_elf_reloc_riscv(const struct drgn_relocating_section *relocating,
		      uint64_t r_offset, uint32_t r_type, const int64_t *r_addend,
		      uint64_t sym_value)
{
	switch (r_type) {
	case R_RISCV_NONE:
		return NULL;
	case R_RISCV_32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	case R_RISCV_64:
		return drgn_reloc_add64(relocating, r_offset, r_addend,
					sym_value);
#define CASE_R_RISCV_ADD_SUB(bits)						\
	case R_RISCV_ADD##bits: {						\
		if (!r_addend)							\
			return &drgn_invalid_rel;				\
		uint##bits##_t value;						\
		if (r_offset > relocating->buf_size ||				\
		    relocating->buf_size - r_offset < sizeof(value))		\
			return &drgn_invalid_relocation_offset;			\
		memcpy(&value, relocating->buf + r_offset, sizeof(value));	\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
		value += sym_value + *r_addend;					\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
		memcpy(relocating->buf + r_offset, &value, sizeof(value));	\
		return NULL;							\
	}									\
	case R_RISCV_SUB##bits: {						\
		if (!r_addend)							\
			return &drgn_invalid_rel;				\
		uint##bits##_t value;						\
		if (r_offset > relocating->buf_size ||				\
		    relocating->buf_size - r_offset < sizeof(value))		\
			return &drgn_invalid_relocation_offset;			\
		memcpy(&value, relocating->buf + r_offset, sizeof(value));	\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
		value -= sym_value + *r_addend;					\
		if (relocating->bswap)						\
			value = bswap_##bits(value);				\
		memcpy(relocating->buf + r_offset, &value, sizeof(value));	\
		return NULL;							\
	}
#define bswap_8(x) (x)
	CASE_R_RISCV_ADD_SUB(8)
#undef bswap_8
	CASE_R_RISCV_ADD_SUB(16)
	CASE_R_RISCV_ADD_SUB(32)
	CASE_R_RISCV_ADD_SUB(64)
#undef CASE_R_RISCV_ADD_SUB
	case R_RISCV_SUB6: {
		if (!r_addend)
			return &drgn_invalid_rel;
		uint8_t value;
		if (r_offset > relocating->buf_size ||
		    relocating->buf_size - r_offset < sizeof(value))
			return &drgn_invalid_relocation_offset;
		memcpy(&value, relocating->buf + r_offset, sizeof(value));
		value = ((value & 0xc0) |
			 (((value & 0x3f) - (sym_value + *r_addend)) & 0x3f));
		memcpy(relocating->buf + r_offset, &value, sizeof(value));
		return NULL;
	}
	case R_RISCV_SET6: {
		if (!r_addend)
			return &drgn_invalid_rel;
		uint8_t value;
		if (r_offset > relocating->buf_size ||
		    relocating->buf_size - r_offset < sizeof(value))
			return &drgn_invalid_relocation_offset;
		memcpy(&value, relocating->buf + r_offset, sizeof(value));
		value = (value & 0xc0) | ((sym_value + *r_addend) & 0x3f);
		memcpy(relocating->buf + r_offset, &value, sizeof(value));
		return NULL;
	}
	case R_RISCV_SET8:
		return drgn_reloc_add8(relocating, r_offset, r_addend,
				       sym_value);
	case R_RISCV_SET16:
		return drgn_reloc_add16(relocating, r_offset, r_addend,
					sym_value);
	case R_RISCV_SET32:
		return drgn_reloc_add32(relocating, r_offset, r_addend,
					sym_value);
	default:
		return DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
	}
}

#endif /* DRGN_ARCH_RISCV_H */
