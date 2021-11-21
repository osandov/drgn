// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <byteswap.h>
#include <elf.h>
#include <inttypes.h>
#include <string.h>

#include "array.h"
#include "drgn.h"
#include "error.h"
#include "linux_kernel.h"
#include "orc.h"
#include "platform.h" // IWYU pragma: associated
#include "program.h"
#include "register_state.h"
#include "serialize.h"
#include "type.h"
#include "util.h"

#define DRGN_ARCH_REGISTER_LAYOUT					\
	/* The psABI calls this the return address (RA) register. */	\
	DRGN_REGISTER_LAYOUT(rip, 8, 16)				\
	DRGN_REGISTER_LAYOUT(rsp, 8, 7)					\
	/* The remaining layout matches struct pt_regs. */		\
	DRGN_REGISTER_LAYOUT(r15, 8, 15)				\
	DRGN_REGISTER_LAYOUT(r14, 8, 14)				\
	DRGN_REGISTER_LAYOUT(r13, 8, 13)				\
	DRGN_REGISTER_LAYOUT(r12, 8, 12)				\
	DRGN_REGISTER_LAYOUT(rbp, 8, 6)					\
	DRGN_REGISTER_LAYOUT(rbx, 8, 3)					\
	DRGN_REGISTER_LAYOUT(r11, 8, 11)				\
	DRGN_REGISTER_LAYOUT(r10, 8, 10)				\
	DRGN_REGISTER_LAYOUT(r9, 8, 9)					\
	DRGN_REGISTER_LAYOUT(r8, 8, 8)					\
	DRGN_REGISTER_LAYOUT(rax, 8, 0)					\
	DRGN_REGISTER_LAYOUT(rcx, 8, 2)					\
	DRGN_REGISTER_LAYOUT(rdx, 8, 1)					\
	DRGN_REGISTER_LAYOUT(rsi, 8, 4)					\
	DRGN_REGISTER_LAYOUT(rdi, 8, 5)

#include "arch_x86_64.inc"

static const struct drgn_cfi_row default_dwarf_cfi_row_x86_64 = DRGN_CFI_ROW(
	/*
	 * The System V psABI defines the CFA as the value of rsp in the calling
	 * frame.
	 */
	[DRGN_REGISTER_NUMBER(rsp)] = { DRGN_CFI_RULE_CFA_PLUS_OFFSET },
	/*
	 * Other callee-saved registers default to DW_CFA_same_value. This isn't
	 * explicitly documented in the psABI, but it seems to be the consensus.
	 */
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(rbx)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(rbp)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r12)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r13)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r14)),
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(r15)),
);

static struct drgn_error *
orc_to_cfi_x86_64(const struct drgn_orc_entry *orc,
		  struct drgn_cfi_row **row_ret, bool *interrupted_ret,
		  drgn_register_number *ret_addr_regno_ret)
{
	enum {
		ORC_REG_UNDEFINED = 0,
		ORC_REG_PREV_SP = 1,
		ORC_REG_DX = 2,
		ORC_REG_DI = 3,
		ORC_REG_BP = 4,
		ORC_REG_SP = 5,
		ORC_REG_R10 = 6,
		ORC_REG_R13 = 7,
		ORC_REG_BP_INDIRECT = 8,
		ORC_REG_SP_INDIRECT = 9,
	};

	if (!drgn_cfi_row_copy(row_ret, drgn_empty_cfi_row))
		return &drgn_enomem;

	struct drgn_cfi_rule rule;
	switch (drgn_orc_sp_reg(orc)) {
	case ORC_REG_UNDEFINED:
		if (drgn_orc_is_end(orc))
			return NULL;
		else
			return &drgn_not_found;
	case ORC_REG_SP:
		rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(rsp);
		rule.offset = orc->sp_offset;
		break;
	case ORC_REG_BP:
		rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(rbp);
		rule.offset = orc->sp_offset;
		break;
	case ORC_REG_SP_INDIRECT:
		rule.kind = DRGN_CFI_RULE_AT_REGISTER_ADD_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(rbp);
		rule.offset = orc->sp_offset;
		break;
	case ORC_REG_BP_INDIRECT:
		rule.kind = DRGN_CFI_RULE_AT_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(rbp);
		rule.offset = orc->sp_offset;
		break;
	case ORC_REG_R10:
		rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(r10);
		rule.offset = 0;
		break;
	case ORC_REG_R13:
		rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(r13);
		rule.offset = 0;
		break;
	case ORC_REG_DI:
		rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(rdi);
		rule.offset = 0;
		break;
	case ORC_REG_DX:
		rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(rdx);
		rule.offset = 0;
		break;
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown ORC SP base register %d",
					 drgn_orc_sp_reg(orc));
	}
	if (!drgn_cfi_row_set_cfa(row_ret, &rule))
		return &drgn_enomem;

	switch (drgn_orc_type(orc)) {
	case DRGN_ORC_TYPE_CALL:
		rule.kind = DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET;
		rule.offset = -8;
		if (!drgn_cfi_row_set_register(row_ret,
					       DRGN_REGISTER_NUMBER(rip),
					       &rule))
			return &drgn_enomem;
		rule.kind = DRGN_CFI_RULE_CFA_PLUS_OFFSET;
		rule.offset = 0;
		if (!drgn_cfi_row_set_register(row_ret,
					       DRGN_REGISTER_NUMBER(rsp),
					       &rule))
			return &drgn_enomem;
		*interrupted_ret = false;
		break;
#define SET_AT_CFA_RULE(reg, cfa_offset) do {					\
	rule.kind = DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET;				\
	rule.offset = cfa_offset;						\
	if (!drgn_cfi_row_set_register(row_ret, DRGN_REGISTER_NUMBER(reg),	\
				       &rule))					\
		return &drgn_enomem;						\
} while (0)
	case DRGN_ORC_TYPE_REGS:
		SET_AT_CFA_RULE(rip, 128);
		SET_AT_CFA_RULE(rsp, 152);
		SET_AT_CFA_RULE(r15, 0);
		SET_AT_CFA_RULE(r14, 8);
		SET_AT_CFA_RULE(r13, 16);
		SET_AT_CFA_RULE(r12, 24);
		SET_AT_CFA_RULE(rbp, 32);
		SET_AT_CFA_RULE(rbx, 40);
		SET_AT_CFA_RULE(r11, 48);
		SET_AT_CFA_RULE(r10, 56);
		SET_AT_CFA_RULE(r9, 64);
		SET_AT_CFA_RULE(r8, 72);
		SET_AT_CFA_RULE(rax, 80);
		SET_AT_CFA_RULE(rcx, 88);
		SET_AT_CFA_RULE(rdx, 96);
		SET_AT_CFA_RULE(rsi, 104);
		SET_AT_CFA_RULE(rdi, 112);
		*interrupted_ret = true;
		break;
	case DRGN_ORC_TYPE_REGS_PARTIAL:
		SET_AT_CFA_RULE(rip, 0);
		SET_AT_CFA_RULE(rsp, 24);
#undef SET_AT_CFA_RULE
#define SET_SAME_VALUE_RULE(reg) do {						\
	rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;				\
	rule.regno = DRGN_REGISTER_NUMBER(reg);					\
	rule.offset = 0;							\
	if (!drgn_cfi_row_set_register(row_ret, DRGN_REGISTER_NUMBER(reg),	\
				       &rule))					\
		return &drgn_enomem;						\
} while (0)
		/*
		 * This ORC entry is for an interrupt handler before it saves
		 * the whole pt_regs. These registers are not clobbered before
		 * they are saved, so they should have the same value. See Linux
		 * kernel commit 81b67439d147 ("x86/unwind/orc: Fix premature
		 * unwind stoppage due to IRET frames").
		 *
		 * This probably also applies to other registers, but to stay on
		 * the safe side we only handle registers used by ORC.
		 */
		SET_SAME_VALUE_RULE(r10);
		SET_SAME_VALUE_RULE(r13);
		SET_SAME_VALUE_RULE(rdi);
		SET_SAME_VALUE_RULE(rdx);
#undef SET_SAME_VALUE_RULE
		*interrupted_ret = true;
		break;
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown ORC entry type %d",
					 drgn_orc_type(orc));
	}

	switch (drgn_orc_bp_reg(orc)) {
	case ORC_REG_UNDEFINED:
		rule.kind = DRGN_CFI_RULE_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(rbp);
		rule.offset = 0;
		break;
	case ORC_REG_PREV_SP:
		rule.kind = DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET;
		rule.offset = orc->bp_offset;
		break;
	case ORC_REG_BP:
		rule.kind = DRGN_CFI_RULE_AT_REGISTER_PLUS_OFFSET;
		rule.regno = DRGN_REGISTER_NUMBER(rbp);
		rule.offset = orc->bp_offset;
		break;
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unknown ORC BP base register %d",
					 drgn_orc_bp_reg(orc));
	}
	if (!drgn_cfi_row_set_register(row_ret, DRGN_REGISTER_NUMBER(rbp),
				       &rule))
		return &drgn_enomem;
	*ret_addr_regno_ret = DRGN_REGISTER_NUMBER(rip);
	return NULL;
}

static struct drgn_error *
get_registers_from_frame_pointer(struct drgn_program *prog,
				 uint64_t frame_pointer,
				 struct drgn_register_state **ret)
{
	struct drgn_error *err;
	uint64_t frame[2];
	err = drgn_program_read_memory(prog, frame, frame_pointer,
				       sizeof(frame), false);
	if (err)
		return err;

	uint64_t unwound_frame_pointer =
		drgn_platform_bswap(&prog->platform) ? bswap_64(frame[0]) : frame[0];
	if (unwound_frame_pointer <= frame_pointer) {
		/*
		 * The next frame pointer isn't valid. Maybe frame pointers are
		 * not enabled or we're in the middle of a prologue or epilogue.
		 */
		return &drgn_stop;
	}

	struct drgn_register_state *regs =
		drgn_register_state_create(rbp, false);
	if (!regs)
		return &drgn_enomem;
	drgn_register_state_set_from_buffer(regs, rip, &frame[1]);
	drgn_register_state_set_from_integer(prog, regs, rsp,
					     frame_pointer + sizeof(frame));
	drgn_register_state_set_from_buffer(regs, rbp, &frame[0]);
	drgn_register_state_set_pc_from_register(prog, regs, rip);
	*ret = regs;
	return NULL;
}

static struct drgn_error *
fallback_unwind_x86_64(struct drgn_program *prog,
		       struct drgn_register_state *regs,
		       struct drgn_register_state **ret)
{
	struct drgn_error *err;

	if (!drgn_register_state_has_register(regs, DRGN_REGISTER_NUMBER(rbp)))
		return &drgn_stop;
	bool little_endian = drgn_platform_is_little_endian(&prog->platform);
	uint64_t rbp;
	copy_lsbytes(&rbp, sizeof(rbp), HOST_LITTLE_ENDIAN,
		     &regs->buf[DRGN_REGISTER_OFFSET(rbp)],
		     DRGN_REGISTER_SIZE(rbp), little_endian);

	err = get_registers_from_frame_pointer(prog, rbp, ret);
	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			drgn_error_destroy(err);
			err = &drgn_stop;
		}
		return err;
	}
	drgn_register_state_set_cfa(prog, regs, rbp + 16);
	return NULL;
}

/*
 * The in-kernel struct pt_regs, UAPI struct pt_regs, elf_gregset_t, and struct
 * user_regs_struct all have the same layout.
 */
static struct drgn_error *
get_initial_registers_from_struct_x86_64(struct drgn_program *prog,
					 const void *buf, size_t size,
					 struct drgn_register_state **ret)
{
	if (size < 160) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "registers are truncated");
	}

	struct drgn_register_state *regs =
		drgn_register_state_create(rdi, true);
	if (!regs)
		return &drgn_enomem;

	drgn_register_state_set_from_buffer(regs, rip, (uint64_t *)buf + 16);
	drgn_register_state_set_from_buffer(regs, rsp, (uint64_t *)buf + 19);
	drgn_register_state_set_range_from_buffer(regs, r15, rdi, buf);
	drgn_register_state_set_pc_from_register(prog, regs, rip);

	*ret = regs;
	return NULL;
}

static struct drgn_error *
pt_regs_get_initial_registers_x86_64(const struct drgn_object *obj,
				     struct drgn_register_state **ret)
{
	return get_initial_registers_from_struct_x86_64(drgn_object_program(obj),
							drgn_object_buffer(obj),
							drgn_object_size(obj),
							ret);
}

static struct drgn_error *
prstatus_get_initial_registers_x86_64(struct drgn_program *prog,
				      const void *prstatus, size_t size,
				      struct drgn_register_state **ret)
{
	if (size < 112) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "NT_PRSTATUS is truncated");
	}
	return get_initial_registers_from_struct_x86_64(prog,
							(char *)prstatus + 112,
							size - 112, ret);
}

static struct drgn_error *
get_initial_registers_inactive_task_frame(struct drgn_object *frame_obj,
					  struct drgn_register_state **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(frame_obj);

	uint64_t address = frame_obj->address;
	err = drgn_object_read(frame_obj, frame_obj);
	if (err)
		return err;
	const char *frame_buf = drgn_object_buffer(frame_obj);
	size_t frame_size = drgn_object_size(frame_obj);

	struct drgn_register_state *regs =
		drgn_register_state_create(rbx, false);
	if (!regs)
		return &drgn_enomem;

#define COPY_REGISTER(id, member_name) do {					\
	struct drgn_type_member *member;					\
	uint64_t bit_offset;							\
	err = drgn_type_find_member(frame_obj->type, member_name, &member,	\
				    &bit_offset);				\
	if (err)								\
		goto err;							\
	if (bit_offset / 8 + DRGN_REGISTER_SIZE(id) > frame_size) {		\
		err = drgn_error_create(DRGN_ERROR_OUT_OF_BOUNDS,		\
					"out of bounds of value");		\
		goto err;							\
	}									\
	drgn_register_state_set_from_buffer(regs, id,				\
					    frame_buf + bit_offset / 8);	\
} while (0)

	COPY_REGISTER(rip, "ret_addr");
	COPY_REGISTER(r15, "r15");
	COPY_REGISTER(r14, "r14");
	COPY_REGISTER(r13, "r13");
	COPY_REGISTER(r12, "r12");
	COPY_REGISTER(rbp, "bp");
	COPY_REGISTER(rbx, "bx");

#undef COPY_REGISTER

	drgn_register_state_set_from_integer(prog, regs,
					     rsp, address + frame_size);
	drgn_register_state_set_pc_from_register(prog, regs, rip);

	*ret = regs;
	return NULL;

err:
	drgn_register_state_destroy(regs);
	return err;
}

static struct drgn_error *
linux_kernel_get_initial_registers_x86_64(const struct drgn_object *task_obj,
					  struct drgn_register_state **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(task_obj);

	struct drgn_object sp_obj;
	drgn_object_init(&sp_obj, prog);

	err = drgn_object_member_dereference(&sp_obj, task_obj, "thread");
	if (err)
		goto out;
	err = drgn_object_member(&sp_obj, &sp_obj, "sp");
	if (err)
		goto out;

	/*
	 * Since Linux kernel commit 0100301bfdf5 ("sched/x86: Rewrite the
	 * switch_to() code") (in v4.9), sp points to a struct
	 * inactive_task_frame, which we can use to get the callee-saved
	 * registers. Before that, sp points to bp. As long as frame pointers
	 * are enabled, this in turn points to the previous bp and the return
	 * address.
	 */
	struct drgn_qualified_type frame_type;
	err = drgn_program_find_type(prog, "struct inactive_task_frame *", NULL,
				     &frame_type);
	if (!err) {
		err = drgn_object_cast(&sp_obj, frame_type, &sp_obj);
		if (err)
			goto out;
		err = drgn_object_dereference(&sp_obj, &sp_obj);
		if (err)
			goto out;
		err = get_initial_registers_inactive_task_frame(&sp_obj, ret);
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		err = drgn_program_find_type(prog, "void **", NULL,
					     &frame_type);
		if (err)
			goto out;
		err = drgn_object_cast(&sp_obj, frame_type, &sp_obj);
		if (err)
			goto out;
		err = drgn_object_dereference(&sp_obj, &sp_obj);
		if (err)
			goto out;
		uint64_t frame_pointer;
		err = drgn_object_read_unsigned(&sp_obj, &frame_pointer);
		if (err)
			return err;
		err = get_registers_from_frame_pointer(prog, frame_pointer,
						       ret);
		if (err == &drgn_stop) {
			err = drgn_error_create(DRGN_ERROR_OTHER,
						"invalid frame pointer");
		}
	}
out:
	drgn_object_deinit(&sp_obj);
	return err;
}

static struct drgn_error *
apply_elf_rela_x86_64(const struct drgn_relocating_section *relocating,
		      uint64_t r_offset, uint32_t r_type, int64_t r_addend,
		      uint64_t sym_value)
{
	if (r_offset > relocating->buf_size) {
invalid_offset:
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "invalid ELF relocation offset");
	}
	size_t dst_size = relocating->buf_size - r_offset;
	char *dst = relocating->buf + r_offset;
	switch (r_type) {
	case R_X86_64_NONE:
		break;
	case R_X86_64_64: {
		uint64_t value = sym_value + r_addend;
		if (dst_size < sizeof(value))
			goto invalid_offset;
		if (relocating->bswap)
			value = bswap_64(value);
		memcpy(dst, &value, sizeof(value));
		break;
	}
	case R_X86_64_PC32: {
		uint32_t value = sym_value + r_addend - (relocating->addr + r_offset);
		if (dst_size < sizeof(value))
			goto invalid_offset;
		if (relocating->bswap)
			value = bswap_32(value);
		memcpy(dst, &value, sizeof(value));
		break;
	}
	case R_X86_64_32: {
		uint32_t value = sym_value + r_addend;
		if (dst_size < sizeof(value))
			goto invalid_offset;
		if (relocating->bswap)
			value = bswap_32(value);
		memcpy(dst, &value, sizeof(value));
		break;
	}
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "unimplemented ELF relocation type %" PRIu32,
					 r_type);
	}
	return NULL;
}

static struct drgn_error *
linux_kernel_get_page_offset_x86_64(struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(ret);

	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_UNSIGNED_LONG,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;

	/*
	 * If KASLR is enabled, PAGE_OFFSET is easily available via
	 * page_offset_base.
	 */
	struct drgn_object tmp;
	drgn_object_init(&tmp, prog);
	err = drgn_program_find_object(prog, "page_offset_base", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &tmp);
	if (!err) {
		err = drgn_object_cast(ret, qualified_type, &tmp);
		goto out;
	}
	if (err->code == DRGN_ERROR_LOOKUP)
		drgn_error_destroy(err);
	else
		goto out;

	/*
	 * If not, we determine it based on the kernel page table. Before Linux
	 * kernel commit d52888aa2753 ("x86/mm: Move LDT remap out of KASLR
	 * region on 5-level paging") (in v4.20), PAGE_OFFSET was pgd slot 272.
	 * After that, it is pgd slot 273, and slot 272 is empty (reserved for
	 * Local Descriptor Table mappings for userspace tasks).
	 */
	uint64_t pgd;
	err = drgn_program_read_u64(prog,
				    prog->vmcoreinfo.swapper_pg_dir + 272 * 8,
				    false, &pgd);
	if (err)
		goto out;
	uint64_t value;
	if (pgd) {
		if (prog->vmcoreinfo.pgtable_l5_enabled)
			value = UINT64_C(0xff10000000000000);
		else
			value = UINT64_C(0xffff880000000000);
	} else {
		if (prog->vmcoreinfo.pgtable_l5_enabled)
			value = UINT64_C(0xff11000000000000);
		else
			value = UINT64_C(0xffff888000000000);
	}
	err = drgn_object_set_unsigned(ret, qualified_type, value, 0);

out:
	drgn_object_deinit(&tmp);
	return err;
}

static struct drgn_error *
linux_kernel_get_vmemmap_x86_64(struct drgn_object *ret)
{

	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(ret);

	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_type(prog, "struct page *", NULL,
				     &qualified_type);
	if (err)
		return err;

	/* If KASLR is enabled, vmemmap is vmemmap_base. */
	struct drgn_object tmp;
	drgn_object_init(&tmp, prog);
	err = drgn_program_find_object(prog, "vmemmap_base", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &tmp);
	if (!err) {
		err = drgn_object_cast(ret, qualified_type, &tmp);
		goto out;
	}
	if (err->code == DRGN_ERROR_LOOKUP)
		drgn_error_destroy(err);
	else
		goto out;

	/* Otherwise, it depends on whether we have 5-level page tables. */
	uint64_t value;
	if (prog->vmcoreinfo.pgtable_l5_enabled)
		value = UINT64_C(0xffd4000000000000);
	else
		value = UINT64_C(0xffffea0000000000);
	err = drgn_object_set_unsigned(ret, qualified_type, value, 0);

out:
	drgn_object_deinit(&tmp);
	return err;
}

static struct drgn_error *
linux_kernel_live_direct_mapping_fallback_x86_64(struct drgn_program *prog,
						 uint64_t *address_ret,
						 uint64_t *size_ret)
{
	struct drgn_error *err;
	unsigned long page_offset_base_address;

	*size_ret = UINT64_C(1) << 46;
	err = proc_kallsyms_symbol_addr("page_offset_base",
					&page_offset_base_address);
	if (!err) {
		return drgn_program_read_word(prog, page_offset_base_address,
					      false, address_ret);
	} else if (err == &drgn_not_found) {
		/*
		 * This is only called for pre-4.11 kernels, so we can assume
		 * the old location.
		 */
		*address_ret = UINT64_C(0xffff880000000000);
		return NULL;
	} else {
		return err;
	}
}

struct pgtable_iterator_x86_64 {
	uint16_t index[5];
	uint64_t table[5][512];
};

static void pgtable_iterator_arch_init_x86_64(void *buf)
{
	struct pgtable_iterator_x86_64 *arch = buf;
	memset(arch->index, 0xff, sizeof(arch->index));
	memset(arch->table, 0, sizeof(arch->table));
}

static struct drgn_error *
linux_kernel_pgtable_iterator_next_x86_64(struct pgtable_iterator *it,
					  uint64_t *virt_addr_ret,
					  uint64_t *phys_addr_ret)
{
	static const int PAGE_SHIFT = 12;
	static const int PGTABLE_SHIFT = 9;
	static const int PGTABLE_MASK = (1 << PGTABLE_SHIFT) - 1;
	static const uint64_t PRESENT = 0x1;
	static const uint64_t PSE = 0x80; /* a.k.a. huge page */
	static const uint64_t ADDRESS_MASK = UINT64_C(0xffffffffff000);
	struct drgn_error *err;
	struct drgn_program *prog = it->prog;
	struct pgtable_iterator_x86_64 *arch = (void *)it->arch;
	int levels = prog->vmcoreinfo.pgtable_l5_enabled ? 5 : 4, level;
	bool bswap = drgn_platform_bswap(&prog->platform);

	/* Find the lowest level with cached entries. */
	for (level = 0; level < levels; level++) {
		if (arch->index[level] < array_size(arch->table[level]))
			break;
	}
	/* For every level below that, refill the cache/return pages. */
	for (;; level--) {
		uint64_t table;
		bool table_physical;
		uint16_t index;
		if (level == levels) {
			uint64_t start_non_canonical, end_non_canonical;
			start_non_canonical = (UINT64_C(1) <<
					       (PAGE_SHIFT +
						PGTABLE_SHIFT * levels - 1));
			end_non_canonical = (UINT64_MAX <<
					     (PAGE_SHIFT +
					      PGTABLE_SHIFT * levels - 1));
			if (it->virt_addr >= start_non_canonical &&
			    it->virt_addr < end_non_canonical) {
				*virt_addr_ret = start_non_canonical;
				*phys_addr_ret = UINT64_MAX;
				it->virt_addr = end_non_canonical;
				return NULL;
			}
			table = it->pgtable;
			table_physical = false;
		} else {
			uint64_t entry = arch->table[level][arch->index[level]++];
			if (bswap)
				entry = bswap_64(entry);
			table = entry & ADDRESS_MASK;
			if (!(entry & PRESENT) || (entry & PSE) || level == 0) {
				uint64_t mask = (UINT64_C(1) <<
						 (PAGE_SHIFT +
						  PGTABLE_SHIFT * level)) - 1;
				*virt_addr_ret = it->virt_addr & ~mask;
				if (entry & PRESENT)
					*phys_addr_ret = table & ~mask;
				else
					*phys_addr_ret = UINT64_MAX;
				it->virt_addr = (it->virt_addr | mask) + 1;
				return NULL;
			}
			table_physical = true;
		}
		index = (it->virt_addr >>
			 (PAGE_SHIFT + PGTABLE_SHIFT * (level - 1))) & PGTABLE_MASK;
		/*
		 * It's only marginally more expensive to read 4096 bytes than 8
		 * bytes, so we always read to the end of the table.
		 */
		err = drgn_program_read_memory(prog,
					       &arch->table[level - 1][index],
					       table + 8 * index,
					       sizeof(arch->table[0]) - 8 * index,
					       table_physical);
		if (err)
			return err;
		arch->index[level - 1] = index;
	}
}

const struct drgn_architecture_info arch_info_x86_64 = {
	.name = "x86-64",
	.arch = DRGN_ARCH_X86_64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	DRGN_ARCHITECTURE_REGISTERS,
	.default_dwarf_cfi_row = &default_dwarf_cfi_row_x86_64,
	.orc_to_cfi = orc_to_cfi_x86_64,
	.fallback_unwind = fallback_unwind_x86_64,
	.pt_regs_get_initial_registers = pt_regs_get_initial_registers_x86_64,
	.prstatus_get_initial_registers = prstatus_get_initial_registers_x86_64,
	.linux_kernel_get_initial_registers =
		linux_kernel_get_initial_registers_x86_64,
	.apply_elf_rela = apply_elf_rela_x86_64,
	.linux_kernel_get_page_offset = linux_kernel_get_page_offset_x86_64,
	.linux_kernel_get_vmemmap = linux_kernel_get_vmemmap_x86_64,
	.linux_kernel_live_direct_mapping_fallback =
		linux_kernel_live_direct_mapping_fallback_x86_64,
	.pgtable_iterator_arch_size = sizeof(struct pgtable_iterator_x86_64),
	.pgtable_iterator_arch_init = pgtable_iterator_arch_init_x86_64,
	.linux_kernel_pgtable_iterator_next =
		linux_kernel_pgtable_iterator_next_x86_64,
};
