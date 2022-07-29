// SPDX-License-Identifier: GPL-3.0-or-later

#include "error.h"
#include "register_state.h"
#include "platform.h" // IWYU pragma: associated

/*
 * The ABI specification can be found at:
 * https://github.com/IBM/s390x-abi
 */

#include "arch_s390_defs.inc"

static const struct drgn_cfi_row default_dwarf_cfi_row_s390 = DRGN_CFI_ROW(
	[DRGN_REGISTER_NUMBER(r15)] = { DRGN_CFI_RULE_CFA_PLUS_OFFSET },
	);

static struct drgn_error drgn_invalid_rel = {
	.code = DRGN_ERROR_OTHER,
	.message = "invalid relocation entry",
};

static struct drgn_error *
apply_rela_bits(char *dest, uint64_t loc, uint64_t val,
			   int sign, int bits, int shift)
{
	unsigned long umax;
	long min, max;

	if (val & ((1UL << shift) - 1))
		return &drgn_invalid_rel;
	if (sign) {
		val = (uint64_t)(((long) val) >> shift);
		min = -(1L << (bits - 1));
		max = (1L << (bits - 1)) - 1;
		if ((long) val < min || (long) val > max)
			return &drgn_invalid_rel;
	} else {
		val >>= shift;
		umax = ((1UL << (bits - 1)) << 1) - 1;
		if ((unsigned long) val > umax)
			return &drgn_invalid_rel;
	}

	if (bits == 8) {
		unsigned char tmp = val;
		memcpy(dest + loc, &tmp, 1);
	} else if (bits == 12) {
		unsigned short tmp = (val & 0xfff) |
			(*(unsigned short *) loc & 0xf000);
		memcpy(dest + loc, &tmp, 2);
	} else if (bits == 16) {
		unsigned short tmp = val;
		memcpy(dest + loc, &tmp, 2);
	} else if (bits == 20) {
		unsigned int tmp = (val & 0xfff) << 16 |
			(val & 0xff000) >> 4 | (*(unsigned int *) loc & 0xf00000ff);
		memcpy(dest + loc, &tmp, 4);
	} else if (bits == 32) {
		unsigned int tmp = val;
		memcpy(dest + loc, &tmp, 4);
	} else if (bits == 64) {
		unsigned long tmp = val;
		memcpy(dest + loc, &tmp, 8);
	}
	return 0;
}

static struct drgn_error *
apply_elf_reloc_s390(const struct drgn_relocating_section *relocating,
			uint64_t r_offset, uint32_t r_type, const int64_t *r_addend,
			uint64_t sym_value)
{
	struct drgn_error *err = NULL;

	switch (r_type) {
	case R_390_NONE:
		break;
	case R_390_8:		/* Direct 8 bit.   */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 8, 0);
		break;
	case R_390_12:		/* Direct 12 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 12, 0);
		break;
	case R_390_16:		/* Direct 16 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 16, 0);
		break;
	case R_390_20:		/* Direct 20 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 1, 20, 0);
		break;
	case R_390_32:		/* Direct 32 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 32, 0);
		break;
	case R_390_64:		/* Direct 64 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend, 0, 64, 0);
		break;
	case R_390_PC16:	/* PC relative 16 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 16, 0);
		break;
	case R_390_PC16DBL:	/* PC relative 16 bit shifted by 1.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 16, 1);
		break;
	case R_390_PC32DBL:	/* PC relative 32 bit shifted by 1.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 32, 1);
		break;
	case R_390_PC32:	/* PC relative 32 bit.  */
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 32, 0);
		break;
	case R_390_PC64:	/* PC relative 64 bit.	*/
		err = apply_rela_bits(relocating->buf, r_offset, *r_addend - r_offset, 1, 64, 0);
		break;
	default:
		err = DRGN_UNKNOWN_RELOCATION_TYPE(r_type);
		break;
	}
	return err;
}

static struct drgn_error *
fallback_unwind_s390(struct drgn_program *prog,
		     struct drgn_register_state *regs,
		     struct drgn_register_state **ret)
{
	struct optional_uint64 bc = drgn_register_state_get_u64(prog, regs, bc);
	struct drgn_qualified_type frame_type;
	struct drgn_type_member *member;
	struct drgn_error *err;
	uint64_t bit_offset, nextbc;
	uint8_t frame[256];

	if (!bc.has_value)
		return &drgn_stop;

	err = drgn_program_read_memory(prog, frame, bc.value, sizeof(frame), false);
	if (err)
		return err;

	err = drgn_program_find_type(prog, "struct stack_frame", NULL, &frame_type);
	if (err)
		return err;

	err = drgn_type_find_member(frame_type.type, "gprs", &member, &bit_offset);
	if (err)
		return err;

	drgn_register_state_set_range_from_buffer(*ret, r6, r15, frame + bit_offset / 8);
	drgn_register_state_set_pc_from_register(prog, *ret, r14);
	err = drgn_type_find_member(frame_type.type, "back_chain", &member, &bit_offset);
	if (err)
		return err;

	nextbc = *(uint64_t *)(frame + bit_offset / 8);
	if (!nextbc)
		return &drgn_stop;
	drgn_register_state_set_from_u64(prog, *ret, bc, nextbc);
	return NULL;
}

static struct drgn_error *
linux_kernel_get_initial_registers_s390(const struct drgn_object *task_obj,
					   struct drgn_register_state **ret)
{
	struct drgn_program *prog = drgn_object_program(task_obj);
	struct drgn_register_state *regs, *regs2;
	struct drgn_qualified_type frame_type;
	struct drgn_object ctx;
	struct drgn_error *err;
	uint64_t ksp;

	drgn_object_init(&ctx, prog);

	err = drgn_object_member_dereference(&ctx, task_obj, "thread");
	if (err)
		goto out;

	err = drgn_object_member(&ctx, &ctx, "ksp");
	if (err)
		goto out;

	err = drgn_object_read_unsigned(&ctx, &ksp);
	if (err)
		goto out;

	regs = drgn_register_state_create(pswa, false);
	if (!regs)
		return &drgn_enomem;

	drgn_register_state_set_from_u64(prog, regs, bc, ksp);

	regs2 = drgn_register_state_create(pswa, false);
	err = fallback_unwind_s390(prog, regs, &regs2);
	if (err) {
		drgn_register_state_destroy(regs2);
		goto out;
	}

	drgn_register_state_destroy(regs);
	*ret = regs2;
out:
	drgn_object_deinit(&ctx);
	return err;
}

const struct drgn_architecture_info arch_info_s390 = {
	.name = "s390",
	.arch = DRGN_ARCH_S390,
	.default_flags = DRGN_PLATFORM_IS_64_BIT,
	.register_by_name = drgn_register_by_name_unknown,
	.apply_elf_reloc = apply_elf_reloc_s390,
	DRGN_ARCHITECTURE_REGISTERS,
	.default_dwarf_cfi_row = &default_dwarf_cfi_row_s390,
	.fallback_unwind = fallback_unwind_s390,
	.linux_kernel_get_initial_registers = linux_kernel_get_initial_registers_s390,
};
