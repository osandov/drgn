// (C) Copyright IBM Corp. 2020
// SPDX-License-Identifier: GPL-3.0-or-later

#include <byteswap.h>
#include <string.h>

#include "drgn.h"
#include "error.h"
#include "platform.h" // IWYU pragma: associated
#include "program.h"
#include "register_state.h"
#include "serialize.h"

/*
 * There are two conflicting definitions of DWARF register numbers after 63. The
 * original definition appears to be "64-bit PowerPC ELF Application Binary
 * Interface Supplement" [1]. The GNU toolchain instead uses its own that was
 * later codified in "Power Architecture 64-Bit ELF V2 ABI Specification" [2].
 * We use the latter.
 *
 * 1: https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html
 * 2: https://openpowerfoundation.org/?resource_lib=64-bit-elf-v2-abi-specification-power-architecture
 */
#define DRGN_ARCH_REGISTER_LAYOUT						\
	/*									\
	 * The psABI calls register 65 the link register, but it's used as the	\
	 * DWARF CFI return_address_register, so it usually contains the program\
	 * counter.								\
	 */									\
	DRGN_REGISTER_LAYOUT(ra, 8, 65)						\
	DRGN_REGISTER_LAYOUT(r0, 8, 0)						\
	DRGN_REGISTER_LAYOUT(r1, 8, 1)						\
	DRGN_REGISTER_LAYOUT(r2, 8, 2)						\
	DRGN_REGISTER_LAYOUT(r3, 8, 3)						\
	DRGN_REGISTER_LAYOUT(r4, 8, 4)						\
	DRGN_REGISTER_LAYOUT(r5, 8, 5)						\
	DRGN_REGISTER_LAYOUT(r6, 8, 6)						\
	DRGN_REGISTER_LAYOUT(r7, 8, 7)						\
	DRGN_REGISTER_LAYOUT(r8, 8, 8)						\
	DRGN_REGISTER_LAYOUT(r9, 8, 9)						\
	DRGN_REGISTER_LAYOUT(r10, 8, 10)					\
	DRGN_REGISTER_LAYOUT(r11, 8, 11)					\
	DRGN_REGISTER_LAYOUT(r12, 8, 12)					\
	DRGN_REGISTER_LAYOUT(r13, 8, 13)					\
	DRGN_REGISTER_LAYOUT(r14, 8, 14)					\
	DRGN_REGISTER_LAYOUT(r15, 8, 15)					\
	DRGN_REGISTER_LAYOUT(r16, 8, 16)					\
	DRGN_REGISTER_LAYOUT(r17, 8, 17)					\
	DRGN_REGISTER_LAYOUT(r18, 8, 18)					\
	DRGN_REGISTER_LAYOUT(r19, 8, 19)					\
	DRGN_REGISTER_LAYOUT(r20, 8, 20)					\
	DRGN_REGISTER_LAYOUT(r21, 8, 21)					\
	DRGN_REGISTER_LAYOUT(r22, 8, 22)					\
	DRGN_REGISTER_LAYOUT(r23, 8, 23)					\
	DRGN_REGISTER_LAYOUT(r24, 8, 24)					\
	DRGN_REGISTER_LAYOUT(r25, 8, 25)					\
	DRGN_REGISTER_LAYOUT(r26, 8, 26)					\
	DRGN_REGISTER_LAYOUT(r27, 8, 27)					\
	DRGN_REGISTER_LAYOUT(r28, 8, 28)					\
	DRGN_REGISTER_LAYOUT(r29, 8, 29)					\
	DRGN_REGISTER_LAYOUT(r30, 8, 30)					\
	DRGN_REGISTER_LAYOUT(r31, 8, 31)					\
	DRGN_REGISTER_LAYOUT(cr0, 8, 68)					\
	DRGN_REGISTER_LAYOUT(cr1, 8, 69)					\
	DRGN_REGISTER_LAYOUT(cr2, 8, 70)					\
	DRGN_REGISTER_LAYOUT(cr3, 8, 71)					\
	DRGN_REGISTER_LAYOUT(cr4, 8, 72)					\
	DRGN_REGISTER_LAYOUT(cr5, 8, 73)					\
	DRGN_REGISTER_LAYOUT(cr6, 8, 74)					\
	DRGN_REGISTER_LAYOUT(cr7, 8, 75)

#include "arch_ppc64.inc"

static const struct drgn_cfi_row default_dwarf_cfi_row_ppc64 = DRGN_CFI_ROW(
	DRGN_CFI_SAME_VALUE_INIT(DRGN_REGISTER_NUMBER(ra)),
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

static struct drgn_error *
fallback_unwind_ppc64(struct drgn_program *prog,
		      struct drgn_register_state *regs,
		      struct drgn_register_state **ret)
{
	struct drgn_error *err;

	if (!drgn_register_state_has_register(regs, DRGN_REGISTER_NUMBER(ra)) ||
	    !drgn_register_state_has_register(regs, DRGN_REGISTER_NUMBER(r1)))
		return &drgn_stop;

	bool little_endian = drgn_platform_is_little_endian(&prog->platform);
	bool bswap = drgn_platform_bswap(&prog->platform);
	uint64_t ra;
	copy_lsbytes(&ra, sizeof(ra), HOST_LITTLE_ENDIAN,
		     &regs->buf[DRGN_REGISTER_OFFSET(ra)],
		     DRGN_REGISTER_SIZE(ra), little_endian);
	uint64_t r1;
	copy_lsbytes(&r1, sizeof(r1), HOST_LITTLE_ENDIAN,
		     &regs->buf[DRGN_REGISTER_OFFSET(r1)],
		     DRGN_REGISTER_SIZE(r1), little_endian);

	uint64_t frame[3];
	err = drgn_program_read_memory(prog, &frame, r1, sizeof(frame), false);
	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			drgn_error_destroy(err);
			err = &drgn_stop;
		}
		return err;
	}

	uint64_t unwound_r1 = bswap ? bswap_64(frame[0]) : frame[0];
	if (unwound_r1 <= r1)
		return &drgn_stop;

	struct drgn_register_state *unwound =
		drgn_register_state_create(r1, true);
	if (!unwound)
		return &drgn_enomem;
	drgn_register_state_set_from_buffer(unwound, ra, &frame[2]);
	drgn_register_state_set_from_buffer(unwound, r1, &frame[0]);
	drgn_register_state_set_pc(prog, unwound, ra);
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

	/* Switched out tasks in the Linux kernel don't save r0-r13 or lr. */
	if (!linux_kernel_switched_out) {
		if (!linux_kernel_prstatus) {
			drgn_register_state_set_from_buffer(regs, ra,
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

static struct drgn_error *
linux_kernel_get_initial_registers_ppc64(const struct drgn_object *task_obj,
					 struct drgn_register_state **ret)

{
	static const uint64_t STACK_FRAME_OVERHEAD = 112;
	static const uint64_t SWITCH_FRAME_SIZE = STACK_FRAME_OVERHEAD + 368;

	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(task_obj);

	struct drgn_object sp_obj;
	drgn_object_init(&sp_obj, prog);

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

	char buf[312];
	err = drgn_program_read_memory(prog, buf, ksp + STACK_FRAME_OVERHEAD,
				       sizeof(buf), false);
	if (err)
		goto out;

	err = get_initial_registers_from_struct_ppc64(prog, buf, sizeof(buf),
						      false, true, ret);
	if (err)
		goto out;

	drgn_register_state_set_from_integer(prog, *ret, r1,
					     ksp + SWITCH_FRAME_SIZE);

	err = NULL;
out:
	drgn_object_deinit(&sp_obj);
	return err;
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
};
