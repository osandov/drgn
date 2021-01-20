// (C) Copyright IBM Corp. 2020
// SPDX-License-Identifier: GPL-3.0+

#include <byteswap.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <string.h>

#include "drgn.h"
#include "error.h"
#include "platform.h" // IWYU pragma: associated
#include "program.h"

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

static struct drgn_error *
set_initial_registers_from_struct_ppc64(struct drgn_program *prog,
					Dwfl_Thread *thread, const void *regs,
					size_t size, bool linux_kernel_prstatus,
					bool linux_kernel_switched_out)
{
	if (size < 312) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "registers are truncated");
	}

	bool bswap = drgn_platform_bswap(&prog->platform);

	Dwarf_Word dwarf_regs[32];

#define READ_REGISTER(n) ({					\
	uint64_t reg;						\
	memcpy(&reg, (uint64_t *)regs + (n), sizeof(reg));	\
	bswap ? bswap_64(reg) : reg;				\
})

	/*
	 * The NT_PRSTATUS note in Linux kernel vmcores is odd. Since Linux
	 * kernel commit d16a58f8854b ("powerpc: Improve ppc_save_regs()") (in
	 * v5.7), the saved stack pointer (r1) is for the caller of the program
	 * counter saved in nip. Before that, the saved nip is set to the same
	 * as the link register. So, use the link register instead of nip.
	 */
	uint64_t nip = READ_REGISTER(32);
	uint64_t link = READ_REGISTER(36);
	if (linux_kernel_prstatus) {
		dwfl_thread_state_register_pc(thread, link);
	} else {
		dwfl_thread_state_register_pc(thread, nip);
		/*
		 * Switched out tasks in the Linux kernel don't save the link
		 * register.
		 */
		if (!linux_kernel_switched_out) {
			dwarf_regs[0] = link;
			if (!dwfl_thread_state_registers(thread, 65, 1,
							 dwarf_regs))
				return drgn_error_libdwfl();
		}
	}

	/*
	 * Switched out tasks in the Linux kernel only save the callee-saved
	 * general purpose registers (14-31).
	 */
	int min_gpr = linux_kernel_switched_out ? 14 : 0;
	for (int i = min_gpr; i < 32; i++)
		dwarf_regs[i] = READ_REGISTER(i);
	if (!dwfl_thread_state_registers(thread, min_gpr, 32 - min_gpr,
					 dwarf_regs))
		return drgn_error_libdwfl();

	/* cr0 - cr7 */
	uint64_t ccr = READ_REGISTER(38);
	for (int i = 0; i < 8; i++)
		dwarf_regs[i] = ccr & (UINT64_C(0xf) << (28 - 4 * i));
	if (!dwfl_thread_state_registers(thread, 68, 8, dwarf_regs))
		return drgn_error_libdwfl();

#undef READ_REGISTER

	return NULL;
}

static struct drgn_error *
pt_regs_set_initial_registers_ppc64(Dwfl_Thread *thread,
				    const struct drgn_object *obj)
{
	return set_initial_registers_from_struct_ppc64(drgn_object_program(obj),
						       thread,
						       drgn_object_buffer(obj),
						       drgn_object_size(obj),
						       false, false);
}

static struct drgn_error *
prstatus_set_initial_registers_ppc64(struct drgn_program *prog,
				     Dwfl_Thread *thread, const void *prstatus,
				     size_t size)
{
	if (size < 112) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
				"NT_PRSTATUS is truncated");
	}
	bool is_linux_kernel = prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL;
	return set_initial_registers_from_struct_ppc64(prog, thread,
						       (char *)prstatus + 112,
						       size - 112,
						       is_linux_kernel, false);
}

static struct drgn_error *
linux_kernel_set_initial_registers_ppc64(Dwfl_Thread *thread,
					 const struct drgn_object *task_obj)
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

	char regs[312];
	err = drgn_program_read_memory(prog, regs, ksp + STACK_FRAME_OVERHEAD,
				       sizeof(regs), false);
	if (err)
		goto out;

	err = set_initial_registers_from_struct_ppc64(prog, thread, regs,
						      sizeof(regs), false,
						      true);
	if (err)
		goto out;

	/* r1 */
	Dwarf_Word dwarf_reg = ksp + SWITCH_FRAME_SIZE;
	if (!dwfl_thread_state_registers(thread, 1, 1, &dwarf_reg)) {
		err = drgn_error_libdwfl();
		goto out;
	}

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
	.default_dwarf_cfi_row = DRGN_CFI_ROW(
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
	),
	.pt_regs_set_initial_registers = pt_regs_set_initial_registers_ppc64,
	.prstatus_set_initial_registers = prstatus_set_initial_registers_ppc64,
	.linux_kernel_set_initial_registers =
		linux_kernel_set_initial_registers_ppc64,
};
