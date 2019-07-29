// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "internal.h"
#include "platform.h"

static inline struct drgn_error *read_register(struct drgn_object *reg_obj,
					       struct drgn_object *frame_obj,
					       const char *name,
					       Dwarf_Addr *ret)
{
	struct drgn_error *err;
	uint64_t reg;

	err = drgn_object_member_dereference(reg_obj, frame_obj, name);
	if (err)
		return err;
	err = drgn_object_read_unsigned(reg_obj, &reg);
	if (err)
		return err;
	*ret = reg;
	return NULL;
}

static struct drgn_error *
linux_kernel_set_initial_registers_x86_64(Dwfl_Thread *thread,
					  struct drgn_object *task_obj)
{
	struct drgn_error *err;
	struct drgn_program *prog = task_obj->prog;
	struct drgn_object frame_obj, reg_obj;
	struct drgn_qualified_type frame_type;
	Dwarf_Word dwarf_regs[5];
	uint64_t sp;

	drgn_object_init(&frame_obj, prog);
	drgn_object_init(&reg_obj, prog);

	/*
	 * This depends on Linux kernel commit 0100301bfdf5 ("sched/x86: Rewrite
	 * the switch_to() code") (in v4.9).
	 */
	err = drgn_object_member_dereference(&frame_obj, task_obj, "thread");
	if (err)
		goto out;
	err = drgn_object_member(&frame_obj, &frame_obj, "sp");
	if (err)
		goto out;
	err = drgn_program_find_type(prog, "struct inactive_task_frame *", NULL,
				     &frame_type);
	if (err)
		goto out;
	err = drgn_object_cast(&frame_obj, frame_type, &frame_obj);
	if (err)
		goto out;

	err = read_register(&reg_obj, &frame_obj, "bx", &dwarf_regs[0]);
	if (err)
		goto out;
	/* rbx is register 3. */
	if (!dwfl_thread_state_registers(thread, 3, 1, dwarf_regs)) {
		err = drgn_error_libdwfl();
		goto out;
	}

	err = read_register(&reg_obj, &frame_obj, "bp", &dwarf_regs[0]);
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&frame_obj, &sp);
	if (err)
		goto out;
	dwarf_regs[1] = sp;
	/* rbp and rsp are registers 6 and 7, respectively. */
	if (!dwfl_thread_state_registers(thread, 6, 2, dwarf_regs)) {
		err = drgn_error_libdwfl();
		goto out;
	}

	err = read_register(&reg_obj, &frame_obj, "r12", &dwarf_regs[0]);
	if (err)
		goto out;
	err = read_register(&reg_obj, &frame_obj, "r13", &dwarf_regs[1]);
	if (err)
		goto out;
	err = read_register(&reg_obj, &frame_obj, "r14", &dwarf_regs[2]);
	if (err)
		goto out;
	err = read_register(&reg_obj, &frame_obj, "r15", &dwarf_regs[3]);
	if (err)
		goto out;
	err = read_register(&reg_obj, &frame_obj, "ret_addr", &dwarf_regs[4]);
	if (err)
		goto out;
	/* r12-r15 are registers 12-15; register 16 is the return address. */
	if (!dwfl_thread_state_registers(thread, 12, 5, dwarf_regs))
		err = drgn_error_libdwfl();

out:
	drgn_object_deinit(&reg_obj);
	drgn_object_deinit(&frame_obj);
	return err;
}

const struct drgn_architecture_info arch_info_x86_64 = {
	.name = "x86-64",
	.arch = DRGN_ARCH_X86_64,
	.default_flags = (DRGN_PLATFORM_IS_64_BIT |
			  DRGN_PLATFORM_IS_LITTLE_ENDIAN),
	.linux_kernel_set_initial_registers = linux_kernel_set_initial_registers_x86_64,
};
