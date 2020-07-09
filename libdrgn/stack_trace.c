// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <byteswap.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <endian.h>
#include <inttypes.h>
#include <stdlib.h>

#include "internal.h"
#include "helpers.h"
#include "program.h"
#include "read.h"
#include "string_builder.h"
#include "symbol.h"

struct drgn_stack_trace {
	struct drgn_program *prog;
	union {
		size_t capacity;
		Dwfl_Thread *thread;
	};
	size_t num_frames;
	Dwfl_Frame *frames[];
};

LIBDRGN_PUBLIC void drgn_stack_trace_destroy(struct drgn_stack_trace *trace)
{
	dwfl_detach_thread(trace->thread);
	free(trace);
}

LIBDRGN_PUBLIC
size_t drgn_stack_trace_num_frames(struct drgn_stack_trace *trace)
{
	return trace->num_frames;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_stack_trace(struct drgn_stack_trace *trace, char **ret)
{
	struct drgn_error *err;
	struct string_builder str = {};
	struct drgn_stack_frame frame = { .trace = trace, };

	for (; frame.i < trace->num_frames; frame.i++) {
		Dwarf_Addr pc;
		bool isactivation;
		Dwfl_Module *module;
		struct drgn_symbol sym;

		if (!string_builder_appendf(&str, "#%-2zu ", frame.i)) {
			err = &drgn_enomem;
			goto err;
		}

		dwfl_frame_pc(trace->frames[frame.i], &pc, &isactivation);
		module = dwfl_frame_module(trace->frames[frame.i]);
		if (module &&
		    drgn_program_find_symbol_by_address_internal(trace->prog,
								 pc - !isactivation,
								 module,
								 &sym)) {
			if (!string_builder_appendf(&str,
						    "%s+0x%" PRIx64 "/0x%" PRIx64,
						    sym.name, pc - sym.address,
						    sym.size)) {
				err = &drgn_enomem;
				goto err;
			}
		} else {
			if (!string_builder_appendf(&str, "0x%" PRIx64, pc)) {
				err = &drgn_enomem;
				goto err;
			}
		}

		if (frame.i != trace->num_frames - 1 &&
		    !string_builder_appendc(&str, '\n')) {
			err = &drgn_enomem;
			goto err;
		}
	}
	if (!string_builder_finalize(&str, ret)) {
		err = &drgn_enomem;
		goto err;
	}
	return NULL;

err:
	free(str.str);
	return err;
}

LIBDRGN_PUBLIC uint64_t drgn_stack_frame_pc(struct drgn_stack_frame frame)
{
	Dwarf_Addr pc;

	dwfl_frame_pc(frame.trace->frames[frame.i], &pc, NULL);
	return pc;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_symbol(struct drgn_stack_frame frame, struct drgn_symbol **ret)
{
	Dwarf_Addr pc;
	bool isactivation;
	Dwfl_Module *module;
	struct drgn_symbol *sym;

	dwfl_frame_pc(frame.trace->frames[frame.i], &pc, &isactivation);
	if (!isactivation)
		pc--;
	module = dwfl_frame_module(frame.trace->frames[frame.i]);
	if (!module)
		return drgn_error_symbol_not_found(pc);
	sym = malloc(sizeof(*sym));
	if (!sym)
		return &drgn_enomem;
	if (!drgn_program_find_symbol_by_address_internal(frame.trace->prog, pc,
							  module, sym)) {
		free(sym);
		return drgn_error_symbol_not_found(pc);
	}
	*ret = sym;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_register(struct drgn_stack_frame frame,
			  enum drgn_register_number regno, uint64_t *ret)
{
	Dwarf_Addr value;

	if (!dwfl_frame_register(frame.trace->frames[frame.i], regno, &value)) {
		return drgn_error_create(DRGN_ERROR_LOOKUP,
					 "register value is not known");
	}
	*ret = value;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_register_by_name(struct drgn_stack_frame frame,
				  const char *name, uint64_t *ret)
{
	const struct drgn_register *reg;

	reg = drgn_architecture_register_by_name(frame.trace->prog->platform.arch,
						 name);
	if (!reg) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "unknown register '%s'", name);
	}
	return drgn_stack_frame_register(frame, reg->number, ret);
}

static bool drgn_thread_memory_read(Dwfl *dwfl, Dwarf_Addr addr,
				    Dwarf_Word *result, void *dwfl_arg)
{
	struct drgn_error *err;
	struct drgn_program *prog = dwfl_arg;
	uint64_t word;

	err = drgn_program_read_word(prog, addr, false, &word);
	if (err) {
		if (err->code == DRGN_ERROR_FAULT) {
			/*
			 * This could be the end of the stack trace, so it shouldn't be
			 * fatal.
			 */
			drgn_error_destroy(err);
		} else {
			drgn_error_destroy(prog->stack_trace_err);
			prog->stack_trace_err = err;
		}
		return false;
	}
	*result = word;
	return true;
}

/*
 * We only care about the specific thread that we're unwinding, so we return it
 * with an arbitrary TID.
 */
#define STACK_TRACE_OBJ_TID 1
static pid_t drgn_object_stack_trace_next_thread(Dwfl *dwfl, void *dwfl_arg,
						 void **thread_argp)
{
	struct drgn_program *prog = dwfl_arg;

	if (*thread_argp)
		return 0;
	*thread_argp = prog;
	return STACK_TRACE_OBJ_TID;
}

static struct drgn_error *
drgn_get_stack_trace_obj(struct drgn_object *res, struct drgn_program *prog,
			 bool *is_pt_regs_ret)
{
	struct drgn_error *err;
	struct drgn_type *type;

	type = drgn_underlying_type(prog->stack_trace_obj->type);
	if (drgn_type_kind(type) == DRGN_TYPE_STRUCT &&
	    strcmp(drgn_type_tag(type), "pt_regs") == 0) {
		*is_pt_regs_ret = true;
		return drgn_object_read(res, prog->stack_trace_obj);
	}

	if (drgn_type_kind(type) != DRGN_TYPE_POINTER)
		goto type_error;
	type = drgn_underlying_type(drgn_type_type(type).type);
	if (drgn_type_kind(type) != DRGN_TYPE_STRUCT)
		goto type_error;

	if ((prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
	    strcmp(drgn_type_tag(type), "task_struct") == 0) {
		*is_pt_regs_ret = false;
		return drgn_object_read(res, prog->stack_trace_obj);
	} else if (strcmp(drgn_type_tag(type), "pt_regs") == 0) {
		*is_pt_regs_ret = true;
		/*
		 * If the drgn_object_read() call fails, we're breaking
		 * the rule of not modifying the result on error, but we
		 * don't care in this context.
		 */
		err = drgn_object_dereference(res, prog->stack_trace_obj);
		if (err)
			return err;
		return drgn_object_read(res, res);
	}

type_error:
	return drgn_error_format(DRGN_ERROR_TYPE,
				 "expected struct pt_regs, struct pt_regs *%s, or int",
				 (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) ?
				 ", struct task_struct *" : "");
}

static bool drgn_thread_set_initial_registers(Dwfl_Thread *thread,
					      void *thread_arg)
{
	struct drgn_error *err;
	struct drgn_program *prog = thread_arg;
	struct drgn_object obj;
	struct drgn_object tmp;
	struct string prstatus;

	drgn_object_init(&obj, prog);
	drgn_object_init(&tmp, prog);

	/* First, try pt_regs. */
	if (prog->stack_trace_obj) {
		bool is_pt_regs;
		err = drgn_get_stack_trace_obj(&obj, prog, &is_pt_regs);
		if (err)
			goto out;

		if (is_pt_regs) {
			assert(obj.kind == DRGN_OBJECT_BUFFER &&
			       !obj.is_reference);
			if (!prog->platform.arch->pt_regs_set_initial_registers) {
				err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
							"pt_regs stack unwinding is not supported for %s architecture",
							prog->platform.arch->name);
				goto out;
			}
			err = prog->platform.arch->pt_regs_set_initial_registers(thread,
										 &obj);
			goto out;
		}
	} else if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		err = drgn_program_find_object(prog, "init_pid_ns", NULL,
					       DRGN_FIND_OBJECT_ANY, &tmp);
		if (err)
			goto out;
		err = drgn_object_address_of(&tmp, &tmp);
		if (err)
			goto out;
		err = linux_helper_find_task(&obj, &tmp, prog->stack_trace_tid);
		if (err)
			goto out;
		bool found;
		err = drgn_object_bool(&obj, &found);
		if (err)
			goto out;
		if (!found) {
			err = drgn_error_create(DRGN_ERROR_LOOKUP, "task not found");
			goto out;
		}
	}

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
			err = drgn_object_member_dereference(&tmp, &obj, "on_cpu");
			if (!err) {
				bool on_cpu;
				err = drgn_object_bool(&tmp, &on_cpu);
				if (err)
					goto out;
				if (on_cpu) {
					err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
								"cannot unwind stack of running task");
					goto out;
				}
			} else if (err->code == DRGN_ERROR_LOOKUP) {
				/*
				 * The running kernel is !SMP. Assume that the
				 * task isn't running (which can only be wrong
				 * for this thread itself).
				 */
				drgn_error_destroy(err);
			} else {
				goto out;
			}
		} else {
			/*
			 * For kernel core dumps, we look up the PRSTATUS note
			 * by CPU rather than by PID. This is because there is
			 * an idle task with PID 0 for each CPU, so we must find
			 * the idle task by CPU. Rather than making PID 0 a
			 * special case, we handle all tasks this way.
			 */
			union drgn_value value;
			err = drgn_object_member_dereference(&tmp, &obj, "cpu");
			if (!err) {
				err = drgn_object_read_integer(&tmp, &value);
				if (err)
					goto out;
			} else if (err->code == DRGN_ERROR_LOOKUP) {
				/* !SMP. Must be CPU 0. */
				drgn_error_destroy(err);
				value.uvalue = 0;
			} else {
				goto out;
			}
			uint32_t prstatus_tid;
			err = drgn_program_find_prstatus_by_cpu(prog,
								value.uvalue,
								&prstatus,
								&prstatus_tid);
			if (err)
				goto out;
			if (prstatus.str) {
				/*
				 * The PRSTATUS note is for the CPU that the
				 * task is assigned to, but it is not
				 * necessarily for this task. Only use it if the
				 * PID matches.
				 *
				 * Note that this isn't perfect: the PID is
				 * populated by the kernel from "current" (the
				 * current task) via a non-maskable interrupt
				 * (NMI). During a context switch, the stack
				 * pointer and current are not updated
				 * atomically, so if the NMI arrives in the
				 * middle of a context switch, the stack pointer
				 * may not actually be that of current.
				 * Therefore, the stack pointer in PRSTATUS may
				 * not actually be for the PID in PRSTATUS.
				 * Unfortunately, we can't easily fix this.
				 */
				err = drgn_object_member_dereference(&tmp, &obj, "pid");
				if (err)
					goto out;
				err = drgn_object_read_integer(&tmp, &value);
				if (err)
					goto out;
				if (prstatus_tid == value.uvalue)
					goto prstatus;
			}
		}
		if (!prog->platform.arch->linux_kernel_set_initial_registers) {
			err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						"Linux kernel stack unwinding is not supported for %s architecture",
						prog->platform.arch->name);
			goto out;
		}
		err = prog->platform.arch->linux_kernel_set_initial_registers(thread,
									      &obj);
	} else {
		err = drgn_program_find_prstatus_by_tid(prog,
							prog->stack_trace_tid,
							&prstatus);
		if (err)
			goto out;
		if (!prstatus.str) {
			err = drgn_error_create(DRGN_ERROR_LOOKUP, "thread not found");
			goto out;
		}
prstatus:
		if (!prog->platform.arch->prstatus_set_initial_registers) {
			err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						"core dump stack unwinding is not supported for %s architecture",
						prog->platform.arch->name);
			goto out;
		}
		err = prog->platform.arch->prstatus_set_initial_registers(prog,
									  thread,
									  prstatus.str,
									  prstatus.len);
	}

out:
	drgn_object_deinit(&tmp);
	drgn_object_deinit(&obj);
	if (err) {
		drgn_error_destroy(prog->stack_trace_err);
		prog->stack_trace_err = err;
		return false;
	}
	return true;
}

static int drgn_append_stack_frame(Dwfl_Frame *state, void *arg)
{
	struct drgn_stack_trace **tracep = arg;
	struct drgn_stack_trace *trace = *tracep;

	if (trace->num_frames >= trace->capacity) {
		struct drgn_stack_trace *tmp;
		size_t new_capacity, bytes;

		if (__builtin_mul_overflow(2U, trace->capacity,
					   &new_capacity) ||
		    __builtin_mul_overflow(new_capacity,
					   sizeof(trace->frames[0]), &bytes) ||
		    __builtin_add_overflow(bytes, sizeof(*trace), &bytes) ||
		    !(tmp = realloc(trace, bytes))) {
			drgn_error_destroy(trace->prog->stack_trace_err);
			trace->prog->stack_trace_err = &drgn_enomem;
			return DWARF_CB_ABORT;
		}
		*tracep = trace = tmp;
		trace->capacity = new_capacity;
	}
	trace->frames[trace->num_frames++] = state;
	return DWARF_CB_OK;
}

static const Dwfl_Thread_Callbacks drgn_linux_kernel_thread_callbacks = {
	.next_thread = drgn_object_stack_trace_next_thread,
	.memory_read = drgn_thread_memory_read,
	.set_initial_registers = drgn_thread_set_initial_registers,
};

static struct drgn_error *drgn_get_stack_trace(struct drgn_program *prog,
					       uint32_t tid,
					       const struct drgn_object *obj,
					       struct drgn_stack_trace **ret)
{
	struct drgn_error *err;
	Dwfl *dwfl;
	Dwfl_Thread *thread;
	struct drgn_stack_trace *trace;

	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot unwind stack without platform");
	}
	if ((prog->flags & (DRGN_PROGRAM_IS_LINUX_KERNEL |
			    DRGN_PROGRAM_IS_LIVE)) == DRGN_PROGRAM_IS_LIVE) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "stack unwinding is not yet supported for live processes");
	}

	err = drgn_program_get_dwfl(prog, &dwfl);
	if (err)
		return err;
	if (!prog->attached_dwfl_state) {
		if (!dwfl_attach_state(dwfl, NULL, 0,
				       &drgn_linux_kernel_thread_callbacks,
				       prog))
			return drgn_error_libdwfl();
		prog->attached_dwfl_state = true;
	}

	prog->stack_trace_tid = tid;
	prog->stack_trace_obj = obj;
	thread = dwfl_attach_thread(dwfl, STACK_TRACE_OBJ_TID);
	prog->stack_trace_obj = NULL;
	prog->stack_trace_tid = 0;
	if (prog->stack_trace_err)
		goto stack_trace_err;
	if (!thread) {
		err = drgn_error_libdwfl();
		goto err;
	}

	trace = malloc(sizeof(*trace) + sizeof(trace->frames[0]));
	if (!trace) {
		err = &drgn_enomem;
		goto err;
	}
	trace->prog = prog;
	trace->capacity = 1;
	trace->num_frames = 0;

	dwfl_thread_getframes(thread, drgn_append_stack_frame, &trace);
	if (prog->stack_trace_err) {
		free(trace);
		goto stack_trace_err;
	}

	/* Shrink the trace to fit if we can, but don't fail if we can't. */
	if (trace->capacity > trace->num_frames) {
		struct drgn_stack_trace *tmp;

		tmp = realloc(trace,
			      sizeof(*trace) +
			      trace->num_frames * sizeof(trace->frames[0]));
		if (tmp)
			trace = tmp;
	}
	trace->thread = thread;
	*ret = trace;
	return NULL;

stack_trace_err:
	/*
	 * The error reporting for dwfl_getthread_frames() is not great. The
	 * documentation says that some of its unwinder implementations always
	 * return an error. So, we do our own error reporting for fatal errors
	 * through prog->stack_trace_err.
	 */
	err = prog->stack_trace_err;
	prog->stack_trace_err = NULL;
err:
	dwfl_detach_thread(thread);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_stack_trace(struct drgn_program *prog, uint32_t tid,
			 struct drgn_stack_trace **ret)
{
	return drgn_get_stack_trace(prog, tid, NULL, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_object_stack_trace(const struct drgn_object *obj,
			struct drgn_stack_trace **ret)
{
	struct drgn_error *err;

	if (drgn_type_kind(drgn_underlying_type(obj->type)) == DRGN_TYPE_INT) {
		union drgn_value value;

		err = drgn_object_read_integer(obj, &value);
		if (err)
			return err;
		return drgn_get_stack_trace(obj->prog, value.uvalue, NULL, ret);
	} else {
		return drgn_get_stack_trace(obj->prog, 0, obj, ret);
	}
}
