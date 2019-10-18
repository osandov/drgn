// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <endian.h>
#include <inttypes.h>
#include <stdlib.h>

#include "internal.h"
#include "program.h"
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
drgn_pretty_print_stack_trace(struct drgn_stack_trace *trace, char **ret)
{
	struct drgn_error *err;
	struct string_builder str = {};
	struct drgn_stack_frame frame = { .trace = trace, };

	for (; frame.i < trace->num_frames; frame.i++) {
		uint64_t pc;
		Dwfl_Module *module;
		struct drgn_symbol sym;

		pc = drgn_stack_frame_pc(frame);
		module = dwfl_frame_module(trace->frames[frame.i]);
		if (module) {
			err = drgn_program_find_symbol_internal(trace->prog,
								module, pc,
								&sym);
		} else {
			err = &drgn_not_found;
		}
		if (err && err != &drgn_not_found)
			goto err;
		if (!string_builder_appendf(&str, "#%-2zu ", frame.i)) {
			err = &drgn_enomem;
			goto err;
		}
		if (err) {
			if (!string_builder_appendf(&str, "0x%" PRIx64, pc)) {
				err = &drgn_enomem;
				goto err;
			}
		} else {
			if (!string_builder_appendf(&str,
						    "%s+0x%" PRIx64 "/0x%" PRIx64,
						    sym.name, pc - sym.address,
						    sym.size)) {
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
	Dwfl_Module *module;

	module = dwfl_frame_module(frame.trace->frames[frame.i]);
	return drgn_program_find_symbol_in_module(frame.trace->prog, module,
						  drgn_stack_frame_pc(frame),
						  ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_register(struct drgn_stack_frame frame,
			  enum drgn_register_number regno, uint64_t *ret)
{
	const Dwarf_Op op = { .atom = DW_OP_regx, .number = regno, };
	Dwarf_Addr value;

	if (!dwfl_frame_eval_expr(frame.trace->frames[frame.i], &op, 1, &value))
		return drgn_error_libdwfl();
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
	bool is_little_endian = drgn_program_is_little_endian(prog);

	if (drgn_program_is_64_bit(prog)) {
		uint64_t u64;

		err = drgn_program_read_memory(prog, &u64, addr, sizeof(u64),
					       false);
		if (err)
			goto err;
		*result = is_little_endian ? le64toh(u64) : be64toh(u64);
	} else {
		uint32_t u32;

		err = drgn_program_read_memory(prog, &u32, addr, sizeof(u32),
					       false);
		if (err)
			goto err;
		*result = is_little_endian ? le32toh(u32) : be32toh(u32);
	}
	return true;

err:
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

/*
 * For drgn_object_stack_trace(), we only care about the thread
 * prog->stack_trace_obj. We return it with an arbitrary TID.
 */
#define STACK_TRACE_OBJ_TID 1
static pid_t drgn_object_stack_trace_next_thread(Dwfl *dwfl, void *dwfl_arg,
						 void **thread_argp)
{
	struct drgn_program *prog = dwfl_arg;

	if (*thread_argp || !prog->stack_trace_obj)
		return 0;
	*thread_argp = (void *)prog->stack_trace_obj;
	return STACK_TRACE_OBJ_TID;
}

static bool drgn_linux_kernel_set_initial_registers(Dwfl_Thread *thread,
						    void *thread_arg)
{
	struct drgn_error *err;
	struct drgn_object *task_obj = thread_arg;
	struct drgn_program *prog = task_obj->prog;

	err = prog->platform.arch->linux_kernel_set_initial_registers(thread,
								      task_obj);
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
	.set_initial_registers = drgn_linux_kernel_set_initial_registers,
};

struct drgn_error *drgn_object_stack_trace(const struct drgn_object *obj,
					   struct drgn_stack_trace **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = obj->prog;
	Dwfl *dwfl;
	Dwfl_Thread *thread;
	struct drgn_stack_trace *trace;

	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot unwind stack without platform");
	}
	if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "stack unwinding is currently only supported for the Linux kernel");
	}
	if (!prog->platform.arch->linux_kernel_set_initial_registers) {
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "stack unwinding is not supported for %s architecture",
					 prog->platform.arch->name);
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

	prog->stack_trace_obj = obj;
	thread = dwfl_attach_thread(dwfl, STACK_TRACE_OBJ_TID);
	prog->stack_trace_obj = NULL;
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
