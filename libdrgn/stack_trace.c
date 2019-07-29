// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <elfutils/libdwfl.h>
#include <endian.h>
#include <inttypes.h>
#include <stdlib.h>

#include "internal.h"
#include "program.h"
#include "string_builder.h"
#include "symbol.h"

struct drgn_stack_frame {
	struct drgn_program *prog;
	uint64_t pc;
};

struct drgn_stack_trace {
	size_t num_frames;
	struct drgn_stack_frame frames[];
};

LIBDRGN_PUBLIC void drgn_stack_trace_destroy(struct drgn_stack_trace *trace)
{
	free(trace);
}

LIBDRGN_PUBLIC
size_t drgn_stack_trace_num_frames(struct drgn_stack_trace *trace)
{
	return trace->num_frames;
}

LIBDRGN_PUBLIC struct drgn_stack_frame *
drgn_stack_trace_frame(struct drgn_stack_trace *trace, size_t i)
{
	if (i >= trace->num_frames)
		return NULL;
	return &trace->frames[i];
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_pretty_print_stack_trace(struct drgn_stack_trace *trace, char **ret)
{
	struct drgn_error *err;
	struct string_builder str = {};
	size_t i;

	for (i = 0; i < trace->num_frames; i++) {
		struct drgn_stack_frame *frame = &trace->frames[i];
		uint64_t pc;
		struct drgn_symbol sym;

		pc = drgn_stack_frame_pc(frame);
		err = drgn_program_find_symbol_internal(frame->prog, pc, &sym);
		if (err && err != &drgn_not_found)
			goto err;
		if (!string_builder_appendf(&str, "#%-2zu ", i)) {
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
		if (i != trace->num_frames - 1 &&
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

LIBDRGN_PUBLIC uint64_t drgn_stack_frame_pc(struct drgn_stack_frame *frame)
{
	return frame->pc;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_symbol(struct drgn_stack_frame *frame,
			struct drgn_symbol **ret)
{
	return drgn_program_find_symbol(frame->prog, frame->pc, ret);
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
 * prog->stack_trace_obj. We return it with an arbitrary PID.
 */
#define STACK_TRACE_OBJ_PID 1
static pid_t drgn_object_stack_trace_next_thread(Dwfl *dwfl, void *dwfl_arg,
						 void **thread_argp)
{
	struct drgn_program *prog = dwfl_arg;

	if (*thread_argp || !prog->stack_trace_obj)
		return 0;
	*thread_argp = (void *)prog->stack_trace_obj;
	return STACK_TRACE_OBJ_PID;
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

struct drgn_stack_trace_builder {
	struct drgn_program *prog;
	struct drgn_stack_trace *trace;
	size_t capacity;
};

static int drgn_append_stack_frame(Dwfl_Frame *dwfl_frame, void *arg)
{
	struct drgn_error *err;
	struct drgn_stack_trace_builder *builder = arg;
	struct drgn_program *prog = builder->prog;
	struct drgn_stack_trace *trace = builder->trace;
	struct drgn_stack_frame *frame;
	Dwarf_Addr pc;

	if (!dwfl_frame_pc(dwfl_frame, &pc, NULL)) {
		err = drgn_error_libdwfl();
		goto err;
	}

	if (trace->num_frames >= builder->capacity) {
		size_t new_capacity, bytes;

		if (__builtin_mul_overflow(2U, builder->capacity,
					   &new_capacity) ||
		    __builtin_mul_overflow(new_capacity,
					   sizeof(trace->frames[0]), &bytes) ||
		    __builtin_add_overflow(bytes, sizeof(*trace), &bytes) ||
		    !(trace = realloc(trace, bytes))) {
			err = &drgn_enomem;
			goto err;
		}
		builder->trace = trace;
		builder->capacity = new_capacity;
	}
	frame = &trace->frames[trace->num_frames++];
	frame->prog = prog;
	frame->pc = pc;
	return DWARF_CB_OK;

err:
	drgn_error_destroy(prog->stack_trace_err);
	prog->stack_trace_err = err;
	return DWARF_CB_ABORT;
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
	struct drgn_stack_trace_builder builder;
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

	builder.prog = prog;
	builder.trace = malloc(sizeof(*builder.trace) +
			       sizeof(builder.trace->frames[0]));
	if (!builder.trace)
		return &drgn_enomem;
	builder.trace->num_frames = 0;
	builder.capacity = 1;

	prog->stack_trace_obj = obj;
	dwfl_getthread_frames(dwfl, STACK_TRACE_OBJ_PID,
			      drgn_append_stack_frame, &builder);
	prog->stack_trace_obj = NULL;
	/*
	 * The error reporting for dwfl_getthread_frames() is not great. The
	 * documentation says that some of its unwinder implementations always
	 * return an error. So, we do our own error reporting for fatal errors
	 * through prog->stack_trace_err.
	 */
	if (prog->stack_trace_err) {
		err = prog->stack_trace_err;
		prog->stack_trace_err = NULL;
		goto err;
	}

	/* Shrink the trace to fit if we can, but don't fail if we can't. */
	trace = realloc(builder.trace,
			sizeof(*builder.trace) +
			builder.trace->num_frames *
			sizeof(builder.trace->frames[0]));
	if (!trace)
		trace = builder.trace;
	*ret = trace;
	return NULL;

err:
	free(builder.trace);
	return err;
}
