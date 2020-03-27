// Copyright 2019-2020 - Omar Sandoval
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
		uint64_t pc;
		Dwfl_Module *module;
		struct drgn_symbol sym;

		if (!string_builder_appendf(&str, "#%-2zu ", frame.i)) {
			err = &drgn_enomem;
			goto err;
		}

		pc = drgn_stack_frame_pc(frame);
		module = dwfl_frame_module(trace->frames[frame.i]);
		if (module &&
		    drgn_program_find_symbol_by_address_internal(trace->prog,
								 pc, module,
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
	uint64_t pc;
	Dwfl_Module *module;
	struct drgn_symbol *sym;

	pc = drgn_stack_frame_pc(frame);
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

static struct drgn_error *
drgn_pt_regs_set_initial_registers(Dwfl_Thread *thread,
				   struct drgn_platform *platform,
				   const struct drgn_object *pt_regs)
{
	struct drgn_error *err;
	struct drgn_object obj;
	size_t i;

	drgn_object_init(&obj, pt_regs->prog);

	if (!platform->arch->num_frame_registers) {
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "pt_regs stack unwinding is not supported for %s architecture",
					 platform->arch->name);
	}

	for (i = 0; i < platform->arch->num_frame_registers; i++) {
		const struct drgn_frame_register *reg;
		union drgn_value value;
		Dwarf_Word word;

		reg = &platform->arch->frame_registers[i];
		err = drgn_object_member(&obj, pt_regs, reg->pt_regs_name);
		if (err && err->code == DRGN_ERROR_LOOKUP &&
		    reg->pt_regs_name2) {
			drgn_error_destroy(err);
			err = drgn_object_member(&obj, pt_regs,
						 reg->pt_regs_name2);
		}
		if (err)
			goto out;
		err = drgn_object_read_integer(&obj, &value);
		if (err)
			goto out;
		word = value.uvalue;
		if (!dwfl_thread_state_registers(thread, reg->number, 1, &word))
			return drgn_error_libdwfl();
	}
	err = NULL;
out:
	drgn_object_deinit(&obj);
	return err;
}

static struct drgn_error *
drgn_get_task_pid(const struct drgn_object *task, uint32_t *ret)
{
	struct drgn_error *err;
	struct drgn_object pid;
	union drgn_value value;

	drgn_object_init(&pid, task->prog);
	err = drgn_object_member_dereference(&pid, task, "pid");
	if (err)
		goto out;
	err = drgn_object_read_integer(&pid, &value);
	if (err)
		goto out;
	*ret = value.uvalue;
out:
	drgn_object_deinit(&pid);
	return err;
}

static struct drgn_error *
drgn_prstatus_set_initial_registers(Dwfl_Thread *thread,
				    struct drgn_platform *platform,
				    struct string *prstatus)
{
	bool bswap = (!!(platform->flags & DRGN_PLATFORM_IS_LITTLE_ENDIAN) !=
		      (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__));
	size_t i;

	if (!platform->arch->num_frame_registers) {
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "core dump stack unwinding is not supported for %s architecture",
					 platform->arch->name);
	}

	for (i = 0; i < platform->arch->num_frame_registers; i++) {
		const struct drgn_frame_register *reg;
		const char *p;
		Dwarf_Word word;

		reg = &platform->arch->frame_registers[i];
		if (prstatus->len < reg->prstatus_offset + reg->size) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "NT_PRSTATUS is truncated");
		}
		p = prstatus->str + reg->prstatus_offset;
		switch (reg->size) {
		case 4: {
			uint32_t tmp;

			memcpy(&tmp, p, sizeof(tmp));
			if (bswap)
				tmp = bswap_32(tmp);
			word = tmp;
			break;
		}
		case 8: {
			uint64_t tmp;

			memcpy(&tmp, p, sizeof(tmp));
			if (bswap)
				tmp = bswap_64(tmp);
			word = tmp;
			break;
		}
		default:
			DRGN_UNREACHABLE();
		}
		if (!dwfl_thread_state_registers(thread, reg->number, 1, &word))
			return drgn_error_libdwfl();
	}
	return NULL;
}

static bool drgn_thread_set_initial_registers(Dwfl_Thread *thread,
					      void *thread_arg)
{
	struct drgn_error *err;
	struct drgn_program *prog = thread_arg;
	struct drgn_object obj;
	bool truthy;
	char state;

	drgn_object_init(&obj, prog);

	/* First, try pt_regs. */
	if (prog->stack_trace_obj) {
		bool is_pt_regs;

		err = drgn_get_stack_trace_obj(&obj, prog, &is_pt_regs);
		if (err)
			goto out;

		if (is_pt_regs) {
			assert(obj.kind == DRGN_OBJECT_BUFFER);
			err = drgn_pt_regs_set_initial_registers(thread,
								 &prog->platform,
								 &obj);
			goto out;
		}
	}

	/* Then, try the core dump (and/or kdump if supported). */
#ifdef WITH_LIBKDUMPFILE
	if (prog->core || prog->kdump_ctx) {
#else
	if (prog->core) {
#endif
		uint32_t tid;
		struct string prstatus;

		if (prog->stack_trace_obj) {
			err = drgn_get_task_pid(&obj, &tid);
			if (err)
				goto out;
		} else {
			tid = prog->stack_trace_tid;
		}
		err = drgn_program_find_prstatus(prog, tid, &prstatus);
		if (err)
			goto out;
		if (prstatus.str) {
			err = drgn_prstatus_set_initial_registers(thread,
								  &prog->platform,
								  &prstatus);
			goto out;
		}
	}

	/* Finally, try the task_struct. */
	if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		err = drgn_error_create(DRGN_ERROR_LOOKUP, "thread not found");
		goto out;
	}

	if (!prog->platform.arch->linux_kernel_set_initial_registers) {
		err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					"Linux kernel stack unwinding is not supported for %s architecture",
					prog->platform.arch->name);
		goto out;
	}

	if (!prog->stack_trace_obj) {
		struct drgn_object ns;

		drgn_object_init(&ns, prog);
		err = drgn_program_find_object(prog, "init_pid_ns", NULL,
					       DRGN_FIND_OBJECT_ANY, &ns);
		if (!err)
			err = drgn_object_address_of(&ns, &ns);
		if (!err) {
			err = linux_helper_find_task(&obj, &ns,
						     prog->stack_trace_tid);
		}
		drgn_object_deinit(&ns);
		if (err)
			goto out;
	}
	err = drgn_object_bool(&obj, &truthy);
	if (err)
		goto out;
	if (!truthy) {
		err = drgn_error_create(DRGN_ERROR_LOOKUP, "task not found");
		goto out;
	}

	err = linux_helper_task_state_to_char(&obj, &state);
	if (err)
		goto out;
	if (state == 'R') {
		err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					"cannot unwind stack of running task");
		goto out;
	}

	err = prog->platform.arch->linux_kernel_set_initial_registers(thread,
								      &obj);
out:
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
