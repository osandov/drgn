// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <byteswap.h>
#include <dwarf.h>
#include <endian.h>
#include <inttypes.h>
#include <stdlib.h>

#include "internal.h"
#include "helpers.h"
#include "program.h"
#include "read.h"
#include "stack_trace.h"
#include "string_builder.h"
#include "symbol.h"

LIBDRGN_PUBLIC void drgn_stack_trace_destroy(struct drgn_stack_trace *trace)
{
	for (int i = 0; i < trace->num_frames; i++)
		free(trace->frames[i].scopes);
	dwfl_detach_thread(trace->thread);
	free(trace);
}

LIBDRGN_PUBLIC int drgn_stack_trace_num_frames(struct drgn_stack_trace *trace)
{
	return trace->num_frames;
}

LIBDRGN_PUBLIC char *drgn_format_stack_trace(struct drgn_stack_trace *trace)
{
	struct string_builder str = {};
	char *ret;

	for (int frame = 0; frame < trace->num_frames; frame++) {
		const char *name;
		const char *filename;
		int line, column;

		if (!string_builder_appendf(&str, "#%-2d ", frame))
			goto enomem;

		name = drgn_stack_frame_name(trace, frame);
		if (name) {
			if (!string_builder_append(&str, name))
				goto enomem;
		} else {
			Dwarf_Addr pc;
			bool isactivation;
			Dwfl_Module *module;
			struct drgn_symbol sym;

			dwfl_frame_pc(trace->frames[frame].state, &pc,
				      &isactivation);
			if (!isactivation)
				pc--;
			module = dwfl_frame_module(trace->frames[frame].state);
			if (module &&
			    drgn_program_find_symbol_by_address_internal(trace->prog,
									 pc,
									 module,
									 &sym)) {
				if (!string_builder_append(&str, sym.name))
					goto enomem;
			} else {
				if (!string_builder_appendf(&str, "%#" PRIx64,
							    pc))
					goto enomem;
			}
		}

		filename = drgn_stack_frame_source(trace, frame, &line,
						   &column);
		if (filename && column) {
			if (!string_builder_appendf(&str, " (%s:%d:%d)",
						    filename, line, column))
				goto enomem;
		} else if (filename) {
			if (!string_builder_appendf(&str, " (%s:%d)", filename,
						    line))
				goto enomem;
		}

		if (frame != trace->num_frames - 1 &&
		    !string_builder_appendc(&str, '\n'))
			goto enomem;
	}
	if (!string_builder_finalize(&str, &ret))
		goto enomem;
	return ret;

enomem:
	free(str.str);
	return NULL;
}

LIBDRGN_PUBLIC char *drgn_format_stack_frame(struct drgn_stack_trace *trace,
					     int frame)
{
	struct string_builder str = {};
	Dwarf_Addr pc;
	bool isactivation;
	Dwfl_Module *module;
	struct drgn_symbol sym;
	const char *name;
	const char *filename;
	int line, column;
	char *ret;

	dwfl_frame_pc(trace->frames[frame].state, &pc, &isactivation);
	if (!string_builder_appendf(&str, "#%d at %#" PRIx64, frame, pc))
		goto enomem;

	module = dwfl_frame_module(trace->frames[frame].state);
	if (module &&
	    drgn_program_find_symbol_by_address_internal(trace->prog,
							 pc - !isactivation,
							 module, &sym) &&
	    !string_builder_appendf(&str, " (%s+%#" PRIx64 "/%#" PRIx64 ")",
				    sym.name, pc - sym.address, sym.size))
		goto enomem;

	name = drgn_stack_frame_name(trace, frame);
	if (name && !string_builder_appendf(&str, " in %s", name))
		goto enomem;

	filename = drgn_stack_frame_source(trace, frame, &line, &column);
	if (filename && column) {
		if (!string_builder_appendf(&str, " at %s:%d:%d", filename,
					    line, column))
			goto enomem;
	} else if (filename) {
		if (!string_builder_appendf(&str, " at %s:%d", filename, line))
			goto enomem;
	}

	if (drgn_stack_frame_is_inline(trace, frame) &&
	    !string_builder_append(&str, " (inlined)"))
		goto enomem;

	if (!string_builder_finalize(&str, &ret))
		goto enomem;
	return ret;

enomem:
	free(str.str);
	return NULL;
}

LIBDRGN_PUBLIC const char *drgn_stack_frame_name(struct drgn_stack_trace *trace,
						 int frame)
{
	Dwarf_Die *scopes = trace->frames[frame].scopes;
	int num_scopes = trace->frames[frame].num_scopes;
	int subprogram = trace->frames[frame].subprogram;

	if (subprogram >= num_scopes)
		return NULL;
	return dwarf_diename(&scopes[subprogram]);
}

LIBDRGN_PUBLIC bool drgn_stack_frame_is_inline(struct drgn_stack_trace *trace,
					       int frame)
{
	Dwarf_Die *scopes = trace->frames[frame].scopes;
	int subprogram = trace->frames[frame].subprogram;

	return (subprogram > 0 &&
		dwarf_tag(&scopes[subprogram - 1]) ==
		DW_TAG_inlined_subroutine);
}

LIBDRGN_PUBLIC const char *
drgn_stack_frame_source(struct drgn_stack_trace *trace, int frame,
			int *line_ret, int *column_ret)
{
	if (frame > 0 &&
	    trace->frames[frame].state == trace->frames[frame - 1].state) {
		/*
		 * This frame is the parent (caller) of an inline frame. Get
		 * the call location from the inlined_subroutine of the callee.
		 */
		Dwarf_Die *inlined_scopes = trace->frames[frame - 1].scopes;
		int inlined_subprogram = trace->frames[frame - 1].subprogram;
		Dwarf_Die *inlined = &inlined_scopes[inlined_subprogram - 1];
		Dwarf_Die inlined_cu;
		Dwarf_Files *files;
		Dwarf_Attribute attr;
		Dwarf_Word value;
		const char *filename;

		if (!dwarf_diecu(inlined, &inlined_cu, NULL, NULL) ||
		    dwarf_getsrcfiles(&inlined_cu, &files, NULL))
			return NULL;
		if (dwarf_formudata(dwarf_attr(inlined, DW_AT_call_file, &attr),
				    &value))
			return NULL;
		filename = dwarf_filesrc(files, value, NULL, NULL);
		if (!filename)
			return NULL;
		if (line_ret) {
			if (dwarf_formudata(dwarf_attr(inlined, DW_AT_call_line,
						       &attr), &value))
				*line_ret = 0;
			else
				*line_ret = value;
		}
		if (column_ret) {
			if (dwarf_formudata(dwarf_attr(inlined,
						       DW_AT_call_column,
						       &attr), &value))
				*column_ret = 0;
			else
				*column_ret = value;
		}
		return filename;
	} else {
		Dwarf_Addr pc;
		bool isactivation;
		Dwfl_Module *module;
		Dwfl_Line *line;

		dwfl_frame_pc(trace->frames[frame].state, &pc, &isactivation);
		if (!isactivation)
			pc--;
		module = dwfl_frame_module(trace->frames[frame].state);
		if (!module)
			return NULL;
		line = dwfl_module_getsrc(module, pc);
		if (!line)
			return NULL;
		return dwfl_lineinfo(line, NULL, line_ret, column_ret, NULL,
				     NULL);
	}
}

LIBDRGN_PUBLIC uint64_t drgn_stack_frame_pc(struct drgn_stack_trace *trace,
					    int frame)
{
	Dwarf_Addr pc;

	dwfl_frame_pc(trace->frames[frame].state, &pc, NULL);
	return pc;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_symbol(struct drgn_stack_trace *trace, int frame,
			struct drgn_symbol **ret)
{
	Dwarf_Addr pc;
	bool isactivation;
	Dwfl_Module *module;
	struct drgn_symbol *sym;

	dwfl_frame_pc(trace->frames[frame].state, &pc, &isactivation);
	if (!isactivation)
		pc--;
	module = dwfl_frame_module(trace->frames[frame].state);
	if (!module)
		return drgn_error_symbol_not_found(pc);
	sym = malloc(sizeof(*sym));
	if (!sym)
		return &drgn_enomem;
	if (!drgn_program_find_symbol_by_address_internal(trace->prog, pc,
							  module, sym)) {
		free(sym);
		return drgn_error_symbol_not_found(pc);
	}
	*ret = sym;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_register(struct drgn_stack_trace *trace, int frame,
			  enum drgn_register_number regno, uint64_t *ret)
{
	Dwarf_Addr value;

	if (!dwfl_frame_register(trace->frames[frame].state, regno, &value)) {
		return drgn_error_create(DRGN_ERROR_LOOKUP,
					 "register value is not known");
	}
	*ret = value;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_register_by_name(struct drgn_stack_trace *trace, int frame,
				  const char *name, uint64_t *ret)
{
	const struct drgn_register *reg;

	reg = drgn_architecture_register_by_name(trace->prog->platform.arch,
						 name);
	if (!reg) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "unknown register '%s'", name);
	}
	return drgn_stack_frame_register(trace, frame, reg->number, ret);
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
		bool found;

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
			prstatus.str = NULL;
			prstatus.len = 0;
		} else {
			union drgn_value value;
			uint32_t cpu;

			err = drgn_object_member_dereference(&tmp, &obj, "cpu");
			if (!err) {
				err = drgn_object_read_integer(&tmp, &value);
				if (err)
					goto out;
				cpu = value.uvalue;
			} else if (err->code == DRGN_ERROR_LOOKUP) {
				/* !SMP. Must be CPU 0. */
				drgn_error_destroy(err);
				cpu = 0;
			} else {
				goto out;
			}
			err = drgn_program_find_prstatus_by_cpu(prog, cpu,
								&prstatus);
			if (err)
				goto out;
		}
		if (!prog->platform.arch->linux_kernel_set_initial_registers) {
			err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						"Linux kernel stack unwinding is not supported for %s architecture",
						prog->platform.arch->name);
			goto out;
		}
		err = prog->platform.arch->linux_kernel_set_initial_registers(thread,
									      &obj,
									      prstatus.str,
									      prstatus.len);
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

static bool append_stack_frame(struct drgn_stack_trace **tracep,
			       Dwfl_Frame *state, Dwarf_Die *scopes,
			       int num_scopes, int subprogram)
{
	struct drgn_stack_trace *trace = *tracep;
	struct drgn_stack_frame *frame;

	if (trace->num_frames >= trace->capacity) {
		struct drgn_stack_trace *tmp;
		int new_capacity;
		size_t bytes;

		if (__builtin_mul_overflow(2, trace->capacity, &new_capacity) ||
		    __builtin_mul_overflow(new_capacity,
					   sizeof(trace->frames[0]), &bytes) ||
		    __builtin_add_overflow(bytes, sizeof(*trace), &bytes) ||
		    !(tmp = realloc(trace, bytes)))
			return false;
		*tracep = trace = tmp;
		trace->capacity = new_capacity;
	}
	frame = &trace->frames[trace->num_frames++];
	frame->state = state;
	frame->scopes = scopes;
	frame->num_scopes = num_scopes;
	frame->subprogram = subprogram;
	return true;
}

static struct drgn_error *append_scopes(Dwfl_Frame *state,
					struct drgn_stack_trace **tracep)
{
	struct drgn_error *err;
	Dwarf_Addr pc;
	bool isactivation;
	Dwfl_Module *module;
	Dwarf_Addr bias;
	Dwarf_Die *cu;
	Dwarf_Die *scopes;
	int num_scopes;
	int first_scope;
	int subprogram;
	int frame_num_scopes;
	Dwarf_Die *frame_scopes;

	dwfl_frame_pc(state, &pc, &isactivation);
	if (!isactivation)
		pc--;
	module = dwfl_frame_module(state);
	if (!module)
		return &drgn_not_found;
	cu = dwfl_module_addrdie(module, pc, &bias);
	if (!cu)
		return &drgn_not_found;
	num_scopes = dwarf_getallscopes(cu, pc - bias, &scopes);
	if (num_scopes <= 0)
		return &drgn_not_found;

	first_scope = 0;
	subprogram = -1;
	for (int i = 0; i < num_scopes; i++) {
		switch (dwarf_tag(&scopes[i])) {
		case DW_TAG_subprogram:
			subprogram = i - first_scope;
			break;
		case DW_TAG_inlined_subroutine: {
			Dwarf_Attribute attr_mem;

			/*
			 * +2 for this inlined_subroutine and its
			 * abstract_origin.
			 */
			frame_num_scopes = i - first_scope + 2;
			frame_scopes = malloc_array(frame_num_scopes,
						    sizeof(*frame_scopes));
			if (!frame_scopes) {
				err = &drgn_enomem;
				goto out;
			}
			memcpy(frame_scopes, &scopes[first_scope],
			       (frame_num_scopes - 1) * sizeof(*frame_scopes));
			subprogram = frame_num_scopes - 1;
			if (dwarf_formref_die(dwarf_attr(&scopes[i],
							 DW_AT_abstract_origin,
							 &attr_mem),
					      &frame_scopes[subprogram])) {
				if (!append_stack_frame(tracep, state,
							frame_scopes,
							frame_num_scopes,
							subprogram)) {
					free(frame_scopes);
					err = &drgn_enomem;
					goto out;
				}
			} else {
				/*
				 * The abstract_origin is missing or invalid.
				 * Omit this subroutine.
				 */
				free(frame_scopes);
			}
			first_scope = i + 1;
			subprogram = -1;
			break;
		}
		default:
			break;
		}
	}
	if (subprogram == -1) {
		/*
		 * The subprogram is missing. Fall back to a scopeless frame.
		 * (We may or may not have found inline subroutines.)
		 */
		err = &drgn_not_found;
		goto out;
	}

	frame_num_scopes = num_scopes - first_scope;
	frame_scopes = malloc_array(frame_num_scopes,
				    sizeof(*frame_scopes));
	if (!frame_scopes) {
		err = &drgn_enomem;
		goto out;
	}
	memcpy(frame_scopes, &scopes[first_scope],
	       frame_num_scopes * sizeof(*frame_scopes));
	if (!append_stack_frame(tracep, state, frame_scopes, frame_num_scopes,
				subprogram)) {
		free(frame_scopes);
		err = &drgn_enomem;
		goto out;
	}
	err = NULL;
out:
	free(scopes);
	return err;
}

static int drgn_append_dwfl_frame(Dwfl_Frame *state, void *arg)
{
	struct drgn_stack_trace **tracep = arg;
	struct drgn_error *err;

	err = append_scopes(state, tracep);
	if (err == &drgn_not_found) {
		if (append_stack_frame(tracep, state, NULL, 0, 0))
			err = NULL;
		else
			err = &drgn_enomem;
	}
	if (err) {
		drgn_error_destroy((*tracep)->prog->stack_trace_err);
		(*tracep)->prog->stack_trace_err = err;
		return DWARF_CB_ABORT;
	}
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
	if (!thread)
		return drgn_error_libdwfl();

	trace = malloc(sizeof(*trace) + sizeof(trace->frames[0]));
	if (!trace) {
		err = &drgn_enomem;
		goto err;
	}
	trace->prog = prog;
	trace->capacity = 1;
	trace->num_frames = 0;

	dwfl_thread_getframes(thread, drgn_append_dwfl_frame, &trace);
	if (prog->stack_trace_err) {
		trace->thread = NULL;
		drgn_stack_trace_destroy(trace);
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
