// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>
#include <byteswap.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "cfi.h"
#include "debug_info.h"
#include "drgn.h"
#include "dwarf_info.h"
#include "error.h"
#include "helpers.h"
#include "minmax.h"
#include "nstring.h"
#include "platform.h"
#include "program.h"
#include "register_state.h"
#include "serialize.h"
#include "stack_trace.h"
#include "string_builder.h"
#include "symbol.h"
#include "type.h"
#include "util.h"

static struct drgn_error *
drgn_stack_trace_append_frame(struct drgn_stack_trace **trace, size_t *capacity,
			      struct drgn_register_state *regs,
			      Dwarf_Die *scopes, size_t num_scopes,
			      size_t function_scope)
{
	if ((*trace)->num_frames == *capacity) {
		static const size_t max_capacity =
			(SIZE_MAX - sizeof(struct drgn_stack_trace)) /
			sizeof(struct drgn_stack_frame);
		if (*capacity == max_capacity)
			return &drgn_enomem;
		size_t new_capacity;
		if (*capacity > max_capacity / 2)
			new_capacity = max_capacity;
		else
			new_capacity = 2 * (*capacity);
		struct drgn_stack_trace *new_trace =
			realloc((*trace),
				offsetof(struct drgn_stack_trace,
					 frames[new_capacity]));
		if (!new_trace)
			return &drgn_enomem;
		*trace = new_trace;
		*capacity = new_capacity;
	}
	struct drgn_stack_frame *frame =
		&(*trace)->frames[(*trace)->num_frames++];
	frame->regs = regs;
	frame->scopes = scopes;
	frame->num_scopes = num_scopes;
	frame->function_scope = function_scope;
	return NULL;
}

static void drgn_stack_trace_shrink_to_fit(struct drgn_stack_trace **trace,
					   size_t capacity)
{
	size_t num_frames = (*trace)->num_frames;
	if (capacity > num_frames) {
		struct drgn_stack_trace *new_trace =
			realloc((*trace),
				offsetof(struct drgn_stack_trace,
					 frames[num_frames]));
		if (new_trace)
			*trace = new_trace;
	}
}

LIBDRGN_PUBLIC void drgn_stack_trace_destroy(struct drgn_stack_trace *trace)
{
	struct drgn_register_state *regs = NULL;
	for (size_t i = 0; i < trace->num_frames; i++) {
		if (trace->frames[i].regs != regs) {
			drgn_register_state_destroy(regs);
			regs = trace->frames[i].regs;
		}
		free(trace->frames[i].scopes);
	}
	drgn_register_state_destroy(regs);
	free(trace);
}

LIBDRGN_PUBLIC size_t
drgn_stack_trace_num_frames(struct drgn_stack_trace *trace)
{
	return trace->num_frames;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_stack_trace(struct drgn_stack_trace *trace, char **ret)
{
	struct string_builder str = {};
	for (size_t frame = 0; frame < trace->num_frames; frame++) {
		if (!string_builder_appendf(&str, "#%-2zu ", frame))
			goto enomem;

		struct drgn_register_state *regs = trace->frames[frame].regs;
		struct optional_uint64 pc;
		const char *name = drgn_stack_frame_name(trace, frame);
		if (name) {
			if (!string_builder_append(&str, name))
				goto enomem;
		} else if ((pc = drgn_register_state_get_pc(regs)).has_value) {
			Dwfl_Module *dwfl_module =
				regs->module ? regs->module->dwfl_module : NULL;
			struct drgn_symbol sym;
			if (dwfl_module &&
			    drgn_program_find_symbol_by_address_internal(trace->prog,
									 pc.value - !regs->interrupted,
									 dwfl_module,
									 &sym)) {
				if (!string_builder_appendf(&str,
							    "%s+0x%" PRIx64 "/0x%" PRIx64,
							    sym.name,
							    pc.value - sym.address,
							    sym.size))
					goto enomem;
			} else {
				if (!string_builder_appendf(&str, "0x%" PRIx64,
							    pc.value))
					goto enomem;
			}
		} else {
			if (!string_builder_append(&str, "???"))
				goto enomem;
		}

		int line, column;
		const char *filename = drgn_stack_frame_source(trace, frame,
							       &line, &column);
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
	if (!string_builder_finalize(&str, ret))
		goto enomem;
	return NULL;

enomem:
	free(str.str);
	return &drgn_enomem;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_stack_frame(struct drgn_stack_trace *trace, size_t frame, char **ret)
{
	struct string_builder str = {};
	struct drgn_register_state *regs = trace->frames[frame].regs;
	if (!string_builder_appendf(&str, "#%zu at ", frame))
		goto enomem;

	struct optional_uint64 pc = drgn_register_state_get_pc(regs);
	if (pc.has_value) {
		if (!string_builder_appendf(&str, "%#" PRIx64, pc.value))
			goto enomem;

		Dwfl_Module *dwfl_module =
			regs->module ? regs->module->dwfl_module : NULL;
		struct drgn_symbol sym;
		if (dwfl_module &&
		    drgn_program_find_symbol_by_address_internal(trace->prog,
								 pc.value - !regs->interrupted,
								 dwfl_module,
								 &sym) &&
		    !string_builder_appendf(&str, " (%s+0x%" PRIx64 "/0x%" PRIx64 ")",
					    sym.name, pc.value - sym.address,
					    sym.size))
				goto enomem;
	} else {
		if (!string_builder_append(&str, "???"))
			goto enomem;
	}

	const char *name = drgn_stack_frame_name(trace, frame);
	if (name && !string_builder_appendf(&str, " in %s", name))
		goto enomem;

	int line, column;
	const char *filename = drgn_stack_frame_source(trace, frame, &line,
						       &column);
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

	if (!string_builder_finalize(&str, ret))
		goto enomem;
	return NULL;

enomem:
	free(str.str);
	return &drgn_enomem;
}

LIBDRGN_PUBLIC const char *drgn_stack_frame_name(struct drgn_stack_trace *trace,
						 size_t frame)
{
	Dwarf_Die *scopes = trace->frames[frame].scopes;
	size_t num_scopes = trace->frames[frame].num_scopes;
	size_t function_scope = trace->frames[frame].function_scope;
	if (function_scope >= num_scopes)
		return NULL;
	return dwarf_diename(&scopes[function_scope]);
}

LIBDRGN_PUBLIC bool drgn_stack_frame_is_inline(struct drgn_stack_trace *trace,
					       size_t frame)
{
	Dwarf_Die *scopes = trace->frames[frame].scopes;
	size_t num_scopes = trace->frames[frame].num_scopes;
	size_t function_scope = trace->frames[frame].function_scope;
	return (function_scope < num_scopes &&
		dwarf_tag(&scopes[function_scope]) ==
		DW_TAG_inlined_subroutine);
}

LIBDRGN_PUBLIC const char *
drgn_stack_frame_source(struct drgn_stack_trace *trace, size_t frame,
			int *line_ret, int *column_ret)
{
	if (frame > 0 &&
	    trace->frames[frame].regs == trace->frames[frame - 1].regs) {
		/*
		 * This frame is the caller of an inline frame. Get the call
		 * location from the inlined_subroutine of the callee.
		 */
		Dwarf_Die *inlined_scopes = trace->frames[frame - 1].scopes;
		size_t inlined_num_scopes = trace->frames[frame - 1].num_scopes;
		size_t inlined_function_scope =
			trace->frames[frame - 1].function_scope;
		if (inlined_function_scope >= inlined_num_scopes)
			return NULL;
		Dwarf_Die *inlined = &inlined_scopes[inlined_function_scope];

		Dwarf_Die inlined_cu;
		Dwarf_Files *files;
		if (!dwarf_diecu(inlined, &inlined_cu, NULL, NULL) ||
		    dwarf_getsrcfiles(&inlined_cu, &files, NULL))
			return NULL;

		Dwarf_Attribute attr;
		Dwarf_Word value;
		if (dwarf_formudata(dwarf_attr(inlined, DW_AT_call_file, &attr),
				    &value))
			return NULL;

		const char *filename = dwarf_filesrc(files, value, NULL, NULL);
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
	} else if (trace->frames[frame].num_scopes > 0) {
		struct drgn_register_state *regs = trace->frames[frame].regs;
		Dwfl_Module *dwfl_module =
			regs->module ? regs->module->dwfl_module : NULL;
		if (!dwfl_module)
			return NULL;

		struct optional_uint64 pc = drgn_register_state_get_pc(regs);
		if (!pc.has_value)
			return NULL;
		Dwarf_Addr bias;
		if (!dwfl_module_getdwarf(dwfl_module, &bias))
			return NULL;
		pc.value = pc.value - bias - !regs->interrupted;

		Dwarf_Die *scopes = trace->frames[frame].scopes;
		size_t num_scopes = trace->frames[frame].num_scopes;
		Dwarf_Die cu_die;
		if (!dwarf_cu_die(scopes[num_scopes - 1].cu, &cu_die, NULL,
				  NULL, NULL, NULL, NULL, NULL))
			return NULL;

		Dwarf_Line *line = dwarf_getsrc_die(&cu_die, pc.value);
		if (!line)
			return NULL;
		if (line_ret)
			dwarf_lineno(line, line_ret);
		if (column_ret)
			dwarf_linecol(line, column_ret);
		return dwarf_linesrc(line, NULL, NULL);
	} else {
		return NULL;
	}
}

LIBDRGN_PUBLIC bool drgn_stack_frame_interrupted(struct drgn_stack_trace *trace,
						 size_t frame)
{
	return trace->frames[frame].regs->interrupted;
}

LIBDRGN_PUBLIC bool drgn_stack_frame_pc(struct drgn_stack_trace *trace,
					size_t frame, uint64_t *ret)
{
	struct optional_uint64 pc =
		drgn_register_state_get_pc(trace->frames[frame].regs);
	if (pc.has_value)
		*ret = pc.value;
	return pc.has_value;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_symbol(struct drgn_stack_trace *trace, size_t frame,
			struct drgn_symbol **ret)
{
	struct drgn_register_state *regs = trace->frames[frame].regs;
	struct optional_uint64 pc = drgn_register_state_get_pc(regs);
	if (!pc.has_value) {
		return drgn_error_create(DRGN_ERROR_LOOKUP,
					 "program counter is not known at stack frame");
	}
	pc.value -= !regs->interrupted;
	Dwfl_Module *dwfl_module =
		regs->module ? regs->module->dwfl_module : NULL;
	if (!dwfl_module)
		return drgn_error_symbol_not_found(pc.value);
	struct drgn_symbol *sym = malloc(sizeof(*sym));
	if (!sym)
		return &drgn_enomem;
	if (!drgn_program_find_symbol_by_address_internal(trace->prog, pc.value,
							  dwfl_module, sym)) {
		free(sym);
		return drgn_error_symbol_not_found(pc.value);
	}
	*ret = sym;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_find_object(struct drgn_stack_trace *trace, size_t frame_i,
			     const char *name, struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_stack_frame *frame = &trace->frames[frame_i];

	if (frame->function_scope >= frame->num_scopes)
		goto not_found;

	Dwarf_Die die, type_die;
	err = drgn_find_in_dwarf_scopes(frame->scopes, frame->num_scopes, name,
					&die, &type_die);
	if (err)
		return err;
	if (!die.addr && frame->function_scope == 0) {
		/*
		 * Scope 0 must be a DW_TAG_inlined_subroutine, and we didn't
		 * find the name in the concrete inlined instance tree. We need
		 * to find the scopes that contain the the abstract instance
		 * root (i.e, the DW_TAG_subprogram definition). (We could do
		 * this ahead of time when unwinding the stack, but for
		 * efficiency we do it lazily.)
		 */
		Dwarf_Attribute attr_mem, *attr;
		if (!(attr = dwarf_attr(frame->scopes, DW_AT_abstract_origin,
					&attr_mem)))
			goto not_found;
		Dwarf_Die abstract_origin;
		if (!dwarf_formref_die(attr, &abstract_origin))
			return drgn_error_libdw();

		Dwarf_Die *ancestors;
		size_t num_ancestors;
		err = drgn_find_die_ancestors(&abstract_origin, &ancestors,
					      &num_ancestors);
		if (err)
			return err;

		size_t new_num_scopes = num_ancestors + frame->num_scopes;
		Dwarf_Die *new_scopes = realloc(ancestors,
						new_num_scopes *
						sizeof(*new_scopes));
		if (!new_scopes) {
			free(ancestors);
			return &drgn_enomem;
		}
		memcpy(&new_scopes[num_ancestors], frame->scopes,
		       frame->num_scopes * sizeof(*new_scopes));
		free(frame->scopes);
		frame->scopes = new_scopes;
		frame->num_scopes = new_num_scopes;
		frame->function_scope = num_ancestors;

		/* Look for the name in the new scopes. */
		err = drgn_find_in_dwarf_scopes(frame->scopes, num_ancestors,
						name, &die, &type_die);
		if (err)
			return err;
	}
	if (!die.addr) {
not_found:;
		const char *frame_name = drgn_stack_frame_name(trace, frame_i);
		if (frame_name) {
			return drgn_error_format(DRGN_ERROR_LOOKUP,
						 "could not find '%s' in '%s'",
						 name, frame_name);
		} else {
			return drgn_error_format(DRGN_ERROR_LOOKUP,
						 "could not find '%s'", name);
		}
	}

	Dwarf_Die function_die = frame->scopes[frame->function_scope];
	return drgn_object_from_dwarf(trace->prog->dbinfo, frame->regs->module,
				      &die,
				      dwarf_tag(&die) == DW_TAG_enumerator ?
				      &type_die : NULL,
				      &function_die, frame->regs, ret);
}

LIBDRGN_PUBLIC bool drgn_stack_frame_register(struct drgn_stack_trace *trace,
					      size_t frame,
					      const struct drgn_register *reg,
					      uint64_t *ret)
{
	struct drgn_program *prog = trace->prog;
	struct drgn_register_state *regs = trace->frames[frame].regs;
	if (!drgn_register_state_has_register(regs, reg->regno))
		return false;
	const struct drgn_register_layout *layout =
		&prog->platform.arch->register_layout[reg->regno];
	if (layout->size > sizeof(*ret))
		return false;
	*ret = 0;
	copy_lsbytes(ret, sizeof(*ret), HOST_LITTLE_ENDIAN,
		     &regs->buf[layout->offset], layout->size,
		     drgn_platform_is_little_endian(&prog->platform));
	if (drgn_platform_bswap(&prog->platform))
		*ret = bswap_64(*ret);
	return true;
}

static struct drgn_error *
drgn_get_stack_trace_obj(struct drgn_object *res,
			 const struct drgn_object *thread_obj,
			 bool *is_pt_regs_ret)
{
	struct drgn_program *prog = drgn_object_program(res);

	struct drgn_type *type = drgn_underlying_type(thread_obj->type);
	if (drgn_type_kind(type) == DRGN_TYPE_STRUCT &&
	    strcmp(drgn_type_tag(type), "pt_regs") == 0) {
		*is_pt_regs_ret = true;
		return drgn_object_read(res, thread_obj);
	}

	if (drgn_type_kind(type) != DRGN_TYPE_POINTER)
		goto type_error;
	type = drgn_underlying_type(drgn_type_type(type).type);
	if (drgn_type_kind(type) != DRGN_TYPE_STRUCT)
		goto type_error;

	if ((prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) &&
	    strcmp(drgn_type_tag(type), "task_struct") == 0) {
		*is_pt_regs_ret = false;
		return drgn_object_read(res, thread_obj);
	} else if (strcmp(drgn_type_tag(type), "pt_regs") == 0) {
		*is_pt_regs_ret = true;
		/*
		 * If the drgn_object_read() call fails, we're breaking
		 * the rule of not modifying the result on error, but we
		 * don't care in this context.
		 */
		struct drgn_error *err = drgn_object_dereference(res,
								 thread_obj);
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
drgn_get_initial_registers(struct drgn_program *prog, uint32_t tid,
			   const struct drgn_object *thread_obj,
			   struct drgn_register_state **ret)
{
	struct drgn_error *err;
	struct drgn_object obj;
	struct drgn_object tmp;
	struct nstring prstatus;

	drgn_object_init(&obj, prog);
	drgn_object_init(&tmp, prog);

	/* First, try pt_regs. */
	if (thread_obj) {
		bool is_pt_regs;
		err = drgn_get_stack_trace_obj(&obj, thread_obj, &is_pt_regs);
		if (err)
			goto out;

		if (is_pt_regs) {
			assert(obj.encoding == DRGN_OBJECT_ENCODING_BUFFER);
			assert(obj.kind == DRGN_OBJECT_VALUE);
			if (!prog->platform.arch->pt_regs_get_initial_registers) {
				err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
							"pt_regs stack unwinding is not supported for %s architecture",
							prog->platform.arch->name);
				goto out;
			}
			err = prog->platform.arch->pt_regs_get_initial_registers(&obj,
										 ret);
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
		err = linux_helper_find_task(&obj, &tmp, tid);
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
		if (!prog->platform.arch->linux_kernel_get_initial_registers) {
			err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						"Linux kernel stack unwinding is not supported for %s architecture",
						prog->platform.arch->name);
			goto out;
		}
		err = prog->platform.arch->linux_kernel_get_initial_registers(&obj,
									      ret);
	} else {
		err = drgn_program_find_prstatus_by_tid(prog, tid, &prstatus);
		if (err)
			goto out;
		if (!prstatus.str) {
			err = drgn_error_create(DRGN_ERROR_LOOKUP, "thread not found");
			goto out;
		}
prstatus:
		if (!prog->platform.arch->prstatus_get_initial_registers) {
			err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
						"core dump stack unwinding is not supported for %s architecture",
						prog->platform.arch->name);
			goto out;
		}
		err = prog->platform.arch->prstatus_get_initial_registers(prog,
									  prstatus.str,
									  prstatus.len,
									  ret);
	}

out:
	drgn_object_deinit(&tmp);
	drgn_object_deinit(&obj);
	return err;
}

static void drgn_add_to_register(void *dst, size_t dst_size, const void *src,
				 size_t src_size, int64_t addend,
				 bool little_endian)
{
	while (addend && dst_size && src_size) {
		uint64_t uvalue;
		copy_lsbytes(&uvalue, sizeof(uvalue), HOST_LITTLE_ENDIAN, src,
			     src_size, little_endian);
		size_t n = min(sizeof(uvalue), src_size);
		if (little_endian)
			src = (char *)src + n;
		src_size -= n;

		bool carry = __builtin_add_overflow(uvalue, (uint64_t)addend,
						    &uvalue);
		addend = (addend < 0 ? -1 : 0) + carry;

		copy_lsbytes(dst, dst_size, little_endian, &uvalue,
			     sizeof(uvalue), HOST_LITTLE_ENDIAN);
		n = min(sizeof(uvalue), dst_size);
		if (little_endian)
			dst = (char *)dst + n;
		dst_size -= n;
	}
	if (dst != src) {
		copy_lsbytes(dst, dst_size, little_endian, src, src_size,
			     little_endian);
	}
}


static struct drgn_error *
drgn_stack_trace_add_frames(struct drgn_stack_trace **trace,
			    size_t *trace_capacity,
			    struct drgn_register_state *regs)
{
	struct drgn_error *err;

	if (!regs->module) {
		err = drgn_stack_trace_append_frame(trace, trace_capacity, regs,
						    NULL, 0, 0);
		goto out;
	}

	uint64_t pc = regs->_pc - !regs->interrupted;
	uint64_t bias;
	Dwarf_Die *scopes;
	size_t num_scopes;
	err = drgn_debug_info_module_find_dwarf_scopes(regs->module, pc, &bias,
						       &scopes, &num_scopes);
	if (err)
		goto out;
	pc -= bias;

	size_t orig_num_frames = (*trace)->num_frames;
	/*
	 * Walk backwards through scopes, splitting into frames. Stop at index 1
	 * because 0 must be a unit DIE.
	 */
	size_t frame_end = num_scopes;
	for (size_t i = num_scopes; i-- > 1;) {
		bool has_pc;
		if (i == num_scopes - 1) {
			/*
			 * The last scope is guaranteed to contain PC, so avoid
			 * a call to dwarf_haspc().
			 */
			has_pc = true;
		} else {
			int r = dwarf_haspc(&scopes[i], pc);
			if (r < 0) {
				err = drgn_error_libdw();
				goto out_scopes;
			}
			has_pc = r > 0;
		}
		if (has_pc) {
			Dwarf_Die *frame_scopes;
			switch (dwarf_tag(&scopes[i])) {
			case DW_TAG_subprogram:
				/*
				 * Reuse the original scopes array (shrinking it
				 * if necessary).
				 */
				if (frame_end == num_scopes ||
				    !(frame_scopes = realloc(scopes,
							     frame_end *
							     sizeof(scopes[i]))))
					frame_scopes = scopes;
				err = drgn_stack_trace_append_frame(trace,
								    trace_capacity,
								    regs,
								    frame_scopes,
								    frame_end,
								    i);
				if (err) {
					free(frame_scopes);
					/*
					 * We stole scopes for frame_scopes, so
					 * not out_scopes.
					 */
					goto out;
				}
				/*
				 * Added the DW_TAG_subprogram frame. We're
				 * done.
				 */
				return NULL;
			case DW_TAG_inlined_subroutine:
				frame_scopes = memdup(&scopes[i],
						      (frame_end - i) *
						      sizeof(scopes[i]));
				if (!frame_scopes) {
					err = &drgn_enomem;
					goto out_scopes;
				}
				err = drgn_stack_trace_append_frame(trace,
								    trace_capacity,
								    regs,
								    frame_scopes,
								    frame_end - i,
								    0);
				if (err) {
					free(frame_scopes);
					goto out_scopes;
				}
				frame_end = i;
				break;
			default:
				break;
			}
		} else {
			/*
			 * This DIE doesn't contain PC. Ignore it and everything
			 * after it.
			 */
			frame_end = i;
		}
	}

	/*
	 * We didn't find a matching DW_TAG_subprogram. Free any matching
	 * DW_TAG_inlined_subroutine frames we found.
	 */
	for (size_t i = orig_num_frames; i < (*trace)->num_frames; i++)
		free((*trace)->frames[i].scopes);
	(*trace)->num_frames = orig_num_frames;
	/* If we at least found the unit DIE, keep it. */
	if (num_scopes > 0) {
		Dwarf_Die *frame_scopes;
		if (!(frame_scopes = realloc(scopes, sizeof(scopes[0]))))
			frame_scopes = scopes;
		err = drgn_stack_trace_append_frame(trace, trace_capacity, regs,
						    frame_scopes, 1, 1);
		if (err) {
			free(frame_scopes);
			goto out;
		}
		return NULL;
	}
	/* Otherwise, add a scopeless frame. */
	err = drgn_stack_trace_append_frame(trace, trace_capacity, regs, NULL,
					    0, 0);
out_scopes:
	free(scopes);
out:
	if (err)
		drgn_register_state_destroy(regs);
	return err;
}

static struct drgn_error *
drgn_unwind_one_register(struct drgn_program *prog,
			 const struct drgn_cfi_rule *rule,
			 const struct drgn_register_state *regs, void *buf,
			 size_t size)
{
	struct drgn_error *err;
	bool little_endian = drgn_platform_is_little_endian(&prog->platform);
	SWITCH_ENUM(rule->kind,
	case DRGN_CFI_RULE_UNDEFINED:
		return &drgn_not_found;
	case DRGN_CFI_RULE_AT_CFA_PLUS_OFFSET: {
		struct optional_uint64 cfa = drgn_register_state_get_cfa(regs);
		if (!cfa.has_value)
			return &drgn_not_found;
		err = drgn_program_read_memory(prog, buf,
					       cfa.value + rule->offset, size,
					       false);
		break;
	}
	case DRGN_CFI_RULE_CFA_PLUS_OFFSET: {
		struct optional_uint64 cfa = drgn_register_state_get_cfa(regs);
		if (!cfa.has_value)
			return &drgn_not_found;
		cfa.value += rule->offset;
		copy_lsbytes(buf, size, little_endian, &cfa.value,
			     sizeof(cfa.value), HOST_LITTLE_ENDIAN);
		return NULL;
	}
	case DRGN_CFI_RULE_AT_REGISTER_PLUS_OFFSET:
	case DRGN_CFI_RULE_AT_REGISTER_ADD_OFFSET: {
		if (!drgn_register_state_has_register(regs, rule->regno))
			return &drgn_not_found;
		const struct drgn_register_layout *layout =
			&prog->platform.arch->register_layout[rule->regno];
		uint64_t address;
		copy_lsbytes(&address, sizeof(address), HOST_LITTLE_ENDIAN,
			     &regs->buf[layout->offset], layout->size,
			     little_endian);
		if (rule->kind == DRGN_CFI_RULE_AT_REGISTER_PLUS_OFFSET)
			address += rule->offset;
		address &= drgn_platform_address_mask(&prog->platform);
		err = drgn_program_read_memory(prog, buf, address, size, false);
		if (!err && rule->kind == DRGN_CFI_RULE_AT_REGISTER_ADD_OFFSET) {
			drgn_add_to_register(buf, size, buf, size, rule->offset,
					     little_endian);
		}
		break;
	}
	case DRGN_CFI_RULE_REGISTER_PLUS_OFFSET: {
		if (!drgn_register_state_has_register(regs, rule->regno))
			return &drgn_not_found;
		const struct drgn_register_layout *layout =
			&prog->platform.arch->register_layout[rule->regno];
		drgn_add_to_register(buf, size, &regs->buf[layout->offset],
				     layout->size, rule->offset, little_endian);
		return NULL;
	}
	case DRGN_CFI_RULE_AT_DWARF_EXPRESSION:
	case DRGN_CFI_RULE_DWARF_EXPRESSION:
		err = drgn_eval_cfi_dwarf_expression(prog, rule, regs, buf,
						     size);
		break;
	)
	/*
	 * If we couldn't read from memory, leave the register unknown instead
	 * of failing hard.
	 */
	if (err && err->code == DRGN_ERROR_FAULT) {
		drgn_error_destroy(err);
		err = &drgn_not_found;
	}
	return err;
}

static struct drgn_error *drgn_unwind_cfa(struct drgn_program *prog,
					  const struct drgn_cfi_row *row,
					  struct drgn_register_state *regs)
{
	struct drgn_error *err;
	struct drgn_cfi_rule rule;
	drgn_cfi_row_get_cfa(row, &rule);
	uint8_t address_size = drgn_platform_address_size(&prog->platform);
	char buf[8];
	err = drgn_unwind_one_register(prog, &rule, regs, buf, address_size);
	if (!err) {
		uint64_t cfa;
		copy_lsbytes(&cfa, sizeof(cfa), HOST_LITTLE_ENDIAN, buf,
			     address_size,
			     drgn_platform_is_little_endian(&prog->platform));
		drgn_register_state_set_cfa(prog, regs, cfa);
	} else if (err == &drgn_not_found) {
		err = NULL;
	}
	return err;
}

static struct drgn_error *
drgn_unwind_with_cfi(struct drgn_program *prog, struct drgn_cfi_row **row,
		     struct drgn_register_state *regs,
		     struct drgn_register_state **ret)
{
	struct drgn_error *err;

	if (!regs->module)
		return &drgn_not_found;

	bool interrupted;
	drgn_register_number ret_addr_regno;
	/* If we found the module, then we must have the PC. */
	err = drgn_debug_info_module_find_cfi(prog, regs->module,
					      regs->_pc - !regs->interrupted,
					      row, &interrupted,
					      &ret_addr_regno);
	if (err)
		return err;

	err = drgn_unwind_cfa(prog, *row, regs);
	if (err)
		return err;

	size_t num_regs = (*row)->num_regs;
	if (num_regs == 0)
		return &drgn_stop;

	const struct drgn_register_layout *layout =
		&prog->platform.arch->register_layout[num_regs - 1];
	struct drgn_register_state *unwound =
		drgn_register_state_create_impl(layout->offset + layout->size,
						num_regs, interrupted);
	if (!unwound)
		return &drgn_enomem;

	bool has_any_register = false;
	for (drgn_register_number regno = 0; regno < num_regs; regno++) {
		struct drgn_cfi_rule rule;
		drgn_cfi_row_get_register(*row, regno, &rule);
		layout = &prog->platform.arch->register_layout[regno];
		err = drgn_unwind_one_register(prog, &rule, regs,
					       &unwound->buf[layout->offset],
					       layout->size);
		if (!err) {
			drgn_register_state_set_has_register(unwound, regno);
			has_any_register = true;
		} else if (err != &drgn_not_found) {
			drgn_register_state_destroy(unwound);
			return err;
		}
	}
	if (!has_any_register) {
		/* Couldn't unwind any registers. We're done. */
		drgn_register_state_destroy(unwound);
		return &drgn_stop;
	}
	if (drgn_register_state_has_register(unwound, ret_addr_regno)) {
		layout = &prog->platform.arch->register_layout[ret_addr_regno];
		drgn_register_state_set_pc_from_register_impl(prog, unwound,
							      ret_addr_regno,
							      layout->offset,
							      layout->size);
	}
	*ret = unwound;
	return NULL;
}

static struct drgn_error *drgn_get_stack_trace(struct drgn_program *prog,
					       uint32_t tid,
					       const struct drgn_object *obj,
					       struct drgn_stack_trace **ret)
{
	struct drgn_error *err;

	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot unwind stack without platform");
	}
	if ((prog->flags & (DRGN_PROGRAM_IS_LINUX_KERNEL |
			    DRGN_PROGRAM_IS_LIVE)) == DRGN_PROGRAM_IS_LIVE) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "stack unwinding is not yet supported for live processes");
	}

	size_t trace_capacity = 1;
	struct drgn_stack_trace *trace =
		malloc(offsetof(struct drgn_stack_trace,
				frames[trace_capacity]));
	if (!trace)
		return &drgn_enomem;
	trace->prog = prog;
	trace->num_frames = 0;

	struct drgn_cfi_row *row = drgn_empty_cfi_row;

	struct drgn_register_state *regs;
	err = drgn_get_initial_registers(prog, tid, obj, &regs);
	if (err)
		goto out;

	/* Limit iterations so we don't get caught in a loop. */
	for (int i = 0; i < 1024; i++) {
		err = drgn_stack_trace_add_frames(&trace, &trace_capacity,
						  regs);
		if (err)
			goto out;

		err = drgn_unwind_with_cfi(prog, &row, regs, &regs);
		if (err == &drgn_not_found) {
			err = prog->platform.arch->fallback_unwind(prog, regs,
								   &regs);
		}
		if (err == &drgn_stop)
			break;
		else if (err)
			goto out;
	}

	err = NULL;
out:
	drgn_cfi_row_destroy(row);
	if (err) {
		drgn_stack_trace_destroy(trace);
	} else {
		drgn_stack_trace_shrink_to_fit(&trace, trace_capacity);
		*ret = trace;
	}
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
		return drgn_get_stack_trace(drgn_object_program(obj),
					    value.uvalue, NULL, ret);
	} else {
		return drgn_get_stack_trace(drgn_object_program(obj), 0, obj,
					    ret);
	}
}
