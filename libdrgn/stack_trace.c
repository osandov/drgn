// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "cfi.h"
#include "cleanup.h"
#include "debug_info.h"
#include "drgn.h"
#include "dwarf_constants.h"
#include "dwarf_info.h"
#include "elf_file.h"
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
	if (trace) {
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
}

LIBDRGN_PUBLIC
struct drgn_program *drgn_stack_trace_program(struct drgn_stack_trace *trace)
{
	return trace->prog;
}

LIBDRGN_PUBLIC size_t
drgn_stack_trace_num_frames(struct drgn_stack_trace *trace)
{
	return trace->num_frames;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_stack_trace(struct drgn_stack_trace *trace, char **ret)
{
	struct drgn_error *err;
	STRING_BUILDER(str);
	for (size_t frame = 0; frame < trace->num_frames; frame++) {
		if (!string_builder_appendf(&str, "#%-2zu ", frame))
			return &drgn_enomem;

		struct drgn_register_state *regs = trace->frames[frame].regs;
		struct optional_uint64 pc;
		const char *name = drgn_stack_frame_name(trace, frame);
		if (name) {
			if (!string_builder_append(&str, name))
				return &drgn_enomem;
		} else if ((pc = drgn_register_state_get_pc(regs)).has_value) {
			_cleanup_symbol_ struct drgn_symbol *sym = NULL;
			err = drgn_program_find_symbol_by_address_internal(trace->prog,
									   pc.value - !regs->interrupted,
									   &sym);
			if (err)
				return err;

			if (sym) {
				if (!string_builder_appendf(&str,
							    "%s+0x%" PRIx64 "/0x%" PRIx64,
							    sym->name,
							    pc.value - sym->address,
							    sym->size))
					return &drgn_enomem;
			} else {
				if (!string_builder_appendf(&str, "0x%" PRIx64,
							    pc.value))
					return &drgn_enomem;
			}
		} else {
			if (!string_builder_append(&str, "???"))
				return &drgn_enomem;
		}

		int line, column;
		const char *filename = drgn_stack_frame_source(trace, frame,
							       &line, &column);
		if (filename && column) {
			if (!string_builder_appendf(&str, " (%s:%d:%d)",
						    filename, line, column))
				return &drgn_enomem;
		} else if (filename) {
			if (!string_builder_appendf(&str, " (%s:%d)", filename,
						    line))
				return &drgn_enomem;
		}

		if (frame != trace->num_frames - 1 &&
		    !string_builder_appendc(&str, '\n'))
			return &drgn_enomem;
	}
	if (!string_builder_null_terminate(&str))
		return &drgn_enomem;
	*ret = string_builder_steal(&str);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_format_stack_frame(struct drgn_stack_trace *trace, size_t frame, char **ret)
{
	STRING_BUILDER(str);
	struct drgn_register_state *regs = trace->frames[frame].regs;
	struct drgn_error *err;
	if (!string_builder_appendf(&str, "#%zu at ", frame))
		return &drgn_enomem;

	struct optional_uint64 pc = drgn_register_state_get_pc(regs);
	if (pc.has_value) {
		if (!string_builder_appendf(&str, "%#" PRIx64, pc.value))
			return &drgn_enomem;

		_cleanup_symbol_ struct drgn_symbol *sym;
		err = drgn_program_find_symbol_by_address_internal(trace->prog,
								   pc.value - !regs->interrupted,
								   &sym);
		if (err)
			return err;
		if (sym && !string_builder_appendf(&str, " (%s+0x%" PRIx64 "/0x%" PRIx64 ")",
						   sym->name, pc.value - sym->address,
						   sym->size))
			return &drgn_enomem;
	} else {
		if (!string_builder_append(&str, "???"))
			return &drgn_enomem;
	}

	const char *name = drgn_stack_frame_name(trace, frame);
	if (name && !string_builder_appendf(&str, " in %s", name))
		return &drgn_enomem;

	int line, column;
	const char *filename = drgn_stack_frame_source(trace, frame, &line,
						       &column);
	if (filename && column) {
		if (!string_builder_appendf(&str, " at %s:%d:%d", filename,
					    line, column))
			return &drgn_enomem;
	} else if (filename) {
		if (!string_builder_appendf(&str, " at %s:%d", filename, line))
			return &drgn_enomem;
	}

	if (drgn_stack_frame_is_inline(trace, frame) &&
	    !string_builder_append(&str, " (inlined)"))
		return &drgn_enomem;

	if (!string_builder_null_terminate(&str))
		return &drgn_enomem;
	*ret = string_builder_steal(&str);
	return NULL;
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
		if (!regs->module)
			return NULL;

		struct optional_uint64 pc = drgn_register_state_get_pc(regs);
		if (!pc.has_value)
			return NULL;
		pc.value -= !regs->interrupted + regs->module->debug_file_bias;

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

LIBDRGN_PUBLIC bool drgn_stack_frame_sp(struct drgn_stack_trace *trace,
					size_t frame, uint64_t *ret)
{
	struct drgn_program *prog = trace->prog;
	drgn_register_number regno = prog->platform.arch->stack_pointer_regno;
	struct drgn_register_state *regs = trace->frames[frame].regs;
	if (!drgn_register_state_has_register(regs, regno))
		return false;
	const struct drgn_register_layout *layout =
		&prog->platform.arch->register_layout[regno];
	copy_lsbytes(ret, sizeof(*ret), HOST_LITTLE_ENDIAN,
		     &regs->buf[layout->offset], layout->size,
		     drgn_platform_is_little_endian(&prog->platform));
	return true;
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
	struct drgn_symbol *sym = NULL;
	struct drgn_error *err;
	err = drgn_program_find_symbol_by_address_internal(trace->prog, pc.value,
							   &sym);
	if (err)
		return err;
	if (!sym)
		return drgn_error_symbol_not_found(pc.value);
	*ret = sym;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_stack_frame_locals(struct drgn_stack_trace *trace, size_t frame_i,
			const char ***names_ret, size_t *count_ret)
{
	struct drgn_stack_frame *frame = &trace->frames[frame_i];
	if (frame->function_scope >= frame->num_scopes) {
		*names_ret = NULL;
		*count_ret = 0;
		return NULL;
	}
	return drgn_dwarf_scopes_names(frame->scopes + frame->function_scope,
				       frame->num_scopes - frame->function_scope,
				       names_ret, count_ret);
}

LIBDRGN_PUBLIC
void drgn_stack_frame_locals_destroy(const char **names, size_t count)
{
	free(names);
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

	const struct drgn_register_state *regs = frame->regs;
	struct drgn_elf_file *file =
		drgn_module_find_dwarf_file(regs->module,
					    dwarf_cu_getdwarf(die.cu));
	if (!file) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "couldn't find file containing DIE");
	}
	// It doesn't make sense to use the registers if the file has a
	// different platform than the program.
	if (!drgn_platforms_equal(&file->platform, &trace->prog->platform))
		regs = NULL;
	// If this is an inline frame, then DW_AT_frame_base is in the
	// containing DW_TAG_subprogram DIE.
	size_t subprogram_frame_i = frame_i;
	Dwarf_Die *function_die;
	for (;;) {
		struct drgn_stack_frame *subprogram_frame =
			&trace->frames[subprogram_frame_i];
		function_die =
			&subprogram_frame->scopes[subprogram_frame->function_scope];
		if (dwarf_tag(function_die) == DW_TAG_subprogram)
			break;
		subprogram_frame_i++;
	}
	return drgn_object_from_dwarf(&trace->prog->dbinfo, file, &die,
				      dwarf_tag(&die) == DW_TAG_enumerator ?
				      &type_die : NULL,
				      function_die, regs, ret);
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
	copy_lsbytes(ret, sizeof(*ret), HOST_LITTLE_ENDIAN,
		     &regs->buf[layout->offset], layout->size,
		     drgn_platform_is_little_endian(&prog->platform));
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
drgn_get_initial_registers_from_prstatus(struct drgn_program *prog,
					 const struct nstring *prstatus,
					 struct drgn_register_state **ret)
{
	if (!prog->platform.arch->prstatus_get_initial_registers) {
		return drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED,
					 "core dump stack unwinding is not supported for %s architecture",
					 prog->platform.arch->name);
	}
	return prog->platform.arch->prstatus_get_initial_registers(prog,
								   prstatus->str,
								   prstatus->len,
								   ret);
}

static struct drgn_error *
drgn_get_initial_registers_from_kernel_core_dump(struct drgn_program *prog,
						 uint64_t cpu,
						 struct drgn_register_state **ret)
{
	struct drgn_error *err;
	// For kernel core dumps, we can't look up PRSTATUS notes by PID for
	// multiple reasons:
	//
	// 1. Each CPU has its own idle task, all with PID 0.
	// 2. Kdump on s390x populates the PID field of the PRSTATUS notes with
	//    the CPU number + 1.
	// 3. QEMU's dump-guest-memory command does the same.
	//
	// Instead, we have to look it up by CPU number. The way to do this
	// depends on whether the core dump was generated by a real crash (e.g.,
	// by kdump) or while the kernel was running (e.g., by a hypervisor) as
	// well as the architecture.
	//
	// Note that all of this is inherently racy: cpu_curr() [1], current
	// [2], registers [3], and the stack pointer [4] are all updated at
	// different times. This might result in confusing stack traces during a
	// context switch, but there's not much we can do about that.
	//
	// 1: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/sched/core.c?h=v6.6#n6672
	// 2: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/kernel/process_64.c?h=v6.6#n623
	// 3: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/entry/entry_64.S?h=v6.6#n267
	// 4: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/entry/entry_64.S?h=v6.6#n249
	if (prog->vmcoreinfo.have_crashtime
	    && prog->platform.arch->arch != DRGN_ARCH_S390X) {
		// If the VMCOREINFO contains CRASHTIME, the core dump is for a
		// real crash, probably from kdump. Core dumps generated by
		// kdump should have a PRSTATUS note for each CPU, in order by
		// CPU number. There are a couple of complications:
		//
		// 1. Offline CPUs are skipped.
		// 2. CPUs that don't respond to the kdump NMI are skipped.
		//
		// So, we can't reliably find the note for a given CPU solely
		// from the note metadata. Instead, we get it directly from
		// crash_notes, the per-CPU variable in the kernel where the
		// notes are stored during a crash.
		//
		// s390x doesn't use crash_notes.
		DRGN_OBJECT(tmp, prog);
		err = drgn_program_find_object(prog, "crash_notes", NULL,
					       DRGN_FIND_OBJECT_ANY, &tmp);
		if (err)
			return err;
		err = linux_helper_per_cpu_ptr(&tmp, &tmp, cpu);
		if (err)
			return err;
		err = drgn_object_dereference(&tmp, &tmp);
		if (err)
			return err;
		err = drgn_object_read(&tmp, &tmp);
		if (err)
			return err;
		if (tmp.encoding != DRGN_OBJECT_ENCODING_BUFFER) {
			return drgn_error_create(DRGN_ERROR_LOOKUP,
						 "could not parse crash_notes");
		}

		const void *p = drgn_object_buffer(&tmp);
		size_t size = drgn_object_size(&tmp);
		bool bswap = drgn_platform_bswap(&prog->platform);
		Elf32_Nhdr nhdr;
		const char *name;
		const void *desc;
		while (next_elf_note(&p, &size, 4, bswap, &nhdr, &name, &desc)
		       && nhdr.n_namesz > 0) {
			if (nhdr.n_namesz == sizeof("CORE")
			    && memcmp(name, "CORE", sizeof("CORE")) == 0
			    && nhdr.n_type == NT_PRSTATUS) {
				struct nstring prstatus = { desc, nhdr.n_descsz };
				return drgn_get_initial_registers_from_prstatus(prog,
										&prstatus,
										ret);
			}
		}
	} else {
		// Either the VMCOREINFO doesn't contain CRASHTIME, so the core
		// dump was captured while the kernel was running, or it is from
		// kdump on s390x. In both cases, we can use the PRSTATUS note
		// with a PID of CPU number + 1. (This assumes that other
		// hypervisors do the same thing as QEMU dump-guest-memory,
		// which may not be the case. QEMU itself as of version 9.1
		// doesn't do it correctly on ppc64 or s390x:
		// https://lore.kernel.org/linux-debuggers/cover.1718771802.git.osandov@osandov.com/T/).
		struct nstring prstatus;
		err = drgn_program_find_prstatus(prog, cpu + 1, &prstatus);
		if (err)
			return err;
		if (prstatus.str) {
			return drgn_get_initial_registers_from_prstatus(prog,
									&prstatus,
									ret);
		}
	}
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "registers for CPU %" PRIu64 " were not saved",
				 cpu);
}

static struct drgn_error *
drgn_get_initial_registers(struct drgn_program *prog, uint32_t tid,
			   const struct drgn_object *thread_obj,
			   struct drgn_register_state **ret)
{
	struct drgn_error *err;

	DRGN_OBJECT(obj, prog);
	DRGN_OBJECT(tmp, prog);

	/* First, try pt_regs. */
	if (thread_obj) {
		bool is_pt_regs;
		err = drgn_get_stack_trace_obj(&obj, thread_obj, &is_pt_regs);
		if (err)
			return err;

		if (is_pt_regs) {
			assert(obj.encoding == DRGN_OBJECT_ENCODING_BUFFER);
			assert(obj.kind == DRGN_OBJECT_VALUE);
			if (!prog->platform.arch->pt_regs_get_initial_registers) {
				return drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED,
							 "pt_regs stack unwinding is not supported for %s architecture",
							 prog->platform.arch->name);
			}
			return prog->platform.arch->pt_regs_get_initial_registers(&obj,
										  ret);
		}
	} else if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		err = drgn_program_find_object(prog, "init_pid_ns", NULL,
					       DRGN_FIND_OBJECT_ANY, &tmp);
		if (err)
			return err;
		err = drgn_object_address_of(&tmp, &tmp);
		if (err)
			return err;
		err = linux_helper_find_task(&obj, &tmp, tid);
		if (err)
			return err;
		bool found;
		err = drgn_object_bool(&obj, &found);
		if (err)
			return err;
		if (!found) {
			return drgn_error_create(DRGN_ERROR_LOOKUP,
						 "task not found");
		}
	}

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		bool on_cpu;
		err = drgn_object_member_dereference(&tmp, &obj, "on_cpu");
		if (!err) {
			err = drgn_object_bool(&tmp, &on_cpu);
			if (err)
				return err;
		} else if (err->code == DRGN_ERROR_LOOKUP) {
			// The kernel must be !SMP. We have to check cpu_curr(0)
			// instead.
			drgn_error_destroy(err);
			err = linux_helper_cpu_curr(&tmp, 0);
			if (err)
				return err;
			int cmp;
			err = drgn_object_cmp(&tmp, &obj, &cmp);
			if (err)
				return err;
			on_cpu = cmp == 0;
		} else {
			return err;
		}
		if (on_cpu) {
			if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
				return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
							 "cannot unwind stack of running task");
			}
			uint64_t cpu;
			err = linux_helper_task_cpu(&obj, &cpu);
			if (err)
				return err;
			return drgn_get_initial_registers_from_kernel_core_dump(prog,
										cpu,
										ret);
		}
		if (!prog->platform.arch->linux_kernel_get_initial_registers) {
			return drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED,
						 "Linux kernel stack unwinding is not supported for %s architecture",
						 prog->platform.arch->name);
		}
		return prog->platform.arch->linux_kernel_get_initial_registers(&obj,
									       ret);
	} else {
		struct nstring prstatus;
		err = drgn_program_find_prstatus(prog, tid, &prstatus);
		if (err)
			return err;
		if (!prstatus.str) {
			return drgn_error_create(DRGN_ERROR_LOOKUP,
						 "thread not found");
		}
		return drgn_get_initial_registers_from_prstatus(prog, &prstatus,
								ret);
	}
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
	err = drgn_module_find_dwarf_scopes(regs->module, pc, &bias, &scopes,
					    &num_scopes);
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
drgn_unwind_one_register(struct drgn_program *prog, struct drgn_elf_file *file,
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
		err = drgn_eval_cfi_dwarf_expression(prog, file, rule, regs,
						     buf, size);
		break;
	case DRGN_CFI_RULE_CONSTANT:
		copy_lsbytes(buf, size, little_endian, &rule->constant,
			     sizeof(rule->constant), HOST_LITTLE_ENDIAN);
		return NULL;
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
					  struct drgn_elf_file *file,
					  const struct drgn_cfi_row *row,
					  struct drgn_register_state *regs)
{
	struct drgn_error *err;
	struct drgn_cfi_rule rule;
	drgn_cfi_row_get_cfa(row, &rule);
	uint8_t address_size = drgn_platform_address_size(&prog->platform);
	char buf[8];
	err = drgn_unwind_one_register(prog, file, &rule, regs, buf,
				       address_size);
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

	struct drgn_elf_file *file;
	bool interrupted;
	drgn_register_number ret_addr_regno;
	/* If we found the module, then we must have the PC. */
	err = drgn_module_find_cfi(prog, regs->module,
				   regs->_pc - !regs->interrupted, &file, row,
				   &interrupted, &ret_addr_regno);
	if (err)
		return err;

	err = drgn_unwind_cfa(prog, file, *row, regs);
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
		err = drgn_unwind_one_register(prog, file, &rule, regs,
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
	if (prog->platform.arch->demangle_cfi_registers)
		prog->platform.arch->demangle_cfi_registers(prog, unwound);
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
					       const struct nstring *prstatus,
					       struct drgn_stack_trace **ret)
{
	struct drgn_error *err;

	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot unwind stack without platform");
	}
	if ((prog->flags & (DRGN_PROGRAM_IS_LINUX_KERNEL |
			    DRGN_PROGRAM_IS_LIVE)) == DRGN_PROGRAM_IS_LIVE) {
		return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
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
	if (prstatus) {
		err = drgn_get_initial_registers_from_prstatus(prog, prstatus,
							       &regs);
	} else {
		err = drgn_get_initial_registers(prog, tid, obj, &regs);
	}
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
	return drgn_get_stack_trace(prog, tid, NULL, NULL, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_stack_trace_from_pcs(struct drgn_program *prog, const uint64_t *pcs,
				  size_t pcs_size, struct drgn_stack_trace **ret)
{
	struct drgn_stack_trace *trace = malloc_flexible_array(
		struct drgn_stack_trace, frames, pcs_size);
	struct drgn_error *err;
	size_t trace_capacity = pcs_size;

	if (!trace)
		return &drgn_enomem;

	trace->prog = prog;
	trace->num_frames = 0;
	for (size_t i = 0; i != pcs_size; ++i) {
		struct drgn_register_state *regs =
			drgn_register_state_create_impl(0, 0, false);
		drgn_register_state_set_pc(prog, regs, pcs[i]);

		err = drgn_stack_trace_add_frames(&trace, &trace_capacity, regs);
		if (err) {
			drgn_stack_trace_destroy(trace);
			return err;
		}
	}

	drgn_stack_trace_shrink_to_fit(&trace, trace_capacity);
	*ret = trace;
	return NULL;
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
					    value.uvalue, NULL, NULL, ret);
	} else {
		return drgn_get_stack_trace(drgn_object_program(obj), 0, obj,
					    NULL, ret);
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_stack_trace(struct drgn_thread *thread,
			struct drgn_stack_trace **ret)
{
	return drgn_get_stack_trace(thread->prog, thread->tid,
				    (thread->prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
				    ? &thread->object : NULL,
				    thread->prstatus.str ? &thread->prstatus : NULL,
				    ret);
}
