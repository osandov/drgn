// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drgnpy.h"
#include "../stack_trace.h"
#include "../util.h"

static void StackTrace_dealloc(StackTrace *self)
{
	struct drgn_program *prog = self->trace->prog;
	drgn_stack_trace_destroy(self->trace);
	Py_XDECREF(container_of(prog, Program, prog));
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *StackTrace_str(StackTrace *self)
{
	struct drgn_error *err;
	PyObject *ret;
	char *str;

	err = drgn_format_stack_trace(self->trace, &str);
	if (err)
		return set_drgn_error(err);

	ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

static Py_ssize_t StackTrace_length(StackTrace *self)
{
	return drgn_stack_trace_num_frames(self->trace);
}

static StackFrame *StackTrace_item(StackTrace *self, Py_ssize_t i)
{
	if (i < 0 || i >= drgn_stack_trace_num_frames(self->trace)) {
		PyErr_SetString(PyExc_IndexError,
				"stack frame index out of range");
		return NULL;
	}
	StackFrame *ret =
		(StackFrame *)StackFrame_type.tp_alloc(&StackFrame_type, 0);
	if (!ret)
		return NULL;
	ret->i = i;
	ret->trace = self;
	Py_INCREF(self);
	return ret;
}

static PySequenceMethods StackTrace_as_sequence = {
	.sq_length = (lenfunc)StackTrace_length,
	.sq_item = (ssizeargfunc)StackTrace_item,
};

PyTypeObject StackTrace_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.StackTrace",
	.tp_basicsize = sizeof(StackTrace),
	.tp_dealloc = (destructor)StackTrace_dealloc,
	.tp_as_sequence = &StackTrace_as_sequence,
	.tp_str = (reprfunc)StackTrace_str,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_StackTrace_DOC,
};

static void StackFrame_dealloc(StackFrame *self)
{
	Py_XDECREF(self->trace);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *StackFrame_str(StackFrame *self)
{
	struct drgn_error *err;
	char *str;
	err = drgn_format_stack_frame(self->trace->trace, self->i, &str);
	if (err)
		return set_drgn_error(err);
	PyObject *ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

static DrgnObject *StackFrame_subscript(StackFrame *self, PyObject *key)
{
	struct drgn_error *err;
	Program *prog = container_of(self->trace->trace->prog, Program, prog);
	if (!PyUnicode_Check(key)) {
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	}
	const char *name = PyUnicode_AsUTF8(key);
	if (!name)
		return NULL;
	DrgnObject *ret = DrgnObject_alloc(prog);
	if (!ret)
		return NULL;
	bool clear = set_drgn_in_python();
	err = drgn_stack_frame_find_object(self->trace->trace, self->i, name,
					   &ret->obj);
	if (clear)
		clear_drgn_in_python();
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			PyErr_SetObject(PyExc_KeyError, key);
		} else {
			set_drgn_error(err);
		}
		Py_DECREF(ret);
		return NULL;
	}
	return ret;
}

static int StackFrame_contains(StackFrame *self, PyObject *key)
{
	struct drgn_error *err;
	if (!PyUnicode_Check(key)) {
		PyErr_SetObject(PyExc_KeyError, key);
		return -1;
	}
	const char *name = PyUnicode_AsUTF8(key);
	if (!name)
		return -1;
	struct drgn_object tmp;
	drgn_object_init(&tmp, self->trace->trace->prog);
	err = drgn_stack_frame_find_object(self->trace->trace, self->i, name,
					   &tmp);
	drgn_object_deinit(&tmp);
	if (!err) {
		return 1;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		return 0;
	} else {
		return -1;
	}
}

static PyObject *StackFrame_source(StackFrame *self)
{
	int line;
	int column;
	const char *filename = drgn_stack_frame_source(self->trace->trace,
						       self->i, &line, &column);
	if (!filename) {
		PyErr_SetString(PyExc_LookupError,
				"source code location not available");
		return NULL;
	}
	return Py_BuildValue("sii", filename, line, column);
}

static PyObject *StackFrame_symbol(StackFrame *self)
{
	struct drgn_error *err;
	Program *prog = container_of(self->trace->trace->prog, Program, prog);
	struct drgn_symbol *sym;
	err = drgn_stack_frame_symbol(self->trace->trace, self->i, &sym);
	if (err)
		return set_drgn_error(err);
	PyObject *ret = Symbol_wrap(sym, prog);
	if (!ret) {
		drgn_symbol_destroy(sym);
		return NULL;
	}
	return ret;
}

static PyObject *StackFrame_register(StackFrame *self, PyObject *arg)
{
	const char *name = PyUnicode_AsUTF8(arg);
	if (!name)
		return NULL;
	const struct drgn_platform *platform =
		drgn_program_platform(self->trace->trace->prog);
	const struct drgn_register *reg =
		drgn_platform_register_by_name(platform, name);
	if (!reg) {
		return PyErr_Format(PyExc_ValueError,
				    "unknown register %R", arg);
	}
	uint64_t value;
	if (!drgn_stack_frame_register(self->trace->trace, self->i, reg,
				       &value)) {
		PyErr_SetString(PyExc_LookupError,
				"register value is not known");
		return NULL;
	}
	return PyLong_FromUnsignedLongLong(value);
}

static PyObject *StackFrame_registers(StackFrame *self)
{
	PyObject *dict = PyDict_New();
	if (!dict)
		return NULL;
	const struct drgn_platform *platform =
		drgn_program_platform(self->trace->trace->prog);
	size_t num_registers = drgn_platform_num_registers(platform);
	for (size_t i = 0; i < num_registers; i++) {
		const struct drgn_register *reg =
			drgn_platform_register(platform, i);
		uint64_t value;
		if (!drgn_stack_frame_register(self->trace->trace, self->i, reg,
					       &value))
			continue;
		PyObject *value_obj = PyLong_FromUnsignedLongLong(value);
		if (!value_obj) {
			Py_DECREF(dict);
			return NULL;
		}
		size_t num_names;
		const char * const *names = drgn_register_names(reg,
								&num_names);
		for (size_t j = 0; j < num_names; j++) {
			int ret = PyDict_SetItemString(dict, names[j],
						       value_obj);
			if (ret == -1) {
				Py_DECREF(value_obj);
				Py_DECREF(dict);
				return NULL;
			}
		}
		Py_DECREF(value_obj);
	}
	return dict;
}

static PyObject *StackFrame_get_name(StackFrame *self, void *arg)
{
	const char *name = drgn_stack_frame_name(self->trace->trace, self->i);
	if (name)
		return PyUnicode_FromString(name);
	else
		Py_RETURN_NONE;
}

static PyObject *StackFrame_get_is_inline(StackFrame *self, void *arg)
{
	Py_RETURN_BOOL(drgn_stack_frame_is_inline(self->trace->trace, self->i));
}

static PyObject *StackFrame_get_interrupted(StackFrame *self, void *arg)
{
	Py_RETURN_BOOL(drgn_stack_frame_interrupted(self->trace->trace,
						    self->i));
}

static PyObject *StackFrame_get_pc(StackFrame *self, void *arg)
{
	uint64_t pc;
	if (drgn_stack_frame_pc(self->trace->trace, self->i, &pc)) {
		return PyLong_FromUnsignedLongLong(pc);
	} else {
		PyErr_SetString(PyExc_LookupError,
				"program counter is not known");
		return NULL;
	}
}

static PyMethodDef StackFrame_methods[] = {
	{"__getitem__", (PyCFunction)StackFrame_subscript,
	 METH_O | METH_COEXIST, drgn_StackFrame___getitem___DOC},
	{"__contains__", (PyCFunction)StackFrame_contains,
	 METH_O | METH_COEXIST, drgn_StackFrame___contains___DOC},
	{"source", (PyCFunction)StackFrame_source, METH_NOARGS,
	 drgn_StackFrame_source_DOC},
	{"symbol", (PyCFunction)StackFrame_symbol, METH_NOARGS,
	 drgn_StackFrame_symbol_DOC},
	{"register", (PyCFunction)StackFrame_register,
	 METH_O, drgn_StackFrame_register_DOC},
	{"registers", (PyCFunction)StackFrame_registers,
	 METH_NOARGS, drgn_StackFrame_registers_DOC},
	{},
};

static PyGetSetDef StackFrame_getset[] = {
	{"name", (getter)StackFrame_get_name, NULL, drgn_StackFrame_name_DOC},
	{"is_inline", (getter)StackFrame_get_is_inline, NULL,
	 drgn_StackFrame_is_inline_DOC},
	{"interrupted", (getter)StackFrame_get_interrupted, NULL,
	 drgn_StackFrame_interrupted_DOC},
	{"pc", (getter)StackFrame_get_pc, NULL, drgn_StackFrame_pc_DOC},
	{},
};

static PyMappingMethods StackFrame_as_mapping = {
	.mp_subscript = (binaryfunc)StackFrame_subscript,
};

static PySequenceMethods StackFrame_as_sequence = {
	.sq_contains = (objobjproc)StackFrame_contains,
};

PyTypeObject StackFrame_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.StackFrame",
	.tp_basicsize = sizeof(StackFrame),
	.tp_dealloc = (destructor)StackFrame_dealloc,
	.tp_as_sequence = &StackFrame_as_sequence,
	.tp_as_mapping = &StackFrame_as_mapping,
	.tp_str = (reprfunc)StackFrame_str,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_StackFrame_DOC,
	.tp_methods = StackFrame_methods,
	.tp_getset = StackFrame_getset,
};
