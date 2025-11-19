// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

PyObject *SourceLocation_wrap(const char *filename, int line, int column,
			      PyObject *obj, size_t i)
{
	SourceLocation *ret = call_tp_alloc(SourceLocation);
	if (!ret)
		return NULL;
	ret->filename = PyUnicode_FromString(filename);
	if (!ret->filename)
		return NULL;
	ret->line = PyLong_FromLong(line);
	if (!ret->line)
		return NULL;
	ret->column = PyLong_FromLong(column);
	if (!ret->column)
		return NULL;
	Py_INCREF(obj);
	ret->obj = obj;
	ret->i = i;
	return (PyObject *)ret;
}

static void SourceLocation_dealloc(SourceLocation *self)
{
	PyObject_GC_UnTrack(self);
	Py_XDECREF(self->obj);
	Py_XDECREF(self->column);
	Py_XDECREF(self->line);
	Py_XDECREF(self->filename);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int SourceLocation_traverse(SourceLocation *self, visitproc visit,
				   void *arg)
{
	Py_VISIT(self->filename);
	Py_VISIT(self->line);
	Py_VISIT(self->column);
	Py_VISIT(self->obj);
	return 0;
}

static PyObject *SourceLocation_str(SourceLocation *self)
{
	struct drgn_error *err;
	_cleanup_free_ char *str = NULL;
	StackTrace *trace = (StackTrace *)self->obj;
	err = drgn_format_stack_frame_source(trace->trace, self->i, &str);
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromString(str);
}

static PyObject *SourceLocation_name(SourceLocation *self)
{
	struct drgn_error *err;
	_cleanup_free_ char *str = NULL;
	StackTrace *trace = (StackTrace *)self->obj;
	err = drgn_stack_frame_source_name(trace->trace, self->i, &str);
	if (err)
		return set_drgn_error(err);
	if (!str)
		Py_RETURN_NONE;
	return PyUnicode_FromString(str);
}

static Py_ssize_t SourceLocation_length(PyObject *self)
{
	return 3;
}

static PyObject *SourceLocation_item(SourceLocation *self, Py_ssize_t i)
{
	switch (i) {
	case 0:
		Py_INCREF(self->filename);
		return self->filename;
	case 1:
		Py_INCREF(self->line);
		return self->line;
	case 2:
		Py_INCREF(self->column);
		return self->column;
	default:
		PyErr_SetString(PyExc_IndexError,
				"SourceLocation index out of range");
		return NULL;
	}
}

static PySequenceMethods SourceLocation_as_sequence = {
	.sq_length = SourceLocation_length,
	.sq_item = (ssizeargfunc)SourceLocation_item,
};

static PyMemberDef SourceLocation_members[] = {
	{"filename", T_OBJECT, offsetof(SourceLocation, filename), READONLY,
	 drgn_SourceLocation_filename_DOC},
	{"line", T_OBJECT, offsetof(SourceLocation, line), READONLY,
	 drgn_SourceLocation_line_DOC},
	{"column", T_OBJECT, offsetof(SourceLocation, column), READONLY,
	 drgn_SourceLocation_column_DOC},
	{},
};

static PyMethodDef SourceLocation_methods[] = {
	{"name", (PyCFunction)SourceLocation_name, METH_NOARGS,
	 drgn_SourceLocation_name_DOC},
	{"_repr_pretty_", (PyCFunction)repr_pretty_from_str,
	 METH_VARARGS | METH_KEYWORDS},
	{},
};

PyTypeObject SourceLocation_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.SourceLocation",
	.tp_basicsize = sizeof(SourceLocation),
	.tp_dealloc = (destructor)SourceLocation_dealloc,
	.tp_str = (reprfunc)SourceLocation_str,
	.tp_as_sequence = &SourceLocation_as_sequence,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_SourceLocation_DOC,
	.tp_traverse = (traverseproc)SourceLocation_traverse,
	.tp_methods = SourceLocation_methods,
	.tp_members = SourceLocation_members,
};
