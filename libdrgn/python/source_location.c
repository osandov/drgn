// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../util.h"

PyObject *SourceLocation_wrap(const char *filename, int line, int column,
			      PyObject *obj, size_t i, bool is_stack_trace)
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
	ret->is_stack_trace = is_stack_trace;
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
	if (self->is_stack_trace) {
		StackTrace *trace = (StackTrace *)self->obj;
		err = drgn_format_stack_frame_source(trace->trace, self->i,
						     &str);
	} else {
		SourceLocationList *locs = (SourceLocationList *)self->obj;
		err = drgn_format_source_location_list_at(locs->locs, self->i,
							  &str);
	}
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromString(str);
}

static PyObject *SourceLocation_name(SourceLocation *self)
{
	struct drgn_error *err;
	_cleanup_free_ char *str = NULL;
	if (self->is_stack_trace) {
		StackTrace *trace = (StackTrace *)self->obj;
		err = drgn_stack_frame_source_name(trace->trace, self->i, &str);
	} else {
		SourceLocationList *locs = (SourceLocationList *)self->obj;
		err = drgn_source_location_list_name_at(locs->locs, self->i,
							&str);
	}
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

PyObject *SourceLocationList_wrap(struct drgn_source_location_list *locs)
{
	SourceLocationList *ret = call_tp_alloc(SourceLocationList);
	if (!ret)
		return NULL;
	Py_INCREF(container_of(drgn_source_location_list_program(locs), Program,
			       prog));
	ret->locs = locs;
	return (PyObject *)ret;
}

static void SourceLocationList_dealloc(SourceLocationList *self)
{
	PyObject_GC_UnTrack(self);
	if (self->locs) {
		struct drgn_program *prog =
			drgn_source_location_list_program(self->locs);
		drgn_source_location_list_destroy(self->locs);
		Py_DECREF(container_of(prog, Program, prog));
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int SourceLocationList_traverse(SourceLocationList *self,
				       visitproc visit, void *arg)
{
	if (self->locs) {
		Py_VISIT(container_of(drgn_source_location_list_program(self->locs),
				      Program, prog));
	}
	return 0;
}

static Program *SourceLocationList_get_prog(SourceLocationList *self, void *arg)
{
	Program *prog =
		container_of(drgn_source_location_list_program(self->locs),
			     Program, prog);
	Py_INCREF(prog);
	return prog;
}

static PyObject *SourceLocationList_str(SourceLocationList *self)
{
	struct drgn_error *err;
	_cleanup_free_ char *str = NULL;
	err = drgn_format_source_location_list(self->locs, &str);
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromString(str);
}

static Py_ssize_t SourceLocationList_length(SourceLocationList *self)
{
	return drgn_source_location_list_length(self->locs);
}

static PyObject *SourceLocationList_item(SourceLocationList *self, Py_ssize_t i)
{
	if (i < 0 || i >= drgn_source_location_list_length(self->locs)) {
		PyErr_SetString(PyExc_IndexError,
				"source location list index out of range");
		return NULL;
	}
	int line, column;
	const char *filename = drgn_source_location_list_source_at(self->locs,
								   i, &line,
								   &column);
	if (!filename) {
		filename = "";
		line = column = 0;
	}
	return SourceLocation_wrap(filename, line, column, (PyObject *)self, i,
				   false);
}

static PyMethodDef SourceLocationList_methods[] = {
	{"_repr_pretty_", (PyCFunction)repr_pretty_from_str,
	 METH_VARARGS | METH_KEYWORDS},
	{},
};

static PySequenceMethods SourceLocationList_as_sequence = {
	.sq_length = (lenfunc)SourceLocationList_length,
	.sq_item = (ssizeargfunc)SourceLocationList_item,
};

static PyGetSetDef SourceLocationList_getset[] = {
	{"prog", (getter)SourceLocationList_get_prog, NULL,
	 drgn_SourceLocationList_prog_DOC},
	{},
};

PyTypeObject SourceLocationList_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.SourceLocationList",
	.tp_basicsize = sizeof(SourceLocationList),
	.tp_dealloc = (destructor)SourceLocationList_dealloc,
	.tp_as_sequence = &SourceLocationList_as_sequence,
	.tp_str = (reprfunc)SourceLocationList_str,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_SourceLocationList_DOC,
	.tp_traverse = (traverseproc)SourceLocationList_traverse,
	.tp_methods = SourceLocationList_methods,
	.tp_getset = SourceLocationList_getset,
};
