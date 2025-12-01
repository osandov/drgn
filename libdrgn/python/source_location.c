// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../util.h"

PyObject *SourceLocation_type;

int add_SourceLocation(PyObject *m)
{
	_cleanup_pydecref_ PyObject *globals = PyDict_New();
	if (!globals)
		return -1;

	_cleanup_pydecref_ PyObject *res = PyRun_String(
"from typing import Callable, NamedTuple, Optional\n"
"\n"
"\n"
"class SourceLocation(\n"
"    NamedTuple(\n"
"        'SourceLocationBase', [('filename', str), ('line', int), ('column', int)]\n"
"    )\n"
"):\n"
"    def __new__(\n"
"        cls,\n"
"        filename: str,\n"
"        line: int,\n"
"        column: int,\n"
"        name: Callable[[], Optional[str]] = lambda: None,\n"
"    ) -> 'Foo':\n"
"        ret = super().__new__(cls, filename, line, column)\n"
"        ret.name = name\n"
"        return ret\n"
"\n"
"    # Keep this in sync with drgn_format_stack_frame_source_impl().\n"
"    def __str__(self) -> str:\n"
"        name = self.name()\n"
"        if name is None:\n"
"            name = '\?\?\?'\n"
"        if self.filename:\n"
"            if self.column:\n"
"                return f'{name} at {self.filename}:{self.line}:{self.column}'\n"
"            else:\n"
"                return f'{name} at {self.filename}:{self.line}'\n"
"        else:\n"
"            return f'{name} at \?\?:\?'\n"
, Py_file_input, globals, globals);
	if (!res)
		return -1;

	SourceLocation_type = PyDict_GetItemString(globals, "SourceLocation");
	if (!SourceLocation_type)
		return -1;
	Py_INCREF(SourceLocation_type);

	if (PyModule_AddObject(m, "SourceLocation", SourceLocation_type) == -1) {
		Py_DECREF(SourceLocation_type);
		return -1;
	}
	return 0;
}

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

static PyObject *SourceLocationList_name(PyObject *self)
{
	SourceLocationList *locs =
		(SourceLocationList *)PyTuple_GET_ITEM(self, 0);
	Py_ssize_t i = PyLong_AsSize_t(PyTuple_GET_ITEM(self, 1));
	if (i == -1 && PyErr_Occurred())
		return NULL;
	_cleanup_free_ char *str = NULL;
	struct drgn_error *err = drgn_source_location_list_name_at(locs->locs,
								   i, &str);
	if (err)
		return set_drgn_error(err);
	if (!str)
		Py_RETURN_NONE;
	return PyUnicode_FromString(str);
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

	static PyMethodDef meth = {
		.ml_name = "name",
		.ml_meth = (PyCFunction)SourceLocationList_name,
		.ml_flags = METH_NOARGS,
	};
	_cleanup_pydecref_ PyObject *name_arg = Py_BuildValue("On", self, i);
	if (!name_arg)
		return NULL;
	return PyObject_CallFunction(SourceLocation_type, "siiN", filename,
				     line, column,
				     PyCFunction_New(&meth, name_arg));
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
