// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

#include "../symbol_index.h"

static int SymbolIndex_init(SymbolIndex *self, PyObject *args, PyObject *kwds)
{
	if (PyTuple_GET_SIZE(args) || (kwds && PyDict_Size(kwds))) {
		PyErr_SetString(PyExc_ValueError,
				"SymbolIndex() takes no arguments");
		return -1;
	}
	if (self->objects) {
		PyDict_Clear(self->objects);
	} else {
		self->objects = PyDict_New();
		if (!self->objects)
			return -1;
	}
	if (self->sindex.finders)
		drgn_symbol_index_deinit(&self->sindex);
	drgn_symbol_index_init(&self->sindex);
	return 0;
}

static void SymbolIndex_dealloc(SymbolIndex *self)
{
	if (self->sindex.finders)
		drgn_symbol_index_deinit(&self->sindex);
	Py_XDECREF(self->objects);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int SymbolIndex_traverse(SymbolIndex *self, visitproc visit, void *arg)
{
	Py_VISIT(self->objects);
	return 0;
}

static int SymbolIndex_clear(SymbolIndex *self)
{
	Py_CLEAR(self->objects);
	return 0;
}

static struct drgn_error *
SymbolIndex_find_fn(const char *name, size_t name_len, const char *filename,
		    enum drgn_find_object_flags flags, void *arg,
		    struct drgn_symbol *ret)
{
	struct drgn_error *err;
	PyGILState_STATE gstate;
	PyObject *name_obj, *flags_obj;
	PyObject *sym_obj;

	gstate = PyGILState_Ensure();
	name_obj = PyUnicode_FromStringAndSize(name, name_len);
	if (!name_obj) {
		err = drgn_error_from_python();
		goto out_gstate;
	}
	flags_obj = PyObject_CallFunction(FindObjectFlags_class, "i",
					  (int)flags);
	if (!flags_obj) {
		err = drgn_error_from_python();
		goto out_name_obj;
	}
	sym_obj = PyObject_CallFunction(PyTuple_GET_ITEM(arg, 1), "OOs",
					name_obj, flags_obj, filename);
	if (!sym_obj) {
		err = drgn_error_from_python();
		goto out_flags_obj;
	}
	if (sym_obj == Py_None) {
		ret->type = NULL;
		goto out;
	}
	if (!PyObject_TypeCheck(sym_obj, &Symbol_type)) {
		PyErr_SetString(PyExc_TypeError,
				"symbol find callback must return Symbol or None");
		err = drgn_error_from_python();
		goto out_sym_obj;
	}
	if (hold_drgn_type(PyTuple_GET_ITEM(arg, 0),
			   ((Symbol *)sym_obj)->type_obj) == -1) {
		err = drgn_error_from_python();
		goto out_sym_obj;
	}

	*ret = ((Symbol *)sym_obj)->sym;
out:
	err = NULL;
out_sym_obj:
	Py_DECREF(sym_obj);
out_flags_obj:
	Py_DECREF(flags_obj);
out_name_obj:
	Py_DECREF(name_obj);
out_gstate:
	PyGILState_Release(gstate);
	return err;
}

static PyObject *SymbolIndex_add_finder(SymbolIndex *self, PyObject *args,
					PyObject *kwds)
{
	static char *keywords[] = {"fn", NULL};
	struct drgn_error *err;
	PyObject *fn, *arg;
	int ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:add_finder", keywords,
					 &fn))
	    return NULL;

	if (!PyCallable_Check(fn)) {
		PyErr_SetString(PyExc_TypeError, "fn must be callable");
		return NULL;
	}

	arg = Py_BuildValue("OO", self->objects, fn);
	if (!arg)
		return NULL;
	ret = hold_object(self->objects, arg);
	Py_DECREF(arg);
	if (ret == -1)
		return NULL;

	err = drgn_symbol_index_add_finder(&self->sindex, SymbolIndex_find_fn,
					   arg);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static Symbol *SymbolIndex_find(SymbolIndex *self, PyObject *args,
				PyObject *kwds)
{
	static char *keywords[] = {"name", "flags", "filename", NULL};
	struct drgn_error *err;
	const char *name, *filename;
	PyObject *flags_obj, *flags_value_obj;
	long flags;
	PyObject *filename_obj = NULL;
	Symbol *sym_obj;
	bool clear;
	struct drgn_qualified_type qualified_type;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "sO!|O&:find", keywords,
					 &name, FindObjectFlags_class,
					 &flags_obj, filename_converter,
					 &filename_obj))
		return NULL;

	filename = filename_obj ? PyBytes_AS_STRING(filename_obj) : NULL;
	flags_value_obj = PyObject_GetAttrString(flags_obj, "value");
	if (!flags_value_obj)
		return NULL;
	flags = PyLong_AsLong(flags_value_obj);
	Py_DECREF(flags_value_obj);
	if (flags == -1 && PyErr_Occurred())
		return NULL;

	sym_obj = (Symbol *)Symbol_type.tp_alloc(&Symbol_type, 0);
	if (!sym_obj)
		return NULL;

	clear = set_drgn_in_python();
	err = drgn_symbol_index_find(&self->sindex, name, filename, flags,
				     &sym_obj->sym);
	if (clear)
		clear_drgn_in_python();
	if (err) {
		Py_DECREF(sym_obj);
		set_drgn_error(err);
		return NULL;
	}

	qualified_type.type = sym_obj->sym.type;
	qualified_type.qualifiers = sym_obj->sym.qualifiers;
	sym_obj->type_obj = (DrgnType *)DrgnType_wrap(qualified_type,
						      self->objects);
	if (!sym_obj->type_obj) {
		Py_DECREF(sym_obj);
		return NULL;
	}
	return sym_obj;
}

static PyMethodDef SymbolIndex_methods[] = {
	{"add_finder", (PyCFunction)SymbolIndex_add_finder,
	 METH_VARARGS | METH_KEYWORDS,
	 "add_finder(fn)\n--\n\n"},
	{"find", (PyCFunction)SymbolIndex_find, METH_VARARGS | METH_KEYWORDS,
	 "find(name, flags, filename=None)\n--\n\n"},
	{},
};

PyTypeObject SymbolIndex_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.SymbolIndex",			/* tp_name */
	sizeof(SymbolIndex),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)SymbolIndex_dealloc,	/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	NULL,					/* tp_repr */
	NULL,					/* tp_as_number */
	NULL,					/* tp_as_sequence */
	NULL,					/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	NULL,					/* tp_str */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,/* tp_flags */
	"drgn_symbol_index wrapper for testing",/* tp_doc */
	(traverseproc)SymbolIndex_traverse,	/* tp_traverse */
	(inquiry)SymbolIndex_clear,		/* tp_clear */
	NULL,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	SymbolIndex_methods,			/* tp_methods */
	NULL,					/* tp_members */
	NULL,					/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	(initproc)SymbolIndex_init,		/* tp_init */
	NULL,					/* tp_alloc */
	PyType_GenericNew,			/* tp_new */
};
