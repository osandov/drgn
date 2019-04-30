// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

#include "../type_index.h"

static int TypeIndex_init(TypeIndex *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"word_size", NULL,
	};
	long word_size;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "l:TypeIndex", keywords,
					 &word_size))
	    return -1;
	if (word_size != 8 && word_size != 4) {
		PyErr_SetString(PyExc_ValueError, "word size must be 8 or 4");
		return -1;
	}
	if (self->objects) {
		PyDict_Clear(self->objects);
	} else {
		self->objects = PyDict_New();
		if (!self->objects)
			return -1;
	}
	if (self->tindex.word_size)
		drgn_type_index_deinit(&self->tindex);
	drgn_type_index_init(&self->tindex, word_size, true);
	return 0;
}

static void TypeIndex_dealloc(TypeIndex *self)
{
	if (self->tindex.word_size)
		drgn_type_index_deinit(&self->tindex);
	Py_XDECREF(self->objects);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int TypeIndex_traverse(TypeIndex *self, visitproc visit, void *arg)
{
	Py_VISIT(self->objects);
	return 0;
}

static int TypeIndex_clear(TypeIndex *self)
{
	Py_CLEAR(self->objects);
	return 0;
}

static struct drgn_error *TypeIndex_find_fn(enum drgn_type_kind kind,
					    const char *name, size_t name_len,
					    const char *filename, void *arg,
					    struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	PyGILState_STATE gstate;
	PyObject *kind_obj, *name_obj;
	PyObject *type_obj;

	gstate = PyGILState_Ensure();
	kind_obj = PyObject_CallFunction(TypeKind_class, "k", kind);
	if (!kind_obj) {
		err = drgn_error_from_python();
		goto out_gstate;
	}
	name_obj = PyUnicode_FromStringAndSize(name, name_len);
	if (!name_obj) {
		err = drgn_error_from_python();
		goto out_kind_obj;
	}
	type_obj = PyObject_CallFunction(PyTuple_GET_ITEM(arg, 1), "OOs",
					 kind_obj, name_obj, filename);
	if (!type_obj) {
		err = drgn_error_from_python();
		goto out_name_obj;
	}
	if (type_obj == Py_None) {
		ret->type = NULL;
		goto out;
	}
	if (!PyObject_TypeCheck(type_obj, &DrgnType_type)) {
		PyErr_SetString(PyExc_TypeError,
				"type find callback must return Type or None");
		err = drgn_error_from_python();
		goto out_type_obj;
	}
	if (hold_drgn_type(PyTuple_GET_ITEM(arg, 0),
			   (DrgnType *)type_obj) == -1) {
		err = drgn_error_from_python();
		goto out_type_obj;
	}

	ret->type = ((DrgnType *)type_obj)->type;
	ret->qualifiers = ((DrgnType *)type_obj)->qualifiers;
out:
	err = NULL;
out_type_obj:
	Py_DECREF(type_obj);
out_name_obj:
	Py_DECREF(name_obj);
out_kind_obj:
	Py_DECREF(kind_obj);
out_gstate:
	PyGILState_Release(gstate);
	return err;
}

static PyObject *TypeIndex_add_finder(TypeIndex *self, PyObject *args,
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

	err = drgn_type_index_add_finder(&self->tindex, TypeIndex_find_fn, arg);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *TypeIndex_find(TypeIndex *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	struct drgn_error *err;
	const char *name, *filename;
	PyObject *filename_obj = NULL;
	struct drgn_qualified_type qualified_type;
	bool clear;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:type", keywords,
					 &name, filename_converter,
					 &filename_obj))
		return NULL;

	filename = filename_obj ? PyBytes_AS_STRING(filename_obj) : NULL;
	clear = set_drgn_in_python();
	err = drgn_type_index_find(&self->tindex, name, filename,
				   &drgn_language_c, &qualified_type);
	if (clear)
		clear_drgn_in_python();
	Py_XDECREF(filename_obj);
	if (err) {
		set_drgn_error(err);
		return NULL;
	}
	return DrgnType_wrap(qualified_type, self->objects);
}

static PyMethodDef TypeIndex_methods[] = {
	{"add_finder", (PyCFunction)TypeIndex_add_finder,
	 METH_VARARGS | METH_KEYWORDS,
	 "add_finder(fn)\n--\n\n"},
	{"find", (PyCFunction)TypeIndex_find, METH_VARARGS | METH_KEYWORDS,
	 "find(name, filename=None)\n--\n\n"},
	{},
};

PyTypeObject TypeIndex_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.TypeIndex",			/* tp_name */
	sizeof(TypeIndex),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)TypeIndex_dealloc,		/* tp_dealloc */
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
	"drgn_type_index wrapper for testing",	/* tp_doc */
	(traverseproc)TypeIndex_traverse,	/* tp_traverse */
	(inquiry)TypeIndex_clear,		/* tp_clear */
	NULL,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	TypeIndex_methods,			/* tp_methods */
	NULL,					/* tp_members */
	NULL,					/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	(initproc)TypeIndex_init,		/* tp_init */
	NULL,					/* tp_alloc */
	PyType_GenericNew,			/* tp_new */
};
