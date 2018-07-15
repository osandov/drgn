// Copyright 2018 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#define PY_SSIZE_T_CLEAN

#include <Python.h>

typedef struct {
	PyObject_HEAD
	PyObject *func;
	PyObject *args;
	PyObject *kwds;
	PyObject *result;
} thunkobject;

static void thunk_dealloc(thunkobject *self)
{
	Py_XDECREF(self->func);
	Py_XDECREF(self->args);
	Py_XDECREF(self->kwds);
	Py_XDECREF(self->result);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int thunk_traverse(thunkobject *self, visitproc visit, void *arg)
{
	Py_VISIT(self->func);
	Py_VISIT(self->args);
	Py_VISIT(self->kwds);
	Py_VISIT(self->result);
	return 0;
}

static int thunk_clear(thunkobject *self)
{
	Py_CLEAR(self->func);
	Py_CLEAR(self->args);
	Py_CLEAR(self->kwds);
	Py_CLEAR(self->result);
	return 0;
}

static thunkobject *thunk_new(PyTypeObject *type, PyObject *args,
			      PyObject *kwds)
{
	thunkobject *obj;
	PyObject *func;

	if (PyTuple_GET_SIZE(args) < 1) {
		PyErr_SetString(PyExc_TypeError,
				"thunk() missing required argument 'func'");
		return NULL;
	}

	func = PyTuple_GET_ITEM(args, 0);
	if (!PyCallable_Check(func)) {
		PyErr_SetString(PyExc_TypeError,
				"'thunk() argument func' must be callable");
		return NULL;
	}

	obj = (thunkobject *)type->tp_alloc(type, 0);
	if (obj == NULL)
		return NULL;

	obj->func = func;
	Py_INCREF(func);

	obj->args = PyTuple_GetSlice(args, 1, PY_SSIZE_T_MAX);
	if (obj->args == NULL) {
		Py_DECREF(obj);
		return NULL;
	}

	if (kwds && PyDict_Size(kwds)) {
		obj->kwds = kwds;
		Py_INCREF(obj->kwds);
	}

	return obj;
}

static PyObject *thunk_call(thunkobject *self, PyObject *args, PyObject *kwds)
{
	if (PyTuple_GET_SIZE(args) || (kwds && PyDict_Size(kwds))) {
		PyErr_SetString(PyExc_TypeError,
				"thunk call takes no arguments");
		return NULL;
	}

	if (self->result) {
		Py_INCREF(self->result);
		return self->result;
	}

	self->result = PyObject_Call(self->func, self->args, self->kwds);
	Py_XINCREF(self->result);
	return self->result;
}

#define thunk_DOC	\
	"thunk(func, *args, **kwds) -> new lazily evaluated function\n\n"	\
	"thunk() is similar to functools.partial(), but the returned callable\n"\
	"caches the return value of the wrapped function. Additionally, the\n"	\
	"returned callable does not take any additional arguments."

static PyTypeObject thunk_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.internal.thunk.thunk",	/* tp_name */
	sizeof(thunkobject),		/* tp_basicsize */
	0,				/* tp_itemsize */
	(destructor)thunk_dealloc,	/* tp_dealloc */
	NULL,				/* tp_print */
	NULL,				/* tp_getattr */
	NULL,				/* tp_setattr */
	NULL,				/* tp_as_async */
	NULL,				/* tp_repr */
	NULL,				/* tp_as_number */
	NULL,				/* tp_as_sequence */
	NULL,				/* tp_as_mapping */
	NULL,				/* tp_hash  */
	(ternaryfunc)thunk_call,	/* tp_call */
	NULL,				/* tp_str */
	NULL,				/* tp_getattro */
	NULL,				/* tp_setattro */
	NULL,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,/* tp_flags */
	thunk_DOC,			/* tp_doc */
	(traverseproc)thunk_traverse,	/* tp_traverse */
	(inquiry)thunk_clear,		/* tp_clear */
	NULL,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	NULL,				/* tp_iter */
	NULL,				/* tp_iternext */
	NULL,				/* tp_methods */
	NULL,				/* tp_members */
	NULL,				/* tp_getset */
	NULL,				/* tp_base */
	NULL,				/* tp_dict */
	NULL,				/* tp_descr_get */
	NULL,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	NULL,				/* tp_init */
	NULL,				/* tp_alloc */
	(newfunc)thunk_new,		/* tp_new */
};

static struct PyModuleDef thunkmodule = {
	PyModuleDef_HEAD_INIT,
	"thunk",
	"Lazily evaluated function calls",
	-1,
};

PyMODINIT_FUNC
PyInit_thunk(void)
{
	PyObject *m;

	m = PyModule_Create(&thunkmodule);
	if (!m)
		return NULL;

	if (PyType_Ready(&thunk_type) < 0)
		return NULL;
	Py_INCREF(&thunk_type);
	PyModule_AddObject(m, "thunk", (PyObject *)&thunk_type);

	return m;
}
