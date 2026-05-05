// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

static PyObject *ThreadFinder_threads(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
	PyErr_SetString(PyExc_ValueError,
			"can't iterate threads in this program");
	return NULL;
}

static PyObject *ThreadFinder_thread(PyObject *self, PyObject *args,
				     PyObject *kwds)
{
	PyErr_SetString(PyExc_ValueError,
			"can't find threads in this program");
	return NULL;
}

static PyObject *ThreadFinder_thread_from_object(PyObject *self, PyObject *args,
						 PyObject *kwds)
{
	PyErr_SetString(PyExc_ValueError,
			"can't get thread from object in this program");
	return NULL;
}

static PyObject *ThreadFinder_main_thread(PyObject *self, PyObject *args,
					  PyObject *kwds)
{
	PyErr_SetString(PyExc_ValueError,
			"main thread is not defined in this program");
	return NULL;
}

static PyObject *ThreadFinder_crashed_thread(PyObject *self, PyObject *args,
					     PyObject *kwds)
{
	PyErr_SetString(PyExc_ValueError,
			"crashed thread is not defined in this program");
	return NULL;
}

static PyObject *ThreadFinder_thread_object(PyObject *self, PyObject *args,
					    PyObject *kwds)
{
	PyErr_SetString(PyExc_ValueError,
			"thread object is not defined in this program");
	return NULL;
}

static PyObject *ThreadFinder_thread_name(PyObject *self, PyObject *args,
					  PyObject *kwds)
{
	Py_RETURN_NONE;
}

static PyMethodDef ThreadFinder_methods[] = {
	{"threads", (PyCFunction)ThreadFinder_threads,
	 METH_VARARGS | METH_KEYWORDS, drgn_ThreadFinder_threads_DOC},
	{"thread", (PyCFunction)ThreadFinder_thread,
	 METH_VARARGS | METH_KEYWORDS, drgn_ThreadFinder_thread_DOC},
	{"thread_from_object", (PyCFunction)ThreadFinder_thread_from_object,
	 METH_VARARGS | METH_KEYWORDS,
	 drgn_ThreadFinder_thread_from_object_DOC},
	{"main_thread", (PyCFunction)ThreadFinder_main_thread,
	 METH_VARARGS | METH_KEYWORDS, drgn_ThreadFinder_main_thread_DOC},
	{"crashed_thread", (PyCFunction)ThreadFinder_crashed_thread,
	 METH_VARARGS | METH_KEYWORDS, drgn_ThreadFinder_crashed_thread_DOC},
	{"thread_object", (PyCFunction)ThreadFinder_thread_object,
	 METH_VARARGS | METH_KEYWORDS, drgn_ThreadFinder_thread_object_DOC},
	{"thread_name", (PyCFunction)ThreadFinder_thread_name,
	 METH_VARARGS | METH_KEYWORDS, drgn_ThreadFinder_thread_name_DOC},
	{},
};

PyTypeObject ThreadFinder_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.ThreadFinder",
	.tp_basicsize = sizeof(PyObject),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = drgn_ThreadFinder_DOC,
	.tp_methods = ThreadFinder_methods,
	.tp_new = PyType_GenericNew,
};
