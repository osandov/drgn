// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

// TODO: warn if promise is never completed.

static bool mark_done(Promise *self)
{
	if (self->done) {
		PyErr_SetString(PyExc_RuntimeError,
				"promise result already set");
		return false;
	}
	self->done = true;
	return true;
}

PyObject *Promise_set_exception(Promise *self, PyObject *arg)
{
	if (!PyExceptionInstance_Check(arg)) {
		PyErr_SetString(PyExc_TypeError, "not an exception");
		return NULL;
	}
	if (!mark_done(self))
		return NULL;
	Py_INCREF(arg);
	self->set_error(self->arg, drgn_error_from_given_exception(arg));
	Py_RETURN_NONE;
}

static PyObject *NonePromise_set_result(NonePromise *self, PyObject *arg)
{
	if (arg != Py_None) {
		PyErr_SetString(PyExc_TypeError, "result must be None");
		return NULL;
	}
	if (!mark_done((Promise *)self))
		return NULL;
	self->set_result(self->arg);
	Py_RETURN_NONE;
}

static PyMethodDef NonePromise_methods[] = {
	{"set_result", (PyCFunction)NonePromise_set_result, METH_O},
	{"set_exception", (PyCFunction)Promise_set_exception, METH_O},
	{},
};

PyTypeObject NonePromise_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._NonePromise",
	.tp_basicsize = sizeof(NonePromise),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = NonePromise_methods,
};

static PyObject *BoolPromise_set_result(BoolPromise *self, PyObject *arg)
{
	if (!PyBool_Check(arg)) {
		return PyErr_Format(PyExc_TypeError,
				    "result must be bool, not %.200s",
				    Py_TYPE(arg)->tp_name);
	}
	if (!mark_done((Promise *)self))
		return NULL;
	self->set_result(self->arg, arg == Py_True);
	Py_RETURN_NONE;
}

static PyMethodDef BoolPromise_methods[] = {
	{"set_result", (PyCFunction)BoolPromise_set_result, METH_O},
	{"set_exception", (PyCFunction)Promise_set_exception, METH_O},
	{},
};

PyTypeObject BoolPromise_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._BoolPromise",
	.tp_basicsize = sizeof(BoolPromise),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = BoolPromise_methods,
};
