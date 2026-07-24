// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

// TODO: warn if promise is never completed.

Promise *NonePromise_wrap(struct drgn_void_promise *promise)
{
	Promise *ret = call_tp_alloc(Promise);
	if (!ret) {
		drgn_promise_set_error(promise, &drgn_enomem);
		return NULL;
	}
	ret->promise = (struct drgn_promise *)promise;
	ret->type = DRGNPY_PROMISE_VOID;
	return ret;
}

Promise *BoolPromise_wrap(struct drgn_bool_promise *promise)
{
	Promise *ret = call_tp_alloc(Promise);
	if (!ret) {
		drgn_promise_set_error(promise, &drgn_enomem);
		return NULL;
	}
	ret->promise = (struct drgn_promise *)promise;
	ret->type = DRGNPY_PROMISE_BOOL;
	return ret;
}

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

static PyObject *Promise_set_result(Promise *self, PyObject *arg)
{
	SWITCH_ENUM(self->type) {
	case DRGNPY_PROMISE_VOID:
		if (arg != Py_None) {
			return PyErr_Format(PyExc_TypeError,
					    "result must be None, not %.200s",
					    Py_TYPE(arg)->tp_name);
		}
		if (!mark_done(self))
			return NULL;
		drgn_void_promise_set_result((struct drgn_void_promise *)
					     self->promise);
		break;
	case DRGNPY_PROMISE_BOOL:
		if (!PyBool_Check(arg)) {
			return PyErr_Format(PyExc_TypeError,
					    "result must be bool, not %.200s",
					    Py_TYPE(arg)->tp_name);
		}
		if (!mark_done(self))
			return NULL;
		drgn_bool_promise_set_result((struct drgn_bool_promise *)
					     self->promise, arg == Py_True);
		break;
	default:
		UNREACHABLE();
	}
	Py_RETURN_NONE;
}

static PyObject *Promise_set_exception(Promise *self, PyObject *arg)
{
	if (!PyExceptionInstance_Check(arg)) {
		PyErr_SetString(PyExc_TypeError, "not an exception");
		return NULL;
	}
	if (!mark_done(self))
		return NULL;
	Py_INCREF(arg);
	drgn_promise_set_error(self->promise, drgn_error_from_given_exception(arg));
	Py_RETURN_NONE;
}

static PyObject *Promise_cancelled(Promise *self, PyObject *Py_UNUSED(ignored))
{
	if (self->done)
		Py_RETURN_FALSE;
	Py_RETURN_BOOL(drgn_promise_cancelled(self->promise));
}

static PyMethodDef Promise_methods[] = {
	{"set_result", (PyCFunction)Promise_set_result, METH_O},
	{"set_exception", (PyCFunction)Promise_set_exception, METH_O},
	{"cancelled", (PyCFunction)Promise_cancelled, METH_NOARGS},
	{},
};

PyTypeObject Promise_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._Promise",
	.tp_basicsize = sizeof(Promise),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = Promise_methods,
};

void Promise_catch_exception(Promise *promise)
{
	if (promise->done) {
		// Exception was raised after result was already set.
		PyErr_WriteUnraisable(NULL);
		return;
	}
	promise->done = true;
	drgn_promise_set_error(promise->promise, drgn_error_from_python());
}
