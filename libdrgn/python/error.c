// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drgnpy.h"
#include "../error.h"

int FaultError_init(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"message", "address", NULL};
	PyObject *address, *message;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO:FaultError", keywords,
					 &message, &address))
		return -1;

	if (PyObject_SetAttrString(self, "message", message) < 0 ||
	    PyObject_SetAttrString(self, "address", address) < 0)
		return -1;
	return 0;
}

static PyObject *FaultError_str(PyObject *self)
{
	PyObject *message, *address, *args, *fmt, *ret = NULL;

	message = PyObject_GetAttrString(self, "message");
	if (!message)
		return NULL;

	address = PyObject_GetAttrString(self, "address");
	if (!address)
		goto out_message;

	args = Py_BuildValue("OO", message, address);
	if (!args)
		goto out_address;

	fmt = PyUnicode_FromString("%s: %#x");
	if (!fmt)
		goto out_args;

	ret = PyUnicode_Format(fmt, args);

	Py_DECREF(fmt);
out_args:
	Py_DECREF(args);
out_address:
	Py_DECREF(address);
out_message:
	Py_DECREF(message);
	return ret;
}

PyTypeObject FaultError_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.FaultError",
	.tp_basicsize = sizeof(PyBaseExceptionObject),
	.tp_str = (reprfunc)FaultError_str,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = drgn_FaultError_DOC,
	.tp_init = (initproc)FaultError_init,
};

static struct drgn_error drgn_error_python = {
	.code = DRGN_ERROR_OTHER,
	.message = "error in Python callback",
};

static _Thread_local bool drgn_in_python = false;

bool set_drgn_in_python(void)
{
	if (drgn_in_python)
		return false;
	drgn_in_python = true;
	return true;
}

void clear_drgn_in_python(void)
{
	drgn_in_python = false;
}

struct drgn_error *drgn_error_from_python(void)
{
	PyObject *exc_type, *exc_value, *exc_traceback, *exc_message;
	const char *type, *message;
	struct drgn_error *err;

	PyErr_Fetch(&exc_type, &exc_value, &exc_traceback);
	if (!exc_type)
		return NULL;

	if (drgn_in_python) {
		PyErr_Restore(exc_type, exc_value, exc_traceback);
		return &drgn_error_python;
	}

	type = ((PyTypeObject *)exc_type)->tp_name;
	if (exc_value) {
		exc_message = PyObject_Str(exc_value);
		message = exc_message ? PyUnicode_AsUTF8(exc_message) : NULL;
		if (!message) {
			err = drgn_error_format(DRGN_ERROR_OTHER,
						"%s: <exception str() failed>", type);
			goto out;
		}
	} else {
		exc_message = NULL;
		message = "";
	}

	if (message[0]) {
		err = drgn_error_format(DRGN_ERROR_OTHER, "%s: %s", type,
					message);
	} else {
		err = drgn_error_create(DRGN_ERROR_OTHER, type);
	}

out:
	Py_XDECREF(exc_message);
	Py_XDECREF(exc_traceback);
	Py_XDECREF(exc_value);
	Py_DECREF(exc_type);
	return err;
}

DRGNPY_PUBLIC void *set_drgn_error(struct drgn_error *err)
{
	if (err == &drgn_error_python)
		return NULL;

	switch (err->code) {
	case DRGN_ERROR_NO_MEMORY:
		PyErr_NoMemory();
		break;
	case DRGN_ERROR_INVALID_ARGUMENT:
		PyErr_SetString(PyExc_ValueError, err->message);
		break;
	case DRGN_ERROR_OVERFLOW:
		PyErr_SetString(PyExc_OverflowError, err->message);
		break;
	case DRGN_ERROR_RECURSION:
		PyErr_SetString(PyExc_RecursionError, err->message);
		break;
	case DRGN_ERROR_OS:
		errno = err->errnum;
		PyErr_SetFromErrnoWithFilename(PyExc_OSError, err->path);
		break;
	case DRGN_ERROR_MISSING_DEBUG_INFO:
		PyErr_SetString(MissingDebugInfoError, err->message);
		break;
	case DRGN_ERROR_SYNTAX:
		PyErr_SetString(PyExc_SyntaxError, err->message);
		break;
	case DRGN_ERROR_LOOKUP:
		PyErr_SetString(PyExc_LookupError, err->message);
		break;
	case DRGN_ERROR_FAULT: {
		PyObject *exc;

		exc = PyObject_CallFunction((PyObject *)&FaultError_type, "sK",
					    err->message, err->address);
		if (exc)
			PyErr_SetObject((PyObject *)&FaultError_type, exc);
		break;
	}
	case DRGN_ERROR_TYPE:
		PyErr_SetString(PyExc_TypeError, err->message);
		break;
	case DRGN_ERROR_ZERO_DIVISION:
		PyErr_SetString(PyExc_ZeroDivisionError, err->message);
		break;
	case DRGN_ERROR_OUT_OF_BOUNDS:
		PyErr_SetString(OutOfBoundsError, err->message);
		break;
	case DRGN_ERROR_OBJECT_ABSENT:
		PyErr_SetString(ObjectAbsentError, err->message);
		break;
	default:
		PyErr_SetString(PyExc_Exception, err->message);
		break;
	}

	drgn_error_destroy(err);
	return NULL;
}

void *set_error_type_name(const char *format,
			  struct drgn_qualified_type qualified_type)
{
	return set_drgn_error(drgn_qualified_type_error(format,
							qualified_type));
}
