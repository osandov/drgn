// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../error.h"

static int FaultError_init(PyObject *self, PyObject *args, PyObject *kwds)
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
	_cleanup_pydecref_ PyObject *message =
		PyObject_GetAttrString(self, "message");
	if (!message)
		return NULL;

	_cleanup_pydecref_ PyObject *address =
		PyObject_GetAttrString(self, "address");
	if (!address)
		return NULL;

	_cleanup_pydecref_ PyObject *args =
		Py_BuildValue("OO", message, address);
	if (!args)
		return NULL;

	_cleanup_pydecref_ PyObject *fmt = PyUnicode_FromString("%s: %#x");
	if (!fmt)
		return NULL;

	return PyUnicode_Format(fmt, args);
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

static int ObjectNotFoundError_init(PyObject *self, PyObject *args,
				    PyObject *kwds)
{
	if (((PyTypeObject *)PyExc_BaseException)->tp_init(self, args, NULL) < 0)
		return -1;

	static char *keywords[] = {"name", NULL};
	_cleanup_pydecref_ PyObject *empty_tuple = PyTuple_New(0);
	if (!empty_tuple)
		return -1;
	PyObject *name;
	if (!PyArg_ParseTupleAndKeywords(empty_tuple, kwds,
					 "|$O:ObjectNotFoundError", keywords,
					 &name))
		return -1;

	return PyObject_SetAttrString(self, "name", name);
}

PyTypeObject ObjectNotFoundError_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.ObjectNotFoundError",
	.tp_basicsize = sizeof(PyBaseExceptionObject),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = drgn_ObjectNotFoundError_DOC,
	.tp_init = (initproc)ObjectNotFoundError_init,
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

static struct drgn_error *drgn_fault_error_from_python(PyObject *exc_value)
{
	_cleanup_pydecref_ PyObject *py_message =
		PyObject_GetAttrString(exc_value, "message");
	const char *message = py_message ? PyUnicode_AsUTF8(py_message) : NULL;
	if (!message)
		return NULL;

	_cleanup_pydecref_ PyObject *py_address =
		PyObject_GetAttrString(exc_value, "address");
	uint64_t address = py_address ? PyLong_AsUint64(py_address) : (uint64_t)-1;
	if (address == (uint64_t)-1 && PyErr_Occurred())
		return NULL;

	return drgn_error_create_fault(message, address);
}

struct drgn_error *drgn_error_from_python(void)
{
	_cleanup_pydecref_ PyObject *exc_type, *exc_value, *exc_traceback;
	PyErr_Fetch(&exc_type, &exc_value, &exc_traceback);
	if (!exc_type)
		return NULL;

	// Python FaultErrors should be translated back to drgn errors because
	// they are frequently handled in libdrgn. They should be translated no
	// matter how deeply nested we are, so we do this before checking
	// drgn_in_python.
	if ((PyTypeObject *)exc_type == &FaultError_type && exc_value) {
		struct drgn_error *err = drgn_fault_error_from_python(exc_value);
		if (err)
			return err;
		// A NULL return means that we encountered a Python error while
		// trying to convert it. Clear the Python error and fall back to
		// the standard code path.
		PyErr_Clear();
	}

	if (drgn_in_python) {
		PyErr_Restore(exc_type, exc_value, exc_traceback);
		exc_type = exc_value = exc_traceback = NULL;
		return &drgn_error_python;
	}

	const char *type = ((PyTypeObject *)exc_type)->tp_name;
	_cleanup_pydecref_ PyObject *exc_message = NULL;
	const char *message;
	if (exc_value) {
		exc_message = PyObject_Str(exc_value);
		message = exc_message ? PyUnicode_AsUTF8(exc_message) : NULL;
		if (!message) {
			PyErr_Clear();
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "%s: <exception str() failed>", type);
		}
	} else {
		message = "";
	}

	if (message[0]) {
		return drgn_error_format(DRGN_ERROR_OTHER, "%s: %s", type,
					 message);
	} else {
		return drgn_error_create(DRGN_ERROR_OTHER, type);
	}
}

void *set_drgn_error(struct drgn_error *err)
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
		_cleanup_pydecref_ PyObject *exc =
			PyObject_CallFunction((PyObject *)&FaultError_type,
					      "sK", err->message,
					      (unsigned long long)err->address);
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
	case DRGN_ERROR_NOT_IMPLEMENTED:
		PyErr_SetString(PyExc_NotImplementedError, err->message);
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
