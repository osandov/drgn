// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../error.h"
#include "../program.h"

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

#define SIMPLE_DRGN_EXCEPTIONS						\
	X(DRGN_ERROR_INVALID_ARGUMENT, PyExc_ValueError)		\
	X(DRGN_ERROR_OVERFLOW, PyExc_OverflowError)			\
	X(DRGN_ERROR_RECURSION, PyExc_RecursionError)			\
	X(DRGN_ERROR_MISSING_DEBUG_INFO, MissingDebugInfoError)		\
	X(DRGN_ERROR_SYNTAX, PyExc_SyntaxError)				\
	X(DRGN_ERROR_LOOKUP, PyExc_LookupError)				\
	X(DRGN_ERROR_TYPE, PyExc_TypeError)				\
	X(DRGN_ERROR_ZERO_DIVISION, PyExc_ZeroDivisionError)		\
	X(DRGN_ERROR_OUT_OF_BOUNDS, OutOfBoundsError)			\
	X(DRGN_ERROR_OBJECT_ABSENT, ObjectAbsentError)			\
	X(DRGN_ERROR_NOT_IMPLEMENTED, PyExc_NotImplementedError)	\
	X(DRGN_ERROR_UNSUPPORTED_OPERATION, UnsupportedOperation)	\
	X(DRGN_ERROR_RUNTIME, PyExc_RuntimeError)			\
	X(DRGN_ERROR_BAD_DATA, BadDataError)

#define DRGN_ERROR_PYTHON (-1)

struct drgn_error *drgn_error_from_python(void)
{
	_cleanup_pydecref_ PyObject *exc = PyErr_GetRaisedException();
	if (!exc)
		return NULL;

	struct drgn_error *err = malloc(sizeof(*err));
	if (!err)
		return &drgn_enomem;
	err->_code = DRGN_ERROR_PYTHON;
	err->_needs_destroy = true;
	err->_message = NULL;
	err->_python_exc = no_cleanup_ptr(exc);
	return err;
}

static void drgn_error_set_exception_message(struct drgn_error *err)
{
	_cleanup_pydecref_ PyObject *exc_message =
		PyObject_Str(err->_python_exc);
	const char *message =
		exc_message ? PyUnicode_AsUTF8(exc_message) : NULL;
	if (message) {
		err->_message = strdup(message);
	} else {
		PyErr_Clear();
		err->_message = strdup("<exception str() failed>");
	}
	if (!err->_message) {
		err->_code = DRGN_ERROR_NO_MEMORY;
		err->_message = drgn_enomem._message;
	}
}

static void drgn_error_resolve_other(struct drgn_error *err)
{
	err->_code = DRGN_ERROR_OTHER;
	PyObject *exc_value = err->_python_exc;
	_cleanup_pydecref_ PyObject *exc_message = PyObject_Str(exc_value);
	const char *message =
		exc_message ? PyUnicode_AsUTF8(exc_message) : NULL;
	if (message && message[0]) {
		if (asprintf(&err->_message, "%s: %s",
			     Py_TYPE(exc_value)->tp_name, message) < 0)
			err->_message = NULL;
	} else if (message) {
		err->_message = strdup(Py_TYPE(exc_value)->tp_name);
	} else {
		PyErr_Clear();
		err->_message = strdup("<exception str() failed>");
	}
	if (!err->_message) {
		err->_code = DRGN_ERROR_NO_MEMORY;
		err->_message = drgn_enomem._message;
	}
}

static void drgn_error_resolve_os(struct drgn_error *err)
{
	PyObject *exc_value = err->_python_exc;
	_cleanup_pydecref_ PyObject *py_errno =
		PyObject_GetAttrString(exc_value, "errno");
	long errnum = py_errno ? PyLong_AsLong(py_errno) : -1;
	if ((errnum == -1 && PyErr_Occurred())
	    || errnum < INT_MIN || errnum > INT_MAX) {
		PyErr_Clear();
		drgn_error_resolve_other(err);
		return;
	}

	const char *path = NULL;
	_cleanup_pydecref_ PyObject *py_filename =
		PyObject_GetAttrString(exc_value, "filename");
	if (!py_filename) {
		PyErr_Clear();
		drgn_error_resolve_other(err);
		return;
	}
	if (py_filename != Py_None) {
		path = PyUnicode_AsUTF8(py_filename);
		if (!path) {
			PyErr_Clear();
			drgn_error_resolve_other(err);
			return;
		}
	}

	_cleanup_free_ char *path_copy = NULL;
	if (path) {
		path_copy = strdup(path);
		if (!path_copy) {
			err->_code = DRGN_ERROR_NO_MEMORY;
			err->_message = drgn_enomem._message;
			return;
		}
	}

	err->_code = DRGN_ERROR_OS;
	drgn_error_set_exception_message(err);
	if (err->_code == DRGN_ERROR_OS) {
		err->_errno = errnum;
		err->_path = no_cleanup_ptr(path_copy);
	}
}

static void drgn_error_resolve_fault(struct drgn_error *err)
{
	PyObject *exc_value = err->_python_exc;
	_cleanup_pydecref_ PyObject *py_address =
		PyObject_GetAttrString(exc_value, "address");
	uint64_t address;
	if (!py_address || PyLong_AsUInt64(py_address, &address)) {
		PyErr_Clear();
		drgn_error_resolve_other(err);
		return;
	}

	err->_code = DRGN_ERROR_FAULT;
	err->_address = address;
	drgn_error_set_exception_message(err);
}

void drgn_error_resolve(struct drgn_error *err)
{
	if (err->_code != DRGN_ERROR_PYTHON)
		return;

	PyGILState_guard();
	PyObject *exc_value = err->_python_exc;
	PyObject *exc_type = (PyObject *)Py_TYPE(exc_value);

#define X(code, type)					\
	if (exc_type == type) {				\
		err->_code = code;			\
		drgn_error_set_exception_message(err);	\
	} else
SIMPLE_DRGN_EXCEPTIONS
#undef X
	if (exc_type == PyExc_MemoryError) {
		err->_code = DRGN_ERROR_NO_MEMORY;
		if (PyTuple_GET_SIZE(((PyBaseExceptionObject *)exc_value)->args)
		    == 0)
			err->_message = drgn_enomem._message;
		else
			drgn_error_set_exception_message(err);
	} else if (exc_type == PyExc_OSError) {
		drgn_error_resolve_os(err);
	} else if (exc_type == (PyObject *)&FaultError_type) {
		drgn_error_resolve_fault(err);
	} else {
		drgn_error_resolve_other(err);
	}
}

void drgn_error_python_exc_decref(void *python_exc)
{
	if (python_exc) {
		PyGILState_guard();
		Py_DECREF(python_exc);
	}
}

void *set_drgn_error(struct drgn_error *err)
{
	if (err->_python_exc) {
		PyErr_SetRaisedException(err->_python_exc);
		err->_python_exc = NULL;
		drgn_error_destroy(err);
		return NULL;
	}

	switch (err->_code) {
#define X(code, type)					\
	case code:					\
		PyErr_SetString(type, err->_message);	\
		break;
	SIMPLE_DRGN_EXCEPTIONS
#undef X
	case DRGN_ERROR_NO_MEMORY:
		PyErr_NoMemory();
		break;
	case DRGN_ERROR_OS:
		errno = err->_errno;
		PyErr_SetFromErrnoWithFilename(PyExc_OSError, err->_path);
		break;
	case DRGN_ERROR_FAULT: {
		_cleanup_pydecref_ PyObject *exc =
			PyObject_CallFunction((PyObject *)&FaultError_type,
					      "sK", err->_message,
					      (unsigned long long)err->_address);
		if (exc)
			PyErr_SetObject((PyObject *)&FaultError_type, exc);
		break;
	}
	default:
		PyErr_SetString(PyExc_Exception, err->_message);
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

struct drgn_error *
drgn_blocking_check_signals(drgn_blocking_state *statep)
{
	if (!*statep)
		return NULL;
	PyEval_RestoreThread((PyThreadState *)*statep);
	struct drgn_error *err = PyErr_CheckSignals()
				 ? drgn_error_from_python() : NULL;
	*statep = (drgn_blocking_state)PyEval_SaveThread();
	return err;
}
