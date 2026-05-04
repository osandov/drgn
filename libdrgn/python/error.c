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

static struct drgn_error drgn_error_python = {
	.code = DRGN_ERROR_OTHER,
	.message = "error in Python callback",
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
	X(DRGN_ERROR_NOT_IMPLEMENTED, PyExc_NotImplementedError)

static struct drgn_error *
drgn_error_from_python_simple(enum drgn_error_code code, PyObject *exc_value)
{
	_cleanup_pydecref_ PyObject *exc_message = PyObject_Str(exc_value);
	const char *message =
		exc_message ? PyUnicode_AsUTF8(exc_message) : NULL;
	if (!message) {
		PyErr_Clear();
		return drgn_error_create(code, "<exception str() failed>");
	}
	return drgn_error_create(code, message);
}

static struct drgn_error *drgn_memory_error_from_python(PyObject *exc_value)
{
	if (!PyTuple_GET_SIZE(((PyBaseExceptionObject *)exc_value)->args))
		return &drgn_enomem;
	return drgn_error_from_python_simple(DRGN_ERROR_NO_MEMORY, exc_value);
}

static struct drgn_error *drgn_os_error_from_python(PyObject *exc_value)
{
	_cleanup_pydecref_ PyObject *py_errno =
		PyObject_GetAttrString(exc_value, "errno");
	if (!py_errno)
		return NULL;
	long errnum = PyLong_AsLong(py_errno);
	if ((errnum == -1 && PyErr_Occurred())
	    || errnum < INT_MIN || errnum > INT_MAX)
		return NULL;

	const char *path = NULL;
	_cleanup_pydecref_ PyObject *py_filename =
		PyObject_GetAttrString(exc_value, "filename");
	if (!py_filename)
		return NULL;
	if (py_filename != Py_None) {
		path = PyUnicode_AsUTF8(py_filename);
		if (!path)
			return NULL;
	}

	return drgn_error_create_os("", errnum, path);
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
	uint64_t address;
	if (!py_address || PyLong_AsUInt64(py_address, &address))
		return NULL;

	return drgn_error_create_fault(message, address);
}

struct drgn_error *drgn_error_from_python(void)
{
	struct drgn_error *err;
	PyObject *occurred = PyErr_Occurred();
	if (!occurred)
		return NULL;

	// If PyEval_GetFrame() returns non-NULL, then we are being called from
	// Python. In that case, we should preserve the original Python
	// exception for set_drgn_error() to bubble up.
	//
	// Python FaultErrors should always be translated back to drgn errors
	// because they are frequently handled in libdrgn.
	if (PyEval_GetFrame() && occurred != (PyObject *)&FaultError_type)
		return &drgn_error_python;

	_cleanup_pydecref_ PyObject *exc_type, *exc_value, *exc_traceback;
	PyErr_Fetch(&exc_type, &exc_value, &exc_traceback);
	PyErr_NormalizeException(&exc_type, &exc_value, &exc_traceback);

#define X(code, type)							\
	if (exc_type == type)						\
		return drgn_error_from_python_simple(code, exc_value);
SIMPLE_DRGN_EXCEPTIONS
#undef X
	if (exc_type == PyExc_MemoryError)
		return drgn_memory_error_from_python(exc_value);

	// If we can't convert these exceptions to a valid error, then these
	// functions return NULL (possibly with a Python exception set), and we
	// fall back to the generic case.
	if (exc_type == PyExc_OSError) {
		err = drgn_os_error_from_python(exc_value);
		if (err)
			return err;
		PyErr_Clear();
	}
	if (exc_type == (PyObject *)&FaultError_type) {
		err = drgn_fault_error_from_python(exc_value);
		if (err)
			return err;
		PyErr_Clear();
	}

	const char *type = ((PyTypeObject *)exc_type)->tp_name;
	_cleanup_pydecref_ PyObject *exc_message = PyObject_Str(exc_value);
	const char *message =
		exc_message ? PyUnicode_AsUTF8(exc_message) : NULL;
	if (!message) {
		PyErr_Clear();
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s: <exception str() failed>", type);
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
#define X(code, type)					\
	case code:					\
		PyErr_SetString(type, err->message);	\
		break;
	SIMPLE_DRGN_EXCEPTIONS
#undef X
	case DRGN_ERROR_NO_MEMORY:
		PyErr_NoMemory();
		break;
	case DRGN_ERROR_OS:
		errno = err->errnum;
		PyErr_SetFromErrnoWithFilename(PyExc_OSError, err->path);
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

struct drgn_error *
drgn_blocking_check_signals(drgn_blocking_state *statep)
{
	if (!*statep)
		return NULL;
	PyEval_RestoreThread((PyThreadState *)*statep);
	int r = PyErr_CheckSignals();
	*statep = (drgn_blocking_state)PyEval_SaveThread();
	return r ? &drgn_error_python : NULL;
}
