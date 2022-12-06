// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdarg.h>

#include "drgnpy.h"

int append_string(PyObject *parts, const char *s)
{
	PyObject *str;
	int ret;

	str = PyUnicode_FromString(s);
	if (!str)
		return -1;

	ret = PyList_Append(parts, str);
	Py_DECREF(str);
	return ret;
}

static int append_formatv(PyObject *parts, const char *format, va_list ap)
{
	PyObject *str;
	int ret;

	str = PyUnicode_FromFormatV(format, ap);
	if (!str)
		return -1;

	ret = PyList_Append(parts, str);
	Py_DECREF(str);
	return ret;
}

int append_format(PyObject *parts, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = append_formatv(parts, format, ap);
	va_end(ap);
	return ret;
}

PyObject *join_strings(PyObject *parts)
{
	PyObject *sep = PyUnicode_New(0, 0);
	if (!sep)
		return NULL;
	PyObject *ret = PyUnicode_Join(sep, parts);
	Py_DECREF(sep);
	return ret;
}

PyObject *repr_pretty_from_str(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"p", "cycle", NULL};
	PyObject *p;
	int cycle;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Op:_repr_pretty_",
					 keywords, &p, &cycle))
		return NULL;

	if (cycle)
		return PyObject_CallMethod(p, "text", "s", "...");

	PyObject *str_obj = PyObject_Str(self);
	if (!str_obj)
		return NULL;
	PyObject *ret = PyObject_CallMethod(p, "text", "O", str_obj);
	Py_DECREF(str_obj);
	return ret;
}

int index_converter(PyObject *o, void *p)
{
	struct index_arg *arg = p;
	PyObject *index_obj;

	arg->is_none = o == Py_None;
	if (arg->allow_none && arg->is_none)
		return 1;

	index_obj = PyNumber_Index(o);
	if (!index_obj)
		return 0;
	if (arg->is_signed) {
		arg->svalue = PyLong_AsLongLong(index_obj);
		Py_DECREF(index_obj);
		return (arg->svalue != -1LL || !PyErr_Occurred());
	} else {
		arg->uvalue = PyLong_AsUnsignedLongLong(index_obj);
		Py_DECREF(index_obj);
		return (arg->uvalue != -1ULL || !PyErr_Occurred());
	}
}

int path_converter(PyObject *o, void *p)
{
	if (o == NULL) {
		path_cleanup(p);
		return 1;
	}

	struct path_arg *path = p;
	if (path->allow_none && o == Py_None) {
		path->path = NULL;
		path->length = 0;
		path->bytes = NULL;
	} else {
		if (!PyUnicode_FSConverter(o, &path->bytes)) {
			path->object = path->bytes = NULL;
			return 0;
		}
		path->path = PyBytes_AS_STRING(path->bytes);
		path->length = PyBytes_GET_SIZE(path->bytes);
	}
	Py_INCREF(o);
	path->object = o;
	return Py_CLEANUP_SUPPORTED;
}

void path_cleanup(struct path_arg *path)
{
	Py_CLEAR(path->bytes);
	Py_CLEAR(path->object);
}

int enum_converter(PyObject *o, void *p)
{
	struct enum_arg *arg = p;

	if (arg->allow_none && o == Py_None)
		return 1;

	if (!PyObject_TypeCheck(o, (PyTypeObject *)arg->type)) {
		PyErr_Format(PyExc_TypeError,
			     "expected %s%s, not %s",
			     ((PyTypeObject *)arg->type)->tp_name,
			     arg->allow_none ? " or None" : "",
			     Py_TYPE(o)->tp_name);
		return 0;
	}

	o = PyObject_GetAttrString(o, "value");
	if (!o)
		return 0;

	arg->value = PyLong_AsUnsignedLong(o);
	Py_DECREF(o);
	if (arg->value == -1 && PyErr_Occurred())
		return 0;
	return 1;
}
