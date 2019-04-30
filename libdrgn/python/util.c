// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

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

unsigned long long index_arg(PyObject *obj, const char *msg)
{
	if (PyLong_Check(obj)) {
		return PyLong_AsUnsignedLongLong(obj);
	} else if (PyIndex_Check(obj)) {
		PyObject *index_obj;
		unsigned long long ret;

		index_obj = PyNumber_Index(obj);
		if (!index_obj)
			return -1;
		ret = PyLong_AsUnsignedLongLong(index_obj);
		Py_DECREF(index_obj);
		return ret;
	} else {
		PyErr_SetString(PyExc_TypeError, msg);
		return -1;
	}
}

PyObject *byteorder_string(bool little_endian)
{
	_Py_IDENTIFIER(little);
	_Py_IDENTIFIER(big);
	PyObject *ret;

	ret = _PyUnicode_FromId(little_endian ? &PyId_little : &PyId_big);
	Py_XINCREF(ret);
	return ret;
}

int parse_byteorder(const char *s, bool *ret)
{
	if (strcmp(s, "little") == 0) {
		*ret = true;
		return 0;
	} else if (strcmp(s, "big") == 0) {
		*ret = false;
		return 0;
	} else {
		PyErr_SetString(PyExc_ValueError,
				"byteorder must be either 'little' or 'big'");
		return -1;
	}
}

int parse_optional_byteorder(PyObject *obj, enum drgn_byte_order *ret)
{
	if (obj == Py_None) {
		*ret = DRGN_PROGRAM_ENDIAN;
		return 0;
	}
	if (PyUnicode_Check(obj)) {
		const char *s;

		s = PyUnicode_AsUTF8(obj);
		if (strcmp(s, "little") == 0) {
			*ret = DRGN_LITTLE_ENDIAN;
			return 0;
		} else if (strcmp(s, "big") == 0) {
			*ret = DRGN_BIG_ENDIAN;
			return 0;
		}
	}
	PyErr_SetString(PyExc_ValueError,
			"byteorder must be 'little', 'big', or None");
	return -1;
}
