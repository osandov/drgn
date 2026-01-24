// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <inttypes.h>
#include <stdarg.h>

#include "drgnpy.h"
#include "../vector.h"

int append_string(PyObject *parts, const char *s)
{
	_cleanup_pydecref_ PyObject *str = PyUnicode_FromString(s);
	if (!str)
		return -1;
	return PyList_Append(parts, str);
}

int append_u64_hex(PyObject *parts, uint64_t value)
{
	char buf[19];
	snprintf(buf, sizeof(buf), "0x%" PRIx64, value);
	return append_string(parts, buf);
}

static int append_formatv(PyObject *parts, const char *format, va_list ap)
{
	_cleanup_pydecref_ PyObject *str = PyUnicode_FromFormatV(format, ap);
	if (!str)
		return -1;
	return PyList_Append(parts, str);
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

int append_attr_repr(PyObject *parts, PyObject *obj, const char *attr_name)
{
	_cleanup_pydecref_ PyObject *attr =
		PyObject_GetAttrString(obj, attr_name);
	if (!attr)
		return -1;
	_cleanup_pydecref_ PyObject *str = PyObject_Repr(attr);
	if (!str)
		return -1;
	return PyList_Append(parts, str);
}

int append_attr_str(PyObject *parts, PyObject *obj, const char *attr_name)
{
	_cleanup_pydecref_ PyObject *attr =
		PyObject_GetAttrString(obj, attr_name);
	if (!attr)
		return -1;
	_cleanup_pydecref_ PyObject *str = PyObject_Str(attr);
	if (!str)
		return -1;
	return PyList_Append(parts, str);
}

PyObject *join_strings(PyObject *parts)
{
	_cleanup_pydecref_ PyObject *sep = PyUnicode_New(0, 0);
	if (!sep)
		return NULL;
	return PyUnicode_Join(sep, parts);
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

	_cleanup_pydecref_ PyObject *str_obj = PyObject_Str(self);
	if (!str_obj)
		return NULL;
	return PyObject_CallMethod(p, "text", "O", str_obj);
}

int index_converter(PyObject *o, void *p)
{
	struct index_arg *arg = p;

	arg->is_none = o == Py_None;
	if (arg->allow_none && arg->is_none)
		return 1;

	_cleanup_pydecref_ PyObject *index_obj = PyNumber_Index(o);
	if (!index_obj)
		return 0;
	if (arg->is_signed) {
		arg->svalue = PyLong_AsLongLong(index_obj);
		return (arg->svalue != -1LL || !PyErr_Occurred());
	} else {
		arg->uvalue = PyLong_AsUnsignedLongLong(index_obj);
		return (arg->uvalue != -1ULL || !PyErr_Occurred());
	}
}

int u64_converter(PyObject *o, void *p)
{
	return PyLong_AsUInt64(o, p) == 0;
}

int path_converter(PyObject *o, void *p)
{
	if (o == NULL) {
		path_cleanup(p);
		return 1;
	}

	struct path_arg *path = p;
	path->fd = -1;
	path->path = NULL;
	path->length = 0;
	path->bytes = NULL;
	if (path->allow_fd && PyIndex_Check(o)) {
		_cleanup_pydecref_ PyObject *fd_obj = PyNumber_Index(o);
		if (!fd_obj)
			return 0;
		int overflow;
		long fd = PyLong_AsLongAndOverflow(fd_obj, &overflow);
		if (fd == -1 && PyErr_Occurred())
			return 0;
		if (overflow > 0 || fd > INT_MAX) {
			PyErr_SetString(PyExc_OverflowError,
					"fd is greater than maximum");
			return 0;
		}
		if (fd < 0) {
			PyErr_SetString(PyExc_ValueError, "fd is negative");
			return 0;
		}
		path->fd = fd;
	} else if (path->allow_none && o == Py_None) {
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

DEFINE_VECTOR_FUNCTIONS(path_arg_vector);

int path_sequence_converter(PyObject *o, void *p)
{
	if (o == NULL) {
		path_sequence_cleanup(p);
		return 1;
	}

	struct path_sequence_arg *paths = p;

	if (paths->allow_none && o == Py_None)
		return 1;

	_cleanup_pydecref_ PyObject *it = PyObject_GetIter(o);
	if (!it)
		return 0;

	Py_ssize_t length_hint = PyObject_LengthHint(o, 1);
	if (length_hint == -1)
		return 0;
	if (!path_arg_vector_reserve(&paths->args, length_hint)) {
		PyErr_NoMemory();
		return 0;
	}

	for (;;) {
		_cleanup_pydecref_ PyObject *item = PyIter_Next(it);
		if (!item)
			break;

		struct path_arg *path_arg =
			path_arg_vector_append_entry(&paths->args);
		if (!path_arg) {
			PyErr_NoMemory();
			return 0;
		}
		memset(path_arg, 0, sizeof(*path_arg));
		if (!path_converter(item, path_arg)) {
			path_arg_vector_pop(&paths->args);
			return 0;
		}
	}
	if (PyErr_Occurred())
		return 0;

	size_t n = path_arg_vector_size(&paths->args);
	if (paths->null_terminate) {
		if (n == SIZE_MAX) {
			PyErr_NoMemory();
			return 0;
		}
		n++;
	}
	paths->paths = malloc_array(n, sizeof(paths->paths[0]));
	if (!paths->paths) {
		PyErr_NoMemory();
		return 0;
	}

	for (size_t i = 0; i < path_arg_vector_size(&paths->args); i++)
		paths->paths[i] = path_arg_vector_at(&paths->args, i)->path;
	if (paths->null_terminate)
		paths->paths[path_arg_vector_size(&paths->args)] = NULL;

	return Py_CLEANUP_SUPPORTED;
}

void path_sequence_cleanup(struct path_sequence_arg *paths)
{
	free(paths->paths);
	paths->paths = NULL;
	vector_for_each(path_arg_vector, path_arg, &paths->args)
		path_cleanup(path_arg);
	path_arg_vector_deinit(&paths->args);
	path_arg_vector_init(&paths->args);
}

size_t path_sequence_size(struct path_sequence_arg *paths)
{
	return path_arg_vector_size(&paths->args);
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

	_cleanup_pydecref_ PyObject *value = PyObject_GetAttrString(o, "value");
	if (!value)
		return 0;
	arg->value = PyLong_AsUnsignedLong(value);
	if (arg->value == -1 && PyErr_Occurred())
		return 0;
	return 1;
}

#if PY_VERSION_HEX < 0x030e00a2
int PyLong_IsNegative(PyObject *obj)
{
	if (!PyLong_Check(obj)) {
		PyErr_SetString(PyExc_TypeError, "expected int");
		return -1;
	}
	return _PyLong_Sign(obj) < 0;
}
#endif

#if PY_VERSION_HEX < 0x030e00a1
// Note that PyLong_AsLong{,Long}() automatically call __index__(), but
// PyLong_AsUnsignedLong{,Long}() don't.
int PyLong_AsInt64(PyObject *obj, int64_t *value)
{
	long long v = PyLong_AsLongLong(obj);
	if (v == -1 && PyErr_Occurred())
		return -1;
	if (v < INT64_MIN || v > INT64_MAX) {
		PyErr_SetString(PyExc_OverflowError,
				"Python int too large to convert to C int64_t");
		return -1;
	}
	*value = v;
	return 0;
}

int PyLong_AsUInt32(PyObject *obj, uint32_t *value)
{
	_cleanup_pydecref_ PyObject *index = PyNumber_Index(obj);
	if (!index)
		return -1;
	unsigned long v = PyLong_AsUnsignedLong(index);
	if (v == (unsigned long)-1 && PyErr_Occurred())
		return -1;
	if (v > UINT32_MAX) {
		PyErr_SetString(PyExc_OverflowError,
				"Python int too large to convert to C uint32_t");
		return -1;
	}
	*value = v;
	return 0;
}

int PyLong_AsUInt64(PyObject *obj, uint64_t *value)
{
	_cleanup_pydecref_ PyObject *index = PyNumber_Index(obj);
	if (!index)
		return -1;
	unsigned long long v = PyLong_AsUnsignedLongLong(index);
	if (v == (unsigned long long)-1 && PyErr_Occurred())
		return -1;
	if (v > UINT64_MAX) {
		PyErr_SetString(PyExc_OverflowError,
				"Python int too large to convert to C uint64_t");
		return -1;
	}
	*value = v;
	return 0;
}
#endif

int PyLong_AsUInt16(PyObject *obj, uint16_t *value)
{
	_cleanup_pydecref_ PyObject *index = PyNumber_Index(obj);
	if (!index)
		return -1;
	unsigned long v = PyLong_AsUnsignedLong(index);
	if (v == (unsigned long)-1 && PyErr_Occurred())
		return -1;
	if (v > UINT16_MAX) {
		PyErr_SetString(PyExc_OverflowError,
				"Python int too large to convert to C uint16_t");
		return -1;
	}
	*value = v;
	return 0;
}
