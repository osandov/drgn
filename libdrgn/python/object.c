// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <inttypes.h>
#include <math.h>

#include "drgnpy.h"
#include "../error.h"
#include "../object.h"
#include "../serialize.h"
#include "../type.h"
#include "../util.h"

static int DrgnObject_literal(struct drgn_object *res, PyObject *literal)
{
	struct drgn_error *err;

	if (PyBool_Check(literal)) {
		err = drgn_object_bool_literal(res, literal == Py_True);
	} else if (PyLong_Check(literal)) {
		unsigned long long uvalue;
		bool is_negative;

		is_negative = Py_SIZE(literal) < 0;
		if (is_negative) {
			literal = PyNumber_Negative(literal);
			if (!literal)
				return -1;
		}
		uvalue = PyLong_AsUnsignedLongLong(literal);
		if (is_negative)
			Py_DECREF(literal);
		if (uvalue == (unsigned long long)-1 && PyErr_Occurred())
			return -1;
		err = drgn_object_integer_literal(res, uvalue);
		if (!err && is_negative)
			err = drgn_object_neg(res, res);
	} else if (PyFloat_Check(literal)) {
		err = drgn_object_float_literal(res,
						PyFloat_AS_DOUBLE(literal));
	} else {
		return 1;
	}
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

static int serialize_py_object(struct drgn_program *prog, char *buf,
			       uint64_t buf_bit_size, uint64_t bit_offset,
			       PyObject *value_obj,
			       const struct drgn_object_type *type);

static int serialize_compound_value(struct drgn_program *prog, char *buf,
				    uint64_t buf_bit_size, uint64_t bit_offset,
				    PyObject *value_obj,
				    const struct drgn_object_type *type)
{
	struct drgn_error *err;
	int ret = -1;

	if (!PyMapping_Check(value_obj)) {
		set_error_type_name("'%s' value must be dictionary or mapping",
				    drgn_object_type_qualified(type));
		return -1;
	}

	PyObject *tmp = PyMapping_Items(value_obj);
	if (!tmp)
		return -1;

	/*
	 * Since Python 3.7, PyMapping_Items() always returns a list. However,
	 * before that, it could also return a tuple.
	 */
	PyObject *items = PySequence_Fast(tmp, "items must be sequence");
	Py_DECREF(tmp);
	if (!items)
		return -1;

	Py_ssize_t num_items = PySequence_Fast_GET_SIZE(items);
	for (Py_ssize_t i = 0; i < num_items; i++) {
		PyObject *item = PySequence_Fast_GET_ITEM(items, i);
		if (!PyTuple_Check(item) || PyTuple_GET_SIZE(item) != 2) {
			PyErr_SetString(PyExc_TypeError, "invalid item");
			goto out;
		}
		PyObject *key = PyTuple_GET_ITEM(item, 0);
		if (!PyUnicode_Check(key)) {
			PyErr_SetString(PyExc_TypeError,
					"member key must be string");
			goto out;
		}
		const char *member_name = PyUnicode_AsUTF8(key);
		if (!member_name)
			goto out;

		struct drgn_type_member *member;
		uint64_t member_bit_offset;
		err = drgn_type_find_member(type->underlying_type, member_name,
					    &member, &member_bit_offset);
		if (err) {
			set_drgn_error(err);
			goto out;
		}
		struct drgn_qualified_type member_qualified_type;
		uint64_t member_bit_field_size;
		err = drgn_member_type(member, &member_qualified_type,
				       &member_bit_field_size);
		if (err) {
			set_drgn_error(err);
			goto out;
		}

		struct drgn_object_type member_type;
		err = drgn_object_type(member_qualified_type,
				       member_bit_field_size, &member_type);
		if (err)
			goto out;
		if (serialize_py_object(prog, buf, buf_bit_size,
					bit_offset + member_bit_offset,
					PyTuple_GET_ITEM(item, 1),
					&member_type) == -1)
			goto out;
	}

	ret = 0;
out:
	Py_DECREF(items);
	return ret;
}

static int serialize_array_value(struct drgn_program *prog, char *buf,
				 uint64_t buf_bit_size, uint64_t bit_offset,
				 PyObject *value_obj,
				 const struct drgn_object_type *type)
{
	struct drgn_error *err;

	struct drgn_object_type element_type;
	err = drgn_object_type(drgn_type_type(type->underlying_type), 0,
			       &element_type);
	if (err) {
		set_drgn_error(err);
		return -1;
	}

	uint64_t length = drgn_type_length(type->underlying_type);
	if (length > PY_SSIZE_T_MAX) {
		PyErr_NoMemory();
		return -1;
	}

	PyObject *seq = PySequence_Fast(value_obj, "");
	if (!seq) {
		if (PyErr_ExceptionMatches(PyExc_TypeError)) {
			set_error_type_name("'%s' value must be iterable",
					    drgn_object_type_qualified(type));
		}
		return -1;
	}
	size_t seq_length = PySequence_Fast_GET_SIZE(seq);
	if (seq_length > length) {
		Py_DECREF(seq);
		PyErr_SetString(PyExc_ValueError,
				"too many items in array value");
		return -1;
	}

	for (size_t i = 0; i < seq_length; i++) {
		if (serialize_py_object(prog, buf, buf_bit_size,
					bit_offset + i * element_type.bit_size,
					PySequence_Fast_GET_ITEM(seq, i),
					&element_type) == -1) {
			Py_DECREF(seq);
			return -1;
		}
	}

	Py_DECREF(seq);
	return 0;
}

static int serialize_py_object(struct drgn_program *prog, char *buf,
			       uint64_t buf_bit_size, uint64_t bit_offset,
			       PyObject *value_obj,
			       const struct drgn_object_type *type)
{
	struct drgn_error *err;

	uint64_t bit_end;
	if (__builtin_add_overflow(bit_offset, type->bit_size, &bit_end) ||
	    bit_end > buf_bit_size) {
		err = drgn_error_create(DRGN_ERROR_OUT_OF_BOUNDS,
					"out of bounds of value");
		set_drgn_error(err);
		return -1;
	}

	switch (type->encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		if (!PyNumber_Check(value_obj)) {
			set_error_type_name("'%s' value must be number",
					    drgn_object_type_qualified(type));
			return -1;
		}
		PyObject *long_obj = PyNumber_Long(value_obj);
		if (!long_obj)
			return -1;
		union {
			int64_t svalue;
			uint64_t uvalue;
		} tmp;
		tmp.uvalue = PyLong_AsUnsignedLongLongMask(long_obj);
		Py_DECREF(long_obj);
		if (tmp.uvalue == (unsigned long long)-1 && PyErr_Occurred())
			return -1;
		if (type->encoding == DRGN_OBJECT_ENCODING_SIGNED) {
			tmp.svalue = truncate_signed(tmp.svalue,
						     type->bit_size);
		} else {
			tmp.uvalue = truncate_unsigned(tmp.uvalue,
						       type->bit_size);
		}
		serialize_bits(buf, bit_offset, tmp.uvalue, type->bit_size,
			       type->little_endian);
		return 0;
	}
	case DRGN_OBJECT_ENCODING_FLOAT: {
		if (!PyNumber_Check(value_obj)) {
			set_error_type_name("'%s' value must be number",
					    drgn_object_type_qualified(type));
			return -1;
		}
		double fvalue = PyFloat_AsDouble(value_obj);
		if (fvalue == -1.0 && PyErr_Occurred())
			return -1;
		union {
			uint64_t uvalue;
			double fvalue64;
			float fvalue32;
		} tmp;
		if (type->bit_size == 64)
			tmp.fvalue64 = fvalue;
		else
			tmp.fvalue32 = fvalue;
		serialize_bits(buf, bit_offset, tmp.uvalue, type->bit_size,
			       type->little_endian);
		return 0;
	}
	case DRGN_OBJECT_ENCODING_BUFFER:
		switch (drgn_type_kind(type->underlying_type)) {
		case DRGN_TYPE_STRUCT:
		case DRGN_TYPE_UNION:
		case DRGN_TYPE_CLASS:
			return serialize_compound_value(prog, buf, buf_bit_size,
							bit_offset, value_obj,
							type);
		case DRGN_TYPE_ARRAY:
			return serialize_array_value(prog, buf, buf_bit_size,
						     bit_offset, value_obj,
						     type);
		default:
			break;
		}
		break;
	default:
		break;
	}
	UNREACHABLE();
}

static int buffer_object_from_value(struct drgn_object *res,
				    struct drgn_qualified_type qualified_type,
				    PyObject *value_obj)
{
	struct drgn_error *err;

	struct drgn_object_type type;
	err = drgn_object_type(qualified_type, 0, &type);
	if (err) {
		set_drgn_error(err);
		return -1;
	}

	uint64_t size = drgn_value_size(type.bit_size);
	if (size > SIZE_MAX) {
		PyErr_NoMemory();
		return -1;
	}
	union drgn_value value;
	char *buf;
	if (size <= sizeof(value.ibuf)) {
		buf = value.ibuf;
	} else {
		buf = malloc64(size);
		if (!buf) {
			PyErr_NoMemory();
			return -1;
		}
		value.bufp = buf;
	}
	memset(buf, 0, size);

	if (serialize_py_object(drgn_object_program(res), buf, type.bit_size, 0,
				value_obj, &type) == -1) {
		if (buf != value.ibuf)
			free(buf);
		return -1;
	}

	drgn_object_reinit(res, &type, DRGN_OBJECT_VALUE);
	res->value = value;
	return 0;
}

static DrgnObject *DrgnObject_new(PyTypeObject *subtype, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {
		"prog", "type", "value", "address", "bit_offset",
		"bit_field_size", NULL,
	};
	struct drgn_error *err;
	Program *prog;
	PyObject *type_obj = Py_None, *value_obj = Py_None;
	struct index_arg address = { .allow_none = true, .is_none = true };
	struct index_arg bit_offset = { .allow_none = true, .is_none = true };
	struct index_arg bit_field_size = { .allow_none = true, .is_none = true };
	struct drgn_qualified_type qualified_type;
	DrgnObject *obj;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|OO$O&O&O&:Object",
					 keywords, &Program_type, &prog,
					 &type_obj, &value_obj, index_converter,
					 &address, index_converter, &bit_offset,
					 index_converter, &bit_field_size))
		return NULL;

	if (Program_type_arg(prog, type_obj, true, &qualified_type) == -1)
		return NULL;

	if (!bit_field_size.is_none && bit_field_size.uvalue == 0) {
		PyErr_SetString(PyExc_ValueError,
				"bit field size cannot be zero");
		return NULL;
	}

	obj = DrgnObject_alloc(prog);
	if (!obj)
		return NULL;
	if (!address.is_none && value_obj != Py_None) {
		PyErr_SetString(PyExc_ValueError,
				"object cannot have address and value");
		goto err;
	} else if (!address.is_none) {
		if (!qualified_type.type) {
			PyErr_SetString(PyExc_ValueError,
					"reference must have type");
			goto err;
		}

		err = drgn_object_set_reference(&obj->obj, qualified_type,
						address.uvalue,
						bit_offset.uvalue,
						bit_field_size.uvalue);
	} else if (value_obj != Py_None && !qualified_type.type) {
		int ret;

		if (!bit_offset.is_none) {
			PyErr_SetString(PyExc_ValueError,
					"literal cannot have bit offset");
			goto err;
		}
		if (!bit_field_size.is_none) {
			PyErr_SetString(PyExc_ValueError,
					"literal cannot be bit field");
			goto err;
		}

		ret = DrgnObject_literal(&obj->obj, value_obj);
		if (ret == -1) {
			goto err;
		} else if (ret) {
			PyErr_Format(PyExc_TypeError,
				     "cannot create %s literal",
				     Py_TYPE(value_obj)->tp_name);
			goto err;
		}
		err = NULL;
	} else if (value_obj != Py_None) {
		if (!bit_offset.is_none) {
			PyErr_SetString(PyExc_ValueError,
					"value cannot have bit offset");
			goto err;
		}

		enum drgn_object_encoding encoding =
			drgn_type_object_encoding(qualified_type.type);
		if (!drgn_object_encoding_is_complete(encoding)) {
			err = drgn_error_incomplete_type("cannot create value with %s type",
							 qualified_type.type);
			set_drgn_error(err);
			goto err;

		}
		if (!bit_field_size.is_none &&
		    encoding != DRGN_OBJECT_ENCODING_SIGNED &&
		    encoding != DRGN_OBJECT_ENCODING_UNSIGNED) {
			PyErr_SetString(PyExc_ValueError,
					"bit field must be integer");
			goto err;
		}

		switch (encoding) {
		case DRGN_OBJECT_ENCODING_BUFFER:
			if (buffer_object_from_value(&obj->obj, qualified_type,
						     value_obj) == -1)
				goto err;
			err = NULL;
			break;
		case DRGN_OBJECT_ENCODING_SIGNED:
		case DRGN_OBJECT_ENCODING_UNSIGNED: {
			PyObject *long_obj;
			union {
				int64_t svalue;
				uint64_t uvalue;
			} tmp;

			if (!PyNumber_Check(value_obj)) {
				set_error_type_name("'%s' value must be number",
						    qualified_type);
				goto err;
			}
			long_obj = PyNumber_Long(value_obj);
			if (!long_obj)
				goto err;
			tmp.uvalue = PyLong_AsUnsignedLongLongMask(long_obj);
			Py_DECREF(long_obj);
			if (tmp.uvalue == (unsigned long long)-1 &&
			    PyErr_Occurred())
				goto err;
			if (encoding == DRGN_OBJECT_ENCODING_SIGNED) {
				err = drgn_object_set_signed(&obj->obj,
							     qualified_type,
							     tmp.svalue,
							     bit_field_size.uvalue);
			} else {
				err = drgn_object_set_unsigned(&obj->obj,
							       qualified_type,
							       tmp.uvalue,
							       bit_field_size.uvalue);
			}
			break;
		}
		case DRGN_OBJECT_ENCODING_FLOAT: {
			double fvalue;

			if (!PyNumber_Check(value_obj)) {
				set_error_type_name("'%s' value must be number",
						    qualified_type);
				goto err;
			}
			fvalue = PyFloat_AsDouble(value_obj);
			if (fvalue == -1.0 && PyErr_Occurred())
				goto err;
			err = drgn_object_set_float(&obj->obj, qualified_type,
						    fvalue);
			break;
		}
		default:
			UNREACHABLE();
		}
	} else {
		if (!qualified_type.type) {
			PyErr_SetString(PyExc_ValueError,
					"absent object must have type");
			goto err;
		}
		if (!bit_offset.is_none) {
			PyErr_SetString(PyExc_ValueError,
					"absent object cannot have bit offset");
			goto err;
		}
		err = drgn_object_set_absent(&obj->obj, qualified_type,
					     bit_field_size.uvalue);
	}
	if (err) {
		set_drgn_error(err);
		goto err;
	}
	return obj;

err:
	Py_DECREF(obj);
	return NULL;
}

static void DrgnObject_dealloc(DrgnObject *self)
{
	Py_DECREF(DrgnObject_prog(self));
	drgn_object_deinit(&self->obj);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *DrgnObject_value_impl(struct drgn_object *obj);

static PyObject *DrgnObject_compound_value(struct drgn_object *obj,
					   struct drgn_type *underlying_type)
{
	struct drgn_error *err;
	PyObject *dict;
	struct drgn_object member;
	struct drgn_type_member *members;
	size_t num_members, i;

	if (!drgn_type_is_complete(underlying_type)) {
		PyErr_Format(PyExc_TypeError,
			     "cannot get value of incomplete %s",
			     drgn_type_kind_spelling[drgn_type_kind(underlying_type)]);
		return NULL;
	}

	dict = PyDict_New();
	if (!dict)
		return NULL;

	drgn_object_init(&member, drgn_object_program(obj));
	members = drgn_type_members(underlying_type);
	num_members = drgn_type_num_members(underlying_type);
	for (i = 0; i < num_members; i++) {
		struct drgn_qualified_type member_type;
		uint64_t member_bit_field_size;
		err = drgn_member_type(&members[i], &member_type,
				       &member_bit_field_size);
		if (err) {
			set_drgn_error(err);
			Py_CLEAR(dict);
			goto out;
		}

		err = drgn_object_slice(&member, obj, member_type,
					members[i].bit_offset,
					member_bit_field_size);
		if (err) {
			set_drgn_error(err);
			Py_CLEAR(dict);
			goto out;
		}

		PyObject *member_value = DrgnObject_value_impl(&member);
		if (!member_value) {
			Py_CLEAR(dict);
			goto out;
		}

		int ret;
		if (members[i].name) {
			ret = PyDict_SetItemString(dict, members[i].name,
						   member_value);
		} else {
			ret = PyDict_Update(dict, member_value);
		}
		Py_DECREF(member_value);
		if (ret) {
			Py_CLEAR(dict);
			goto out;
		}
	}

out:
	drgn_object_deinit(&member);
	return dict;
}

static PyObject *DrgnObject_array_value(struct drgn_object *obj,
					struct drgn_type *underlying_type)
{
	struct drgn_error *err;
	struct drgn_qualified_type element_type;
	uint64_t element_bit_size, length, i;
	PyObject *list;
	struct drgn_object element;

	element_type = drgn_type_type(underlying_type);
	err = drgn_type_bit_size(element_type.type, &element_bit_size);
	if (err)
		return set_drgn_error(err);

	length = drgn_type_length(underlying_type);
	if (length > PY_SSIZE_T_MAX) {
		PyErr_NoMemory();
		return NULL;
	}

	list = PyList_New(length);
	if (!list)
		return NULL;

	drgn_object_init(&element, drgn_object_program(obj));
	for (i = 0; i < length; i++) {
		PyObject *element_value;

		err = drgn_object_slice(&element, obj, element_type,
					i * element_bit_size, 0);
		if (err) {
			set_drgn_error(err);
			Py_CLEAR(list);
			goto out;
		}

		element_value = DrgnObject_value_impl(&element);
		if (!element_value) {
			Py_CLEAR(list);
			goto out;
		}

		PyList_SET_ITEM(list, i, element_value);
	}

out:
	drgn_object_deinit(&element);
	return list;
}

static PyObject *DrgnObject_value_impl(struct drgn_object *obj)
{
	struct drgn_error *err;
	struct drgn_type *underlying_type;

	if (!drgn_object_encoding_is_complete(obj->encoding)) {
		err = drgn_error_incomplete_type("cannot read object with %s type",
						 obj->type);
		return set_drgn_error(err);
	}

	underlying_type = drgn_underlying_type(obj->type);
	switch (obj->encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED: {
		int64_t svalue;

		err = drgn_object_read_signed(obj, &svalue);
		if (err)
			return set_drgn_error(err);
		return PyLong_FromLongLong(svalue);
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t uvalue;

		err = drgn_object_read_unsigned(obj, &uvalue);
		if (err)
			return set_drgn_error(err);
		if (drgn_type_kind(underlying_type) == DRGN_TYPE_BOOL)
			Py_RETURN_BOOL(uvalue);
		else
			return PyLong_FromUnsignedLongLong(uvalue);
	}
	case DRGN_OBJECT_ENCODING_FLOAT: {
		double fvalue;

		err = drgn_object_read_float(obj, &fvalue);
		if (err)
			return set_drgn_error(err);
		return PyFloat_FromDouble(fvalue);
	}
	case DRGN_OBJECT_ENCODING_BUFFER:
		switch (drgn_type_kind(underlying_type)) {
		case DRGN_TYPE_STRUCT:
		case DRGN_TYPE_UNION:
		case DRGN_TYPE_CLASS:
			return DrgnObject_compound_value(obj, underlying_type);
		case DRGN_TYPE_ARRAY:
			return DrgnObject_array_value(obj, underlying_type);
		default:
			break;
		}
		break;
	default:
		break;
	}
	UNREACHABLE();
}

static PyObject *DrgnObject_value(DrgnObject *self)
{
	return DrgnObject_value_impl(&self->obj);
}

static PyObject *DrgnObject_string(DrgnObject *self)
{
	struct drgn_error *err;
	char *str;
	PyObject *ret;

	err = drgn_object_read_c_string(&self->obj, &str);
	if (err)
		return set_drgn_error(err);

	ret = PyBytes_FromString(str);
	free(str);
	return ret;
}

static DrgnObject *DrgnObject_address_of(DrgnObject *self)
{
	struct drgn_error *err;
	DrgnObject *res;

	res = DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		return NULL;

	err = drgn_object_address_of(&res->obj, &self->obj);
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

static DrgnObject *DrgnObject_read(DrgnObject *self)
{
	struct drgn_error *err;
	DrgnObject *res;

	SWITCH_ENUM(self->obj.kind,
	case DRGN_OBJECT_VALUE:
		Py_INCREF(self);
		return self;
	case DRGN_OBJECT_REFERENCE:
		res = DrgnObject_alloc(DrgnObject_prog(self));
		if (!res)
			return NULL;

		err = drgn_object_read(&res->obj, &self->obj);
		if (err) {
			Py_DECREF(res);
			return set_drgn_error(err);
		}
		return res;
	case DRGN_OBJECT_ABSENT:
		return set_drgn_error(&drgn_error_object_absent);
	)
}

static PyObject *DrgnObject_to_bytes(DrgnObject *self)
{
	struct drgn_error *err;
	PyObject *buf = PyBytes_FromStringAndSize(NULL,
						  drgn_object_size(&self->obj));
	if (!buf)
		return NULL;
	err = drgn_object_read_bytes(&self->obj, PyBytes_AS_STRING(buf));
	if (err) {
		Py_DECREF(buf);
		return set_drgn_error(err);
	}
	return buf;
}

static DrgnObject *DrgnObject_from_bytes(PyTypeObject *type, PyObject *args,
					 PyObject *kwds)
{
	static char *keywords[] = {
		"prog", "type", "bytes", "bit_offset", "bit_field_size", NULL
	};
	struct drgn_error *err;
	Program *prog;
	PyObject *type_obj = Py_None;
	Py_buffer bytes;
	struct index_arg bit_offset = {};
	struct index_arg bit_field_size = { .allow_none = true, .is_none = true };
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!Oy*|O&O&:from_bytes_",
					 keywords, &Program_type, &prog,
					 &type_obj, &bytes, index_converter,
					 &bit_offset, index_converter,
					 &bit_field_size))
		return NULL;

	DrgnObject *res = NULL;
	struct drgn_qualified_type qualified_type;
	if (Program_type_arg(prog, type_obj, false, &qualified_type) == -1)
		goto out;

	if (!bit_field_size.is_none && bit_field_size.uvalue == 0) {
		PyErr_SetString(PyExc_ValueError,
				"bit field size cannot be zero");
		goto out;
	}

	res = DrgnObject_alloc(prog);
	if (!res)
		goto out;

	err = drgn_object_set_from_buffer(&res->obj, qualified_type, bytes.buf,
					  bytes.len, bit_offset.uvalue,
					  bit_field_size.uvalue);
	if (err) {
		set_drgn_error(err);
		Py_DECREF(res);
		res = NULL;
		goto out;
	}

out:
	PyBuffer_Release(&bytes);
	return res;
}

static int append_bit_offset(PyObject *parts, uint8_t bit_offset)
{
	if (bit_offset == 0)
		return 0;
	return append_format(parts, ", bit_offset=%d", bit_offset);
}

static PyObject *DrgnObject_repr(DrgnObject *self)
{
	struct drgn_error *err;
	PyObject *parts, *tmp, *ret = NULL;
	char *type_name;

	parts = PyList_New(0);
	if (!parts)
		return NULL;

	err = drgn_format_type_name(drgn_object_qualified_type(&self->obj),
				    &type_name);
	if (err) {
		set_drgn_error(err);
		goto out;
	}
	tmp = PyUnicode_FromString(type_name);
	free(type_name);
	if (!tmp)
		goto out;

	if (append_format(parts, "Object(prog, %R", tmp) == -1) {
		Py_DECREF(tmp);
		goto out;
	}
	Py_DECREF(tmp);

	SWITCH_ENUM(self->obj.kind,
	case DRGN_OBJECT_VALUE: {
		if (append_string(parts, ", value=") == -1)
			goto out;
		PyObject *value_obj = DrgnObject_value(self);
		if (!value_obj)
			goto out;
		if (drgn_type_kind(drgn_underlying_type(self->obj.type)) ==
		    DRGN_TYPE_POINTER)
			tmp = PyNumber_ToBase(value_obj, 16);
		else
			tmp = PyObject_Repr(value_obj);
		Py_DECREF(value_obj);
		if (!tmp)
			goto out;
		if (PyList_Append(parts, tmp) == -1) {
			Py_DECREF(tmp);
			goto out;
		}
		Py_DECREF(tmp);
		break;
	}
	case DRGN_OBJECT_REFERENCE: {
		char buf[17];
		snprintf(buf, sizeof(buf), "%" PRIx64, self->obj.address);
		if (append_format(parts, ", address=0x%s", buf) == -1 ||
		    append_bit_offset(parts, self->obj.bit_offset) == -1)
			goto out;
		break;
	}
	case DRGN_OBJECT_ABSENT:
		break;
	)

	if (self->obj.is_bit_field &&
	    append_format(parts, ", bit_field_size=%llu",
			  (unsigned long long)self->obj.bit_size) == -1)
		goto out;

	if (append_string(parts, ")") == -1)
		goto out;

	ret = join_strings(parts);
out:
	Py_DECREF(parts);
	return ret;
}

static PyObject *DrgnObject_str(DrgnObject *self)
{
	struct drgn_error *err;
	char *str;
	PyObject *ret;

	err = drgn_format_object(&self->obj, SIZE_MAX,
				 DRGN_FORMAT_OBJECT_PRETTY, &str);
	if (err)
		return set_drgn_error(err);

	ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

struct format_object_flag_arg {
	enum drgn_format_object_flags *flags;
	enum drgn_format_object_flags value;
};

static int format_object_flag_converter(PyObject *o, void *p)
{
	struct format_object_flag_arg *arg = p;
	int ret;

	if (o == Py_None)
		return 1;
	ret = PyObject_IsTrue(o);
	if (ret == -1)
		return 0;
	if (ret)
		*arg->flags |= arg->value;
	else
		*arg->flags &= ~arg->value;
	return 1;
}

static PyObject *DrgnObject_format(DrgnObject *self, PyObject *args,
				   PyObject *kwds)
{
#define FLAGS								\
	X(dereference, DRGN_FORMAT_OBJECT_DEREFERENCE)			\
	X(symbolize, DRGN_FORMAT_OBJECT_SYMBOLIZE)			\
	X(string, DRGN_FORMAT_OBJECT_STRING)				\
	X(char, DRGN_FORMAT_OBJECT_CHAR)				\
	X(type_name, DRGN_FORMAT_OBJECT_TYPE_NAME)			\
	X(member_type_names, DRGN_FORMAT_OBJECT_MEMBER_TYPE_NAMES)	\
	X(element_type_names, DRGN_FORMAT_OBJECT_ELEMENT_TYPE_NAMES)	\
	X(members_same_line, DRGN_FORMAT_OBJECT_MEMBERS_SAME_LINE)	\
	X(elements_same_line, DRGN_FORMAT_OBJECT_ELEMENTS_SAME_LINE)	\
	X(member_names, DRGN_FORMAT_OBJECT_MEMBER_NAMES)		\
	X(element_indices, DRGN_FORMAT_OBJECT_ELEMENT_INDICES)		\
	X(implicit_members, DRGN_FORMAT_OBJECT_IMPLICIT_MEMBERS)	\
	X(implicit_elements, DRGN_FORMAT_OBJECT_IMPLICIT_ELEMENTS)

	static char *keywords[] = {
#define X(name, value) #name,
		FLAGS
#undef X
		"columns",
		NULL,
	};
	struct drgn_error *err;
	PyObject *columns_obj = Py_None;
	size_t columns = SIZE_MAX;
	enum drgn_format_object_flags flags = DRGN_FORMAT_OBJECT_PRETTY;
#define X(name, value)	\
	struct format_object_flag_arg name##_arg = { &flags, value };
	FLAGS
#undef X
	char *str;
	PyObject *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$"
#define X(name, value) "O&"
					 FLAGS
#undef X
					 "O:format_", keywords,
#define X(name, value) format_object_flag_converter, &name##_arg,
					 FLAGS
#undef X
					 &columns_obj))
		return NULL;

	if (columns_obj != Py_None) {
		columns_obj = PyNumber_Index(columns_obj);
		if (!columns_obj)
			return NULL;
		columns = PyLong_AsSize_t(columns_obj);
		Py_DECREF(columns_obj);
		if (columns == (size_t)-1 && PyErr_Occurred())
			return NULL;
	}

	err = drgn_format_object(&self->obj, columns, flags, &str);
	if (err)
		return set_drgn_error(err);

	ret = PyUnicode_FromString(str);
	free(str);
	return ret;

#undef FLAGS
}

static Program *DrgnObject_get_prog(DrgnObject *self, void *arg)
{
	Py_INCREF(DrgnObject_prog(self));
	return DrgnObject_prog(self);
}

static PyObject *DrgnObject_get_type(DrgnObject *self, void *arg)
{
	return DrgnType_wrap(drgn_object_qualified_type(&self->obj));
}

static PyObject *DrgnObject_get_absent(DrgnObject *self, void *arg)
{
	Py_RETURN_BOOL(self->obj.kind == DRGN_OBJECT_ABSENT);
}

static PyObject *DrgnObject_get_address(DrgnObject *self, void *arg)
{
	if (self->obj.kind == DRGN_OBJECT_REFERENCE)
		return PyLong_FromUnsignedLongLong(self->obj.address);
	else
		Py_RETURN_NONE;
}

static PyObject *DrgnObject_get_bit_offset(DrgnObject *self, void *arg)
{
	SWITCH_ENUM(self->obj.kind,
	case DRGN_OBJECT_REFERENCE:
		return PyLong_FromLong(self->obj.bit_offset);
	case DRGN_OBJECT_VALUE:
	case DRGN_OBJECT_ABSENT:
		Py_RETURN_NONE;
	)
}

static PyObject *DrgnObject_get_bit_field_size(DrgnObject *self, void *arg)
{
	if (self->obj.is_bit_field)
		return PyLong_FromUnsignedLongLong(self->obj.bit_size);
	else
		Py_RETURN_NONE;
}

static int DrgnObject_binary_operand(PyObject *self, PyObject *other,
				     struct drgn_object **obj,
				     struct drgn_object *tmp)
{
	if (PyObject_TypeCheck(self, &DrgnObject_type)) {
		*obj = &((DrgnObject *)self)->obj;
		return 0;
	} else {
		*obj = tmp;
		/* If self isn't a DrgnObject, then other must be. */
		drgn_object_init(tmp,
				 drgn_object_program(&((DrgnObject *)other)->obj));
		return DrgnObject_literal(tmp, self);
	}
}

#define DrgnObject_BINARY_OP(op)						\
static PyObject *DrgnObject_##op(PyObject *left, PyObject *right)		\
{										\
	struct drgn_error *err;							\
	struct drgn_object *lhs, lhs_tmp, *rhs, rhs_tmp;			\
	DrgnObject *res = NULL;							\
	int ret;								\
										\
	ret = DrgnObject_binary_operand(left, right, &lhs, &lhs_tmp);		\
	if (ret)								\
		goto out;							\
	ret = DrgnObject_binary_operand(right, left, &rhs, &rhs_tmp);		\
	if (ret)								\
		goto out_lhs;							\
										\
	res = DrgnObject_alloc(container_of(drgn_object_program(lhs), Program,	\
					    prog));				\
	if (!res) {								\
		ret = -1;							\
		goto out_rhs;							\
	}									\
										\
	err = drgn_object_##op(&res->obj, lhs, rhs);				\
	if (err) {								\
		set_drgn_error(err);						\
		Py_DECREF(res);							\
		ret = -1;							\
		goto out_rhs;							\
	}									\
										\
out_rhs:									\
	if (rhs == &rhs_tmp)							\
		drgn_object_deinit(&rhs_tmp);					\
out_lhs:									\
	if (lhs == &lhs_tmp)							\
		drgn_object_deinit(&lhs_tmp);					\
out:										\
	if (ret == -1)								\
		return NULL;							\
	else if (ret)								\
		Py_RETURN_NOTIMPLEMENTED;					\
	else									\
		return (PyObject *)res;						\
}
DrgnObject_BINARY_OP(add)
DrgnObject_BINARY_OP(sub)
DrgnObject_BINARY_OP(mul)
DrgnObject_BINARY_OP(div)
DrgnObject_BINARY_OP(mod)
DrgnObject_BINARY_OP(lshift)
DrgnObject_BINARY_OP(rshift)
DrgnObject_BINARY_OP(and)
DrgnObject_BINARY_OP(or)
DrgnObject_BINARY_OP(xor)
#undef DrgnObject_BINARY_OP

#define DrgnObject_UNARY_OP(op)				\
static DrgnObject *DrgnObject_##op(DrgnObject *self)	\
{							\
	struct drgn_error *err;				\
	DrgnObject *res;				\
							\
	res = DrgnObject_alloc(DrgnObject_prog(self));	\
	if (!res)					\
		return NULL;				\
							\
	err = drgn_object_##op(&res->obj, &self->obj);	\
	if (err) {					\
		Py_DECREF(res);				\
		return set_drgn_error(err);		\
	}						\
	return res;					\
}
DrgnObject_UNARY_OP(pos)
DrgnObject_UNARY_OP(neg)
DrgnObject_UNARY_OP(not)
#undef DrgnObject_UNARY_OP

static int DrgnObject_bool(DrgnObject *self)
{
	struct drgn_error *err;
	bool ret;

	err = drgn_object_bool(&self->obj, &ret);
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return ret;
}

static PyObject *DrgnObject_int(DrgnObject *self)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;
	PyObject *ret;

	if (!drgn_type_is_scalar(self->obj.type)) {
		return set_error_type_name("cannot convert '%s' to int",
					   drgn_object_qualified_type(&self->obj));
	}

	err = drgn_object_read_value(&self->obj, &value_mem, &value);
	if (err)
		return set_drgn_error(err);

	switch (self->obj.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
		ret = PyLong_FromLongLong(value->svalue);
		break;
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		ret = PyLong_FromUnsignedLongLong(value->uvalue);
		break;
	case DRGN_OBJECT_ENCODING_FLOAT:
		ret = PyLong_FromDouble(value->fvalue);
		break;
	default:
		UNREACHABLE();
	}
	drgn_object_deinit_value(&self->obj, value);
	return ret;
}

static PyObject *DrgnObject_float(DrgnObject *self)
{
	struct drgn_error *err;
	union drgn_value value_mem;
	const union drgn_value *value;
	PyObject *ret;

	if (!drgn_type_is_arithmetic(self->obj.type)) {
		return set_error_type_name("cannot convert '%s' to float",
					   drgn_object_qualified_type(&self->obj));
	}

	err = drgn_object_read_value(&self->obj, &value_mem, &value);
	if (err)
		return set_drgn_error(err);

	switch (self->obj.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
		ret = PyFloat_FromDouble(value->svalue);
		break;
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		ret = PyFloat_FromDouble(value->uvalue);
		break;
	case DRGN_OBJECT_ENCODING_FLOAT:
		ret = PyFloat_FromDouble(value->fvalue);
		break;
	default:
		UNREACHABLE();
	}
	drgn_object_deinit_value(&self->obj, value);
	return ret;
}

static PyObject *DrgnObject_index(DrgnObject *self)
{
	struct drgn_error *err;
	struct drgn_type *underlying_type;
	union drgn_value value_mem;
	const union drgn_value *value;
	PyObject *ret;

	underlying_type = drgn_underlying_type(self->obj.type);
	if (!drgn_type_is_integer(underlying_type) &&
	    drgn_type_kind(underlying_type) != DRGN_TYPE_POINTER) {
		return set_error_type_name("'%s' object cannot be interpreted as an integer",
					   drgn_object_qualified_type(&self->obj));
	}

	err = drgn_object_read_value(&self->obj, &value_mem, &value);
	if (err)
		return set_drgn_error(err);

	switch (self->obj.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
		ret = PyLong_FromLongLong(value->svalue);
		break;
	case DRGN_OBJECT_ENCODING_UNSIGNED:
		ret = PyLong_FromUnsignedLongLong(value->uvalue);
		break;
	default:
		UNREACHABLE();
	}
	drgn_object_deinit_value(&self->obj, value);
	return ret;
}

static PyObject *DrgnObject_round(DrgnObject *self, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {"ndigits", NULL};
	PyObject *ndigits = Py_None, *value, *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O:round", keywords,
					 &ndigits))
		return NULL;

	if (!drgn_type_is_arithmetic(self->obj.type)) {
		return set_error_type_name("cannot round '%s'",
					   drgn_object_qualified_type(&self->obj));
	}

	value = DrgnObject_value(self);
	if (!value)
		return NULL;

	if (ndigits == Py_None) {
		ret = PyObject_CallMethod(value, "__round__", NULL);
		Py_DECREF(value);
	} else {
		PyObject *args, *kwds, *tmp, *type;

		tmp = PyObject_CallMethod(value, "__round__", "O", ndigits);
		Py_DECREF(value);
		if (!tmp)
			return NULL;
		value = tmp;

		kwds = PyDict_New();
		if (!kwds) {
			Py_DECREF(value);
			return NULL;
		}

		if (PyDict_SetItemString(kwds, "value", value) == -1) {
			Py_DECREF(value);
			return NULL;
		}
		Py_DECREF(value);

		type = DrgnObject_get_type(self, NULL);
		if (!type) {
			Py_DECREF(kwds);
			return NULL;
		}
		args = Py_BuildValue("OO", DrgnObject_prog(self), type);
		Py_DECREF(type);
		if (!args) {
			Py_DECREF(kwds);
			return NULL;
		}

		ret = PyObject_Call((PyObject *)&DrgnObject_type, args, kwds);
		Py_DECREF(args);
		Py_DECREF(kwds);
	}
	return ret;
}

#define DrgnObject_round_method(func)					\
static PyObject *DrgnObject_##func(DrgnObject *self)			\
{									\
	struct drgn_error *err;						\
	union drgn_value value_mem;					\
	const union drgn_value *value;					\
	PyObject *ret;							\
									\
	if (!drgn_type_is_arithmetic(self->obj.type)) {			\
		return set_error_type_name("cannot round '%s'",		\
					   drgn_object_qualified_type(&self->obj));\
	}								\
									\
	err = drgn_object_read_value(&self->obj, &value_mem, &value);	\
	if (err)							\
		return set_drgn_error(err);				\
									\
	switch (self->obj.encoding) {					\
	case DRGN_OBJECT_ENCODING_SIGNED:				\
		ret = PyLong_FromLongLong(value->svalue);		\
		break;							\
	case DRGN_OBJECT_ENCODING_UNSIGNED:				\
		ret = PyLong_FromUnsignedLongLong(value->uvalue);	\
		break;							\
	case DRGN_OBJECT_ENCODING_FLOAT:				\
		ret = PyLong_FromDouble(func(value->fvalue));		\
		break;							\
	default:							\
		UNREACHABLE();						\
	}								\
	drgn_object_deinit_value(&self->obj, value);			\
	return ret;							\
}
DrgnObject_round_method(trunc)
DrgnObject_round_method(floor)
DrgnObject_round_method(ceil)

static PyObject *DrgnObject_richcompare(PyObject *left, PyObject *right, int op)
{
	struct drgn_error *err;
	struct drgn_object *lhs, lhs_tmp, *rhs, rhs_tmp;
	int ret, cmp;

	ret = DrgnObject_binary_operand(left, right, &lhs, &lhs_tmp);
	if (ret)
		goto out;
	ret = DrgnObject_binary_operand(right, left, &rhs, &rhs_tmp);
	if (ret)
		goto out_lhs;

	err = drgn_object_cmp(lhs, rhs, &cmp);
	if (err) {
		set_drgn_error(err);
		ret = -1;
	}

	if (rhs == &rhs_tmp)
		drgn_object_deinit(&rhs_tmp);
out_lhs:
	if (lhs == &lhs_tmp)
		drgn_object_deinit(&lhs_tmp);
out:
	if (ret == -1)
		return NULL;
	else if (ret)
		Py_RETURN_NOTIMPLEMENTED;
	else
		Py_RETURN_RICHCOMPARE(cmp, 0, op);
}

static DrgnObject *DrgnObject_member(DrgnObject *self, PyObject *args,
				     PyObject *kwds)
{
	static char *keywords[] = {"name", NULL};
	struct drgn_error *err;
	const char *name;
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s:member_", keywords,
					 &name))
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		return NULL;

	if (self->obj.encoding == DRGN_OBJECT_ENCODING_UNSIGNED) {
		err = drgn_object_member_dereference(&res->obj, &self->obj,
						     name);
	} else {
		err = drgn_object_member(&res->obj, &self->obj, name);
	}
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

static PyObject *DrgnObject_getattro(DrgnObject *self, PyObject *attr_name)
{
	struct drgn_error *err;
	PyObject *attr;
	const char *name;
	DrgnObject *res;

	/*
	 * In Python 3.7 and newer, _PyObject_GenericGetAttrWithDict() can
	 * suppress the AttributeError if the attribute isn't found. This makes
	 * member lookups much more efficient.
	 */
#define GETATTR_SUPPRESS (PY_VERSION_HEX >= 0x030700b1)
#if GETATTR_SUPPRESS
	attr = _PyObject_GenericGetAttrWithDict((PyObject *)self, attr_name,
						NULL, 1);
	if (attr || PyErr_Occurred())
		return attr;
#else
	PyObject *exc_type, *exc_value, *exc_traceback;

	attr = PyObject_GenericGetAttr((PyObject *)self, attr_name);
	if (attr || !PyErr_ExceptionMatches(PyExc_AttributeError))
		return attr;
	PyErr_Fetch(&exc_type, &exc_value, &exc_traceback);
#endif

	name = PyUnicode_AsUTF8(attr_name);
	if (!name) {
		res = NULL;
		goto out;
	}

	res = DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		goto out;

	if (self->obj.encoding == DRGN_OBJECT_ENCODING_UNSIGNED) {
		err = drgn_object_member_dereference(&res->obj, &self->obj,
						     name);
	} else {
		err = drgn_object_member(&res->obj, &self->obj, name);
	}
	if (err) {
		Py_CLEAR(res);
		if (err->code == DRGN_ERROR_TYPE) {
			/*
			 * If the object doesn't have a compound type, raise a
			 * generic AttributeError (or restore the original one
			 * if we weren't able to suppress it).
			 */
#if GETATTR_SUPPRESS
			PyErr_Format(PyExc_AttributeError,
				     "'%s' object has no attribute '%U'",
				     Py_TYPE(self)->tp_name, attr_name);
#else
			PyErr_Restore(exc_type, exc_value, exc_traceback);
#endif
			drgn_error_destroy(err);
			return NULL;
		} else if (err->code == DRGN_ERROR_LOOKUP) {
			PyErr_SetString(PyExc_AttributeError, err->message);
			drgn_error_destroy(err);
		} else {
			set_drgn_error(err);
		}
	}
out:
#if !GETATTR_SUPPRESS
	Py_XDECREF(exc_traceback);
	Py_XDECREF(exc_value);
	Py_DECREF(exc_type);
#endif
#undef GETATTR_SUPPRESS
	return (PyObject *)res;
}

static Py_ssize_t DrgnObject_length(DrgnObject *self)
{
	struct drgn_type *underlying_type;
	uint64_t length;

	underlying_type = drgn_underlying_type(self->obj.type);
	if (drgn_type_kind(underlying_type) != DRGN_TYPE_ARRAY ||
	    !drgn_type_is_complete(underlying_type)) {
		set_error_type_name("'%s' has no len()",
				    drgn_object_qualified_type(&self->obj));
		return -1;
	}
	length = drgn_type_length(underlying_type);
	if (length > PY_SSIZE_T_MAX) {
		PyErr_SetString(PyExc_OverflowError, "length is too large");
		return -1;
	}
	return length;
}

static DrgnObject *DrgnObject_subscript_impl(DrgnObject *self,
					     int64_t index)
{
	struct drgn_error *err;
	DrgnObject *res;

	res = DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		return NULL;

	err = drgn_object_subscript(&res->obj, &self->obj, index);
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

static DrgnObject *DrgnObject_subscript(DrgnObject *self, PyObject *key)
{
	struct index_arg index = { .is_signed = true };

	if (!index_converter(key, &index))
		return NULL;
	return DrgnObject_subscript_impl(self, index.svalue);
}

static ObjectIterator *DrgnObject_iter(DrgnObject *self)
{
	struct drgn_type *underlying_type;
	ObjectIterator *it;

	underlying_type = drgn_underlying_type(self->obj.type);
	if (drgn_type_kind(underlying_type) != DRGN_TYPE_ARRAY ||
	    !drgn_type_is_complete(underlying_type)) {
		set_error_type_name("'%s' is not iterable",
				    drgn_object_qualified_type(&self->obj));
		return NULL;
	}

	it = (ObjectIterator *)ObjectIterator_type.tp_alloc(&ObjectIterator_type,
							    0);
	if (!it)
		return NULL;
	it->obj = self;
	Py_INCREF(self);
	it->length = drgn_type_length(underlying_type);
	return it;
}

static int add_to_dir(PyObject *dir, struct drgn_type *type)
{
	struct drgn_error *err;

	type = drgn_underlying_type(type);
	if (!drgn_type_has_members(type))
		return 0;

	struct drgn_type_member *members = drgn_type_members(type);
	size_t num_members = drgn_type_num_members(type);
	for (size_t i = 0; i < num_members; i++) {
		struct drgn_type_member *member;

		member = &members[i];
		if (member->name) {
			PyObject *str = PyUnicode_FromString(member->name);
			if (!str)
				return -1;
			if (PyList_Append(dir, str) == -1) {
				Py_DECREF(str);
				return -1;
			}
			Py_DECREF(str);
		} else {
			struct drgn_qualified_type member_type;
			err = drgn_member_type(member, &member_type, NULL);
			if (err) {
				set_drgn_error(err);
				return -1;
			}
			if (add_to_dir(dir, member_type.type) == -1)
				return -1;
		}
	}
	return 0;
}

static PyObject *DrgnObject_dir(DrgnObject *self)
{
	_Py_IDENTIFIER(__dir__);
	PyObject *method, *dir;
	struct drgn_type *type;

	method = _PyObject_GetAttrId((PyObject *)Py_TYPE(self)->tp_base,
				     &PyId___dir__);
	if (!method)
		return NULL;

	dir = PyObject_CallFunctionObjArgs(method, self, NULL);
	Py_DECREF(method);
	if (!dir)
		return NULL;

	type = drgn_underlying_type(self->obj.type);
	if (drgn_type_kind(type) == DRGN_TYPE_POINTER)
		type = drgn_type_type(type).type;
	if (add_to_dir(dir, type) == -1) {
		Py_DECREF(dir);
		return NULL;
	}

	return dir;
}

static PyGetSetDef DrgnObject_getset[] = {
	{"prog_", (getter)DrgnObject_get_prog, NULL, drgn_Object_prog__DOC},
	{"type_", (getter)DrgnObject_get_type, NULL, drgn_Object_type__DOC},
	{"absent_", (getter)DrgnObject_get_absent, NULL,
	 drgn_Object_absent__DOC},
	{"address_", (getter)DrgnObject_get_address, NULL,
	 drgn_Object_address__DOC},
	{"bit_offset_", (getter)DrgnObject_get_bit_offset, NULL,
	 drgn_Object_bit_offset__DOC},
	{"bit_field_size_", (getter)DrgnObject_get_bit_field_size, NULL,
	 drgn_Object_bit_field_size__DOC},
	{},
};

static PyMethodDef DrgnObject_methods[] = {
	{"__getitem__", (PyCFunction)DrgnObject_subscript,
	 METH_O | METH_COEXIST, drgn_Object___getitem___DOC},
	{"value_", (PyCFunction)DrgnObject_value, METH_NOARGS,
	 drgn_Object_value__DOC},
	{"string_", (PyCFunction)DrgnObject_string, METH_NOARGS,
	 drgn_Object_string__DOC},
	{"member_", (PyCFunction)DrgnObject_member,
	 METH_VARARGS | METH_KEYWORDS, drgn_Object_member__DOC},
	{"address_of_", (PyCFunction)DrgnObject_address_of, METH_NOARGS,
	 drgn_Object_address_of__DOC},
	{"read_", (PyCFunction)DrgnObject_read, METH_NOARGS,
	 drgn_Object_read__DOC},
	{"to_bytes_", (PyCFunction)DrgnObject_to_bytes, METH_NOARGS,
	 drgn_Object_to_bytes__DOC},
	{"from_bytes_", (PyCFunction)DrgnObject_from_bytes,
	 METH_CLASS | METH_VARARGS | METH_KEYWORDS,
	 drgn_Object_from_bytes__DOC},
	{"format_", (PyCFunction)DrgnObject_format,
	 METH_VARARGS | METH_KEYWORDS, drgn_Object_format__DOC},
	{"__round__", (PyCFunction)DrgnObject_round,
	 METH_VARARGS | METH_KEYWORDS},
	{"__trunc__", (PyCFunction)DrgnObject_trunc, METH_NOARGS},
	{"__floor__", (PyCFunction)DrgnObject_floor, METH_NOARGS},
	{"__ceil__", (PyCFunction)DrgnObject_ceil, METH_NOARGS},
	{"__dir__", (PyCFunction)DrgnObject_dir, METH_NOARGS,
"dir() implementation which includes structure, union, and class members."},
	{},
};

static PyNumberMethods DrgnObject_as_number = {
	.nb_add = (binaryfunc)DrgnObject_add,
	.nb_subtract = (binaryfunc)DrgnObject_sub,
	.nb_multiply = (binaryfunc)DrgnObject_mul,
	.nb_remainder = (binaryfunc)DrgnObject_mod,
	.nb_negative = (unaryfunc)DrgnObject_neg,
	.nb_positive = (unaryfunc)DrgnObject_pos,
	.nb_bool = (inquiry)DrgnObject_bool,
	.nb_invert = (unaryfunc)DrgnObject_not,
	.nb_lshift = (binaryfunc)DrgnObject_lshift,
	.nb_rshift = (binaryfunc)DrgnObject_rshift,
	.nb_and = (binaryfunc)DrgnObject_and,
	.nb_xor = (binaryfunc)DrgnObject_xor,
	.nb_or = (binaryfunc)DrgnObject_or,
	.nb_int = (unaryfunc)DrgnObject_int,
	.nb_float = (unaryfunc)DrgnObject_float,
	.nb_true_divide = (binaryfunc)DrgnObject_div,
	.nb_index = (unaryfunc)DrgnObject_index,
};

static PyMappingMethods DrgnObject_as_mapping = {
	.mp_length = (lenfunc)DrgnObject_length,
	.mp_subscript = (binaryfunc)DrgnObject_subscript,
};

PyTypeObject DrgnObject_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Object",
	.tp_basicsize = sizeof(DrgnObject),
	.tp_dealloc = (destructor)DrgnObject_dealloc,
	.tp_repr = (reprfunc)DrgnObject_repr,
	.tp_as_number = &DrgnObject_as_number,
	.tp_as_mapping = &DrgnObject_as_mapping,
	.tp_str = (reprfunc)DrgnObject_str,
	.tp_getattro = (getattrofunc)DrgnObject_getattro,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_Object_DOC,
	.tp_richcompare = DrgnObject_richcompare,
	.tp_iter = (getiterfunc)DrgnObject_iter,
	.tp_methods = DrgnObject_methods,
	.tp_getset = DrgnObject_getset,
	.tp_new = (newfunc)DrgnObject_new,
};

PyObject *DrgnObject_NULL(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"prog", "type", NULL};
	PyObject *prog_obj, *type_obj;
	PyObject *a, *k, *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO:NULL", keywords,
					 &prog_obj, &type_obj))
		return NULL;

	a = Py_BuildValue("OO", prog_obj, type_obj);
	if (!a)
		return NULL;
	k = Py_BuildValue("{s:i}", "value", 0);
	if (!k) {
		Py_DECREF(a);
		return NULL;
	}
	ret = PyObject_Call((PyObject *)&DrgnObject_type, a, k);
	Py_DECREF(k);
	Py_DECREF(a);
	return ret;
}

DrgnObject *cast(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"type", "obj", NULL};
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	PyObject *type_obj;
	DrgnObject *obj, *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO!:cast", keywords,
					 &type_obj, &DrgnObject_type, &obj))
		return NULL;

	if (Program_type_arg(DrgnObject_prog(obj), type_obj, false,
			     &qualified_type) == -1)
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(obj));
	if (!res)
		return NULL;

	err = drgn_object_cast(&res->obj, qualified_type, &obj->obj);
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

DrgnObject *reinterpret(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"type", "obj", NULL};
	struct drgn_error *err;
	PyObject *type_obj;
	struct drgn_qualified_type qualified_type;
	DrgnObject *obj, *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO!:reinterpret",
					 keywords, &type_obj, &DrgnObject_type,
					 &obj))
		return NULL;

	if (Program_type_arg(DrgnObject_prog(obj), type_obj, false,
			     &qualified_type) == -1)
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(obj));
	if (!res)
		return NULL;

	err = drgn_object_reinterpret(&res->obj, qualified_type, &obj->obj);
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

DrgnObject *DrgnObject_container_of(PyObject *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"ptr", "type", "member", NULL};
	struct drgn_error *err;
	DrgnObject *obj, *res;
	PyObject *type_obj;
	struct drgn_qualified_type qualified_type;
	const char *member_designator;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!Os:container_of",
					 keywords, &DrgnObject_type, &obj,
					 &type_obj, &member_designator))
		return NULL;

	if (Program_type_arg(DrgnObject_prog(obj), type_obj, false,
			     &qualified_type) == -1)
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(obj));
	if (!res)
		return NULL;

	err = drgn_object_container_of(&res->obj, &obj->obj, qualified_type,
				       member_designator);
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

static void ObjectIterator_dealloc(ObjectIterator *self)
{
	Py_DECREF(self->obj);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static DrgnObject *ObjectIterator_next(ObjectIterator *self)
{
	if (self->index >= self->length)
		return NULL;
	return DrgnObject_subscript_impl(self->obj, self->index++);
}

static PyObject *ObjectIterator_length_hint(ObjectIterator *self)
{
	return PyLong_FromUnsignedLongLong(self->length);
}

static PyMethodDef ObjectIterator_methods[] = {
	{"__length_hint__", (PyCFunction)ObjectIterator_length_hint,
	 METH_NOARGS},
	{},
};

PyTypeObject ObjectIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._ObjectIterator",
	.tp_basicsize = sizeof(ObjectIterator),
	.tp_dealloc = (destructor)ObjectIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)ObjectIterator_next,
	.tp_methods = ObjectIterator_methods,
};
