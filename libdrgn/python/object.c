// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

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
		bool is_negative = false;
		uint64_t uvalue = PyLong_AsUint64(literal);

		/* Assume an overflow is due to a negative number and retry */
		if (uvalue == (uint64_t)-1 && PyErr_Occurred() &&
		    PyErr_ExceptionMatches(PyExc_OverflowError)) {
			is_negative = true;
			PyErr_Clear();
			_cleanup_pydecref_ PyObject *negated =
				PyNumber_Negative(literal);
			if (!negated)
				return -1;
			uvalue = PyLong_AsUint64(negated);
		}
		if (uvalue == (uint64_t)-1 && PyErr_Occurred())
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

static void *
py_long_to_bytes_for_object_type(PyObject *value_obj,
				 const struct drgn_object_type *type)
{
	if (!PyNumber_Check(value_obj)) {
		return set_error_type_name("'%s' value must be number",
					   drgn_object_type_qualified(type));
	}
	_cleanup_pydecref_ PyObject *long_obj = PyNumber_Long(value_obj);
	if (!long_obj)
		return NULL;
	uint64_t size = drgn_value_size(type->bit_size);
	_cleanup_free_ void *buf = malloc64(size);
	if (!buf) {
		PyErr_NoMemory();
		return NULL;
	}
#if PY_VERSION_HEX >= 0x030d00a4
	Py_ssize_t r = PyLong_AsNativeBytes(long_obj, buf, size,
					    type->little_endian);
	if (r < 0)
		return NULL;
#else
	// _PyLong_AsByteArray() still returns the least significant bytes on
	// OverflowError unless the object is negative and is_signed is false.
	// So, we always pass is_signed as true.
	int r = _PyLong_AsByteArray((PyLongObject *)long_obj, buf, size,
				    type->little_endian, true);
	if (r) {
		PyObject *exc_type, *exc_value, *exc_traceback;
		PyErr_Fetch(&exc_type, &exc_value, &exc_traceback);
		if (PyErr_GivenExceptionMatches(exc_type, PyExc_OverflowError)) {
			Py_XDECREF(exc_traceback);
			Py_XDECREF(exc_value);
			Py_DECREF(exc_type);
		} else {
			PyErr_Restore(exc_type, exc_value, exc_traceback);
			return NULL;
		}
	}
#endif
	return_ptr(buf);
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

	if (!PyMapping_Check(value_obj)) {
		set_error_type_name("'%s' value must be dictionary or mapping",
				    drgn_object_type_qualified(type));
		return -1;
	}

	_cleanup_pydecref_ PyObject *items = PyMapping_Items(value_obj);
	if (!items)
		return -1;

	Py_ssize_t num_items = PyList_GET_SIZE(items);
	for (Py_ssize_t i = 0; i < num_items; i++) {
		PyObject *item = PyList_GET_ITEM(items, i);
		if (!PyTuple_Check(item) || PyTuple_GET_SIZE(item) != 2) {
			PyErr_SetString(PyExc_TypeError, "invalid item");
			return -1;
		}
		PyObject *key = PyTuple_GET_ITEM(item, 0);
		if (!PyUnicode_Check(key)) {
			PyErr_SetString(PyExc_TypeError,
					"member key must be string");
			return -1;
		}
		const char *member_name = PyUnicode_AsUTF8(key);
		if (!member_name)
			return -1;

		struct drgn_type_member *member;
		uint64_t member_bit_offset;
		err = drgn_type_find_member(type->underlying_type, member_name,
					    &member, &member_bit_offset);
		if (err) {
			set_drgn_error(err);
			return -1;
		}
		struct drgn_qualified_type member_qualified_type;
		uint64_t member_bit_field_size;
		err = drgn_member_type(member, &member_qualified_type,
				       &member_bit_field_size);
		if (err) {
			set_drgn_error(err);
			return -1;
		}

		struct drgn_object_type member_type;
		err = drgn_object_type(member_qualified_type,
				       member_bit_field_size, &member_type);
		if (err)
			return -1;
		if (serialize_py_object(prog, buf, buf_bit_size,
					bit_offset + member_bit_offset,
					PyTuple_GET_ITEM(item, 1),
					&member_type) == -1)
			return -1;
	}

	return 0;
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

	_cleanup_pydecref_ PyObject *seq = PySequence_Fast(value_obj, "");
	if (!seq) {
		if (PyErr_ExceptionMatches(PyExc_TypeError)) {
			set_error_type_name("'%s' value must be iterable",
					    drgn_object_type_qualified(type));
		}
		return -1;
	}
	size_t seq_length = PySequence_Fast_GET_SIZE(seq);
	if (seq_length > length) {
		PyErr_SetString(PyExc_ValueError,
				"too many items in array value");
		return -1;
	}

	for (size_t i = 0; i < seq_length; i++) {
		if (serialize_py_object(prog, buf, buf_bit_size,
					bit_offset + i * element_type.bit_size,
					PySequence_Fast_GET_ITEM(seq, i),
					&element_type) == -1)
			return -1;
	}

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
		_cleanup_pydecref_ PyObject *long_obj =
			PyNumber_Long(value_obj);
		if (!long_obj)
			return -1;
		union {
			int64_t svalue;
			uint64_t uvalue;
		} tmp;
		tmp.uvalue = PyLong_AsUint64Mask(long_obj);
		if (tmp.uvalue == (uint64_t)-1 && PyErr_Occurred())
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
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG: {
		_cleanup_free_ void *tmp =
			py_long_to_bytes_for_object_type(value_obj, type);
		if (!tmp)
			return -1;
		int src_bit_offset = 0;
		if (!type->little_endian)
			src_bit_offset = -type->bit_size % 8;
		copy_bits(buf + bit_offset / 8, bit_offset % 8, tmp,
			  src_bit_offset, type->bit_size, type->little_endian);
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
			struct {
#if !HOST_LITTLE_ENDIAN
				float pad;
#endif
				float fvalue32;
			};
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
				    const struct drgn_object_type *type,
				    PyObject *value_obj)
{
	uint64_t size = drgn_value_size(type->bit_size);
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

	if (serialize_py_object(drgn_object_program(res), buf, type->bit_size,
				0, value_obj, type) == -1) {
		if (buf != value.ibuf)
			free(buf);
		return -1;
	}

	drgn_object_reinit(res, type, DRGN_OBJECT_VALUE);
	res->value = value;
	return 0;
}

static DrgnObject *DrgnObject_new(PyTypeObject *subtype, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {
		"prog", "type", "value", "address", "absence_reason",
		"bit_offset", "bit_field_size", NULL,
	};
	struct drgn_error *err;
	Program *prog;
	PyObject *type_obj = Py_None, *value_obj = Py_None;
	struct index_arg address = { .allow_none = true, .is_none = true };
	struct enum_arg absence_reason = {
		.type = AbsenceReason_class,
		// Sentinel value so we can tell when the argument was passed.
		.value = ULONG_MAX,
	};
	struct index_arg bit_offset = { .allow_none = true, .is_none = true };
	struct index_arg bit_field_size = { .allow_none = true, .is_none = true };
	struct drgn_qualified_type qualified_type;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|OO$O&O&O&O&:Object",
					 keywords, &Program_type, &prog,
					 &type_obj, &value_obj, index_converter,
					 &address, enum_converter,
					 &absence_reason, index_converter,
					 &bit_offset, index_converter,
					 &bit_field_size))
		return NULL;

	if (Program_type_arg(prog, type_obj, true, &qualified_type) == -1)
		return NULL;

	if (!bit_field_size.is_none && bit_field_size.uvalue == 0) {
		PyErr_SetString(PyExc_ValueError,
				"bit field size cannot be zero");
		return NULL;
	}

	_cleanup_pydecref_ DrgnObject *obj = DrgnObject_alloc(prog);
	if (!obj)
		return NULL;
	if (!address.is_none
	    + (value_obj != Py_None)
	    + (absence_reason.value != ULONG_MAX) > 1) {
		PyErr_Format(PyExc_ValueError,
			     "object cannot have %s and %s",
			     !address.is_none
			     ? (value_obj != Py_None
				&& absence_reason.value != ULONG_MAX)
			     ? "address, value," : "address" : "value",
			     absence_reason.value != ULONG_MAX
			     ? "absence reason" : "value");
		return NULL;
	} else if (!address.is_none) {
		if (!qualified_type.type) {
			PyErr_SetString(PyExc_ValueError,
					"reference must have type");
			return NULL;
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
			return NULL;
		}
		if (!bit_field_size.is_none) {
			PyErr_SetString(PyExc_ValueError,
					"literal cannot be bit field");
			return NULL;
		}

		ret = DrgnObject_literal(&obj->obj, value_obj);
		if (ret == -1) {
			return NULL;
		} else if (ret) {
			PyErr_Format(PyExc_TypeError,
				     "literal must be int, float, or bool, not '%s'",
				     Py_TYPE(value_obj)->tp_name);
			return NULL;
		}
		err = NULL;
	} else if (value_obj != Py_None) {
		if (!bit_offset.is_none) {
			PyErr_SetString(PyExc_ValueError,
					"value cannot have bit offset");
			return NULL;
		}

		struct drgn_object_type object_type;
		err = drgn_object_type(qualified_type, bit_field_size.uvalue,
				       &object_type);
		if (err)
			return set_drgn_error(err);

		SWITCH_ENUM(object_type.encoding) {
		case DRGN_OBJECT_ENCODING_BUFFER:
			if (buffer_object_from_value(&obj->obj, &object_type,
						     value_obj) == -1)
				return NULL;
			err = NULL;
			break;
		case DRGN_OBJECT_ENCODING_SIGNED:
		case DRGN_OBJECT_ENCODING_UNSIGNED: {
			if (!PyNumber_Check(value_obj)) {
				return set_error_type_name("'%s' value must be number",
							   qualified_type);
			}
			_cleanup_pydecref_ PyObject *long_obj =
				PyNumber_Long(value_obj);
			if (!long_obj)
				return NULL;
			union {
				int64_t svalue;
				uint64_t uvalue;
			} tmp = {
				.uvalue = PyLong_AsUint64Mask(long_obj)
			};
			if (tmp.uvalue == (uint64_t)-1 && PyErr_Occurred())
				return NULL;
			if (object_type.encoding == DRGN_OBJECT_ENCODING_SIGNED) {
				err = drgn_object_set_signed_internal(&obj->obj,
								      &object_type,
								      tmp.svalue);
			} else {
				err = drgn_object_set_unsigned_internal(&obj->obj,
									&object_type,
									tmp.uvalue);
			}
			break;
		}
		case DRGN_OBJECT_ENCODING_SIGNED_BIG:
		case DRGN_OBJECT_ENCODING_UNSIGNED_BIG: {
			_cleanup_free_ void *tmp =
				py_long_to_bytes_for_object_type(value_obj,
								 &object_type);
			if (!tmp)
				return NULL;
			uint64_t src_bit_offset = 0;
			if (!object_type.little_endian)
				src_bit_offset = -object_type.bit_size % 8;
			err = drgn_object_set_from_buffer_internal(&obj->obj,
								   &object_type,
								   tmp,
								   src_bit_offset);
			break;
		}
		case DRGN_OBJECT_ENCODING_FLOAT: {
			if (!PyNumber_Check(value_obj)) {
				return set_error_type_name("'%s' value must be number",
							   qualified_type);
			}
			double fvalue = PyFloat_AsDouble(value_obj);
			if (fvalue == -1.0 && PyErr_Occurred())
				return NULL;
			err = drgn_object_set_float_internal(&obj->obj,
							     &object_type,
							     fvalue);
			break;
		}
		case DRGN_OBJECT_ENCODING_NONE:
		case DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER:
		case DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER:
			err = drgn_error_incomplete_type("cannot create value with %s type",
							 qualified_type.type);
			break;
		default:
			UNREACHABLE();
		}
	} else {
		if (!qualified_type.type) {
			PyErr_SetString(PyExc_ValueError,
					"absent object must have type");
			return NULL;
		}
		if (!bit_offset.is_none) {
			PyErr_SetString(PyExc_ValueError,
					"absent object cannot have bit offset");
			return NULL;
		}
		err = drgn_object_set_absent(&obj->obj, qualified_type,
					     absence_reason.value == ULONG_MAX
					     ? DRGN_ABSENCE_REASON_OTHER
					     : absence_reason.value,
					     bit_field_size.uvalue);
	}
	if (err)
		return set_drgn_error(err);
	return_ptr(obj);
}

static void DrgnObject_dealloc(DrgnObject *self)
{
	PyObject_GC_UnTrack(self);
	Py_DECREF(DrgnObject_prog(self));
	drgn_object_deinit(&self->obj);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *DrgnObject_value_impl(struct drgn_object *obj);

static PyObject *DrgnObject_compound_value(struct drgn_object *obj,
					   struct drgn_type *underlying_type)
{
	struct drgn_error *err;

	if (!drgn_type_is_complete(underlying_type)) {
		PyErr_Format(PyExc_TypeError,
			     "cannot get value of incomplete %s",
			     drgn_type_kind_spelling[drgn_type_kind(underlying_type)]);
		return NULL;
	}

	_cleanup_pydecref_ PyObject *dict = PyDict_New();
	if (!dict)
		return NULL;

	DRGN_OBJECT(member, drgn_object_program(obj));
	struct drgn_type_member *members = drgn_type_members(underlying_type);
	size_t num_members = drgn_type_num_members(underlying_type);
	for (size_t i = 0; i < num_members; i++) {
		struct drgn_qualified_type member_type;
		uint64_t member_bit_field_size;
		err = drgn_member_type(&members[i], &member_type,
				       &member_bit_field_size);
		if (err)
			return set_drgn_error(err);

		err = drgn_object_fragment(&member, obj, member_type,
					   members[i].bit_offset,
					   member_bit_field_size);
		if (err)
			return set_drgn_error(err);

		_cleanup_pydecref_ PyObject *member_value =
			DrgnObject_value_impl(&member);
		if (!member_value)
			return NULL;

		if (members[i].name) {
			if (PyDict_SetItemString(dict, members[i].name,
						 member_value))
				return NULL;
		} else {
			if (PyDict_Update(dict, member_value))
				return NULL;
		}
	}
	return_ptr(dict);
}

static PyObject *DrgnObject_array_value(struct drgn_object *obj,
					struct drgn_type *underlying_type)
{
	struct drgn_error *err;

	struct drgn_qualified_type element_type =
		drgn_type_type(underlying_type);
	uint64_t element_bit_size;
	err = drgn_type_bit_size(element_type.type, &element_bit_size);
	if (err)
		return set_drgn_error(err);

	uint64_t length = drgn_type_length(underlying_type);
	if (length > PY_SSIZE_T_MAX) {
		PyErr_NoMemory();
		return NULL;
	}

	_cleanup_pydecref_ PyObject *list = PyList_New(length);
	if (!list)
		return NULL;

	DRGN_OBJECT(element, drgn_object_program(obj));
	for (uint64_t i = 0; i < length; i++) {
		err = drgn_object_fragment(&element, obj, element_type,
					   i * element_bit_size, 0);
		if (err)
			return set_drgn_error(err);

		PyObject *element_value = DrgnObject_value_impl(&element);
		if (!element_value)
			return NULL;
		PyList_SET_ITEM(list, i, element_value);
	}
	return_ptr(list);
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
		return PyLong_FromInt64(svalue);
	}
	case DRGN_OBJECT_ENCODING_UNSIGNED: {
		uint64_t uvalue;
		err = drgn_object_read_unsigned(obj, &uvalue);
		if (err)
			return set_drgn_error(err);
		if (drgn_type_kind(underlying_type) == DRGN_TYPE_BOOL)
			Py_RETURN_BOOL(uvalue);
		else
			return PyLong_FromUint64(uvalue);
	}
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG: {
		union drgn_value value_mem;
		const union drgn_value *value;
		err = drgn_object_read_value(obj, &value_mem, &value);
		if (err)
			return set_drgn_error(err);
		return _PyLong_FromByteArray((void *)value->bufp,
					     drgn_object_size(obj),
					     obj->little_endian,
					     obj->encoding
					     == DRGN_OBJECT_ENCODING_SIGNED_BIG);
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
	_cleanup_free_ char *str = NULL;
	err = drgn_object_read_c_string(&self->obj, &str);
	if (err)
		return set_drgn_error(err);
	return PyBytes_FromString(str);
}

static DrgnObject *DrgnObject_address_of(DrgnObject *self)
{
	struct drgn_error *err;
	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		return NULL;
	err = drgn_object_address_of(&res->obj, &self->obj);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

static DrgnObject *DrgnObject_read(DrgnObject *self)
{
	struct drgn_error *err;
	SWITCH_ENUM(self->obj.kind) {
	case DRGN_OBJECT_VALUE:
		Py_INCREF(self);
		return self;
	case DRGN_OBJECT_REFERENCE: {
		_cleanup_pydecref_ DrgnObject *res =
			DrgnObject_alloc(DrgnObject_prog(self));
		if (!res)
			return NULL;
		err = drgn_object_read(&res->obj, &self->obj);
		if (err)
			return set_drgn_error(err);
		return_ptr(res);
	}
	case DRGN_OBJECT_ABSENT:
		return set_drgn_error(&drgn_error_object_absent);
	default:
		UNREACHABLE();
	}
}

static PyObject *DrgnObject_to_bytes(DrgnObject *self)
{
	struct drgn_error *err;
	_cleanup_pydecref_ PyObject *buf =
		PyBytes_FromStringAndSize(NULL, drgn_object_size(&self->obj));
	if (!buf)
		return NULL;
	err = drgn_object_read_bytes(&self->obj, PyBytes_AS_STRING(buf));
	if (err)
		return set_drgn_error(err);
	return_ptr(buf);
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
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!Oy*|$O&O&:from_bytes_",
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
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;

	_cleanup_free_ char *type_name = NULL;
	err = drgn_format_type_name(drgn_object_qualified_type(&self->obj),
				    &type_name);
	if (err)
		return set_drgn_error(err);
	_cleanup_pydecref_ PyObject *tmp = PyUnicode_FromString(type_name);
	if (!tmp)
		return NULL;

	if (append_format(parts, "Object(prog, %R", tmp) == -1)
		return NULL;

	SWITCH_ENUM(self->obj.kind) {
	case DRGN_OBJECT_VALUE: {
		if (append_string(parts, ", value=") == -1)
			return NULL;
		_cleanup_pydecref_ PyObject *value_obj = DrgnObject_value(self);
		if (!value_obj)
			return NULL;
		_cleanup_pydecref_ PyObject *part;
		if (drgn_type_kind(drgn_underlying_type(self->obj.type))
		    == DRGN_TYPE_POINTER)
			part = PyNumber_ToBase(value_obj, 16);
		else
			part = PyObject_Repr(value_obj);
		if (!part)
			return NULL;
		if (PyList_Append(parts, part) == -1)
			return NULL;
		break;
	}
	case DRGN_OBJECT_REFERENCE: {
		char buf[17];
		snprintf(buf, sizeof(buf), "%" PRIx64, self->obj.address);
		if (append_format(parts, ", address=0x%s", buf) == -1 ||
		    append_bit_offset(parts, self->obj.bit_offset) == -1)
			return NULL;
		break;
	}
	case DRGN_OBJECT_ABSENT:
		if (self->obj.absence_reason != DRGN_ABSENCE_REASON_OTHER) {
			if (append_format(parts, ", absence_reason=") < 0
			    || append_attr_str(parts, (PyObject *)self,
					       "absence_reason_") < 0)
				return NULL;
		}
		break;
	default:
		UNREACHABLE();
	}

	if (self->obj.is_bit_field &&
	    append_format(parts, ", bit_field_size=%llu",
			  (unsigned long long)self->obj.bit_size) == -1)
		return NULL;

	if (append_string(parts, ")") == -1)
		return NULL;

	return join_strings(parts);
}

static PyObject *DrgnObject_str(DrgnObject *self)
{
	_cleanup_free_ char *str = NULL;
	struct drgn_error *err = drgn_format_object(&self->obj, NULL, &str);
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromString(str);
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
		"integer_base",
		NULL,
	};
	struct drgn_error *err;
	PyObject *columns_obj = Py_None;
	PyObject *integer_base_obj = Py_None;
	struct drgn_format_object_options options = {
		.columns = SIZE_MAX,
		.flags = DRGN_FORMAT_OBJECT_PRETTY,
		.integer_base = 10,
	};
#define X(name, value)	\
	struct format_object_flag_arg name##_arg = { &options.flags, value };
	FLAGS
#undef X

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$"
#define X(name, value) "O&"
					 FLAGS
#undef X
					 "OO:format_", keywords,
#define X(name, value) format_object_flag_converter, &name##_arg,
					 FLAGS
#undef X
					 &columns_obj, &integer_base_obj))
		return NULL;

	if (columns_obj != Py_None) {
		columns_obj = PyNumber_Index(columns_obj);
		if (!columns_obj)
			return NULL;
		options.columns = PyLong_AsSize_t(columns_obj);
		Py_DECREF(columns_obj);
		if (options.columns == (size_t)-1 && PyErr_Occurred())
			return NULL;
	}

	if (integer_base_obj != Py_None) {
		int overflow;
		long integer_base = PyLong_AsLongAndOverflow(integer_base_obj,
							     &overflow);
		if (integer_base == -1 && PyErr_Occurred())
			return NULL;
		if (overflow
		    || integer_base < INT_MIN || integer_base > INT_MAX) {
			PyErr_SetString(PyExc_ValueError,
					"invalid integer base");
			return NULL;
		}
		options.integer_base = integer_base;
	}

	_cleanup_free_ char *str = NULL;
	err = drgn_format_object(&self->obj, &options, &str);
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromString(str);

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

static PyObject *DrgnObject_get_absence_reason(DrgnObject *self, void *arg)
{
	if (self->obj.kind != DRGN_OBJECT_ABSENT)
		Py_RETURN_NONE;
	return PyObject_CallFunction(AbsenceReason_class, "i",
				     (int)self->obj.absence_reason);
}

static PyObject *DrgnObject_get_address(DrgnObject *self, void *arg)
{
	if (self->obj.kind == DRGN_OBJECT_REFERENCE)
		return PyLong_FromUint64(self->obj.address);
	else
		Py_RETURN_NONE;
}

static PyObject *DrgnObject_get_bit_offset(DrgnObject *self, void *arg)
{
	SWITCH_ENUM(self->obj.kind) {
	case DRGN_OBJECT_REFERENCE:
		return PyLong_FromUint8(self->obj.bit_offset);
	case DRGN_OBJECT_VALUE:
	case DRGN_OBJECT_ABSENT:
		Py_RETURN_NONE;
	default:
		UNREACHABLE();
	}
}

static PyObject *DrgnObject_get_bit_field_size(DrgnObject *self, void *arg)
{
	if (self->obj.is_bit_field)
		return PyLong_FromUint64(self->obj.bit_size);
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

#define DrgnObject_UNARY_OP(op)					\
static DrgnObject *DrgnObject_##op(DrgnObject *self)		\
{								\
	struct drgn_error *err;					\
	_cleanup_pydecref_ DrgnObject *res =			\
		DrgnObject_alloc(DrgnObject_prog(self));	\
	if (!res)						\
		return NULL;					\
	err = drgn_object_##op(&res->obj, &self->obj);		\
	if (err)						\
		return set_drgn_error(err);			\
	return_ptr(res);					\
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
	SWITCH_ENUM(self->obj.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
	case DRGN_OBJECT_ENCODING_UNSIGNED:
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG:
		return DrgnObject_value(self);
	case DRGN_OBJECT_ENCODING_FLOAT: {
		double fvalue;
		err = drgn_object_read_float(&self->obj, &fvalue);
		if (err)
			return set_drgn_error(err);
		return PyLong_FromDouble(fvalue);
	}
	case DRGN_OBJECT_ENCODING_BUFFER:
	case DRGN_OBJECT_ENCODING_NONE:
	case DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER:
	case DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER:
		return set_error_type_name("cannot convert '%s' to int",
					   drgn_object_qualified_type(&self->obj));
	default:
		UNREACHABLE();
	}
}

static PyObject *DrgnObject_float(DrgnObject *self)
{
	struct drgn_error *err;
	SWITCH_ENUM(self->obj.encoding) {
	case DRGN_OBJECT_ENCODING_FLOAT: {
		double fvalue;
		err = drgn_object_read_float(&self->obj, &fvalue);
		if (err)
			return set_drgn_error(err);
		return PyFloat_FromDouble(fvalue);
	}
	case DRGN_OBJECT_ENCODING_SIGNED:
	case DRGN_OBJECT_ENCODING_UNSIGNED:
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG: {
		if (drgn_type_kind(drgn_underlying_type(self->obj.type))
		    != DRGN_TYPE_POINTER) {
			_cleanup_pydecref_ PyObject *value =
				DrgnObject_value(self);
			if (!value)
				return NULL;
			return PyObject_CallFunctionObjArgs((PyObject *)&PyFloat_Type,
							    value, NULL);
		}
		fallthrough;
	}
	case DRGN_OBJECT_ENCODING_BUFFER:
	case DRGN_OBJECT_ENCODING_NONE:
	case DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER:
	case DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER:
		return set_error_type_name("cannot convert '%s' to float",
					   drgn_object_qualified_type(&self->obj));
	default:
		UNREACHABLE();
	}
}

static PyObject *DrgnObject_index(DrgnObject *self)
{
	SWITCH_ENUM(self->obj.encoding) {
	case DRGN_OBJECT_ENCODING_SIGNED:
	case DRGN_OBJECT_ENCODING_UNSIGNED:
	case DRGN_OBJECT_ENCODING_SIGNED_BIG:
	case DRGN_OBJECT_ENCODING_UNSIGNED_BIG:
		return DrgnObject_value(self);
	case DRGN_OBJECT_ENCODING_FLOAT:
	case DRGN_OBJECT_ENCODING_BUFFER:
	case DRGN_OBJECT_ENCODING_NONE:
	case DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER:
	case DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER:
		return set_error_type_name("'%s' object cannot be interpreted as an integer",
					   drgn_object_qualified_type(&self->obj));
	default:
		UNREACHABLE();
	}
}

static PyObject *DrgnObject_round(DrgnObject *self, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {"ndigits", NULL};
	PyObject *ndigits = Py_None;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O:round", keywords,
					 &ndigits))
		return NULL;

	if (!drgn_type_is_arithmetic(self->obj.type)) {
		return set_error_type_name("cannot round '%s'",
					   drgn_object_qualified_type(&self->obj));
	}

	_cleanup_pydecref_ PyObject *value = DrgnObject_value(self);
	if (!value)
		return NULL;

	if (ndigits == Py_None)
		return PyObject_CallMethod(value, "__round__", NULL);

	_cleanup_pydecref_ PyObject *rounded_value =
		PyObject_CallMethod(value, "__round__", "O", ndigits);
	if (!rounded_value)
		return NULL;

	_cleanup_pydecref_ PyObject *type = DrgnObject_get_type(self, NULL);
	if (!type)
		return NULL;
	return PyObject_CallFunctionObjArgs((PyObject *)&DrgnObject_type,
					    DrgnObject_prog(self), type,
					    rounded_value, NULL);
}

#define DrgnObject_round_method(func)					\
static PyObject *DrgnObject_##func(DrgnObject *self)			\
{									\
	if (!drgn_type_is_arithmetic(self->obj.type)) {			\
		return set_error_type_name("cannot round '%s'",		\
					   drgn_object_qualified_type(&self->obj));\
	}								\
	if (self->obj.encoding != DRGN_OBJECT_ENCODING_FLOAT)		\
		return DrgnObject_value(self);				\
	union drgn_value value_mem;					\
	const union drgn_value *value;					\
	struct drgn_error *err =					\
		drgn_object_read_value(&self->obj, &value_mem, &value);	\
	if (err)							\
		return set_drgn_error(err);				\
	PyObject *ret = PyLong_FromDouble(func(value->fvalue));		\
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
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s:member_", keywords,
					 &name))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		return NULL;

	if (self->obj.encoding == DRGN_OBJECT_ENCODING_UNSIGNED) {
		err = drgn_object_member_dereference(&res->obj, &self->obj,
						     name);
	} else {
		err = drgn_object_member(&res->obj, &self->obj, name);
	}
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

static DrgnObject *DrgnObject_subobject(DrgnObject *self, PyObject *args,
					PyObject *kwds)
{
	static char *keywords[] = {"designator", NULL};
	struct drgn_error *err;
	const char *designator;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s:subobject_", keywords,
					 &designator))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		return NULL;
	err = drgn_object_subobject(&res->obj, &self->obj, designator);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

static PyObject *DrgnObject_getattro(DrgnObject *self, PyObject *attr_name)
{
	struct drgn_error *err;

	PyObject *attr = _PyObject_GenericGetAttrWithDict((PyObject *)self,
							  attr_name, NULL, 1);
	if (attr || PyErr_Occurred())
		return attr;

	const char *name = PyUnicode_AsUTF8(attr_name);
	if (!name)
		return NULL;

	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		return NULL;

	if (self->obj.encoding == DRGN_OBJECT_ENCODING_UNSIGNED) {
		err = drgn_object_member_dereference(&res->obj, &self->obj,
						     name);
	} else {
		err = drgn_object_member(&res->obj, &self->obj, name);
	}
	if (drgn_error_catch(&err, DRGN_ERROR_TYPE)) {
		// If the object doesn't have a compound type, raise a generic
		// AttributeError.
		return PyErr_Format(PyExc_AttributeError,
				    "'%s' object has no attribute '%U'",
				    Py_TYPE(self)->tp_name, attr_name);
	} else if (err && err->code == DRGN_ERROR_LOOKUP) {
		PyErr_SetString(PyExc_AttributeError, err->message);
		drgn_error_destroy(err);
		return NULL;
	} else if (err) {
		return set_drgn_error(err);
	}
	return (PyObject *)no_cleanup_ptr(res);
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
	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(self));
	if (!res)
		return NULL;
	err = drgn_object_subscript(&res->obj, &self->obj, index);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

static int64_t index_to_int64(PyObject *number)
{
	_cleanup_pydecref_ PyObject *index = PyNumber_Index(number);
	if (!index)
		return -1;
	return PyLong_AsInt64(index);
}

static DrgnObject *DrgnObject_subscript(DrgnObject *self, PyObject *item)
{
	if (PyIndex_Check(item)) {
		int64_t index = index_to_int64(item);
		if (index == -1 && PyErr_Occurred())
			return NULL;
		return DrgnObject_subscript_impl(self, index);
	} else if (PySlice_Check(item)) {
		PySliceObject *slice = (PySliceObject *)item;
		Py_ssize_t start, stop;
		if (slice->start == Py_None) {
			start = 0;
		} else {
			start = index_to_int64(slice->start);
			if (start == -1 && PyErr_Occurred())
				return NULL;
		}
		if (slice->stop == Py_None) {
			struct drgn_type *underlying_type =
				drgn_underlying_type(self->obj.type);
			if (drgn_type_kind(underlying_type) != DRGN_TYPE_ARRAY
			    || !drgn_type_is_complete(underlying_type)) {
				set_error_type_name("'%s' has no length; slice stop must be given",
						    drgn_object_qualified_type(&self->obj));
				return NULL;
			}
			uint64_t length = drgn_type_length(underlying_type);
			if (length > INT64_MAX) {
				PyErr_SetString(PyExc_OverflowError,
						"length is too large");
				return NULL;
			}
			stop = length;
		} else {
			stop = index_to_int64(slice->stop);
			if (stop == -1 && PyErr_Occurred())
				return NULL;
		}
		if (slice->step != Py_None) {
			Py_ssize_t step =
				PyNumber_AsSsize_t(slice->step,
						   PyExc_OverflowError);
			if (step == -1 && PyErr_Occurred())
				return NULL;
			if (step != 1) {
				PyErr_SetString(PyExc_ValueError,
						"object slice step must be 1");
				return NULL;
			}
		}
		struct drgn_error *err;
		_cleanup_pydecref_ DrgnObject *res =
			DrgnObject_alloc(DrgnObject_prog(self));
		if (!res)
			return NULL;
		err = drgn_object_slice(&res->obj, &self->obj, start, stop);
		if (err)
			return set_drgn_error(err);
		return_ptr(res);
	} else {
		PyErr_Format(PyExc_TypeError,
			     "object subscript must be integer or slice, not %.200s",
			     Py_TYPE(item)->tp_name);
		return NULL;
	}
}

static ObjectIterator *DrgnObject_iter_impl(DrgnObject *self, bool reversed)
{
	struct drgn_type *underlying_type =
		drgn_underlying_type(self->obj.type);
	if (drgn_type_kind(underlying_type) != DRGN_TYPE_ARRAY ||
	    !drgn_type_is_complete(underlying_type)) {
		set_error_type_name("'%s' is not iterable",
				    drgn_object_qualified_type(&self->obj));
		return NULL;
	}

	ObjectIterator *it = call_tp_alloc(ObjectIterator);
	if (!it)
		return NULL;
	it->obj = self;
	Py_INCREF(self);
	if (reversed) {
		it->index = drgn_type_length(underlying_type) - 1;
		it->end = -1;
		it->step = -1;
	} else {
		it->index = 0;
		it->end = drgn_type_length(underlying_type);
		it->step = 1;
	}
	return it;
}

static ObjectIterator *DrgnObject_iter(DrgnObject *self)
{
	return DrgnObject_iter_impl(self, false);
}

static ObjectIterator *DrgnObject_reversed(DrgnObject *self)
{
	return DrgnObject_iter_impl(self, true);
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
			_cleanup_pydecref_ PyObject *str =
				PyUnicode_FromString(member->name);
			if (!str)
				return -1;
			if (PyList_Append(dir, str) == -1)
				return -1;
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
	_cleanup_pydecref_ PyObject *method =
		_PyObject_GetAttrId((PyObject *)Py_TYPE(self)->tp_base,
				    &PyId___dir__);
	if (!method)
		return NULL;
	_cleanup_pydecref_ PyObject *dir =
		PyObject_CallFunctionObjArgs(method, self, NULL);
	if (!dir)
		return NULL;

	struct drgn_type *type = drgn_underlying_type(self->obj.type);
	if (drgn_type_kind(type) == DRGN_TYPE_POINTER)
		type = drgn_type_type(type).type;
	if (add_to_dir(dir, type) == -1)
		return NULL;

	return_ptr(dir);
}

static PyGetSetDef DrgnObject_getset[] = {
	{"prog_", (getter)DrgnObject_get_prog, NULL, drgn_Object_prog__DOC},
	{"type_", (getter)DrgnObject_get_type, NULL, drgn_Object_type__DOC},
	{"absent_", (getter)DrgnObject_get_absent, NULL,
	 drgn_Object_absent__DOC},
	{"absence_reason_", (getter)DrgnObject_get_absence_reason, NULL,
	 drgn_Object_absence_reason__DOC},
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
	{"subobject_", (PyCFunction)DrgnObject_subobject,
	 METH_VARARGS | METH_KEYWORDS, drgn_Object_subobject__DOC},
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
	{"__reversed__", (PyCFunction)DrgnObject_reversed, METH_NOARGS},
	{"__round__", (PyCFunction)DrgnObject_round,
	 METH_VARARGS | METH_KEYWORDS},
	{"__trunc__", (PyCFunction)DrgnObject_trunc, METH_NOARGS},
	{"__floor__", (PyCFunction)DrgnObject_floor, METH_NOARGS},
	{"__ceil__", (PyCFunction)DrgnObject_ceil, METH_NOARGS},
	{"__dir__", (PyCFunction)DrgnObject_dir, METH_NOARGS,
"dir() implementation which includes structure, union, and class members."},
	{"_repr_pretty_", (PyCFunction)repr_pretty_from_str,
	 METH_VARARGS | METH_KEYWORDS},
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

static int DrgnObject_traverse(DrgnObject *self, visitproc visit, void *arg)
{
	Py_VISIT(DrgnObject_prog(self));
	return 0;
}

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
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)DrgnObject_traverse,
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
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO:NULL", keywords,
					 &prog_obj, &type_obj))
		return NULL;
	return PyObject_CallFunction((PyObject *)&DrgnObject_type, "OOi",
				     prog_obj, type_obj, 0);
}

#define DrgnObject_CAST_OP(op)							\
DrgnObject *op(PyObject *self, PyObject *args, PyObject *kwds)			\
{										\
	static char *keywords[] = {"type", "obj", NULL};			\
	struct drgn_error *err;							\
	PyObject *type_obj;							\
	DrgnObject *obj;							\
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO!:" #op, keywords,	\
					 &type_obj, &DrgnObject_type, &obj))	\
		return NULL;							\
										\
	struct drgn_qualified_type qualified_type;				\
	if (Program_type_arg(DrgnObject_prog(obj), type_obj, false,		\
			     &qualified_type) == -1)				\
		return NULL;							\
										\
	_cleanup_pydecref_ DrgnObject *res =					\
		DrgnObject_alloc(DrgnObject_prog(obj));				\
	if (!res)								\
		return NULL;							\
										\
	err = drgn_object_##op(&res->obj, qualified_type, &obj->obj);		\
	if (err)								\
		return set_drgn_error(err);					\
	return_ptr(res);							\
}

DrgnObject_CAST_OP(cast)

DrgnObject *implicit_convert(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"type", "obj", "bit_field_size", NULL};
	struct drgn_error *err;
	PyObject *type_obj;
	DrgnObject *obj;
	struct index_arg bit_field_size = { .allow_none = true, .is_none = true };
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO!|$O&:implicit_convert",
					 keywords, &type_obj, &DrgnObject_type,
					 &obj, index_converter,
					 &bit_field_size))
		return NULL;

	if (!bit_field_size.is_none && bit_field_size.uvalue == 0) {
		PyErr_SetString(PyExc_ValueError,
				"bit field size cannot be zero");
		return NULL;
	}

	struct drgn_qualified_type qualified_type;
	if (Program_type_arg(DrgnObject_prog(obj), type_obj, false,
			     &qualified_type) == -1)
		return NULL;

	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(obj));
	if (!res)
		return NULL;

	err = drgn_object_implicit_convert(&res->obj, qualified_type,
					   bit_field_size.uvalue, &obj->obj);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

DrgnObject_CAST_OP(reinterpret)

#undef DrgnObject_CAST_OP

DrgnObject *DrgnObject_container_of(PyObject *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"ptr", "type", "member", NULL};
	struct drgn_error *err;
	DrgnObject *obj;
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

	_cleanup_pydecref_ DrgnObject *res = DrgnObject_alloc(DrgnObject_prog(obj));
	if (!res)
		return NULL;

	err = drgn_object_container_of(&res->obj, &obj->obj, qualified_type,
				       member_designator);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

static void ObjectIterator_dealloc(ObjectIterator *self)
{
	PyObject_GC_UnTrack(self);
	Py_DECREF(self->obj);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int ObjectIterator_traverse(ObjectIterator *self, visitproc visit,
				   void *arg)
{
	Py_VISIT(self->obj);
	return 0;
}

static DrgnObject *ObjectIterator_next(ObjectIterator *self)
{
	if (self->index == self->end)
		return NULL;
	DrgnObject *ret = DrgnObject_subscript_impl(self->obj, self->index);
	if (ret)
		self->index += self->step;
	return ret;
}

static PyObject *ObjectIterator_length_hint(ObjectIterator *self)
{
	uint64_t length;
	if (self->step == 1)
		length = self->end - self->index;
	else
		length = self->index + 1;
	return PyLong_FromUint64(length);
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
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)ObjectIterator_traverse,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)ObjectIterator_next,
	.tp_methods = ObjectIterator_methods,
};
