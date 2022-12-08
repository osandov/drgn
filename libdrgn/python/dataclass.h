// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGNPY_DATACLASS_H
#define DRGNPY_DATACLASS_H

// Imitation of Python's dataclass for the C API.

#define PP_COMMA ,
#define DATACLASS_FIELD_PYOBJECTP(prefix, name, typeobject) \
	PyObject *prefix##name;
#define DATACLASS_FIELD_LITERAL(literal, name, typeobject) literal
#define DATACLASS_FIELD_NEW_KEYWORD(ARG, name, typeobject) #name,
#define DATACLASS_FIELD_PYARG(ARG, name, typeobject) typeobject, &arg_##name
#define DATACLASS_FIELD_NEW_SET(ARG, name, typeobject) \
	Py_INCREF(arg_##name); ret->name = arg_##name;
#define DATACLASS_FIELD_SELF_XDECREF(ARG, name, typeobject) \
	Py_XDECREF(self->name);
#define DATACLASS_FIELD_SELF(ARG, name, typeobject) self->name
#define DATACLASS_FIELD_REPR_FORMAT(ARG, name, typeobject) #name"=%R"
#define DATACLASS_FIELD_PYMEMBERDEF(type, name, typeobject) \
	{#name, T_OBJECT_EX, offsetof(type, name), READONLY, drgn_##type##_##name##_DOC},
#define DATACLASS_FIELD_EQUAL(ARG, name, typeobject)			\
	ret = PyObject_RichCompareBool(self->name, other->name, Py_EQ);	\
	if (ret <= 0)							\
		return ret;

#define DEFINE_DATACLASS_TYPE(name)			\
typedef struct {					\
	PyObject_HEAD					\
	name##_fields(DATACLASS_FIELD_PYOBJECTP,,)	\
} name;							\
extern PyTypeObject name##_type

#define DEFINE_FROZEN_DATACLASS(type, ...)					\
static type *type##_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)	\
{										\
	static char *keywords[] = {						\
		type##_fields(DATACLASS_FIELD_NEW_KEYWORD,,) NULL		\
	};									\
	type##_fields(DATACLASS_FIELD_PYOBJECTP, arg_,)				\
	if (!PyArg_ParseTupleAndKeywords(args, kwds,				\
					 type##_fields(DATACLASS_FIELD_LITERAL, "O!",) ":" #type,\
					 keywords,				\
					 type##_fields(DATACLASS_FIELD_PYARG,, PP_COMMA)))\
		return NULL;							\
										\
	type *ret = (type *)subtype->tp_alloc(subtype, 0);			\
	if (ret) {								\
		type##_fields(DATACLASS_FIELD_NEW_SET,,)			\
	}									\
	return ret;								\
}										\
										\
static void type##_dealloc(type *self)						\
{										\
	type##_fields(DATACLASS_FIELD_SELF_XDECREF,,)				\
	Py_TYPE(self)->tp_free((PyObject *)self);				\
}										\
										\
static PyObject *type##_repr(type *self)					\
{										\
	return PyUnicode_FromFormat(#type "("					\
				    type##_fields(DATACLASS_FIELD_REPR_FORMAT,, ", ")\
				    ")",					\
				    type##_fields(DATACLASS_FIELD_SELF,, PP_COMMA));\
}										\
										\
static int type##_equal(type *self, type *other)				\
{										\
	int ret;								\
	type##_fields(DATACLASS_FIELD_EQUAL,,)					\
	return 1;								\
}										\
										\
static PyObject *type##_richcompare(type *self, PyObject *other, int op)	\
{										\
	if ((op != Py_EQ && op != Py_NE) ||					\
	    !PyObject_TypeCheck(other, &type##_type))				\
		Py_RETURN_NOTIMPLEMENTED;					\
	int ret = type##_equal(self, (type *)other);				\
	if (ret < 0)								\
		return NULL;							\
	if (op == Py_NE)							\
		ret = !ret;							\
	Py_RETURN_BOOL(ret);							\
}										\
										\
static PyMemberDef type##_members[] = {						\
	type##_fields(DATACLASS_FIELD_PYMEMBERDEF, type,)			\
	{},									\
};										\
										\
PyTypeObject type##_type = {							\
	PyVarObject_HEAD_INIT(NULL, 0)						\
	.tp_name = "_drgn." #type,						\
	.tp_basicsize = sizeof(type),						\
	.tp_dealloc = (destructor)type##_dealloc,				\
	.tp_repr = (reprfunc)type##_repr,					\
	.tp_flags = Py_TPFLAGS_DEFAULT,						\
	.tp_doc = drgn_##type##_DOC,						\
	.tp_richcompare = (richcmpfunc)type##_richcompare,			\
	.tp_members = type##_members,						\
	.tp_new = (newfunc)type##_new,						\
	__VA_ARGS__								\
}

#endif /* DRGNPY_DATACLASS_H */
