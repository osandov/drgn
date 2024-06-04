// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../bitops.h"

static PyObject *collections_abc_Set;

PyObject *TypeKindSet_wrap(uint64_t mask)
{
	TypeKindSet *res = call_tp_alloc(TypeKindSet);
	if (res)
		res->kinds = mask;
	return (PyObject *)res;
}

int init_type_kind_set(void)
{
	_cleanup_pydecref_ PyObject *collections_abc =
		PyImport_ImportModule("collections.abc");
	if (!collections_abc)
		return -1;
	collections_abc_Set = PyObject_GetAttrString(collections_abc, "Set");
	if (!collections_abc_Set)
		return -1;
	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(collections_abc_Set, "register", "O",
				    &TypeKindSet_type);
	if (!res)
		return -1;
	Py_DECREF(res);
	return 0;
}

static inline const char *type_kind_to_str(enum drgn_type_kind kind)
{
	SWITCH_ENUM(kind,
	case DRGN_TYPE_VOID:
		return "TypeKind.VOID";
	case DRGN_TYPE_INT:
		return "TypeKind.INT";
	case DRGN_TYPE_BOOL:
		return "TypeKind.BOOL";
	case DRGN_TYPE_FLOAT:
		return "TypeKind.FLOAT";
	case DRGN_TYPE_STRUCT:
		return "TypeKind.STRUCT";
	case DRGN_TYPE_UNION:
		return "TypeKind.UNION";
	case DRGN_TYPE_CLASS:
		return "TypeKind.CLASS";
	case DRGN_TYPE_ENUM:
		return "TypeKind.ENUM";
	case DRGN_TYPE_TYPEDEF:
		return "TypeKind.TYPEDEF";
	case DRGN_TYPE_POINTER:
		return "TypeKind.POINTER";
	case DRGN_TYPE_ARRAY:
		return "TypeKind.ARRAY";
	case DRGN_TYPE_FUNCTION:
		return "TypeKind.FUNCTION";
	)
}

static PyObject *TypeKindSet_repr(TypeKindSet *self)
{
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;
	if (append_string(parts, "TypeKindSet("))
		return NULL;
	bool first = true;
	unsigned int kind;
	uint64_t kinds = self->kinds;
	for_each_bit(kind, kinds) {
		if (append_format(parts, "%s%s", first ? "{" : ", ",
				  type_kind_to_str(kind)))
			return NULL;
		first = false;
	}
	if (append_string(parts, first ? ")" : "})"))
		return NULL;
	return join_strings(parts);
}

static int TypeKind_value(PyObject *obj)
{
	_cleanup_pydecref_ PyObject *value_obj =
		PyObject_GetAttrString(obj, "value");
	if (!value_obj)
		return -1;
	long value = PyLong_AsLong(value_obj);
	if ((value < 0 && !PyErr_Occurred()) || value >= 64) {
		PyErr_BadArgument();
		return -1;
	}
	return value;
}

static int TypeKindSet_mask_from_iterable(PyObject *iterable, uint64_t *ret)
{
	if (PyObject_TypeCheck(iterable, &TypeKindSet_type)) {
		*ret = ((TypeKindSet *)iterable)->kinds;
		return 0;
	}

	int non_typekind = 0;
	uint64_t mask = 0;
	if (iterable) {
		_cleanup_pydecref_ PyObject *it = PyObject_GetIter(iterable);
		if (!it)
			return -1;

		for (;;) {
			_cleanup_pydecref_ PyObject *item = PyIter_Next(it);
			if (!item)
				break;
			if (PyObject_TypeCheck(item,
					       (PyTypeObject *)TypeKind_class)) {
				int value = TypeKind_value(item);
				if (value < 0)
					return -1;
				mask |= 1 << value;
			} else {
				non_typekind = 1;
			}
		}
		if (PyErr_Occurred())
			return -1;
	}
	*ret = mask;
	return non_typekind;
}

static TypeKindSet *TypeKindSet_new(PyTypeObject *subtype, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = { "", NULL };
	PyObject *iterable = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O:TypeKindSet", keywords,
					 &iterable))
		return NULL;
	uint64_t kinds = 0;
	if (iterable) {
		int r = TypeKindSet_mask_from_iterable(iterable, &kinds);
		if (r < 0)
			return NULL;
		if (r > 0) {
			PyErr_SetString(PyExc_TypeError,
					"TypeKindSet elements must be TypeKind");
			return NULL;
		}
	}
	TypeKindSet *res = (TypeKindSet *)subtype->tp_alloc(subtype, 0);
	res->kinds = kinds;
	return res;
}

static Py_ssize_t TypeKindSet_length(TypeKindSet *self)
{
	return popcount(self->kinds);
}

static int TypeKindSet_contains(TypeKindSet *self, PyObject *other)
{
	if (!PyObject_TypeCheck(other, (PyTypeObject *)TypeKind_class))
		return 0;
	int value = TypeKind_value(other);
	if (value < 0)
		return value;
	return !!(self->kinds & (1 << value));
}

static Py_ssize_t TypeKindSet_hash(TypeKindSet *self)
{
	return self->kinds;
}

static PyObject *TypeKindSet_richcompare(TypeKindSet *self, PyObject *other,
					 int op)
{
	if (!PyObject_IsInstance(other, collections_abc_Set))
		Py_RETURN_NOTIMPLEMENTED;

	uint64_t other_kinds;
	int other_non_typekind =
		TypeKindSet_mask_from_iterable(other, &other_kinds);
	if (other_non_typekind < 0)
		return NULL;

	switch (op) {
	case Py_EQ:
		Py_RETURN_BOOL(self->kinds == other_kinds && !other_non_typekind);
	case Py_NE:
		Py_RETURN_BOOL(self->kinds != other_kinds || other_non_typekind);
	case Py_LT:
		Py_RETURN_BOOL((self->kinds != other_kinds || other_non_typekind)
			       && (other_kinds | self->kinds) == other_kinds);
	case Py_GT:
		Py_RETURN_BOOL(self->kinds != other_kinds
			       && (self->kinds | other_kinds) == self->kinds
			       && !other_non_typekind);
	case Py_LE:
		Py_RETURN_BOOL((other_kinds | self->kinds) == other_kinds);
	case Py_GE:
		Py_RETURN_BOOL((self->kinds | other_kinds) == self->kinds
			       && !other_non_typekind);
	default:
		Py_UNREACHABLE();
	}
}

static TypeKindSetIterator *TypeKindSet_iter(TypeKindSet *self)
{
	TypeKindSetIterator *it = call_tp_alloc(TypeKindSetIterator);
	if (!it)
		return NULL;
	it->mask = self->kinds;
	return it;
}

static PyObject *TypeKindSet_isdisjoint(TypeKindSet *self, PyObject *other)
{
	uint64_t other_kinds;
	if (TypeKindSet_mask_from_iterable(other, &other_kinds) < 0)
		return NULL;
	// Non-TypeKind elements in other cannot be in self, so they don't
	// affect the answer and can be ignored.
	Py_RETURN_BOOL((self->kinds ^ other_kinds)
		       == (self->kinds | other_kinds));
}

static PyObject *TypeKindSet_sub(PyObject *left, PyObject *right)
{
	uint64_t left_kinds;
	int left_r = TypeKindSet_mask_from_iterable(left, &left_kinds);
	if (left_r < 0)
		return NULL;
	if (left_r > 0)
		Py_RETURN_NOTIMPLEMENTED;

	uint64_t right_kinds;
	if (TypeKindSet_mask_from_iterable(right, &right_kinds) < 0)
		return NULL;
	// If right has non-TypeKind elements, then left is a TypeKindSet and
	// removing non-TypeKind elements has no effect, so they can be ignored.
	return TypeKindSet_wrap(left_kinds & ~right_kinds);
}

static PyObject *TypeKindSet_and(PyObject *left, PyObject *right)
{
	uint64_t left_kinds, right_kinds;
	if (TypeKindSet_mask_from_iterable(left, &left_kinds) < 0
	    || TypeKindSet_mask_from_iterable(right, &right_kinds) < 0)
		return NULL;
	// At least one of the operands is a TypeKindSet, so non-TypeKind
	// elements cannot be in both and can be ignored.
	return TypeKindSet_wrap(left_kinds & right_kinds);
}

#define TypeKindSet_OR_OP(name, op)						\
static PyObject *TypeKindSet_##name(PyObject *left, PyObject *right)		\
{										\
	/* Both operands must only contain TypeKind elements. */		\
	uint64_t left_kinds;							\
	int left_r = TypeKindSet_mask_from_iterable(left, &left_kinds);		\
	if (left_r < 0)								\
		return NULL;							\
	if (left_r > 0)								\
		Py_RETURN_NOTIMPLEMENTED;					\
										\
	uint64_t right_kinds;							\
	int right_r = TypeKindSet_mask_from_iterable(right, &right_kinds);	\
	if (right_r < 0)							\
		return NULL;							\
	if (right_r > 0)							\
		Py_RETURN_NOTIMPLEMENTED;					\
										\
	return TypeKindSet_wrap(left_kinds op right_kinds);			\
}
TypeKindSet_OR_OP(xor, ^)
TypeKindSet_OR_OP(or, |)
#undef TypeKindSet_OR_OP

static PyNumberMethods TypeKindSet_as_number = {
    .nb_subtract = TypeKindSet_sub,
    .nb_and = TypeKindSet_and,
    .nb_xor = TypeKindSet_xor,
    .nb_or = TypeKindSet_or,
};

static PySequenceMethods TypeKindSet_as_sequence = {
	.sq_length = (lenfunc)TypeKindSet_length,
	.sq_contains = (objobjproc)TypeKindSet_contains,
};

static PyMethodDef TypeKindSet_methods[] = {
	{"isdisjoint", (PyCFunction)TypeKindSet_isdisjoint, METH_O},
	{},
};

PyTypeObject TypeKindSet_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.TypeKindSet",
	.tp_basicsize = sizeof(TypeKindSet),
	.tp_repr = (reprfunc)TypeKindSet_repr,
	.tp_as_number = &TypeKindSet_as_number,
	.tp_as_sequence = &TypeKindSet_as_sequence,
	.tp_hash = (hashfunc)TypeKindSet_hash,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_TypeKindSet_DOC,
	.tp_richcompare = (richcmpfunc)TypeKindSet_richcompare,
	.tp_iter = (getiterfunc)TypeKindSet_iter,
	.tp_methods = TypeKindSet_methods,
	.tp_new = (newfunc)TypeKindSet_new,
};

static PyObject *TypeKindSetIterator_next(TypeKindSetIterator *self)
{
	if (self->mask == 0)
		return NULL;
	unsigned int i = ctz(self->mask);
	self->mask &= self->mask - 1;
	return PyObject_CallFunction(TypeKind_class, "I", i);
}

static PyObject *TypeKindSetIterator_length_hint(TypeKindSetIterator *self)
{
	return PyLong_FromUnsignedLong(popcount(self->mask));
}

static PyMethodDef TypeKindSetIterator_methods[] = {
	{"__length_hint__", (PyCFunction)TypeKindSetIterator_length_hint,
	 METH_NOARGS},
	{},
};

PyTypeObject TypeKindSetIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._TypeKindSetIterator",
	.tp_basicsize = sizeof(TypeKindSetIterator),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)TypeKindSetIterator_next,
	.tp_methods = TypeKindSetIterator_methods,
};
