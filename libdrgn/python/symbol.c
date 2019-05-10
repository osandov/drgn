// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

#include "../symbol_index.h"

Symbol *Symbol_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"type", "value", "address", "is_enumerator", "byteorder", NULL,
	};
	DrgnType *type_obj;
	struct drgn_qualified_type qualified_type;
	PyObject *value_obj = Py_None, *address_obj = Py_None;
	int is_enumerator = 0;
	const char *byteorder = NULL;
	Symbol *sym;
	int num_given;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|$OOpz", keywords,
					 &DrgnType_type, &type_obj, &value_obj,
					 &address_obj, &is_enumerator,
					 &byteorder)) {
		fprintf(stderr, "ya\n");
		return NULL;
	}

	qualified_type.type = type_obj->type;
	qualified_type.qualifiers = type_obj->qualifiers;

	num_given = ((value_obj != Py_None) + (address_obj != Py_None) +
		     is_enumerator);
	if (num_given == 0) {
		PyErr_SetString(PyExc_ValueError,
				"one of value, address, or is_enumerator is required");
		return NULL;
	} else if (num_given > 1) {
		PyErr_SetString(PyExc_ValueError,
				"only one of value, address, or is_enumerator may be given");
		return NULL;
	}
	if (address_obj != Py_None && !byteorder) {
		PyErr_SetString(PyExc_ValueError,
				"byteorder must be given with address");
		return NULL;
	} else if (address_obj == Py_None && byteorder) {
		PyErr_SetString(PyExc_ValueError,
				"byteorder may only be given with address");
		return NULL;
	}

	sym = (Symbol *)subtype->tp_alloc(subtype, 0);
	if (!sym)
		return NULL;

	sym->sym.type = type_obj->type;
	sym->sym.qualifiers = type_obj->qualifiers;
	if (value_obj != Py_None) {
		enum drgn_object_kind kind;

		sym->sym.kind = DRGN_SYMBOL_CONSTANT;
		kind = drgn_type_object_kind(qualified_type.type);
		switch (kind) {
		case DRGN_OBJECT_SIGNED:
		case DRGN_OBJECT_UNSIGNED: {
			union {
				int64_t svalue;
				uint64_t uvalue;
			} tmp;

			if (!PyNumber_Check(value_obj)) {
				set_error_type_name("'%s' value must be number",
						    qualified_type);
				goto err;
			}
			tmp.uvalue = PyLong_AsUnsignedLongLongMask(value_obj);
			if (tmp.uvalue == (unsigned long long)-1 &&
			    PyErr_Occurred())
				goto err;
			if (kind == DRGN_OBJECT_SIGNED)
				sym->sym.svalue = tmp.svalue;
			else
				sym->sym.uvalue = tmp.uvalue;
			break;
		}
		case DRGN_OBJECT_FLOAT: {
			double fvalue;

			if (!PyNumber_Check(value_obj)) {
				set_error_type_name("'%s' value must be number",
						    qualified_type);
				goto err;
			}
			fvalue = PyFloat_AsDouble(value_obj);
			if (fvalue == -1.0 && PyErr_Occurred())
				goto err;
			sym->sym.fvalue = fvalue;
			break;
		}
		default:
			set_error_type_name("cannot have '%s' constant",
					    qualified_type);
			goto err;
		}
	} else if (address_obj != Py_None) {
		sym->sym.kind = DRGN_SYMBOL_ADDRESS;
		sym->sym.address =
			index_arg(address_obj, "address must be integer");
		if (sym->sym.address == (unsigned long long)-1 &&
		    PyErr_Occurred())
			goto err;
		if (parse_byteorder(byteorder, &sym->sym.little_endian) == -1)
			goto err;
	} else {
		sym->sym.kind = DRGN_SYMBOL_ENUMERATOR;
	}
	Py_INCREF(type_obj);
	sym->type_obj = type_obj;
	return sym;

err:
	Py_DECREF(sym);
	return NULL;
}

static void Symbol_dealloc(Symbol *self)
{
	Py_XDECREF(self->type_obj);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static struct drgn_error *drgn_symbol_eq(struct drgn_symbol *a,
					 struct drgn_symbol *b,
					 bool *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type type_a, type_b;

	if (a->kind != b->kind) {
		*ret = false;
		return NULL;
	}

	type_a.type = a->type;
	type_a.qualifiers = a->qualifiers;
	type_b.type = b->type;
	type_b.qualifiers = b->qualifiers;

	err = drgn_qualified_type_eq(type_a, type_b, ret);
	if (err || !*ret)
		return err;

	switch (a->kind) {
	case DRGN_SYMBOL_CONSTANT:
		switch (drgn_type_object_kind(a->type)) {
		case DRGN_OBJECT_SIGNED:
			*ret = a->svalue == b->svalue;
			break;
		case DRGN_OBJECT_UNSIGNED:
			*ret = a->uvalue == b->uvalue;
			break;
		case DRGN_OBJECT_FLOAT:
			*ret = a->fvalue == b->fvalue;
			break;
		default:
			return drgn_type_error("cannot create '%s' constant",
					       a->type);
		}
		return NULL;
	case DRGN_SYMBOL_ADDRESS:
		*ret = (a->address == b->address &&
			a->little_endian == b->little_endian);
		return NULL;
	case DRGN_SYMBOL_ENUMERATOR:
		*ret = true;
		return NULL;
	}
	DRGN_UNREACHABLE();
}

static PyObject *Symbol_richcompare(Symbol *left, PyObject *right, int op)
{
	struct drgn_error *err;
	bool clear, ret;

	if (!PyObject_TypeCheck(right, &Symbol_type) ||
	    (op != Py_EQ && op != Py_NE))
		Py_RETURN_NOTIMPLEMENTED;

	clear = set_drgn_in_python();
	err = drgn_symbol_eq(&left->sym, &((Symbol *)right)->sym, &ret);
	if (clear)
		clear_drgn_in_python();
	if (err)
		return set_drgn_error(err);
	if (op == Py_NE)
		ret = !ret;
	if (ret)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

static PyObject *Symbol_get_type(Symbol *self, void *arg)
{
	Py_INCREF(self->type_obj);
	return (PyObject *)self->type_obj;
}

static PyObject *Symbol_get_value(Symbol *self, void *arg)
{
	if (self->sym.kind != DRGN_SYMBOL_CONSTANT)
		Py_RETURN_NONE;

	switch (drgn_type_object_kind(self->sym.type)) {
	case DRGN_OBJECT_SIGNED:
		return PyLong_FromLongLong(self->sym.svalue);
	case DRGN_OBJECT_UNSIGNED:
		return PyLong_FromUnsignedLongLong(self->sym.uvalue);
	case DRGN_OBJECT_FLOAT:
		return PyFloat_FromDouble(self->sym.fvalue);
	default:
		DRGN_UNREACHABLE();
	}
}

static PyObject *Symbol_get_address(Symbol *self, void *arg)
{
	if (self->sym.kind == DRGN_SYMBOL_ADDRESS)
		return PyLong_FromUnsignedLongLong(self->sym.address);
	else
		Py_RETURN_NONE;
}

static PyObject *Symbol_get_is_enumerator(Symbol *self, void *arg)
{
	if (self->sym.kind == DRGN_SYMBOL_ENUMERATOR)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

static PyObject *Symbol_get_byteorder(Symbol *self, void *arg)
{
	if (self->sym.kind == DRGN_SYMBOL_ADDRESS)
		return byteorder_string(self->sym.little_endian);
	else
		Py_RETURN_NONE;
}

static PyGetSetDef Symbol_getset[] = {
	{"type", (getter)Symbol_get_type, NULL, drgn_Symbol_type_DOC},
	{"value", (getter)Symbol_get_value, NULL, drgn_Symbol_value_DOC},
	{"address", (getter)Symbol_get_address, NULL, drgn_Symbol_address_DOC},
	{"is_enumerator", (getter)Symbol_get_is_enumerator, NULL,
	 drgn_Symbol_is_enumerator_DOC},
	{"byteorder", (getter)Symbol_get_byteorder, NULL,
	 drgn_Symbol_byteorder_DOC},
	{},
};

PyTypeObject Symbol_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.Symbol",				/* tp_name */
	sizeof(Symbol),				/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)Symbol_dealloc,		/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	NULL,					/* tp_repr */
	NULL,					/* tp_as_number */
	NULL,					/* tp_as_sequence */
	NULL,					/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	NULL,					/* tp_str */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	drgn_Symbol_DOC,			/* tp_doc */
	NULL,					/* tp_traverse */
	NULL,					/* tp_clear */
	(richcmpfunc)Symbol_richcompare,	/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	NULL,					/* tp_methods */
	NULL,					/* tp_members */
	Symbol_getset,				/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	NULL,					/* tp_init */
	NULL,					/* tp_alloc */
	(newfunc)Symbol_new,			/* tp_new */
};
