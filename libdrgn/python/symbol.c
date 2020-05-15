// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

PyObject *Symbol_wrap(struct drgn_symbol *sym, Program *prog)
{
	Symbol *ret;

	ret = (Symbol *)Symbol_type.tp_alloc(&Symbol_type, 0);
	if (ret) {
		ret->sym = sym;
		ret->prog = prog;
		Py_INCREF(prog);
	}
	return (PyObject *)ret;
}

static void Symbol_dealloc(Symbol *self)
{
	drgn_symbol_destroy(self->sym);
	Py_XDECREF(self->prog);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *Symbol_repr(Symbol *self)
{
	PyObject *tmp, *ret;
	char address[19], size[19];

	tmp = PyUnicode_FromString(drgn_symbol_name(self->sym));
	if (!tmp)
		return NULL;
	sprintf(address, "0x%" PRIx64, drgn_symbol_address(self->sym));
	sprintf(size, "0x%" PRIx64, drgn_symbol_size(self->sym));
	ret = PyUnicode_FromFormat("Symbol(name=%R, address=%s, size=%s)", tmp,
				   address, size);
	Py_DECREF(tmp);
	return ret;
}

static PyObject *Symbol_richcompare(Symbol *self, PyObject *other, int op)
{
	bool ret;

	if (!PyObject_TypeCheck(other, &Symbol_type) ||
	    (op != Py_EQ && op != Py_NE))
		Py_RETURN_NOTIMPLEMENTED;
	ret = drgn_symbol_eq(self->sym, ((Symbol *)other)->sym);
	if (op == Py_NE)
		ret = !ret;
	if (ret)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

static PyObject *Symbol_get_name(Symbol *self, void *arg)
{
	return PyUnicode_FromString(drgn_symbol_name(self->sym));
}

static PyObject *Symbol_get_address(Symbol *self, void *arg)
{
	return PyLong_FromUnsignedLongLong(drgn_symbol_address(self->sym));
}

static PyObject *Symbol_get_size(Symbol *self, void *arg)
{
	return PyLong_FromUnsignedLongLong(drgn_symbol_size(self->sym));
}

static PyGetSetDef Symbol_getset[] = {
	{"name", (getter)Symbol_get_name, NULL, drgn_Symbol_name_DOC},
	{"address", (getter)Symbol_get_address, NULL, drgn_Symbol_address_DOC},
	{"size", (getter)Symbol_get_size, NULL, drgn_Symbol_size_DOC},
	{},
};

PyTypeObject Symbol_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Symbol",
	.tp_basicsize = sizeof(Symbol),
	.tp_dealloc = (destructor)Symbol_dealloc,
	.tp_repr = (reprfunc)Symbol_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_Symbol_DOC,
	.tp_richcompare = (richcmpfunc)Symbol_richcompare,
	.tp_getset = Symbol_getset,
};
