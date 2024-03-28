// Copyright (c) 2024 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgn.h"
#include "drgnpy.h"
#include "modsupport.h"
#include "pyerrors.h"
#include "symbol.h"

static void SymbolIndex_dealloc(SymbolIndex *self)
{
	drgn_symbol_index_deinit(&self->index);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *SymbolIndex_repr(SymbolIndex *self)
{
	return (PyObject *)PyUnicode_FromString("SymbolIndex()");
}

static PyObject *SymbolIndex_call(SymbolIndex *self, PyObject *args, PyObject *kwargs)
{
	PyObject *address_obj, *name_obj;
	uint64_t address = 0;
	const char *name = NULL;
	static char *kwnames[] = {"name", "address", "one", NULL};
	unsigned int flags = 0;
	int single; // 'p' format specifier expects an int, not bool
	struct drgn_symbol_result_builder builder;
	struct drgn_error *err;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOp:__call__", kwnames,
					 &name_obj, &address_obj, &single))
		return NULL;

	flags |= single ? DRGN_FIND_SYMBOL_ONE : 0;

	if (address_obj != Py_None) {
		if (!PyLong_Check(address_obj)) {
			PyErr_SetString(PyExc_TypeError, "address: an integer is required");
			return NULL;
		}
		flags |= DRGN_FIND_SYMBOL_ADDR;
		address = PyLong_AsUint64(address_obj);
		/* Overflow check */
		if (PyErr_Occurred())
			return NULL;
	}
	if (name_obj != Py_None) {
		if (!PyUnicode_Check(name_obj)) {
			PyErr_SetString(PyExc_TypeError, "name: a string is required");
			return NULL;
		}
		flags |= DRGN_FIND_SYMBOL_NAME;
		name = PyUnicode_AsUTF8(name_obj);
	}

	drgn_symbol_result_builder_init(&builder, flags & DRGN_FIND_SYMBOL_ONE);

	err = drgn_symbol_index_find(name, address, flags, &self->index, &builder);
	if (err)
		goto error;

	/* We return a list regardless */
	if (single) {
		struct drgn_symbol *symbol = drgn_symbol_result_builder_single(&builder);
		_cleanup_pydecref_ PyObject *list = PyList_New(symbol ? 1 : 0);
		if (!list)
			goto error;
		if (symbol) {
			PyObject *pysym = Symbol_wrap(symbol, (PyObject *)self);
			if (!pysym)
				goto error;
			PyList_SET_ITEM(list, 0, pysym);
		}
		return_ptr(list);
	} else if (!single) {
		struct drgn_symbol **syms;
		size_t count;
		drgn_symbol_result_builder_array(&builder, &syms, &count);
		return Symbol_list_wrap(syms, count, (PyObject *)self);
	}

	return NULL;
error:
	drgn_symbol_result_builder_abort(&builder);
	return err ? set_drgn_error(err) : NULL;
}

static PyObject *SymbolIndex_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
	static char *kwnames[] = {"symbols", NULL};
	PyObject *list_obj;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwnames, &list_obj))
		return NULL;

	_cleanup_pydecref_ PyObject *seq_obj =
		PySequence_Fast(list_obj, "expected sequence of Symbols");
	if (!seq_obj)
		return NULL;
	size_t len = PySequence_Fast_GET_SIZE(seq_obj);
	if (len == 0)
		return PyErr_Format(PyExc_ValueError,
				    "symbol finder must contain at least one symbol");

	_cleanup_pydecref_ SymbolIndex *index_obj = call_tp_alloc(SymbolIndex);
	if (!index_obj)
		return NULL;

	struct drgn_symbol_index_builder builder;
	drgn_symbol_index_builder_init(&builder);

	for (size_t i = 0; i < len; i++) {
		PyObject *item = PySequence_Fast_GET_ITEM(list_obj, i);
		if (!PyObject_TypeCheck(item, &Symbol_type))
			return PyErr_Format(PyExc_TypeError, "expected sequence of Symbols");
		Symbol *sym = (Symbol *)item;
		if (!drgn_symbol_index_builder_add(&builder, sym->sym)) {
			drgn_symbol_index_builder_deinit(&builder);
			return PyErr_NoMemory();
		}
	}

	struct drgn_error *err =
		drgn_symbol_index_init_from_builder(&index_obj->index, &builder);
	// On error, the builder and index are already deinitialized
	if (err)
		return set_drgn_error(err);

	return (PyObject *)no_cleanup_ptr(index_obj);
}

PyTypeObject SymbolIndex_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.SymbolIndex",
	.tp_basicsize = sizeof(SymbolIndex),
	.tp_dealloc = (destructor)SymbolIndex_dealloc,
	.tp_repr = (reprfunc)SymbolIndex_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_SymbolIndex_DOC,
	.tp_call = (ternaryfunc)SymbolIndex_call,
	.tp_new = SymbolIndex_new,
};
