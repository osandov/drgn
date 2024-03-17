// Copyright (c) 2024 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../symbol.h"

static void SymbolIndex_dealloc(SymbolIndex *self)
{
	drgn_symbol_index_deinit(&self->index);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *SymbolIndex_call(SymbolIndex *self, PyObject *args, PyObject *kwargs)
{
	PyObject *prog_obj;
	struct index_arg address = { .allow_none = true };
	const char *name;
	static char *kwnames[] = {"prog", "name", "address", "one", NULL};
	int single; // 'p' format specifier expects an int, not bool

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OzO&p:__call__", kwnames,
					 &prog_obj, &name, index_converter, &address,
					 &single))
		return NULL;

	unsigned int flags = 0;
	if (single)
		flags |= DRGN_FIND_SYMBOL_ONE;
	if (!address.is_none)
		flags |= DRGN_FIND_SYMBOL_ADDR;
	if (name)
		flags |= DRGN_FIND_SYMBOL_NAME;

	struct drgn_symbol_result_builder builder;
	drgn_symbol_result_builder_init(&builder, flags & DRGN_FIND_SYMBOL_ONE);

	struct drgn_error *err =
		drgn_symbol_index_find(name, address.uvalue, flags, &self->index, &builder);
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
	} else {
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

	_cleanup_pydecref_ PyObject *iter =
		PyObject_GetIter(list_obj);
	if (!iter)
		return NULL;

	_cleanup_(drgn_symbol_index_builder_deinit)
		struct drgn_symbol_index_builder builder;
	drgn_symbol_index_builder_init(&builder);

	for (;;) {
		_cleanup_pydecref_ PyObject *item = PyIter_Next(iter);
		if (!item)
			break;
		if (!PyObject_TypeCheck(item, &Symbol_type))
			return PyErr_Format(PyExc_TypeError, "expected sequence of Symbols");
		Symbol *sym = (Symbol *)item;
		if (!drgn_symbol_index_builder_add(&builder, sym->sym))
			return PyErr_NoMemory();
	}

	if (PyErr_Occurred())
		return NULL;

	_cleanup_pydecref_ SymbolIndex *index_obj = call_tp_alloc(SymbolIndex);
	if (!index_obj)
		return NULL;

	struct drgn_error *err =
		drgn_symbol_index_init_from_builder(&index_obj->index,
						    &builder);
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
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_SymbolIndex_DOC,
	.tp_call = (ternaryfunc)SymbolIndex_call,
	.tp_new = SymbolIndex_new,
};
