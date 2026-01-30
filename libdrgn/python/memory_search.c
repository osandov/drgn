// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../error.h"

PyObject *MemorySearchIterator_wrap(PyTypeObject *type,
				    struct drgn_memory_search_iterator *it)
{
	MemorySearchIterator *ret =
		(MemorySearchIterator *)type->tp_alloc(type, 0);
	if (!ret)
		return NULL;
	struct drgn_program *prog = drgn_memory_search_iterator_program(it);
	Py_INCREF(container_of(prog, Program, prog));
	ret->it = it;
	return (PyObject *)ret;
}

static void MemorySearchIterator_dealloc(MemorySearchIterator *self)
{
	PyObject_GC_UnTrack(self);
	if (self->it) {
		struct drgn_program *prog =
			drgn_memory_search_iterator_program(self->it);
		drgn_memory_search_iterator_destroy(self->it);
		Py_DECREF(container_of(prog, Program, prog));
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int MemorySearchIterator_traverse(MemorySearchIterator *self,
					 visitproc visit, void *arg)
{
	if (self->it) {
		struct drgn_program *prog =
			drgn_memory_search_iterator_program(self->it);
		Py_VISIT(container_of(prog, Program, prog));
	}
	return 0;
}

static PyObject *MemorySearchIterator_next(MemorySearchIterator *self)
{
	struct drgn_error *err;
	uint64_t address;
	err = drgn_memory_search_iterator_next(self->it, &address, NULL, NULL);
	if (drgn_error_catch(&err, DRGN_ERROR_STOP))
		return NULL;
	else if (err)
		return set_drgn_error(err);
	return PyLong_FromUInt64(address);
}

static PyObject *MemorySearchIteratorWithBytes_next(MemorySearchIterator *self)
{
	struct drgn_error *err;
	uint64_t address;
	const void *match;
	size_t match_len;
	err = drgn_memory_search_iterator_next(self->it, &address, &match,
					       &match_len);
	if (drgn_error_catch(&err, DRGN_ERROR_STOP))
		return NULL;
	else if (err)
		return set_drgn_error(err);
	_cleanup_pydecref_ PyObject *ret = PyTuple_New(2);
	if (ret) {
		PyObject *tmp = PyLong_FromUInt64(address);
		if (!tmp)
			return NULL;
		PyTuple_SET_ITEM(ret, 0, tmp);

		tmp = PyBytes_FromStringAndSize(match, match_len);
		if (!tmp)
			return NULL;
		PyTuple_SET_ITEM(ret, 1, tmp);
	}
	return_ptr(ret);
}

static PyObject *MemorySearchIteratorWithStr_next(MemorySearchIterator *self)
{
	struct drgn_error *err;
	uint64_t address;
	const void *match;
	size_t match_len;
	err = drgn_memory_search_iterator_next(self->it, &address, &match,
					       &match_len);
	if (drgn_error_catch(&err, DRGN_ERROR_STOP))
		return NULL;
	else if (err)
		return set_drgn_error(err);
	_cleanup_pydecref_ PyObject *ret = PyTuple_New(2);
	if (ret) {
		PyObject *tmp = PyLong_FromUInt64(address);
		if (!tmp)
			return NULL;
		PyTuple_SET_ITEM(ret, 0, tmp);

		tmp = PyUnicode_FromStringAndSize(match, match_len);
		if (!tmp)
			return NULL;
		PyTuple_SET_ITEM(ret, 1, tmp);
	}
	return_ptr(ret);
}

static PyObject *MemorySearchIteratorWithInt_next(MemorySearchIterator *self)
{
	struct drgn_error *err;
	uint64_t address;
	const void *match;
	size_t match_len;
	err = drgn_memory_search_iterator_next(self->it, &address, &match,
					       &match_len);
	if (drgn_error_catch(&err, DRGN_ERROR_STOP))
		return NULL;
	else if (err)
		return set_drgn_error(err);
	_cleanup_pydecref_ PyObject *ret = PyTuple_New(2);
	if (ret) {
		PyObject *tmp = PyLong_FromUInt64(address);
		if (!tmp)
			return NULL;
		PyTuple_SET_ITEM(ret, 0, tmp);

		struct drgn_program *prog =
			drgn_memory_search_iterator_program(self->it);
		// We must know the byte order if we did an int search, so no
		// need to check has_platform.
		bool bswap = drgn_platform_bswap(&prog->platform);
		if (0) {}
#define X(bits)							\
		else if (match_len == sizeof(uint##bits##_t)) {	\
			uint##bits##_t value;			\
			memcpy(&value, match, sizeof(value));	\
			if (bswap)				\
				value = bswap_##bits(value);	\
			tmp = PyLong_FromUInt##bits(value);	\
		}
		SEARCH_MEMORY_UINT_SIZES
#undef X
		else
			assert(false);
		if (!tmp)
			return NULL;
		PyTuple_SET_ITEM(ret, 1, tmp);
	}
	return_ptr(ret);
}

static MemorySearchIterator *
MemorySearchIterator_set_address_range(MemorySearchIterator *self,
				       PyObject *args, PyObject *kwds)
{
	struct drgn_error *err;
	static char *keywords[] = {
		"min_address", "max_address", "physical", NULL
	};
	PyObject *min_address_obj = Py_None;
	PyObject *max_address_obj = Py_None;
	int physical = 0;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOp:set_address_range",
					 keywords, &min_address_obj,
					 &max_address_obj, &physical))
		return NULL;

	uint64_t min_address = 0;
	if (min_address_obj != Py_None
	    && PyLong_AsUInt64(min_address_obj, &min_address))
		return NULL;
	uint64_t max_address = UINT64_MAX;
	if (max_address_obj != Py_None
	    && PyLong_AsUInt64(max_address_obj, &max_address))
		return NULL;
	err = drgn_memory_search_iterator_set_address_range(self->it,
							    min_address,
							    max_address,
							    physical);
	if (err)
		return set_drgn_error(err);
	Py_INCREF(self);
	return self;
}

static PyMethodDef MemorySearchIterator_methods[] = {
	{"set_address_range",
	 (PyCFunction)MemorySearchIterator_set_address_range,
	 METH_VARARGS | METH_KEYWORDS,
	 drgn_MemorySearchIterator_set_address_range_DOC},
	{},
};

PyTypeObject MemorySearchIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._MemorySearchIterator",
	.tp_basicsize = sizeof(MemorySearchIterator),
	.tp_dealloc = (destructor)MemorySearchIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)MemorySearchIterator_traverse,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)MemorySearchIterator_next,
	.tp_methods = MemorySearchIterator_methods,
};

PyTypeObject MemorySearchIteratorWithBytes_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._MemorySearchIteratorWithBytes",
	.tp_basicsize = sizeof(MemorySearchIterator),
	.tp_dealloc = (destructor)MemorySearchIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)MemorySearchIterator_traverse,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)MemorySearchIteratorWithBytes_next,
	.tp_methods = MemorySearchIterator_methods,
};

PyTypeObject MemorySearchIteratorWithStr_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._MemorySearchIteratorWithStr",
	.tp_basicsize = sizeof(MemorySearchIterator),
	.tp_dealloc = (destructor)MemorySearchIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)MemorySearchIterator_traverse,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)MemorySearchIteratorWithStr_next,
	.tp_methods = MemorySearchIterator_methods,
};

PyTypeObject MemorySearchIteratorWithInt_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._MemorySearchIteratorWithInt",
	.tp_basicsize = sizeof(MemorySearchIterator),
	.tp_dealloc = (destructor)MemorySearchIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)MemorySearchIterator_traverse,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)MemorySearchIteratorWithInt_next,
	.tp_methods = MemorySearchIterator_methods,
};
