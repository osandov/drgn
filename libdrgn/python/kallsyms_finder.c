// Copyright (c) 2023 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgn.h"
#include "drgnpy.h"
#include "kallsyms.h"
#include "modsupport.h"
#include "pyerrors.h"
#include "symbol.h"

static void KallsymsFinder_dealloc(KallsymsFinder *self)
{
	/* This can't be called if the finder has been added to the program. The
	 * program should take a reference and prevent deallocation. */
	drgn_kallsyms_destroy(self->finder);
	free(self->finder);
	Py_TYPE(self)->tp_free((PyObject *)self);
}


static PyObject *KallsymsFinder_repr(KallsymsFinder *self)
{
	return (PyObject *)PyUnicode_FromString("KallsymsFinder()");
}

static PyObject *KallsymsFinder_call(KallsymsFinder *self, PyObject *args, PyObject *kwargs)
{
	PyObject *address_obj, *name_obj;
	uint64_t address = 0;
	const char *name = NULL;
	static char *kwnames[] = {"name", "address", "one", NULL};
	unsigned int flags = 0;
	bool single;
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

	err = drgn_kallsyms_symbol_finder(name, address, flags, self->finder, &builder);
	if (err)
		goto error;

	/* We return a list regardless */
	if (single) {
		_cleanup_pydecref_ PyObject *list = PyList_New(1);
		if (!list)
			goto error;
		struct drgn_symbol* symbol = drgn_symbol_result_builder_single(&builder);
		PyObject *prog_obj = (PyObject *)container_of(self->finder->prog, Program, prog);
		PyObject *pysym = Symbol_wrap(symbol, prog_obj);
		if (!pysym)
			goto error;
		PyList_SET_ITEM(list, 0, pysym);
		return_ptr(list);
	} else {
		struct drgn_symbol **syms;
		size_t count;
		drgn_symbol_result_builder_array(&builder, &syms, &count);
		return Symbol_list_wrap(syms, count,
					container_of(self->finder->prog, Program, prog));
	}

	return NULL;
error:
	drgn_symbol_result_builder_abort(&builder);
	return err ? set_drgn_error(err) : NULL;
}

static PyObject *KallsymsFinder_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
	static char *kwnames[] = {"prog", "names", "token_table", "token_index", "num_syms",
	                          "offsets", "relative_base", "addresses", "_stext", NULL};
	struct kallsyms_locations kl;
	PyObject *prog_obj;
	struct drgn_program *prog;
	struct drgn_error *err;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OKKKKKKKK", kwnames,
					 &prog_obj, &kl.kallsyms_names, &kl.kallsyms_token_table,
					 &kl.kallsyms_token_index, &kl.kallsyms_num_syms,
					 &kl.kallsyms_offsets, &kl.kallsyms_relative_base,
					 &kl.kallsyms_addresses, &kl._stext))
		return NULL;

	if (!PyObject_TypeCheck(prog_obj, &Program_type))
		return PyErr_Format(PyExc_TypeError, "expected Program, not %s",
				    Py_TYPE(prog_obj)->tp_name);

	prog = &((Program *)prog_obj)->prog;

	struct kallsyms_finder *finder = calloc(1, sizeof(*finder));
	if (!finder)
		return set_drgn_error(&drgn_enomem);
	err = drgn_kallsyms_init(finder, prog, &kl);
	if (err)
		goto out;

	KallsymsFinder *finder_obj = call_tp_alloc(KallsymsFinder);
	if (!finder_obj) {
		drgn_kallsyms_destroy(finder);
		goto out;
	}
	finder_obj->finder = finder;
	Py_INCREF(prog_obj);
	return (PyObject *)finder_obj;
out:
	free(finder);
	return set_drgn_error(err);
}

PyTypeObject KallsymsFinder_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.KallsymsFinder",
	.tp_basicsize = sizeof(KallsymsFinder),
	.tp_dealloc = (destructor)KallsymsFinder_dealloc,
	.tp_repr = (reprfunc)KallsymsFinder_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_KallsymsFinder_DOC,
	.tp_call = (ternaryfunc)KallsymsFinder_call,
	.tp_new = KallsymsFinder_new,
};
