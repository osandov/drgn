// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../cleanup.h"
#include "../util.h"

PyObject *ModuleSectionAddresses_class;

static ModuleSectionAddresses *ModuleSectionAddresses_new(PyTypeObject *subtype,
							  PyObject *args,
							  PyObject *kwds)
{
	static char *keywords[] = {"module", NULL};
	Module *module;
	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					 "O!:_ModuleSectionAddresses", keywords,
					 &Module_type, &module))
		return NULL;
	ModuleSectionAddresses *ret =
		(ModuleSectionAddresses *)subtype->tp_alloc(subtype, 0);
	if (ret) {
		Py_INCREF(Module_prog(module));
		ret->module = module->module;
	}
	return ret;
}

static void ModuleSectionAddresses_dealloc(ModuleSectionAddresses *self)
{
	if (self->module) {
		struct drgn_program *prog = drgn_module_program(self->module);
		Py_DECREF(container_of(prog, Program, prog));
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static inline void
drgn_module_section_address_iterator_destroyp(struct drgn_module_section_address_iterator **itp)
{
	drgn_module_section_address_iterator_destroy(*itp);
}

static PyObject *ModuleSectionAddresses_repr(ModuleSectionAddresses *self)
{
	struct drgn_error *err;

	_cleanup_(drgn_module_section_address_iterator_destroyp)
		struct drgn_module_section_address_iterator *it = NULL;
	err = drgn_module_section_address_iterator_create(self->module, &it);
	if (err)
		return set_drgn_error(err);

	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;
	if (append_string(parts, "ModuleSectionAddresses("))
		return NULL;
	bool first = true;
	for (;;) {
		const char *name;
		uint64_t address;
		err = drgn_module_section_address_iterator_next(it, &name,
								&address);
		if (err)
			return set_drgn_error(err);
		if (!name)
			break;

		_cleanup_pydecref_ PyObject *name_obj =
			PyUnicode_FromString(name);
		if (!name_obj)
			return NULL;
		if (append_format(parts, "%s%R: ", first ? "{" : ", ", name_obj)
		    || append_u64_hex(parts, address))
			return NULL;
		first = false;
	}
	if (append_string(parts, first ? ")" : "})"))
		return NULL;
	return join_strings(parts);
}

static Py_ssize_t ModuleSectionAddresses_length(ModuleSectionAddresses *self)
{
	size_t ret;
	struct drgn_error *err =
		drgn_module_num_section_addresses(self->module, &ret);
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return ret;
}

static PyObject *ModuleSectionAddresses_subscript(ModuleSectionAddresses *self,
						  PyObject *key)
{
	if (!PyUnicode_Check(key)) {
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	}
	const char *name = PyUnicode_AsUTF8(key);
	if (!name)
		return NULL;
	uint64_t address;
	struct drgn_error *err = drgn_module_get_section_address(self->module,
								 name,
								 &address);
	if (err && err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	} else if (err) {
		return set_drgn_error(err);
	}
	return PyLong_FromUint64(address);
}

static int ModuleSectionAddresses_ass_subscript(ModuleSectionAddresses *self,
						PyObject *key,
						PyObject *value)
{
	struct drgn_error *err;
	if (value) {
		if (!PyUnicode_Check(key)) {
			PyErr_SetString(PyExc_TypeError,
					"section_addresses key must be str");
			return -1;
		}
		const char *name = PyUnicode_AsUTF8(key);
		if (!name)
			return -1;
		uint64_t address = PyLong_AsUint64(value);
		if (address == (uint64_t)-1 && PyErr_Occurred())
			return -1;
		err = drgn_module_set_section_address(self->module, name,
						      address);
	} else {
		if (!PyUnicode_Check(key)) {
			PyErr_SetObject(PyExc_KeyError, key);
			return -1;
		}
		const char *name = PyUnicode_AsUTF8(key);
		if (!name)
			return -1;
		err = drgn_module_delete_section_address(self->module, name);
		if (err && err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			PyErr_SetObject(PyExc_KeyError, key);
			return -1;
		}
	}
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

static ModuleSectionAddressesIterator *
ModuleSectionAddresses_iter(ModuleSectionAddresses *self)
{
	struct drgn_error *err;
	_cleanup_pydecref_ ModuleSectionAddressesIterator *it =
		call_tp_alloc(ModuleSectionAddressesIterator);
	if (!it)
		return NULL;
	err = drgn_module_section_address_iterator_create(self->module,
							  &it->it);
	if (err)
		return set_drgn_error(err);
	struct drgn_program *prog = drgn_module_program(self->module);
	Py_INCREF(container_of(prog, Program, prog));
	return_ptr(it);
}

// We only define the bare minimum for collections.abc.MutableMapping,
// which gives us naive implementations of the remaining methods. We can
// define performance-sensitive ones as needed.
static PyMappingMethods ModuleSectionAddressesMixin_as_mapping = {
	.mp_length = (lenfunc)ModuleSectionAddresses_length,
	.mp_subscript = (binaryfunc)ModuleSectionAddresses_subscript,
	.mp_ass_subscript = (objobjargproc)ModuleSectionAddresses_ass_subscript,
};

static PyTypeObject ModuleSectionAddressesMixin_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.ModuleSectionAddressesMixin",
	.tp_dealloc = (destructor)ModuleSectionAddresses_dealloc,
	.tp_basicsize = sizeof(ModuleSectionAddresses),
	.tp_repr = (reprfunc)ModuleSectionAddresses_repr,
	.tp_as_mapping = &ModuleSectionAddressesMixin_as_mapping,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_iter = (getiterfunc)ModuleSectionAddresses_iter,
	.tp_new = (newfunc)ModuleSectionAddresses_new,
};

static void
ModuleSectionAddressesIterator_dealloc(ModuleSectionAddressesIterator *self)
{
	if (self->it) {
		struct drgn_module *module =
			drgn_module_section_address_iterator_module(self->it);
		struct drgn_program *prog = drgn_module_program(module);
		Py_DECREF(container_of(prog, Program, prog));
		drgn_module_section_address_iterator_destroy(self->it);
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
ModuleSectionAddressesIterator_next(ModuleSectionAddressesIterator *self)
{
	struct drgn_error *err;
	const char *name;
	err = drgn_module_section_address_iterator_next(self->it, &name, NULL);
	if (err)
		return set_drgn_error(err);
	if (!name)
		return NULL;
	return PyUnicode_FromString(name);
}

PyTypeObject ModuleSectionAddressesIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._ModuleSectionAddressesIterator",
	.tp_basicsize = sizeof(ModuleSectionAddressesIterator),
	.tp_dealloc = (destructor)ModuleSectionAddressesIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)ModuleSectionAddressesIterator_next,
};

int init_module_section_addresses(void)
{
	if (PyType_Ready(&ModuleSectionAddressesMixin_type))
		return -1;
	_cleanup_pydecref_ PyObject *collections_abc =
		PyImport_ImportModule("collections.abc");
	if (!collections_abc)
		return -1;
	_cleanup_pydecref_ PyObject *MutableMapping =
		PyObject_GetAttrString(collections_abc, "MutableMapping");
	if (!MutableMapping)
		return -1;
	// We can't create a direct subclass of MutableMapping from C (see
	// https://github.com/python/cpython/issues/103968). Use this multiple
	// inheritance trick taken from cpython/Modules/_decimal/_decimal.c
	// instead.
	ModuleSectionAddresses_class =
		PyObject_CallFunction((PyObject *)&PyType_Type, "s(OO){}",
				      "ModuleSectionAddresses",
				      &ModuleSectionAddressesMixin_type,
				      MutableMapping);
	if (!ModuleSectionAddresses_class)
		return -1;
	return 0;
}
