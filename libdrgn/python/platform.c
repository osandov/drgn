// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

PyObject *Platform_wrap(const struct drgn_platform *platform)
{
	struct drgn_error *err;
	struct drgn_platform *tmp;
	err = drgn_platform_create(drgn_platform_arch(platform),
				   drgn_platform_flags(platform),
				   &tmp);
	if (err)
		return set_drgn_error(err);
	Platform *ret = call_tp_alloc(Platform);
	if (!ret)
		return NULL;
	ret->platform = tmp;
	return (PyObject *)ret;
}

static Platform *Platform_new(PyTypeObject *subtype, PyObject *args,
			      PyObject *kwds)
{
	static char *keywords[] = {"arch", "flags", NULL};
	struct enum_arg arch = { .type = Architecture_class, };
	struct enum_arg flags = {
		.type = PlatformFlags_class,
		.value = DRGN_PLATFORM_DEFAULT_FLAGS,
		.allow_none = true,
	};
	struct drgn_error *err;
	struct drgn_platform *platform;
	Platform *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&|O&:Platform", keywords,
					 enum_converter, &arch, enum_converter,
					 &flags))
		return NULL;

	err = drgn_platform_create(arch.value, flags.value, &platform);
	if (err)
		return set_drgn_error(err);
	ret = (Platform *)subtype->tp_alloc(subtype, 0);
	if (!ret) {
		drgn_platform_destroy(platform);
		return NULL;
	}
	ret->platform = platform;
	return ret;
}

static void Platform_dealloc(Platform *self)
{
	drgn_platform_destroy(self->platform);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *Platform_richcompare(Platform *self, PyObject *other, int op)
{
	if (!PyObject_TypeCheck(other, &Platform_type) ||
	    (op != Py_EQ && op != Py_NE))
		Py_RETURN_NOTIMPLEMENTED;
	bool ret = drgn_platform_eq(self->platform,
				    ((Platform *)other)->platform);
	if (op == Py_NE)
		ret = !ret;
	Py_RETURN_BOOL(ret);
}

static PyObject *Platform_get_arch(Platform *self, void *arg)
{
	return PyObject_CallFunction(Architecture_class, "k",
				     (unsigned long)drgn_platform_arch(self->platform));
}

static PyObject *Platform_get_flags(Platform *self, void *arg)
{
	return PyObject_CallFunction(PlatformFlags_class, "k",
				     (unsigned long)drgn_platform_flags(self->platform));
}

static PyObject *Platform_get_registers(Platform *self, void *arg)
{
	size_t num_registers = drgn_platform_num_registers(self->platform);
	_cleanup_pydecref_ PyObject *tuple = PyTuple_New(num_registers);
	if (!tuple)
		return NULL;
	for (size_t i = 0; i < num_registers; i++) {
		const struct drgn_register *reg =
			drgn_platform_register(self->platform, i);
		Register *item = call_tp_alloc(Register);
		if (!item)
			return NULL;
		item->reg = reg;
		PyTuple_SET_ITEM(tuple, i, (PyObject *)item);
	}
	return_ptr(tuple);
}

static PyObject *Platform_repr(Platform *self)
{
	_cleanup_pydecref_ PyObject *arch_obj = Platform_get_arch(self, NULL);
	if (!arch_obj)
		return NULL;
	_cleanup_pydecref_ PyObject *flags_obj = Platform_get_flags(self, NULL);
	if (!flags_obj)
		return NULL;
	return PyUnicode_FromFormat("Platform(%R, %R)", arch_obj, flags_obj);
}

static PyGetSetDef Platform_getset[] = {
	{"arch", (getter)Platform_get_arch, NULL, drgn_Platform_arch_DOC},
	{"flags", (getter)Platform_get_flags, NULL, drgn_Platform_flags_DOC},
	{"registers", (getter)Platform_get_registers, NULL,
	 drgn_Platform_registers_DOC},
	{},
};

PyTypeObject Platform_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Platform",
	.tp_basicsize = sizeof(Platform),
	.tp_dealloc = (destructor)Platform_dealloc,
	.tp_repr = (reprfunc)Platform_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_Platform_DOC,
	.tp_richcompare = (richcmpfunc)Platform_richcompare,
	.tp_getset = Platform_getset,
	.tp_new = (newfunc)Platform_new,
};

static PyObject *Register_richcompare(Register *self, PyObject *other, int op)
{
	if (!PyObject_TypeCheck(other, &Register_type) ||
	    (op != Py_EQ && op != Py_NE))
		Py_RETURN_NOTIMPLEMENTED;
	bool ret = self->reg == ((Register *)other)->reg;
	if (op == Py_NE)
		ret = !ret;
	Py_RETURN_BOOL(ret);
}

static PyObject *Register_get_names(Register *self, void *arg)
{
	size_t num_names;
	const char * const *names = drgn_register_names(self->reg, &num_names);
	_cleanup_pydecref_ PyObject *ret = PyTuple_New(num_names);
	for (size_t i = 0; i < num_names; i++) {
		PyObject *item = PyUnicode_FromString(names[i]);
		if (!item)
			return NULL;
		PyTuple_SET_ITEM(ret, i, item);
	}
	return_ptr(ret);
}

static PyObject *Register_repr(Register *self)
{
	_cleanup_pydecref_ PyObject *names_obj = Register_get_names(self, NULL);
	if (!names_obj)
		return NULL;
	return PyUnicode_FromFormat("Register(%R)", names_obj);
}

static PyGetSetDef Register_getset[] = {
	{"names", (getter)Register_get_names, NULL, drgn_Register_names_DOC},
	{},
};

PyTypeObject Register_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Register",
	.tp_basicsize = sizeof(Register),
	.tp_repr = (reprfunc)Register_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_Register_DOC,
	.tp_richcompare = (richcmpfunc)Register_richcompare,
	.tp_getset = Register_getset,
};
