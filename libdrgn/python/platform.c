// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

PyObject *Platform_wrap(const struct drgn_platform *platform)
{
	struct drgn_error *err;
	struct drgn_platform *tmp;
	Platform *ret;

	err = drgn_platform_create(drgn_platform_arch(platform),
				   drgn_platform_flags(platform),
				   &tmp);
	if (err)
		return set_drgn_error(err);
	ret = (Platform *)Platform_type.tp_alloc(&Platform_type, 0);
	if (!ret)
		return NULL;
	ret->platform = tmp;
	return (PyObject *)ret;
}

Platform *Platform_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
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
	bool ret;

	if (!PyObject_TypeCheck(other, &Platform_type) ||
	    (op != Py_EQ && op != Py_NE))
		Py_RETURN_NOTIMPLEMENTED;
	ret = drgn_platform_eq(self->platform, ((Platform *)other)->platform);
	if (op == Py_NE)
		ret = !ret;
	if (ret)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
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

static PyObject *Platform_repr(Platform *self)
{
	PyObject *arch_obj, *flags_obj, *ret;

	arch_obj = Platform_get_arch(self, NULL);
	if (!arch_obj)
		return NULL;
	flags_obj = Platform_get_flags(self, NULL);
	if (!flags_obj) {
		Py_DECREF(arch_obj);
		return NULL;
	}
	ret = PyUnicode_FromFormat("Platform(%R, %R)", arch_obj, flags_obj);
	Py_XDECREF(flags_obj);
	Py_XDECREF(arch_obj);
	return ret;
}

static PyGetSetDef Platform_getset[] = {
	{"arch", (getter)Platform_get_arch, NULL, drgn_Platform_arch_DOC},
	{"flags", (getter)Platform_get_flags, NULL, drgn_Platform_flags_DOC},
	{},
};

PyTypeObject Platform_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.Platform",			/* tp_name */
	sizeof(Platform),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)Platform_dealloc,		/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	(reprfunc)Platform_repr,		/* tp_repr */
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
	drgn_Platform_DOC,			/* tp_doc */
	NULL,					/* tp_traverse */
	NULL,					/* tp_clear */
	(richcmpfunc)Platform_richcompare,	/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	NULL,					/* tp_methods */
	NULL,					/* tp_members */
	Platform_getset,			/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	NULL,					/* tp_init */
	NULL,					/* tp_alloc */
	(newfunc)Platform_new,			/* tp_new */
};
