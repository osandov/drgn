// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drgnpy.h"
#include "../language.h"

static PyObject *Language_repr(Language *self)
{
	return PyUnicode_FromFormat("Language.%s", self->attr_name);
}

static PyObject *Language_get_name(Language *self, void *arg)
{
	return PyUnicode_FromString(self->language->name);
}

static PyGetSetDef Language_getset[] = {
	{"name", (getter)Language_get_name, NULL, drgn_Language_name_DOC, NULL},
	{},
};

PyTypeObject Language_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Language",
	.tp_basicsize = sizeof(Language),
	.tp_repr = (reprfunc)Language_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_Language_DOC,
	.tp_getset = Language_getset,
};

static PyObject *languages_py[DRGN_NUM_LANGUAGES];

PyObject *Language_wrap(const struct drgn_language *language)
{
	PyObject *obj = languages_py[language - drgn_languages];
	Py_INCREF(obj);
	return obj;
}

int language_converter(PyObject *o, void *p)
{
	const struct drgn_language **ret = p;

	if (o == Py_None) {
		*ret = NULL;
		return 1;
	} else if (PyObject_TypeCheck(o, &Language_type)) {
		*ret = ((Language *)o)->language;
		return 1;
	} else {
		PyErr_Format(PyExc_TypeError,
			     "expected Language, not %s",
			     Py_TYPE(o)->tp_name);
		return 0;
	}
}

int add_languages(void)
{
	static const char *attr_names[] = {
		[DRGN_LANGUAGE_C] = "C",
		[DRGN_LANGUAGE_CPP] = "CPP",
	};
	size_t i;

	for (i = 0; i < DRGN_NUM_LANGUAGES; i++) {
		Language *language_obj;
		int ret;

		language_obj = (Language *)Language_type.tp_alloc(&Language_type, 0);
		if (!language_obj)
			return -1;
		language_obj->attr_name = attr_names[i];
		language_obj->language = &drgn_languages[i];
		languages_py[i] = (PyObject *)language_obj;
		ret = PyDict_SetItemString(Language_type.tp_dict, attr_names[i],
					   (PyObject *)language_obj);
		if (ret)
			return ret;
	}
	return 0;
}
