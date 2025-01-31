// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

static PyObject *DebugInfoOptions_wrap_list(const char * const *list)
{
	if (!list)
		Py_RETURN_NONE;
	size_t n = 0;
	while (list[n])
		n++;
	_cleanup_pydecref_ PyObject *ret = PyTuple_New(n);
	if (!ret)
		return NULL;
	for (size_t i = 0; i < n; i++) {
		PyObject *item = PyUnicode_FromString(list[i]);
		if (!item)
			return NULL;
		PyTuple_SET_ITEM(ret, i, item);
	}
	return_ptr(ret);
}

#define DebugInfoOptions_SETTER(name)						\
static int DebugInfoOptions_set_##name(DebugInfoOptions *self, PyObject *value,	\
				       void *arg)				\
{										\
	SETTER_NO_DELETE(#name, value);						\
	if (!DebugInfoOptions_##name##_converter(value, self->options))		\
		return -1;							\
	return 0;								\
}

#define LIST_OPTION(name)							\
static int DebugInfoOptions_##name##_converter(PyObject *o, void *p)		\
{										\
	PATH_SEQUENCE_ARG(list, .null_terminate = true);			\
	if (!path_sequence_converter(o, &list))					\
		return 0;							\
	struct drgn_error *err =						\
		drgn_debug_info_options_set_##name(p, list.paths);		\
	if (err) {								\
		set_drgn_error(err);						\
		return 0;							\
	}									\
	return 1;								\
}										\
										\
static PyObject *DebugInfoOptions_get_##name(DebugInfoOptions *self, void *arg)	\
{										\
	const char * const *list =						\
		drgn_debug_info_options_get_##name(self->options);		\
	return DebugInfoOptions_wrap_list(list);				\
}										\
DebugInfoOptions_SETTER(name)

#define BOOL_OPTION(name, default_value)					\
static int DebugInfoOptions_##name##_converter(PyObject *o, void *p)		\
{										\
	int r = PyObject_IsTrue(o);						\
	if (r < 0)								\
		return 0;							\
	drgn_debug_info_options_set_##name(p, r);				\
	return 1;								\
}										\
										\
static PyObject *DebugInfoOptions_get_##name(DebugInfoOptions *self, void *arg)	\
{										\
	Py_RETURN_BOOL(drgn_debug_info_options_get_##name(self->options));	\
}										\
DebugInfoOptions_SETTER(name)

#define drgn_kmod_search_method_class KmodSearchMethod_class

#define ENUM_OPTION(name, type, default_value)					\
static int DebugInfoOptions_##name##_converter(PyObject *o, void *p)		\
{										\
	if (!PyObject_TypeCheck(o, (PyTypeObject *)type##_class)) {		\
		PyErr_Format(PyExc_TypeError, "%s must be %s", #name,		\
			     ((PyTypeObject *)type##_class)->tp_name);		\
		return 0;							\
	}									\
	_cleanup_pydecref_ PyObject *value_obj =				\
		PyObject_GetAttrString(o, "value");				\
	if (!value_obj)								\
		return 0;							\
	long value = PyLong_AsLong(value_obj);					\
	if (value == -1 && PyErr_Occurred())					\
		return 0;							\
	drgn_debug_info_options_set_##name(p, value);				\
	return 1;								\
}										\
										\
static PyObject *DebugInfoOptions_get_##name(DebugInfoOptions *self, void *arg)	\
{										\
	return PyObject_CallFunction(type##_class, "i",				\
				     drgn_debug_info_options_get_##name(self->options));\
}										\
DebugInfoOptions_SETTER(name)

DRGN_DEBUG_INFO_OPTIONS

#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION

static inline void
drgn_debug_info_options_destroyp(struct drgn_debug_info_options **optionsp)
{
	drgn_debug_info_options_destroy(*optionsp);
}

static DebugInfoOptions *DebugInfoOptions_new(PyTypeObject *subtype,
					      PyObject *args, PyObject *kwds)
{
	struct drgn_error *err;

	_cleanup_(drgn_debug_info_options_destroyp)
	struct drgn_debug_info_options *options = NULL;
	err = drgn_debug_info_options_create(&options);
	if (err)
		return set_drgn_error(err);

	// Parse the positional options argument manually so that we can parse
	// the keyword arguments directly into the struct
	// drgn_debug_info_options.
	if (PyTuple_GET_SIZE(args) > 0) {
		PyObject *source = PyTuple_GET_ITEM(args, 0);
		if (source != Py_None) {
			if (!PyObject_TypeCheck(source,
						&DebugInfoOptions_type)) {
				PyErr_SetString(PyExc_TypeError,
						"options must be DebugInfoOptions");
				return NULL;
			}
			err = drgn_debug_info_options_copy(options,
							   ((DebugInfoOptions *)source)->options);
			if (err) {
				set_drgn_error(err);
				return NULL;
			}
		}
	}

#define BOOL_OPTION(name, default_value) LIST_OPTION(name)
#define ENUM_OPTION(name, type, default_value) LIST_OPTION(name)
	static char *keywords[] = {
		"",
#define LIST_OPTION(name) #name,
		DRGN_DEBUG_INFO_OPTIONS
#undef LIST_OPTION
		NULL,
	};
	PyObject *unused;
	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					 "|O$"
#define LIST_OPTION(name) "O&"
					 DRGN_DEBUG_INFO_OPTIONS
#undef LIST_OPTION
					 ":DebugInfoOptions", keywords, &unused
#define LIST_OPTION(name) , DebugInfoOptions_##name##_converter, options
					 DRGN_DEBUG_INFO_OPTIONS
#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION
					 ))
		return NULL;

	DebugInfoOptions *ret =
		(DebugInfoOptions *)subtype->tp_alloc(subtype, 0);
	if (ret)
		ret->options = no_cleanup_ptr(options);
	return ret;
}

static void DebugInfoOptions_dealloc(DebugInfoOptions *self)
{
	if (self->prog)
		Py_DECREF(self->prog);
	else
		drgn_debug_info_options_destroy(self->options);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyGetSetDef DebugInfoOptions_getset[] = {
#define LIST_OPTION(name)				\
	{#name, (getter)DebugInfoOptions_get_##name,	\
	 (setter)DebugInfoOptions_set_##name,		\
	 drgn_DebugInfoOptions_##name##_DOC},
#define BOOL_OPTION(name, default_value) LIST_OPTION(name)
#define ENUM_OPTION(name, type, default_value) LIST_OPTION(name)
	DRGN_DEBUG_INFO_OPTIONS
#undef ENUM_OPTION
#undef BOOL_OPTION
#undef LIST_OPTION
	{},
};

static PyObject *DebugInfoOptions_repr(PyObject *self)
{
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;
	if (append_string(parts, "DebugInfoOptions("))
		return NULL;
	bool first = true;
	for (size_t i = 0; DebugInfoOptions_getset[i].name; i++) {
		if (append_format(parts, "%s%s=", first ? "" : ", ",
				  DebugInfoOptions_getset[i].name)
		    || append_attr_repr(parts, self,
					DebugInfoOptions_getset[i].name))
			return NULL;
		first = false;
	}
	if (append_string(parts, ")"))
		return NULL;
	return join_strings(parts);
}

PyTypeObject DebugInfoOptions_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.DebugInfoOptions",
	.tp_dealloc = (destructor)DebugInfoOptions_dealloc,
	.tp_basicsize = sizeof(DebugInfoOptions),
	.tp_repr = DebugInfoOptions_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_DebugInfoOptions_DOC,
	.tp_getset = DebugInfoOptions_getset,
	.tp_new = (newfunc)DebugInfoOptions_new,
};
