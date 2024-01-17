// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdarg.h>

#include "drgnpy.h"
#include "../lazy_object.h"
#include "../platform.h"
#include "../program.h"
#include "../type.h"
#include "../util.h"

/* Sentinel values for LazyObject::lazy_obj. */
static const union drgn_lazy_object drgnpy_lazy_object_evaluated;
#define DRGNPY_LAZY_OBJECT_EVALUATED ((union drgn_lazy_object *)&drgnpy_lazy_object_evaluated)
static const union drgn_lazy_object drgnpy_lazy_object_callable;
#define DRGNPY_LAZY_OBJECT_CALLABLE ((union drgn_lazy_object *)&drgnpy_lazy_object_callable)

static const char *drgn_type_kind_str(struct drgn_type *type)
{
	return drgn_type_kind_spelling[drgn_type_kind(type)];
}

DRGNPY_PUBLIC PyObject *DrgnType_wrap(struct drgn_qualified_type qualified_type)
{
	_cleanup_pydecref_ DrgnType *type_obj = call_tp_alloc(DrgnType);
	if (!type_obj)
		return NULL;
	type_obj->type = qualified_type.type;
	type_obj->qualifiers = qualified_type.qualifiers;
	Py_INCREF(DrgnType_prog(type_obj));
	type_obj->attr_cache = PyDict_New();
	if (!type_obj->attr_cache)
		return NULL;
	return (PyObject *)no_cleanup_ptr(type_obj);
}

static inline struct drgn_qualified_type DrgnType_unwrap(DrgnType *type)
{
	return (struct drgn_qualified_type){
		.type = type->type,
		.qualifiers = type->qualifiers,
	};
}

static PyObject *DrgnType_get_ptr(DrgnType *self, void *arg)
{
	return PyLong_FromVoidPtr(self->type);
}

static Program *DrgnType_get_prog(DrgnType *self, void *arg)
{
	Py_INCREF(DrgnType_prog(self));
	return DrgnType_prog(self);
}

static PyObject *DrgnType_get_kind(DrgnType *self)
{
	return PyObject_CallFunction(TypeKind_class, "k",
				     (unsigned long)drgn_type_kind(self->type));
}

static PyObject *DrgnType_get_primitive(DrgnType *self)
{
	if (drgn_type_primitive(self->type) == DRGN_NOT_PRIMITIVE_TYPE)
		Py_RETURN_NONE;
	return PyObject_CallFunction(PrimitiveType_class, "k",
				     (unsigned long)drgn_type_primitive(self->type));
}

static PyObject *DrgnType_get_qualifiers(DrgnType *self)
{
	return PyObject_CallFunction(Qualifiers_class, "k",
				     (unsigned long)self->qualifiers);
}

static PyObject *DrgnType_get_language(DrgnType *self, void *arg)
{
	return Language_wrap(drgn_type_language(self->type));
}

static PyObject *DrgnType_get_name(DrgnType *self)
{
	if (!drgn_type_has_name(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have a name",
				    drgn_type_kind_str(self->type));
	}
	return PyUnicode_FromString(drgn_type_name(self->type));
}

static PyObject *DrgnType_get_tag(DrgnType *self)
{
	const char *tag;

	if (!drgn_type_has_tag(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have a tag",
				    drgn_type_kind_str(self->type));
	}

	tag = drgn_type_tag(self->type);
	if (tag)
		return PyUnicode_FromString(tag);
	else
		Py_RETURN_NONE;
}

static PyObject *DrgnType_get_size(DrgnType *self)
{
	if (!drgn_type_has_size(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have a size",
				    drgn_type_kind_str(self->type));
	}
	if (!drgn_type_is_complete(self->type))
		Py_RETURN_NONE;
	return PyLong_FromUint64(drgn_type_size(self->type));
}

static PyObject *DrgnType_get_length(DrgnType *self)
{
	if (!drgn_type_has_length(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have a length",
				    drgn_type_kind_str(self->type));
	}
	if (drgn_type_is_complete(self->type))
		return PyLong_FromUint64(drgn_type_length(self->type));
	else
		Py_RETURN_NONE;
}

static PyObject *DrgnType_get_is_signed(DrgnType *self)
{
	if (!drgn_type_has_is_signed(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have a signedness",
				    drgn_type_kind_str(self->type));
	}
	Py_RETURN_BOOL(drgn_type_is_signed(self->type));
}

/*
 * This returns one of two static strings, so it doesn't need the attribute
 * cache.
 */
static PyObject *DrgnType_get_byteorder(DrgnType *self, void *arg)
{
	if (!drgn_type_has_little_endian(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have a byte order",
				    drgn_type_kind_str(self->type));
	}
	_Py_IDENTIFIER(little);
	_Py_IDENTIFIER(big);
	PyObject *ret =
		_PyUnicode_FromId(drgn_type_little_endian(self->type) ?
				  &PyId_little : &PyId_big);
	Py_XINCREF(ret);
	return ret;
}

static PyObject *DrgnType_get_type(DrgnType *self)
{
	if (!drgn_type_has_type(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have an underlying type",
				    drgn_type_kind_str(self->type));
	}
	if (drgn_type_kind(self->type) == DRGN_TYPE_ENUM &&
	    !drgn_type_is_complete(self->type))
		Py_RETURN_NONE;
	else
		return DrgnType_wrap(drgn_type_type(self->type));
}

static TypeMember *TypeMember_wrap(PyObject *parent,
				   struct drgn_type_member *member,
				   uint64_t bit_offset)
{
	_cleanup_pydecref_ TypeMember *py_member = call_tp_alloc(TypeMember);
	if (!py_member)
		return NULL;

	Py_INCREF(parent);
	py_member->lazy_obj.obj = parent;
	py_member->lazy_obj.lazy_obj = &member->object;
	if (member->name) {
		py_member->name = PyUnicode_FromString(member->name);
		if (!py_member->name)
			return NULL;
	} else {
		Py_INCREF(Py_None);
		py_member->name = Py_None;
	}
	py_member->bit_offset = PyLong_FromUint64(bit_offset);
	if (!py_member->bit_offset)
		return NULL;
	return_ptr(py_member);
}

static PyObject *DrgnType_get_members(DrgnType *self)
{
	if (!drgn_type_has_members(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have members",
				    drgn_type_kind_str(self->type));
	}

	if (!drgn_type_is_complete(self->type))
		Py_RETURN_NONE;

	struct drgn_type_member *members = drgn_type_members(self->type);
	size_t num_members = drgn_type_num_members(self->type);

	_cleanup_pydecref_ PyObject *members_obj = PyTuple_New(num_members);
	if (!members_obj)
		return NULL;

	for (size_t i = 0; i < num_members; i++) {
		TypeMember *item = TypeMember_wrap((PyObject *)self,
						   &members[i],
						   members[i].bit_offset);
		if (!item)
			return NULL;
		PyTuple_SET_ITEM(members_obj, i, (PyObject *)item);
	}
	return_ptr(members_obj);
}

static PyObject *DrgnType_get_enumerators(DrgnType *self)
{
	if (!drgn_type_has_enumerators(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have enumerators",
				    drgn_type_kind_str(self->type));
	}

	if (!drgn_type_is_complete(self->type))
		Py_RETURN_NONE;

	const struct drgn_type_enumerator *enumerators =
		drgn_type_enumerators(self->type);
	size_t num_enumerators = drgn_type_num_enumerators(self->type);
	bool is_signed = drgn_enum_type_is_signed(self->type);

	_cleanup_pydecref_ PyObject *enumerators_obj = PyTuple_New(num_enumerators);
	if (!enumerators_obj)
		return NULL;

	for (size_t i = 0; i < num_enumerators; i++) {
		PyObject *item;

		if (is_signed) {
			item = PyObject_CallFunction((PyObject *)&TypeEnumerator_type,
						     "sL", enumerators[i].name,
						     (long long)enumerators[i].svalue);
		} else {
			item = PyObject_CallFunction((PyObject *)&TypeEnumerator_type,
						     "sK", enumerators[i].name,
						     (unsigned long long)enumerators[i].uvalue);
		}
		if (!item)
			return NULL;
		PyTuple_SET_ITEM(enumerators_obj, i, item);
	}

	return_ptr(enumerators_obj);
}

static PyObject *DrgnType_get_parameters(DrgnType *self)
{
	if (!drgn_type_has_parameters(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have parameters",
				    drgn_type_kind_str(self->type));
	}

	struct drgn_type_parameter *parameters =
		drgn_type_parameters(self->type);
	size_t num_parameters = drgn_type_num_parameters(self->type);

	_cleanup_pydecref_ PyObject *parameters_obj =
		PyTuple_New(num_parameters);
	if (!parameters_obj)
		return NULL;

	for (size_t i = 0; i < num_parameters; i++) {
		struct drgn_type_parameter *parameter = &parameters[i];
		TypeParameter *item = call_tp_alloc(TypeParameter);
		if (!item)
			return NULL;
		PyTuple_SET_ITEM(parameters_obj, i, (PyObject *)item);
		Py_INCREF(self);
		item->lazy_obj.obj = (PyObject *)self;
		item->lazy_obj.lazy_obj = &parameter->default_argument;
		if (parameter->name) {
			item->name = PyUnicode_FromString(parameter->name);
			if (!item->name)
				return NULL;
		} else {
			Py_INCREF(Py_None);
			item->name = Py_None;
		}
	}
	return_ptr(parameters_obj);
}

static PyObject *DrgnType_get_is_variadic(DrgnType *self)
{
	if (!drgn_type_has_is_variadic(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type cannot be variadic",
				    drgn_type_kind_str(self->type));
	}
	Py_RETURN_BOOL(drgn_type_is_variadic(self->type));
}

static PyObject *DrgnType_get_template_parameters(DrgnType *self)
{
	if (!drgn_type_has_template_parameters(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have template parameters",
				    drgn_type_kind_str(self->type));
	}

	struct drgn_type_template_parameter *template_parameters =
		drgn_type_template_parameters(self->type);
	size_t num_template_parameters =
		drgn_type_num_template_parameters(self->type);

	_cleanup_pydecref_ PyObject *template_parameters_obj =
		PyTuple_New(num_template_parameters);
	if (!template_parameters_obj)
		return NULL;

	for (size_t i = 0; i < num_template_parameters; i++) {
		struct drgn_type_template_parameter *template_parameter =
			&template_parameters[i];

		TypeTemplateParameter *item =
			call_tp_alloc(TypeTemplateParameter);
		if (!item)
			return NULL;
		PyTuple_SET_ITEM(template_parameters_obj, i, (PyObject *)item);
		Py_INCREF(self);
		item->lazy_obj.obj = (PyObject *)self;
		item->lazy_obj.lazy_obj = &template_parameter->argument;
		if (template_parameter->name) {
			item->name = PyUnicode_FromString(template_parameter->name);
			if (!item->name)
				return NULL;
		} else {
			Py_INCREF(Py_None);
			item->name = Py_None;
		}
		item->is_default =
			PyBool_FromLong(template_parameter->is_default);
	}
	return_ptr(template_parameters_obj);
}

struct DrgnType_Attr {
	_Py_Identifier id;
	PyObject *(*getter)(DrgnType *);
};

#define DrgnType_ATTR(name)				\
static struct DrgnType_Attr DrgnType_attr_##name = {	\
	.id = _Py_static_string_init(#name),		\
	.getter = DrgnType_get_##name,			\
}

DrgnType_ATTR(kind);
DrgnType_ATTR(primitive);
DrgnType_ATTR(qualifiers);
DrgnType_ATTR(name);
DrgnType_ATTR(tag);
DrgnType_ATTR(size);
DrgnType_ATTR(length);
DrgnType_ATTR(is_signed);
DrgnType_ATTR(type);
DrgnType_ATTR(members);
DrgnType_ATTR(enumerators);
DrgnType_ATTR(parameters);
DrgnType_ATTR(is_variadic);
DrgnType_ATTR(template_parameters);

static int DrgnType_cache_attr(DrgnType *self, struct DrgnType_Attr *attr,
			       PyObject *value)
{
	PyObject *key = _PyUnicode_FromId(&attr->id);
	if (!key)
		return -1;
	return PyDict_SetItem(self->attr_cache, key, value);
}

static PyObject *DrgnType_getter(DrgnType *self, struct DrgnType_Attr *attr)
{
	PyObject *key = _PyUnicode_FromId(&attr->id);
	if (!key)
		return NULL;
	PyObject *value = PyDict_GetItemWithError(self->attr_cache, key);
	if (value) {
		Py_INCREF(value);
		return value;
	}
	if (PyErr_Occurred())
		return NULL;

	value = attr->getter(self);
	if (!value)
		return NULL;

	if (PyDict_SetItem(self->attr_cache, key, value) == -1) {
		Py_DECREF(value);
		return NULL;
	}
	return value;
}

static PyGetSetDef DrgnType_getset[] = {
	{"_ptr", (getter)DrgnType_get_ptr, NULL,
"Address of underlying ``struct drgn_type``.\n"
"\n"
"This is used for testing.\n"
"\n"
":vartype: int"},
	{"prog", (getter)DrgnType_get_prog, NULL, drgn_Type_prog_DOC},
	{"kind", (getter)DrgnType_getter, NULL,
	 drgn_Type_kind_DOC, &DrgnType_attr_kind},
	{"primitive", (getter)DrgnType_getter, NULL, drgn_Type_primitive_DOC,
	 &DrgnType_attr_primitive},
	{"qualifiers", (getter)DrgnType_getter, NULL, drgn_Type_qualifiers_DOC,
	 &DrgnType_attr_qualifiers},
	{"language", (getter)DrgnType_get_language, NULL,
	 drgn_Type_language_DOC},
	{"name", (getter)DrgnType_getter, NULL, drgn_Type_name_DOC,
	 &DrgnType_attr_name},
	{"tag", (getter)DrgnType_getter, NULL, drgn_Type_tag_DOC,
	 &DrgnType_attr_tag},
	{"size", (getter)DrgnType_getter, NULL, drgn_Type_size_DOC,
	 &DrgnType_attr_size},
	{"length", (getter)DrgnType_getter, NULL, drgn_Type_length_DOC,
	 &DrgnType_attr_length},
	{"is_signed", (getter)DrgnType_getter, NULL, drgn_Type_is_signed_DOC,
	 &DrgnType_attr_is_signed},
	{"byteorder", (getter)DrgnType_get_byteorder, NULL,
	 drgn_Type_byteorder_DOC},
	{"type", (getter)DrgnType_getter, NULL, drgn_Type_type_DOC,
	 &DrgnType_attr_type},
	{"members", (getter)DrgnType_getter, NULL, drgn_Type_members_DOC,
	 &DrgnType_attr_members},
	{"enumerators", (getter)DrgnType_getter, NULL,
	 drgn_Type_enumerators_DOC, &DrgnType_attr_enumerators},
	{"parameters", (getter)DrgnType_getter, NULL, drgn_Type_parameters_DOC,
	 &DrgnType_attr_parameters},
	{"is_variadic", (getter)DrgnType_getter, NULL,
	 drgn_Type_is_variadic_DOC, &DrgnType_attr_is_variadic},
	{"template_parameters", (getter)DrgnType_getter, NULL,
	 drgn_Type_template_parameters_DOC, &DrgnType_attr_template_parameters},
	{},
};

static void DrgnType_dealloc(DrgnType *self)
{
	Py_XDECREF(self->attr_cache);
	if (self->type)
		Py_DECREF(DrgnType_prog(self));
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int DrgnType_traverse(DrgnType *self, visitproc visit, void *arg)
{
	Py_VISIT(self->attr_cache);
	if (self->type)
		Py_VISIT(DrgnType_prog(self));
	return 0;
}

static int DrgnType_clear(DrgnType *self)
{
	Py_CLEAR(self->attr_cache);
	if (self->type) {
		Py_DECREF(DrgnType_prog(self));
		self->type = NULL;
	}
	return 0;
}

static int append_field(PyObject *parts, bool *first, const char *format, ...)
{
	if (!*first && append_string(parts, ", ") == -1)
		return -1;
	*first = false;

	va_list ap;
	va_start(ap, format);
	_cleanup_pydecref_ PyObject *str = PyUnicode_FromFormatV(format, ap);
	va_end(ap);
	if (!str)
		return -1;
	return PyList_Append(parts, str);
}

#define append_member(parts, type_obj, first, member) ({			\
	int _ret = 0;								\
	if (drgn_type_has_##member((type_obj)->type)) {				\
		_cleanup_pydecref_ PyObject *_obj =				\
			DrgnType_getter((type_obj), &DrgnType_attr_##member);	\
		if (_obj) {							\
			_ret = append_field((parts), (first), #member"=%R",	\
					    _obj);				\
		} else {							\
			_ret = -1;						\
		}								\
	}									\
	_ret;									\
})

static PyObject *DrgnType_repr(DrgnType *self)
{
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;

	bool first = true;
	if (append_format(parts, "prog.%s_type(",
			  drgn_type_kind_str(self->type)) == -1)
		return NULL;
	if (append_member(parts, self, &first, name) == -1)
		return NULL;
	if (append_member(parts, self, &first, tag) == -1)
		return NULL;

	if (drgn_type_kind(self->type) != DRGN_TYPE_POINTER &&
	    append_member(parts, self, &first, size) == -1)
		return NULL;
	if (append_member(parts, self, &first, is_signed) == -1)
		return NULL;
	if (append_member(parts, self, &first, type) == -1)
		return NULL;
	if (drgn_type_kind(self->type) == DRGN_TYPE_POINTER &&
	    (!drgn_type_program(self->type)->has_platform ||
	     drgn_type_size(self->type) !=
	     drgn_platform_address_size(&drgn_type_program(self->type)->platform)) &&
	    append_member(parts, self, &first, size) == -1)
		return NULL;
	if (drgn_type_has_little_endian(self->type) &&
	    (!drgn_type_program(self->type)->has_platform ||
	     drgn_type_little_endian(self->type) !=
	     drgn_platform_is_little_endian(&drgn_type_program(self->type)->platform))) {
		_cleanup_pydecref_ PyObject *obj =
			DrgnType_get_byteorder(self, NULL);
		if (!obj
		    || append_field(parts, &first, "byteorder=%R", obj) == -1)
			return NULL;
	}
	if (append_member(parts, self, &first, length) == -1)
		return NULL;
	if (append_member(parts, self, &first, members) == -1)
		return NULL;
	if (append_member(parts, self, &first, enumerators) == -1)
		return NULL;
	if (append_member(parts, self, &first, parameters) == -1)
		return NULL;
	if (append_member(parts, self, &first, is_variadic) == -1)
		return NULL;
	if (drgn_type_has_template_parameters(self->type) &&
	    drgn_type_num_template_parameters(self->type) > 0 &&
	    append_member(parts, self, &first, template_parameters) == -1)
		return NULL;
	if (self->qualifiers) {
		_cleanup_pydecref_ PyObject *obj =
			DrgnType_getter(self, &DrgnType_attr_qualifiers);
		if (!obj
		    || append_field(parts, &first, "qualifiers=%R", obj) == -1)
			return NULL;
	}
	if (drgn_type_language(self->type) !=
	    drgn_program_language(drgn_type_program(self->type))) {
		_cleanup_pydecref_ PyObject *obj = DrgnType_get_language(self, NULL);
		if (!obj
		    || append_field(parts, &first, "language=%R", obj) == -1)
			return NULL;
	}
	if (append_string(parts, ")") == -1)
		return NULL;

	return join_strings(parts);
}

static PyObject *DrgnType_str(DrgnType *self)
{
	_cleanup_free_ char *str = NULL;
	struct drgn_error *err = drgn_format_type(DrgnType_unwrap(self), &str);
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromString(str);
}

static PyObject *DrgnType_type_name(DrgnType *self)
{
	_cleanup_free_ char *str = NULL;
	struct drgn_error *err = drgn_format_type_name(DrgnType_unwrap(self),
						       &str);
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromString(str);
}

static PyObject *DrgnType_is_complete(DrgnType *self)
{
	Py_RETURN_BOOL(drgn_type_is_complete(self->type));
}

static int qualifiers_converter(PyObject *o, void *p)
{
	struct enum_arg arg = {
		.type = Qualifiers_class,
		.value = 0,
	};
	if (!enum_converter(o, &arg))
		return 0;
	*(enum drgn_qualifiers *)p = arg.value;
	return 1;
}

static PyObject *DrgnType_qualified(DrgnType *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = { "qualifiers", NULL, };
	enum drgn_qualifiers qualifiers;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&:qualified", keywords,
					 qualifiers_converter, &qualifiers))
		return NULL;

	struct drgn_qualified_type qualified_type = {
		.type = self->type,
		.qualifiers = qualifiers,
	};
	return DrgnType_wrap(qualified_type);
}

static PyObject *DrgnType_unqualified(DrgnType *self)
{
	struct drgn_qualified_type qualified_type = { .type = self->type };
	return DrgnType_wrap(qualified_type);
}

static TypeMember *DrgnType_member(DrgnType *self, PyObject *args,
				   PyObject *kwds)
{
	struct drgn_error *err;

	static char *keywords[] = {"name", NULL};
	const char *name;
	Py_ssize_t name_len;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#:member", keywords,
					 &name, &name_len))
		return NULL;

	struct drgn_type_member *member;
	uint64_t bit_offset;
	err = drgn_type_find_member_len(self->type, name, name_len, &member,
					&bit_offset);
	if (err)
		return set_drgn_error(err);
	return TypeMember_wrap((PyObject *)self, member, bit_offset);
}

static PyObject *DrgnType_has_member(DrgnType *self, PyObject *args,
				     PyObject *kwds)
{
	struct drgn_error *err;

	static char *keywords[] = {"name", NULL};
	const char *name;
	Py_ssize_t name_len;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#:has_member", keywords,
					 &name, &name_len))
		return NULL;

	bool has_member;
	err = drgn_type_has_member_len(self->type, name, name_len, &has_member);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_BOOL(has_member);
}

static PyMethodDef DrgnType_methods[] = {
	{"type_name", (PyCFunction)DrgnType_type_name, METH_NOARGS,
	 drgn_Type_type_name_DOC},
	{"is_complete", (PyCFunction)DrgnType_is_complete, METH_NOARGS,
	 drgn_Type_is_complete_DOC},
	{"qualified", (PyCFunction)DrgnType_qualified,
	 METH_VARARGS | METH_KEYWORDS, drgn_Type_qualified_DOC},
	{"unqualified", (PyCFunction)DrgnType_unqualified, METH_NOARGS,
	 drgn_Type_unqualified_DOC},
	{"member", (PyCFunction)DrgnType_member, METH_VARARGS | METH_KEYWORDS,
	 drgn_Type_member_DOC},
	{"has_member", (PyCFunction)DrgnType_has_member,
	 METH_VARARGS | METH_KEYWORDS, drgn_Type_has_member_DOC},
	{"_repr_pretty_", (PyCFunction)repr_pretty_from_str,
	 METH_VARARGS | METH_KEYWORDS},
	{},
};

PyTypeObject DrgnType_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Type",
	.tp_basicsize = sizeof(DrgnType),
	.tp_dealloc = (destructor)DrgnType_dealloc,
	.tp_repr = (reprfunc)DrgnType_repr,
	.tp_str = (reprfunc)DrgnType_str,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_Type_DOC,
	.tp_traverse = (traverseproc)DrgnType_traverse,
	.tp_clear = (inquiry)DrgnType_clear,
	.tp_methods = DrgnType_methods,
	.tp_getset = DrgnType_getset,
};

static TypeEnumerator *TypeEnumerator_new(PyTypeObject *subtype, PyObject *args,
					  PyObject *kwds)
{
	static char *keywords[] = {"name", "value", NULL};
	PyObject *name, *value;
	TypeEnumerator *enumerator;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O!:TypeEnumerator",
					 keywords, &PyUnicode_Type, &name,
					 &PyLong_Type, &value))
		return NULL;

	enumerator = (TypeEnumerator *)subtype->tp_alloc(subtype, 0);
	if (enumerator) {
		Py_INCREF(name);
		enumerator->name = name;
		Py_INCREF(value);
		enumerator->value = value;
	}
	return enumerator;
}

static void TypeEnumerator_dealloc(TypeEnumerator *self)
{
	Py_XDECREF(self->value);
	Py_XDECREF(self->name);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *TypeEnumerator_repr(TypeEnumerator *self)
{
	return PyUnicode_FromFormat("TypeEnumerator(%R, %R)", self->name,
				    self->value);
}

static Py_ssize_t TypeEnumerator_length(PyObject *self)
{
	return 2;
}

static PyObject *TypeEnumerator_item(TypeEnumerator *self, Py_ssize_t i)
{
	switch (i) {
	case 0:
		Py_INCREF(self->name);
		return self->name;
	case 1:
		Py_INCREF(self->value);
		return self->value;
	default:
		PyErr_SetString(PyExc_IndexError,
				"TypeEnumerator index out of range");
		return NULL;
	}
}

static PyObject *TypeEnumerator_richcompare(TypeEnumerator *self,
					    TypeEnumerator *other,
					    int op)
{
	int ret;

	if ((op != Py_EQ && op != Py_NE) ||
	    !PyObject_TypeCheck((PyObject *)other, &TypeEnumerator_type))
		Py_RETURN_NOTIMPLEMENTED;

	ret = PyUnicode_Compare(self->name, other->name);
	if (ret == -1 && PyErr_Occurred())
		return NULL;
	if (ret != 0)
		Py_RETURN_RICHCOMPARE(ret, 0, op);
	return PyObject_RichCompare(self->value, other->value, op);
}

static PySequenceMethods TypeEnumerator_as_sequence = {
	.sq_length = TypeEnumerator_length,
	.sq_item = (ssizeargfunc)TypeEnumerator_item,
};

static PyMemberDef TypeEnumerator_members[] = {
	{"name", T_OBJECT, offsetof(TypeEnumerator, name), READONLY,
	 drgn_TypeEnumerator_name_DOC},
	{"value", T_OBJECT, offsetof(TypeEnumerator, value), READONLY,
	 drgn_TypeEnumerator_value_DOC},
	{},
};

PyTypeObject TypeEnumerator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.TypeEnumerator",
	.tp_basicsize = sizeof(TypeEnumerator),
	.tp_dealloc = (destructor)TypeEnumerator_dealloc,
	.tp_repr = (reprfunc)TypeEnumerator_repr,
	.tp_as_sequence = &TypeEnumerator_as_sequence,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_TypeEnumerator_DOC,
	.tp_richcompare = (richcmpfunc)TypeEnumerator_richcompare,
	.tp_members = TypeEnumerator_members,
	.tp_new = (newfunc)TypeEnumerator_new,
};

static DrgnObject *DrgnType_to_absent_DrgnObject(DrgnType *type)
{
	_cleanup_pydecref_ DrgnObject *obj = DrgnObject_alloc(DrgnType_prog(type));
	if (!obj)
		return NULL;
	struct drgn_error *err =
		drgn_object_set_absent(&obj->obj, DrgnType_unwrap(type), 0);
	if (err)
		return set_drgn_error(err);
	return_ptr(obj);
}

static const char *PyType_name(PyTypeObject *type)
{
	const char *name = type->tp_name;
	const char *dot = strrchr(name, '.');
	return dot ? dot + 1 : name;
}

static DrgnObject *LazyObject_get_borrowed(LazyObject *self)
{
	if (unlikely(self->lazy_obj != DRGNPY_LAZY_OBJECT_EVALUATED)) {
		DrgnObject *obj;
		if (self->lazy_obj == DRGNPY_LAZY_OBJECT_CALLABLE) {
			PyObject *ret = PyObject_CallObject(self->obj, NULL);
			if (!ret)
				return NULL;
			if (PyObject_TypeCheck(ret, &DrgnObject_type)) {
				obj = (DrgnObject *)ret;
				if (Py_TYPE(self) ==
				    &TypeTemplateParameter_type &&
				    obj->obj.kind == DRGN_OBJECT_ABSENT) {
					Py_DECREF(ret);
					PyErr_Format(PyExc_ValueError,
						     "%s() callable must not return absent Object",
						     PyType_name(Py_TYPE(self)));
					return NULL;
				}
			} else if (PyObject_TypeCheck(ret, &DrgnType_type)) {
				obj = DrgnType_to_absent_DrgnObject((DrgnType *)ret);
				Py_DECREF(ret);
				if (!obj)
					return NULL;
			} else {
				Py_DECREF(ret);
				PyErr_Format(PyExc_TypeError,
					     "%s() callable must return Object or Type",
					     PyType_name(Py_TYPE(self)));
				return NULL;
			}
		} else {
			bool clear = false;
			/* Avoid the thread state overhead if we can. */
			if (!drgn_lazy_object_is_evaluated(self->lazy_obj))
				clear = set_drgn_in_python();
			struct drgn_error *err =
				drgn_lazy_object_evaluate(self->lazy_obj);
			if (clear)
				clear_drgn_in_python();
			if (err)
				return set_drgn_error(err);
			obj = DrgnObject_alloc(container_of(drgn_object_program(&self->lazy_obj->obj),
							    Program, prog));
			if (!obj)
				return NULL;
			err = drgn_object_copy(&obj->obj, &self->lazy_obj->obj);
			if (err) {
				Py_DECREF(obj);
				return set_drgn_error(err);
			}
		}
		Py_DECREF(self->obj);
		self->obj = (PyObject *)obj;
		self->lazy_obj = DRGNPY_LAZY_OBJECT_EVALUATED;
	}
	return (DrgnObject *)self->obj;
}

static DrgnObject *LazyObject_get(LazyObject *self, void *arg)
{
	DrgnObject *ret = LazyObject_get_borrowed(self);
	Py_XINCREF(ret);
	return ret;
}

static PyObject *LazyObject_get_type(LazyObject *self, void *arg)
{
	DrgnObject *obj = LazyObject_get_borrowed(self);
	if (!obj)
		return NULL;
	return DrgnType_wrap(drgn_object_qualified_type(&obj->obj));
}

static void LazyObject_dealloc(LazyObject *self)
{
	Py_XDECREF(self->obj);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int append_lazy_object_repr(PyObject *parts, LazyObject *self)
{
	struct drgn_error *err;

	DrgnObject *object = LazyObject_get_borrowed(self);
	if (!object)
		return -1;
	if (object->obj.kind == DRGN_OBJECT_ABSENT &&
	    !object->obj.is_bit_field) {
		_cleanup_free_ char *type_name = NULL;
		err = drgn_format_type_name(drgn_object_qualified_type(&object->obj),
					    &type_name);
		if (err) {
			set_drgn_error(err);
			return -1;
		}
		_cleanup_pydecref_ PyObject *tmp = PyUnicode_FromString(type_name);
		if (!tmp)
			return -1;
		return append_format(parts, "prog.type(%R)", tmp);
	} else {
		return append_format(parts, "%R", object);
	}
}

static int LazyObject_arg(PyObject *arg, const char *function_name,
			  bool can_be_absent, PyObject **obj_ret,
			  union drgn_lazy_object **state_ret)
{
	if (PyCallable_Check(arg)) {
		Py_INCREF(arg);
		*obj_ret = arg;
		*state_ret = DRGNPY_LAZY_OBJECT_CALLABLE;
	} else if (PyObject_TypeCheck(arg, &DrgnObject_type)) {
		if (!can_be_absent &&
		    ((DrgnObject *)arg)->obj.kind == DRGN_OBJECT_ABSENT) {
			PyErr_Format(PyExc_ValueError,
				     "%s() first argument must not be absent Object",
				     function_name);
			return -1;
		}
		Py_INCREF(arg);
		*obj_ret = arg;
		*state_ret = DRGNPY_LAZY_OBJECT_EVALUATED;
	} else if (PyObject_TypeCheck(arg, &DrgnType_type)) {
		DrgnObject *obj =
			DrgnType_to_absent_DrgnObject((DrgnType *)arg);
		if (!obj)
			return -1;
		*obj_ret = (PyObject *)obj;
		*state_ret = DRGNPY_LAZY_OBJECT_EVALUATED;
	} else {
		PyErr_Format(PyExc_TypeError,
			     "%s() first argument must be Object, Type, or callable returning Object or Type",
			     function_name);
		return -1;
	}
	return 0;
}

static TypeMember *TypeMember_new(PyTypeObject *subtype, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {"object_or_type", "name", "bit_offset", NULL};
	PyObject *object, *name = Py_None, *bit_offset = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OO!:TypeMember",
					 keywords, &object, &name,
					 &PyLong_Type, &bit_offset))
		return NULL;

	if (name != Py_None && !PyUnicode_Check(name)) {
		PyErr_SetString(PyExc_TypeError,
				"TypeMember name must be str or None");
		return NULL;
	}

	PyObject *obj;
	union drgn_lazy_object *state;
	if (LazyObject_arg(object, "TypeMember", true, &obj, &state))
		return NULL;

	_cleanup_pydecref_ TypeMember *member =
		(TypeMember *)subtype->tp_alloc(subtype, 0);
	if (!member) {
		Py_DECREF(obj);
		return NULL;
	}
	member->lazy_obj.obj = obj;
	member->lazy_obj.lazy_obj = state;
	Py_INCREF(name);
	member->name = name;
	if (bit_offset) {
		Py_INCREF(bit_offset);
	} else {
		bit_offset = PyLong_FromLong(0);
		if (!bit_offset)
			return NULL;
	}
	member->bit_offset = bit_offset;
	return_ptr(member);
}

static void TypeMember_dealloc(TypeMember *self)
{
	Py_XDECREF(self->bit_offset);
	Py_XDECREF(self->name);
	LazyObject_dealloc((LazyObject *)self);
}

static PyObject *TypeMember_get_offset(TypeMember *self, void *arg)
{
	uint64_t bit_offset = PyLong_AsUint64(self->bit_offset);
	if (bit_offset == (uint64_t)-1 && PyErr_Occurred())
		return NULL;
	if (bit_offset % 8) {
		PyErr_SetString(PyExc_ValueError,
				"member is not byte-aligned");
		return NULL;
	}
	return PyLong_FromUint64(bit_offset / 8);
}

static PyObject *TypeMember_get_bit_field_size(TypeMember *self, void *arg)
{
	DrgnObject *object = LazyObject_get_borrowed((LazyObject *)self);
	if (!object)
		return NULL;
	if (object->obj.is_bit_field)
		return PyLong_FromUint64(object->obj.bit_size);
	else
		Py_RETURN_NONE;
}

static PyObject *TypeMember_repr(TypeMember *self)
{
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;
	if (append_format(parts, "TypeMember(") < 0 ||
	    append_lazy_object_repr(parts, (LazyObject *)self) < 0)
		return NULL;
	if (self->name != Py_None &&
	    append_format(parts, ", name=%R", self->name) < 0)
		return NULL;
	/* Include the bit offset even if it is the default of 0 for clarity. */
	if (append_format(parts, ", bit_offset=%R)", self->bit_offset) < 0)
		return NULL;
	return join_strings(parts);
}

static PyMemberDef TypeMember_members[] = {
	{"name", T_OBJECT, offsetof(TypeMember, name), READONLY,
	 drgn_TypeMember_name_DOC},
	{"bit_offset", T_OBJECT, offsetof(TypeMember, bit_offset), READONLY,
	 drgn_TypeMember_bit_offset_DOC},
	{},
};

static PyGetSetDef TypeMember_getset[] = {
	{"object", (getter)LazyObject_get, NULL, drgn_TypeMember_object_DOC,
	 NULL},
	{"type", (getter)LazyObject_get_type, NULL, drgn_TypeMember_type_DOC,
	 NULL},
	{"offset", (getter)TypeMember_get_offset, NULL,
	 drgn_TypeMember_offset_DOC, NULL},
	{"bit_field_size", (getter)TypeMember_get_bit_field_size, NULL,
	 drgn_TypeMember_bit_field_size_DOC, NULL},
	{},
};

PyTypeObject TypeMember_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.TypeMember",
	.tp_basicsize = sizeof(TypeMember),
	.tp_dealloc = (destructor)TypeMember_dealloc,
	.tp_repr = (reprfunc)TypeMember_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_TypeMember_DOC,
	.tp_members = TypeMember_members,
	.tp_getset = TypeMember_getset,
	.tp_new = (newfunc)TypeMember_new,
};

static TypeParameter *TypeParameter_new(PyTypeObject *subtype, PyObject *args,
					PyObject *kwds)
{
	static char *keywords[] = {"default_argument_or_type", "name", NULL};
	PyObject *object, *name = Py_None;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O:TypeParameter",
					 keywords, &object, &name))
		return NULL;

	if (name != Py_None && !PyUnicode_Check(name)) {
		PyErr_SetString(PyExc_TypeError,
				"TypeParameter name must be str or None");
		return NULL;
	}

	PyObject *obj;
	union drgn_lazy_object *state;
	if (LazyObject_arg(object, "TypeParameter", true, &obj, &state))
		return NULL;

	TypeParameter *parameter = (TypeParameter *)subtype->tp_alloc(subtype,
								      0);
	if (!parameter) {
		Py_DECREF(obj);
		return NULL;
	}

	parameter->lazy_obj.obj = obj;
	parameter->lazy_obj.lazy_obj = state;
	Py_INCREF(name);
	parameter->name = name;
	return parameter;
}

static void TypeParameter_dealloc(TypeParameter *self)
{
	Py_XDECREF(self->name);
	LazyObject_dealloc((LazyObject *)self);
}

static PyObject *TypeParameter_repr(TypeParameter *self)
{
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;
	if (append_format(parts, "TypeParameter(") < 0 ||
	    append_lazy_object_repr(parts, (LazyObject *)self) < 0)
		return NULL;
	if (self->name != Py_None &&
	    append_format(parts, ", name=%R", self->name) < 0)
		return NULL;
	if (append_string(parts, ")") < 0)
		return NULL;
	return join_strings(parts);
}

static PyMemberDef TypeParameter_members[] = {
	{"name", T_OBJECT, offsetof(TypeParameter, name), READONLY,
	 drgn_TypeParameter_name_DOC},
	{},
};

static PyGetSetDef TypeParameter_getset[] = {
	{"default_argument", (getter)LazyObject_get, NULL,
	 drgn_TypeParameter_default_argument_DOC, NULL},
	{"type", (getter)LazyObject_get_type, NULL, drgn_TypeParameter_type_DOC,
	 NULL},
	{},
};

PyTypeObject TypeParameter_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.TypeParameter",
	.tp_basicsize = sizeof(TypeParameter),
	.tp_dealloc = (destructor)TypeParameter_dealloc,
	.tp_repr = (reprfunc)TypeParameter_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_TypeParameter_DOC,
	.tp_members = TypeParameter_members,
	.tp_getset = TypeParameter_getset,
	.tp_new = (newfunc)TypeParameter_new,
};

static TypeTemplateParameter *TypeTemplateParameter_new(PyTypeObject *subtype,
							PyObject *args,
							PyObject *kwds)
{
	static char *keywords[] = {"argument", "name", "is_default", NULL};
	PyObject *object, *name = Py_None, *is_default = Py_False;
	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					 "O|OO!:TypeTemplateParameter",
					 keywords, &object, &name, &PyBool_Type,
					 &is_default))
		return NULL;

	if (name != Py_None && !PyUnicode_Check(name)) {
		PyErr_SetString(PyExc_TypeError,
				"TypeTemplateParameter name must be str or None");
		return NULL;
	}

	PyObject *obj;
	union drgn_lazy_object *state;
	if (LazyObject_arg(object, "TypeTemplateParameter", false, &obj, &state))
		return NULL;

	TypeTemplateParameter *parameter =
		(TypeTemplateParameter *)subtype->tp_alloc(subtype, 0);
	if (!parameter) {
		Py_DECREF(obj);
		return NULL;
	}

	parameter->lazy_obj.obj = obj;
	parameter->lazy_obj.lazy_obj = state;
	Py_INCREF(name);
	parameter->name = name;
	Py_INCREF(is_default);
	parameter->is_default = is_default;
	return parameter;
}

static void TypeTemplateParameter_dealloc(TypeTemplateParameter *self)
{
	Py_XDECREF(self->is_default);
	Py_XDECREF(self->name);
	LazyObject_dealloc((LazyObject *)self);
}

static PyObject *TypeTemplateParameter_repr(TypeTemplateParameter *self)
{
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;
	if (append_format(parts, "TypeTemplateParameter(") < 0 ||
	    append_lazy_object_repr(parts, (LazyObject *)self) < 0)
		return NULL;
	if (self->name != Py_None &&
	    append_format(parts, ", name=%R", self->name) < 0)
		return NULL;
	if (self->is_default == Py_True &&
	    append_string(parts, ", is_default=True") < 0)
		return NULL;
	if (append_string(parts, ")") < 0)
		return NULL;
	return join_strings(parts);
}

static PyObject *TypeTemplateParameter_get_argument(TypeTemplateParameter *self,
						    void *arg)
{
	DrgnObject *object = LazyObject_get_borrowed((LazyObject *)self);
	if (!object)
		return NULL;
	if (object->obj.kind == DRGN_OBJECT_ABSENT) {
		return DrgnType_wrap(drgn_object_qualified_type(&object->obj));
	} else {
		Py_INCREF(object);
		return (PyObject *)object;
	}
}

static PyMemberDef TypeTemplateParameter_members[] = {
	{"name", T_OBJECT, offsetof(TypeTemplateParameter, name), READONLY,
	 drgn_TypeTemplateParameter_name_DOC},
	{"is_default", T_OBJECT, offsetof(TypeTemplateParameter, is_default),
	 READONLY, drgn_TypeTemplateParameter_is_default_DOC},
	{},
};

static PyGetSetDef TypeTemplateParameter_getset[] = {
	{"argument", (getter)TypeTemplateParameter_get_argument, NULL,
	 drgn_TypeTemplateParameter_argument_DOC, NULL},
	{},
};

PyTypeObject TypeTemplateParameter_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.TypeTemplateParameter",
	.tp_basicsize = sizeof(TypeTemplateParameter),
	.tp_dealloc = (destructor)TypeTemplateParameter_dealloc,
	.tp_repr = (reprfunc)TypeTemplateParameter_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_TypeTemplateParameter_DOC,
	.tp_members = TypeTemplateParameter_members,
	.tp_getset = TypeTemplateParameter_getset,
	.tp_new = (newfunc)TypeTemplateParameter_new,
};

DrgnType *Program_void_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = { "qualifiers", "language", NULL };
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$O&O&:void_type",
					 keywords, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	struct drgn_qualified_type qualified_type = {
		.type = drgn_void_type(&self->prog, language),
		.qualifiers = qualifiers,
	};
	return (DrgnType *)DrgnType_wrap(qualified_type);
}

struct byteorder_arg {
	bool allow_none;
	bool is_none;
	enum drgn_byte_order value;
};

static int byteorder_converter(PyObject *o, void *p)
{
	struct byteorder_arg *arg = p;

	arg->is_none = o == Py_None;
	if (arg->allow_none && o == Py_None)
		return 1;

	if (PyUnicode_Check(o)) {
		const char *s = PyUnicode_AsUTF8(o);
		if (strcmp(s, "little") == 0) {
			arg->value = DRGN_LITTLE_ENDIAN;
			return 1;
		} else if (strcmp(s, "big") == 0) {
			arg->value = DRGN_BIG_ENDIAN;
			return 1;
		}
	}
	PyErr_Format(PyExc_ValueError,
		     "expected 'little'%s 'big'%s for byteorder",
		     arg->allow_none ? "," : " or",
		     arg->allow_none ? ", or None" : "");
	return 0;
}

DrgnType *Program_int_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "is_signed", "byteorder", "qualifiers",
		"language", NULL
	};
	PyObject *name_obj;
	struct index_arg size = {};
	int is_signed;
	struct byteorder_arg byteorder = {
		.allow_none = true,
		.is_none = true,
		.value = DRGN_PROGRAM_ENDIAN,
	};
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&p|O&$O&O&:int_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 index_converter, &size, &is_signed,
					 byteorder_converter, &byteorder,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	const char *name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	if (!Program_hold_reserve(self, 1))
		return NULL;

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_int_type_create(&self->prog, name,
						      size.uvalue, is_signed,
						      byteorder.value, language,
						      &qualified_type.type);
	if (err)
		return set_drgn_error(err);

	if (drgn_type_name(qualified_type.type) == name)
		Program_hold_object(self, name_obj);

	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (drgn_type_name(qualified_type.type) == name
	    && DrgnType_cache_attr(type_obj, &DrgnType_attr_name, name_obj))
		return NULL;

	return_ptr(type_obj);
}

DrgnType *Program_bool_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "byteorder", "qualifiers", "language", NULL
	};
	PyObject *name_obj;
	struct index_arg size = {};
	struct byteorder_arg byteorder = {
		.allow_none = true,
		.is_none = true,
		.value = DRGN_PROGRAM_ENDIAN,
	};
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&|O&$O&O&:bool_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 index_converter, &size,
					 byteorder_converter, &byteorder,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	const char *name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	if (!Program_hold_reserve(self, 1))
		return NULL;

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_bool_type_create(&self->prog, name,
						       size.uvalue,
						       byteorder.value,
						       language,
						       &qualified_type.type);
	if (err)
		return set_drgn_error(err);

	if (drgn_type_name(qualified_type.type) == name)
		Program_hold_object(self, name_obj);

	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (drgn_type_name(qualified_type.type) == name
	    && DrgnType_cache_attr(type_obj, &DrgnType_attr_name, name_obj))
		return NULL;

	return_ptr(type_obj);
}

DrgnType *Program_float_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "byteorder", "qualifiers", "language", NULL
	};
	PyObject *name_obj;
	struct index_arg size = {};
	struct byteorder_arg byteorder = {
		.allow_none = true,
		.is_none = true,
		.value = DRGN_PROGRAM_ENDIAN,
	};
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&|O&$O&O&:float_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 index_converter, &size,
					 byteorder_converter, &byteorder,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	const char *name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	if (!Program_hold_reserve(self, 1))
		return NULL;

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_float_type_create(&self->prog, name,
							size.uvalue,
							byteorder.value,
							language,
							&qualified_type.type);
	if (err)
		return set_drgn_error(err);

	if (drgn_type_name(qualified_type.type) == name)
		Program_hold_object(self, name_obj);

	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (drgn_type_name(qualified_type.type) == name
	    && DrgnType_cache_attr(type_obj, &DrgnType_attr_name, name_obj))
		return NULL;

	return_ptr(type_obj);
}

static struct drgn_error *py_lazy_object_thunk_fn(struct drgn_object *res,
						  void *arg)
{
	if (!res)
		return NULL; /* Nothing to free. */
	PyGILState_guard();
	DrgnObject *obj = LazyObject_get_borrowed(arg);
	if (obj)
		return drgn_object_copy(res, &obj->obj);
	else
		return drgn_error_from_python();
}

static int lazy_object_from_py(union drgn_lazy_object *lazy_obj,
			       LazyObject *py_lazy_obj,
			       struct drgn_program *prog, bool *can_cache)
{
	if (py_lazy_obj->lazy_obj == DRGNPY_LAZY_OBJECT_EVALUATED) {
		struct drgn_object *obj = &((DrgnObject *)py_lazy_obj->obj)->obj;
		drgn_object_init(&lazy_obj->obj, drgn_object_program(obj));
		struct drgn_error *err = drgn_object_copy(&lazy_obj->obj, obj);
		if (err) {
			set_drgn_error(err);
			drgn_object_deinit(&lazy_obj->obj);
			return -1;
		}
	} else {
		drgn_lazy_object_init_thunk(lazy_obj, prog,
					    py_lazy_object_thunk_fn,
					    py_lazy_obj);
		/*
		 * We created a new thunk, so we can't reuse the passed
		 * LazyObject. Don't cache the container so we create a new one
		 * when it's accessed.
		 */
		*can_cache = false;
	}
	return 0;
}

static int unpack_member(struct drgn_compound_type_builder *builder,
			 PyObject *item, bool *can_cache)
{
	if (!PyObject_TypeCheck((PyObject *)item, &TypeMember_type)) {
		PyErr_SetString(PyExc_TypeError, "member must be TypeMember");
		return -1;
	}
	TypeMember *member = (TypeMember *)item;

	const char *name;
	if (member->name == Py_None) {
		name = NULL;
	} else {
		name = PyUnicode_AsUTF8(member->name);
		if (!name)
			return -1;
	}

	uint64_t bit_offset = PyLong_AsUint64(member->bit_offset);
	if (bit_offset == (uint64_t)-1 && PyErr_Occurred())
		return -1;

	union drgn_lazy_object object;
	if (lazy_object_from_py(&object, (LazyObject *)member,
				builder->template_builder.prog,
				can_cache) == -1)
		return -1;
	struct drgn_error *err =
		drgn_compound_type_builder_add_member(builder, &object, name,
						      bit_offset);
	if (err) {
		drgn_lazy_object_deinit(&object);
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

static int
unpack_template_parameter(struct drgn_template_parameters_builder *builder,
			  PyObject *item, bool *can_cache)
{
	if (!PyObject_TypeCheck((PyObject *)item,
				&TypeTemplateParameter_type)) {
		PyErr_SetString(PyExc_TypeError,
				"template parameter must be TypeTemplateParameter");
		return -1;
	}
	TypeTemplateParameter *parameter = (TypeTemplateParameter *)item;

	const char *name;
	if (parameter->name == Py_None) {
		name = NULL;
	} else {
		name = PyUnicode_AsUTF8(parameter->name);
		if (!name)
			return -1;
	}
	/* parameter->is_default is always a PyBool, so we can use ==. */
	bool is_default = parameter->is_default == Py_True;

	union drgn_lazy_object object;
	if (lazy_object_from_py(&object, (LazyObject *)parameter, builder->prog,
				can_cache) == -1)
		return -1;
	struct drgn_error *err =
		drgn_template_parameters_builder_add(builder, &object, name,
						     is_default);
	if (err) {
		drgn_lazy_object_deinit(&object);
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

#define compound_type_arg_format "O|O&O$OO&O&"

static DrgnType *Program_compound_type(Program *self, PyObject *args,
				       PyObject *kwds, const char *arg_format,
				       enum drgn_type_kind kind)
{
	static char *keywords[] = {
		"tag", "size", "members", "template_parameters", "qualifiers",
		"language", NULL,
	};
	PyObject *tag_obj;
	struct index_arg size = { .allow_none = true, .is_none = true };
	PyObject *members_obj = Py_None;
	PyObject *template_parameters_obj = NULL;
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_format, keywords,
					 &tag_obj, index_converter, &size,
					 &members_obj, &template_parameters_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	const char *tag;
	if (tag_obj == Py_None) {
		tag = NULL;
	} else if (PyUnicode_Check(tag_obj)) {
		tag = PyUnicode_AsUTF8(tag_obj);
		if (!tag)
			return NULL;
	} else {
		PyErr_Format(PyExc_TypeError,
			     "%s_type() tag must be str or None",
			     drgn_type_kind_spelling[kind]);
		return NULL;
	}

	_cleanup_pydecref_ PyObject *cached_members = NULL;
	size_t num_members;
	if (members_obj == Py_None) {
		if (!size.is_none) {
			PyErr_Format(PyExc_ValueError,
				     "incomplete %s type must not have size",
				     drgn_type_kind_spelling[kind]);
			return NULL;
		}
		num_members = 0;
	} else {
		if (size.is_none) {
			PyErr_Format(PyExc_ValueError, "%s type must have size",
				     drgn_type_kind_spelling[kind]);
			return NULL;
		}
		if (!PySequence_Check(members_obj)) {
			PyErr_SetString(PyExc_TypeError,
					"members must be sequence or None");
			return NULL;
		}
		cached_members = PySequence_Tuple(members_obj);
		if (!cached_members)
			return NULL;
		num_members = PyTuple_GET_SIZE(cached_members);
	}
	bool can_cache_members = true;

	_cleanup_pydecref_ PyObject *cached_template_parameters;
	if (template_parameters_obj) {
		cached_template_parameters =
			PySequence_Tuple(template_parameters_obj);
	} else {
		cached_template_parameters = PyTuple_New(0);
	}
	if (!cached_template_parameters)
		return NULL;
	size_t num_template_parameters =
		PyTuple_GET_SIZE(cached_template_parameters);
	bool can_cache_template_parameters = true;

	struct drgn_compound_type_builder builder;
	drgn_compound_type_builder_init(&builder, &self->prog, kind);
	for (size_t i = 0; i < num_members; i++) {
		if (unpack_member(&builder, PyTuple_GET_ITEM(cached_members, i),
				  &can_cache_members) == -1)
			goto err_builder;
	}
	for (size_t i = 0; i < num_template_parameters; i++) {
		if (unpack_template_parameter(&builder.template_builder,
					      PyTuple_GET_ITEM(cached_template_parameters, i),
					      &can_cache_template_parameters) == -1)
			goto err_builder;
	}

	if (!Program_hold_reserve(self,
				  (tag_obj != Py_None) +
				  (num_members > 0) +
				  (num_template_parameters > 0)))
		goto err_builder;

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_compound_type_create(&builder, tag,
							   size.uvalue,
							   members_obj != Py_None,
							   language,
							   &qualified_type.type);
	if (err) {
		set_drgn_error(err);
err_builder:
		drgn_compound_type_builder_deinit(&builder);
		return NULL;
	}

	if (tag_obj != Py_None && drgn_type_tag(qualified_type.type) == tag)
		Program_hold_object(self, tag_obj);
	if (num_members > 0)
		Program_hold_object(self, cached_members);
	if (num_template_parameters > 0)
		Program_hold_object(self, cached_template_parameters);

	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (DrgnType_cache_attr(type_obj, &DrgnType_attr_tag, tag_obj)
	    || (can_cache_members
		&& DrgnType_cache_attr(type_obj, &DrgnType_attr_members,
				       cached_members
				       ? cached_members : Py_None))
	    || (can_cache_template_parameters
		&& DrgnType_cache_attr(type_obj,
				       &DrgnType_attr_template_parameters,
				       cached_template_parameters)))
		return NULL;

	return_ptr(type_obj);
}

DrgnType *Program_struct_type(Program *self, PyObject *args, PyObject *kwds)
{
	return Program_compound_type(self, args, kwds,
				     compound_type_arg_format ":struct_type",
				     DRGN_TYPE_STRUCT);
}

DrgnType *Program_union_type(Program *self, PyObject *args, PyObject *kwds)
{
	return Program_compound_type(self, args, kwds,
				     compound_type_arg_format ":union_type",
				     DRGN_TYPE_UNION);
}

DrgnType *Program_class_type(Program *self, PyObject *args, PyObject *kwds)
{
	return Program_compound_type(self, args, kwds,
				     compound_type_arg_format ":class_type",
				     DRGN_TYPE_CLASS);
}

static int unpack_enumerator(struct drgn_enum_type_builder *builder,
			     PyObject *item, bool is_signed)
{
	if (!PyObject_TypeCheck(item, &TypeEnumerator_type)) {
		PyErr_SetString(PyExc_TypeError,
				"enumerator must be TypeEnumerator");
		return -1;
	}
	TypeEnumerator *enumerator = (TypeEnumerator *)item;

	const char *name = PyUnicode_AsUTF8(enumerator->name);
	if (!name)
		return -1;

	struct drgn_error *err;
	if (is_signed) {
		int64_t svalue = PyLong_AsInt64(enumerator->value);
		if (svalue == -1 && PyErr_Occurred())
			return -1;
		err = drgn_enum_type_builder_add_signed(builder, name, svalue);
	} else {
		uint64_t uvalue = PyLong_AsUint64(enumerator->value);
		if (uvalue == (uint64_t)-1 && PyErr_Occurred())
			return -1;
		err = drgn_enum_type_builder_add_unsigned(builder, name,
							  uvalue);
	}
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

DrgnType *Program_enum_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"tag", "type", "enumerators", "qualifiers", "language", NULL
	};
	PyObject *tag_obj;
	PyObject *compatible_type_obj = Py_None;
	PyObject *enumerators_obj = Py_None;
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OO$O&O&:enum_type",
					 keywords, &tag_obj,
					 &compatible_type_obj, &enumerators_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	const char *tag;
	if (tag_obj == Py_None) {
		tag = NULL;
	} else if (PyUnicode_Check(tag_obj)) {
		tag = PyUnicode_AsUTF8(tag_obj);
		if (!tag)
			return NULL;
	} else {
		PyErr_SetString(PyExc_TypeError,
				"enum_type() tag must be str or None");
		return NULL;
	}

	if (compatible_type_obj != Py_None &&
	    !PyObject_TypeCheck(compatible_type_obj, &DrgnType_type)) {
		PyErr_SetString(PyExc_TypeError,
				"enum_type() compatible type must be Type or None");
		return NULL;
	}

	_cleanup_pydecref_ PyObject *cached_enumerators = NULL;
	struct drgn_qualified_type qualified_type;
	struct drgn_error *err;
	if (enumerators_obj == Py_None) {
		if (compatible_type_obj != Py_None) {
			PyErr_SetString(PyExc_ValueError,
					"incomplete enum type must not have compatible type");
			return NULL;
		}

		if (!Program_hold_reserve(self, tag_obj != Py_None))
			return NULL;

		err = drgn_incomplete_enum_type_create(&self->prog, tag,
						       language,
						       &qualified_type.type);
		if (err)
			return set_drgn_error(err);
	} else {
		if (compatible_type_obj == Py_None) {
			PyErr_SetString(PyExc_ValueError,
					"enum type must have compatible type");
			return NULL;
		}
		struct drgn_type *compatible_type =
			((DrgnType *)compatible_type_obj)->type;
		if (drgn_type_kind(compatible_type) != DRGN_TYPE_INT) {
			PyErr_SetString(PyExc_ValueError,
					"enum_type() compatible type must be integer type");
			return NULL;
		}
		if (((DrgnType *)compatible_type_obj)->qualifiers) {
			PyErr_SetString(PyExc_ValueError,
					"enum_type() compatible type must be unqualified");
			return NULL;
		}

		if (!PySequence_Check(enumerators_obj)) {
			PyErr_SetString(PyExc_TypeError,
					"enumerators must be sequence or None");
			return NULL;
		}
		cached_enumerators = PySequence_Tuple(enumerators_obj);
		if (!cached_enumerators)
			return NULL;
		size_t num_enumerators = PyTuple_GET_SIZE(cached_enumerators);

		struct drgn_enum_type_builder builder;
		drgn_enum_type_builder_init(&builder, &self->prog);
		bool is_signed = drgn_type_is_signed(compatible_type);
		for (size_t i = 0; i < num_enumerators; i++) {
			if (unpack_enumerator(&builder,
					      PyTuple_GET_ITEM(cached_enumerators, i),
					      is_signed) == -1)
				return NULL;
		}

		if (!Program_hold_reserve(self, 1 + (tag_obj != Py_None)))
			goto err_builder;

		err = drgn_enum_type_create(&builder, tag, compatible_type,
					    language, &qualified_type.type);
		if (err) {
			set_drgn_error(err);
err_builder:
			drgn_enum_type_builder_deinit(&builder);
			return NULL;
		}

		Program_hold_object(self, cached_enumerators);
	}

	if (tag_obj != Py_None && drgn_type_tag(qualified_type.type) == tag)
		Program_hold_object(self, tag_obj);

	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (DrgnType_cache_attr(type_obj, &DrgnType_attr_tag, tag_obj)
	    || DrgnType_cache_attr(type_obj, &DrgnType_attr_type,
				   compatible_type_obj)
	    || DrgnType_cache_attr(type_obj, &DrgnType_attr_enumerators,
				   cached_enumerators
				   ? cached_enumerators : Py_None))
		return NULL;

	return_ptr(type_obj);
}

DrgnType *Program_typedef_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "type", "qualifiers", "language", NULL
	};
	PyObject *name_obj;
	DrgnType *aliased_type_obj;
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O!|$O&O&:typedef_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 &DrgnType_type, &aliased_type_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	const char *name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	if (!Program_hold_reserve(self, 1))
		return NULL;

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_typedef_type_create(&self->prog, name,
							  DrgnType_unwrap(aliased_type_obj),
							  language,
							  &qualified_type.type);
	if (err)
		return set_drgn_error(err);

	if (drgn_type_name(qualified_type.type) == name)
		Program_hold_object(self, name_obj);

	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (DrgnType_cache_attr(type_obj, &DrgnType_attr_type,
				(PyObject *)aliased_type_obj)
	    || DrgnType_cache_attr(type_obj, &DrgnType_attr_name, name_obj))
		return NULL;

	return_ptr(type_obj);
}

DrgnType *Program_pointer_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"type", "size", "byteorder", "qualifiers", "language", NULL
	};
	DrgnType *referenced_type_obj;
	struct index_arg size = { .allow_none = true, .is_none = true };
	struct byteorder_arg byteorder = {
		.allow_none = true,
		.is_none = true,
		.value = DRGN_PROGRAM_ENDIAN,
	};
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|O&O&$O&O&:pointer_type",
					 keywords, &DrgnType_type,
					 &referenced_type_obj, index_converter,
					 &size, byteorder_converter, &byteorder,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	if (size.is_none) {
		uint8_t address_size;
		struct drgn_error *err =
			drgn_program_address_size(&self->prog, &address_size);
		if (err)
			return set_drgn_error(err);
		size.uvalue = address_size;
	}

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_pointer_type_create(&self->prog,
							  DrgnType_unwrap(referenced_type_obj),
							  size.uvalue,
							  byteorder.value,
							  language,
							  &qualified_type.type);
	if (err)
		return set_drgn_error(err);
	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (DrgnType_cache_attr(type_obj, &DrgnType_attr_type,
				(PyObject *)referenced_type_obj))
		return NULL;

	return_ptr(type_obj);
}

DrgnType *Program_array_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"type", "length", "qualifiers", "language", NULL
	};
	DrgnType *element_type_obj;
	struct index_arg length = { .allow_none = true, .is_none = true };
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|O&$O&O&:array_type",
					 keywords, &DrgnType_type,
					 &element_type_obj, index_converter,
					 &length, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err;
	if (length.is_none) {
		err = drgn_incomplete_array_type_create(&self->prog,
							DrgnType_unwrap(element_type_obj),
							language,
							&qualified_type.type);
	} else {
		err = drgn_array_type_create(&self->prog,
					     DrgnType_unwrap(element_type_obj),
					     length.uvalue, language,
					     &qualified_type.type);
	}
	if (err)
		return set_drgn_error(err);
	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (DrgnType_cache_attr(type_obj, &DrgnType_attr_type,
				(PyObject *)element_type_obj))
		return NULL;

	return_ptr(type_obj);
}

static int unpack_parameter(struct drgn_function_type_builder *builder,
			    PyObject *item, bool *can_cache)
{
	if (!PyObject_TypeCheck(item, &TypeParameter_type)) {
		PyErr_SetString(PyExc_TypeError,
				"parameter must be TypeParameter");
		return -1;
	}
	TypeParameter *parameter = (TypeParameter *)item;

	const char *name;
	if (parameter->name == Py_None) {
		name = NULL;
	} else {
		name = PyUnicode_AsUTF8(parameter->name);
		if (!name)
			return -1;
	}

	union drgn_lazy_object default_argument;
	if (lazy_object_from_py(&default_argument, (LazyObject *)parameter,
				builder->template_builder.prog,
				can_cache) == -1)
		return -1;
	struct drgn_error *err =
		drgn_function_type_builder_add_parameter(builder,
							 &default_argument,
							 name);
	if (err) {
		drgn_lazy_object_deinit(&default_argument);
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

DrgnType *Program_function_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"type", "parameters", "is_variadic", "template_parameters",
		"qualifiers", "language", NULL,
	};
	DrgnType *return_type_obj;
	PyObject *parameters_obj;
	int is_variadic = 0;
	PyObject *template_parameters_obj = NULL;
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					 "O!O|p$OO&O&:function_type", keywords,
					 &DrgnType_type, &return_type_obj,
					 &parameters_obj, &is_variadic,
					 &template_parameters_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	if (!PySequence_Check(parameters_obj)) {
		PyErr_SetString(PyExc_TypeError, "parameters must be sequence");
		return NULL;
	}

	_cleanup_pydecref_ PyObject *cached_parameters =
		PySequence_Tuple(parameters_obj);
	if (!cached_parameters)
		return NULL;
	size_t num_parameters = PyTuple_GET_SIZE(cached_parameters);
	bool can_cache_parameters = true;

	_cleanup_pydecref_ PyObject *cached_template_parameters;
	if (template_parameters_obj) {
		cached_template_parameters =
			PySequence_Tuple(template_parameters_obj);
	} else {
		cached_template_parameters = PyTuple_New(0);
	}
	if (!cached_template_parameters)
		return NULL;
	size_t num_template_parameters =
		PyTuple_GET_SIZE(cached_template_parameters);
	bool can_cache_template_parameters = true;

	struct drgn_function_type_builder builder;
	drgn_function_type_builder_init(&builder, &self->prog);
	for (size_t i = 0; i < num_parameters; i++) {
		if (unpack_parameter(&builder,
				     PyTuple_GET_ITEM(cached_parameters, i),
				     &can_cache_parameters) == -1)
			goto err_builder;
	}
	for (size_t i = 0; i < num_template_parameters; i++) {
		if (unpack_template_parameter(&builder.template_builder,
					      PyTuple_GET_ITEM(cached_template_parameters, i),
					      &can_cache_template_parameters) == -1)
			goto err_builder;
	}

	if (!Program_hold_reserve(self,
				  (num_parameters > 0) +
				  (num_template_parameters > 0)))
		goto err_builder;

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_function_type_create(&builder,
							   DrgnType_unwrap(return_type_obj),
							   is_variadic,
							   language,
							   &qualified_type.type);
	if (err) {
		set_drgn_error(err);
err_builder:
		drgn_function_type_builder_deinit(&builder);
		return NULL;
	}

	if (num_parameters > 0)
		Program_hold_object(self, cached_parameters);
	if (num_template_parameters > 0)
		Program_hold_object(self, cached_template_parameters);

	qualified_type.qualifiers = qualifiers;
	_cleanup_pydecref_ DrgnType *type_obj =
		(DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (DrgnType_cache_attr(type_obj, &DrgnType_attr_type,
			      (PyObject *)return_type_obj)
	    || (can_cache_parameters
		&& DrgnType_cache_attr(type_obj, &DrgnType_attr_parameters,
				       cached_parameters))
	    || (can_cache_template_parameters
		&& DrgnType_cache_attr(type_obj,
				       &DrgnType_attr_template_parameters,
				       cached_template_parameters)))
		return NULL;

	return_ptr(type_obj);
}
