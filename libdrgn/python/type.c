// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include <stdarg.h>

#include "drgnpy.h"
#include "../program.h"
#include "../type.h"
#include "../util.h"

static const char *drgn_type_kind_str(struct drgn_type *type)
{
	return drgn_type_kind_spelling[drgn_type_kind(type)];
}

DRGNPY_PUBLIC PyObject *DrgnType_wrap(struct drgn_qualified_type qualified_type)
{
	DrgnType *type_obj = (DrgnType *)DrgnType_type.tp_alloc(&DrgnType_type,
								0);
	if (!type_obj)
		return NULL;
	type_obj->type = qualified_type.type;
	type_obj->qualifiers = qualified_type.qualifiers;
	Py_INCREF(DrgnType_prog(type_obj));
	type_obj->attr_cache = PyDict_New();
	if (!type_obj->attr_cache) {
		Py_DECREF(type_obj);
		return NULL;
	}
	return (PyObject *)type_obj;
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
				     drgn_type_kind(self->type));
}

static PyObject *DrgnType_get_primitive(DrgnType *self)
{
	if (drgn_type_primitive(self->type) == DRGN_NOT_PRIMITIVE_TYPE)
		Py_RETURN_NONE;
	return PyObject_CallFunction(PrimitiveType_class, "k",
				     drgn_type_primitive(self->type));
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
	return PyLong_FromUnsignedLongLong(drgn_type_size(self->type));
}

static PyObject *DrgnType_get_length(DrgnType *self)
{
	if (!drgn_type_has_length(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have a length",
				    drgn_type_kind_str(self->type));
	}
	if (drgn_type_is_complete(self->type))
		return PyLong_FromUnsignedLongLong(drgn_type_length(self->type));
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
	return PyBool_FromLong(drgn_type_is_signed(self->type));
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

static PyObject *DrgnType_get_members(DrgnType *self)
{
	PyObject *members_obj;
	struct drgn_type_member *members;
	size_t num_members, i;

	if (!drgn_type_has_members(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have members",
				    drgn_type_kind_str(self->type));
	}

	if (!drgn_type_is_complete(self->type))
		Py_RETURN_NONE;

	members = drgn_type_members(self->type);
	num_members = drgn_type_num_members(self->type);
	members_obj = PyTuple_New(num_members);
	if (!members_obj)
		return NULL;

	for (i = 0; i < num_members; i++) {
		struct drgn_type_member *member = &members[i];
		TypeMember *item;

		item = (TypeMember *)TypeMember_type.tp_alloc(&TypeMember_type,
							      0);
		if (!item)
			goto err;
		PyTuple_SET_ITEM(members_obj, i, (PyObject *)item);
		item->lazy_type.state = DRGNPY_LAZY_TYPE_UNEVALUATED;
		item->lazy_type.lazy_type = &member->type;
		if (member->name) {
			item->name = PyUnicode_FromString(member->name);
			if (!item->name)
				goto err;
		} else {
			Py_INCREF(Py_None);
			item->name = Py_None;
		}
		item->bit_offset =
			PyLong_FromUnsignedLongLong(member->bit_offset);
		if (!item->bit_offset)
			goto err;
		item->bit_field_size =
			PyLong_FromUnsignedLongLong(member->bit_field_size);
		if (!item->bit_field_size)
			goto err;
	}
	return members_obj;

err:
	Py_DECREF(members_obj);
	return NULL;
}

static PyObject *DrgnType_get_enumerators(DrgnType *self)
{
	PyObject *enumerators_obj;
	const struct drgn_type_enumerator *enumerators;
	bool is_signed;
	size_t num_enumerators, i;

	if (!drgn_type_has_enumerators(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have enumerators",
				    drgn_type_kind_str(self->type));
	}

	if (!drgn_type_is_complete(self->type))
		Py_RETURN_NONE;

	enumerators = drgn_type_enumerators(self->type);
	num_enumerators = drgn_type_num_enumerators(self->type);
	is_signed = drgn_enum_type_is_signed(self->type);

	enumerators_obj = PyTuple_New(num_enumerators);
	if (!enumerators_obj)
		return NULL;

	for (i = 0; i < num_enumerators; i++) {
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
		if (!item) {
			Py_DECREF(enumerators_obj);
			return NULL;
		}
		PyTuple_SET_ITEM(enumerators_obj, i, item);
	}

	return enumerators_obj;
}

static PyObject *DrgnType_get_parameters(DrgnType *self)
{
	PyObject *parameters_obj;
	struct drgn_type_parameter *parameters;
	size_t num_parameters, i;

	if (!drgn_type_has_parameters(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type does not have parameters",
				    drgn_type_kind_str(self->type));
	}

	parameters = drgn_type_parameters(self->type);
	num_parameters = drgn_type_num_parameters(self->type);
	parameters_obj = PyTuple_New(num_parameters);
	if (!parameters_obj)
		return NULL;

	for (i = 0; i < num_parameters; i++) {
		struct drgn_type_parameter *parameter = &parameters[i];
		TypeParameter *item;

		item = (TypeParameter *)TypeParameter_type.tp_alloc(&TypeParameter_type,
								    0);
		if (!item)
			goto err;
		PyTuple_SET_ITEM(parameters_obj, i, (PyObject *)item);
		item->lazy_type.state = DRGNPY_LAZY_TYPE_UNEVALUATED;
		item->lazy_type.lazy_type = &parameter->type;
		if (parameter->name) {
			item->name = PyUnicode_FromString(parameter->name);
			if (!item->name)
				goto err;
		} else {
			Py_INCREF(Py_None);
			item->name = Py_None;
		}
	}
	return parameters_obj;

err:
	Py_DECREF(parameters_obj);
	return NULL;
}

static PyObject *DrgnType_get_is_variadic(DrgnType *self)
{
	if (!drgn_type_has_is_variadic(self->type)) {
		return PyErr_Format(PyExc_AttributeError,
				    "%s type cannot be variadic",
				    drgn_type_kind_str(self->type));
	}
	return PyBool_FromLong(drgn_type_is_variadic(self->type));
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

static PyObject *DrgnType_getter(DrgnType *self, struct DrgnType_Attr *attr)
{
	PyObject *value;

	value = _PyDict_GetItemId(self->attr_cache, &attr->id);
	if (value) {
		Py_INCREF(value);
		return value;
	}

	value = attr->getter(self);
	if (!value)
		return NULL;

	if (_PyDict_SetItemId(self->attr_cache, &attr->id, value) == -1) {
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
	va_list ap;
	PyObject *str;
	int ret;

	if (!*first && append_string(parts, ", ") == -1)
		return -1;
	*first = false;

	va_start(ap, format);
	str = PyUnicode_FromFormatV(format, ap);
	va_end(ap);
	if (!str)
		return -1;

	ret = PyList_Append(parts, str);
	Py_DECREF(str);
	return ret;
}

#define append_member(parts, type_obj, first, member) ({			\
	int _ret = 0;								\
	PyObject *_obj;								\
										\
	if (drgn_type_has_##member((type_obj)->type)) {				\
		_obj = DrgnType_getter((type_obj), &DrgnType_attr_##member);	\
		if (_obj) {							\
			_ret = append_field((parts), (first), #member"=%R",	\
					    _obj);				\
			Py_DECREF(_obj);					\
		} else {							\
			_ret = -1;						\
		}								\
	}									\
	_ret;									\
})

_Py_IDENTIFIER(DrgnType_Repr);

/*
 * We only want to print compound types one level deep in order to avoid very
 * deep recursion. Return 0 if this is the first level, 1 if this is a deeper
 * level (and thus we shouldn't print more members), and -1 on error.
 */
static int DrgnType_ReprEnter(DrgnType *self)
{
	PyObject *dict, *key, *value;

	if (!drgn_type_has_members(self->type))
		return 0;

	dict = PyThreadState_GetDict();
	if (dict == NULL)
		return 0;
	key = _PyUnicode_FromId(&PyId_DrgnType_Repr);
	if (!key) {
		PyErr_Clear();
		return -1;
	}
	value = PyDict_GetItemWithError(dict, key);
	if (value == Py_True)
		return 1;
	if ((!value && PyErr_Occurred()) ||
	    PyDict_SetItem(dict, key, Py_True) == -1) {
		PyErr_Clear();
		return -1;
	}
	return 0;
}

/* Pair with DrgnType_ReprEnter() only if it returned 0. */
static void DrgnType_ReprLeave(DrgnType *self)
{
	PyObject *exc_type, *exc_value, *exc_traceback;
	PyObject *dict;

	if (!drgn_type_has_members(self->type))
		return;

	PyErr_Fetch(&exc_type, &exc_value, &exc_traceback);
	dict = PyThreadState_GetDict();
	if (dict)
		_PyDict_SetItemId(dict, &PyId_DrgnType_Repr, Py_False);
	PyErr_Restore(exc_type, exc_value, exc_traceback);
}

static PyObject *DrgnType_repr(DrgnType *self)
{
	PyObject *parts, *sep, *ret = NULL;
	bool first = true;
	int recursive;

	parts = PyList_New(0);
	if (!parts)
		return NULL;

	if (append_format(parts, "prog.%s_type(",
			  drgn_type_kind_str(self->type)) == -1)
		goto out;
	if (append_member(parts, self, &first, name) == -1)
		goto out;
	if (append_member(parts, self, &first, tag) == -1)
		goto out;

	recursive = DrgnType_ReprEnter(self);
	if (recursive == -1) {
		goto out;
	} else if (recursive) {
		if (append_field(parts, &first, "...)") == -1)
			goto out;
		goto join;
	}

	if (drgn_type_kind(self->type) != DRGN_TYPE_POINTER &&
	    append_member(parts, self, &first, size) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, is_signed) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, type) == -1)
		goto out_repr_leave;
	if (drgn_type_kind(self->type) == DRGN_TYPE_POINTER) {
		bool print_size;
		if (drgn_type_program(self->type)->has_platform) {
			uint8_t word_size;
			struct drgn_error *err =
				drgn_program_word_size(drgn_type_program(self->type),
						       &word_size);
			if (err) {
				set_drgn_error(err);
				goto out_repr_leave;
			}
			print_size = drgn_type_size(self->type) != word_size;
		} else {
			print_size = true;
		}
		if (print_size &&
		    append_member(parts, self, &first, size) == -1)
			goto out_repr_leave;
	}
	if (append_member(parts, self, &first, length) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, members) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, enumerators) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, parameters) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, is_variadic) == -1)
		goto out_repr_leave;
	if (self->qualifiers) {
		PyObject *obj;

		obj = DrgnType_getter(self, &DrgnType_attr_qualifiers);
		if (!obj)
			goto out_repr_leave;

		if (append_field(parts, &first, "qualifiers=%R", obj) == -1) {
			Py_DECREF(obj);
			goto out_repr_leave;
		}
		Py_DECREF(obj);
	}
	if (drgn_type_language(self->type) !=
	    drgn_program_language(drgn_type_program(self->type))) {
		PyObject *obj = DrgnType_get_language(self, NULL);
		if (append_field(parts, &first, "language=%R", obj) == -1) {
			Py_DECREF(obj);
			goto out_repr_leave;
		}
		Py_DECREF(obj);
	}
	if (append_string(parts, ")") == -1)
		goto out_repr_leave;

join:
	sep = PyUnicode_New(0, 0);
	if (!sep)
		goto out;
	ret = PyUnicode_Join(sep, parts);
	Py_DECREF(sep);
out_repr_leave:
	if (!recursive)
		DrgnType_ReprLeave(self);
out:
	Py_DECREF(parts);
	return ret;
}

static PyObject *DrgnType_str(DrgnType *self)
{
	char *str;
	struct drgn_error *err = drgn_format_type(DrgnType_unwrap(self), &str);
	if (err)
		return set_drgn_error(err);

	PyObject *ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

static PyObject *DrgnType_type_name(DrgnType *self)
{
	char *str;
	struct drgn_error *err = drgn_format_type_name(DrgnType_unwrap(self),
						       &str);
	if (err)
		return set_drgn_error(err);

	PyObject *ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

static PyObject *DrgnType_is_complete(DrgnType *self)
{
	return PyBool_FromLong(drgn_type_is_complete(self->type));
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

static PyObject *DrgnType_richcompare(DrgnType *self, PyObject *other, int op)
{
	if (!PyObject_TypeCheck(other, &DrgnType_type) ||
	    (op != Py_EQ && op != Py_NE))
		Py_RETURN_NOTIMPLEMENTED;

	bool clear = set_drgn_in_python();
	bool ret;
	struct drgn_error *err = drgn_qualified_type_eq(DrgnType_unwrap(self),
							DrgnType_unwrap((DrgnType *)other),
							&ret);
	if (clear)
		clear_drgn_in_python();
	if (err)
		return set_drgn_error(err);
	if (op == Py_NE)
		ret = !ret;
	if (ret)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
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
	.tp_richcompare = (richcmpfunc)DrgnType_richcompare,
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

Py_ssize_t TypeEnumerator_length(PyObject *self)
{
	return 2;
}

PyObject *TypeEnumerator_item(TypeEnumerator *self, Py_ssize_t i)
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

static DrgnType *LazyType_get_borrowed(LazyType *self)
{
	if (unlikely(self->state != DRGNPY_LAZY_TYPE_EVALUATED)) {
		PyObject *type;
		if (self->state == DRGNPY_LAZY_TYPE_UNEVALUATED) {
			bool clear = false;
			/* Avoid the thread state overhead if we can. */
			if (!drgn_lazy_type_is_evaluated(self->lazy_type))
				clear = set_drgn_in_python();
			struct drgn_qualified_type qualified_type;
			struct drgn_error *err =
				drgn_lazy_type_evaluate(self->lazy_type,
							&qualified_type);
			if (clear)
				clear_drgn_in_python();
			if (err)
				return set_drgn_error(err);
			type = DrgnType_wrap(qualified_type);
			if (!type)
				return NULL;
		} else { /* (self->state == DRGNPY_LAZY_TYPE_CALLABLE) */
			type = PyObject_CallObject(self->obj, NULL);
			if (!type)
				return NULL;
			if (!PyObject_TypeCheck(type, &DrgnType_type)) {
				Py_DECREF(type);
				PyErr_SetString(PyExc_TypeError,
						"type callable must return Type");
				return NULL;
			}
			Py_DECREF(self->obj);
		}
		self->state = DRGNPY_LAZY_TYPE_EVALUATED;
		self->obj = type;
	}
	return (DrgnType *)self->obj;
}

static DrgnType *LazyType_get(LazyType *self, void *arg)
{
	DrgnType *ret = LazyType_get_borrowed(self);
	Py_XINCREF(ret);
	return ret;
}

static void LazyType_dealloc(LazyType *self)
{
	if (self->state != DRGNPY_LAZY_TYPE_UNEVALUATED)
		Py_XDECREF(self->obj);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static TypeMember *TypeMember_new(PyTypeObject *subtype, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {
		"type", "name", "bit_offset", "bit_field_size", NULL
	};
	PyObject *type_arg, *name = Py_None, *bit_offset = NULL, *bit_field_size = NULL;
	int type_state;
	TypeMember *member;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OO!O!:TypeMember",
					 keywords, &type_arg, &name,
					 &PyLong_Type, &bit_offset,
					 &PyLong_Type, &bit_field_size))
		return NULL;

	if (PyCallable_Check(type_arg)) {
		type_state = DRGNPY_LAZY_TYPE_CALLABLE;
	} else if (PyObject_TypeCheck(type_arg, &DrgnType_type)) {
		type_state = DRGNPY_LAZY_TYPE_EVALUATED;
	} else {
		PyErr_SetString(PyExc_TypeError,
				"TypeMember type must be type or callable returning Type");
		return NULL;
	}

	if (name != Py_None && !PyUnicode_Check(name)) {
		PyErr_SetString(PyExc_TypeError,
				"TypeMember name must be str or None");
		return NULL;
	}

	member = (TypeMember *)subtype->tp_alloc(subtype, 0);
	if (!member)
		return NULL;

	member->lazy_type.state = type_state;
	Py_INCREF(type_arg);
	member->lazy_type.obj = type_arg;
	Py_INCREF(name);
	member->name = name;

	if (bit_offset) {
		Py_INCREF(bit_offset);
	} else {
		bit_offset = PyLong_FromLong(0);
		if (!bit_offset) {
			Py_DECREF(member);
			return NULL;
		}
	}
	member->bit_offset = bit_offset;

	if (bit_field_size) {
		Py_INCREF(bit_field_size);
	} else {
		bit_field_size = PyLong_FromLong(0);
		if (!bit_field_size) {
			Py_DECREF(member);
			return NULL;
		}
	}
	member->bit_field_size = bit_field_size;
	return member;
}

static void TypeMember_dealloc(TypeMember *self)
{
	Py_XDECREF(self->bit_field_size);
	Py_XDECREF(self->bit_offset);
	Py_XDECREF(self->name);
	LazyType_dealloc((LazyType *)self);
}

static PyObject *TypeMember_get_offset(TypeMember *self, void *arg)
{
	unsigned long long bit_offset;

	bit_offset = PyLong_AsUnsignedLongLong(self->bit_offset);
	if (bit_offset == (unsigned long long)-1 && PyErr_Occurred())
		return NULL;
	if (bit_offset % 8) {
		PyErr_SetString(PyExc_ValueError,
				"member is not byte-aligned");
		return NULL;
	}
	return PyLong_FromUnsignedLongLong(bit_offset / 8);
}

static PyObject *TypeMember_repr(TypeMember *self)
{
	DrgnType *type;
	int ret;

	type = LazyType_get_borrowed((LazyType *)self);
	if (!type)
		return NULL;
	ret = PyObject_IsTrue(self->bit_field_size);
	if (ret == -1)
		return NULL;
	if (ret) {
		return PyUnicode_FromFormat("TypeMember(type=%R, name=%R, bit_offset=%R, bit_field_size=%R)",
					    type, self->name, self->bit_offset,
					    self->bit_field_size);
	} else {
		return PyUnicode_FromFormat("TypeMember(type=%R, name=%R, bit_offset=%R)",
					    type, self->name, self->bit_offset);
	}
}

static PyObject *TypeMember_richcompare(TypeMember *self, TypeMember *other,
					int op)
{
	DrgnType *self_type, *other_type;
	PyObject *self_key, *other_key, *ret;

	if ((op != Py_EQ && op != Py_NE) ||
	    !PyObject_TypeCheck((PyObject *)other, &TypeMember_type))
		Py_RETURN_NOTIMPLEMENTED;

	self_type = LazyType_get_borrowed((LazyType *)self);
	if (!self_type)
		return NULL;
	other_type = LazyType_get_borrowed((LazyType *)other);
	if (!other_type)
		return NULL;

	self_key = Py_BuildValue("OOOO", self_type, self->name,
				 self->bit_offset, self->bit_field_size);
	if (!self_key)
		return NULL;

	other_key = Py_BuildValue("OOOO", other_type, other->name,
				  other->bit_offset, other->bit_field_size);
	if (!other_key) {
		Py_DECREF(self_key);
		return NULL;
	}

	ret = PyObject_RichCompare(self_key, other_key, op);
	Py_DECREF(other_key);
	Py_DECREF(self_key);
	return ret;
}

static PyMemberDef TypeMember_members[] = {
	{"name", T_OBJECT, offsetof(TypeMember, name), READONLY,
	 drgn_TypeMember_name_DOC},
	{"bit_offset", T_OBJECT, offsetof(TypeMember, bit_offset), READONLY,
	 drgn_TypeMember_bit_offset_DOC},
	{"bit_field_size", T_OBJECT, offsetof(TypeMember, bit_field_size),
	 READONLY, drgn_TypeMember_bit_field_size_DOC},
	{},
};

static PyGetSetDef TypeMember_getset[] = {
	{"type", (getter)LazyType_get, NULL, drgn_TypeMember_type_DOC, NULL},
	{"offset", (getter)TypeMember_get_offset, NULL,
	 drgn_TypeMember_offset_DOC, NULL},
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
	.tp_richcompare = (richcmpfunc)TypeMember_richcompare,
	.tp_members = TypeMember_members,
	.tp_getset = TypeMember_getset,
	.tp_new = (newfunc)TypeMember_new,
};

static TypeParameter *TypeParameter_new(PyTypeObject *subtype, PyObject *args,
					PyObject *kwds)
{
	static char *keywords[] = {"type", "name", NULL};
	PyObject *type_arg, *name = Py_None;
	int type_state;
	TypeParameter *parameter;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O:TypeParameter",
					 keywords, &type_arg, &name))
		return NULL;

	if (PyCallable_Check(type_arg)) {
		type_state = DRGNPY_LAZY_TYPE_CALLABLE;
	} else if (PyObject_TypeCheck(type_arg, &DrgnType_type)) {
		type_state = DRGNPY_LAZY_TYPE_EVALUATED;
	} else {
		PyErr_SetString(PyExc_TypeError,
				"TypeParameter type must be type or callable returning Type");
		return NULL;
	}

	if (name != Py_None && !PyUnicode_Check(name)) {
		PyErr_SetString(PyExc_TypeError,
				"TypeParameter name must be str or None");
		return NULL;
	}

	parameter = (TypeParameter *)subtype->tp_alloc(subtype, 0);
	if (parameter) {
		parameter->lazy_type.state = type_state;
		Py_INCREF(type_arg);
		parameter->lazy_type.obj = type_arg;
		Py_INCREF(name);
		parameter->name = name;
	}
	return parameter;
}

static void TypeParameter_dealloc(TypeParameter *self)
{
	Py_XDECREF(self->name);
	LazyType_dealloc((LazyType *)self);
}

static PyObject *TypeParameter_repr(TypeParameter *self)
{
	DrgnType *type;

	type = LazyType_get_borrowed((LazyType *)self);
	if (!type)
		return NULL;
	return PyUnicode_FromFormat("TypeParameter(type=%R, name=%R)", type,
				    self->name);
}

static PyObject *TypeParameter_richcompare(TypeParameter *self, TypeParameter *other,
					int op)
{
	DrgnType *self_type, *other_type;
	PyObject *self_key, *other_key, *ret;

	if ((op != Py_EQ && op != Py_NE) ||
	    !PyObject_TypeCheck((PyObject *)other, &TypeParameter_type))
		Py_RETURN_NOTIMPLEMENTED;

	self_type = LazyType_get_borrowed((LazyType *)self);
	if (!self_type)
		return NULL;
	other_type = LazyType_get_borrowed((LazyType *)other);
	if (!other_type)
		return NULL;

	self_key = Py_BuildValue("OO", self_type, self->name);
	if (!self_key)
		return NULL;

	other_key = Py_BuildValue("OO", other_type, other->name);
	if (!other_key) {
		Py_DECREF(self_key);
		return NULL;
	}

	ret = PyObject_RichCompare(self_key, other_key, op);
	Py_DECREF(other_key);
	Py_DECREF(self_key);
	return ret;
}

static PyMemberDef TypeParameter_members[] = {
	{"name", T_OBJECT, offsetof(TypeParameter, name), READONLY,
	 drgn_TypeParameter_name_DOC},
	{},
};

static PyGetSetDef TypeParameter_getset[] = {
	{"type", (getter)LazyType_get, NULL, drgn_TypeParameter_type_DOC, NULL},
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
	.tp_richcompare = (richcmpfunc)TypeParameter_richcompare,
	.tp_members = TypeParameter_members,
	.tp_getset = TypeParameter_getset,
	.tp_new = (newfunc)TypeParameter_new,
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

DrgnType *Program_int_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "is_signed", "qualifiers", "language", NULL
	};
	PyObject *name_obj;
	struct index_arg size = {};
	int is_signed;
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&p|$O&O&:int_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 index_converter, &size, &is_signed,
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
						      language,
						      &qualified_type.type);
	if (err)
		return set_drgn_error(err);

	if (drgn_type_name(qualified_type.type) == name)
		Program_hold_object(self, name_obj);

	qualified_type.qualifiers = qualifiers;
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (drgn_type_name(qualified_type.type) == name &&
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

DrgnType *Program_bool_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "qualifiers", "language", NULL
	};
	PyObject *name_obj;
	struct index_arg size = {};
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&|$O&O&:bool_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 index_converter, &size,
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
						       size.uvalue, language,
						       &qualified_type.type);
	if (err)
		return set_drgn_error(err);

	if (drgn_type_name(qualified_type.type) == name)
		Program_hold_object(self, name_obj);

	qualified_type.qualifiers = qualifiers;
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (drgn_type_name(qualified_type.type) == name &&
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

DrgnType *Program_float_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "qualifiers", "language", NULL
	};
	PyObject *name_obj;
	struct index_arg size = {};
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&|$O&O&:float_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 index_converter, &size,
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
							size.uvalue, language,
							&qualified_type.type);
	if (err)
		return set_drgn_error(err);

	if (drgn_type_name(qualified_type.type) == name)
		Program_hold_object(self, name_obj);

	qualified_type.qualifiers = qualifiers;
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (drgn_type_name(qualified_type.type) == name &&
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

DrgnType *Program_complex_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "type", "qualifiers", "language", NULL
	};
	PyObject *name_obj;
	struct index_arg size = {};
	DrgnType *real_type_obj;
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					 "O!O&O!|$O&O&:complex_type", keywords,
					 &PyUnicode_Type, &name_obj,
					 index_converter, &size, &DrgnType_type,
					 &real_type_obj, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	const char *name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	struct drgn_type *real_type = real_type_obj->type;
	if (drgn_type_kind(real_type) != DRGN_TYPE_FLOAT &&
	    drgn_type_kind(real_type) != DRGN_TYPE_INT) {
		PyErr_SetString(PyExc_ValueError,
				"complex_type() real type must be floating-point or integer type");
		return NULL;
	}
	if (real_type_obj->qualifiers) {
		PyErr_SetString(PyExc_ValueError,
				"complex_type() real type must be unqualified");
		return NULL;
	}

	if (!Program_hold_reserve(self, 1))
		return NULL;

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_complex_type_create(&self->prog, name,
							  size.uvalue,
							  real_type, language,
							  &qualified_type.type);
	if (err)
		return set_drgn_error(err);

	if (drgn_type_name(qualified_type.type) == name)
		Program_hold_object(self, name_obj);

	qualified_type.qualifiers = qualifiers;
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_type.id,
			      (PyObject *)real_type_obj) == -1 ||
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

struct py_type_thunk {
	struct drgn_type_thunk thunk;
	LazyType *lazy_type;
};

static struct drgn_error *
py_type_thunk_evaluate_fn(struct drgn_type_thunk *thunk,
			  struct drgn_qualified_type *ret)
{
	struct py_type_thunk *t = container_of(thunk, struct py_type_thunk, thunk);
	PyGILState_STATE gstate = PyGILState_Ensure();
	DrgnType *type = LazyType_get_borrowed(t->lazy_type);
	struct drgn_error *err;
	if (type) {
		ret->type = type->type;
		ret->qualifiers = type->qualifiers;
		err = NULL;
	} else {
		err = drgn_error_from_python();
	}
	PyGILState_Release(gstate);
	return err;
}

static void py_type_thunk_free_fn(struct drgn_type_thunk *thunk)
{
	free(container_of(thunk, struct py_type_thunk, thunk));
}

static int lazy_type_from_py(struct drgn_lazy_type *lazy_type, LazyType *obj,
			     struct drgn_program *prog, bool *can_cache)
{
	if (obj->state == DRGNPY_LAZY_TYPE_EVALUATED) {
		DrgnType *type = (DrgnType *)obj->obj;
		drgn_lazy_type_init_evaluated(lazy_type, type->type,
					      type->qualifiers);
	} else {
		struct py_type_thunk *thunk = malloc(sizeof(*thunk));
		if (!thunk) {
			PyErr_NoMemory();
			return -1;
		}
		thunk->thunk.prog = prog;
		thunk->thunk.evaluate_fn = py_type_thunk_evaluate_fn;
		thunk->thunk.free_fn = py_type_thunk_free_fn;
		thunk->lazy_type = obj;
		drgn_lazy_type_init_thunk(lazy_type, &thunk->thunk);
		/*
		 * We created a new thunk, so we can't reuse the passed
		 * LazyType. Don't cache the container so we create a new one
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

	unsigned long long bit_offset =
		PyLong_AsUnsignedLongLong(member->bit_offset);
	if (bit_offset == (unsigned long long)-1 && PyErr_Occurred())
		return -1;
	unsigned long long bit_field_size =
		PyLong_AsUnsignedLongLong(member->bit_field_size);
	if (bit_field_size == (unsigned long long)-1 && PyErr_Occurred())
		return -1;

	struct drgn_lazy_type member_type;
	if (lazy_type_from_py(&member_type, (LazyType *)member,
			      builder->prog, can_cache) == -1)
		return -1;
	struct drgn_error *err =
		drgn_compound_type_builder_add_member(builder, member_type,
						      name, bit_offset,
						      bit_field_size);
	if (err) {
		drgn_lazy_type_deinit(&member_type);
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

#define compound_type_arg_format "O|O&O$O&O&"

static DrgnType *Program_compound_type(Program *self, PyObject *args,
				       PyObject *kwds, const char *arg_format,
				       enum drgn_type_kind kind)
{
	static char *keywords[] = {
		"tag", "size", "members", "qualifiers", "language", NULL
	};
	PyObject *tag_obj;
	struct index_arg size = { .allow_none = true, .is_none = true };
	PyObject *members_obj = Py_None;
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, arg_format, keywords,
					 &tag_obj, index_converter, &size,
					 &members_obj, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
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

	PyObject *cached_members;
	bool can_cache_members = true;
	struct drgn_qualified_type qualified_type;
	struct drgn_error *err;
	if (members_obj == Py_None) {
		if (!size.is_none) {
			PyErr_Format(PyExc_ValueError,
				     "incomplete %s type must not have size",
				     drgn_type_kind_spelling[kind]);
			return NULL;
		}

		if (!Program_hold_reserve(self, tag_obj != Py_None))
			return NULL;

		err = drgn_incomplete_compound_type_create(&self->prog, kind,
							   tag, language,
							   &qualified_type.type);
		if (err)
			return set_drgn_error(err);

		cached_members = NULL;
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
		size_t num_members = PyTuple_GET_SIZE(cached_members);

		struct drgn_compound_type_builder builder;
		drgn_compound_type_builder_init(&builder, &self->prog, kind);
		for (size_t i = 0; i < num_members; i++) {
			if (unpack_member(&builder,
					  PyTuple_GET_ITEM(cached_members, i),
					  &can_cache_members) == -1)
				goto err_builder;
		}

		if (!Program_hold_reserve(self, 1 + (tag_obj != Py_None)))
			goto err_builder;

		err = drgn_compound_type_create(&builder, tag, size.uvalue,
						language, &qualified_type.type);
		if (err) {
			set_drgn_error(err);
err_builder:
			drgn_compound_type_builder_deinit(&builder);
			goto err_members;
		}

		Program_hold_object(self, cached_members);
	}

	if (tag_obj != Py_None && drgn_type_tag(qualified_type.type) == tag)
		Program_hold_object(self, tag_obj);

	qualified_type.qualifiers = qualifiers;
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		goto err_members;

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_tag.id,
			      tag_obj) == -1 ||
	    (can_cache_members &&
	     _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_members.id,
			       cached_members ?
			       cached_members : Py_None) == -1))
		goto err_type;
	Py_XDECREF(cached_members);

	return type_obj;

err_type:
	Py_DECREF(type_obj);
err_members:
	Py_XDECREF(cached_members);
	return NULL;
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
		long long svalue = PyLong_AsLongLong(enumerator->value);
		if (svalue == -1 && PyErr_Occurred())
			return -1;
		err = drgn_enum_type_builder_add_signed(builder, name, svalue);
	} else {
		unsigned long long uvalue =
			PyLong_AsUnsignedLongLong(enumerator->value);
		if (uvalue == (unsigned long long)-1 && PyErr_Occurred())
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

	PyObject *cached_enumerators;
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

		cached_enumerators = NULL;
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
				goto err_enumerators;
		}

		if (!Program_hold_reserve(self, 1 + (tag_obj != Py_None)))
			goto err_builder;

		err = drgn_enum_type_create(&builder, tag, compatible_type,
					    language, &qualified_type.type);
		if (err) {
			set_drgn_error(err);
err_builder:
			drgn_enum_type_builder_deinit(&builder);
			goto err_enumerators;
		}

		Program_hold_object(self, cached_enumerators);
	}

	if (tag_obj != Py_None && drgn_type_tag(qualified_type.type) == tag)
		Program_hold_object(self, tag_obj);

	qualified_type.qualifiers = qualifiers;
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		goto err_enumerators;

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_tag.id,
			      tag_obj) == -1 ||
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_type.id,
			      compatible_type_obj) == -1 ||
	    _PyDict_SetItemId(type_obj->attr_cache,
			      &DrgnType_attr_enumerators.id,
			      cached_enumerators ?
			      cached_enumerators : Py_None) == -1)
		goto err_type;
	Py_XDECREF(cached_enumerators);

	return type_obj;

err_type:
	Py_DECREF(type_obj);
err_enumerators:
	Py_XDECREF(cached_enumerators);
	return NULL;
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
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_type.id,
			      (PyObject *)aliased_type_obj) == -1 ||
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

DrgnType *Program_pointer_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"type", "size", "qualifiers", "language", NULL
	};
	DrgnType *referenced_type_obj;
	struct index_arg size = { .allow_none = true, .is_none = true };
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|O&$O&O&:pointer_type",
					 keywords, &DrgnType_type,
					 &referenced_type_obj, index_converter,
					 &size, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	if (size.is_none) {
		uint8_t word_size;
		struct drgn_error *err = drgn_program_word_size(&self->prog,
								&word_size);
		if (err)
			return set_drgn_error(err);
		size.uvalue = word_size;
	}

	struct drgn_qualified_type qualified_type;
	struct drgn_error *err = drgn_pointer_type_create(&self->prog,
							  DrgnType_unwrap(referenced_type_obj),
							  size.uvalue, language,
							  &qualified_type.type);
	if (err)
		return set_drgn_error(err);
	qualified_type.qualifiers = qualifiers;
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_type.id,
			      (PyObject *)referenced_type_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
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
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		return NULL;

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_type.id,
			      (PyObject *)element_type_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
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

	struct drgn_lazy_type parameter_type;
	if (lazy_type_from_py(&parameter_type, (LazyType *)parameter,
			      builder->prog, can_cache) == -1)
		return -1;
	struct drgn_error *err =
		drgn_function_type_builder_add_parameter(builder,
							 parameter_type, name);
	if (err) {
		drgn_lazy_type_deinit(&parameter_type);
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

DrgnType *Program_function_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"type", "parameters", "is_variadic", "qualifiers", "language",
		NULL,
	};
	DrgnType *return_type_obj;
	PyObject *parameters_obj;
	int is_variadic = 0;
	enum drgn_qualifiers qualifiers = 0;
	const struct drgn_language *language = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O|p$O&O&:function_type",
					 keywords, &DrgnType_type,
					 &return_type_obj, &parameters_obj,
					 &is_variadic, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	if (!PySequence_Check(parameters_obj)) {
		PyErr_SetString(PyExc_TypeError, "parameters must be sequence");
		return NULL;
	}

	PyObject *cached_parameters = PySequence_Tuple(parameters_obj);
	if (!cached_parameters)
		return NULL;
	size_t num_parameters = PyTuple_GET_SIZE(cached_parameters);
	bool can_cache_parameters = true;

	struct drgn_function_type_builder builder;
	drgn_function_type_builder_init(&builder, &self->prog);
	for (size_t i = 0; i < num_parameters; i++) {
		if (unpack_parameter(&builder,
				     PyTuple_GET_ITEM(cached_parameters, i),
				     &can_cache_parameters) == -1)
			goto err_builder;
	}

	if (!Program_hold_reserve(self, 1))
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
		goto err_parameters;
	}

	Program_hold_object(self, cached_parameters);

	qualified_type.qualifiers = qualifiers;
	DrgnType *type_obj = (DrgnType *)DrgnType_wrap(qualified_type);
	if (!type_obj)
		goto err_parameters;

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_type.id,
			      (PyObject *)return_type_obj) == -1 ||
	    (can_cache_parameters &&
	     _PyDict_SetItemId(type_obj->attr_cache,
			       &DrgnType_attr_parameters.id,
			       cached_parameters) == -1))
		goto err_type;
	Py_DECREF(cached_parameters);

	return type_obj;

err_type:
	Py_DECREF(type_obj);
err_parameters:
	Py_DECREF(cached_parameters);
	return NULL;
}
