// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"
#include "../type.h"

static const char *drgn_type_kind_str(struct drgn_type *type)
{
	return drgn_type_kind_spelling[drgn_type_kind(type)];
}

static DrgnType *DrgnType_new(enum drgn_qualifiers qualifiers, size_t nmemb,
			      size_t size)
{
	DrgnType *type_obj;
	size_t bytes;

	if (__builtin_mul_overflow(nmemb, size, &bytes) ||
	    __builtin_add_overflow(bytes, sizeof(struct drgn_type), &bytes) ||
	    __builtin_add_overflow(bytes, sizeof(void *) - 1, &bytes) ||
	    bytes / sizeof(void *) > PY_SSIZE_T_MAX - sizeof(DrgnType)) {
		PyErr_NoMemory();
		return NULL;
	}
	type_obj = (DrgnType *)DrgnType_type.tp_alloc(&DrgnType_type,
						      bytes / sizeof(void *));
	if (!type_obj)
		return NULL;
	type_obj->qualifiers = qualifiers;
	type_obj->attr_cache = PyDict_New();
	if (!type_obj->attr_cache) {
		Py_DECREF(type_obj);
		return NULL;
	}
	type_obj->type = type_obj->_type;
	return type_obj;
}

DRGNPY_PUBLIC PyObject *DrgnType_wrap(struct drgn_qualified_type qualified_type,
				      PyObject *parent)
{
	DrgnType *type_obj;

	type_obj = (DrgnType *)DrgnType_type.tp_alloc(&DrgnType_type, 0);
	if (!type_obj)
		return NULL;
	type_obj->qualifiers = qualified_type.qualifiers;
	type_obj->attr_cache = PyDict_New();
	if (!type_obj->attr_cache) {
		Py_DECREF(type_obj);
		return NULL;
	}
	type_obj->type = qualified_type.type;
	if (parent) {
		Py_INCREF(parent);
		type_obj->parent = parent;
	}
	return (PyObject *)type_obj;
}

static DrgnType *LazyType_get_borrowed(LazyType *self)
{
	if (unlikely(self->obj & DRGNPY_LAZY_TYPE_UNEVALUATED)) {
		PyObject *obj;
		PyObject *type;

		obj = (PyObject *)(self->obj & DRGNPY_LAZY_TYPE_MASK);
		if (self->lazy_type) {
			struct drgn_error *err;
			struct drgn_qualified_type qualified_type;
			bool clear = false;

			/* Avoid the thread state overhead if we can. */
			if (!drgn_lazy_type_is_evaluated(self->lazy_type))
				clear = set_drgn_in_python();
			err = drgn_lazy_type_evaluate(self->lazy_type,
						      &qualified_type);
			if (clear)
				clear_drgn_in_python();
			if (err) {
				set_drgn_error(err);
				return NULL;
			}
			type = DrgnType_wrap(qualified_type, obj);
			if (!type)
				return NULL;
		} else {
			type = PyObject_CallObject(obj, NULL);
			if (!type)
				return NULL;
			if (!PyObject_TypeCheck(type, &DrgnType_type)) {
				Py_DECREF(type);
				PyErr_SetString(PyExc_TypeError,
						"type callable must return Type");
				return NULL;
			}
		}
		Py_DECREF(obj);
		self->obj = (uintptr_t)type;
	}
	return (DrgnType *)self->obj;
}

static DrgnType *LazyType_get(LazyType *self, void *arg)
{
	DrgnType *ret;

	ret = LazyType_get_borrowed(self);
	Py_XINCREF(ret);
	return ret;
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
	PyGILState_STATE gstate;
	struct drgn_error *err = NULL;
	DrgnType *type;

	gstate = PyGILState_Ensure();
	type = LazyType_get_borrowed(t->lazy_type);
	if (!type) {
		err = drgn_error_from_python();
		goto out;
	}
	ret->type = type->type;
	ret->qualifiers = type->qualifiers;
out:
	PyGILState_Release(gstate);
	return err;
}

static void py_type_thunk_free_fn(struct drgn_type_thunk *thunk)
{
	free(container_of(thunk, struct py_type_thunk, thunk));
}

static PyObject *DrgnType_get_ptr(DrgnType *self, void *arg)
{
	return PyLong_FromVoidPtr(self->type);
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
	    !drgn_type_is_complete(self->type)) {
		Py_RETURN_NONE;
	} else {
		return DrgnType_wrap(drgn_type_type(self->type),
				     (PyObject *)self);
	}
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
		Py_INCREF(self);
		item->obj = (uintptr_t)self | DRGNPY_LAZY_TYPE_UNEVALUATED;
		item->lazy_type = &member->type;
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
		Py_INCREF(self);
		item->obj = (uintptr_t)self | DRGNPY_LAZY_TYPE_UNEVALUATED;
		item->lazy_type = &parameter->type;
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

static int type_arg(PyObject *arg, struct drgn_qualified_type *qualified_type,
		    DrgnType *type_obj)
{
	Py_INCREF(arg);
	if (!PyObject_IsInstance(arg, (PyObject *)&DrgnType_type)) {
		Py_DECREF(arg);
		PyErr_SetString(PyExc_TypeError, "type must be Type");
		return -1;
	}

	if (type_obj) {
		if (_PyDict_SetItemId(type_obj->attr_cache,
				      &DrgnType_attr_type.id, arg) == -1) {
			Py_DECREF(arg);
			return -1;
		}
	}
	qualified_type->type = ((DrgnType *)arg)->type;
	qualified_type->qualifiers = ((DrgnType *)arg)->qualifiers;
	Py_DECREF(arg);
	return 0;
}

static int lazy_type_from_py(struct drgn_lazy_type *lazy_type, LazyType *obj)
{
	if (obj->obj & DRGNPY_LAZY_TYPE_UNEVALUATED) {
		struct py_type_thunk *thunk;

		thunk = malloc(sizeof(*thunk));
		if (!thunk) {
			PyErr_NoMemory();
			return -1;
		}
		thunk->thunk.evaluate_fn = py_type_thunk_evaluate_fn;
		thunk->thunk.free_fn = py_type_thunk_free_fn;
		thunk->lazy_type = obj;
		drgn_lazy_type_init_thunk(lazy_type, &thunk->thunk);
	} else {
		DrgnType *type = (DrgnType *)obj->obj;

		drgn_lazy_type_init_evaluated(lazy_type, type->type,
					      type->qualifiers);
	}
	return 0;
}

static void DrgnType_dealloc(DrgnType *self)
{
	if (self->type != self->_type) {
		Py_XDECREF(self->parent);
	} else if (drgn_type_is_complete(self->type)) {
		if (drgn_type_has_members(self->type)) {
			struct drgn_type_member *members;
			size_t num_members, i;

			members = drgn_type_members(self->type);
			num_members = drgn_type_num_members(self->type);
			for (i = 0; i < num_members; i++)
				drgn_lazy_type_deinit(&members[i].type);
		}
		if (drgn_type_has_parameters(self->type)) {
			struct drgn_type_parameter *parameters;
			size_t num_parameters, i;

			parameters = drgn_type_parameters(self->type);
			num_parameters = drgn_type_num_parameters(self->type);
			for (i = 0; i < num_parameters; i++)
				drgn_lazy_type_deinit(&parameters[i].type);
		}
	}
	Py_XDECREF(self->attr_cache);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int DrgnType_traverse(DrgnType *self, visitproc visit, void *arg)
{
	if (self->type != self->_type)
		Py_VISIT(self->parent);
	Py_VISIT(self->attr_cache);
	return 0;
}

static int DrgnType_clear(DrgnType *self)
{
	if (self->type != self->_type)
		Py_CLEAR(self->parent);
	Py_CLEAR(self->attr_cache);
	return 0;
}

#undef visit_type_thunks
#undef visit_lazy_type

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

	if (append_format(parts, "%s_type(",
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

	if (append_member(parts, self, &first, size) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, length) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, is_signed) == -1)
		goto out_repr_leave;
	if (append_member(parts, self, &first, type) == -1)
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
	struct drgn_qualified_type qualified_type = {
		.type = self->type,
		.qualifiers = self->qualifiers,
	};
	struct drgn_error *err;
	PyObject *ret;
	char *str;

	err = drgn_format_type(qualified_type, &str);
	if (err)
		return set_drgn_error(err);

	ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

static PyObject *DrgnType_type_name(DrgnType *self)
{
	struct drgn_qualified_type qualified_type = {
		.type = self->type,
		.qualifiers = self->qualifiers,
	};
	struct drgn_error *err;
	PyObject *ret;
	char *str;

	err = drgn_format_type_name(qualified_type, &str);
	if (err)
		return set_drgn_error(err);

	ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

static PyObject *DrgnType_is_complete(DrgnType *self)
{
	return PyBool_FromLong(drgn_type_is_complete(self->type));
}

int qualifiers_converter(PyObject *o, void *p)
{
	struct enum_arg arg = {
		.type = Qualifiers_class,
		.value = 0,
		.allow_none = true,
	};

	if (!enum_converter(o, &arg))
		return 0;
	*(unsigned char *)p = arg.value;
	return 1;
}

static PyObject *DrgnType_qualified(DrgnType *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = { "qualifiers", NULL, };
	unsigned char qualifiers;
	struct drgn_qualified_type qualified_type;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&:qualified", keywords,
					 qualifiers_converter, &qualifiers))
		return NULL;

	qualified_type.type = self->type;
	qualified_type.qualifiers = qualifiers;
	return DrgnType_wrap(qualified_type, DrgnType_parent(self));
}

static PyObject *DrgnType_unqualified(DrgnType *self)
{
	struct drgn_qualified_type qualified_type;

	qualified_type.type = self->type;
	qualified_type.qualifiers = 0;
	return DrgnType_wrap(qualified_type, DrgnType_parent(self));
}

static PyObject *DrgnType_richcompare(DrgnType *self, PyObject *other, int op)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type1, qualified_type2;
	bool clear;
	bool ret;

	if (!PyObject_TypeCheck(other, &DrgnType_type) ||
	    (op != Py_EQ && op != Py_NE))
		Py_RETURN_NOTIMPLEMENTED;

	clear = set_drgn_in_python();
	qualified_type1.type = self->type;
	qualified_type1.qualifiers = self->qualifiers;
	qualified_type2.type = ((DrgnType *)other)->type;
	qualified_type2.qualifiers = ((DrgnType *)other)->qualifiers;
	err = drgn_qualified_type_eq(qualified_type1, qualified_type2, &ret);
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
	/*
	 * The "item" of a Type object is an optional struct drgn_type + an
	 * optional array of struct drgn_type_member, struct
	 * drgn_type_enumerator, or struct drgn_type_parameter. We set
	 * tp_itemsize to a word so that we can allocate whatever arbitrary size
	 * we need.
	 */
	.tp_itemsize = sizeof(void *),
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

static TypeMember *TypeMember_new(PyTypeObject *subtype, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {
		"type", "name", "bit_offset", "bit_field_size", NULL
	};
	PyObject *type_arg, *name = Py_None, *bit_offset = NULL, *bit_field_size = NULL;
	uintptr_t obj;
	TypeMember *member;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OO!O!:TypeMember",
					 keywords, &type_arg, &name,
					 &PyLong_Type, &bit_offset,
					 &PyLong_Type, &bit_field_size))
		return NULL;

	if (PyCallable_Check(type_arg)) {
		obj = (uintptr_t)type_arg | DRGNPY_LAZY_TYPE_UNEVALUATED;
	} else if (PyObject_TypeCheck(type_arg, &DrgnType_type)) {
		obj = (uintptr_t)type_arg;
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

	Py_INCREF(type_arg);
	member->obj = obj;
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
	Py_XDECREF((PyObject *)(self->obj & DRGNPY_LAZY_TYPE_MASK));
	Py_TYPE(self)->tp_free((PyObject *)self);
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
	uintptr_t obj;
	TypeParameter *parameter;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O:TypeParameter",
					 keywords, &type_arg, &name))
		return NULL;

	if (PyCallable_Check(type_arg)) {
		obj = (uintptr_t)type_arg | DRGNPY_LAZY_TYPE_UNEVALUATED;
	} else if (PyObject_TypeCheck(type_arg, &DrgnType_type)) {
		obj = (uintptr_t)type_arg;
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
		Py_INCREF(type_arg);
		parameter->obj = obj;
		Py_INCREF(name);
		parameter->name = name;
	}
	return parameter;
}

static void TypeParameter_dealloc(TypeParameter *self)
{
	Py_XDECREF(self->name);
	Py_XDECREF((PyObject *)(self->obj & DRGNPY_LAZY_TYPE_MASK));
	Py_TYPE(self)->tp_free((PyObject *)self);
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

DrgnType *void_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = { "qualifiers", "language", NULL, };
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;
	struct drgn_qualified_type qualified_type;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O&$O&:void_type",
					 keywords, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	qualified_type.type = drgn_void_type(language);
	qualified_type.qualifiers = qualifiers;
	return (DrgnType *)DrgnType_wrap(qualified_type, NULL);
}

DrgnType *int_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "is_signed", "qualifiers", "language", NULL,
	};
	DrgnType *type_obj;
	PyObject *name_obj;
	const char *name;
	unsigned long size;
	int is_signed;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!kp|O&$O&:int_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 &size, &is_signed,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	type_obj = DrgnType_new(qualifiers, 0, 0);
	if (!type_obj)
		return NULL;

	drgn_int_type_init(type_obj->type, name, size, is_signed, language);

	if (drgn_type_name(type_obj->type) == name &&
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

DrgnType *bool_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "qualifiers", "language", NULL,
	};
	DrgnType *type_obj;
	PyObject *name_obj;
	const char *name;
	unsigned long size;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!k|O&$O&:bool_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 &size, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	type_obj = DrgnType_new(qualifiers, 0, 0);
	if (!type_obj)
		return NULL;

	drgn_bool_type_init(type_obj->type, name, size, language);

	if (drgn_type_name(type_obj->type) == name &&
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

DrgnType *float_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "size", "qualifiers", "language", NULL,
	};
	DrgnType *type_obj;
	PyObject *name_obj;
	const char *name;
	unsigned long size;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!k|O&$O&:float_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 &size, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	type_obj = DrgnType_new(qualifiers, 0, 0);
	if (!type_obj)
		return NULL;

	drgn_float_type_init(type_obj->type, name, size, language);

	if (drgn_type_name(type_obj->type) == name &&
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

DrgnType *complex_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = { "name", "size", "type", "qualifiers", NULL, };
	DrgnType *type_obj;
	PyObject *name_obj;
	const char *name;
	unsigned long size;
	PyObject *real_type_obj;
	struct drgn_type *real_type;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!kO|O&$O&:complex_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 &size, &real_type_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	if (!PyObject_TypeCheck(real_type_obj, &DrgnType_type)) {
		PyErr_SetString(PyExc_TypeError,
				"complex_type() real type must be Type");
		return NULL;
	}
	real_type = ((DrgnType *)real_type_obj)->type;
	if (drgn_type_kind(real_type) != DRGN_TYPE_FLOAT &&
	    drgn_type_kind(real_type) != DRGN_TYPE_INT) {
		PyErr_SetString(PyExc_ValueError,
				"complex_type() real type must be floating-point or integer type");
		return NULL;
	}
	if (((DrgnType *)real_type_obj)->qualifiers) {
		PyErr_SetString(PyExc_ValueError,
				"complex_type() real type must be unqualified");
		return NULL;
	}

	type_obj = DrgnType_new(qualifiers, 0, 0);
	if (!type_obj)
		return NULL;

	drgn_complex_type_init(type_obj->type, name, size, real_type, language);

	if (drgn_type_name(type_obj->type) == name &&
	    _PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}
	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_type.id,
			      real_type_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	return type_obj;
}

static int unpack_member(DrgnType *type_obj, PyObject *cached_members_obj,
			 size_t i)
{
	TypeMember *item;
	const char *name;
	unsigned long long bit_offset, bit_field_size;
	struct drgn_lazy_type member_type;

	item = (TypeMember *)PyTuple_GET_ITEM(cached_members_obj, i);
	if (!PyObject_TypeCheck((PyObject *)item, &TypeMember_type)) {
		PyErr_SetString(PyExc_TypeError, "member must be TypeMember");
		return -1;
	}

	if (item->name == Py_None) {
		name = NULL;
	} else {
		name = PyUnicode_AsUTF8(item->name);
		if (!name)
			return -1;
	}

	bit_offset = PyLong_AsUnsignedLongLong(item->bit_offset);
	if (bit_offset == (unsigned long long)-1 && PyErr_Occurred())
		return -1;
	bit_field_size = PyLong_AsUnsignedLongLong(item->bit_field_size);
	if (bit_field_size == (unsigned long long)-1 && PyErr_Occurred())
		return -1;

	if (lazy_type_from_py(&member_type, (LazyType *)item) == -1)
		return -1;
	drgn_type_member_init(type_obj->type, i, member_type, name, bit_offset,
			      bit_field_size);
	return 0;
}

static DrgnType *compound_type(PyObject *tag_obj, PyObject *size_obj,
			       PyObject *members_obj,
			       enum drgn_qualifiers qualifiers,
			       const struct drgn_language *language,
			       enum drgn_type_kind kind)
{
	const char *tag;
	DrgnType *type_obj = NULL;
	unsigned long long size;
	PyObject *cached_members_obj = NULL;
	size_t num_members;

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

	if (members_obj == Py_None) {
		if (size_obj != Py_None) {
			PyErr_Format(PyExc_ValueError,
				     "incomplete %s type must not have size",
				     drgn_type_kind_spelling[kind]);
			return NULL;
		}
		type_obj = DrgnType_new(qualifiers, 0, 0);
		if (!type_obj)
			return NULL;
		if (_PyDict_SetItemId(type_obj->attr_cache,
				      &DrgnType_attr_members.id, Py_None) == -1)
			goto err;
	} else {
		size_t i;

		if (size_obj == Py_None) {
			PyErr_Format(PyExc_ValueError, "%s type must have size",
				     drgn_type_kind_spelling[kind]);
			return NULL;
		}

		size = PyLong_AsUnsignedLongLong(size_obj);
		if (size == (unsigned long long)-1)
			return NULL;

		if (!PySequence_Check(members_obj)) {
			PyErr_SetString(PyExc_TypeError,
					"members must be sequence or None");
			return NULL;
		}
		cached_members_obj = PySequence_Tuple(members_obj);
		if (!cached_members_obj)
			return NULL;
		num_members = PyTuple_GET_SIZE(cached_members_obj);

		type_obj = DrgnType_new(qualifiers, num_members,
					sizeof(struct drgn_type_member));
		if (!type_obj)
			goto err;
		for (i = 0; i < num_members; i++) {
			if (unpack_member(type_obj, cached_members_obj,
					  i) == -1)
				goto err;
		}

		if (_PyDict_SetItemId(type_obj->attr_cache,
				      &DrgnType_attr_members.id,
				      cached_members_obj) == -1)
			goto err;
		Py_CLEAR(cached_members_obj);
	}

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_tag.id,
			      tag_obj) == -1)
		goto err;

	if (members_obj == Py_None) {
		switch (kind) {
		case DRGN_TYPE_STRUCT:
			drgn_struct_type_init_incomplete(type_obj->type, tag,
							 language);
			break;
		case DRGN_TYPE_UNION:
			drgn_union_type_init_incomplete(type_obj->type, tag,
							language);
			break;
		case DRGN_TYPE_CLASS:
			drgn_class_type_init_incomplete(type_obj->type, tag,
							language);
			break;
		default:
			DRGN_UNREACHABLE();
		}
	} else {
		switch (kind) {
		case DRGN_TYPE_STRUCT:
			drgn_struct_type_init(type_obj->type, tag, size,
					      num_members, language);
			break;
		case DRGN_TYPE_UNION:
			drgn_union_type_init(type_obj->type, tag, size,
					     num_members, language);
			break;
		case DRGN_TYPE_CLASS:
			drgn_class_type_init(type_obj->type, tag, size,
					     num_members, language);
			break;
		default:
			DRGN_UNREACHABLE();
		}
	}
	return type_obj;

err:
	Py_XDECREF(type_obj);
	Py_XDECREF(cached_members_obj);
	return NULL;
}

DrgnType *struct_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"tag", "size", "members", "qualifiers", "language", NULL,
	};
	PyObject *tag_obj;
	PyObject *size_obj = Py_None;
	PyObject *members_obj = Py_None;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OOO&$O&:struct_type",
					 keywords, &tag_obj, &size_obj,
					 &members_obj, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	return compound_type(tag_obj, size_obj, members_obj, qualifiers,
			     language, DRGN_TYPE_STRUCT);
}

DrgnType *union_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"tag", "size", "members", "qualifiers", "language", NULL,
	};
	PyObject *tag_obj;
	PyObject *size_obj = Py_None;
	PyObject *members_obj = Py_None;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OOO&$O&:union_type",
					 keywords, &tag_obj, &size_obj,
					 &members_obj, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	return compound_type(tag_obj, size_obj, members_obj, qualifiers,
			     language, DRGN_TYPE_UNION);
}

DrgnType *class_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"tag", "size", "members", "qualifiers", "language", NULL,
	};
	PyObject *tag_obj;
	PyObject *size_obj = Py_None;
	PyObject *members_obj = Py_None;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OOO&$O&:class_type",
					 keywords, &tag_obj, &size_obj,
					 &members_obj, qualifiers_converter,
					 &qualifiers, language_converter,
					 &language))
		return NULL;

	return compound_type(tag_obj, size_obj, members_obj, qualifiers,
			     language, DRGN_TYPE_CLASS);
}

static int unpack_enumerator(DrgnType *type_obj, PyObject *cached_enumerators_obj,
			     size_t i, bool is_signed)
{
	TypeEnumerator *item;
	const char *name;

	item = (TypeEnumerator *)PyTuple_GET_ITEM(cached_enumerators_obj, i);
	if (!PyObject_TypeCheck((PyObject *)item, &TypeEnumerator_type)) {
		PyErr_SetString(PyExc_TypeError,
				"enumerator must be TypeEnumerator");
		return -1;
	}

	name = PyUnicode_AsUTF8(item->name);
	if (!name)
		return -1;

	if (is_signed) {
		long long svalue;

		svalue = PyLong_AsLongLong(item->value);
		if (svalue == -1 && PyErr_Occurred())
			return -1;
		drgn_type_enumerator_init_signed(type_obj->type, i, name,
						 svalue);
	} else {
		unsigned long long uvalue;

		uvalue = PyLong_AsUnsignedLongLong(item->value);
		if (uvalue == (unsigned long long)-1 && PyErr_Occurred())
			return -1;
		drgn_type_enumerator_init_unsigned(type_obj->type, i, name,
						   uvalue);
	}
	return 0;
}

DrgnType *enum_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"tag", "type", "enumerators", "qualifiers", "language", NULL,
	};
	DrgnType *type_obj = NULL;
	PyObject *tag_obj;
	const char *tag;
	PyObject *compatible_type_obj = Py_None;
	struct drgn_type *compatible_type;
	PyObject *enumerators_obj = Py_None;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;
	PyObject *cached_enumerators_obj = NULL;
	size_t num_enumerators;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|OOO&$O&:enum_type",
					 keywords, &tag_obj,
					 &compatible_type_obj, &enumerators_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

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

	if (compatible_type_obj == Py_None) {
		compatible_type = NULL;
	} else if (PyObject_TypeCheck(compatible_type_obj, &DrgnType_type)) {
		compatible_type = ((DrgnType *)compatible_type_obj)->type;
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
	} else {
		PyErr_SetString(PyExc_TypeError,
				"enum_type() compatible type must be Type or None");
		return NULL;
	}

	if (enumerators_obj == Py_None) {
		if (compatible_type) {
			PyErr_SetString(PyExc_ValueError,
					"incomplete enum type must not have compatible type");
			return NULL;
		}
		num_enumerators = 0;
		type_obj = DrgnType_new(qualifiers, 0, 0);
		if (!type_obj)
			return NULL;
		if (_PyDict_SetItemId(type_obj->attr_cache,
				      &DrgnType_attr_enumerators.id,
				      Py_None) == -1)
			goto err;
	} else {
		bool is_signed;
		size_t i;

		if (!compatible_type) {
			PyErr_SetString(PyExc_ValueError,
					"enum type must have compatible type");
			return NULL;
		}
		if (!PySequence_Check(enumerators_obj)) {
			PyErr_SetString(PyExc_TypeError,
					"enumerators must be sequence or None");
			return NULL;
		}
		cached_enumerators_obj = PySequence_Tuple(enumerators_obj);
		if (!cached_enumerators_obj)
			return NULL;
		num_enumerators = PyTuple_GET_SIZE(cached_enumerators_obj);
		is_signed = drgn_type_is_signed(compatible_type);

		type_obj = DrgnType_new(qualifiers, num_enumerators,
					sizeof(struct drgn_type_enumerator));
		if (!type_obj)
			goto err;
		for (i = 0; i < num_enumerators; i++) {
			if (unpack_enumerator(type_obj, cached_enumerators_obj,
					      i, is_signed) == -1)
				goto err;
		}

		if (_PyDict_SetItemId(type_obj->attr_cache,
				      &DrgnType_attr_enumerators.id,
				      cached_enumerators_obj) == -1)
			goto err;
		Py_CLEAR(cached_enumerators_obj);
	}

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_tag.id,
			      tag_obj) == -1)
		goto err;
	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_type.id,
			      compatible_type_obj) == -1)
		goto err;

	if (enumerators_obj == Py_None) {
		drgn_enum_type_init_incomplete(type_obj->type, tag, language);
	} else {
		drgn_enum_type_init(type_obj->type, tag, compatible_type,
				    num_enumerators, language);
	}
	return type_obj;

err:
	Py_XDECREF(type_obj);
	Py_XDECREF(cached_enumerators_obj);
	return NULL;
}

DrgnType *typedef_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"name", "type", "qualifiers", "language", NULL,
	};
	DrgnType *type_obj;
	PyObject *name_obj;
	const char *name;
	PyObject *aliased_type_obj;
	struct drgn_qualified_type aliased_type;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O|O&$O&:typedef_type",
					 keywords, &PyUnicode_Type, &name_obj,
					 &aliased_type_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	name = PyUnicode_AsUTF8(name_obj);
	if (!name)
		return NULL;

	type_obj = DrgnType_new(qualifiers, 0, 0);
	if (!type_obj)
		return NULL;

	if (type_arg(aliased_type_obj, &aliased_type, type_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	if (_PyDict_SetItemId(type_obj->attr_cache, &DrgnType_attr_name.id,
			      name_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	drgn_typedef_type_init(type_obj->type, name, aliased_type, language);
	return type_obj;
}

DrgnType *pointer_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"size", "type", "qualifiers", "language", NULL,
	};
	DrgnType *type_obj;
	unsigned long size;
	PyObject *referenced_type_obj;
	struct drgn_qualified_type referenced_type;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "kO|O&$O&:pointer_type",
					 keywords, &size, &referenced_type_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	type_obj = DrgnType_new(qualifiers, 0, 0);
	if (!type_obj)
		return NULL;

	if (type_arg(referenced_type_obj, &referenced_type, type_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	drgn_pointer_type_init(type_obj->type, size, referenced_type, language);
	return type_obj;
}

DrgnType *array_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"length", "type", "qualifiers", "language", NULL,
	};
	DrgnType *type_obj;
	PyObject *length_obj;
	unsigned long long length;
	PyObject *element_type_obj;
	struct drgn_qualified_type element_type;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO|O&$O&:array_type",
					 keywords, &length_obj,
					 &element_type_obj,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	if (length_obj == Py_None) {
		length = 0;
	} else {
		if (!PyLong_Check(length_obj)) {
			PyErr_SetString(PyExc_TypeError,
					"length must be integer or None");
			return NULL;
		}
		length = PyLong_AsUnsignedLongLong(length_obj);
		if (length == (unsigned long long)-1 && PyErr_Occurred())
			return NULL;
	}

	type_obj = DrgnType_new(qualifiers, 0, 0);
	if (!type_obj)
		return NULL;

	if (type_arg(element_type_obj, &element_type, type_obj) == -1) {
		Py_DECREF(type_obj);
		return NULL;
	}

	if (length_obj == Py_None) {
		drgn_array_type_init_incomplete(type_obj->type, element_type,
						language);
	} else {
		drgn_array_type_init(type_obj->type, length, element_type,
				     language);
	}
	return type_obj;
}

static int unpack_parameter(DrgnType *type_obj, PyObject *cached_parameters_obj,
			    size_t i)
{
	TypeParameter *item;
	const char *name;
	struct drgn_lazy_type parameter_type;

	item = (TypeParameter *)PyTuple_GET_ITEM(cached_parameters_obj, i);
	if (!PyObject_TypeCheck((PyObject *)item, &TypeParameter_type)) {
		PyErr_SetString(PyExc_TypeError, "parameter must be TypeParameter");
		return -1;
	}

	if (item->name == Py_None) {
		name = NULL;
	} else {
		name = PyUnicode_AsUTF8(item->name);
		if (!name)
			return -1;
	}

	if (lazy_type_from_py(&parameter_type, (LazyType *)item) == -1)
		return -1;
	drgn_type_parameter_init(type_obj->type, i, parameter_type, name);
	return 0;
}

DrgnType *function_type(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"type", "parameters", "is_variadic", "qualifiers", "language",
		NULL,
	};
	DrgnType *type_obj = NULL;
	PyObject *return_type_obj;
	struct drgn_qualified_type return_type;
	PyObject *parameters_obj, *cached_parameters_obj = NULL;
	size_t num_parameters, i;
	int is_variadic = 0;
	unsigned char qualifiers = 0;
	const struct drgn_language *language = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO|pO&$O&:function_type",
					 keywords, &return_type_obj,
					 &parameters_obj, &is_variadic,
					 qualifiers_converter, &qualifiers,
					 language_converter, &language))
		return NULL;

	if (!PySequence_Check(parameters_obj)) {
		PyErr_SetString(PyExc_TypeError, "parameters must be sequence");
		return NULL;
	}
	cached_parameters_obj = PySequence_Tuple(parameters_obj);
	if (!cached_parameters_obj)
		return NULL;
	num_parameters = PyTuple_GET_SIZE(cached_parameters_obj);

	type_obj = DrgnType_new(qualifiers, num_parameters,
				sizeof(struct drgn_type_parameter));
	if (!type_obj)
		goto err;
	for (i = 0; i < num_parameters; i++) {
		if (unpack_parameter(type_obj, cached_parameters_obj, i) == -1)
			goto err;
	}

	if (_PyDict_SetItemId(type_obj->attr_cache,
			      &DrgnType_attr_parameters.id,
			      cached_parameters_obj) == -1)
		goto err;
	Py_CLEAR(cached_parameters_obj);

	if (type_arg(return_type_obj, &return_type, type_obj) == -1)
		goto err;

	drgn_function_type_init(type_obj->type, return_type, num_parameters,
				is_variadic, language);
	return type_obj;

err:
	Py_XDECREF(type_obj);
	Py_XDECREF(cached_parameters_obj);
	return NULL;
}
