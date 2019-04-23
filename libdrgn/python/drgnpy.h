// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#ifndef DRGNPY_H
#define DRGNPY_H

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include "structmember.h"

#include "docstrings.h"
#include "../drgn.h"
#include "../program.h"

/* These were added in Python 3.7. */
#ifndef Py_UNREACHABLE
#define Py_UNREACHABLE() abort()
#endif
#ifndef Py_RETURN_RICHCOMPARE
#define Py_RETURN_RICHCOMPARE(val1, val2, op)                               \
    do {                                                                    \
        switch (op) {                                                       \
        case Py_EQ: if ((val1) == (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;  \
        case Py_NE: if ((val1) != (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;  \
        case Py_LT: if ((val1) < (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;   \
        case Py_GT: if ((val1) > (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;   \
        case Py_LE: if ((val1) <= (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;  \
        case Py_GE: if ((val1) >= (val2)) Py_RETURN_TRUE; Py_RETURN_FALSE;  \
        default:                                                            \
            Py_UNREACHABLE();                                               \
        }                                                                   \
    } while (0)
#endif

#define DRGNPY_PUBLIC __attribute__((visibility("default")))

typedef struct {
	PyObject_HEAD
	struct drgn_object obj;
} DrgnObject;

typedef struct {
	PyObject_VAR_HEAD
	enum drgn_qualifiers qualifiers;
	/*
	 * This serves two purposes: it caches attributes which were previously
	 * converted from a struct drgn_type member, and it keeps a reference to
	 * any objects which are referenced internally by _type. For example, in
	 * order to avoid doing a strdup(), we can set the name of a type
	 * directly to PyUnicode_AsUTF8(s). This is only valid as long as s is
	 * alive, so we store it here.
	 */
	PyObject *attr_cache;
	/*
	 * A Type object can wrap a struct drgn_type created elsewhere, or it
	 * can have an embedded struct drgn_type. In the latter case, type
	 * points to _type.
	 */
	struct drgn_type *type;
	union {
		struct drgn_type _type[0];
		/* An object which must be kept alive for type to be valid. */
		PyObject *parent;
	};
} DrgnType;

typedef struct {
	PyObject_HEAD
	DrgnObject *obj;
	uint64_t length, index;
} ObjectIterator;

typedef struct {
	PyObject_HEAD
	struct drgn_program prog;
	PyObject *objects;
	Py_buffer *buffers;
	size_t num_buffers;
	bool inited;
} Program;

extern PyObject *PrimitiveType_class;
extern PyObject *ProgramFlags_class;
extern PyObject *Qualifiers_class;
extern PyObject *TypeKind_class;
extern PyTypeObject DrgnObject_type;
extern PyTypeObject DrgnType_type;
extern PyTypeObject ObjectIterator_type;
extern PyTypeObject Program_type;

int append_string(PyObject *parts, const char *s);
int append_format(PyObject *parts, const char *format, ...);
PyObject *byteorder_string(bool little_endian);
int parse_byteorder(const char *s, bool *ret);
int parse_optional_byteorder(PyObject *obj, enum drgn_byte_order *ret);

int add_module_constants(PyObject *m);
PyObject *set_drgn_error(struct drgn_error *err);

static inline PyObject *DrgnType_parent(DrgnType *type)
{
	if (type->type == type->_type)
		return (PyObject *)type;
	else
		return type->parent;
}

static inline DrgnObject *DrgnObject_alloc(Program *prog)
{
	DrgnObject *ret;

	ret = (DrgnObject *)DrgnObject_type.tp_alloc(&DrgnObject_type, 0);
	if (ret) {
		drgn_object_init(&ret->obj, &prog->prog);
		Py_INCREF(prog);
	}
	return ret;
}

int Program_type_arg(Program *prog, PyObject *type_obj, bool can_be_none,
		     struct drgn_qualified_type *ret);
int qualifiers_converter(PyObject *arg, void *result);

PyObject *DrgnObject_NULL(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *cast(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *reinterpret(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *DrgnObject_container_of(PyObject *self, PyObject *args,
				    PyObject *kwds);

Program *mock_program(PyObject *self, PyObject *args, PyObject *kwds);
Program *program_from_core_dump(PyObject *self, PyObject *args, PyObject *kwds);
Program *program_from_kernel(PyObject *self, PyObject *args, PyObject *kwds);
Program *program_from_pid(PyObject *self, PyObject *args, PyObject *kwds);
PyObject *DrgnType_wrap(struct drgn_qualified_type qualified_type,
			PyObject *parent);
DrgnType *void_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *int_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *bool_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *float_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *complex_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *struct_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *union_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *enum_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *typedef_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *pointer_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *array_type(PyObject *self, PyObject *args, PyObject *kwds);
DrgnType *function_type(PyObject *self, PyObject *args, PyObject *kwds);

/*
 * This fake error is returned from a libdrgn callback if there is an active
 * Python exception.
 */
#define DRGN_ERROR_PYTHON ((struct drgn_error *)-1)

#endif /* DRGNPY_H */
