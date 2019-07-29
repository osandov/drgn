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
	struct drgn_platform *platform;
} Platform;

typedef struct {
	PyObject_HEAD
	struct drgn_program prog;
	PyObject *objects;
	PyObject *cache;
} Program;

typedef struct {
	PyObject_HEAD
	Program *prog;
	struct drgn_symbol *sym;
} Symbol;

extern PyObject *Architecture_class;
extern PyObject *FindObjectFlags_class;
extern PyObject *PlatformFlags_class;
extern PyObject *PrimitiveType_class;
extern PyObject *ProgramFlags_class;
extern PyObject *Qualifiers_class;
extern PyObject *TypeKind_class;
extern PyTypeObject DrgnObject_type;
extern PyTypeObject DrgnType_type;
extern PyTypeObject ObjectIterator_type;
extern PyTypeObject Platform_type;
extern PyTypeObject Program_type;
extern PyTypeObject Symbol_type;
extern PyObject *FaultError;
extern PyObject *FileFormatError;
extern PyObject *MissingDebugInfoError;

int add_module_constants(PyObject *m);

bool set_drgn_in_python(void);
void clear_drgn_in_python(void);
struct drgn_error *drgn_error_from_python(void);
void *set_drgn_error(struct drgn_error *err);
void *set_error_type_name(const char *format,
			  struct drgn_qualified_type qualified_type);

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
PyObject *DrgnObject_NULL(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *cast(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *reinterpret(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *DrgnObject_container_of(PyObject *self, PyObject *args,
				    PyObject *kwds);

PyObject *Platform_wrap(const struct drgn_platform *platform);

int Program_type_arg(Program *prog, PyObject *type_obj, bool can_be_none,
		     struct drgn_qualified_type *ret);
Program *program_from_core_dump(PyObject *self, PyObject *args, PyObject *kwds);
Program *program_from_kernel(PyObject *self);
Program *program_from_pid(PyObject *self, PyObject *args, PyObject *kwds);

static inline PyObject *DrgnType_parent(DrgnType *type)
{
	if (type->type == type->_type)
		return (PyObject *)type;
	else
		return type->parent;
}
PyObject *DrgnType_wrap(struct drgn_qualified_type qualified_type,
			PyObject *parent);
int qualifiers_converter(PyObject *arg, void *result);
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

int append_string(PyObject *parts, const char *s);
int append_format(PyObject *parts, const char *format, ...);
unsigned long long index_arg(PyObject *obj, const char *msg);
PyObject *byteorder_string(bool little_endian);
int parse_byteorder(const char *s, bool *ret);
int parse_optional_byteorder(PyObject *obj, enum drgn_byte_order *ret);

/* Helpers for path arguments based on posixmodule.c in CPython. */
struct path_arg {
	bool allow_none;
	char *path;
	Py_ssize_t length;
	PyObject *object;
	PyObject *cleanup;
};
int path_converter(PyObject *o, void *p);
void path_cleanup(struct path_arg *path);

struct enum_arg {
	PyObject *type;
	unsigned long value;
	bool allow_none;
};
int enum_converter(PyObject *o, void *p);

#endif /* DRGNPY_H */
