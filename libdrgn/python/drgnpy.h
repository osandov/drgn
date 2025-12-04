// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGNPY_H
#define DRGNPY_H

#define PY_SSIZE_T_CLEAN

// IWYU pragma: begin_exports
#include <Python.h>
#include "structmember.h"

#include "docstrings.h"
#include "../cleanup.h"
#include "../drgn_internal.h"
// IWYU pragma: end_exports

#include "../hash_table.h"
#include "../pp.h"
#include "../program.h"
#include "../symbol.h"
#include "../vector.h"

#if PY_VERSION_HEX < 0x030900a1
static inline PyObject *PyObject_CallNoArgs(PyObject *func)
{
	return PyObject_CallFunctionObjArgs(func, NULL);
}
static inline PyObject *PyObject_CallOneArg(PyObject *callable, PyObject *arg)
{
	return PyObject_CallFunctionObjArgs(callable, arg, NULL);
}
#endif

#if PY_VERSION_HEX < 0x030d00a1
#define PyThreadState_GetUnchecked _PyThreadState_UncheckedGet
#endif

#if PY_VERSION_HEX < 0x030e00a5
#define Py_HashPointer _Py_HashPointer
#endif

#define DRGNPY_PUBLIC __attribute__((__visibility__("default")))

// PyLong_From* and PyLong_As* for stdint.h types. These use _Generic for
// slightly more type safety (e.g., so you can't pass an int64_t to
// PyLong_FromUint64()).
#if ULONG_MAX == UINT64_MAX
#define PyLong_FromUint64(v) _Generic((v), uint64_t: PyLong_FromUnsignedLong)(v)
#define PyLong_AsUint64(obj) ((uint64_t)PyLong_AsUnsignedLong(obj))
#define PyLong_AsUint64Mask(obj) ((uint64_t)PyLong_AsUnsignedLongMask(obj))
#elif ULLONG_MAX == UINT64_MAX
#define PyLong_FromUint64(v) _Generic((v), uint64_t: PyLong_FromUnsignedLongLong)(v)
#define PyLong_AsUint64(obj) ((uint64_t)PyLong_AsUnsignedLongLong(obj))
#define PyLong_AsUint64Mask(obj) ((uint64_t)PyLong_AsUnsignedLongLongMask(obj))
#endif

#if LONG_MIN == INT64_MIN && LONG_MAX == INT64_MAX
#define PyLong_FromInt64(v) _Generic((v), int64_t: PyLong_FromLong)(v)
#define PyLong_AsInt64(obj) ((int64_t)PyLong_AsLong(obj))
#elif LLONG_MIN == INT64_MIN && LLONG_MAX == INT64_MAX
#define PyLong_FromInt64(v) _Generic((v), int64_t: PyLong_FromLongLong)(v)
#define PyLong_AsInt64(obj) ((int64_t)PyLong_AsLongLong(obj))
#endif

#if ULONG_MAX >= UINT32_MAX
#define PyLong_FromUint32(v) _Generic((v), uint32_t: PyLong_FromUnsignedLong)(v)
#define PyLong_FromUint16(v) _Generic((v), uint16_t: PyLong_FromUnsignedLong)(v)
#define PyLong_FromUint8(v) _Generic((v), uint8_t: PyLong_FromUnsignedLong)(v)
#endif

#define Py_RETURN_BOOL(cond) do {	\
	if (cond)			\
		Py_RETURN_TRUE;		\
	else				\
		Py_RETURN_FALSE;	\
} while (0)

/**
 * Return from a PyGetSetDef setter with an error if attempting to delete the
 * attribute.
 */
#define SETTER_NO_DELETE(name, value) do {				\
	if (!(value)) {							\
		PyErr_Format(PyExc_AttributeError,			\
			     "can't delete '%s' attribute", (name));	\
		return -1;						\
	}								\
} while (0)

static inline void pydecrefp(void *p)
{
	Py_XDECREF(*(PyObject **)p);
}

/** Scope guard that wraps PyGILState_Ensure() and PyGILState_Release(). */
#define PyGILState_guard()						\
	__attribute__((__cleanup__(PyGILState_Releasep), __unused__))	\
	PyGILState_STATE PP_UNIQUE(gstate) = PyGILState_Ensure()
static inline void PyGILState_Releasep(PyGILState_STATE *gstatep)
{
	PyGILState_Release(*gstatep);
}

/** Call @c Py_XDECREF() when the variable goes out of scope. */
#define _cleanup_pydecref_ _cleanup_(pydecrefp)

typedef struct {
	PyObject_HEAD
	struct drgn_object obj;
} DrgnObject;

typedef struct {
	PyObject_HEAD
	struct drgn_type *type;
	enum drgn_qualifiers qualifiers;
	/*
	 * Cache of attributes which were previously converted from a struct
	 * drgn_type member or used to create the type.
	 */
	PyObject *attr_cache;
} DrgnType;

typedef struct {
	PyObject_HEAD
	struct drgn_symbol_index index;
} SymbolIndex;

typedef struct {
	PyObject_HEAD
	/*
	 * "Python-friendly" name used for the object, which may differ from the
	 * language name if the language name is not a valid identifier (e.g.,
	 * C++).
	 */
	const char *attr_name;
	const struct drgn_language *language;
} Language;

typedef struct {
	PyObject_HEAD
	struct drgn_module *module;
} Module;

typedef struct {
	PyObject_HEAD
	struct drgn_module_iterator *it;
} ModuleIterator;

typedef struct {
	PyObject_HEAD
	struct drgn_module *module;
} ModuleSectionAddresses;

typedef struct {
	PyObject_HEAD
	struct drgn_module_section_address_iterator *it;
} ModuleSectionAddressesIterator;

typedef struct {
	PyObject_HEAD
	DrgnObject *obj;
	uint64_t index, end;
	int step;
} ObjectIterator;

typedef struct {
	PyObject_HEAD
	struct drgn_platform *platform;
} Platform;

DEFINE_HASH_SET_TYPE(pyobjectp_set, PyObject *);

typedef struct {
	PyObject_HEAD
	struct drgn_program prog;
	PyObject *cache;
	PyObject *config;
	/*
	 * Set of objects that we need to hold a reference to during the
	 * lifetime of the Program.
	 */
	struct pyobjectp_set objects;
} Program;

typedef struct {
	PyObject_HEAD
	struct drgn_debug_info_options *options;
	// If this is a Program's default debug info options, the Program.
	// Otherwise, NULL.
	Program *prog;
} DebugInfoOptions;

typedef struct {
	PyObject_HEAD
	struct drgn_thread thread;
} Thread;

typedef struct {
	PyObject_HEAD
	Program *prog;
	struct drgn_thread_iterator *iterator;
} ThreadIterator;

typedef struct {
	PyObject_HEAD
	const struct drgn_register *reg;
} Register;

typedef struct {
	PyObject_HEAD
	struct drgn_source_location_list *locs;
} SourceLocationList;

typedef struct {
	PyObject_HEAD
	struct drgn_stack_trace *trace;
} StackTrace;

typedef struct {
	PyObject_HEAD
	StackTrace *trace;
	size_t i;
} StackFrame;

typedef struct {
	PyObject_HEAD
	PyObject *name_obj; /* object owning the reference to the symbol name */
	struct drgn_symbol *sym;
} Symbol;

typedef struct {
	PyObject_HEAD
	PyObject *name;
	PyObject *value;
} TypeEnumerator;

typedef struct {
	PyObject_HEAD
	PyObject *obj;
	/*
	 * If DRGNPY_LAZY_OBJECT_EVALUATED, obj is the evaluated Object.
	 * If DRGNPY_LAZY_OBJECT_CALLABLE, obj is a Python callable that should
	 * return the Object.
	 * Otherwise, this must be evaluated and wrapped, and obj is a reference
	 * required to keep this alive.
	 */
	union drgn_lazy_object *lazy_obj;
} LazyObject;

typedef struct {
	PyObject_HEAD
	uint64_t kinds;
} TypeKindSet;

typedef struct {
	PyObject_HEAD
	uint64_t mask;
} TypeKindSetIterator;

typedef struct {
	LazyObject lazy_obj;
	PyObject *name;
	PyObject *bit_offset;
} TypeMember;

typedef struct {
	LazyObject lazy_obj;
	PyObject *name;
} TypeParameter;

typedef struct {
	LazyObject lazy_obj;
	PyObject *name;
	PyObject *is_default;
} TypeTemplateParameter;

extern PyObject *AbsenceReason_class;
extern PyObject *Architecture_class;
extern PyObject *FindObjectFlags_class;
extern PyObject *KmodSearchMethod_class;
extern PyObject *ModuleFileStatus_class;
extern PyObject *ModuleSectionAddresses_class;
extern PyObject *PlatformFlags_class;
extern PyObject *PrimitiveType_class;
extern PyObject *ProgramFlags_class;
extern PyObject *Qualifiers_class;
extern PyObject *SupplementaryFileKind_class;
extern PyObject *SymbolBinding_class;
extern PyObject *SymbolKind_class;
extern PyObject *TypeKind_class;
extern PyTypeObject DebugInfoOptions_type;
extern PyTypeObject DrgnObject_type;
extern PyTypeObject DrgnType_type;
extern PyTypeObject ExtraModule_type;
extern PyTypeObject FaultError_type;
extern PyTypeObject Language_type;
extern PyTypeObject MainModule_type;
extern PyTypeObject ModuleIteratorWithNew_type;
extern PyTypeObject ModuleIterator_type;
extern PyTypeObject ModuleSectionAddressesIterator_type;
extern PyTypeObject Module_type;
extern PyTypeObject ObjectIterator_type;
extern PyTypeObject ObjectNotFoundError_type;
extern PyTypeObject Platform_type;
extern PyTypeObject Program_type;
extern PyTypeObject Register_type;
extern PyTypeObject RelocatableModule_type;
extern PyTypeObject SharedLibraryModule_type;
extern PyTypeObject SourceLocationList_type;
extern PyObject *SourceLocation_type;
extern PyTypeObject StackFrame_type;
extern PyTypeObject StackTrace_type;
extern PyTypeObject SymbolIndex_type;
extern PyTypeObject Symbol_type;
extern PyTypeObject ThreadIterator_type;
extern PyTypeObject Thread_type;
extern PyTypeObject TypeEnumerator_type;
extern PyTypeObject TypeKindSetIterator_type;
extern PyTypeObject TypeKindSet_type;
extern PyTypeObject TypeMember_type;
extern PyTypeObject TypeParameter_type;
extern PyTypeObject TypeTemplateParameter_type;
extern PyTypeObject VdsoModule_type;
extern PyObject *MissingDebugInfoError;
extern PyObject *ObjectAbsentError;
extern PyObject *OutOfBoundsError;

PyGILState_STATE drgn_initialize_python(bool *success_ret);

#define drgn_initialize_python_guard(success_ret)				\
	__attribute__((__cleanup__(PyGILState_Releasep), __unused__))		\
	PyGILState_STATE PP_UNIQUE(gstate) = drgn_initialize_python(success_ret)

int add_module_constants(PyObject *m);
int init_logging(void);

bool set_drgn_in_python(void);
void clear_drgn_in_python(void);

static inline void drgn_in_python_cleanup(bool *clearp)
{
	if (*clearp)
		clear_drgn_in_python();
}

#define drgn_in_python_guard()							\
	__attribute__((__cleanup__(drgn_in_python_cleanup), __unused__))	\
	bool PP_UNIQUE(clear) = set_drgn_in_python()

struct drgn_error *drgn_error_from_python(void);
void *set_drgn_error(struct drgn_error *err);
void *set_error_type_name(const char *format,
			  struct drgn_qualified_type qualified_type);

#define call_tp_alloc(type) ((type *)type##_type.tp_alloc(&type##_type, 0))

PyObject *Module_wrap(struct drgn_module *module);
static inline Program *Module_prog(Module *module)
{
	struct drgn_program *prog = drgn_module_program(module->module);
	return container_of(prog, Program, prog);
}

int add_WantedSupplementaryFile(PyObject *m);
int init_module_section_addresses(void);

PyObject *Language_wrap(const struct drgn_language *language);
int language_converter(PyObject *o, void *p);
int add_languages(void);

PyObject *TypeKindSet_wrap(uint64_t mask);
int init_type_kind_set(void);

static inline DrgnObject *DrgnObject_alloc(Program *prog)
{
	DrgnObject *ret = call_tp_alloc(DrgnObject);
	if (ret) {
		drgn_object_init(&ret->obj, &prog->prog);
		Py_INCREF(prog);
	}
	return ret;
}
static inline Program *DrgnObject_prog(DrgnObject *obj)
{
	return container_of(drgn_object_program(&obj->obj), Program, prog);
}
PyObject *DrgnObject_NULL(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *cast(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *implicit_convert(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *reinterpret(PyObject *self, PyObject *args, PyObject *kwds);
DrgnObject *DrgnObject_container_of(PyObject *self, PyObject *args,
				    PyObject *kwds);

PyObject *Platform_wrap(const struct drgn_platform *platform);

int Program_hold_object(Program *prog, PyObject *obj);
bool Program_hold_reserve(Program *prog, size_t n);
int Program_type_arg(Program *prog, PyObject *type_obj, bool can_be_none,
		     struct drgn_qualified_type *ret);
Program *program_from_core_dump(PyObject *self, PyObject *args, PyObject *kwds);
Program *program_from_kernel(PyObject *self);
Program *program_from_pid(PyObject *self, PyObject *args, PyObject *kwds);

int add_SourceLocation(PyObject *m);
PyObject *SourceLocationList_wrap(struct drgn_source_location_list *locs);

PyObject *Symbol_wrap(struct drgn_symbol *sym, PyObject *name_obj);
PyObject *Symbol_list_wrap(struct drgn_symbol **symbols, size_t count,
			   PyObject *name_obj);

PyObject *Thread_wrap(struct drgn_thread *drgn_thread);

PyObject *StackTrace_wrap(struct drgn_stack_trace *trace);

static inline Program *DrgnType_prog(DrgnType *type)
{
	return container_of(drgn_type_program(type->type), Program, prog);
}
PyObject *DrgnType_wrap(struct drgn_qualified_type qualified_type);
DrgnType *Program_void_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_int_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_bool_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_float_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_struct_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_union_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_class_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_enum_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_typedef_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_pointer_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_array_type(Program *self, PyObject *args, PyObject *kwds);
DrgnType *Program_function_type(Program *self, PyObject *args, PyObject *kwds);

int append_string(PyObject *parts, const char *s);
int append_u64_hex(PyObject *parts, uint64_t value);
int append_format(PyObject *parts, const char *format, ...);
int append_attr_repr(PyObject *parts, PyObject *obj, const char *attr_name);
int append_attr_str(PyObject *parts, PyObject *obj, const char *attr_name);
PyObject *join_strings(PyObject *parts);
// Implementation of _repr_pretty_() for IPython/Jupyter that just calls str().
PyObject *repr_pretty_from_str(PyObject *self, PyObject *args, PyObject *kwds);

struct index_arg {
	bool allow_none;
	bool is_none;
	bool is_signed;
	union {
		unsigned long long uvalue;
		long long svalue;
	};
};
int index_converter(PyObject *o, void *p);

int u64_converter(PyObject *o, void *p);

struct path_arg {
	bool allow_fd;
	bool allow_none;
	int fd;
	char *path;
	Py_ssize_t length;
	PyObject *object;
	PyObject *bytes;
};
int path_converter(PyObject *o, void *p);
void path_cleanup(struct path_arg *path);

#define PATH_ARG(name, ...)				\
	__attribute__((__cleanup__(path_cleanup)))	\
	struct path_arg name = { __VA_ARGS__ }

DEFINE_VECTOR_TYPE(path_arg_vector, struct path_arg);

struct path_sequence_arg {
	bool allow_none;
	bool null_terminate;
	struct path_arg_vector args;
	const char **paths;
};
int path_sequence_converter(PyObject *o, void *p);
void path_sequence_cleanup(struct path_sequence_arg *paths);
size_t path_sequence_size(struct path_sequence_arg *paths);

#define PATH_SEQUENCE_ARG(name, ...)						\
	__attribute__((__cleanup__(path_sequence_cleanup)))			\
	struct path_sequence_arg name = { .args = VECTOR_INIT, __VA_ARGS__ }

struct enum_arg {
	PyObject *type;
	unsigned long value;
	bool allow_none;
};
int enum_converter(PyObject *o, void *p);

PyObject *drgnpy_linux_helper_direct_mapping_offset(PyObject *self,
						    PyObject *arg);
PyObject *drgnpy_linux_helper_read_vm(PyObject *self, PyObject *args,
				      PyObject *kwds);
PyObject *drgnpy_linux_helper_follow_phys(PyObject *self, PyObject *args,
					  PyObject *kwds);
DrgnObject *drgnpy_linux_helper_per_cpu_ptr(PyObject *self, PyObject *args,
					    PyObject *kwds);
DrgnObject *drgnpy_linux_helper_cpu_curr(PyObject *self, PyObject *args);
DrgnObject *drgnpy_linux_helper_idle_task(PyObject *self, PyObject *args);
DrgnObject *drgnpy_linux_helper_task_thread_info(PyObject *self, PyObject *args,
						 PyObject *kwds);
PyObject *drgnpy_linux_helper_task_cpu(PyObject *self, PyObject *args,
				       PyObject *kwds);
PyObject *drgnpy_linux_helper_task_on_cpu(PyObject *self, PyObject *args,
					  PyObject *kwds);
DrgnObject *drgnpy_linux_helper_xa_load(PyObject *self, PyObject *args,
					PyObject *kwds);
DrgnObject *drgnpy_linux_helper_idr_find(PyObject *self, PyObject *args,
					 PyObject *kwds);
DrgnObject *drgnpy_linux_helper_find_pid(PyObject *self, PyObject *args);
DrgnObject *drgnpy_linux_helper_pid_task(PyObject *self, PyObject *args,
					 PyObject *kwds);
DrgnObject *drgnpy_linux_helper_find_task(PyObject *self, PyObject *args);
PyObject *drgnpy_linux_helper_kaslr_offset(PyObject *self, PyObject *arg);
PyObject *drgnpy_linux_helper_pgtable_l5_enabled(PyObject *self, PyObject *arg);
PyObject *drgnpy_linux_helper_load_proc_kallsyms(PyObject *self, PyObject *args,
						 PyObject *kwds);
PyObject *drgnpy_linux_helper_load_builtin_kallsyms(PyObject *self, PyObject *args,
						    PyObject *kwds);

#endif /* DRGNPY_H */
