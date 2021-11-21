// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drgnpy.h"
#include "../hash_table.h"
#include "../program.h"
#include "../vector.h"
#include "../util.h"

DEFINE_HASH_SET_FUNCTIONS(pyobjectp_set, ptr_key_hash_pair, scalar_key_eq)

int Program_hold_object(Program *prog, PyObject *obj)
{
	int ret = pyobjectp_set_insert(&prog->objects, &obj, NULL);
	if (ret > 0) {
		Py_INCREF(obj);
		ret = 0;
	}
	return ret;
}

bool Program_hold_reserve(Program *prog, size_t n)
{
	return pyobjectp_set_reserve(&prog->objects,
				     pyobjectp_set_size(&prog->objects) + n);
}

int Program_type_arg(Program *prog, PyObject *type_obj, bool can_be_none,
		     struct drgn_qualified_type *ret)
{
	struct drgn_error *err;

	if (PyObject_TypeCheck(type_obj, &DrgnType_type)) {
		if (DrgnType_prog((DrgnType *)type_obj) != prog) {
			PyErr_SetString(PyExc_ValueError,
					"type is from different program");
			return -1;
		}
		ret->type = ((DrgnType *)type_obj)->type;
		ret->qualifiers = ((DrgnType *)type_obj)->qualifiers;
	} else if (PyUnicode_Check(type_obj)) {
		const char *name;

		name = PyUnicode_AsUTF8(type_obj);
		if (!name)
			return -1;
		err = drgn_program_find_type(&prog->prog, name, NULL, ret);
		if (err) {
			set_drgn_error(err);
			return -1;
		}
	} else if (can_be_none && type_obj == Py_None) {
		ret->type = NULL;
		ret->qualifiers = 0;
	} else {
		PyErr_SetString(PyExc_TypeError,
				can_be_none ?
				"type must be Type, str, or None" :
				"type must be Type or str");
		return -1;
	}
	return 0;
}

static Program *Program_new(PyTypeObject *subtype, PyObject *args,
			    PyObject *kwds)
{
	static char *keywords[] = { "platform", NULL };
	PyObject *platform_obj = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O:Program", keywords,
					 &platform_obj))
		return NULL;

	struct drgn_platform *platform;
	if (!platform_obj || platform_obj == Py_None) {
		platform = NULL;
	} else if (PyObject_TypeCheck(platform_obj, &Platform_type)) {
		platform = ((Platform *)platform_obj)->platform;
	} else {
		PyErr_SetString(PyExc_TypeError,
				"platform must be Platform or None");
		return NULL;
	}

	PyObject *cache = PyDict_New();
	if (!cache)
		return NULL;

	Program *prog = (Program *)Program_type.tp_alloc(&Program_type, 0);
	if (!prog) {
		Py_DECREF(cache);
		return NULL;
	}
	prog->cache = cache;
	pyobjectp_set_init(&prog->objects);
	drgn_program_init(&prog->prog, platform);
	return prog;
}

static void Program_dealloc(Program *self)
{
	drgn_program_deinit(&self->prog);
	for (struct pyobjectp_set_iterator it =
	     pyobjectp_set_first(&self->objects); it.entry;
	     it = pyobjectp_set_next(it))
		Py_DECREF(*it.entry);
	pyobjectp_set_deinit(&self->objects);
	Py_XDECREF(self->cache);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int Program_traverse(Program *self, visitproc visit, void *arg)
{
	for (struct pyobjectp_set_iterator it =
	     pyobjectp_set_first(&self->objects); it.entry;
	     it = pyobjectp_set_next(it))
		Py_VISIT(*it.entry);
	Py_VISIT(self->cache);
	return 0;
}

static int Program_clear(Program *self)
{
	for (struct pyobjectp_set_iterator it =
	     pyobjectp_set_first(&self->objects); it.entry;
	     it = pyobjectp_set_next(it))
		Py_DECREF(*it.entry);
	pyobjectp_set_deinit(&self->objects);
	pyobjectp_set_init(&self->objects);
	Py_CLEAR(self->cache);
	return 0;
}

static struct drgn_error *py_memory_read_fn(void *buf, uint64_t address,
					    size_t count, uint64_t offset,
					    void *arg, bool physical)
{
	struct drgn_error *err;
	PyGILState_STATE gstate;
	PyObject *ret;
	Py_buffer view;

	gstate = PyGILState_Ensure();
	ret = PyObject_CallFunction(arg, "KKKO", (unsigned long long)address,
				    (unsigned long long)count,
				    (unsigned long long)offset,
				    physical ? Py_True : Py_False);
	if (!ret) {
		err = drgn_error_from_python();
		goto out;
	}
	if (PyObject_GetBuffer(ret, &view, PyBUF_SIMPLE) == -1) {
		err = drgn_error_from_python();
		goto out_ret;
	}
	if (view.len != count) {
		PyErr_Format(PyExc_ValueError,
			     "memory read callback returned buffer of length %zd (expected %zu)",
			     view.len, count);
		err = drgn_error_from_python();
		goto out_view;
	}
	memcpy(buf, view.buf, count);

	err = NULL;
out_view:
	PyBuffer_Release(&view);
out_ret:
	Py_DECREF(ret);
out:
	PyGILState_Release(gstate);
	return err;
}

static PyObject *Program_add_memory_segment(Program *self, PyObject *args,
					    PyObject *kwds)
{
	static char *keywords[] = {
		"address", "size", "read_fn", "physical", NULL,
	};
	struct drgn_error *err;
	struct index_arg address = {};
	struct index_arg size = {};
	PyObject *read_fn;
	int physical = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					 "O&O&O|p:add_memory_segment", keywords,
					 index_converter, &address,
					 index_converter, &size, &read_fn,
					 &physical))
	    return NULL;

	if (!PyCallable_Check(read_fn)) {
		PyErr_SetString(PyExc_TypeError, "read_fn must be callable");
		return NULL;
	}

	if (Program_hold_object(self, read_fn) == -1)
		return NULL;
	err = drgn_program_add_memory_segment(&self->prog, address.uvalue,
					      size.uvalue, py_memory_read_fn,
					      read_fn, physical);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static struct drgn_error *py_type_find_fn(enum drgn_type_kind kind,
					  const char *name, size_t name_len,
					  const char *filename, void *arg,
					  struct drgn_qualified_type *ret)
{
	struct drgn_error *err;
	PyGILState_STATE gstate;
	PyObject *kind_obj, *name_obj;
	PyObject *type_obj;

	gstate = PyGILState_Ensure();
	kind_obj = PyObject_CallFunction(TypeKind_class, "k",
					 (unsigned long)kind);
	if (!kind_obj) {
		err = drgn_error_from_python();
		goto out_gstate;
	}
	name_obj = PyUnicode_FromStringAndSize(name, name_len);
	if (!name_obj) {
		err = drgn_error_from_python();
		goto out_kind_obj;
	}
	type_obj = PyObject_CallFunction(PyTuple_GET_ITEM(arg, 1), "OOs",
					 kind_obj, name_obj, filename);
	if (!type_obj) {
		err = drgn_error_from_python();
		goto out_name_obj;
	}
	if (type_obj == Py_None) {
		err = &drgn_not_found;
		goto out_type_obj;
	}
	if (!PyObject_TypeCheck(type_obj, &DrgnType_type)) {
		PyErr_SetString(PyExc_TypeError,
				"type find callback must return Type or None");
		err = drgn_error_from_python();
		goto out_type_obj;
	}
	/*
	 * This check is also done in libdrgn, but we need it here because if
	 * the type isn't from this program, then there's no guarantee that it
	 * will remain valid after we decrement its reference count.
	 */
	if (DrgnType_prog((DrgnType *)type_obj) !=
	    (Program *)PyTuple_GET_ITEM(arg, 0)) {
		PyErr_SetString(PyExc_ValueError,
				"type find callback returned type from wrong program");
		err = drgn_error_from_python();
		goto out_type_obj;
	}

	ret->type = ((DrgnType *)type_obj)->type;
	ret->qualifiers = ((DrgnType *)type_obj)->qualifiers;
	err = NULL;
out_type_obj:
	Py_DECREF(type_obj);
out_name_obj:
	Py_DECREF(name_obj);
out_kind_obj:
	Py_DECREF(kind_obj);
out_gstate:
	PyGILState_Release(gstate);
	return err;
}

static PyObject *Program_add_type_finder(Program *self, PyObject *args,
					 PyObject *kwds)
{
	static char *keywords[] = {"fn", NULL};
	struct drgn_error *err;
	PyObject *fn, *arg;
	int ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:add_type_finder",
					 keywords, &fn))
	    return NULL;

	if (!PyCallable_Check(fn)) {
		PyErr_SetString(PyExc_TypeError, "fn must be callable");
		return NULL;
	}

	arg = Py_BuildValue("OO", self, fn);
	if (!arg)
		return NULL;
	ret = Program_hold_object(self, arg);
	Py_DECREF(arg);
	if (ret == -1)
		return NULL;

	err = drgn_program_add_type_finder(&self->prog, py_type_find_fn, arg);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static struct drgn_error *py_object_find_fn(const char *name, size_t name_len,
					    const char *filename,
					    enum drgn_find_object_flags flags,
					    void *arg, struct drgn_object *ret)
{
	struct drgn_error *err;
	PyGILState_STATE gstate;
	PyObject *name_obj, *flags_obj;
	PyObject *obj;

	gstate = PyGILState_Ensure();
	name_obj = PyUnicode_FromStringAndSize(name, name_len);
	if (!name_obj) {
		err = drgn_error_from_python();
		goto out_gstate;
	}
	flags_obj = PyObject_CallFunction(FindObjectFlags_class, "i",
					  (int)flags);
	if (!flags_obj) {
		err = drgn_error_from_python();
		goto out_name_obj;
	}
	obj = PyObject_CallFunction(PyTuple_GET_ITEM(arg, 1), "OOOs",
				    PyTuple_GET_ITEM(arg, 0), name_obj,
				    flags_obj, filename);
	if (!obj) {
		err = drgn_error_from_python();
		goto out_flags_obj;
	}
	if (obj == Py_None) {
		err = &drgn_not_found;
		goto out_obj;
	}
	if (!PyObject_TypeCheck(obj, &DrgnObject_type)) {
		PyErr_SetString(PyExc_TypeError,
				"object find callback must return Object or None");
		err = drgn_error_from_python();
		goto out_obj;
	}

	err = drgn_object_copy(ret, &((DrgnObject *)obj)->obj);
out_obj:
	Py_DECREF(obj);
out_flags_obj:
	Py_DECREF(flags_obj);
out_name_obj:
	Py_DECREF(name_obj);
out_gstate:
	PyGILState_Release(gstate);
	return err;
}

static PyObject *Program_add_object_finder(Program *self, PyObject *args,
					   PyObject *kwds)
{
	static char *keywords[] = {"fn", NULL};
	struct drgn_error *err;
	PyObject *fn, *arg;
	int ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:add_object_finder",
					 keywords, &fn))
	    return NULL;

	if (!PyCallable_Check(fn)) {
		PyErr_SetString(PyExc_TypeError, "fn must be callable");
		return NULL;
	}

	arg = Py_BuildValue("OO", self, fn);
	if (!arg)
		return NULL;
	ret = Program_hold_object(self, arg);
	Py_DECREF(arg);
	if (ret == -1)
		return NULL;

	err = drgn_program_add_object_finder(&self->prog, py_object_find_fn,
					     arg);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *Program_set_core_dump(Program *self, PyObject *args,
				       PyObject *kwds)
{
	static char *keywords[] = {"path", NULL};
	struct drgn_error *err;
	struct path_arg path = {};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&:set_core_dump",
					 keywords, path_converter, &path))
		return NULL;

	err = drgn_program_set_core_dump(&self->prog, path.path);
	path_cleanup(&path);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *Program_set_kernel(Program *self)
{
	struct drgn_error *err;

	err = drgn_program_set_kernel(&self->prog);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *Program_set_pid(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"pid", NULL};
	struct drgn_error *err;
	int pid;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:set_pid", keywords,
					 &pid))
		return NULL;

	err = drgn_program_set_pid(&self->prog, pid);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

DEFINE_VECTOR(path_arg_vector, struct path_arg)

static PyObject *Program_load_debug_info(Program *self, PyObject *args,
					 PyObject *kwds)
{
	static char *keywords[] = {"paths", "default", "main", NULL};
	struct drgn_error *err;
	PyObject *paths_obj = Py_None;
	int load_default = 0;
	int load_main = 0;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|Opp:load_debug_info",
					 keywords, &paths_obj, &load_default,
					 &load_main))
		return NULL;

	struct path_arg_vector path_args = VECTOR_INIT;
	const char **paths = NULL;
	if (paths_obj != Py_None) {
		Py_ssize_t length_hint;
		PyObject *it, *item;

		it = PyObject_GetIter(paths_obj);
		if (!it)
			goto out;

		length_hint = PyObject_LengthHint(paths_obj, 1);
		if (length_hint == -1) {
			Py_DECREF(it);
			goto out;
		}
		if (!path_arg_vector_reserve(&path_args, length_hint)) {
			PyErr_NoMemory();
			Py_DECREF(it);
			goto out;
		}

		while ((item = PyIter_Next(it))) {
			struct path_arg *path_arg;
			int ret;

			path_arg = path_arg_vector_append_entry(&path_args);
			if (!path_arg) {
				PyErr_NoMemory();
				Py_DECREF(item);
				break;
			}
			memset(path_arg, 0, sizeof(*path_arg));
			ret = path_converter(item, path_arg);
			Py_DECREF(item);
			if (!ret) {
				path_args.size--;
				break;
			}
		}
		Py_DECREF(it);
		if (PyErr_Occurred())
			goto out;

		paths = malloc_array(path_args.size, sizeof(*paths));
		if (!paths) {
			PyErr_NoMemory();
			goto out;
		}
		for (size_t i = 0; i < path_args.size; i++)
			paths[i] = path_args.data[i].path;
	}
	err = drgn_program_load_debug_info(&self->prog, paths, path_args.size,
					   load_default, load_main);
	free(paths);
	if (err)
		set_drgn_error(err);

out:
	for (size_t i = 0; i < path_args.size; i++)
		path_cleanup(&path_args.data[i]);
	path_arg_vector_deinit(&path_args);
	if (PyErr_Occurred())
		return NULL;
	Py_RETURN_NONE;
}

static PyObject *Program_load_default_debug_info(Program *self)
{
	struct drgn_error *err;

	err = drgn_program_load_debug_info(&self->prog, NULL, 0, true, true);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *Program_read(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"address", "size", "physical", NULL};
	struct drgn_error *err;
	struct index_arg address = {};
	Py_ssize_t size;
	int physical = 0;
	PyObject *buf;
	bool clear;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&n|p:read", keywords,
					 index_converter, &address, &size,
					 &physical))
	    return NULL;

	if (size < 0) {
		PyErr_SetString(PyExc_ValueError, "negative size");
		return NULL;
	}
	buf = PyBytes_FromStringAndSize(NULL, size);
	if (!buf)
		return NULL;
	clear = set_drgn_in_python();
	err = drgn_program_read_memory(&self->prog, PyBytes_AS_STRING(buf),
				       address.uvalue, size, physical);
	if (clear)
		clear_drgn_in_python();
	if (err) {
		Py_DECREF(buf);
		return set_drgn_error(err);
	}
	return buf;
}

#define METHOD_READ(x, type)							\
static PyObject *Program_read_##x(Program *self, PyObject *args,		\
				  PyObject *kwds)				\
{										\
	static char *keywords[] = {"address", "physical", NULL};		\
	struct drgn_error *err;							\
	struct index_arg address = {};						\
	int physical = 0;							\
	type tmp;								\
										\
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&|p:read_"#x, keywords,	\
					 index_converter, &address, &physical))	\
	    return NULL;							\
										\
	err = drgn_program_read_##x(&self->prog, address.uvalue, physical,	\
				    &tmp);					\
	if (err)								\
		return set_drgn_error(err);					\
	if (sizeof(tmp) <= sizeof(unsigned long))				\
		return PyLong_FromUnsignedLong(tmp);				\
	else									\
		return PyLong_FromUnsignedLongLong(tmp);			\
}
METHOD_READ(u8, uint8_t)
METHOD_READ(u16, uint16_t)
METHOD_READ(u32, uint32_t)
METHOD_READ(u64, uint64_t)
METHOD_READ(word, uint64_t)
#undef METHOD_READ

static PyObject *Program_find_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	struct drgn_error *err;
	const char *name;
	struct path_arg filename = {.allow_none = true};
	struct drgn_qualified_type qualified_type;
	bool clear;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:type", keywords,
					 &name, path_converter, &filename))
		return NULL;

	clear = set_drgn_in_python();
	err = drgn_program_find_type(&self->prog, name, filename.path,
				     &qualified_type);
	if (clear)
		clear_drgn_in_python();
	path_cleanup(&filename);
	if (err)
		return set_drgn_error(err);
	return DrgnType_wrap(qualified_type);
}

static DrgnObject *Program_find_object(Program *self, const char *name,
				       struct path_arg *filename,
				       enum drgn_find_object_flags flags)
{
	struct drgn_error *err;
	DrgnObject *ret;
	bool clear;

	ret = DrgnObject_alloc(self);
	if (!ret)
		return NULL;

	clear = set_drgn_in_python();
	err = drgn_program_find_object(&self->prog, name, filename->path, flags,
				       &ret->obj);
	if (clear)
		clear_drgn_in_python();
	path_cleanup(filename);
	if (err) {
		Py_DECREF(ret);
		return set_drgn_error(err);
	}
	return ret;
}

static DrgnObject *Program_object(Program *self, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {"name", "flags", "filename", NULL};
	const char *name;
	struct enum_arg flags = {
		.type = FindObjectFlags_class,
		.value = DRGN_FIND_OBJECT_ANY,
	};
	struct path_arg filename = {.allow_none = true};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&O&:object", keywords,
					 &name, enum_converter, &flags,
					 path_converter, &filename))
		return NULL;

	return Program_find_object(self, name, &filename, flags.value);
}

static DrgnObject *Program_constant(Program *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	const char *name;
	struct path_arg filename = {.allow_none = true};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:constant", keywords,
					 &name, path_converter, &filename))
		return NULL;

	return Program_find_object(self, name, &filename,
				   DRGN_FIND_OBJECT_CONSTANT);
}

static DrgnObject *Program_function(Program *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	const char *name;
	struct path_arg filename = {.allow_none = true};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:function", keywords,
					 &name, path_converter, &filename))
		return NULL;

	return Program_find_object(self, name, &filename,
				   DRGN_FIND_OBJECT_FUNCTION);
}

static DrgnObject *Program_variable(Program *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	const char *name;
	struct path_arg filename = {.allow_none = true};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:variable", keywords,
					 &name, path_converter, &filename))
		return NULL;

	return Program_find_object(self, name, &filename,
				   DRGN_FIND_OBJECT_VARIABLE);
}

static StackTrace *Program_stack_trace(Program *self, PyObject *args,
				       PyObject *kwds)
{
	static char *keywords[] = {"thread", NULL};
	struct drgn_error *err;
	PyObject *thread;
	struct drgn_stack_trace *trace;
	StackTrace *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:stack_trace", keywords,
					 &thread))
		return NULL;

	if (PyObject_TypeCheck(thread, &DrgnObject_type)) {
		err = drgn_object_stack_trace(&((DrgnObject *)thread)->obj,
					      &trace);
	} else {
		struct index_arg tid = {};

		if (!index_converter(thread, &tid))
			return NULL;
		err = drgn_program_stack_trace(&self->prog, tid.uvalue, &trace);
	}
	if (err)
		return set_drgn_error(err);

	ret = (StackTrace *)StackTrace_type.tp_alloc(&StackTrace_type, 0);
	if (!ret) {
		drgn_stack_trace_destroy(trace);
		return NULL;
	}
	ret->trace = trace;
	Py_INCREF(self);
	return ret;
}

static PyObject *Program_symbol(Program *self, PyObject *arg)
{
	struct drgn_error *err;
	struct drgn_symbol *sym;
	PyObject *ret;

	if (PyUnicode_Check(arg)) {
		const char *name;

		name = PyUnicode_AsUTF8(arg);
		if (!name)
			return NULL;
		err = drgn_program_find_symbol_by_name(&self->prog, name, &sym);
	} else {
		struct index_arg address = {};

		if (!index_converter(arg, &address))
			return NULL;
		err = drgn_program_find_symbol_by_address(&self->prog,
							  address.uvalue, &sym);
	}
	if (err)
		return set_drgn_error(err);
	ret = Symbol_wrap(sym, self);
	if (!ret) {
		drgn_symbol_destroy(sym);
		return NULL;
	}
	return ret;
}

static DrgnObject *Program_subscript(Program *self, PyObject *key)
{
	struct drgn_error *err;
	const char *name;
	DrgnObject *ret;
	bool clear;

	if (!PyUnicode_Check(key)) {
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	}

	name = PyUnicode_AsUTF8(key);
	if (!name)
		return NULL;

	ret = DrgnObject_alloc(self);
	if (!ret)
		return NULL;

	clear = set_drgn_in_python();
	err = drgn_program_find_object(&self->prog, name, NULL,
				       DRGN_FIND_OBJECT_ANY, &ret->obj);
	if (clear)
		clear_drgn_in_python();
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			PyErr_SetObject(PyExc_KeyError, key);
		} else {
			set_drgn_error(err);
		}
		Py_DECREF(ret);
		return NULL;
	}
	return ret;
}

static int Program_contains(Program *self, PyObject *key)
{
	struct drgn_error *err;
	const char *name;
	struct drgn_object tmp;
	bool clear;

	if (!PyUnicode_Check(key)) {
		PyErr_SetObject(PyExc_KeyError, key);
		return 0;
	}

	name = PyUnicode_AsUTF8(key);
	if (!name)
		return -1;

	drgn_object_init(&tmp, &self->prog);
	clear = set_drgn_in_python();
	err = drgn_program_find_object(&self->prog, name, NULL,
				       DRGN_FIND_OBJECT_ANY, &tmp);
	if (clear)
		clear_drgn_in_python();
	drgn_object_deinit(&tmp);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			return 0;
		} else {
			set_drgn_error(err);
			return -1;
		}
	}
	return 1;
}

static PyObject *Program_get_flags(Program *self, void *arg)
{
	return PyObject_CallFunction(ProgramFlags_class, "k",
				     (unsigned long)self->prog.flags);
}

static PyObject *Program_get_platform(Program *self, void *arg)
{
	const struct drgn_platform *platform;

	platform = drgn_program_platform(&self->prog);
	if (platform)
		return Platform_wrap(platform);
	else
		Py_RETURN_NONE;
}

static PyObject *Program_get_language(Program *self, void *arg)
{
	return Language_wrap(drgn_program_language(&self->prog));
}

static PyMethodDef Program_methods[] = {
	{"add_memory_segment", (PyCFunction)Program_add_memory_segment,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_add_memory_segment_DOC},
	{"add_type_finder", (PyCFunction)Program_add_type_finder,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_add_type_finder_DOC},
	{"add_object_finder", (PyCFunction)Program_add_object_finder,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_add_object_finder_DOC},
	{"set_core_dump", (PyCFunction)Program_set_core_dump,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_set_core_dump_DOC},
	{"set_kernel", (PyCFunction)Program_set_kernel, METH_NOARGS,
	 drgn_Program_set_kernel_DOC},
	{"set_pid", (PyCFunction)Program_set_pid, METH_VARARGS | METH_KEYWORDS,
	 drgn_Program_set_pid_DOC},
	{"load_debug_info", (PyCFunction)Program_load_debug_info,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_load_debug_info_DOC},
	{"load_default_debug_info",
	 (PyCFunction)Program_load_default_debug_info, METH_NOARGS,
	 drgn_Program_load_default_debug_info_DOC},
	{"__getitem__", (PyCFunction)Program_subscript, METH_O | METH_COEXIST,
	 drgn_Program___getitem___DOC},
	{"__contains__", (PyCFunction)Program_contains, METH_O | METH_COEXIST,
	 drgn_Program___contains___DOC},
	{"read", (PyCFunction)Program_read, METH_VARARGS | METH_KEYWORDS,
	 drgn_Program_read_DOC},
#define METHOD_DEF_READ(x)						\
	{"read_"#x, (PyCFunction)Program_read_##x,			\
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_read_##x##_DOC}
	METHOD_DEF_READ(u8),
	METHOD_DEF_READ(u16),
	METHOD_DEF_READ(u32),
	METHOD_DEF_READ(u64),
	METHOD_DEF_READ(word),
#undef METHOD_READ_U
	{"type", (PyCFunction)Program_find_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_Program_type_DOC},
	{"object", (PyCFunction)Program_object, METH_VARARGS | METH_KEYWORDS,
	 drgn_Program_object_DOC},
	{"constant", (PyCFunction)Program_constant,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_constant_DOC},
	{"function", (PyCFunction)Program_function,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_function_DOC},
	{"variable", (PyCFunction)Program_variable,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_variable_DOC},
	{"stack_trace", (PyCFunction)Program_stack_trace,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_stack_trace_DOC},
	{"symbol", (PyCFunction)Program_symbol, METH_O,
	 drgn_Program_symbol_DOC},
	{"void_type", (PyCFunction)Program_void_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_void_type_DOC},
	{"int_type", (PyCFunction)Program_int_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_int_type_DOC},
	{"bool_type", (PyCFunction)Program_bool_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_bool_type_DOC},
	{"float_type", (PyCFunction)Program_float_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_float_type_DOC},
	{"struct_type", (PyCFunction)Program_struct_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_struct_type_DOC},
	{"union_type", (PyCFunction)Program_union_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_union_type_DOC},
	{"class_type", (PyCFunction)Program_class_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_class_type_DOC},
	{"enum_type", (PyCFunction)Program_enum_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_enum_type_DOC},
	{"typedef_type", (PyCFunction)Program_typedef_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_typedef_type_DOC},
	{"pointer_type", (PyCFunction)Program_pointer_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_pointer_type_DOC},
	{"array_type", (PyCFunction)Program_array_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_array_type_DOC},
	{"function_type", (PyCFunction)Program_function_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_function_type_DOC},
	{},
};

static PyMemberDef Program_members[] = {
	{"cache", T_OBJECT_EX, offsetof(Program, cache), 0,
	 drgn_Program_cache_DOC},
	{},
};

static PyGetSetDef Program_getset[] = {
	{"flags", (getter)Program_get_flags, NULL, drgn_Program_flags_DOC},
	{"platform", (getter)Program_get_platform, NULL,
	 drgn_Program_platform_DOC},
	{"language", (getter)Program_get_language, NULL,
	 drgn_Program_language_DOC},
	{},
};

static PyMappingMethods Program_as_mapping = {
	.mp_subscript = (binaryfunc)Program_subscript,
};

static PySequenceMethods Program_as_sequence = {
	.sq_contains = (objobjproc)Program_contains,
};

PyTypeObject Program_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Program",
	.tp_basicsize = sizeof(Program),
	.tp_dealloc = (destructor)Program_dealloc,
	.tp_as_sequence = &Program_as_sequence,
	.tp_as_mapping = &Program_as_mapping,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_Program_DOC,
	.tp_traverse = (traverseproc)Program_traverse,
	.tp_clear = (inquiry)Program_clear,
	.tp_methods = Program_methods,
	.tp_members = Program_members,
	.tp_getset = Program_getset,
	.tp_new = (newfunc)Program_new,
};

Program *program_from_core_dump(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"path", NULL};
	struct drgn_error *err;
	struct path_arg path = {};
	Program *prog;

	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					 "O&:program_from_core_dump", keywords,
					 path_converter, &path))
		return NULL;

	prog = (Program *)PyObject_CallObject((PyObject *)&Program_type, NULL);
	if (!prog) {
		path_cleanup(&path);
		return NULL;
	}

	err = drgn_program_init_core_dump(&prog->prog, path.path);
	path_cleanup(&path);
	if (err) {
		Py_DECREF(prog);
		return set_drgn_error(err);
	}
	return prog;
}

Program *program_from_kernel(PyObject *self)
{
	struct drgn_error *err;
	Program *prog;

	prog = (Program *)PyObject_CallObject((PyObject *)&Program_type, NULL);
	if (!prog)
		return NULL;

	err = drgn_program_init_kernel(&prog->prog);
	if (err) {
		Py_DECREF(prog);
		return set_drgn_error(err);
	}
	return prog;
}

Program *program_from_pid(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"pid", NULL};
	struct drgn_error *err;
	int pid;
	Program *prog;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:program_from_pid",
					 keywords, &pid))
		return NULL;

	prog = (Program *)PyObject_CallObject((PyObject *)&Program_type, NULL);
	if (!prog)
		return NULL;

	err = drgn_program_init_pid(&prog->prog, pid);
	if (err) {
		Py_DECREF(prog);
		return set_drgn_error(err);
	}
	return prog;
}
