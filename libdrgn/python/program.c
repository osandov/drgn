// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

static int Program_hold_object(Program *prog, PyObject *obj)
{
	PyObject *key;
	int ret;

	key = PyLong_FromVoidPtr(obj);
	if (!key)
		return -1;

	ret = PyDict_SetItem(prog->objects, key, obj);
	Py_DECREF(key);
	return ret;
}

static int Program_hold_type(Program *prog, DrgnType *type)
{
	PyObject *parent;

	parent = DrgnType_parent(type);
	if (parent && parent != (PyObject *)prog)
		return Program_hold_object(prog, parent);
	else
		return 0;
}

int Program_type_arg(Program *prog, PyObject *type_obj, bool can_be_none,
		     struct drgn_qualified_type *ret)
{
	struct drgn_error *err;

	if (PyObject_TypeCheck(type_obj, &DrgnType_type)) {
		if (Program_hold_type(prog, (DrgnType *)type_obj) == -1)
			return -1;
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
	static char *keywords[] = {"platform", NULL};
	PyObject *platform_obj = NULL, *objects, *cache;
	struct drgn_platform *platform;
	Program *prog;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O:Program", keywords,
					 &platform_obj))
		return NULL;

	if (!platform_obj || platform_obj == Py_None) {
		platform = NULL;
	} else if (PyObject_TypeCheck(platform_obj, &Platform_type)) {
		platform = ((Platform *)platform_obj)->platform;
	} else {
		PyErr_SetString(PyExc_TypeError,
				"platform must be Platform or None");
		return NULL;
	}

	objects = PyDict_New();
	if (!objects)
		return NULL;

	cache = PyDict_New();
	if (!cache)
		return NULL;

	prog = (Program *)Program_type.tp_alloc(&Program_type, 0);
	if (!prog) {
		Py_DECREF(cache);
		Py_DECREF(objects);
		return NULL;
	}
	prog->objects = objects;
	prog->cache = cache;
	drgn_program_init(&prog->prog, platform);
	return prog;
}

static void Program_dealloc(Program *self)
{
	drgn_program_deinit(&self->prog);
	Py_XDECREF(self->objects);
	Py_XDECREF(self->cache);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int Program_traverse(Program *self, visitproc visit, void *arg)
{
	Py_VISIT(self->objects);
	Py_VISIT(self->cache);
	return 0;
}

static int Program_clear(Program *self)
{
	Py_CLEAR(self->objects);
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
	unsigned long long address;
	unsigned long long size;
	PyObject *read_fn;
	int physical = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "KKO|p:add_memory_segment",
					 keywords, &address, &size, &read_fn,
					 &physical))
	    return NULL;

	if (!PyCallable_Check(read_fn)) {
		PyErr_SetString(PyExc_TypeError, "read_fn must be callable");
		return NULL;
	}

	if (Program_hold_object(self, read_fn) == -1)
		return NULL;
	err = drgn_program_add_memory_segment(&self->prog, address, size,
					      py_memory_read_fn, read_fn,
					      physical);
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
	kind_obj = PyObject_CallFunction(TypeKind_class, "k", kind);
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
	if (Program_hold_type((Program *)PyTuple_GET_ITEM(arg, 0),
			      (DrgnType *)type_obj) == -1) {
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

static PyObject *Program_load_debug_info(Program *self, PyObject *args,
					 PyObject *kwds)
{
	static char *keywords[] = {"paths", NULL};
	struct drgn_error *err;
	PyObject *paths_obj, *it, *item;
	struct path_arg *path_args = NULL;
	Py_ssize_t length_hint;
	size_t n = 0, i;
	const char **paths;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:load_debug_info",
					 keywords, &paths_obj))
		return NULL;

	it = PyObject_GetIter(paths_obj);
	if (!it)
		return NULL;

	length_hint = PyObject_LengthHint(paths_obj, 1);
	if (length_hint == -1) {
		Py_DECREF(it);
		return NULL;
	}
	path_args = calloc(length_hint, sizeof(*path_args));
	if (!path_args) {
		Py_DECREF(it);
		return NULL;
	}

	while ((item = PyIter_Next(it))) {
		int ret;

		if (n >= length_hint) {
			length_hint *= 2;
			if (!resize_array(&path_args, length_hint)) {
				Py_DECREF(item);
				PyErr_NoMemory();
				break;
			}
		}
		ret = path_converter(item, &path_args[n]);
		Py_DECREF(item);
		if (!ret)
			break;
		n++;
	}
	Py_DECREF(it);
	if (PyErr_Occurred())
		goto out;

	paths = malloc_array(n, sizeof(*paths));
	if (!paths) {
		PyErr_NoMemory();
		goto out;
	}
	for (i = 0; i < n; i++)
		paths[i] = path_args[i].path;
	err = drgn_program_load_debug_info(&self->prog, paths, n);
	free(paths);
	if (err)
		set_drgn_error(err);

out:
	for (i = 0; i < n; i++)
		path_cleanup(&path_args[i]);
	if (PyErr_Occurred())
		return NULL;
	Py_RETURN_NONE;
}

static PyObject *Program_load_default_debug_info(Program *self)
{
	struct drgn_error *err;

	err = drgn_program_load_default_debug_info(&self->prog);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *Program_read(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"address", "size", "physical", NULL};
	struct drgn_error *err;
	unsigned long long address;
	Py_ssize_t size;
	int physical = 0;
	PyObject *buf;
	bool clear;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Kn|p:read", keywords,
					 &address, &size, &physical))
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
				       address, size, physical);
	if (clear)
		clear_drgn_in_python();
	if (err) {
		Py_DECREF(buf);
		return set_drgn_error(err);
	}
	return buf;
}

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
	return DrgnType_wrap(qualified_type, (PyObject *)self);
}

static PyObject *Program_pointer_type(Program *self, PyObject *args,
				      PyObject *kwds)
{
	static char *keywords[] = {"type", "qualifiers", NULL};
	struct drgn_error *err;
	PyObject *referenced_type_obj;
	struct drgn_qualified_type referenced_type;
	unsigned char qualifiers = 0;
	struct drgn_qualified_type qualified_type;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O&:pointer_type",
					 keywords, &referenced_type_obj,
					 qualifiers_converter, &qualifiers))
		return NULL;

	if (Program_type_arg(self, referenced_type_obj, false,
			     &referenced_type) == -1)
		return NULL;

	err = drgn_type_index_pointer_type(&self->prog.tindex, referenced_type,
					   &qualified_type.type);
	if (err)
		return set_drgn_error(err);
	qualified_type.qualifiers = qualifiers;
	return DrgnType_wrap(qualified_type, (PyObject *)self);
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
		.allow_none = true,
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

static Symbol *Program_symbol(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"address", NULL};
	struct drgn_error *err;
	unsigned long long address;
	struct drgn_symbol *sym;
	Symbol *ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "K", keywords, &address))
		return NULL;

	err = drgn_program_find_symbol(&self->prog, address, &sym);
	if (err)
		return set_drgn_error(err);
	ret = (Symbol *)Symbol_type.tp_alloc(&Symbol_type, 0);
	if (!ret) {
		drgn_symbol_destroy(sym);
		return NULL;
	}
	ret->sym = sym;
	ret->prog = self;
	Py_INCREF(self);
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
	{"read", (PyCFunction)Program_read, METH_VARARGS | METH_KEYWORDS,
	 drgn_Program_read_DOC},
	{"type", (PyCFunction)Program_find_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_Program_type_DOC},
	{"pointer_type", (PyCFunction)Program_pointer_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_pointer_type_DOC},
	{"object", (PyCFunction)Program_object, METH_VARARGS | METH_KEYWORDS,
	 drgn_Program_object_DOC},
	{"constant", (PyCFunction)Program_constant,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_constant_DOC},
	{"function", (PyCFunction)Program_function,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_function_DOC},
	{"variable", (PyCFunction)Program_variable,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_variable_DOC},
	{"symbol", (PyCFunction)Program_symbol, METH_VARARGS | METH_KEYWORDS,
	 drgn_Program_symbol_DOC},
	{},
};

static PyMemberDef Program_members[] = {
	{"cache", T_OBJECT_EX, offsetof(Program, cache), 0,
	 drgn_Program_cache_DOC},
	{},
};

static PyGetSetDef Program_getset[] = {
	{"flags", (getter)Program_get_flags, NULL, drgn_Program_flags_DOC},
	{"platform", (getter)Program_get_platform, NULL, drgn_Program_platform_DOC},
	{},
};

static PyMappingMethods Program_as_mapping = {
	NULL,				/* mp_length */
	(binaryfunc)Program_subscript,	/* mp_subscript */
};


static PySequenceMethods Program_as_sequence = {
	NULL,				/* sq_length */
	NULL,				/* sq_concat */
	NULL,				/* sq_repeat */
	NULL,				/* sq_item */
	NULL,				/* sq_slice */
	NULL,				/* sq_ass_item */
	NULL,				/* sq_ass_slice */
	(objobjproc)Program_contains,	/* sq_contains */
	NULL,				/* sq_inplace_concat */
	NULL,				/* sq_inplace_repeat */
};

PyTypeObject Program_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.Program",			/* tp_name */
	sizeof(Program),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)Program_dealloc,		/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	NULL,					/* tp_repr */
	NULL,					/* tp_as_number */
	&Program_as_sequence,			/* tp_as_sequence */
	&Program_as_mapping,			/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	NULL,					/* tp_str */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,/* tp_flags */
	drgn_Program_DOC,			/* tp_doc */
	(traverseproc)Program_traverse,		/* tp_traverse */
	(inquiry)Program_clear,			/* tp_clear */
	NULL,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	Program_methods,			/* tp_methods */
	Program_members,			/* tp_members */
	Program_getset,				/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	NULL,					/* tp_init */
	NULL,					/* tp_alloc */
	(newfunc)Program_new,			/* tp_new */
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
