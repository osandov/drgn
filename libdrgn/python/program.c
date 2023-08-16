// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../bitops.h"
#include "../error.h"
#include "../hash_table.h"
#include "../log.h"
#include "../program.h"
#include "../string_builder.h"
#include "../util.h"
#include "../vector.h"

DEFINE_HASH_SET_FUNCTIONS(pyobjectp_set, ptr_key_hash_pair, scalar_key_eq);

static PyObject *percent_s;
static PyObject *logger;
static PyObject *logger_log;

static void drgnpy_log_fn(struct drgn_program *prog, void *arg,
			  enum drgn_log_level level, const char *format,
			  va_list ap, struct drgn_error *err)
{
	struct string_builder sb = STRING_BUILDER_INIT;
	if (!string_builder_vappendf(&sb, format, ap))
		goto out;
	if (err && !string_builder_append_error(&sb, err))
		goto out;

	PyGILState_STATE gstate = PyGILState_Ensure();
	PyObject *ret = PyObject_CallFunction(logger_log, "iOs#",
					      (level + 1) * 10, percent_s,
					      sb.str ? sb.str : "",
					      (Py_ssize_t)sb.len);
	if (ret)
		Py_DECREF(ret);
	else
		PyErr_WriteUnraisable(logger_log);
	PyGILState_Release(gstate);

out:
	free(sb.str);
}

static int get_log_level(void)
{
	// We don't use getEffectiveLevel() because that doesn't take
	// logging.disable() into account.
	int level;
	for (level = 0; level < DRGN_LOG_NONE; level++) {
		_cleanup_pydecref_ PyObject *enabled =
			PyObject_CallMethod(logger, "isEnabledFor", "i",
					    (level + 1) * 10);
		if (!enabled)
			return -1;
		int ret = PyObject_IsTrue(enabled);
		if (ret < 0)
			return -1;
		if (ret)
			break;
	}
	return level;
}

// This is slightly heinous. We need to sync the Python log level with the
// libdrgn log level, but the Python log level can change at any time, and there
// is no API to be notified of this. So, we monkey patch logger._cache.clear()
// to update the log level on every live program. This only works since CPython
// commit 78c18a9b9a14 ("bpo-30962: Added caching to Logger.isEnabledFor()
// (GH-2752)") (in v3.7), though. Before that, the best we can do is sync the
// level at the time that the program is created.
#if PY_VERSION_HEX >= 0x030700a1
static int cached_log_level;
static struct pyobjectp_set programs = HASH_TABLE_INIT;

static int cache_log_level(void)
{
	int level = get_log_level();
	if (level < 0)
		return level;
	cached_log_level = level;
	return 0;
}

static PyObject *LoggerCacheWrapper_clear(PyObject *self)
{
	PyDict_Clear(self);
	if (cache_log_level())
		return NULL;
	for (struct pyobjectp_set_iterator it = pyobjectp_set_first(&programs);
	     it.entry; it = pyobjectp_set_next(it)) {
		Program *prog = (Program *)*it.entry;
		drgn_program_set_log_level(&prog->prog, cached_log_level);
	}
	Py_RETURN_NONE;
}

static PyMethodDef LoggerCacheWrapper_methods[] = {
	{"clear", (PyCFunction)LoggerCacheWrapper_clear, METH_NOARGS},
	{},
};

static PyTypeObject LoggerCacheWrapper_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._LoggerCacheWrapper",
	.tp_methods = LoggerCacheWrapper_methods,
};

static int init_logger_cache_wrapper(void)
{
	LoggerCacheWrapper_type.tp_base = &PyDict_Type;
	if (PyType_Ready(&LoggerCacheWrapper_type))
		return -1;
	_cleanup_pydecref_ PyObject *cache_wrapper =
		PyObject_CallFunction((PyObject *)&LoggerCacheWrapper_type,
				      NULL);
	if (!cache_wrapper)
		return -1;
	if (PyObject_SetAttrString(logger, "_cache", cache_wrapper))
		return -1;

	return cache_log_level();
}

static int Program_init_logging(Program *prog)
{
	PyObject *obj = (PyObject *)prog;
	if (pyobjectp_set_insert(&programs, &obj, NULL) < 0)
		return -1;
	drgn_program_set_log_callback(&prog->prog, drgnpy_log_fn, NULL);
	drgn_program_set_log_level(&prog->prog, cached_log_level);
	return 0;
}

static void Program_deinit_logging(Program *prog)
{
	PyObject *obj = (PyObject *)prog;
	pyobjectp_set_delete(&programs, &obj);
}
#else
static int init_logger_cache_wrapper(void) { return 0; }

static int Program_init_logging(Program *prog)
{
	int level = get_log_level();
	if (level < 0)
		return level;
	drgn_program_set_log_callback(&prog->prog, drgnpy_log_fn, NULL);
	drgn_program_set_log_level(&prog->prog, level);
	return 0;
}

static void Program_deinit_logging(Program *prog) {}
#endif

int init_logging(void)
{
	percent_s = PyUnicode_InternFromString("%s");
	if (!percent_s)
		return -1;

	_cleanup_pydecref_ PyObject *logging = PyImport_ImportModule("logging");
	if (!logging)
		return -1;
	logger = PyObject_CallMethod(logging, "getLogger", "s", "drgn");
	if (!logger)
		return -1;
	logger_log = PyObject_GetAttrString(logger, "log");
	if (!logger_log)
		return -1;

	return init_logger_cache_wrapper();
}

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

static void *drgnpy_begin_blocking(struct drgn_program *prog, void *arg)
{
	return PyEval_SaveThread();
}

static void drgnpy_end_blocking(struct drgn_program *prog, void *arg, void *state)
{
	PyEval_RestoreThread(state);
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

	_cleanup_pydecref_ PyObject *cache = PyDict_New();
	if (!cache)
		return NULL;

	_cleanup_pydecref_ Program *prog = call_tp_alloc(Program);
	if (!prog)
		return NULL;
	prog->cache = no_cleanup_ptr(cache);
	pyobjectp_set_init(&prog->objects);
	drgn_program_init(&prog->prog, platform);
	drgn_program_set_blocking_callback(&prog->prog, drgnpy_begin_blocking,
					   drgnpy_end_blocking, NULL);
	if (Program_init_logging(prog))
		return NULL;
	return_ptr(prog);
}

static void Program_dealloc(Program *self)
{
	Program_deinit_logging(self);
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

	PyGILState_guard();

	_cleanup_pydecref_ PyObject *ret =
		PyObject_CallFunction(arg, "KKKO", (unsigned long long)address,
				      (unsigned long long)count,
				      (unsigned long long)offset,
				      physical ? Py_True : Py_False);
	if (!ret)
		return drgn_error_from_python();
	Py_buffer view;
	if (PyObject_GetBuffer(ret, &view, PyBUF_SIMPLE) == -1)
		return drgn_error_from_python();
	if (view.len != count) {
		PyErr_Format(PyExc_ValueError,
			     "memory read callback returned buffer of length %zd (expected %zu)",
			     view.len, count);
		err = drgn_error_from_python();
		goto out;
	}
	memcpy(buf, view.buf, count);
	err = NULL;
out:
	PyBuffer_Release(&view);
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

static struct drgn_error *py_type_find_fn(uint64_t kinds, const char *name,
					  size_t name_len, const char *filename,
					  void *arg,
					  struct drgn_qualified_type *ret)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *name_obj =
		PyUnicode_FromStringAndSize(name, name_len);
	if (!name_obj)
		return drgn_error_from_python();

	int kind;
	for_each_bit(kind, kinds) {
		_cleanup_pydecref_ PyObject *
			kind_obj = PyObject_CallFunction(TypeKind_class, "i",
							 kind);
		if (!kind_obj)
			return drgn_error_from_python();
		_cleanup_pydecref_ PyObject *type_obj =
			PyObject_CallFunction(PyTuple_GET_ITEM(arg, 1), "OOs",
					      kind_obj, name_obj, filename);
		if (!type_obj)
			return drgn_error_from_python();
		if (type_obj == Py_None)
			continue;
		if (!PyObject_TypeCheck(type_obj, &DrgnType_type)) {
			PyErr_SetString(PyExc_TypeError,
					"type find callback must return Type or None");
			return drgn_error_from_python();
		}
		// This check is also done in libdrgn, but we need it here
		// because if the type isn't from this program, then there's no
		// guarantee that it will remain valid after we decrement its
		// reference count.
		if (DrgnType_prog((DrgnType *)type_obj)
		    != (Program *)PyTuple_GET_ITEM(arg, 0)) {
			PyErr_SetString(PyExc_ValueError,
					"type find callback returned type from wrong program");
			return drgn_error_from_python();
		}
		ret->type = ((DrgnType *)type_obj)->type;
		ret->qualifiers = ((DrgnType *)type_obj)->qualifiers;
		return NULL;
	}
	return &drgn_not_found;
}

static PyObject *Program_add_type_finder(Program *self, PyObject *args,
					 PyObject *kwds)
{
	struct drgn_error *err;

	static char *keywords[] = {"fn", NULL};
	PyObject *fn;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:add_type_finder",
					 keywords, &fn))
	    return NULL;

	if (!PyCallable_Check(fn)) {
		PyErr_SetString(PyExc_TypeError, "fn must be callable");
		return NULL;
	}

	_cleanup_pydecref_ PyObject *arg = Py_BuildValue("OO", self, fn);
	if (!arg)
		return NULL;
	if (Program_hold_object(self, arg))
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
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *name_obj =
		PyUnicode_FromStringAndSize(name, name_len);
	if (!name_obj)
		return drgn_error_from_python();
	_cleanup_pydecref_ PyObject *flags_obj =
		PyObject_CallFunction(FindObjectFlags_class, "i", (int)flags);
	if (!flags_obj)
		return drgn_error_from_python();
	_cleanup_pydecref_ PyObject *obj =
		PyObject_CallFunction(PyTuple_GET_ITEM(arg, 1), "OOOs",
				      PyTuple_GET_ITEM(arg, 0), name_obj,
				      flags_obj, filename);
	if (!obj)
		return drgn_error_from_python();
	if (obj == Py_None)
		return &drgn_not_found;
	if (!PyObject_TypeCheck(obj, &DrgnObject_type)) {
		PyErr_SetString(PyExc_TypeError,
				"object find callback must return Object or None");
		return drgn_error_from_python();
	}

	return drgn_object_copy(ret, &((DrgnObject *)obj)->obj);
}

static PyObject *Program_add_object_finder(Program *self, PyObject *args,
					   PyObject *kwds)
{
	struct drgn_error *err;

	static char *keywords[] = {"fn", NULL};
	PyObject *fn;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:add_object_finder",
					 keywords, &fn))
	    return NULL;

	if (!PyCallable_Check(fn)) {
		PyErr_SetString(PyExc_TypeError, "fn must be callable");
		return NULL;
	}

	_cleanup_pydecref_ PyObject *arg = Py_BuildValue("OO", self, fn);
	if (!arg)
		return NULL;
	if (Program_hold_object(self, arg))
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
	struct path_arg path = { .allow_fd = true };

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&:set_core_dump",
					 keywords, path_converter, &path))
		return NULL;

	if (path.fd >= 0)
		err = drgn_program_set_core_dump_fd(&self->prog, path.fd);
	else
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

DEFINE_VECTOR(path_arg_vector, struct path_arg);

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
		_cleanup_pydecref_ PyObject *it = PyObject_GetIter(paths_obj);
		if (!it)
			goto out;

		Py_ssize_t length_hint = PyObject_LengthHint(paths_obj, 1);
		if (length_hint == -1)
			goto out;
		if (!path_arg_vector_reserve(&path_args, length_hint)) {
			PyErr_NoMemory();
			goto out;
		}

		for (;;) {
			_cleanup_pydecref_ PyObject *item = PyIter_Next(it);
			if (!item)
				break;

			struct path_arg *path_arg =
				path_arg_vector_append_entry(&path_args);
			if (!path_arg) {
				PyErr_NoMemory();
				break;
			}
			memset(path_arg, 0, sizeof(*path_arg));
			if (!path_converter(item, path_arg)) {
				path_arg_vector_pop(&path_args);
				break;
			}
		}
		if (PyErr_Occurred())
			goto out;

		paths = malloc_array(path_arg_vector_size(&path_args),
				     sizeof(*paths));
		if (!paths) {
			PyErr_NoMemory();
			goto out;
		}
		for (size_t i = 0; i < path_arg_vector_size(&path_args); i++)
			paths[i] = path_arg_vector_at(&path_args, i)->path;
	}
	err = drgn_program_load_debug_info(&self->prog, paths,
					   path_arg_vector_size(&path_args),
					   load_default, load_main);
	free(paths);
	if (err)
		set_drgn_error(err);

out:
	vector_for_each(path_arg_vector, path_arg, &path_args)
		path_cleanup(path_arg);
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
	bool clear;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&n|p:read", keywords,
					 index_converter, &address, &size,
					 &physical))
	    return NULL;

	if (size < 0) {
		PyErr_SetString(PyExc_ValueError, "negative size");
		return NULL;
	}
	_cleanup_pydecref_ PyObject *buf =
		PyBytes_FromStringAndSize(NULL, size);
	if (!buf)
		return NULL;
	clear = set_drgn_in_python();
	err = drgn_program_read_memory(&self->prog, PyBytes_AS_STRING(buf),
				       address.uvalue, size, physical);
	if (clear)
		clear_drgn_in_python();
	if (err)
		return set_drgn_error(err);
	return_ptr(buf);
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
	PyObject *name_or_type;
	struct path_arg filename = {.allow_none = true};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O&:type", keywords,
					 &name_or_type, path_converter,
					 &filename))
		return NULL;

	PyObject *ret = NULL;
	if (PyObject_TypeCheck(name_or_type, &DrgnType_type)) {
		if (DrgnType_prog((DrgnType *)name_or_type) != self) {
			PyErr_SetString(PyExc_ValueError,
					"type is from different program");
			goto out;
		}
		Py_INCREF(name_or_type);
		ret = name_or_type;
		goto out;
	} else if (!PyUnicode_Check(name_or_type)) {
		PyErr_SetString(PyExc_TypeError,
				"type() argument 1 must be str or Type");
		goto out;
	}

	const char *name = PyUnicode_AsUTF8(name_or_type);
	if (!name)
		goto out;
	bool clear = set_drgn_in_python();
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_type(&self->prog, name, filename.path,
				     &qualified_type);
	if (clear)
		clear_drgn_in_python();
	if (err) {
		set_drgn_error(err);
		goto out;
	}
	ret = DrgnType_wrap(qualified_type);
out:
	path_cleanup(&filename);
	return ret;
}

static DrgnObject *Program_find_object(Program *self, const char *name,
				       struct path_arg *filename,
				       enum drgn_find_object_flags flags)
{
	struct drgn_error *err;

	DrgnObject *ret = DrgnObject_alloc(self);
	if (!ret)
		goto out;
	bool clear = set_drgn_in_python();
	err = drgn_program_find_object(&self->prog, name, filename->path, flags,
				       &ret->obj);
	if (clear)
		clear_drgn_in_python();
	if (err) {
		set_drgn_error(err);
		Py_DECREF(ret);
		ret = NULL;
	}
out:
	path_cleanup(filename);
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

static PyObject *Program_stack_trace(Program *self, PyObject *args,
				     PyObject *kwds)
{
	static char *keywords[] = {"thread", NULL};
	struct drgn_error *err;
	PyObject *thread;
	struct drgn_stack_trace *trace;

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

	PyObject *ret = StackTrace_wrap(trace);
	if (!ret)
		drgn_stack_trace_destroy(trace);
	return ret;
}

static PyObject *Program_symbols(Program *self, PyObject *args)
{
	struct drgn_error *err;

	PyObject *arg = Py_None;
	if (!PyArg_ParseTuple(args, "|O:symbols", &arg))
		return NULL;

	struct drgn_symbol **symbols;
	size_t count;
	if (arg == Py_None) {
		err = drgn_program_find_symbols_by_name(&self->prog, NULL,
							&symbols, &count);
	} else if (PyUnicode_Check(arg)) {
		const char *name = PyUnicode_AsUTF8(arg);
		if (!name)
			return NULL;
		err = drgn_program_find_symbols_by_name(&self->prog, name,
							&symbols, &count);
	} else {
		struct index_arg address = {};
		if (!index_converter(arg, &address))
			return NULL;
		err = drgn_program_find_symbols_by_address(&self->prog,
							   address.uvalue,
							   &symbols, &count);
	}
	if (err)
		return set_drgn_error(err);

	_cleanup_pydecref_ PyObject *list = PyList_New(count);
	if (!list) {
		drgn_symbols_destroy(symbols, count);
		return NULL;
	}
	for (size_t i = 0; i < count; i++) {
		PyObject *pysym = Symbol_wrap(symbols[i], self);
		if (!pysym) {
			/* Free symbols which aren't yet added to list. */
			drgn_symbols_destroy(symbols, count);
			return NULL;
		}
		symbols[i] = NULL;
		PyList_SET_ITEM(list, i, pysym);
	}
	free(symbols);
	return_ptr(list);
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

static ThreadIterator *Program_threads(Program *self)
{
	struct drgn_thread_iterator *it;
	struct drgn_error *err = drgn_thread_iterator_create(&self->prog, &it);
	if (err)
		return set_drgn_error(err);
	ThreadIterator *ret = call_tp_alloc(ThreadIterator);
	if (!ret) {
		drgn_thread_iterator_destroy(it);
		return NULL;
	}
	ret->prog = self;
	ret->iterator = it;
	Py_INCREF(self);
	return ret;
}

static PyObject *Program_thread(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"tid", NULL};
	struct drgn_error *err;
	struct index_arg tid = {};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&:thread", keywords,
					 index_converter, &tid))
		return NULL;

	struct drgn_thread *thread;
	err = drgn_program_find_thread(&self->prog, tid.uvalue, &thread);
	if (err)
		return set_drgn_error(err);
	if (!thread) {
		return PyErr_Format(PyExc_LookupError,
				    "thread with ID %llu not found",
				    tid.uvalue);
	}
	PyObject *ret = Thread_wrap(thread);
	drgn_thread_destroy(thread);
	return ret;
}

static PyObject *Program_main_thread(Program *self)
{
	struct drgn_error *err;
	struct drgn_thread *thread;
	err = drgn_program_main_thread(&self->prog, &thread);
	if (err)
		return set_drgn_error(err);
	return Thread_wrap(thread);
}

static PyObject *Program_crashed_thread(Program *self)
{
	struct drgn_error *err;
	struct drgn_thread *thread;
	err = drgn_program_crashed_thread(&self->prog, &thread);
	if (err)
		return set_drgn_error(err);
	return Thread_wrap(thread);
}

// Used for testing.
static PyObject *Program__log(Program *self, PyObject *args, PyObject *kwds)
{
	int level;
	const char *str;
	if (!PyArg_ParseTuple(args, "is", &level, &str))
		return NULL;
	drgn_log(level, &self->prog, "%s", str);
	Py_RETURN_NONE;
}

static DrgnObject *Program_subscript(Program *self, PyObject *key)
{
	struct drgn_error *err;

	if (!PyUnicode_Check(key)) {
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	}

	const char *name = PyUnicode_AsUTF8(key);
	if (!name)
		return NULL;

	_cleanup_pydecref_ DrgnObject *ret = DrgnObject_alloc(self);
	if (!ret)
		return NULL;

	bool clear = set_drgn_in_python();
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
		return NULL;
	}
	return_ptr(ret);
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

static int Program_set_language(Program *self, PyObject *value, void *arg)
{
	if (!PyObject_TypeCheck(value, &Language_type)) {
		PyErr_SetString(PyExc_TypeError, "language must be Language");
		return -1;
	}
	drgn_program_set_language(&self->prog, ((Language *)value)->language);
	return 0;
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
	{"symbols", (PyCFunction)Program_symbols, METH_VARARGS,
	 drgn_Program_symbols_DOC},
	{"symbol", (PyCFunction)Program_symbol, METH_O,
	 drgn_Program_symbol_DOC},
	{"threads", (PyCFunction)Program_threads, METH_NOARGS,
	 drgn_Program_threads_DOC},
	{"thread", (PyCFunction)Program_thread,
	 METH_VARARGS | METH_KEYWORDS, drgn_Program_thread_DOC},
	{"main_thread", (PyCFunction)Program_main_thread, METH_NOARGS,
	 drgn_Program_main_thread_DOC},
	{"crashed_thread", (PyCFunction)Program_crashed_thread, METH_NOARGS,
	 drgn_Program_crashed_thread_DOC},
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
	{"_log", (PyCFunction)Program__log, METH_VARARGS},
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
	{"language", (getter)Program_get_language, (setter)Program_set_language,
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
	struct path_arg path = { .allow_fd = true };
	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					 "O&:program_from_core_dump", keywords,
					 path_converter, &path))
		return NULL;

	_cleanup_pydecref_ Program *prog =
		(Program *)PyObject_CallObject((PyObject *)&Program_type, NULL);
	if (!prog) {
		path_cleanup(&path);
		return NULL;
	}

	if (path.fd >= 0)
		err = drgn_program_init_core_dump_fd(&prog->prog, path.fd);
	else
		err = drgn_program_init_core_dump(&prog->prog, path.path);
	path_cleanup(&path);
	if (err)
		return set_drgn_error(err);
	return_ptr(prog);
}

Program *program_from_kernel(PyObject *self)
{
	struct drgn_error *err;
	_cleanup_pydecref_ Program *prog =
		(Program *)PyObject_CallObject((PyObject *)&Program_type, NULL);
	if (!prog)
		return NULL;
	err = drgn_program_init_kernel(&prog->prog);
	if (err)
		return set_drgn_error(err);
	return_ptr(prog);
}

Program *program_from_pid(PyObject *self, PyObject *args, PyObject *kwds)
{
	struct drgn_error *err;
	static char *keywords[] = {"pid", NULL};
	int pid;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:program_from_pid",
					 keywords, &pid))
		return NULL;

	_cleanup_pydecref_ Program *prog =
		(Program *)PyObject_CallObject((PyObject *)&Program_type, NULL);
	if (!prog)
		return NULL;
	err = drgn_program_init_pid(&prog->prog, pid);
	if (err)
		return set_drgn_error(err);
	return_ptr(prog);
}
