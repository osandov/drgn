// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../pp.h"

static PyObject *ThreadFinder_not_implemented(PyObject *self, PyObject *args,
					      PyObject *kwds)
{
	PyErr_SetNone(PyExc_NotImplementedError);
	return NULL;
}

#define THREAD_FINDER_METHODS						\
	X(threads, iterator_create, iterator_next)			\
	X(thread, find_thread)						\
	X(thread_from_object, thread_from_object)			\
	X(main_thread, main_thread)					\
	X(crashed_thread, crashed_thread)				\
	X(thread_object, thread_object)					\
	X(thread_name, thread_name)

static PyMethodDef ThreadFinder_methods[] = {
#define X(name, ...)							\
	{#name, (PyCFunction)ThreadFinder_not_implemented,		\
	 METH_VARARGS | METH_KEYWORDS, drgn_ThreadFinder_##name##_DOC},
THREAD_FINDER_METHODS
#undef X
	{},
};

PyTypeObject ThreadFinder_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.ThreadFinder",
	.tp_basicsize = sizeof(PyObject),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = drgn_ThreadFinder_DOC,
	.tp_methods = ThreadFinder_methods,
	.tp_new = PyType_GenericNew,
};

static struct drgn_error *py_thread_result(struct drgn_thread_cache *cache,
					   PyObject *res,
					   struct drgn_thread **ret)
{
	if (!res) {
		return drgn_error_from_python();
	} else if (res == Py_None) {
		Py_DECREF(res);
		*ret = NULL;
		return NULL;
	} else if (!PyObject_TypeCheck(res, &Thread_type)) {
		Py_DECREF(res);
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "expected Thread or None");
	} else if (drgn_thread_program(&((Thread *)res)->thread)
		   != drgn_thread_cache_program(cache)) {
		Py_DECREF(res);
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "returned Thread is from different program");
	} else {
		*ret = &((Thread *)res)->thread;
		return NULL;
	}
}

static struct drgn_error *
py_thread_finder_iterator_create(void *arg, struct drgn_thread_cache *cache,
				 void **ret)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *cache_obj = ThreadCache_wrap(cache);
	if (!cache_obj)
		return drgn_error_from_python();
	_cleanup_pydecref_ PyObject *it =
		PyObject_CallMethod(arg, "threads", "O", cache_obj);
	if (!it)
		return drgn_error_from_python();
	if (!PyIter_Check(it)) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "threads() must return iterator");
	}
	*ret = no_cleanup_ptr(it);
	return NULL;
}

static struct drgn_error *
py_thread_finder_iterator_next(void *arg, struct drgn_thread_cache *cache,
			       void *it, struct drgn_thread **ret)
{
	PyGILState_guard();

	PyObject *res = PyIter_Next(it);
	if (!res) {
		if (PyErr_Occurred())
			return drgn_error_from_python();
		*ret = NULL;
		return NULL;
	}
	if (!PyObject_TypeCheck(res, &Thread_type)) {
		Py_DECREF(res);
		return drgn_error_create(DRGN_ERROR_TYPE, "expected Thread");
	}
	if (drgn_thread_program(&((Thread *)res)->thread)
	    != drgn_thread_cache_program(cache)) {
		Py_DECREF(res);
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "yielded Thread is from different program");
	}
	*ret = &((Thread *)res)->thread;
	return NULL;
}

static struct drgn_error *
py_thread_finder_find_thread(void *arg, struct drgn_thread_cache *cache,
			     uint32_t tid, struct drgn_thread **ret)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *cache_obj = ThreadCache_wrap(cache);
	if (!cache_obj)
		return drgn_error_from_python();
	_cleanup_pydecref_ PyObject *tid_obj = PyLong_FromUInt32(tid);
	if (!tid_obj)
		return drgn_error_from_python();
	PyObject *res = PyObject_CallMethod(arg, "thread", "OO", cache_obj,
					    tid_obj);
	return py_thread_result(cache, res, ret);
}

static struct drgn_error *
py_thread_finder_thread_from_object(void *arg, struct drgn_thread_cache *cache,
				    const struct drgn_object *obj,
				    struct drgn_thread **ret)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *cache_obj = ThreadCache_wrap(cache);
	if (!cache_obj)
		return drgn_error_from_python();
	Program *prog = container_of(drgn_object_program(obj), Program, prog);
	_cleanup_pydecref_ DrgnObject *obj_arg = DrgnObject_alloc(prog);
	if (!obj_arg)
		return drgn_error_from_python();
	struct drgn_error *err = drgn_object_copy(&obj_arg->obj, obj);
	if (err)
		return err;
	PyObject *res = PyObject_CallMethod(arg, "thread_from_object", "OO",
					    cache_obj, obj_arg);
	return py_thread_result(cache, res, ret);
}

static struct drgn_error *
py_thread_finder_main_thread(void *arg, struct drgn_thread_cache *cache,
			     struct drgn_thread **ret)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *cache_obj = ThreadCache_wrap(cache);
	if (!cache_obj)
		return drgn_error_from_python();
	PyObject *res = PyObject_CallMethod(arg, "main_thread", "O", cache_obj);
	return py_thread_result(cache, res, ret);
}

static struct drgn_error *
py_thread_finder_crashed_thread(void *arg, struct drgn_thread_cache *cache,
				struct drgn_thread **ret)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *cache_obj = ThreadCache_wrap(cache);
	if (!cache_obj)
		return drgn_error_from_python();
	PyObject *res = PyObject_CallMethod(arg, "crashed_thread", "O",
					    cache_obj);
	return py_thread_result(cache, res, ret);
}

static struct drgn_error *
py_thread_finder_thread_object(void *arg, struct drgn_thread *thread,
			       struct drgn_object *ret)
{
	PyGILState_guard();

	PyObject *thread_obj = (PyObject *)container_of(thread, Thread, thread);
	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "thread_object", "O", thread_obj);
	if (!res)
		return drgn_error_from_python();
	if (!PyObject_TypeCheck(res, &DrgnObject_type)) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "thread_object() must return Object");
	}
	if (drgn_object_program(&((DrgnObject *)res)->obj)
	    != drgn_thread_program(thread)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "thread_object() returned Object from different program");
	}
	return drgn_object_copy(ret, &((DrgnObject *)res)->obj);
}

static struct drgn_error *
py_thread_finder_thread_name(void *arg, struct drgn_thread *thread, char **ret)
{
	PyGILState_guard();

	PyObject *thread_obj = (PyObject *)container_of(thread, Thread, thread);
	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "thread_name", "O", thread_obj);
	if (!res)
		return drgn_error_from_python();
	if (res == Py_None) {
		*ret = NULL;
		return NULL;
	}
	if (!PyUnicode_Check(res)) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "thread_name() must return str or None");
	}
	const char *s = PyUnicode_AsUTF8(res);
	if (!s)
		return drgn_error_from_python();
	*ret = strdup(s);
	if (!*ret)
		return &drgn_enomem;
	return NULL;
}

static int method_implemented(PyObject *finder, const char *name)
{
	_cleanup_pydecref_ PyObject *method =
		PyObject_GetAttrString(finder, name);
	if (!method)
		return -1;
	return !PyCFunction_Check(method)
	       || PyCFunction_GET_FUNCTION(method)
		  != (PyCFunction)ThreadFinder_not_implemented;
}

int drgnpy_thread_finder_set_ops(struct drgn_thread_finder_ops *ops,
				 PyObject *finder)
{
	ops->thread_data_destroy = py_destroy_data;
	ops->iterator_destroy = py_destroy_data;
	int r;
#define set_op(arg, name) ops->name = py_thread_finder_##name;
#define X(name, ...)				\
	r = method_implemented(finder, #name);	\
	if (r < 0)				\
		return r;			\
	if (r) {				\
		PP_MAP(set_op,, __VA_ARGS__)	\
	}
THREAD_FINDER_METHODS
#undef X
#undef set_op

	return 0;
}
