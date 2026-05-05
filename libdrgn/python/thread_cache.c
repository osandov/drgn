// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../util.h"

PyObject *ThreadCache_wrap(struct drgn_thread_cache *cache)
{
	ThreadCache *ret = call_tp_alloc(ThreadCache);
	if (!ret)
		return NULL;
	ret->cache = cache;
	struct drgn_program *prog = drgn_thread_cache_program(cache);
	Py_INCREF(container_of(prog, Program, prog));
	return (PyObject *)ret;
}

static void ThreadCache_dealloc(ThreadCache *self)
{
	PyObject_GC_UnTrack(self);
	struct drgn_program *prog = drgn_thread_cache_program(self->cache);
	Py_DECREF(container_of(prog, Program, prog));
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int ThreadCache_traverse(ThreadCache *self, visitproc visit, void *arg)
{
	struct drgn_program *prog = drgn_thread_cache_program(self->cache);
	Py_VISIT(container_of(prog, Program, prog));
	return 0;
}

static Program *ThreadCache_get_prog(ThreadCache *self)
{
	Program *ret = container_of(drgn_thread_cache_program(self->cache),
				    Program, prog);
	Py_INCREF(ret);
	return ret;
}

static PyObject *ThreadCache_find(ThreadCache *self, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {"tid", "generation", NULL};
	struct index_arg tid = {};
	struct index_arg generation = {};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&:find", keywords,
					 index_converter, &tid, index_converter,
					 &generation))
		return NULL;

	struct drgn_thread *thread =
		drgn_thread_cache_find(self->cache, tid.uvalue,
				       generation.uvalue);
	if (!thread)
		Py_RETURN_NONE;
	return (PyObject *)container_of(thread, Thread, thread);
}

static PyObject *ThreadCache_find_or_create(ThreadCache *self, PyObject *args,
					    PyObject *kwds)
{
	struct drgn_error *err;
	static char *keywords[] = {"tid", "generation", "object", NULL};
	struct index_arg tid = {};
	struct index_arg generation = {};
	PyObject *object_arg = Py_None;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&|O:find_or_create",
					 keywords, index_converter, &tid,
					 index_converter, &generation,
					 &object_arg))
		return NULL;

	const struct drgn_object *object;
	if (object_arg == Py_None) {
		object = NULL;
	} else if (PyObject_TypeCheck(object_arg, &DrgnObject_type)) {
		object = &((DrgnObject *)object_arg)->obj;
	} else {
		PyErr_SetString(PyExc_TypeError,
				"object must be Object or None");
		return NULL;
	}

	struct drgn_thread *thread;
	bool new;
	err = drgn_thread_cache_find_or_create(self->cache, tid.uvalue,
					       generation.uvalue, object,
					       &thread, &new);
	if (err)
		return set_drgn_error(err);

	return Py_BuildValue("NO",
			     (PyObject *)container_of(thread, Thread, thread),
			     new ? Py_True : Py_False);
}

static PyGetSetDef ThreadCache_getset[] = {
	{"prog", (getter)ThreadCache_get_prog, NULL, drgn_ThreadCache_prog_DOC},
	{},
};

static PyMethodDef ThreadCache_methods[] = {
	{"find", (PyCFunction)ThreadCache_find, METH_VARARGS | METH_KEYWORDS,
	 drgn_ThreadCache_find_DOC},
	{"find_or_create", (PyCFunction)ThreadCache_find_or_create,
	 METH_VARARGS | METH_KEYWORDS, drgn_ThreadCache_find_or_create_DOC},
	{},
};

PyTypeObject ThreadCache_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.ThreadCache",
	.tp_basicsize = sizeof(ThreadCache),
	.tp_dealloc = (destructor)ThreadCache_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_ThreadCache_DOC,
	.tp_traverse = (traverseproc)ThreadCache_traverse,
	.tp_getset = ThreadCache_getset,
	.tp_methods = ThreadCache_methods,
};
