// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../thread.h"
#include "../util.h"

struct drgn_thread *drgn_thread_alloc(struct drgn_program *prog)
{
	Thread *ret = call_tp_alloc(Thread);
	if (!ret)
		return NULL;
	Py_INCREF(container_of(prog, Program, prog));
	drgn_thread_init(&ret->thread, prog);
	return &ret->thread;
}

LIBDRGN_PUBLIC void drgn_thread_incref(struct drgn_thread *thread)
{
	Py_INCREF(container_of(thread, Thread, thread));
}

LIBDRGN_PUBLIC void drgn_thread_decref(struct drgn_thread *thread)
{
	if (thread)
		Py_DECREF(container_of(thread, Thread, thread));
}

static void Thread_dealloc(Thread *self)
{
	PyObject_GC_UnTrack(self);
	struct drgn_program *prog = drgn_thread_program(&self->thread);
	drgn_thread_deinit(&self->thread);
	Py_DECREF(container_of(prog, Program, prog));
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int Thread_traverse(Thread *self, visitproc visit, void *arg)
{
	struct drgn_program *prog = drgn_thread_program(&self->thread);
	Py_VISIT(container_of(prog, Program, prog));
	if (self->thread.finder->ops.thread_data_destroy
	    == py_thread_data_destroy_fn)
		Py_VISIT(drgn_thread_get_finder_data(&self->thread));
	return 0;
}

static int Thread_clear(Thread *self)
{
	if (self->thread.finder->ops.thread_data_destroy
	    == py_thread_data_destroy_fn)
		drgn_thread_set_finder_data(&self->thread, NULL);
	return 0;
}

static Program *Thread_get_prog(Thread *self)
{
	Program *ret =
		container_of(drgn_thread_program(&self->thread), Program, prog);
	Py_INCREF(ret);
	return ret;
}

static PyObject *Thread_get_tid(Thread *self)
{
	return PyLong_FromUInt32(drgn_thread_tid(&self->thread));
}

static PyObject *Thread_get_generation(Thread *self)
{
	return PyLong_FromUInt64(drgn_thread_generation(&self->thread));
}

static DrgnObject *Thread_get_object(Thread *self)
{
	const struct drgn_object *object;
	struct drgn_error *err = drgn_thread_object(&self->thread, &object);
	if (err)
		return set_drgn_error(err);
	_cleanup_pydecref_ DrgnObject *ret =
		DrgnObject_alloc(container_of(drgn_object_program(object),
					      Program, prog));
	if (!ret)
		return NULL;
	err = drgn_object_copy(&ret->obj, object);
	if (err)
		return set_drgn_error(err);
	return_ptr(ret);
}

static PyObject *Thread_get_name(Thread *self)
{
	_cleanup_free_ char *ret = NULL;
	struct drgn_error *err = drgn_thread_name(&self->thread, &ret);
	if (err)
		return set_drgn_error(err);
	if (!ret) {
		Py_RETURN_NONE;
	}
	return PyUnicode_DecodeFSDefault(ret);
}

static PyObject *Thread_get_finder_data(Thread *self, void *arg)
{
	if (self->thread.finder->ops.thread_data_destroy
	    != py_thread_data_destroy_fn) {
		PyErr_SetString(PyExc_RuntimeError,
				"thread is not from Python finder");
		return NULL;
	}
	PyObject *data = drgn_thread_get_finder_data(&self->thread);
	if (!data)
		Py_RETURN_NONE;
	Py_INCREF(data);
	return data;
}

static int Thread_set_finder_data(Thread *self, PyObject *value, void *arg)
{
	SETTER_NO_DELETE("_finder_data", value);
	if (self->thread.finder->ops.thread_data_destroy
	    != py_thread_data_destroy_fn) {
		PyErr_SetString(PyExc_RuntimeError,
				"thread is not from Python finder");
		return -1;
	}
	Py_INCREF(value);
	drgn_thread_set_finder_data(&self->thread, value);
	return 0;
}

static RegisterState *Thread_register_state(Thread *self)
{
	struct drgn_register_state *regs;
	struct drgn_error *err = drgn_thread_register_state(&self->thread,
							    &regs);
	if (err)
		return set_drgn_error(err);
	if (!regs) {
		PyErr_SetString(PyExc_LookupError,
				"thread registers not available");
		return NULL;
	}
	return container_of(regs, RegisterState, regs);
}

static PyObject *Thread_stack_trace(Thread *self)
{
	struct drgn_error *err;
	struct drgn_stack_trace *trace;
	err = drgn_thread_stack_trace(&self->thread, &trace);
	if (err)
		return set_drgn_error(err);
	PyObject *ret = StackTrace_wrap(trace);
	if (!ret)
		drgn_stack_trace_destroy(trace);
	return ret;
}

static PyGetSetDef Thread_getset[] = {
	{"prog", (getter)Thread_get_prog, NULL, drgn_Thread_prog_DOC},
	{"tid", (getter)Thread_get_tid, NULL, drgn_Thread_tid_DOC},
	{"generation", (getter)Thread_get_generation, NULL,
	 drgn_Thread_generation_DOC},
	{"object", (getter)Thread_get_object, NULL, drgn_Thread_object_DOC},
	{"name", (getter)Thread_get_name, NULL, drgn_Thread_name_DOC},
	{"_finder_data", (getter)Thread_get_finder_data,
	 (setter)Thread_set_finder_data, drgn_Thread__finder_data_DOC},
	{},
};

static PyMethodDef Thread_methods[] = {
	{"register_state", (PyCFunction)Thread_register_state, METH_NOARGS,
	 drgn_Thread_register_state_DOC},
	{"stack_trace", (PyCFunction)Thread_stack_trace, METH_NOARGS,
	 drgn_Thread_stack_trace_DOC},
	{},
};

PyTypeObject Thread_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Thread",
	.tp_basicsize = sizeof(Thread),
	.tp_dealloc = (destructor)Thread_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_Thread_DOC,
	.tp_traverse = (traverseproc)Thread_traverse,
	.tp_clear = (inquiry)Thread_clear,
	.tp_getset = Thread_getset,
	.tp_methods = Thread_methods,
};

static void ThreadIterator_dealloc(ThreadIterator *self)
{
	PyObject_GC_UnTrack(self);
	drgn_thread_iterator_destroy(self->iterator);
	Py_XDECREF(self->prog);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int ThreadIterator_traverse(ThreadIterator *self, visitproc visit,
				   void *arg)
{
	Py_VISIT(self->prog);
	if (self->iterator->finder->ops.iterator_destroy
	    == py_thread_iterator_destroy_fn)
		Py_VISIT(self->iterator->data);
	return 0;
}

static Thread *ThreadIterator_next(ThreadIterator *self)
{
	struct drgn_error *err;
	struct drgn_thread *thread;
	err = drgn_thread_iterator_next(self->iterator, &thread);
	if (err)
		return set_drgn_error(err);
	return thread ? container_of(thread, Thread, thread) : NULL;
}

PyTypeObject ThreadIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._ThreadIterator",
	.tp_basicsize = sizeof(ThreadIterator),
	.tp_dealloc = (destructor)ThreadIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)ThreadIterator_traverse,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)ThreadIterator_next,
};
