// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../program.h"
#include "../util.h"

static Program *Thread_prog(Thread *self)
{
	return container_of(self->thread.prog, Program, prog);
}

PyObject *Thread_wrap(struct drgn_thread *thread)
{
	_cleanup_pydecref_ Thread *ret = call_tp_alloc(Thread);
	if (!ret)
		return NULL;
	struct drgn_error *err =
		drgn_thread_dup_internal(thread, &ret->thread);
	if (err) {
		ret->thread.prog = NULL;
		return set_drgn_error(err);
	}
	Py_INCREF(container_of(thread->prog, Program, prog));
	return (PyObject *)no_cleanup_ptr(ret);
}

static void Thread_dealloc(Thread *self)
{
	if (self->thread.prog) {
		Program *prog = Thread_prog(self);
		drgn_thread_deinit(&self->thread);
		Py_DECREF(prog);
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *Thread_get_tid(Thread *self)
{
	return PyLong_FromUint32(self->thread.tid);
}

static DrgnObject *Thread_get_object(Thread *self)
{
	const struct drgn_object *object;
	struct drgn_error *err = drgn_thread_object(&self->thread, &object);
	if (err)
		return set_drgn_error(err);
	_cleanup_pydecref_ DrgnObject *ret =
		DrgnObject_alloc(Thread_prog(self));
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
	{"tid", (getter)Thread_get_tid, NULL, drgn_Thread_tid_DOC},
	{"object", (getter)Thread_get_object, NULL, drgn_Thread_object_DOC},
	{"name", (getter)Thread_get_name, NULL, drgn_Thread_name_DOC},
	{},
};

static PyMethodDef Thread_methods[] = {
	{"stack_trace", (PyCFunction)Thread_stack_trace, METH_NOARGS,
	 drgn_Thread_stack_trace_DOC},
	{},
};

PyTypeObject Thread_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Thread",
	.tp_basicsize = sizeof(Thread),
	.tp_dealloc = (destructor)Thread_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_Thread_DOC,
	.tp_getset = Thread_getset,
	.tp_methods = Thread_methods,
};

static void ThreadIterator_dealloc(ThreadIterator *self)
{
	drgn_thread_iterator_destroy(self->iterator);
	Py_XDECREF(self->prog);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *ThreadIterator_next(ThreadIterator *self)
{
	struct drgn_error *err;
	struct drgn_thread *thread;
	err = drgn_thread_iterator_next(self->iterator, &thread);
	if (err)
		return set_drgn_error(err);
	return thread ? Thread_wrap(thread) : NULL;
}

PyTypeObject ThreadIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._ThreadIterator",
	.tp_basicsize = sizeof(ThreadIterator),
	.tp_dealloc = (destructor)ThreadIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)ThreadIterator_next,
};
