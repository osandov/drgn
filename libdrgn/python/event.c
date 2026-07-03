// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../util.h"

PyObject *Event_wrap(struct drgn_event *event)
{
	struct drgn_error *err;
	int status;
	struct drgn_thread *thread;
	SWITCH_ENUM(drgn_event_type(event)) {
	case DRGN_EVENT_PROGRAM_EXIT:
		err = drgn_event_exit_status(event, &status);
		if (err)
			return set_drgn_error(err);
		return PyObject_CallFunction(ProgramExitEvent_class, "i",
					     status);
	case DRGN_EVENT_THREAD_EXIT:
		err = drgn_event_thread(event, &thread);
		if (err)
			return set_drgn_error(err);
		err = drgn_event_exit_status(event, &status);
		if (err)
			return set_drgn_error(err);
		return PyObject_CallFunction(ThreadExitEvent_class, "Oi",
					     container_of(thread, Thread, thread),
					     status);
	case DRGN_EVENT_THREAD_STOP:
		err = drgn_event_thread(event, &thread);
		if (err)
			return set_drgn_error(err);
		return PyObject_CallOneArg(ThreadStopEvent_class,
					   (PyObject *)container_of(thread, Thread, thread));
	default:
		UNREACHABLE();
	}
}

static void EventListener_dealloc(EventListener *self)
{
	PyObject_GC_UnTrack(self);
	if (self->listener) {
		struct drgn_program *prog =
			drgn_event_listener_program(self->listener);
		Py_DECREF(container_of(prog, Program, prog));
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int EventListener_traverse(EventListener *self, visitproc visit,
				  void *arg)
{
	if (self->listener) {
		struct drgn_program *prog =
			drgn_event_listener_program(self->listener);
		Py_VISIT(container_of(prog, Program, prog));
	}
	return 0;
}

static PyObject *EventListener_remove(EventListener *self,
				      PyObject *Py_UNUSED(ignored))
{
	if (self->listener) {
		struct drgn_program *prog =
			drgn_event_listener_program(self->listener);
		drgn_event_listener_remove(self->listener);
		self->listener = NULL;
		Py_DECREF(container_of(prog, Program, prog));
	}
	Py_RETURN_NONE;
}

static PyObject *EventListener_enter(PyObject *self, PyObject *Py_UNUSED(ignored))
{
	Py_INCREF(self);
	return self;
}

static PyMethodDef EventListener_methods[] = {
	{"remove", (PyCFunction)EventListener_remove, METH_NOARGS,
	 drgn_EventListener_remove_DOC},
	{"__enter__", EventListener_enter, METH_NOARGS},
	{"__exit__", (PyCFunction)EventListener_remove, METH_VARARGS},
	{},
};

PyTypeObject EventListener_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.EventListener",
	.tp_basicsize = sizeof(EventListener),
	.tp_dealloc = (destructor)EventListener_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_EventListener_DOC,
	.tp_traverse = (traverseproc)EventListener_traverse,
	.tp_methods = EventListener_methods,
};
