// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../util.h"

#define EVENT_TYPES		\
	X(ProgramExitEvent)	\
	X(ThreadExitEvent)	\
	X(ThreadStopEvent)

#define X(name) static PyObject *name##_class;
EVENT_TYPES
#undef X

int add_event_types(PyObject *m)
{
	_cleanup_pydecref_ PyObject *collections =
		PyImport_ImportModule("collections");
	if (!collections)
		return -1;
	_cleanup_pydecref_ PyObject *namedtuple =
		PyObject_GetAttrString(collections, "namedtuple");
	if (!namedtuple)
		return -1;

	_cleanup_pydecref_ PyObject *kwargs =
		Py_BuildValue("{s:s}", "module", "_drgn");
	if (!kwargs)
		return -1;

#define add_event_type(name, field_names)					\
	do {									\
		_cleanup_pydecref_ PyObject *args =				\
			Py_BuildValue("ss", #name, field_names);		\
		if (!args)							\
			return -1;						\
										\
		_cleanup_pydecref_ PyObject *doc =				\
			PyUnicode_FromString(drgn_##name##_DOC);		\
		if (!doc)							\
			return -1;						\
										\
		name##_class = PyObject_Call(namedtuple, args, kwargs);		\
		if (!name##_class						\
		    || PyObject_SetAttrString(name##_class, "__doc__", doc))	\
			return -1;						\
										\
		if (PyModule_AddObjectRef(m, #name, name##_class))		\
			return -1;						\
	} while (0)

	add_event_type(ProgramExitEvent, "status");
	add_event_type(ThreadExitEvent, "thread status");
	add_event_type(ThreadStopEvent, "thread");

#undef add_event_type

	// TODO: deduplicate this import?
	_cleanup_pydecref_ PyObject *typing_module =
		PyImport_ImportModule("typing");
	if (!typing_module)
		return -1;
	_cleanup_pydecref_ PyObject *typing_Union =
		PyObject_GetAttrString(typing_module, "Union");
	if (!typing_Union)
		return -1;

	_cleanup_pydecref_ PyObject *item =
		Py_BuildValue(
#define X(name) "O"
EVENT_TYPES
#undef X
#define X(name) , name##_class
EVENT_TYPES
#undef X
				      );
	if (!item)
		return -1;
	if (PyModule_Add(m, "Event", PyObject_GetItem(typing_Union, item)))
		return -1;

	return 0;
}

#undef EVENT_TYPES

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
