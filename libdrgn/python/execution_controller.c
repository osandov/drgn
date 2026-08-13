// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

static PyObject *ResumeAction_wrap(const struct drgn_resume_action *action)
{
	PyObject *type;
	SWITCH_ENUM(action->mode) {
	case DRGN_RESUME_MODE_CONTINUE:
		type = ContinueResumeAction_class;
		break;
	case DRGN_RESUME_MODE_STEPI:
		type = StepiResumeAction_class;
		break;
	default:
		UNREACHABLE();
	}

	PyObject *thread;
	if (action->thread) {
		thread = (PyObject *)container_of(action->thread, Thread,
						  thread);
	} else {
		thread = Py_None;
	}
	return PyObject_CallFunction(type, "Oi", thread, action->sig);
}

static PyObject *ExecutionController_not_implemented(PyObject *self,
						     PyObject *args,
						     PyObject *kwds)
{
	PyErr_SetNone(PyExc_NotImplementedError);
	return NULL;
}

#define EXECUTION_CONTROLLER_METHODS	\
	X(attach)			\
	X(detach)			\
	/* X(set_all_stop) */		\
	/* X(interrupt_thread) */	\
	X(interrupt_any_thread)		\
	X(stop_all_threads)		\
	X(resume_threads)		\
	X(enable_breakpoint_sites)	\
	X(disable_breakpoint_sites)

static PyMethodDef ExecutionController_methods[] = {
#define X(name)									\
	{#name, (PyCFunction)ExecutionController_not_implemented,		\
	 METH_VARARGS | METH_KEYWORDS, drgn_ExecutionController_##name##_DOC},
EXECUTION_CONTROLLER_METHODS
#undef X
	{},
};

PyTypeObject ExecutionController_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.ExecutionController",
	.tp_basicsize = sizeof(PyObject),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = drgn_ExecutionController_DOC,
	.tp_methods = ExecutionController_methods,
	.tp_new = PyType_GenericNew,
};

static void
py_execution_controller_attach(void *arg, struct drgn_program *prog,
			       enum drgn_attach_flags flags,
			       struct drgn_bool_promise *promise)
{
	PyGILState_guard();

	_cleanup_pydecref_ Promise *promise_obj = BoolPromise_wrap(promise);
	if (!promise_obj)
		return;

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "attach", "ONO",
				    container_of(prog, Program, prog),
				    PyObject_CallFunction(AttachFlags_class,
							  "k",
							  (unsigned long)flags),
				    promise_obj);
	if (!res)
		Promise_catch_exception(promise_obj);
}

static void
py_execution_controller_detach(void *arg, struct drgn_program *prog,
			       struct drgn_void_promise *promise)
{
	PyGILState_guard();

	_cleanup_pydecref_ Promise *promise_obj = NonePromise_wrap(promise);
	if (!promise_obj)
		return;

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "detach", "OO",
				    container_of(prog, Program, prog),
				    promise_obj);
	if (!res)
		Promise_catch_exception(promise_obj);
}

#if 0
static struct drgn_error *
py_execution_controller_set_all_stop(void *arg, struct drgn_program *prog,
				     bool all_stop)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "set_all_stop", "OO",
				    container_of(prog, Program, prog),
				    all_stop ? Py_True : Py_False);
	if (!res)
		return drgn_error_from_python();
	return NULL;
}

static struct drgn_error *
py_execution_controller_interrupt_thread(void *arg,
					 struct drgn_thread *thread)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "interrupt_thread", "O",
				    container_of(thread, Thread, thread));
	if (!res)
		return drgn_error_from_python();
	return NULL;
}
#endif

static void
py_execution_controller_interrupt_any_thread(void *arg,
					     struct drgn_program *prog,
					     struct drgn_void_promise *promise)
{
	PyGILState_guard();

	_cleanup_pydecref_ Promise *promise_obj = NonePromise_wrap(promise);
	if (!promise_obj)
		return;

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "interrupt_any_thread", "OO",
				    container_of(prog, Program, prog),
				    promise_obj);
	if (!res)
		Promise_catch_exception(promise_obj);
}

static void
py_execution_controller_stop_all_threads(void *arg, struct drgn_program *prog,
					 struct drgn_void_promise *promise)
{
	PyGILState_guard();

	_cleanup_pydecref_ Promise *promise_obj = NonePromise_wrap(promise);
	if (!promise_obj)
		return;

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "stop_all_threads", "OO",
				    container_of(prog, Program, prog),
				    promise_obj);
	if (!res)
		Promise_catch_exception(promise_obj);
}

static void
py_execution_controller_resume_threads(void *arg, struct drgn_program *prog,
				       const struct drgn_resume_action *actions,
				       size_t num_actions,
				       struct drgn_void_promise *promise)
{
	PyGILState_guard();

	_cleanup_pydecref_ Promise *promise_obj = NonePromise_wrap(promise);
	if (!promise_obj)
		return;

	_cleanup_pydecref_ PyObject *actions_tuple = PyTuple_New(num_actions);
	if (!actions_tuple)
		goto err;

	for (size_t i = 0; i < num_actions; i++) {
		PyObject *action_obj = ResumeAction_wrap(&actions[i]);
		if (!action_obj)
			goto err;
		PyTuple_SET_ITEM(actions_tuple, i, action_obj);
	}

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "resume_threads", "OOO",
				    container_of(prog, Program, prog),
				    actions_tuple, promise_obj);
	if (res)
		return;

err:
	Promise_catch_exception(promise_obj);
}

#if 0
static struct drgn_error *
py_execution_controller_resume_threads_call(void *arg, const char *method,
					    struct drgn_program *prog,
					    struct drgn_thread * const *threads,
					    const int *sigs,
					    size_t num_threads)
{
	_cleanup_pydecref_ PyObject *threads_tuple = PyTuple_New(num_threads);
	if (!threads_tuple)
		return drgn_error_from_python();
	for (size_t i = 0; i < num_threads; i++) {
		PyObject *pair =
			Py_BuildValue("(Oi)",
				      container_of(threads[i], Thread, thread),
				      sigs[i]);
		if (!pair)
			return drgn_error_from_python();
		PyTuple_SET_ITEM(threads_tuple, i, pair);
	}
	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, method, "OO",
				    container_of(prog, Program, prog),
				    threads_tuple);
	if (!res)
		return drgn_error_from_python();
	return NULL;
}

static struct drgn_error *
py_execution_controller_resume_all_threads(void *arg,
					   struct drgn_program *prog,
					   struct drgn_thread * const *threads,
					   const int *sigs,
					   size_t num_threads)
{
	PyGILState_guard();
	return py_execution_controller_resume_threads_call(arg,
							   "resume_all_threads",
							   prog, threads, sigs,
							   num_threads);
}

static struct drgn_error *
py_execution_controller_resume_only_threads(void *arg,
					    struct drgn_program *prog,
					    struct drgn_thread * const *threads,
					    const int *sigs,
					    size_t num_threads)
{
	PyGILState_guard();
	return py_execution_controller_resume_threads_call(arg,
							   "resume_only_threads",
							   prog, threads, sigs,
							   num_threads);
}
#endif

static void
py_execution_controller_breakpoint_sites_call(const char *method, void *arg,
					      struct drgn_breakpoint_site * const *sites,
					      size_t num_sites,
					      struct drgn_void_promise *promise)
{
	PyGILState_guard();

	_cleanup_pydecref_ Promise *promise_obj = NonePromise_wrap(promise);
	if (!promise_obj)
		return;

	_cleanup_pydecref_ PyObject *sites_tuple = PyTuple_New(num_sites);
	if (!sites_tuple)
		goto err;

	for (size_t i = 0; i < num_sites; i++) {
		BreakpointSite *py_site =
			container_of(sites[i], BreakpointSite, site);
		Py_INCREF(py_site);
		PyTuple_SET_ITEM(sites_tuple, i, (PyObject *)py_site);
	}

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, method, "OO", sites_tuple,
				    promise_obj);
	if (res)
		return;

err:
	Promise_catch_exception(promise_obj);
}

static void
py_execution_controller_enable_breakpoint_sites(void *arg,
						struct drgn_breakpoint_site * const *sites,
						size_t num_sites,
						struct drgn_void_promise *promise)
{
	py_execution_controller_breakpoint_sites_call("enable_breakpoint_sites",
						      arg, sites, num_sites,
						      promise);
}

static void
py_execution_controller_disable_breakpoint_sites(void *arg,
						 struct drgn_breakpoint_site * const *sites,
						 size_t num_sites,
						 struct drgn_void_promise *promise)
{
	py_execution_controller_breakpoint_sites_call("disable_breakpoint_sites",
						      arg, sites, num_sites,
						      promise);
}

#if 0
static struct drgn_error *
py_execution_controller_queue_events(void *arg, struct drgn_program *prog,
				     bool block)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "queue_events", "OO",
				    container_of(prog, Program, prog),
				    block ? Py_True : Py_False);
	if (!res)
		return drgn_error_from_python();
	return NULL;
}
#endif

static int method_implemented(PyObject *finder, const char *name)
{
	_cleanup_pydecref_ PyObject *method =
		PyObject_GetAttrString(finder, name);
	if (!method)
		return -1;
	return !PyCFunction_Check(method)
	       || PyCFunction_GET_FUNCTION(method)
		  != (PyCFunction)ExecutionController_not_implemented;
}

int drgnpy_execution_controller_set_ops(struct drgn_execution_controller_ops *ops,
					PyObject *controller)
{
	int r;
#define X(name)							\
	r = method_implemented(controller, #name);		\
	if (r < 0)						\
		return r;					\
	if (r)							\
		ops->name = py_execution_controller_##name;
EXECUTION_CONTROLLER_METHODS
#undef X

	return 0;
}
