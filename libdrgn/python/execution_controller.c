// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

static PyObject *ExecutionController_not_implemented(PyObject *self,
						     PyObject *args,
						     PyObject *kwds)
{
	PyErr_SetNone(PyExc_NotImplementedError);
	return NULL;
}

#define EXECUTION_CONTROLLER_METHODS	\
	X(attach)			\
	X(detach)
	// X(set_all_stop)
	// X(interrupt_thread)
	// X(interrupt_any_thread)
	// X(resume_all_threads)
	// X(resume_only_threads)
	// X(enable_breakpoint_sites)
	// X(disable_breakpoint_sites)

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

static Promise *NonePromise_wrap(drgn_success_fn *set_result,
				 drgn_error_fn *set_error, void *arg)
{
	NonePromise *promise = call_tp_alloc(NonePromise);
	if (!promise) {
		set_error(arg, &drgn_enomem);
		return NULL;
	}
	promise->set_result = set_result;
	promise->set_error = set_error;
	promise->arg = arg;
	return (Promise *)promise;
}

static Promise *BoolPromise_wrap(void (*set_result)(void *arg, bool all_stop),
				 drgn_error_fn *set_error, void *arg)
{
	BoolPromise *promise = call_tp_alloc(BoolPromise);
	if (!promise) {
		set_error(arg, &drgn_enomem);
		return NULL;
	}
	promise->set_result = set_result;
	promise->set_error = set_error;
	promise->arg = arg;
	return (Promise *)promise;
}

static void promise_catch_exception(Promise *promise)
{
	if (promise->done) {
		// Exception was raised after promise result was already set.
		PyErr_WriteUnraisable(NULL);
		return;
	}
	promise->done = true;
	promise->set_error(promise->arg, drgn_error_from_python());
}

static void
py_execution_controller_attach(void *arg, struct drgn_program *prog,
			       enum drgn_attach_flags flags,
			       void (*on_success)(void *result_arg, bool all_stop),
			       drgn_error_fn *on_error, void *result_arg)
{
	PyGILState_guard();

	_cleanup_pydecref_ Promise *promise =
		BoolPromise_wrap(on_success, on_error, result_arg);
	if (!promise)
		return;

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "attach", "ONO",
				    container_of(prog, Program, prog),
				    PyObject_CallFunction(AttachFlags_class, "k",
							  (unsigned long)flags),
				    promise);
	if (!res)
		promise_catch_exception(promise);
}

static void
py_execution_controller_detach(void *arg, struct drgn_program *prog,
			       drgn_success_fn *on_success,
			       drgn_error_fn *on_error, void *result_arg)
{
	PyGILState_guard();

	_cleanup_pydecref_ Promise *promise =
		NonePromise_wrap(on_success, on_error, result_arg);
	if (!promise)
		return;

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "detach", "OO",
				    container_of(prog, Program, prog), promise);
	if (!res)
		promise_catch_exception(promise);
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

static struct drgn_error *
py_execution_controller_interrupt_any_thread(void *arg,
					     struct drgn_program *prog)
{
	PyGILState_guard();

	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, "interrupt_any_thread", "O",
				    container_of(prog, Program, prog));
	if (!res)
		return drgn_error_from_python();
	return NULL;
}

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

static struct drgn_error *
py_execution_controller_breakpoint_sites_call(void *arg, const char *method,
					      struct drgn_breakpoint_site * const *sites,
					      size_t num_sites)
{
	_cleanup_pydecref_ PyObject *sites_tuple = PyTuple_New(num_sites);
	if (!sites_tuple)
		return drgn_error_from_python();
	for (size_t i = 0; i < num_sites; i++) {
		BreakpointSite *py_site =
			container_of(sites[i], BreakpointSite, site);
		Py_INCREF(py_site);
		PyTuple_SET_ITEM(sites_tuple, i, (PyObject *)py_site);
	}
	_cleanup_pydecref_ PyObject *res =
		PyObject_CallMethod(arg, method, "O", sites_tuple);
	if (!res)
		return drgn_error_from_python();
	return NULL;
}

static struct drgn_error *
py_execution_controller_enable_breakpoint_sites(void *arg,
						struct drgn_breakpoint_site * const *sites,
						size_t num_sites)
{
	PyGILState_guard();
	return py_execution_controller_breakpoint_sites_call(arg,
							     "enable_breakpoint_sites",
							     sites, num_sites);
}

static struct drgn_error *
py_execution_controller_disable_breakpoint_sites(void *arg,
						 struct drgn_breakpoint_site * const *sites,
						 size_t num_sites)
{
	PyGILState_guard();
	return py_execution_controller_breakpoint_sites_call(arg,
							     "disable_breakpoint_sites",
							     sites, num_sites);
}

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
