// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"

struct drgn_breakpoint *drgn_breakpoint_alloc(void)
{
	// TODO: this sets the Python error indicator. I think we need to clear
	// it. There are other instances of this bug.
	Breakpoint *ret = call_tp_alloc(Breakpoint);
	if (!ret)
		return NULL;
	return &ret->bp;
}

LIBDRGN_PUBLIC void drgn_breakpoint_incref(struct drgn_breakpoint *bp)
{
	Py_INCREF(container_of(bp, Breakpoint, bp));
}

LIBDRGN_PUBLIC void drgn_breakpoint_decref(struct drgn_breakpoint *bp)
{
	if (bp)
		Py_DECREF(container_of(bp, Breakpoint, bp));
}

static void Breakpoint_dealloc(Breakpoint *self)
{
	PyObject_GC_UnTrack(self);
	Py_XDECREF(self->cached_sites);
	drgn_breakpoint_deinit(&self->bp);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int Breakpoint_traverse(Breakpoint *self, visitproc visit, void *arg)
{
	Py_VISIT(container_of(drgn_breakpoint_program(&self->bp), Program,
			      prog));
	for (size_t i = 0; i < self->bp.num_sites; i++)
		Py_VISIT(container_of(self->bp.site_nodes[i].site, BreakpointSite, site));
	Py_VISIT(self->cached_sites);
	if (self->bp.destroy_data == py_destroy_data)
		Py_VISIT(drgn_breakpoint_get_data(&self->bp));
	return 0;
}

static int Breakpoint_clear(Breakpoint *self)
{
	if (self->bp.destroy_data == py_destroy_data)
		drgn_breakpoint_set_data(&self->bp, NULL, NULL);
	Py_CLEAR(self->cached_sites);
	return 0;
}

static PyObject *Breakpoint_repr(Breakpoint *self)
{
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts || append_string(parts, "<Breakpoint at "))
		return NULL;
	size_t n = drgn_breakpoint_num_sites(&self->bp);
	for (size_t i = 0; i < n; i++) {
		struct drgn_breakpoint_site *site =
			drgn_breakpoint_get_site(&self->bp, i);
		if ((i > 0 && append_string(parts, ", "))
		    || append_u64_hex(parts, drgn_breakpoint_site_address(site)))
			return NULL;
	}
	if (append_string(parts, ">"))
		return NULL;
	return join_strings(parts);
}

static Program *Breakpoint_get_prog(Breakpoint *self)
{
	Program *ret = container_of(drgn_breakpoint_program(&self->bp),
				    Program, prog);
	Py_INCREF(ret);
	return ret;
}

static PyObject *Breakpoint_get_sites(Breakpoint *self)
{
	if (!self->cached_sites) {
		size_t n = drgn_breakpoint_num_sites(&self->bp);
		_cleanup_pydecref_ PyObject *tuple = PyTuple_New(n);
		if (!tuple)
			return NULL;
		for (size_t i = 0; i < n; i++) {
			struct drgn_breakpoint_site *site =
				drgn_breakpoint_get_site(&self->bp, i);
			BreakpointSite *py_site =
				container_of(site, BreakpointSite, site);
			Py_INCREF(py_site);
			PyTuple_SET_ITEM(tuple, i, (PyObject *)py_site);
		}
		self->cached_sites = no_cleanup_ptr(tuple);
	}
	Py_INCREF(self->cached_sites);
	return self->cached_sites;
}

static PyObject *Breakpoint_get_data(Breakpoint *self)
{
	if (!self->bp.destroy_data) {
		Py_RETURN_NONE;
	} else if (self->bp.destroy_data != py_destroy_data) {
		PyErr_SetString(PyExc_RuntimeError,
				"breakpoint data was not set from Python");
		return NULL;
	}
	PyObject *data = drgn_breakpoint_get_data(&self->bp);
	Py_INCREF(data);
	return data;
}

static int Breakpoint_set_data(Breakpoint *self, PyObject *value)
{
	SETTER_NO_DELETE("data", value);
	Py_INCREF(value);
	drgn_breakpoint_set_data(&self->bp, value, py_destroy_data);
	return 0;
}

#if 0
static PyObject *Breakpoint_remove(Breakpoint *self, PyObject *args,
				   PyObject *kwds)
{
	static char *keywords[] = {"sync_events", NULL};
	int sync_events = 1;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$p:remove", keywords,
					 &sync_events))
		return NULL;
	struct drgn_error *err = drgn_breakpoint_remove(&self->bp, sync_events);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *Breakpoint_enable(Breakpoint *self, PyObject *args,
				   PyObject *kwds)
{
	static char *keywords[] = {"sync_events", NULL};
	int sync_events = 1;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$p:enable", keywords,
					 &sync_events))
		return NULL;
	struct drgn_error *err = drgn_breakpoint_enable(&self->bp, sync_events);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *Breakpoint_disable(Breakpoint *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"sync_events", NULL};
	int sync_events = 1;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|$p:disable", keywords,
					 &sync_events))
		return NULL;
	struct drgn_error *err = drgn_breakpoint_disable(&self->bp, sync_events);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}
#endif

static PyObject *Breakpoint_get_enabled(Breakpoint *self)
{
	Py_RETURN_BOOL(drgn_breakpoint_enabled(&self->bp));
}

static PyObject *Breakpoint_get_removed(Breakpoint *self)
{
	Py_RETURN_BOOL(drgn_breakpoint_removed(&self->bp));
}

static PyGetSetDef Breakpoint_getset[] = {
	{"prog", (getter)Breakpoint_get_prog, NULL, drgn_Breakpoint_prog_DOC},
	{"sites", (getter)Breakpoint_get_sites, NULL,
	 drgn_Breakpoint_sites_DOC},
	{"enabled", (getter)Breakpoint_get_enabled, NULL,
	 drgn_Breakpoint_enabled_DOC},
	{"removed", (getter)Breakpoint_get_removed, NULL,
	 drgn_Breakpoint_removed_DOC},
	{"data", (getter)Breakpoint_get_data, (setter)Breakpoint_set_data,
	 drgn_Breakpoint_data_DOC},
	{},
};

static PyMethodDef Breakpoint_methods[] = {
#if 0
	{"remove", (PyCFunction)Breakpoint_remove,
	 METH_VARARGS | METH_KEYWORDS, drgn_Breakpoint_remove_DOC},
	{"enable", (PyCFunction)Breakpoint_enable,
	 METH_VARARGS | METH_KEYWORDS, drgn_Breakpoint_enable_DOC},
	{"disable", (PyCFunction)Breakpoint_disable,
	 METH_VARARGS | METH_KEYWORDS, drgn_Breakpoint_disable_DOC},
#endif
	{},
};

PyTypeObject Breakpoint_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Breakpoint",
	.tp_basicsize = sizeof(Breakpoint),
	.tp_dealloc = (destructor)Breakpoint_dealloc,
	.tp_repr = (reprfunc)Breakpoint_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_Breakpoint_DOC,
	.tp_traverse = (traverseproc)Breakpoint_traverse,
	.tp_clear = (inquiry)Breakpoint_clear,
	.tp_getset = Breakpoint_getset,
	.tp_methods = Breakpoint_methods,
};

static void BreakpointIterator_dealloc(BreakpointIterator *self)
{
	PyObject_GC_UnTrack(self);
	if (self->it) {
		Program *prog = container_of(drgn_breakpoint_iterator_program(self->it),
					     Program, prog);
		drgn_breakpoint_iterator_destroy(self->it);
		Py_DECREF(prog);
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int BreakpointIterator_traverse(BreakpointIterator *self,
				       visitproc visit, void *arg)
{
	if (self->it) {
		Py_VISIT(container_of(drgn_breakpoint_iterator_program(self->it),
				      Program, prog));
	}
	return 0;
}

static Breakpoint *BreakpointIterator_next(BreakpointIterator *self)
{
	struct drgn_error *err;
	struct drgn_breakpoint *bp;
	err = drgn_breakpoint_iterator_next(self->it, &bp);
	if (err)
		return set_drgn_error(err);
	return bp ? container_of(bp, Breakpoint, bp) : NULL;
}

PyTypeObject BreakpointIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._BreakpointIterator",
	.tp_basicsize = sizeof(BreakpointIterator),
	.tp_dealloc = (destructor)BreakpointIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)BreakpointIterator_traverse,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)BreakpointIterator_next,
};
