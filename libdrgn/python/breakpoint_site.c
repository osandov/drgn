// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../util.h"

struct drgn_breakpoint_site *drgn_breakpoint_site_alloc(void)
{
	BreakpointSite *ret = call_tp_alloc(BreakpointSite);
	if (!ret)
		return NULL;
	return &ret->site;
}

LIBDRGN_PUBLIC void drgn_breakpoint_site_incref(struct drgn_breakpoint_site *site)
{
	Py_INCREF(container_of(site, BreakpointSite, site));
}

LIBDRGN_PUBLIC void drgn_breakpoint_site_decref(struct drgn_breakpoint_site *site)
{
	if (site)
		Py_DECREF(container_of(site, BreakpointSite, site));
}

static void BreakpointSite_dealloc(BreakpointSite *self)
{
	PyObject_GC_UnTrack(self);
	drgn_breakpoint_site_deinit(&self->site);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int BreakpointSite_traverse(BreakpointSite *self, visitproc visit,
				   void *arg)
{
	Py_VISIT(container_of(drgn_breakpoint_site_program(&self->site),
			      Program, prog));
	if (self->site.destroy_controller_data == py_destroy_data)
		Py_VISIT(drgn_breakpoint_site_get_controller_data(&self->site));
	return 0;
}

static int BreakpointSite_clear(BreakpointSite *self)
{
	if (self->site.destroy_controller_data == py_destroy_data) {
		drgn_breakpoint_site_set_controller_data(&self->site, NULL,
							 NULL);
	}
	return 0;
}

static PyObject *BreakpointSite_repr(BreakpointSite *self)
{
	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts
	    || append_string(parts, "BreakpointSite(address=")
	    || append_u64_hex(parts, drgn_breakpoint_site_address(&self->site))
	    || append_format(parts, ", hardware=%s)",
			     drgn_breakpoint_site_hardware(&self->site)
			     ? "True" : "False"))
		return NULL;
	return join_strings(parts);
}

static Program *BreakpointSite_get_prog(BreakpointSite *self)
{
	Program *ret = container_of(drgn_breakpoint_site_program(&self->site),
				    Program, prog);
	Py_INCREF(ret);
	return ret;
}

static PyObject *BreakpointSite_get_address(BreakpointSite *self)
{
	return PyLong_FromUInt64(drgn_breakpoint_site_address(&self->site));
}

static PyObject *BreakpointSite_get_hardware(BreakpointSite *self)
{
	Py_RETURN_BOOL(drgn_breakpoint_site_hardware(&self->site));
}

static PyObject *BreakpointSite_get_enabled(BreakpointSite *self)
{
	Py_RETURN_BOOL(drgn_breakpoint_site_enabled(&self->site));
}

static PyObject *BreakpointSite_get_removed(BreakpointSite *self)
{
	Py_RETURN_BOOL(drgn_breakpoint_site_removed(&self->site));
}

static BreakpointIterator *
BreakpointSite_breakpoints_iter(BreakpointSite *self,
				struct drgn_error *(*create)(struct drgn_breakpoint_site *,
							     struct drgn_breakpoint_iterator **))
{
	struct drgn_breakpoint_iterator *it;
	struct drgn_error *err = create(&self->site, &it);
	if (err)
		return set_drgn_error(err);
	BreakpointIterator *ret = call_tp_alloc(BreakpointIterator);
	if (!ret) {
		drgn_breakpoint_iterator_destroy(it);
		return NULL;
	}
	Program *prog =
		container_of(drgn_breakpoint_site_program(&self->site), Program,
			     prog);
	Py_INCREF(prog);
	ret->it = it;
	return ret;
}

static BreakpointIterator *
BreakpointSite_enabled_breakpoints(BreakpointSite *self)
{
	return BreakpointSite_breakpoints_iter(self,
					       drgn_breakpoint_site_enabled_breakpoints);
}

static BreakpointIterator *
BreakpointSite_disabled_breakpoints(BreakpointSite *self)
{
	return BreakpointSite_breakpoints_iter(self,
					       drgn_breakpoint_site_disabled_breakpoints);
}

static PyObject *BreakpointSite_get_controller_data(BreakpointSite *self)
{
	if (!self->site.destroy_controller_data) {
		Py_RETURN_NONE;
	} else if (self->site.destroy_controller_data != py_destroy_data) {
		PyErr_SetString(PyExc_RuntimeError,
				"breakpoint site controller data was not set from Python");
		return NULL;
	}
	PyObject *data = drgn_breakpoint_site_get_controller_data(&self->site);
	Py_INCREF(data);
	return data;
}

static int BreakpointSite_set_controller_data(BreakpointSite *self,
					      PyObject *value)
{
	SETTER_NO_DELETE("_controller_data", value);
	Py_INCREF(value);
	drgn_breakpoint_site_set_controller_data(&self->site, value,
						 py_destroy_data);
	return 0;
}

static PyGetSetDef BreakpointSite_getset[] = {
	{"prog", (getter)BreakpointSite_get_prog, NULL,
	 drgn_BreakpointSite_prog_DOC},
	{"address", (getter)BreakpointSite_get_address, NULL,
	 drgn_BreakpointSite_address_DOC},
	{"hardware", (getter)BreakpointSite_get_hardware, NULL,
	 drgn_BreakpointSite_hardware_DOC},
	{"enabled", (getter)BreakpointSite_get_enabled, NULL,
	 drgn_BreakpointSite_enabled_DOC},
	{"removed", (getter)BreakpointSite_get_removed, NULL,
	 drgn_BreakpointSite_removed_DOC},
	{"_controller_data", (getter)BreakpointSite_get_controller_data,
	 (setter)BreakpointSite_set_controller_data,
	 drgn_BreakpointSite__controller_data_DOC},
	{},
};

static PyMethodDef BreakpointSite_methods[] = {
	{"enabled_breakpoints", (PyCFunction)BreakpointSite_enabled_breakpoints,
	 METH_NOARGS, drgn_BreakpointSite_enabled_breakpoints_DOC},
	{"disabled_breakpoints",
	 (PyCFunction)BreakpointSite_disabled_breakpoints, METH_NOARGS,
	 drgn_BreakpointSite_disabled_breakpoints_DOC},
	{},
};

PyTypeObject BreakpointSite_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.BreakpointSite",
	.tp_basicsize = sizeof(BreakpointSite),
	.tp_dealloc = (destructor)BreakpointSite_dealloc,
	.tp_repr = (reprfunc)BreakpointSite_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_BreakpointSite_DOC,
	.tp_traverse = (traverseproc)BreakpointSite_traverse,
	.tp_clear = (inquiry)BreakpointSite_clear,
	.tp_getset = BreakpointSite_getset,
	.tp_methods = BreakpointSite_methods,
};

static void BreakpointSiteIterator_dealloc(BreakpointSiteIterator *self)
{
	PyObject_GC_UnTrack(self);
	if (self->it) {
		Program *prog = container_of(drgn_breakpoint_site_iterator_program(self->it),
					     Program, prog);
		drgn_breakpoint_site_iterator_destroy(self->it);
		Py_DECREF(prog);
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int BreakpointSiteIterator_traverse(BreakpointSiteIterator *self,
					   visitproc visit, void *arg)
{
	if (self->it) {
		Py_VISIT(container_of(drgn_breakpoint_site_iterator_program(self->it),
				      Program, prog));
	}
	return 0;
}

static BreakpointSite *BreakpointSiteIterator_next(BreakpointSiteIterator *self)
{
	struct drgn_error *err;
	struct drgn_breakpoint_site *site;
	err = drgn_breakpoint_site_iterator_next(self->it, &site);
	if (err)
		return set_drgn_error(err);
	return site ? container_of(site, BreakpointSite, site) : NULL;
}

PyTypeObject BreakpointSiteIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._BreakpointSiteIterator",
	.tp_basicsize = sizeof(BreakpointSiteIterator),
	.tp_dealloc = (destructor)BreakpointSiteIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_traverse = (traverseproc)BreakpointSiteIterator_traverse,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)BreakpointSiteIterator_next,
};
