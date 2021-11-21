// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drgnpy.h"
#include "../helpers.h"
#include "../program.h"

PyObject *drgnpy_linux_helper_read_vm(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
	static char *keywords[] = {"prog", "pgtable", "address", "size", NULL};
	struct drgn_error *err;
	Program *prog;
	struct index_arg pgtable = {};
	struct index_arg address = {};
	Py_ssize_t size;
	PyObject *buf;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&O&n:read_vm",
					 keywords, &Program_type, &prog,
					 index_converter, &pgtable,
					 index_converter, &address, &size))
		return NULL;

	if (size < 0) {
		PyErr_SetString(PyExc_ValueError, "negative size");
		return NULL;
	}
	buf = PyBytes_FromStringAndSize(NULL, size);
	if (!buf)
		return NULL;
	err = linux_helper_read_vm(&prog->prog, pgtable.uvalue, address.uvalue,
				   PyBytes_AS_STRING(buf), size);
	if (err) {
		Py_DECREF(buf);
		return set_drgn_error(err);
	}
	return buf;
}

DrgnObject *drgnpy_linux_helper_radix_tree_lookup(PyObject *self,
						  PyObject *args,
						  PyObject *kwds)
{
	static char *keywords[] = {"root", "index", NULL};
	struct drgn_error *err;
	DrgnObject *root;
	struct index_arg index = {};
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:radix_tree_lookup",
					 keywords, &DrgnObject_type, &root,
					 index_converter, &index))
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(root));
	if (!res)
		return NULL;
	err = linux_helper_radix_tree_lookup(&res->obj, &root->obj,
					     index.uvalue);
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

DrgnObject *drgnpy_linux_helper_idr_find(PyObject *self, PyObject *args,
					 PyObject *kwds)
{
	static char *keywords[] = {"idr", "id", NULL};
	struct drgn_error *err;
	DrgnObject *idr;
	struct index_arg id = {};
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:idr_find", keywords,
					 &DrgnObject_type, &idr,
					 index_converter, &id))
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(idr));
	if (!res)
		return NULL;
	err = linux_helper_idr_find(&res->obj, &idr->obj, id.uvalue);
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

struct prog_or_ns_arg {
	Program *prog;
	struct drgn_object *ns;
	struct drgn_object tmp;
};

static void prog_or_ns_cleanup(struct prog_or_ns_arg *arg)
{
	if (arg->ns == &arg->tmp)
		drgn_object_deinit(arg->ns);
}

static int prog_or_pid_ns_converter(PyObject *o, void *p)
{
	struct prog_or_ns_arg *arg = p;

	if (!o) {
		prog_or_ns_cleanup(arg);
		return 1;
	}

	if (PyObject_TypeCheck(o, &Program_type)) {
		struct drgn_error *err;

		arg->prog = (Program *)o;
		arg->ns = &arg->tmp;
		drgn_object_init(arg->ns, &arg->prog->prog);
		err = drgn_program_find_object(&arg->prog->prog, "init_pid_ns",
					       NULL, DRGN_FIND_OBJECT_ANY,
					       arg->ns);
		if (!err)
			err = drgn_object_address_of(arg->ns, arg->ns);
		if (err) {
			drgn_object_deinit(arg->ns);
			set_drgn_error(err);
			return 0;
		}
	} else if (PyObject_TypeCheck(o, &DrgnObject_type)) {
		arg->prog = DrgnObject_prog((DrgnObject *)o);
		arg->ns = &((DrgnObject *)o)->obj;
	} else {
		PyErr_Format(PyExc_TypeError,
			     "expected Program or Object, not %s",
			     Py_TYPE(o)->tp_name);
		return 0;
	}
	return Py_CLEANUP_SUPPORTED;
}

DrgnObject *drgnpy_linux_helper_find_pid(PyObject *self, PyObject *args,
					  PyObject *kwds)
{
	static char *keywords[] = {"prog_or_ns", "pid", NULL};
	struct drgn_error *err;
	struct prog_or_ns_arg prog_or_ns;
	struct index_arg pid = {};
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&:find_pid", keywords,
					 &prog_or_pid_ns_converter, &prog_or_ns,
					 index_converter, &pid))
		return NULL;

	res = DrgnObject_alloc(prog_or_ns.prog);
	if (!res)
		goto out;
	err = linux_helper_find_pid(&res->obj, prog_or_ns.ns, pid.uvalue);
	if (err) {
		Py_DECREF(res);
		set_drgn_error(err);
		res = NULL;
	}
out:
	prog_or_ns_cleanup(&prog_or_ns);
	return res;
}

DrgnObject *drgnpy_linux_helper_pid_task(PyObject *self, PyObject *args,
					 PyObject *kwds)
{
	static char *keywords[] = {"pid", "pid_type", NULL};
	struct drgn_error *err;
	DrgnObject *pid;
	struct index_arg pid_type = {};
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:pid_task", keywords,
					 &DrgnObject_type, &pid,
					 index_converter, &pid_type))
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(pid));
	if (!res)
		return NULL;
	err = linux_helper_pid_task(&res->obj, &pid->obj, pid_type.uvalue);
	if (err) {
		Py_DECREF(res);
		return set_drgn_error(err);
	}
	return res;
}

DrgnObject *drgnpy_linux_helper_find_task(PyObject *self, PyObject *args,
					  PyObject *kwds)
{
	static char *keywords[] = {"ns", "pid", NULL};
	struct drgn_error *err;
	struct prog_or_ns_arg prog_or_ns;
	struct index_arg pid = {};
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&:find_task", keywords,
					 &prog_or_pid_ns_converter, &prog_or_ns,
					 index_converter, &pid))
		return NULL;

	res = DrgnObject_alloc(prog_or_ns.prog);
	if (!res)
		goto out;
	err = linux_helper_find_task(&res->obj, prog_or_ns.ns, pid.uvalue);
	if (err) {
		Py_DECREF(res);
		set_drgn_error(err);
		res = NULL;
	}
out:
	prog_or_ns_cleanup(&prog_or_ns);
	return res;
}

PyObject *drgnpy_linux_helper_kaslr_offset(PyObject *self, PyObject *args,
					   PyObject *kwds)

{
	static char *keywords[] = {"prog", NULL};
	Program *prog;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:kaslr_offset",
					 keywords, &Program_type, &prog))
		return NULL;

	if (!(prog->prog.flags & DRGN_PROGRAM_IS_LINUX_KERNEL))
		return PyErr_Format(PyExc_ValueError, "not Linux kernel");
	return PyLong_FromUnsignedLongLong(prog->prog.vmcoreinfo.kaslr_offset);
}

PyObject *drgnpy_linux_helper_pgtable_l5_enabled(PyObject *self, PyObject *args,
						 PyObject *kwds)

{
	static char *keywords[] = {"prog", NULL};
	Program *prog;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:pgtable_l5_enabled",
					 keywords, &Program_type, &prog))
		return NULL;

	if (!(prog->prog.flags & DRGN_PROGRAM_IS_LINUX_KERNEL))
		return PyErr_Format(PyExc_ValueError, "not Linux kernel");
	Py_RETURN_BOOL(prog->prog.vmcoreinfo.pgtable_l5_enabled);
}
