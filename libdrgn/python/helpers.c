// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"
#include "../helpers.h"

DrgnObject *drgnpy_linux_helper_radix_tree_lookup(PyObject *self,
						  PyObject *args,
						  PyObject *kwds)
{
	static char *keywords[] = {"root", "index", NULL};
	struct drgn_error *err;
	DrgnObject *root;
	struct index_arg index;
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:radix_tree_lookup",
					 keywords, &DrgnObject_type, &root,
					 index_converter, &index))
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(root));
	if (!res)
		return NULL;
	err = linux_helper_radix_tree_lookup(&res->obj, &root->obj,
					     index.value);
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
	struct index_arg id;
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:idr_find", keywords,
					 &DrgnObject_type, &idr,
					 index_converter, &id))
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(idr));
	if (!res)
		return NULL;
	err = linux_helper_idr_find(&res->obj, &idr->obj, id.value);
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
	static char *keywords[] = {"ns", "pid", NULL};
	struct drgn_error *err;
	struct prog_or_ns_arg prog_or_ns;
	struct index_arg pid;
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&:find_pid", keywords,
					 &prog_or_pid_ns_converter, &prog_or_ns,
					 index_converter, &pid))
		return NULL;

	res = DrgnObject_alloc(prog_or_ns.prog);
	if (!res)
		goto out;
	err = linux_helper_find_pid(&res->obj, prog_or_ns.ns, pid.value);
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
	struct index_arg pid_type;
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:pid_task", keywords,
					 &DrgnObject_type, &pid,
					 index_converter, &pid_type))
		return NULL;

	res = DrgnObject_alloc(DrgnObject_prog(pid));
	if (!res)
		return NULL;
	err = linux_helper_pid_task(&res->obj, &pid->obj, pid_type.value);
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
	struct index_arg pid;
	DrgnObject *res;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&:find_task", keywords,
					 &prog_or_pid_ns_converter, &prog_or_ns,
					 index_converter, &pid))
		return NULL;

	res = DrgnObject_alloc(prog_or_ns.prog);
	if (!res)
		goto out;
	err = linux_helper_find_task(&res->obj, prog_or_ns.ns, pid.value);
	if (err) {
		Py_DECREF(res);
		set_drgn_error(err);
		res = NULL;
	}
out:
	prog_or_ns_cleanup(&prog_or_ns);
	return res;
}

PyObject *drgnpy_linux_helper_task_state_to_char(PyObject *self, PyObject *args,
						 PyObject *kwds)
{
	static char *keywords[] = {"task", NULL};
	struct drgn_error *err;
	DrgnObject *task;
	char c;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:task_state_to_char",
					 keywords, &DrgnObject_type, &task))
		return NULL;

	err = linux_helper_task_state_to_char(&task->obj, &c);
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromStringAndSize(&c, 1);
}
