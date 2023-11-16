// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../helpers.h"
#include "../program.h"

PyObject *drgnpy_linux_helper_direct_mapping_offset(PyObject *self, PyObject *arg)
{
	struct drgn_error *err;
	if (!PyObject_TypeCheck(arg, &Program_type)) {
		return PyErr_Format(PyExc_TypeError, "expected Program, not %s",
				    Py_TYPE(arg)->tp_name);
	}
	uint64_t ret;
	err = linux_helper_direct_mapping_offset(&((Program *)arg)->prog, &ret);
	if (err)
		return set_drgn_error(err);
	return PyLong_FromUint64(ret);
}

PyObject *drgnpy_linux_helper_read_vm(PyObject *self, PyObject *args,
				      PyObject *kwds)
{
	static char *keywords[] = {"prog", "pgtable", "address", "size", NULL};
	struct drgn_error *err;
	Program *prog;
	struct index_arg pgtable = {};
	struct index_arg address = {};
	Py_ssize_t size;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&O&n:read_vm",
					 keywords, &Program_type, &prog,
					 index_converter, &pgtable,
					 index_converter, &address, &size))
		return NULL;

	if (size < 0) {
		PyErr_SetString(PyExc_ValueError, "negative size");
		return NULL;
	}
	_cleanup_pydecref_ PyObject *buf = PyBytes_FromStringAndSize(NULL, size);
	if (!buf)
		return NULL;
	err = linux_helper_read_vm(&prog->prog, pgtable.uvalue, address.uvalue,
				   PyBytes_AS_STRING(buf), size);
	if (err)
		return set_drgn_error(err);
	return_ptr(buf);
}

PyObject *drgnpy_linux_helper_follow_phys(PyObject *self, PyObject *args,
					  PyObject *kwds)
{
	static char *keywords[] = {"prog", "pgtable", "address", NULL};
	struct drgn_error *err;
	Program *prog;
	struct index_arg pgtable = {};
	struct index_arg address = {};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&O&:follow_phys",
					 keywords, &Program_type, &prog,
					 index_converter, &pgtable,
					 index_converter, &address))
		return NULL;

	uint64_t phys;
	err = linux_helper_follow_phys(&prog->prog, pgtable.uvalue,
				       address.uvalue, &phys);
	if (err)
		return set_drgn_error(err);
	return PyLong_FromUint64(phys);
}

DrgnObject *drgnpy_linux_helper_per_cpu_ptr(PyObject *self, PyObject *args,
					    PyObject *kwds)
{
	static char *keywords[] = {"ptr", "cpu", NULL};
	struct drgn_error *err;
	DrgnObject *ptr;
	struct index_arg cpu = {};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:per_cpu_ptr",
					 keywords, &DrgnObject_type, &ptr,
					 index_converter, &cpu))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res = DrgnObject_alloc(DrgnObject_prog(ptr));
	if (!res)
		return NULL;
	err = linux_helper_per_cpu_ptr(&res->obj, &ptr->obj, cpu.uvalue);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

DrgnObject *drgnpy_linux_helper_cpu_curr(PyObject *self, PyObject *args)
{
	struct drgn_error *err;
	Program *prog;
	struct index_arg cpu = {};
	if (!PyArg_ParseTuple(args, "O!O&:cpu_curr", &Program_type, &prog,
			      index_converter, &cpu))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res = DrgnObject_alloc(prog);
	if (!res)
		return NULL;
	err = linux_helper_cpu_curr(&res->obj, cpu.uvalue);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

DrgnObject *drgnpy_linux_helper_idle_task(PyObject *self, PyObject *args)
{
	struct drgn_error *err;
	Program *prog;
	struct index_arg cpu = {};
	if (!PyArg_ParseTuple(args, "O!O&:idle_task", &Program_type, &prog,
			      index_converter, &cpu))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res = DrgnObject_alloc(prog);
	if (!res)
		return NULL;
	err = linux_helper_idle_task(&res->obj, cpu.uvalue);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

PyObject *drgnpy_linux_helper_task_cpu(PyObject *self, PyObject *args,
				       PyObject *kwds)
{
	static char *keywords[] = {"task", NULL};
	struct drgn_error *err;
	DrgnObject *task;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!:task_cpu", keywords,
					 &DrgnObject_type, &task))
		return NULL;
	uint64_t cpu;
	err = linux_helper_task_cpu(&task->obj, &cpu);
	if (err)
		return set_drgn_error(err);
	return PyLong_FromUint64(cpu);
}

DrgnObject *drgnpy_linux_helper_xa_load(PyObject *self, PyObject *args,
					PyObject *kwds)
{
	static char *keywords[] = {"xa", "index", NULL};
	struct drgn_error *err;
	DrgnObject *xa;
	struct index_arg index = {};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:xa_load", keywords,
					 &DrgnObject_type, &xa, index_converter,
					 &index))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res = DrgnObject_alloc(DrgnObject_prog(xa));
	if (!res)
		return NULL;
	err = linux_helper_xa_load(&res->obj, &xa->obj, index.uvalue);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

DrgnObject *drgnpy_linux_helper_idr_find(PyObject *self, PyObject *args,
					 PyObject *kwds)
{
	static char *keywords[] = {"idr", "id", NULL};
	struct drgn_error *err;
	DrgnObject *idr;
	struct index_arg id = {};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:idr_find", keywords,
					 &DrgnObject_type, &idr,
					 index_converter, &id))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(idr));
	if (!res)
		return NULL;
	err = linux_helper_idr_find(&res->obj, &idr->obj, id.uvalue);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

DrgnObject *drgnpy_linux_helper_find_pid(PyObject *self, PyObject *args)
{
	struct drgn_error *err;
	DrgnObject *ns;
	struct index_arg pid = {};
	if (!PyArg_ParseTuple(args, "O!O&:find_pid", &DrgnObject_type, &ns,
			      index_converter, &pid))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(ns));
	if (!res)
		return NULL;
	err = linux_helper_find_pid(&res->obj, &ns->obj, pid.uvalue);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

DrgnObject *drgnpy_linux_helper_pid_task(PyObject *self, PyObject *args,
					 PyObject *kwds)
{
	static char *keywords[] = {"pid", "pid_type", NULL};
	struct drgn_error *err;
	DrgnObject *pid;
	struct index_arg pid_type = {};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O&:pid_task", keywords,
					 &DrgnObject_type, &pid,
					 index_converter, &pid_type))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res = DrgnObject_alloc(DrgnObject_prog(pid));
	if (!res)
		return NULL;
	err = linux_helper_pid_task(&res->obj, &pid->obj, pid_type.uvalue);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

DrgnObject *drgnpy_linux_helper_find_task(PyObject *self, PyObject *args)
{
	struct drgn_error *err;
	DrgnObject *ns;
	struct index_arg pid = {};
	if (!PyArg_ParseTuple(args, "O!O&:find_task", &DrgnObject_type, &ns,
			      index_converter, &pid))
		return NULL;

	_cleanup_pydecref_ DrgnObject *res =
		DrgnObject_alloc(DrgnObject_prog(ns));
	if (!res)
		return NULL;
	err = linux_helper_find_task(&res->obj, &ns->obj, pid.uvalue);
	if (err)
		return set_drgn_error(err);
	return_ptr(res);
}

PyObject *drgnpy_linux_helper_kaslr_offset(PyObject *self, PyObject *arg)

{
	if (!PyObject_TypeCheck(arg, &Program_type)) {
		return PyErr_Format(PyExc_TypeError, "expected Program, not %s",
				    Py_TYPE(arg)->tp_name);
	}
	Program *prog = (Program *)arg;
	if (!(prog->prog.flags & DRGN_PROGRAM_IS_LINUX_KERNEL))
		return PyErr_Format(PyExc_ValueError, "not Linux kernel");
	return PyLong_FromUint64(prog->prog.vmcoreinfo.kaslr_offset);
}

PyObject *drgnpy_linux_helper_pgtable_l5_enabled(PyObject *self, PyObject *arg)

{
	if (!PyObject_TypeCheck(arg, &Program_type)) {
		return PyErr_Format(PyExc_TypeError, "expected Program, not %s",
				    Py_TYPE(arg)->tp_name);
	}
	Program *prog = (Program *)arg;
	if (!(prog->prog.flags & DRGN_PROGRAM_IS_LINUX_KERNEL))
		return PyErr_Format(PyExc_ValueError, "not Linux kernel");
	Py_RETURN_BOOL(prog->prog.vmcoreinfo.pgtable_l5_enabled);
}
