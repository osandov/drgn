// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../platform.h"
#include "../program.h"
#include "../register_state.h"
#include "../util.h"

struct drgn_register_state *drgn_register_state_alloc(struct drgn_program *prog)
{
	RegisterState *ret = call_tp_alloc(RegisterState);
	if (!ret)
		return NULL;
	drgn_register_state_init(&ret->regs, prog);
	Py_INCREF(container_of(prog, Program, prog));
	return &ret->regs;
}

LIBDRGN_PUBLIC void drgn_register_state_incref(struct drgn_register_state *regs)
{
	Py_INCREF(container_of(regs, RegisterState, regs));
}

LIBDRGN_PUBLIC void drgn_register_state_decref(struct drgn_register_state *regs)
{
	if (regs)
		Py_DECREF(container_of(regs, RegisterState, regs));
}

static void RegisterState_dealloc(RegisterState *self)
{
	PyObject_GC_UnTrack(self);
	struct drgn_program *prog = drgn_register_state_program(&self->regs);
	drgn_register_state_deinit(&self->regs);
	Py_DECREF(container_of(prog, Program, prog));
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *RegisterState_str(RegisterState *self)
{
	_cleanup_free_ char *str = NULL;
	struct drgn_error *err = drgn_format_register_state(&self->regs, &str);
	if (err)
		return set_drgn_error(err);
	return PyUnicode_FromString(str);
}

static int RegisterState_traverse(RegisterState *self, visitproc visit,
				  void *arg)
{
	Py_VISIT(container_of(drgn_register_state_program(&self->regs), Program,
			      prog));
	return 0;
}

static PyObject *RegisterState_new(PyTypeObject *subtype, PyObject *args,
				   PyObject *kwds)
{
	struct drgn_error *err;
	static char *keywords[] = {"prog", "interrupted", NULL};
	Program *prog;
	int interrupted;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!p:RegisterState",
					 keywords, &Program_type, &prog,
					 &interrupted))
		return NULL;

	struct drgn_register_state *regs;
	err = drgn_register_state_create(&prog->prog, interrupted, &regs);
	if (err)
		return set_drgn_error(err);
	return (PyObject *)container_of(regs, RegisterState, regs);
}

static const struct drgn_register *drgn_register_arg(RegisterState *regs,
						     PyObject *reg_obj)
{
	if (PyUnicode_Check(reg_obj)) {
		const char *name = PyUnicode_AsUTF8(reg_obj);
		if (!name)
			return NULL;
		const struct drgn_register *reg =
			drgn_register_state_register_by_name(&regs->regs, name);
		if (!reg) {
			PyErr_Format(PyExc_ValueError, "unknown register %R",
				     reg_obj);
			return NULL;
		}
		return reg;
	} else if (PyObject_TypeCheck(reg_obj, &Register_type)) {
		return ((Register *)reg_obj)->reg;
	} else {
		PyErr_SetString(PyExc_TypeError,
				"register must be str or drgn.Register");
		return NULL;
	}
}

static PyObject *RegisterState_is_set(RegisterState *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"reg", NULL};
	PyObject *reg_obj;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:is_set", keywords,
					 &reg_obj))
		return NULL;
	const struct drgn_register *reg = drgn_register_arg(self, reg_obj);
	if (!reg)
		return NULL;
	Py_RETURN_BOOL(drgn_register_state_is_set(&self->regs, reg));
}

static PyObject *RegisterState_get(RegisterState *self, PyObject *args,
				   PyObject *kwds)
{
	static char *keywords[] = {"reg", NULL};
	PyObject *reg_obj;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:get", keywords,
					 &reg_obj))
		return NULL;
	const struct drgn_register *reg = drgn_register_arg(self, reg_obj);
	if (!reg)
		return NULL;

	size_t size = drgn_register_size(reg);
	if (size <= sizeof(uint64_t)) {
		struct drgn_optional_u64 value =
			drgn_register_state_get_u64(&self->regs, reg);
		if (!value.has_value)
			Py_RETURN_NONE;
		return PyLong_FromUInt64(value.value);
	} else {
		_cleanup_free_ void *buf = malloc(size);
		if (!buf)
			return PyErr_NoMemory();
		if (!drgn_register_state_get_raw(&self->regs, reg, buf))
			Py_RETURN_NONE;
		bool little_endian =
			drgn_platform_is_little_endian(&self->regs.prog->platform);
		return _PyLong_FromByteArray(buf, size, little_endian, false);
	}
}

static PyObject *RegisterState_get_raw(RegisterState *self, PyObject *args,
				       PyObject *kwds)
{
	static char *keywords[] = {"reg", NULL};
	PyObject *reg_obj;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:get_raw", keywords,
					 &reg_obj))
		return NULL;
	const struct drgn_register *reg = drgn_register_arg(self, reg_obj);
	if (!reg)
		return NULL;

	size_t size = drgn_register_size(reg);
	_cleanup_pydecref_ PyObject *ret =
		PyBytes_FromStringAndSize(NULL, size);
	if (!ret)
		return NULL;
	if (!drgn_register_state_get_raw(&self->regs, reg,
					 PyBytes_AS_STRING(ret)))
		Py_RETURN_NONE;
	return_ptr(ret);
}

static PyObject *RegisterState_set(RegisterState *self, PyObject *args,
				   PyObject *kwds)
{
	struct drgn_error *err;
	static char *keywords[] = {"reg", "value", NULL};
	PyObject *reg_obj, *value;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO:set", keywords,
					 &reg_obj, &value))
		return NULL;
	const struct drgn_register *reg = drgn_register_arg(self, reg_obj);
	if (!reg)
		return NULL;

	// We could pass the register state buffer directly to
	// drgn_pylong_to_bytes(), but the underlying PyLong_AsNativeBytes() or
	// _PyLong_AsByteArray() functions don't promise that they don't modify
	// the buffer on error, so we use a temporary buffer just in case.
	void *buf;
	char small_buf[sizeof(uint64_t)];
	_cleanup_free_ void *large_buf = NULL;
	size_t size = drgn_register_size(reg);
	if (size <= sizeof(small_buf)) {
		buf = small_buf;
	} else {
		large_buf = malloc(size);
		if (!large_buf)
			return PyErr_NoMemory();
		buf = large_buf;
	}

	_cleanup_pydecref_ PyObject *index = PyNumber_Index(value);
	if (!index)
		return NULL;
	bool little_endian =
		drgn_platform_is_little_endian(&self->regs.prog->platform);
	if (drgn_pylong_to_bytes(index, buf, size, little_endian))
		return NULL;

	err = drgn_register_state_set_raw(&self->regs, reg, buf);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *RegisterState_set_raw(RegisterState *self, PyObject *args,
				       PyObject *kwds)
{
	struct drgn_error *err;
	static char *keywords[] = {"reg", "value", NULL};
	PyObject *reg_obj;
	Py_buffer value;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oy*:set_raw", keywords,
					 &reg_obj, &value))
		return NULL;
	const struct drgn_register *reg = drgn_register_arg(self, reg_obj);
	if (!reg)
		goto err;

	if (value.len != drgn_register_size(reg)) {
		PyErr_SetString(PyExc_ValueError, "value is wrong size");
		goto err;
	}

	err = drgn_register_state_set_raw(&self->regs, reg, value.buf);
	if (err) {
		set_drgn_error(err);
		goto err;
	}

	PyBuffer_Release(&value);
	Py_RETURN_NONE;

err:
	PyBuffer_Release(&value);
	return NULL;
}

static PyObject *RegisterState_unset(RegisterState *self, PyObject *args,
				     PyObject *kwds)
{
	struct drgn_error *err;
	static char *keywords[] = {"reg", NULL};
	PyObject *reg_obj;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:unset", keywords,
					 &reg_obj))
		return NULL;
	const struct drgn_register *reg = drgn_register_arg(self, reg_obj);
	if (!reg)
		return NULL;
	err = drgn_register_state_unset(&self->regs, reg);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static RegisterState *RegisterState_copy(RegisterState *self)
{
	struct drgn_register_state *regs =
		drgn_register_state_copy(&self->regs);
	if (!regs) {
		PyErr_NoMemory();
		return NULL;
	}
	return container_of(regs, RegisterState, regs);
}

static RegisterState *RegisterState_deepcopy(RegisterState *self, PyObject *arg)
{
	return RegisterState_copy(self);
}

static Program *RegisterState_get_prog(RegisterState *self, void *arg)
{
	Program *prog = container_of(drgn_register_state_program(&self->regs),
				     Program, prog);
	Py_INCREF(prog);
	return prog;
}

static PyObject *RegisterState_get_interrupted(RegisterState *self, void *arg)
{
	Py_RETURN_BOOL(drgn_register_state_interrupted(&self->regs));
}

static int RegisterState_set_interrupted(RegisterState *self, PyObject *value, void *arg)
{
	SETTER_NO_DELETE("interrupted", value);

	struct drgn_error *err;
	if (!PyBool_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "interrupted must be bool");
		return -1;
	}
	err = drgn_register_state_set_interrupted(&self->regs,
						  value == Py_True);
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

static PyObject *RegisterState_get_pc(RegisterState *self, void *arg)
{
	struct drgn_optional_u64 pc = drgn_register_state_pc(&self->regs);
	if (!pc.has_value)
		Py_RETURN_NONE;
	return PyLong_FromUInt64(pc.value);
}

static int RegisterState_set_pc(RegisterState *self, PyObject *value, void *arg)
{
	SETTER_NO_DELETE("pc", value);

	struct drgn_error *err;
	if (value == Py_None) {
		err = drgn_register_state_unset_pc(&self->regs);
	} else {
		uint64_t pc;
		if (PyLong_AsUInt64(value, &pc))
			return -1;
		err = drgn_register_state_set_pc(&self->regs, pc);
	}
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

static PyObject *RegisterState_get_cfa(RegisterState *self, void *arg)
{
	struct drgn_optional_u64 cfa = drgn_register_state_cfa(&self->regs);
	if (!cfa.has_value)
		Py_RETURN_NONE;
	return PyLong_FromUInt64(cfa.value);
}

static int RegisterState_set_cfa(RegisterState *self, PyObject *value, void *arg)
{
	SETTER_NO_DELETE("cfa", value);

	struct drgn_error *err;
	if (value == Py_None) {
		err = drgn_register_state_unset_cfa(&self->regs);
	} else {
		uint64_t cfa;
		if (PyLong_AsUInt64(value, &cfa))
			return -1;
		err = drgn_register_state_set_cfa(&self->regs, cfa);
	}
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

static PyMethodDef RegisterState_methods[] = {
	{"is_set", (PyCFunction)RegisterState_is_set,
	 METH_VARARGS | METH_KEYWORDS, drgn_RegisterState_is_set_DOC},
	{"get", (PyCFunction)RegisterState_get,
	 METH_VARARGS | METH_KEYWORDS, drgn_RegisterState_get_DOC},
	{"get_raw", (PyCFunction)RegisterState_get_raw,
	 METH_VARARGS | METH_KEYWORDS, drgn_RegisterState_get_raw_DOC},
	{"set", (PyCFunction)RegisterState_set,
	 METH_VARARGS | METH_KEYWORDS, drgn_RegisterState_set_DOC},
	{"set_raw", (PyCFunction)RegisterState_set_raw,
	 METH_VARARGS | METH_KEYWORDS, drgn_RegisterState_set_raw_DOC},
	{"unset", (PyCFunction)RegisterState_unset,
	 METH_VARARGS | METH_KEYWORDS, drgn_RegisterState_unset_DOC},
	{"copy", (PyCFunction)RegisterState_copy, METH_NOARGS,
	 drgn_RegisterState_copy_DOC},
	{"__copy__", (PyCFunction)RegisterState_copy, METH_NOARGS},
	{"__deepcopy__", (PyCFunction)RegisterState_deepcopy, METH_O},
	{},
};

static PyGetSetDef RegisterState_getset[] = {
	{"prog", (getter)RegisterState_get_prog, NULL,
	 drgn_RegisterState_prog_DOC},
	{"interrupted", (getter)RegisterState_get_interrupted,
	 (setter)RegisterState_set_interrupted,
	 drgn_RegisterState_interrupted_DOC},
	{"pc", (getter)RegisterState_get_pc, (setter)RegisterState_set_pc,
	 drgn_RegisterState_pc_DOC},
	{"cfa", (getter)RegisterState_get_cfa, (setter)RegisterState_set_cfa,
	 drgn_RegisterState_cfa_DOC},
	{},
};

PyTypeObject RegisterState_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.RegisterState",
	.tp_basicsize = sizeof(RegisterState),
	.tp_dealloc = (destructor)RegisterState_dealloc,
	.tp_str = (reprfunc)RegisterState_str,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
	.tp_doc = drgn_RegisterState_DOC,
	.tp_traverse = (traverseproc)RegisterState_traverse,
	.tp_methods = RegisterState_methods,
	.tp_getset = RegisterState_getset,
	.tp_new = RegisterState_new,
};
