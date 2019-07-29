// Copyright 2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

static void StackTrace_dealloc(StackTrace *self)
{
	drgn_stack_trace_destroy(self->trace);
	Py_XDECREF(self->prog);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *StackTrace_str(StackTrace *self)
{
	struct drgn_error *err;
	PyObject *ret;
	char *str;

	err = drgn_pretty_print_stack_trace(self->trace, &str);
	if (err)
		return set_drgn_error(err);

	ret = PyUnicode_FromString(str);
	free(str);
	return ret;
}

static Py_ssize_t StackTrace_length(StackTrace *self)
{
	return drgn_stack_trace_num_frames(self->trace);
}

static StackFrame *StackTrace_item(StackTrace *self, Py_ssize_t i)
{
	struct drgn_stack_frame *frame;
	StackFrame *ret;

	if (i < 0 || !(frame = drgn_stack_trace_frame(self->trace, i))) {
		PyErr_SetString(PyExc_IndexError,
				"stack frame index out of range");
		return NULL;
	}
	ret = (StackFrame *)StackFrame_type.tp_alloc(&StackFrame_type, 0);
	if (!ret)
		return NULL;
	ret->frame = frame;
	ret->trace = self;
	Py_INCREF(self);
	return ret;
}

static PySequenceMethods StackTrace_as_sequence = {
	(lenfunc)StackTrace_length,	/* sq_length */
	NULL,				/* sq_concat */
	NULL,				/* sq_repeat */
	(ssizeargfunc)StackTrace_item,	/* sq_item */
};

PyTypeObject StackTrace_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.StackTrace",			/* tp_name */
	sizeof(StackTrace),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)StackTrace_dealloc,		/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	NULL,					/* tp_repr */
	NULL,					/* tp_as_number */
	&StackTrace_as_sequence,		/* tp_as_sequence */
	NULL,					/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	(reprfunc)StackTrace_str,		/* tp_str */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	drgn_StackTrace_DOC,			/* tp_doc */
};

static void StackFrame_dealloc(StackFrame *self)
{
	Py_XDECREF(self->trace);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static Symbol *StackFrame_symbol(StackFrame *self)
{
	return Program_find_symbol(self->trace->prog,
				   drgn_stack_frame_pc(self->frame));
}

static PyObject *StackFrame_get_pc(StackFrame *self, void *arg)
{
	return PyLong_FromUnsignedLongLong(drgn_stack_frame_pc(self->frame));
}

static PyMethodDef StackFrame_methods[] = {
	{"symbol", (PyCFunction)StackFrame_symbol, METH_NOARGS,
	 drgn_StackFrame_symbol_DOC},
	{},
};

static PyGetSetDef StackFrame_getset[] = {
	{"pc", (getter)StackFrame_get_pc, NULL, drgn_StackFrame_pc_DOC},
	{},
};

PyTypeObject StackFrame_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.StackFrame",			/* tp_name */
	sizeof(StackFrame),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)StackFrame_dealloc,		/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	NULL,					/* tp_repr */
	NULL,					/* tp_as_number */
	NULL,					/* tp_as_sequence */
	NULL,					/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	NULL,					/* tp_str */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
	drgn_StackFrame_DOC,			/* tp_doc */
	NULL,					/* tp_traverse */
	NULL,					/* tp_clear */
	NULL,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	StackFrame_methods,			/* tp_methods */
	NULL,					/* tp_members */
	StackFrame_getset,			/* tp_getset */
};
