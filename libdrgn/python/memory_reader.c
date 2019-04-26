#include "drgnpy.h"

#include "../memory_reader.h"

static int MemoryReader_init(MemoryReader *self, PyObject *args, PyObject *kwds)
{
	if (PyTuple_GET_SIZE(args) || (kwds && PyDict_Size(kwds))) {
		PyErr_SetString(PyExc_ValueError,
				"MemoryReader() takes no arguments");
		return -1;
	}
	if (self->objects) {
		drgn_memory_reader_deinit(&self->reader);
		PyDict_Clear(self->objects);
	} else {
		self->objects = PyDict_New();
		if (!self->objects)
			return -1;
	}
	drgn_memory_reader_init(&self->reader);
	return 0;
}

static void MemoryReader_dealloc(MemoryReader *self)
{
	drgn_memory_reader_deinit(&self->reader);
	Py_XDECREF(self->objects);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int MemoryReader_traverse(MemoryReader *self, visitproc visit, void *arg)
{
	Py_VISIT(self->objects);
	return 0;
}

static int MemoryReader_clear(MemoryReader *self)
{
	Py_CLEAR(self->objects);
	return 0;
}

static int addr_converter(PyObject *arg, void *result)
{
	uint64_t *ret = result;
	unsigned long long tmp;

	if (arg == Py_None) {
		*ret = UINT64_MAX;
		return 1;
	}

	tmp = PyLong_AsUnsignedLongLong(arg);
	if (tmp == (unsigned long long)-1 && PyErr_Occurred())
		return 0;
	if (tmp >= UINT64_MAX) {
		PyErr_SetString(PyExc_OverflowError, "address is too large");
		return 0;
	}
	*ret = tmp;
	return 1;
}

static struct drgn_error *MemoryReader_read_fn(void *buf, uint64_t address,
					       size_t count, bool physical,
					       uint64_t offset, void *arg)
{
	struct drgn_error *err;
	PyGILState_STATE gstate;
	PyObject *ret;
	Py_buffer view;

	gstate = PyGILState_Ensure();
	ret = PyObject_CallFunction(arg, "KKOK", (unsigned long long)address,
				    (unsigned long long)count,
				    physical ? Py_True : Py_False,
				    (unsigned long long)offset);
	if (!ret) {
		err = drgn_error_from_python();
		goto out;
	}
	if (PyObject_GetBuffer(ret, &view, PyBUF_SIMPLE) == -1) {
		err = drgn_error_from_python();
		goto out_ret;
	}
	if (view.len != count) {
		PyErr_Format(PyExc_ValueError,
			     "memory read callback returned buffer of length %zd (expected %zu)",
			     view.len, count);
		err = drgn_error_from_python();
		goto out_view;
	}
	memcpy(buf, view.buf, count);

	err = NULL;
out_view:
	PyBuffer_Release(&view);
out_ret:
	Py_DECREF(ret);
out:
	PyGILState_Release(gstate);
	return err;
}

static PyObject *MemoryReader_add_segment(MemoryReader *self, PyObject *args,
					  PyObject *kwds)
{
	static char *keywords[] = {
		"virt_addr", "phys_addr", "size", "read_fn", NULL,
	};
	struct drgn_error *err;
	uint64_t virt_addr, phys_addr;
	unsigned long long size;
	PyObject *read_fn;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&KO:add_segment",
					 keywords, addr_converter, &virt_addr,
					 addr_converter, &phys_addr, &size,
					 &read_fn))
	    return NULL;

	if (!PyCallable_Check(read_fn)) {
		PyErr_SetString(PyExc_TypeError, "read_fn must be callable");
		return NULL;
	}

	if (hold_object(self->objects, read_fn) == -1)
		return NULL;
	err = drgn_memory_reader_add_segment(&self->reader, virt_addr,
					     phys_addr, size,
					     MemoryReader_read_fn, read_fn);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static PyObject *MemoryReader_read(MemoryReader *self, PyObject *args,
				   PyObject *kwds)
{
	static char *keywords[] = {"address", "size", "physical", NULL};
	struct drgn_error *err;
	unsigned long long address;
	Py_ssize_t size;
	int physical = 0;
	PyObject *buf;
	bool clear;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Kn|p:read", keywords,
					 &address, &size, &physical))
	    return NULL;

	if (size < 0) {
		PyErr_SetString(PyExc_ValueError, "negative size");
		return NULL;
	}
	buf = PyBytes_FromStringAndSize(NULL, size);
	if (!buf)
		return NULL;
	clear = set_drgn_in_python();
	err = drgn_memory_reader_read(&self->reader, PyBytes_AS_STRING(buf),
				      address, size, physical);
	if (clear)
		clear_drgn_in_python();
	if (err) {
		set_drgn_error(err);
		Py_DECREF(buf);
		return NULL;
	}
	return buf;
}

static PyMethodDef MemoryReader_methods[] = {
	{"add_segment", (PyCFunction)MemoryReader_add_segment,
	 METH_VARARGS | METH_KEYWORDS,
	 "add_segment(virt_addr, phys_addr, size, read_fn)\n--\n\n"},
	{"read", (PyCFunction)MemoryReader_read, METH_VARARGS | METH_KEYWORDS,
	 "read(address, size, physical=False)\n--\n\n"},
	{},
};

PyTypeObject MemoryReader_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.MemoryReader",			/* tp_name */
	sizeof(MemoryReader),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)MemoryReader_dealloc,	/* tp_dealloc */
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
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,/* tp_flags */
	"drgn_memory_reader wrapper for testing",/* tp_doc */
	(traverseproc)MemoryReader_traverse,	/* tp_traverse */
	(inquiry)MemoryReader_clear,		/* tp_clear */
	NULL,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	MemoryReader_methods,			/* tp_methods */
	NULL,					/* tp_members */
	NULL,					/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	(initproc)MemoryReader_init,		/* tp_init */
	NULL,					/* tp_alloc */
	PyType_GenericNew,			/* tp_new */
};
