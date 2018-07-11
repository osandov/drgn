// Copyright 2018 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#define PY_SSIZE_T_CLEAN

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <Python.h>

#define min(a, b) ((a) < (b) ? (a) : (b))

struct segment {
	uint64_t offset;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t filesz;
	uint64_t memsz;
};

typedef struct {
	PyObject_HEAD
	int fd;
	int num_segments;
	struct segment *segments;
} CoreReader;

static int pread_all(int fd, void *buf, size_t count, off_t offset)
{
	char *p = buf;

	while (count) {
		ssize_t ret;

		ret = pread(fd, p, count, offset);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		} else if (ret == 0) {
			errno = ENODATA;
			return -1;
		}
		p += ret;
		count -= ret;
		offset += ret;
	}
	return 0;
}

static void CoreReader_dealloc(CoreReader *self)
{
	free(self->segments);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int CoreReader_init(CoreReader *self, PyObject *args, PyObject *kwds)
{
	static const char *errmsg = "segment must be (offset, vaddr, paddr, filesz, memsz)";
	static char *keywords[] = {"fd", "segments", NULL};
	int fd;
	PyObject *segments_list;
	struct segment *segments;
	int num_segments, i;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "iO!:CoreReader", keywords,
					 &fd, &PyList_Type, &segments_list))
		return -1;

	if (PyList_GET_SIZE(segments_list) > INT_MAX) {
		PyErr_SetString(PyExc_OverflowError, "too many segments");
		return -1;
	}

	num_segments = PyList_GET_SIZE(segments_list);
	segments = calloc(num_segments, sizeof(*segments));
	if (!segments) {
		PyErr_NoMemory();
		return -1;
	}

	for (i = 0; i < num_segments; i++) {
		struct segment *segment = &segments[i];
		PyObject *segment_obj;

		segment_obj = PySequence_Fast(PyList_GET_ITEM(segments_list, i),
					      errmsg);
		if (!segment_obj)
			goto err;

		if (PySequence_Fast_GET_SIZE(segment_obj) != 5) {
			PyErr_SetString(PyExc_ValueError, errmsg);
			Py_DECREF(segment_obj);
			goto err;
		}

#define GET_MEMBER(var, idx) do {					\
	PyObject *tmp_obj;						\
	unsigned long long tmp;						\
									\
	tmp_obj = PySequence_Fast_GET_ITEM(segment_obj, idx);		\
	tmp = PyLong_AsUnsignedLongLong(tmp_obj);			\
	if (tmp == (unsigned long long)-1 && PyErr_Occurred()) {	\
		Py_DECREF(segment_obj);					\
		goto err;						\
	}								\
	var = tmp;							\
} while (0);
		GET_MEMBER(segment->offset, 0);
		GET_MEMBER(segment->vaddr, 1);
		GET_MEMBER(segment->paddr, 2);
		GET_MEMBER(segment->filesz, 3);
		GET_MEMBER(segment->memsz, 4);
#undef GET_MEMBER

		Py_DECREF(segment_obj);
	}

	free(self->segments);
	self->fd = fd;
	self->segments = segments;
	self->num_segments = num_segments;

	return 0;

err:
	free(segments);
	return -1;
}

static CoreReader *CoreReader_new(PyTypeObject *subtype, PyObject *args,
				  PyObject *kwds)
{
	CoreReader *reader;

	reader = (CoreReader *)subtype->tp_alloc(subtype, 0);
	if (reader)
		reader->fd = -1;
	return reader;
}

static int read_core(CoreReader *self, void *buf, uint64_t address,
		     uint64_t count, int physical)
{
	char *p = buf;

	while (count) {
		struct segment *segment;
		uint64_t segment_address;
		uint64_t segment_offset;
		off_t read_offset;
		size_t read_count, zero_count;
		int i;

		/*
		 * The most recently used segments are at the end of the list,
		 * so search backwards.
		 */
		for (i = self->num_segments - 1; i >= 0; i--) {
			segment = &self->segments[i];
			segment_address = (physical ? segment->paddr :
					   segment->vaddr);
			if (segment_address == (uint64_t)-1)
				continue;
			if (segment_address <= address &&
			    address < segment_address + segment->memsz)
				break;
		}
		if (i < 0) {
			char errmsg[60];

			sprintf(errmsg, "could not find memory segment containing 0x%" PRIx64,
				address);
			PyErr_SetString(PyExc_ValueError, errmsg);
			return -1;
		}

		/* Move the used segment to the end of the list. */
		if (i != self->num_segments - 1) {
			struct segment tmp = *segment;

			memmove(&self->segments[i], &self->segments[i + 1],
				(self->num_segments - i - 1) *
				sizeof(*self->segments));
			segment = &self->segments[self->num_segments - 1];
			*segment = tmp;
		}

		segment_offset = address - segment_address;
		if (segment_offset < segment->filesz)
			read_count = min(segment->filesz - segment_offset, count);
		else
			read_count = 0;
		if (segment_offset + read_count < segment->memsz)
			zero_count = min(segment->memsz - segment_offset - read_count,
					 count - read_count);
		else
			zero_count = 0;
		read_offset = segment->offset + segment_offset;
		if (pread_all(self->fd, p, read_count, read_offset) == -1) {
			PyErr_SetFromErrno(PyExc_OSError);
			return -1;
		}
		memset(p + read_count, 0, zero_count);

		p += read_count + zero_count;
		count -= read_count + zero_count;
		address += read_count + zero_count;
	}
	return 0;
}

static PyObject *CoreReader_read(CoreReader *self, PyObject *args,
				 PyObject *kwds)
{
	static char *keywords[] = {"address", "size", "physical", NULL};
	uint64_t address, size;
	int physical = 0;
	PyObject *buffer;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "KK|p:read", keywords,
					 &address, &size, &physical))
		return NULL;

	if (size > PY_SSIZE_T_MAX) {
		PyErr_SetString(PyExc_OverflowError, "size is too large");
		return NULL;
	}

	buffer = PyBytes_FromStringAndSize(NULL, size);
	if (!buffer)
		return NULL;

	if (read_core(self, PyBytes_AS_STRING(buffer), address, size,
		      physical) == -1) {
		Py_DECREF(buffer);
		return NULL;
	}

	return buffer;
}

#define CoreReader_READ(name, type, converter)					\
static PyObject *CoreReader_read_##name(CoreReader *self, PyObject *args,	\
					PyObject *kwds)				\
{										\
	static char *keywords[] = {"address", "physical", NULL};		\
	uint64_t address;							\
	int physical = 0;							\
	type value;								\
										\
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "K|p:read_" #name,		\
					 keywords, &address, &physical))	\
		return NULL;							\
										\
	if (read_core(self, &value, address, sizeof(value), physical) == -1)	\
		return NULL;							\
										\
	return converter(value);						\
}

CoreReader_READ(u8, uint8_t, PyLong_FromUnsignedLong)
CoreReader_READ(u16, uint16_t, PyLong_FromUnsignedLong)
CoreReader_READ(u32, uint32_t, PyLong_FromUnsignedLong)
CoreReader_READ(u64, uint64_t, PyLong_FromUnsignedLongLong)
CoreReader_READ(s8, int8_t, PyLong_FromLong)
CoreReader_READ(s16, int16_t, PyLong_FromLong)
CoreReader_READ(s32, int32_t, PyLong_FromLong)
CoreReader_READ(s64, int64_t, PyLong_FromLongLong)
CoreReader_READ(bool, int8_t, PyBool_FromLong)
CoreReader_READ(bool16, int16_t, PyBool_FromLong)
CoreReader_READ(bool32, int32_t, PyBool_FromLong)
CoreReader_READ(bool64, int64_t, PyBool_FromLong)
CoreReader_READ(float, float, PyFloat_FromDouble)
CoreReader_READ(double, double, PyFloat_FromDouble)
CoreReader_READ(long_double, long double, PyFloat_FromDouble)

#define CoreReader_READ_METHOD(name, description)		\
	{"read_" #name, (PyCFunction)CoreReader_read_##name,	\
	 METH_VARARGS | METH_KEYWORDS,				\
	 "read_" #name "(address, physical=False)\n\n"		\
	 "Read " description " from memory.\n\n"		\
	 "Arguments:\n"						\
	 "address -- address to read at\n"			\
	 "physical -- whether address is a physical memory address"}

#define CoreReader_DOC	\
	"CoreReader(fd, segments) -> new core file reader"

static PyMethodDef CoreReader_methods[] = {
	{"read", (PyCFunction)CoreReader_read,
	 METH_VARARGS | METH_KEYWORDS,
	 "read(address, size, physical=False)\n\n"
	 "Read memory.\n\n"
	 "Arguments:\n"
	 "address -- address to read at\n"
	 "size -- number of bytes to read\n"
	 "physical -- whether address is a physical memory address"},
	CoreReader_READ_METHOD(u8, "an unsigned 8-bit integer"),
	CoreReader_READ_METHOD(u16, "an unsigned 16-bit integer"),
	CoreReader_READ_METHOD(u32, "an unsigned 32-bit integer"),
	CoreReader_READ_METHOD(u64, "an unsigned 64-bit integer"),
	CoreReader_READ_METHOD(s8, "a signed 8-bit integer"),
	CoreReader_READ_METHOD(s16, "a signed 16-bit integer"),
	CoreReader_READ_METHOD(s32, "a signed 32-bit integer"),
	CoreReader_READ_METHOD(s64, "a signed 64-bit integer"),
	CoreReader_READ_METHOD(bool, "an 8-bit boolean"),
	CoreReader_READ_METHOD(bool16, "a 16-bit boolean"),
	CoreReader_READ_METHOD(bool32, "a 32-bit boolean"),
	CoreReader_READ_METHOD(bool64, "a 64-bit boolean"),
	CoreReader_READ_METHOD(float, "a 32-bit floating-point number"),
	CoreReader_READ_METHOD(double, "a 64-bit floating-point number"),
	CoreReader_READ_METHOD(long_double, "an 80-bit floating-point number"),
	{},
};

static PyTypeObject CoreReader_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.corereader.CoreReader",	/* tp_name */
	sizeof(CoreReader),		/* tp_basicsize */
	0,				/* tp_itemsize */
	(destructor)CoreReader_dealloc,	/* tp_dealloc */
	NULL,				/* tp_print */
	NULL,				/* tp_getattr */
	NULL,				/* tp_setattr */
	NULL,				/* tp_as_async */
	NULL,				/* tp_repr */
	NULL,				/* tp_as_number */
	NULL,				/* tp_as_sequence */
	NULL,				/* tp_as_mapping */
	NULL,				/* tp_hash  */
	NULL,				/* tp_call */
	NULL,				/* tp_str */
	NULL,				/* tp_getattro */
	NULL,				/* tp_setattro */
	NULL,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */
	CoreReader_DOC,			/* tp_doc */
	NULL,				/* tp_traverse */
	NULL,				/* tp_clear */
	NULL,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	NULL,				/* tp_iter */
	NULL,				/* tp_iternext */
	CoreReader_methods,		/* tp_methods */
	NULL,				/* tp_members */
	NULL,				/* tp_getset */
	NULL,				/* tp_base */
	NULL,				/* tp_dict */
	NULL,				/* tp_descr_get */
	NULL,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	(initproc)CoreReader_init,	/* tp_init */
	NULL,				/* tp_alloc */
	(newfunc)CoreReader_new,	/* tp_new */
};

static struct PyModuleDef corereadermodule = {
	PyModuleDef_HEAD_INIT,
	"corereader",
	"Core file reader",
	-1,
};

PyMODINIT_FUNC
PyInit_corereader(void)
{
	PyObject *m;

	m = PyModule_Create(&corereadermodule);
	if (!m)
		return NULL;

	if (PyType_Ready(&CoreReader_type) < 0)
		return NULL;
	Py_INCREF(&CoreReader_type);
	PyModule_AddObject(m, "CoreReader", (PyObject *)&CoreReader_type);

	return m;
}
