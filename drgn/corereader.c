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

static PyObject *ElfFormatError;

struct segment {
	uint64_t virt_address;
	uint64_t phys_address;
	uint64_t size;
	off_t offset;
};

typedef struct {
	PyObject_HEAD
	int fd;
	int num_segments;
	struct segment *segments;
} CoreReader;

static int read_all(int fd, void *buf, size_t count)
{
	char *p = buf;

	while (count) {
		ssize_t ret;

		ret = read(fd, p, count);
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
	}
	return 0;
}

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

static void close_reader(CoreReader *self)
{
	free(self->segments);
	self->segments = NULL;

	if (self->fd != -1) {
		close(self->fd);
		self->fd = -1;
	}
}

static void CoreReader_dealloc(CoreReader *self)
{
	close_reader(self);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int CoreReader_init(CoreReader *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"path", NULL};
	PyObject *path_obj, *path;
	Elf64_Phdr *phdrs = NULL;
	struct segment *segments = NULL;
	Elf64_Ehdr ehdr;
	unsigned int i;
	int fd;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:CoreReader", keywords,
					 &path_obj))
		return -1;

	if (!PyUnicode_FSConverter(path_obj, &path))
		return -1;

	fd = open(PyBytes_AsString(path), O_RDONLY);
	if (fd == -1) {
		PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, path_obj);
		Py_DECREF(path);
		return -1;
	}
	Py_DECREF(path);

	if (read_all(fd, ehdr.e_ident, EI_NIDENT) == -1) {
		if (errno == ENODATA)
			PyErr_SetString(ElfFormatError, "not an ELF file");
		else
			PyErr_SetFromErrno(PyExc_OSError);
		goto err;
	}

	if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		PyErr_SetString(ElfFormatError, "not an ELF file");
		goto err;
	}

	if (ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
		PyErr_Format(ElfFormatError, "ELF version %u is not EV_CURRENT",
			     (unsigned int)ehdr.e_ident[EI_VERSION]);
		return -1;
	}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
#else
	if (ehdr.e_ident[EI_DATA] != ELFDATA2MSB) {
#endif
		PyErr_SetString(PyExc_NotImplementedError,
				"ELF file endianness does not match machine");
		return -1;
	}

	if (read_all(fd, (char *)&ehdr + EI_NIDENT,
		      sizeof(Elf64_Ehdr) - EI_NIDENT) == -1) {
		if (errno == ENODATA)
			PyErr_SetString(ElfFormatError, "ELF header is truncated");
		else
			PyErr_SetFromErrno(PyExc_OSError);
		goto err;
	}

	if (ehdr.e_phnum == 0) {
		PyErr_SetString(ElfFormatError, "ELF file has no segments");
		goto err;
	}

	/* Don't need to worry about overflow because e_phnum is 16 bits. */
	phdrs = malloc(ehdr.e_phnum * sizeof(*phdrs));
	segments = malloc(ehdr.e_phnum * sizeof(*segments));
	if (!phdrs || !segments) {
		PyErr_NoMemory();
		goto err;
	}

	if ((off_t)ehdr.e_phoff < 0) {
		PyErr_SetString(ElfFormatError,
				"ELF program header table is beyond EOF");
		goto err;
	}

	if (lseek(fd, ehdr.e_phoff, SEEK_SET) == -1) {
		PyErr_SetFromErrno(PyExc_OSError);
		goto err;
	}

	if (read_all(fd, phdrs, ehdr.e_phnum * sizeof(*phdrs)) == -1) {
		if (errno == ENODATA)
			PyErr_SetString(ElfFormatError,
					"ELF program header table is beyond EOF");
		else
			PyErr_SetFromErrno(PyExc_OSError);
		goto err;
	}

	for (i = 0; i < ehdr.e_phnum; i++) {
		segments[i].virt_address = phdrs[i].p_vaddr;
		segments[i].phys_address = phdrs[i].p_paddr;
		segments[i].size = phdrs[i].p_memsz;
		segments[i].offset = phdrs[i].p_offset;
	}

	free(phdrs);
	free(self->segments);
	close(self->fd);
	self->fd = fd;
	self->segments = segments;
	self->num_segments = ehdr.e_phnum;

	return 0;

err:
	free(segments);
	free(phdrs);
	close(fd);
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

static PyObject *CoreReader_close(CoreReader *self)
{
	close_reader(self);
	Py_RETURN_NONE;
}

static PyObject *CoreReader_enter(PyObject *self)
{
	Py_INCREF(self);
	return self;
}

static PyObject *CoreReader_exit(CoreReader *self, PyObject *args,
				 PyObject *kwds)
{
	static char *keywords[] = {"exc_type", "exc_value", "traceback", NULL};
	PyObject *exc_type, *exc_value, *traceback;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOO:__exit__", keywords,
					 &exc_type, &exc_value, &traceback))
		return NULL;

	return CoreReader_close(self);
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
		size_t read_count;
		int i;

		/*
		 * The most recently used segments are at the end of the list,
		 * so search backwards.
		 */
		for (i = self->num_segments - 1; i >= 0; i--) {
			segment = &self->segments[i];
			segment_address = (physical ? segment->phys_address :
					   segment->virt_address);
			if (segment_address == (uint64_t)-1)
				continue;
			if (segment_address <= address &&
			    address < segment_address + segment->size)
				break;
		}
		if (i < 0) {
			PyErr_Format(PyExc_ValueError,
				     "could not find memory segment containing %p",
				     (void *)address);
			return -1;
		}

		/* Move the used segment to the end of the list. */
		if (i != self->num_segments - 1) {
			struct segment tmp = *segment;

			memmove(&self->segments[i], &self->segments[i + 1],
				(self->num_segments - i - 1) * sizeof(*self->segments));
			segment = &self->segments[self->num_segments - 1];
			*segment = tmp;
		}

		segment_offset = address - segment_address;
		if (segment->size - segment_offset < count)
			read_count = segment->size - segment_offset;
		else
			read_count = count;
		read_offset = segment->offset + segment_offset;
		if (pread_all(self->fd, p, read_count, read_offset) == -1) {
			PyErr_SetFromErrno(PyExc_OSError);
			return -1;
		}

		p += read_count;
		count -= read_count;
		address += read_count;
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
	"CoreReader(path) -> new core file reader"

static PyMethodDef CoreReader_methods[] = {
	{"close", (PyCFunction)CoreReader_close,
	 METH_NOARGS,
	 "close()\n\n"
	 "Close a core file reader."},
	{"__enter__", (PyCFunction)CoreReader_enter,
	 METH_NOARGS},
	{"__exit__", (PyCFunction)CoreReader_exit,
	 METH_VARARGS | METH_KEYWORDS},
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
	PyObject *name;
	PyObject *m;

	name = PyUnicode_FromString("drgn.elf");
	if (!name)
		return NULL;

	m = PyImport_Import(name);
	Py_DECREF(name);
	if (!m)
		return NULL;

	ElfFormatError = PyObject_GetAttrString(m, "ElfFormatError");
	if (!ElfFormatError) {
		Py_DECREF(m);
		return NULL;
	}

	Py_DECREF(m);

	m = PyModule_Create(&corereadermodule);
	if (!m)
		return NULL;

	if (PyType_Ready(&CoreReader_type) < 0)
		return NULL;
	Py_INCREF(&CoreReader_type);
	PyModule_AddObject(m, "CoreReader", (PyObject *)&CoreReader_type);

	return m;
}
