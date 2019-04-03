// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

static Program *Program_alloc(void)
{
	Program *prog;
	PyObject *dict;

	dict = PyDict_New();
	if (!dict)
		return NULL;

	prog = (Program *)Program_type.tp_alloc(&Program_type, 0);
	if (!prog) {
		Py_DECREF(dict);
		return NULL;
	}
	prog->objects = dict;
	return prog;
}

static int Program_hold_object(Program *prog, PyObject *obj)
{
	PyObject *key;
	int ret;

	key = PyLong_FromVoidPtr(obj);
	if (!key)
		return -1;

	ret = PyDict_SetItem(prog->objects, key, obj);
	Py_DECREF(key);
	return ret;
}

int Program_hold_type(Program *prog, DrgnType *type)
{
	PyObject *parent;

	parent = DrgnType_parent(type);
	if (parent && parent != (PyObject *)prog)
		return Program_hold_object(prog, parent);
	else
		return 0;
}

static void mock_program_deinit(struct drgn_program *prog)
{
	Program *self = container_of(prog, Program, prog);
	struct drgn_mock_memory_reader *mreader;
	struct drgn_mock_type_index *mtindex;
	struct drgn_mock_object_index *moindex;
	size_t i;

	moindex = container_of(self->prog.oindex, struct drgn_mock_object_index,
			       oindex);
	free(moindex->objects);

	mtindex = container_of(self->prog.tindex, struct drgn_mock_type_index,
			       tindex);
	free(mtindex->types);

	mreader = container_of(self->prog.reader,
			       struct drgn_mock_memory_reader, reader);
	for (i = 0; i < mreader->num_segments; i++)
		PyBuffer_Release(&self->buffers[i]);
	free(self->buffers);
	free(mreader->segments);
}

static void Program_dealloc(Program *self)
{
	if (self->inited)
		drgn_program_deinit(&self->prog);
	Py_XDECREF(self->objects);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int Program_traverse(Program *self, visitproc visit, void *arg)
{
	Py_VISIT(self->objects);
	return 0;
}

static int Program_clear(Program *self)
{
	Py_CLEAR(self->objects);
	return 0;
}

static PyObject *Program_read(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"address", "size", "physical", NULL};
	struct drgn_error *err;
	unsigned long long address;
	Py_ssize_t size;
	int physical = 0;
	PyObject *buf;

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
	err = drgn_program_read_memory(&self->prog, PyBytes_AS_STRING(buf),
				       address, size, physical);
	if (err) {
		set_drgn_error(err);
		Py_DECREF(buf);
		return NULL;
	}
	return buf;
}

static int filename_converter(PyObject *obj, void *result)
{
	if (obj == NULL) {
		Py_XDECREF(*(PyObject **)result);
		return 1;
	}

	if (obj == Py_None) {
		obj = NULL;
	} else if (PyUnicode_Check(obj)) {
		obj = PyUnicode_EncodeFSDefault(obj);
		if (!obj)
			return 0;
	} else if (PyBytes_Check(obj)) {
		Py_INCREF(obj);
	} else {
		PyErr_SetString(PyExc_TypeError,
				"filename must be string, bytes, or None");
		return 0;
	}
	*(PyObject **)result = obj;
	return Py_CLEANUP_SUPPORTED;
}

static PyObject *Program_find_type(Program *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	struct drgn_error *err;
	const char *name, *filename;
	PyObject *filename_obj = NULL;
	struct drgn_qualified_type qualified_type;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:type", keywords,
					 &name, filename_converter,
					 &filename_obj))
		return NULL;

	filename = filename_obj ? PyBytes_AS_STRING(filename_obj) : NULL;
	err = drgn_program_find_type(&self->prog, name, filename,
				     &qualified_type);
	Py_XDECREF(filename_obj);
	if (err) {
		set_drgn_error(err);
		return NULL;
	}
	return DrgnType_wrap(qualified_type, (PyObject *)self);
}

static DrgnObject *Program_find_object(Program *self, const char *name,
				       PyObject *filename_obj,
				       enum drgn_find_object_flags flags)
{
	struct drgn_error *err;
	const char *filename;
	DrgnObject *ret;

	ret = DrgnObject_alloc(self);
	if (!ret)
		return NULL;

	filename = filename_obj ? PyBytes_AS_STRING(filename_obj) : NULL;
	err = drgn_program_find_object(&self->prog, name, filename, flags,
				       &ret->obj);
	if (err) {
		set_drgn_error(err);
		Py_DECREF(ret);
		return NULL;
	}
	return ret;
}

static DrgnObject *Program_constant(Program *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	const char *name;
	PyObject *filename_obj = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:constant", keywords,
					 &name, filename_converter,
					 &filename_obj))
		return NULL;

	return Program_find_object(self, name, filename_obj,
				   DRGN_FIND_OBJECT_CONSTANT);
}

static DrgnObject *Program_function(Program *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	const char *name;
	PyObject *filename_obj = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:function", keywords,
					 &name, filename_converter,
					 &filename_obj))
		return NULL;

	return Program_find_object(self, name, filename_obj,
				   DRGN_FIND_OBJECT_FUNCTION);
}

static DrgnObject *Program_variable(Program *self, PyObject *args,
				    PyObject *kwds)
{
	static char *keywords[] = {"name", "filename", NULL};
	const char *name;
	PyObject *filename_obj = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|O&:variable", keywords,
					 &name, filename_converter,
					 &filename_obj))
		return NULL;

	return Program_find_object(self, name, filename_obj,
				   DRGN_FIND_OBJECT_VARIABLE);
}

static DrgnObject *Program_subscript(Program *self, PyObject *key)
{
	struct drgn_error *err;
	const char *name;
	DrgnObject *ret;

	if (!PyUnicode_Check(key)) {
		PyErr_SetObject(PyExc_KeyError, key);
		return NULL;
	}

	name = PyUnicode_AsUTF8(key);
	if (!name)
		return NULL;

	ret = DrgnObject_alloc(self);
	if (!ret)
		return NULL;

	err = drgn_program_find_object(&self->prog, name, NULL,
				       DRGN_FIND_OBJECT_ANY, &ret->obj);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			PyErr_SetObject(PyExc_KeyError, key);
		} else {
			set_drgn_error(err);
		}
		Py_DECREF(ret);
		return NULL;
	}
	return ret;
}

static PyObject *Program_get_flags(Program *self, void *arg)
{
	return PyObject_CallFunction(ProgramFlags_class, "k",
				     (unsigned long)self->prog.flags);
}

static PyObject *Program_get_word_size(Program *self, void *arg)
{
	return PyLong_FromUnsignedLong(drgn_program_word_size(&self->prog));
}

static PyObject *Program_get_byteorder(Program *self, void *arg)
{
	return byteorder_string(drgn_program_is_little_endian(&self->prog));
}

static PyMethodDef Program_methods[] = {
	{"__getitem__", (PyCFunction)Program_subscript, METH_O | METH_COEXIST,
"__getitem__(self, name) -> Object\n"
"\n"
"Implement self[name]. Return an Object (variable, constant, or function)\n"
"with the given name.\n"
"\n"
"If there are multiple objects with the same name, one is returned\n"
"arbitrarily. In this case, the constant(), function(), or variable()\n"
"methods can be used instead."},
	{"read", (PyCFunction)Program_read, METH_VARARGS | METH_KEYWORDS,
"read(self, address: int, size: int, physical: bool = False) -> bytes\n"
"\n"
"Return size bytes of memory starting at address in the program. The\n"
"address may be virtual (the default) or physical if the program supports\n"
"it.\n"
"\n"
">>> prog.read(0xffffffffbe012b40, 16)\n"
"b'swapper/0\\x00\\x00\\x00\\x00\\x00\\x00\\x00'"},
	{"type", (PyCFunction)Program_find_type, METH_VARARGS | METH_KEYWORDS,
"type(self, name: str, filename: Optional[str] = None) -> Type\n"
"\n"
"Return a Type object for the type with the given name.\n"
"\n"
"If there are multiple types with the given name, they can be\n"
"distinguished by passing the filename that the desired identifier was\n"
"defined in. If no filename is given, it is undefined which one is\n"
"returned.\n"
"\n"
"If no matches are found, this raises a LookupError.\n"
"\n"
">>> prog.type('long')\n"
"int_type(name='long', size=8, is_signed=True)"},
	{"constant", (PyCFunction)Program_constant,
	 METH_VARARGS | METH_KEYWORDS,
"constant(self, name: str, filename: Optional[str] = None) -> Object\n"
"\n"
"Return an Object representing the constant (e.g., enumeration constant\n"
"or macro) with the given name.\n"
"\n"
"If there are multiple constants with the given name, they can be\n"
"distinguished by passing the filename that the desired constant was\n"
"defined in. If no filename is given, it is undefined which one is\n"
"returned.\n"
"\n"
"If no matches are found, this raises a LookupError.\n"
"\n"
"Note that support for macro constants is not yet implemented for DWARF\n"
"files, and most compilers don't generate macro debugging information\n"
"by default anyways.\n"
"\n"
">>> prog.constant('PIDTYPE_MAX')\n"
"Object(prog, 'enum pid_type', value=4)"},
	{"function", (PyCFunction)Program_function,
	 METH_VARARGS | METH_KEYWORDS,
"function(self, name: str, filename: Optional[str] = None) -> Object\n"
"\n"
"Return an Object representing the function with the given name.\n"
"\n"
"If there are multiple functions with the given name, they can be\n"
"distinguished by passing the filename that the desired function was\n"
"defined in. If no filename is given, it is undefined which one is\n"
"returned.\n"
"\n"
"If no matches are found, this raises a LookupError.\n"
"\n"
">>> prog.function('schedule')\n"
"Object(prog, 'void (void)', address=0xffffffff94392370)"},
	{"variable", (PyCFunction)Program_variable,
	 METH_VARARGS | METH_KEYWORDS,
"variable(self, name: str, filename: Optional[str] = None) -> Object\n"
"\n"
"Return an Object representing the variable with the given name.\n"
"\n"
"If there are multiple variables with the given name, they can be\n"
"distinguished by passing the filename that the desired variable was\n"
"defined in. If no filename is given, it is undefined which one is\n"
"returned.\n"
"\n"
"If no matches are found, this raises a LookupError.\n"
"\n"
">>> prog.variable('jiffies')\n"
"Object(prog, 'volatile unsigned long', address=0xffffffff94c05000)"},
	{},
};

static PyGetSetDef Program_getset[] = {
	{"flags", (getter)Program_get_flags, NULL,
"ProgramFlags\n"
"\n"
"flags which apply to this program"},
	{"word_size", (getter)Program_get_word_size, NULL,
"int\n"
"\n"
"size of a word in this program in bytes"},
	{"byteorder", (getter)Program_get_byteorder, NULL,
"str\n"
"\n"
"byte order in this program (either 'little' or 'big')"},
	{},
};

static PyMappingMethods Program_as_mapping = {
	NULL,				/* mp_length */
	(binaryfunc)Program_subscript,	/* mp_subscript */
};

#define Program_DOC								\
"A Program represents a crashed or running program. It can be used to lookup\n"	\
"type definitions, access variables, and read arbitrary memory.\n"		\
"\n"										\
"The main functionality of a Program is looking up objects (i.e.,\n"		\
"variables, constants, or functions). This is done with the \"[]\"\n"		\
"operator.\n"									\
"\n"										\
">>> print(prog['pid_max'])\n"							\
"(int)32768\n"									\
"\n"										\
"A Program cannot be constructed directly. Instead, use\n"			\
"program_from_core_dump(), program_from_kernel(), or program_from_pid()."

PyTypeObject Program_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"_drgn.Program",			/* tp_name */
	sizeof(Program),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)Program_dealloc,		/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	NULL,					/* tp_repr */
	NULL,					/* tp_as_number */
	NULL,					/* tp_as_sequence */
	&Program_as_mapping,			/* tp_as_mapping */
	NULL,					/* tp_hash  */
	NULL,					/* tp_call */
	NULL,					/* tp_str */
	NULL,					/* tp_getattro */
	NULL,					/* tp_setattro */
	NULL,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,/* tp_flags */
	Program_DOC,				/* tp_doc */
	(traverseproc)Program_traverse,		/* tp_traverse */
	(inquiry)Program_clear,			/* tp_clear */
	NULL,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	Program_methods,			/* tp_methods */
	NULL,					/* tp_members */
	Program_getset,				/* tp_getset */
};

static int mock_get_address(PyObject *mock_obj, const char *name,
			    bool optional, uint64_t *ret)
{
	PyObject *addr_obj;

	addr_obj = PyObject_GetAttrString(mock_obj, name);
	if (!addr_obj)
		return -1;

	if (optional && addr_obj == Py_None) {
		*ret = UINT64_MAX;
	} else {
		unsigned long long addr;

		addr = PyLong_AsUnsignedLongLong(addr_obj);
		if (addr == (unsigned long long)-1 && PyErr_Occurred()) {
			Py_DECREF(addr_obj);
			return -1;
		}
		*ret = addr;
	}
	Py_DECREF(addr_obj);
	return 0;
}

static int mock_get_filename(Program *prog, PyObject *mock_obj,
			     const char **ret)
{
	PyObject *filename_obj;

	filename_obj = PyObject_GetAttrString(mock_obj, "filename");
	if (!filename_obj)
		return -1;
	if (filename_obj == Py_None) {
		Py_DECREF(filename_obj);
		*ret = NULL;
	} else {
		PyObject *encoded_obj;

		encoded_obj = PyUnicode_EncodeFSDefault(filename_obj);
		if (!encoded_obj) {
			Py_DECREF(filename_obj);
			return -1;
		}
		Py_DECREF(filename_obj);
		if (Program_hold_object(prog, encoded_obj) == -1) {
			Py_DECREF(encoded_obj);
			return -1;
		}
		*ret = PyBytes_AS_STRING(encoded_obj);
		Py_DECREF(encoded_obj);
	}
	return 0;
}

static int mock_get_bool(PyObject *mock_obj, const char *name, bool *ret)
{
	PyObject *bool_obj;
	int b;

	bool_obj = PyObject_GetAttrString(mock_obj, name);
	if (!bool_obj)
		return -1;
	b = PyObject_IsTrue(bool_obj);
	Py_DECREF(bool_obj);
	if (b == -1)
		return -1;
	*ret = b;
	return 0;
}

Program *mock_program(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {
		"word_size", "byteorder", "segments", "types", "variables",
		NULL,
	};
	struct drgn_error *err;
	unsigned char word_size;
	const char *byteorder;
	bool little_endian;
	PyObject *segments_obj = Py_None;
	PyObject *types_obj = Py_None;
	PyObject *objects_obj = Py_None;
	PyObject *segments_seq = NULL, *types_seq = NULL, *objects_seq = NULL;
	size_t num_segments = 0, num_types = 0, num_objects = 0;
	struct drgn_mock_memory_segment *segments = NULL;
	struct drgn_mock_type *types = NULL;
	struct drgn_mock_object *objects = NULL;
	Program *prog;
	size_t i;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "bs|OOO:mock_program",
					 keywords, &word_size, &byteorder,
					 &segments_obj, &types_obj,
					 &objects_obj))
		return NULL;

	if (parse_byteorder(byteorder, &little_endian) == -1)
		return NULL;

	prog = Program_alloc();
	if (!prog)
		return NULL;

	if (segments_obj != Py_None) {
		segments_seq = PySequence_Fast(segments_obj,
					       "segments must be sequence");
		if (!segments_seq)
			goto err;
		num_segments = PySequence_Fast_GET_SIZE(segments_seq);
		prog->buffers = calloc(num_segments, sizeof(*prog->buffers));
		if (!prog->buffers) {
			PyErr_NoMemory();
			goto err;
		}
		segments = calloc(num_segments, sizeof(*segments));
		if (!segments) {
			PyErr_NoMemory();
			goto err;
		}
		for (i = 0; i < num_segments; i++) {
			PyObject *segment_obj, *buf_obj;

			segment_obj = PySequence_Fast_GET_ITEM(segments_seq, i);

			buf_obj = PyObject_GetAttrString(segment_obj, "buf");
			if (!buf_obj)
				goto err;
			if (PyObject_GetBuffer(buf_obj, &prog->buffers[i],
					       PyBUF_SIMPLE) == -1) {
				Py_DECREF(buf_obj);
				goto err;
			}
			Py_DECREF(buf_obj);
			segments[i].buf = prog->buffers[i].buf;
			segments[i].size = prog->buffers[i].len;

			if (mock_get_address(segment_obj, "virt_addr", true,
					     &segments[i].virt_addr) == -1)
				goto err;

			if (mock_get_address(segment_obj, "phys_addr", true,
					     &segments[i].phys_addr) == -1)
				goto err;
		}
		Py_DECREF(segments_seq);
		segments_seq = NULL;
	}

	if (types_obj != Py_None) {
		types_seq = PySequence_Fast(types_obj,
					    "types must be sequence");
		if (!types_seq)
			goto err;
		num_types = PySequence_Fast_GET_SIZE(types_seq);
		types = calloc(num_types, sizeof(*types));
		if (!types) {
			PyErr_NoMemory();
			goto err;
		}
		for (i = 0; i < num_types; i++) {
			PyObject *type_obj, *tmp;

			type_obj = PySequence_Fast_GET_ITEM(types_seq, i);

			tmp = PyObject_GetAttrString(type_obj, "type");
			if (!tmp)
				goto err;
			if (!PyObject_TypeCheck(tmp, &DrgnType_type)) {
				PyErr_SetString(PyExc_TypeError,
						"mock type must be Type");
				Py_DECREF(tmp);
				goto err;
			}
			if (((DrgnType *)tmp)->qualifiers) {
				Py_DECREF(tmp);
				PyErr_SetString(PyExc_ValueError,
						"mock type must be unqualified");
				goto err;
			}
			if (Program_hold_object(prog, tmp) == -1) {
				Py_DECREF(tmp);
				goto err;
			}
			types[i].type = ((DrgnType *)tmp)->type;
			Py_DECREF(tmp);

			if (mock_get_filename(prog, type_obj,
					      &types[i].filename) == -1)
				goto err;
		}
		Py_DECREF(types_seq);
		types_seq = NULL;
	}

	if (objects_obj != Py_None) {
		objects_seq = PySequence_Fast(objects_obj, "objects must be sequence");
		if (!objects_seq)
			goto err;
		num_objects = PySequence_Fast_GET_SIZE(objects_seq);
		objects = calloc(num_objects, sizeof(*objects));
		if (!objects) {
			PyErr_NoMemory();
			goto err;
		}
		for (i = 0; i < num_objects; i++) {
			PyObject *object_obj, *tmp;

			object_obj = PySequence_Fast_GET_ITEM(objects_seq, i);

			tmp = PyObject_GetAttrString(object_obj, "type");
			if (!tmp)
				goto err;
			if (!PyObject_TypeCheck(tmp, &DrgnType_type)) {
				PyErr_SetString(PyExc_TypeError,
						"mock object type must be Type");
				Py_DECREF(tmp);
				goto err;
			}
			if (Program_hold_type(prog, (DrgnType *)tmp) == -1) {
				Py_DECREF(tmp);
				goto err;
			}
			objects[i].qualified_type.type =
				((DrgnType *)tmp)->type;
			objects[i].qualified_type.qualifiers =
				((DrgnType *)tmp)->qualifiers;
			Py_DECREF(tmp);

			tmp = PyObject_GetAttrString(object_obj, "name");
			if (!tmp)
				goto err;
			objects[i].name = PyUnicode_AsUTF8(tmp);
			if (!objects[i].name) {
				Py_DECREF(tmp);
				goto err;
			}
			if (Program_hold_object(prog, tmp) == -1) {
				Py_DECREF(tmp);
				goto err;
			}
			Py_DECREF(tmp);

			if (mock_get_filename(prog, object_obj,
					      &objects[i].filename) == -1)
				goto err;

			if (mock_get_bool(object_obj, "is_enumerator",
					  &objects[i].is_enumerator) == -1)
				goto err;

			if (objects[i].is_enumerator)
				continue;

			tmp = PyObject_GetAttrString(object_obj, "byteorder");
			if (tmp) {
				enum drgn_byte_order byte_order;

				if (parse_optional_byteorder(tmp,
							     &byte_order) == -1) {
					Py_DECREF(tmp);
					goto err;
				}
				if (byte_order == DRGN_PROGRAM_ENDIAN) {
					objects[i].little_endian =
						little_endian;
				} else {
					objects[i].little_endian =
						byte_order == DRGN_LITTLE_ENDIAN;
				}
				Py_DECREF(tmp);
			} else if (PyErr_ExceptionMatches(PyExc_AttributeError)) {
				PyErr_Clear();
			} else {
				goto err;
			}
			if (mock_get_address(object_obj, "address", false,
					     &objects[i].address) == -1)
				goto err;
		}
		Py_DECREF(objects_seq);
		objects_seq = NULL;
	}

	err = drgn_program_init_mock(&prog->prog, word_size, little_endian,
				     segments, num_segments, types, num_types,
				     objects, num_objects, mock_program_deinit);
	if (err) {
		set_drgn_error(err);
		goto err;
	}
	prog->inited = true;
	return prog;

err:
	for (i = 0; i < num_segments; i++)
		PyBuffer_Release(&prog->buffers[i]);
	free(objects);
	free(types);
	free(segments);
	free(prog->buffers);
	Py_XDECREF(objects_seq);
	Py_XDECREF(types_seq);
	Py_XDECREF(segments_seq);
	Py_DECREF(prog);
	return NULL;
}

Program *program_from_core_dump(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"path", "verbose", NULL};
	struct drgn_error *err;
	PyObject *path_obj;
	int verbose = 0;
	Program *prog;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&|p:program_from_core_dump",
					 keywords, PyUnicode_FSConverter,
					 &path_obj, &verbose))
		return NULL;

	prog = Program_alloc();
	if (!prog) {
		Py_DECREF(path_obj);
		return NULL;
	}

	err = drgn_program_init_core_dump(&prog->prog,
					  PyBytes_AS_STRING(path_obj), verbose);
	Py_DECREF(path_obj);
	if (err) {
		Py_DECREF(prog);
		set_drgn_error(err);
		return NULL;
	}
	prog->inited = true;
	return prog;
}

Program *program_from_kernel(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"verbose", NULL};
	struct drgn_error *err;
	int verbose = 0;
	Program *prog;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|p:program_from_kernel",
					 keywords, &verbose))
		return NULL;

	prog = Program_alloc();
	if (!prog)
		return NULL;

	err = drgn_program_init_kernel(&prog->prog, verbose);
	if (err) {
		Py_DECREF(prog);
		set_drgn_error(err);
		return NULL;
	}
	prog->inited = true;
	return prog;
}

Program *program_from_pid(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"pid", NULL};
	struct drgn_error *err;
	int pid;
	Program *prog;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:program_from_pid",
					 keywords, &pid))
		return NULL;

	prog = Program_alloc();
	if (!prog)
		return NULL;

	err = drgn_program_init_pid(&prog->prog, pid);
	if (err) {
		Py_DECREF(prog);
		set_drgn_error(err);
		return NULL;
	}
	prog->inited = true;
	return prog;
}
