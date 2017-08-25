#include "lldwarf.h"

static void CompilationUnitHeader_dealloc(CompilationUnitHeader *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

PyObject *CompilationUnitHeader_die_offset(CompilationUnitHeader *self)
{
	Py_ssize_t header_length = self->is_64_bit ? 23 : 11;
	Py_ssize_t ret;

	if (__builtin_add_overflow(self->offset, header_length, &ret)) {
		PyErr_SetString(PyExc_OverflowError, "DIE offset too large");
		return NULL;
	}

	return PyLong_FromSsize_t(ret);
}

PyObject *CompilationUnitHeader_next_offset(CompilationUnitHeader *self)
{
	uint64_t unit_length_length = self->is_64_bit ? 12 : 4;
	uint64_t unit_length;
	Py_ssize_t ret;

	if (__builtin_add_overflow(self->unit_length, unit_length_length, &unit_length) ||
	    __builtin_add_overflow(self->offset, unit_length, &ret)) {
		PyErr_SetString(PyExc_OverflowError, "next offset too large");
		return NULL;
	}

	return PyLong_FromSsize_t(ret);
}

PyObject *LLDwarf_ParseCompilationUnitHeader(Py_buffer *buffer,
					     Py_ssize_t *offset)
{
	CompilationUnitHeader *cu;
	uint32_t length;

	cu = PyObject_New(CompilationUnitHeader, &CompilationUnitHeader_type);
	if (!cu)
		return NULL;

	cu->offset = *offset;

	if (read_u32(buffer, offset, &length) == -1)
		goto err;

	cu->is_64_bit = length == UINT32_C(0xffffffff);
	if (cu->is_64_bit) {
		if (read_u64(buffer, offset, &cu->unit_length) == -1)
			goto err;
	} else {
		cu->unit_length = length;
	}

	if (read_u16(buffer, offset, &cu->version) == -1)
		goto err;

	if (cu->is_64_bit) {
		if (read_u64(buffer, offset, &cu->debug_abbrev_offset) == -1)
			goto err;
	} else {
		unsigned int debug_abbrev_offset;

		if (read_u32(buffer, offset, &debug_abbrev_offset) == -1)
			goto err;
		cu->debug_abbrev_offset = debug_abbrev_offset;
	}

	if (read_u8(buffer, offset, &cu->address_size) == -1)
		goto err;

	return (PyObject *)cu;

err:
	PyErr_SetString(PyExc_ValueError,
			"compilation unit header is truncated");
	Py_DECREF(cu);
	return NULL;
}

static PyMethodDef CompilationUnitHeader_methods[] = {
	{"die_offset", (PyCFunction)CompilationUnitHeader_die_offset,
	 METH_NOARGS,
	 "die_offset() -> int\n\n"
	 "Get the offset into the buffer where the DIE for this CU begins. This\n"
	 "is the starting offset of the CU plus the length of the header."},
	{"next_offset", (PyCFunction)CompilationUnitHeader_next_offset,
	 METH_NOARGS,
	 "next_offset() -> int\n\n"
	 "Get the offset into the buffer where the next CU starts. This\n"
	 "is the starting offset of the CU plus the length of the unit,\n"
	 "including the header. If this is the last CU, this offset is the\n"
	 "end of the .debug_info section."},
	{},
};

static PyMemberDef CompilationUnitHeader_members[] = {
	{"offset", T_PYSSIZET, offsetof(CompilationUnitHeader, offset), 0,
	 "offset into the buffer where this CU starts"},
	{"unit_length", T_UINT64T, offsetof(CompilationUnitHeader, unit_length), 0,
	 "length of this CU, not including the unit_length field"},
	{"version", T_UINT16T, offsetof(CompilationUnitHeader, version), 0,
	 "format version of this CU"},
	{"debug_abbrev_offset", T_UINT64T, offsetof(CompilationUnitHeader, debug_abbrev_offset), 0,
	 "location of this CU's abbreviation table as an offset into the .debug_abbrev section"},
	{"address_size", T_UINT8T, offsetof(CompilationUnitHeader, address_size), 0,
	 "size of an address in this CU"},
	{"is_64_bit", T_BOOL, offsetof(CompilationUnitHeader, is_64_bit), 0,
	 "whether this CU is using the 64-bit format"},
	{},
};

#define CompilationUnitHeader_DOC						\
	"CompilationUnitHeader(offset, unit_length, version,\n"			\
	"                      debug_abbrev_offset, address_size,\n"		\
        "                      is_64_bit) -> new compilation unit header\n\n"	\
	"Create a new DWARF compilation unit header.\n\n"			\
	"Arguments:\n"								\
	"offset -- integer offset\n"						\
	"unit_length -- integer length\n"					\
	"version -- integer format version\n"					\
	"debug_abbrev_offset -- integer offset\n"				\
	"address_size -- integer size\n"					\
	"is_64_bit -- boolean"

PyTypeObject CompilationUnitHeader_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.lldwarf.CompilationUnitHeader",	/* tp_name */
	sizeof(CompilationUnitHeader),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)CompilationUnitHeader_dealloc,	/* tp_dealloc */
	NULL,					/* tp_print */
	NULL,					/* tp_getattr */
	NULL,					/* tp_setattr */
	NULL,					/* tp_as_async */
	LLDwarfObject_repr,			/* tp_repr */
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
	CompilationUnitHeader_DOC,		/* tp_doc */
	NULL,					/* tp_traverse */
	NULL,					/* tp_clear */
	LLDwarfObject_richcompare,		/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	CompilationUnitHeader_methods,		/* tp_methods */
	CompilationUnitHeader_members,		/* tp_members */
	NULL,					/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	LLDwarfObject_init,			/* tp_init */
};
