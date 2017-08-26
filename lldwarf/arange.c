#include "lldwarf.h"

static void ArangeTableHeader_dealloc(ArangeTableHeader *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

PyObject *ArangeTableHeader_table_offset(ArangeTableHeader *self)
{
	uint64_t header_length = self->is_64_bit ? 24 : 12;
	Py_ssize_t ret, alignment;

	if (__builtin_add_overflow(self->offset, header_length, &ret)) {
		PyErr_SetString(PyExc_OverflowError, "table offset too large");
		return NULL;
	}

	alignment = self->segment_size + 2 * self->address_size;
	if (ret % alignment &&
	    __builtin_add_overflow(ret, alignment - ret % alignment, &ret)) {
		PyErr_SetString(PyExc_OverflowError, "table offset too large");
		return NULL;
	}

	return PyLong_FromSsize_t(ret);
}

PyObject *ArangeTableHeader_next_offset(ArangeTableHeader *self)
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

PyObject *LLDwarf_ParseArangeTableHeader(Py_buffer *buffer, Py_ssize_t *offset)
{
	ArangeTableHeader *art;
	uint32_t length;

	art = PyObject_New(ArangeTableHeader, &ArangeTableHeader_type);
	if (!art)
		return NULL;

	art->offset = *offset;

	if (read_u32(buffer, offset, &length) == -1)
		goto err;

	art->is_64_bit = length == UINT32_C(0xffffffff);
	if (art->is_64_bit) {
		if (read_u64(buffer, offset, &art->unit_length) == -1)
			goto err;
	} else {
		art->unit_length = length;
	}

	if (read_u16(buffer, offset, &art->version) == -1)
		goto err;

	if (art->is_64_bit) {
		if (read_u64(buffer, offset, &art->debug_info_offset) == -1)
			goto err;
	} else {
		unsigned int debug_info_offset;

		if (read_u32(buffer, offset, &debug_info_offset) == -1)
			goto err;
		art->debug_info_offset = debug_info_offset;
	}

	if (read_u8(buffer, offset, &art->address_size) == -1)
		goto err;

	if (read_u8(buffer, offset, &art->segment_size) == -1)
		goto err;

	return (PyObject *)art;

err:
	PyErr_SetString(PyExc_ValueError,
			"address range table header is truncated");
	Py_DECREF(art);
	return NULL;
}

static PyMethodDef ArangeTableHeader_methods[] = {
	{"table_offset", (PyCFunction)ArangeTableHeader_table_offset,
	 METH_NOARGS,
	 "table_offset() -> int\n\n"
	 "Get the offset into the buffer where the address range table itself\n"
	 "begins. This is the starting offset of the arange table header plus\n"
	 "the length of the header, aligned up to a multiple of the address\n"
	 "range tuple size."},
	{"next_offset", (PyCFunction)ArangeTableHeader_next_offset,
	 METH_NOARGS,
	 "next_offset() -> int\n\n"
	 "Get the offset into the buffer where the next address range table\n"
	 "starts. This is the starting offset of the CU plus the length of\n"
	 "the unit, including the header. If this is the last address range\n"
	 "table, this offset is the end of the .debug_aranges section."},
	{},
};

static PyMemberDef ArangeTableHeader_members[] = {
	{"offset", T_PYSSIZET, offsetof(ArangeTableHeader, offset), 0,
	 "offset into the buffer where this arange table starts"},
	{"unit_length", T_UINT64T, offsetof(ArangeTableHeader, unit_length), 0,
	 "length of this arange table, not including the unit_length field"},
	{"version", T_UINT16T, offsetof(ArangeTableHeader, version), 0,
	 "format version of this arange table"},
	{"debug_info_offset", T_UINT64T, offsetof(ArangeTableHeader, debug_info_offset), 0,
	 "location of this arange table's compilation unit as an offset into the .debug_info section"},
	{"address_size", T_UINT8T, offsetof(ArangeTableHeader, address_size), 0,
	 "size of an address in this arange table"},
	{"segment_size", T_UINT8T, offsetof(ArangeTableHeader, segment_size), 0,
	 "size of a segment selector in this arange table"},
	{"is_64_bit", T_BOOL, offsetof(ArangeTableHeader, is_64_bit), 0,
	 "whether this CU is using the 64-bit format"},
	{},
};

#define ArangeTableHeader_DOC							\
	"ArangeTableHeader(offset, unit_length, version, debug_info_offset,\n"	\
	"                  address_size, segment_size,\n"			\
	"                  is_64_bit) -> new address range table header\n\n"	\
	"Create a new DWARF address range table header.\n\n"			\
	"Arguments:\n"								\
	"offset -- integer offset\n"						\
	"unit_length -- integer length\n"					\
	"version -- integer format version\n"					\
	"debug_info_offset -- integer offset\n"					\
	"address_size -- integer size\n"					\
	"segment_size -- integer size\n"					\
	"is_64_bit -- boolean"

PyTypeObject ArangeTableHeader_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.lldwarf.ArangeTableHeader",	/* tp_name */
	sizeof(ArangeTableHeader),		/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)ArangeTableHeader_dealloc,	/* tp_dealloc */
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
	ArangeTableHeader_DOC,			/* tp_doc */
	NULL,					/* tp_traverse */
	NULL,					/* tp_clear */
	LLDwarfObject_richcompare,		/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	ArangeTableHeader_methods,		/* tp_methods */
	ArangeTableHeader_members,		/* tp_members */
	NULL,					/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	LLDwarfObject_init,			/* tp_init */
};

static void AddressRange_dealloc(AddressRange *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

PyObject *LLDwarf_ParseArangeTable(Py_buffer *buffer, Py_ssize_t *offset,
				   Py_ssize_t segment_size,
				   Py_ssize_t address_size)
{
	PyObject *arange_table;

	arange_table = PyList_New(0);
	if (!arange_table)
		return NULL;

	for (;;) {
		AddressRange *arange;
		uint64_t segment, address, length;
		uint32_t tmp;
		int ret;

		switch (segment_size) {
		case 4:
			if (read_u32(buffer, offset, &tmp) == -1)
				goto err;
			segment = tmp;
			break;
		case 8:
			if (read_u64(buffer, offset, &segment) == -1)
				goto err;
			break;
		case 0:
			segment = 0;
			break;
		default:
			PyErr_Format(PyExc_ValueError, "unsupported segment size %ld",
				     (long)segment_size);
			goto err;
		}

		switch (address_size) {
		case 4:
			if (read_u32(buffer, offset, &tmp) == -1)
				goto err;
			address = tmp;
			if (read_u32(buffer, offset, &tmp) == -1)
				goto err;
			length = tmp;
			break;
		case 8:
			if (read_u64(buffer, offset, &address) == -1)
				goto err;
			if (read_u64(buffer, offset, &length) == -1)
				goto err;
			break;
		default:
			PyErr_Format(PyExc_ValueError, "unsupported address size %ld",
				     (long)address_size);
			goto err;
		}

		if (segment == 0 && address == 0 && length == 0)
			break;

		arange = PyMem_Malloc(sizeof(AddressRange));
		if (!arange)
			goto err;
		PyObject_Init((PyObject *)arange, &AddressRange_type);
		arange->segment = segment;
		arange->address = address;
		arange->length = length;

		ret = PyList_Append(arange_table, (PyObject *)arange);
		Py_DECREF((PyObject *)arange);
		if (ret == -1)
			goto err;
	}

	return arange_table;

err:
	Py_DECREF(arange_table);
	return NULL;
}

static PyMemberDef AddressRange_members[] = {
	{"segment", T_UINT64T, offsetof(AddressRange, segment), 0,
	 "segment selector of the address range"},
	{"address", T_UINT64T, offsetof(AddressRange, address), 0,
	 "starting address of the address range"},
	{"length", T_UINT64T, offsetof(AddressRange, length), 0,
	 "length of the address range"},
	{},
};

#define AddressRange_DOC							\
	"AddressRange(segment, address, length) -> new address range\n"		\
	"Create a new address range.\n\n"					\
	"Arguments:\n"								\
	"segment -- integer segment selector\n"					\
	"address -- integer start address\n"					\
	"length -- integer range length\n"

PyTypeObject AddressRange_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.lldwarf.AddressRange",		/* tp_name */
	sizeof(AddressRange),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)AddressRange_dealloc,	/* tp_dealloc */
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
	AddressRange_DOC,			/* tp_doc */
	NULL,					/* tp_traverse */
	NULL,					/* tp_clear */
	LLDwarfObject_richcompare,		/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	NULL,					/* tp_methods */
	AddressRange_members,			/* tp_members */
	NULL,					/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	LLDwarfObject_init,			/* tp_init */
};
