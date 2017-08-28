#include "lldwarf.h"

PyObject *LLDwarf_ParseRangeList(Py_buffer *buffer, Py_ssize_t *offset,
				 Py_ssize_t address_size)
{
	PyObject *ranges;

	ranges = PyList_New(0);
	if (!ranges)
		return NULL;

	for (;;) {
		Range *range;
		uint64_t start, end;
		uint32_t tmp;
		int ret;

		switch (address_size) {
		case 4:
			if (read_u32(buffer, offset, &tmp) == -1)
				goto err;
			if (tmp == UINT32_C(0xffffffff))
				start = UINT64_C(0xffffffffffffffff);
			else
				start = tmp;
			if (read_u32(buffer, offset, &tmp) == -1)
				goto err;
			end = tmp;
			break;
		case 8:
			if (read_u64(buffer, offset, &start) == -1)
				goto err;
			if (read_u64(buffer, offset, &end) == -1)
				goto err;
			break;
		default:
			PyErr_Format(PyExc_ValueError, "unsupported address size %ld",
				     (long)address_size);
			goto err;
		}

		if (start == 0 && end == 0)
			break;

		range = PyObject_New(Range, &Range_type);
		if (!range)
			goto err;
		range->start = start;
		range->end = end;

		ret = PyList_Append(ranges, (PyObject *)range);
		Py_DECREF((PyObject *)range);
		if (ret == -1)
			goto err;
	}

	return ranges;

err:
	Py_DECREF(ranges);
	return NULL;
}

static PyMemberDef Range_members[] = {
	{"start", T_UINT64T, offsetof(Range, start), 0,
	 "starting address (inclusive) of the range"},
	{"end", T_UINT64T, offsetof(Range, end), 0,
	 "ending address (exclusive) of the range"},
	{},
};

#define Range_DOC					\
	"Range(address, length) -> new address range\n"	\
	"Create a new address range.\n\n"		\
	"Arguments:\n"					\
	"start -- integer start address\n"		\
	"end -- integer end address\n"

PyTypeObject Range_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.lldwarf.Range",		/* tp_name */
	sizeof(Range),			/* tp_basicsize */
	0,				/* tp_itemsize */
	LLDwarfObject_dealloc,		/* tp_dealloc */
	NULL,				/* tp_print */
	NULL,				/* tp_getattr */
	NULL,				/* tp_setattr */
	NULL,				/* tp_as_async */
	LLDwarfObject_repr,		/* tp_repr */
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
	Range_DOC,			/* tp_doc */
	NULL,				/* tp_traverse */
	NULL,				/* tp_clear */
	LLDwarfObject_richcompare,	/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	NULL,				/* tp_iter */
	NULL,				/* tp_iternext */
	NULL,				/* tp_methods */
	Range_members,			/* tp_members */
	NULL,				/* tp_getset */
	NULL,				/* tp_base */
	NULL,				/* tp_dict */
	NULL,				/* tp_descr_get */
	NULL,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	LLDwarfObject_init,		/* tp_init */
};
