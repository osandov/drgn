#include "lldwarf.h"
#include "dwarfdefs.h"

static int DwarfDie_AttribFromObject(struct DwarfAttrib *attrib, PyObject *object)
{
	PyObject *value;
	Py_buffer buffer;
	Py_ssize_t len;

	switch (attrib->form) {
	case DW_FORM_addr:
	case DW_FORM_udata:
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_ref_sig8:
	case DW_FORM_sec_offset:
	case DW_FORM_strp:
		attrib->u = PyLong_AsUint64_t(object);
		if (PyErr_Occurred())
			return -1;
		return 0;
	case DW_FORM_sdata:
		attrib->s = PyLong_AsInt64_t(object);
		if (PyErr_Occurred())
			return -1;
		return 0;
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_block:
	case DW_FORM_exprloc:
	case DW_FORM_string:
		value = PySequence_Tuple(object);
		if (!value)
			return -1;

		if (PyTuple_GET_SIZE(value) != 2) {
			PyErr_SetString(PyExc_ValueError, "attribute value must be pair");
			Py_DECREF(value);
			return -1;
		}

		attrib->offset = PyLong_AsSsize_t(PyTuple_GET_ITEM(value, 0));
		if (PyErr_Occurred()) {
			if (PyErr_ExceptionMatches(PyExc_OverflowError))
				PyErr_SetString(PyExc_OverflowError, "offset too big");
			Py_DECREF(value);
			return -1;
		}
		attrib->length = PyLong_AsSsize_t(PyTuple_GET_ITEM(value, 1));
		if (PyErr_Occurred()) {
			if (PyErr_ExceptionMatches(PyExc_OverflowError))
				PyErr_SetString(PyExc_OverflowError, "length too big");
			Py_DECREF(value);
			return -1;
		}
		Py_DECREF(value);
		return 0;
	case DW_FORM_data1:
		len = 1;
		goto data;
	case DW_FORM_data2:
		len = 2;
		goto data;
	case DW_FORM_data4:
		len = 4;
		goto data;
	case DW_FORM_data8:
		len = 8;
data:
		if (PyObject_GetBuffer(object, &buffer, PyBUF_SIMPLE) == -1)
			return -1;
		if (buffer.len != len) {
			PyErr_Format(PyExc_ValueError, "DW_FORM_data%zd buffer must have length %zd",
				     len, len);
			PyBuffer_Release(&buffer);
			return -1;
		}
		memcpy(attrib->data, buffer.buf, len);
		PyBuffer_Release(&buffer);
		return 0;
	case DW_FORM_flag:
		attrib->u = PyObject_IsTrue(object);
		return 0;
	case DW_FORM_flag_present:
		attrib->u = 1;
		return 0;
	default:
		PyErr_Format(PyExc_ValueError, "unknown form %llu",
			     attrib->form);
		return -1;
	}
}

static PyObject *DwarfDie_new(PyTypeObject *subtype, PyObject *args,
			      PyObject *kwds)
{
	static char *keywords[] = {
		"offset", "die_length", "tag", "children", "attributes", NULL
	};
	PyObject *offset;
	PyObject *die_length;
	PyObject *tag;
	PyObject *children, *attribs;
	PyObject *tmp = NULL;
	DwarfDie *die = NULL;
	Py_ssize_t i, len;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOOOO:DwarfDie", keywords,
					 &offset, &die_length, &tag, &children,
					 &attribs))
		return NULL;

	tmp = PySequence_Tuple(attribs);
	if (!tmp)
		goto err;

	len = PyTuple_GET_SIZE(tmp);
	die = (DwarfDie *)subtype->tp_alloc(subtype, len);
	if (!die)
		goto err;
	die->offset = PyLong_AsSsize_t(offset);
	if (PyErr_Occurred()) {
		if (PyErr_ExceptionMatches(PyExc_OverflowError))
			PyErr_SetString(PyExc_OverflowError, "offset too big");
		goto err;
	}
	die->die_length = PyLong_AsSsize_t(die_length);
	if (PyErr_Occurred()) {
		if (PyErr_ExceptionMatches(PyExc_OverflowError))
			PyErr_SetString(PyExc_OverflowError, "die_length too big");
		goto err;
	}
	die->tag = PyLong_AsUint64_t(tag);
	if (PyErr_Occurred()) {
		if (PyErr_ExceptionMatches(PyExc_OverflowError))
			PyErr_SetString(PyExc_OverflowError, "tag too big");
		goto err;
	}
	if (children == Py_None) {
		Py_INCREF(Py_None);
		die->children = Py_None;
	} else {
		die->children = PySequence_List(children);
		if (!die->children)
			goto err;
	}
	memset(die->attribs, 0, len * sizeof(die->attribs[0]));

	for (i = 0; i < len; i++) {
		PyObject *item;

		item = PySequence_Tuple(PyTuple_GET_ITEM(tmp, i));
		if (!item)
			goto err;

		if (PyTuple_GET_SIZE(item) != 3) {
			PyErr_SetString(PyExc_ValueError, "attribute must be triple");
			Py_DECREF(item);
			goto err;
		}

		die->attribs[i].name = PyLong_AsUint64_t(PyTuple_GET_ITEM(item, 0));
		if (PyErr_Occurred()) {
			if (PyErr_ExceptionMatches(PyExc_OverflowError))
				PyErr_SetString(PyExc_OverflowError, "name too big");
			Py_DECREF(item);
			goto err;
		}
		die->attribs[i].form = PyLong_AsUint64_t(PyTuple_GET_ITEM(item, 1));
		if (PyErr_Occurred()) {
			if (PyErr_ExceptionMatches(PyExc_OverflowError))
				PyErr_SetString(PyExc_OverflowError, "form too big");
			Py_DECREF(item);
			goto err;
		}
		if (DwarfDie_AttribFromObject(&die->attribs[i],
					      PyTuple_GET_ITEM(item, 2)) == -1) {
			Py_DECREF(item);
			goto err;
		}
		Py_DECREF(item);
	}

	Py_DECREF(tmp);

	return (PyObject *)die;

err:
	Py_XDECREF(die);
	Py_XDECREF(tmp);
	return NULL;
}

static void DwarfDie_dealloc(DwarfDie *self)
{
	Py_XDECREF(self->children);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int DwarfDie_traverse(DwarfDie *self, visitproc visit, void *arg)
{
	Py_VISIT(self->children);
	return 0;
}

static PyObject *DwarfDie_repr(DwarfDie *self)
{
	PyObject *tmp, *ret = NULL;
	int enter;

	enter = Py_ReprEnter((PyObject *)self);
	if (enter == -1)
		return NULL;
	if (enter)
		return PyUnicode_FromString("DwarfDie(...)");

	tmp = PySequence_Tuple((PyObject *)self);
	if (!tmp)
		goto out;

	/* XXX: children = NULL? */
	ret = PyUnicode_FromFormat("DwarfDie(offset=%zd, die_length=%zd, tag=%llu, children=%R, attributes=%R)",
				   self->offset, self->die_length,
				   (unsigned long long)self->tag,
				   self->children, tmp);

out:
	Py_XDECREF(tmp);
	Py_ReprLeave((PyObject *)self);
	return ret;
}

static PyObject *DwarfDie_richcompare(DwarfDie *self, PyObject *other_, int op)
{
	DwarfDie *other;
	int cmp;

	if (op != Py_EQ && op != Py_NE) {
		PyErr_SetString(PyExc_TypeError, "not supported");
		return NULL;
	}

	cmp = LLDwarfObject_RichCompareBool((PyObject *)self, other_, Py_EQ);
	if (cmp == -1)
		return NULL;
	else if (!cmp)
		goto out;

	other = (DwarfDie *)other_;

	cmp = (Py_SIZE(self) == Py_SIZE(other) &&
	       !memcmp(self->attribs, other->attribs,
		       Py_SIZE(self) * sizeof(struct DwarfAttrib)));

out:
	if (op == Py_NE)
		cmp = !cmp;
	if (cmp)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

static Py_ssize_t DwarfDie_length(DwarfDie *self)
{
	return Py_SIZE(self);
}

static PyObject *DwarfDie_ObjectFromAttrib(struct DwarfAttrib *attrib)
{
	switch (attrib->form) {
	case DW_FORM_addr:
	case DW_FORM_udata:
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_ref_sig8:
	case DW_FORM_sec_offset:
	case DW_FORM_strp:
		return PyLong_FromUnsignedLongLong(attrib->u);
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	case DW_FORM_block:
	case DW_FORM_exprloc:
	case DW_FORM_string:
		return Py_BuildValue("nn", attrib->offset, attrib->length);
	case DW_FORM_data1:
		return PyBytes_FromStringAndSize(attrib->data, 1);
	case DW_FORM_data2:
		return PyBytes_FromStringAndSize(attrib->data, 2);
	case DW_FORM_data4:
		return PyBytes_FromStringAndSize(attrib->data, 4);
	case DW_FORM_data8:
		return PyBytes_FromStringAndSize(attrib->data, 8);
	case DW_FORM_sdata:
		return PyLong_FromLongLong(attrib->s);
	case DW_FORM_flag:
		return PyBool_FromLong(attrib->u ? 1 : 0);
	case DW_FORM_flag_present:
		Py_RETURN_TRUE;
	default:
		PyErr_Format(PyExc_ValueError, "unknown form %llu",
			     attrib->form);
		return NULL;
	}
}

static PyObject *DwarfDie_item(DwarfDie *self, Py_ssize_t i)
{
	struct DwarfAttrib *attrib;
	PyObject *value, *ret;

	if (i < 0 || i >= Py_SIZE(self)) {
		PyErr_SetString(PyExc_IndexError, "index out of range");
		return NULL;
	}

	attrib = &self->attribs[i];

	value = DwarfDie_ObjectFromAttrib(attrib);
	if (!value)
		return NULL;

	ret = Py_BuildValue("KKO", (unsigned long long)attrib->name,
			    (unsigned long long)attrib->form, value);
	Py_DECREF(value);
	return ret;
}

static PyObject *DwarfDie_find(DwarfDie *self, PyObject *args, PyObject *kwds)
{
	static char *keywords[] = {"name", NULL};
	struct DwarfAttrib *attrib;
	PyObject *value, *ret;
	PyObject *name_obj;
	uint64_t name;
	Py_ssize_t i, len;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O:find", keywords,
					 &name_obj))
		return NULL;

	name = PyLong_AsUint64_t(name_obj);
	if (!name)
		return NULL;

	len = Py_SIZE(self);
	for (i = 0; i < len; i++) {
		if (self->attribs[i].name == name)
			break;
	}
	if (i == len) {
		PyErr_SetString(PyExc_KeyError, "no attribute with that name");
		return NULL;
	}

	attrib = &self->attribs[i];

	value = DwarfDie_ObjectFromAttrib(attrib);
	if (!value)
		return NULL;

	ret = Py_BuildValue("KO", (unsigned long long)attrib->form, value);
	Py_DECREF(value);
	return ret;
}

static AbbrevDecl *get_decl(PyObject *abbrev_table, uint64_t code)
{
	PyObject *key;
	PyObject *value;

	key = PyLong_FromUnsignedLongLong(code);
	if (!key)
		return NULL;

	value = PyObject_GetItem(abbrev_table, key);
	Py_DECREF(key);
	if (!value) {
		PyErr_Format(PyExc_ValueError, "unknown abbreviation code %llu\n",
			     (unsigned long long)code);
	}
	return (AbbrevDecl *)value;
}

static int LLDwarf_ParseAttrib(Py_buffer *buffer, Py_ssize_t *offset,
			       CompilationUnitHeader *cu,
			       struct DwarfAttrib *attrib)
{
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64;

	switch (attrib->form) {
	/* address */
	case DW_FORM_addr:
		switch (cu->address_size) {
		case 4:
			if (read_u32(buffer, offset, &u32) == -1)
				return -1;
			attrib->u = u32;
			return 0;
		case 8:
			return read_u64(buffer, offset, &attrib->u);
		default:
			PyErr_Format(PyExc_ValueError, "unsupported address size %u",
				     (unsigned int)cu->address_size);
			return -1;
		}
	/* block */
	case DW_FORM_block1:
		if (read_u8(buffer, offset, &u8) == -1)
			return -1;
		attrib->length = u8;
		goto block;
	case DW_FORM_block2:
		if (read_u16(buffer, offset, &u16) == -1)
			return -1;
		attrib->length = u16;
		goto block;
	case DW_FORM_block4:
		if (read_u32(buffer, offset, &u32) == -1)
			return -1;
		attrib->length = u32;
		goto block;
	case DW_FORM_block:
	/* exprloc */
	case DW_FORM_exprloc:
		if (read_uleb128(buffer, offset, &u64) == -1)
			return -1;
		if (u64 > PY_SSIZE_T_MAX) {
			PyErr_SetString(PyExc_ValueError, "attribute length too big");
			return -1;
		}
		attrib->length = u64;
block:
		if (read_check_bounds(buffer, *offset, attrib->length) == -1)
			return -1;
		attrib->offset = *offset;
		*offset += attrib->length;
		return 0;
	/* constant */
	case DW_FORM_data1:
		return read_buffer(buffer, offset, &attrib->data, 1);
	case DW_FORM_data2:
		return read_buffer(buffer, offset, &attrib->data, 2);
	case DW_FORM_data4:
		return read_buffer(buffer, offset, &attrib->data, 4);
	case DW_FORM_data8:
		return read_buffer(buffer, offset, &attrib->data, 8);
	case DW_FORM_sdata:
		return read_sleb128(buffer, offset, &attrib->s);
	case DW_FORM_udata:
	 /* reference */
	case DW_FORM_ref_udata:
		return read_uleb128(buffer, offset, &attrib->u);
	case DW_FORM_ref_addr:
        /* lineptr, loclistptr, macptr, rangelistptr */
	case DW_FORM_sec_offset:
	/* string */
	case DW_FORM_strp:
		if (cu->is_64_bit) {
			return read_u64(buffer, offset, &attrib->u);
		} else {
			if (read_u32(buffer, offset, &u32) == -1)
				return -1;
			attrib->u = u32;
			return 0;
		}
	case DW_FORM_string:
		attrib->offset = *offset;
		if (read_strlen(buffer, offset, &attrib->length) == -1)
			return -1;
		return 0;
	 /* flag */
	case DW_FORM_flag_present:
		attrib->u = 1;
		return 0;
	case DW_FORM_flag:
	/* reference */
	case DW_FORM_ref1:
		if (read_u8(buffer, offset, &u8) == -1)
			return -1;
		attrib->u = u8;
		return 0;
	case DW_FORM_ref2:
		if (read_u16(buffer, offset, &u16) == -1)
			return -1;
		attrib->u = u16;
		return 0;
	case DW_FORM_ref4:
		if (read_u32(buffer, offset, &u32) == -1)
			return -1;
		attrib->u = u32;
		return 0;
	case DW_FORM_ref8:
	case DW_FORM_ref_sig8:
		return read_u64(buffer, offset, &attrib->u);
	case DW_FORM_indirect:
		PyErr_Format(PyExc_ValueError, "DW_FORM_indirect is not supported");
		return -1;
	default:
		PyErr_Format(PyExc_ValueError, "unknown form 0x%llu",
			     attrib->form);
		return -1;
	}
}

PyObject *LLDwarf_ParseDieSiblings(Py_buffer *buffer, Py_ssize_t *offset,
				   CompilationUnitHeader *cu,
				   PyObject *abbrev_table, bool recurse)
{
	PyObject *children;

	children = PyList_New(0);
	if (!children)
		return NULL;

	for (;;) {
		PyObject *child;

		child = LLDwarf_ParseDie(buffer, offset, cu, abbrev_table,
					 recurse, true);
		if (PyErr_Occurred())
			goto err;
		if (!child)
			break;
		if (PyList_Append(children, child) == -1) {
			Py_DECREF(child);
			goto err;
		}
		Py_DECREF(child);
	}

	return children;

err:
	Py_DECREF(children);
	return NULL;
}

PyObject *LLDwarf_ParseDie(Py_buffer *buffer, Py_ssize_t *offset,
			   CompilationUnitHeader *cu, PyObject *abbrev_table,
			   bool recurse, bool jump_to_sibling)
{
	Py_ssize_t orig_offset;
	DwarfDie *die;
	AbbrevDecl *decl;
	uint64_t code;
	Py_ssize_t i, len;
	uint64_t sibling = 0;

	orig_offset = *offset;

	if (read_uleb128(buffer, offset, &code) == -1) {
		if (PyErr_ExceptionMatches(PyExc_EOFError)) {
			PyErr_SetString(PyExc_ValueError,
					"DIE abbreviation code is truncated");
		}
		return NULL;
	}

	if (code == 0)
		return NULL;

	decl = get_decl(abbrev_table, code);
	if (!decl)
		return NULL;
	len = Py_SIZE(decl);

	die = PyObject_NewVar(DwarfDie, &DwarfDie_type, len);
	if (!die) {
		Py_DECREF(decl);
		return NULL;
	}
	die->offset = orig_offset;
	die->tag = decl->tag;
	die->children = NULL;
	memset(die->attribs, 0, len * sizeof(die->attribs[0]));

	for (i = 0; i < len; i++) {
		die->attribs[i].name = decl->attribs[i].name;
		die->attribs[i].form = decl->attribs[i].form;
		if (LLDwarf_ParseAttrib(buffer, offset, cu, &die->attribs[i]) == -1)
			goto err;
		if (die->attribs[i].name == DW_AT_sibling)
			sibling = die->attribs[i].u;
	}

	die->die_length = *offset - orig_offset;

	if (!decl->children) {
		Py_INCREF(Py_None);
		die->children = Py_None;
	} else if (recurse || (jump_to_sibling && !sibling)) {
		die->children = LLDwarf_ParseDieSiblings(buffer, offset, cu,
							 abbrev_table, true);
		if (!die->children)
			goto err;
	} else if (jump_to_sibling) {
		*offset = cu->offset + sibling;
	}

	Py_DECREF(decl);
	return (PyObject *)die;

err:
	Py_DECREF(die);
	Py_DECREF(decl);
	return NULL;
}

static PySequenceMethods DwarfDie_as_sequence = {
	(lenfunc)DwarfDie_length,	/* sq_length */
	NULL,				/* sq_concat */
	NULL,				/* sq_repeat */
	(ssizeargfunc)DwarfDie_item,	/* sq_item */
};

static PyMethodDef DwarfDie_methods[] = {
	{"find", (PyCFunction)DwarfDie_find, METH_VARARGS | METH_KEYWORDS,
	 "find(name) -> (form, value)\n\n"
	 "Find an attribute.\n\n"
	 "Arguments:\n"
	 "name -- attribute name (DW_AT_*)"},
	{},
};

static PyMemberDef DwarfDie_members[] = {
	{"offset", T_UINT64T, offsetof(DwarfDie, offset), 0,
	 "offset into the buffer where this DIE starts"},
	{"die_length", T_UINT64T, offsetof(DwarfDie, die_length), 0,
	 "length of this DIE"},
	{"tag", T_UINT64T, offsetof(DwarfDie, tag), 0,
	 "this DIE's tag (DW_TAG_*)"},
	{"children", T_OBJECT_EX, offsetof(DwarfDie, children), 0,
	 "list of this DIE's children, or None; this attribute may be\n"
	 "missing if the DIE was parsed non-recursively"},
	{},
};

#define DwarfDie_DOC	\
	"DwarfDie(offset, die_length, tag, children, attribs) -> new debugging information entry\n\n"	\
	"Create a new DWARF debugging information entry. len(die) is the\n"		\
	"number of attributes and die[i] is the ith attribute.\n\n"			\
	"Arguments:\n"									\
	"offset -- integer offset\n"							\
	"die_length -- intger length\n"							\
	"tag -- integer tag of the DIE\n"						\
	"children -- list of children DIEs\n"						\
	"attribs -- iterable of (name, form, value) triples"

PyTypeObject DwarfDie_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.lldwarf.DwarfDie",	/* tp_name */
	sizeof(DwarfDie),		/* tp_basicsize */
	sizeof(struct DwarfAttrib),	/* tp_itemsize */
	(destructor)DwarfDie_dealloc,	/* tp_dealloc */
	NULL,				/* tp_print */
	NULL,				/* tp_getattr */
	NULL,				/* tp_setattr */
	NULL,				/* tp_as_async */
	(reprfunc)DwarfDie_repr,	/* tp_repr */
	NULL,				/* tp_as_number */
	&DwarfDie_as_sequence,		/* tp_as_sequence */
	NULL,				/* tp_as_mapping */
	NULL,				/* tp_hash  */
	NULL,				/* tp_call */
	NULL,				/* tp_str */
	NULL,				/* tp_getattro */
	NULL,				/* tp_setattro */
	NULL,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */
	DwarfDie_DOC,			/* tp_doc */
	(traverseproc)DwarfDie_traverse,	/* tp_traverse */
	NULL,				/* tp_clear */
	(richcmpfunc)DwarfDie_richcompare,	/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	NULL,				/* tp_iter */
	NULL,				/* tp_iternext */
	DwarfDie_methods,		/* tp_methods */
	DwarfDie_members,		/* tp_members */
	NULL,				/* tp_getset */
	NULL,				/* tp_base */
	NULL,				/* tp_dict */
	NULL,				/* tp_descr_get */
	NULL,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	NULL,				/* tp_init */
	NULL,				/* tp_alloc */
	(newfunc)DwarfDie_new,		/* tp_new */
};
