#include "lldwarf.h"
#include "dwarfdefs.h"

static PyObject *AbbrevDecl_new(PyTypeObject *subtype, PyObject *args,
				PyObject *kwds)
{
	static char *keywords[] = {"tag", "children", "attributes", NULL};
	PyObject *tag;
	int children;
	PyObject *attribs;
	PyObject *tmp = NULL;
	AbbrevDecl *decl = NULL;
	Py_ssize_t i, len;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OpO:AbbrevDecl", keywords,
					 &tag, &children, &attribs))
		return NULL;

	tmp = PySequence_Tuple(attribs);
	if (!tmp)
		goto err;

	len = PyTuple_GET_SIZE(tmp);
	decl = (AbbrevDecl *)subtype->tp_alloc(subtype, len);
	if (!decl)
		goto err;
	decl->tag = PyLong_AsUint64_t(tag);
	if (PyErr_Occurred()) {
		PyErr_SetString(PyExc_OverflowError, "tag too big");
		goto err;
	}
	decl->children = children;

	for (i = 0; i < len; i++) {
		PyObject *item;

		item = PySequence_Tuple(PyTuple_GET_ITEM(tmp, i));
		if (!item)
			goto err;

		if (PyTuple_GET_SIZE(item) != 2) {
			PyErr_SetString(PyExc_ValueError, "attribute must be pair");
			Py_DECREF(item);
			goto err;
		}

		decl->attribs[i].name = PyLong_AsUint64_t(PyTuple_GET_ITEM(item, 0));
		if (PyErr_Occurred()) {
			if (PyErr_ExceptionMatches(PyExc_OverflowError))
				PyErr_SetString(PyExc_OverflowError, "name too big");
			Py_DECREF(item);
			goto err;
		}
		decl->attribs[i].form = PyLong_AsUint64_t(PyTuple_GET_ITEM(item, 1));
		if (PyErr_Occurred()) {
			if (PyErr_ExceptionMatches(PyExc_OverflowError))
				PyErr_SetString(PyExc_OverflowError, "form too big");
			Py_DECREF(item);
			goto err;
		}
		Py_DECREF(item);
	}

	Py_DECREF(tmp);

	return (PyObject *)decl;

err:
	Py_XDECREF(decl);
	Py_XDECREF(tmp);
	return NULL;
}

static void AbbrevDecl_dealloc(AbbrevDecl *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *AbbrevDecl_repr(AbbrevDecl *self)
{
	PyObject *tmp, *ret;
	Py_ssize_t i, len;

	len = Py_SIZE(self);
	tmp = PyTuple_New(len);
	if (!tmp)
		return NULL;

	for (i = 0; i < len; i++) {
		PyObject *item;

		item = Py_BuildValue("KK",
				     (unsigned long long)self->attribs[i].name,
				     (unsigned long long)self->attribs[i].form);
		if (!item) {
			Py_DECREF(tmp);
			return NULL;
		}

		PyTuple_SET_ITEM(tmp, i, item);
	}

	ret = PyUnicode_FromFormat("AbbrevDecl(tag=%llu, children=%s, attributes=%R)",
				   self->tag, self->children ? "True" : "False",
				   tmp);
	Py_DECREF(tmp);
	return ret;
}

static PyObject *AbbrevDecl_richcompare(AbbrevDecl *self, PyObject *other_, int op)
{
	AbbrevDecl *other;
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

	other = (AbbrevDecl *)other_;

	cmp = (Py_SIZE(self) == Py_SIZE(other) &&
	       !memcmp(self->attribs, other->attribs,
		       Py_SIZE(self) * sizeof(struct AttribSpec)));

out:
	if (op == Py_NE)
		cmp = !cmp;
	if (cmp)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

static Py_ssize_t AbbrevDecl_length(AbbrevDecl *self)
{
	return Py_SIZE(self);
}

static PyObject *AbbrevDecl_item(AbbrevDecl *self, Py_ssize_t i)
{
	if (i < 0 || i >= Py_SIZE(self)) {
		PyErr_SetString(PyExc_IndexError, "index out of range");
		return NULL;
	}

	return Py_BuildValue("KK", (unsigned long long)self->attribs[i].name,
			     (unsigned long long)self->attribs[i].form);
}

static int AbbrevDecl_Realloc(AbbrevDecl **decl, size_t capacity)
{
	AbbrevDecl *tmp;
	size_t specsize, size;

	if (__builtin_mul_overflow(capacity, sizeof(struct AttribSpec), &specsize) ||
	    __builtin_add_overflow(sizeof(AbbrevDecl), specsize, &size)) {
		PyErr_NoMemory();
		return -1;
	}

	tmp = PyMem_Realloc(*decl, size);
	if (!tmp) {
		PyErr_NoMemory();
		return -1;
	}

	*decl = tmp;
	return 0;
}

static PyObject *LLDwarf_ParseAbbrevDecl(Py_buffer *buffer, Py_ssize_t *offset,
					 uint64_t *code)
{
	AbbrevDecl *decl = NULL;
	uint8_t children;
	size_t num = 0, capacity = 1;

	if (read_uleb128(buffer, offset, code) == -1) {
		if (PyErr_ExceptionMatches(PyExc_EOFError)) {
			PyErr_SetString(PyExc_ValueError,
					"abbreviation declaration code is truncated");
		}
		return NULL;
	}

	if (*code == 0)
		return NULL;

	if (AbbrevDecl_Realloc(&decl, capacity) == -1)
		return NULL;

	if (read_uleb128(buffer, offset, &decl->tag) == -1) {
		if (PyErr_ExceptionMatches(PyExc_EOFError)) {
			PyErr_SetString(PyExc_ValueError,
					"abbreviation declaration tag is truncated");
		}
		goto err;
	}

	if (read_u8(buffer, offset, &children)) {
		PyErr_SetString(PyExc_ValueError,
				"abbreviation declaration children flag is truncated");
		goto err;
	}
	decl->children = children != DW_CHILDREN_no;

	for (;;) {
		uint64_t name, form;

		if (read_uleb128(buffer, offset, &name) == -1) {
			if (PyErr_ExceptionMatches(PyExc_EOFError)) {
				PyErr_SetString(PyExc_ValueError,
						"abbreviation specification name is truncated");
			}
			goto err;
		}
		if (read_uleb128(buffer, offset, &form) == -1) {
			if (PyErr_ExceptionMatches(PyExc_EOFError)) {
				PyErr_SetString(PyExc_ValueError,
						"abbreviation specification form is truncated");
			}
			goto err;
		}
		if (name == 0 && form == 0)
			break;

		if (num >= capacity) {
			capacity *= 2;
			if (AbbrevDecl_Realloc(&decl, capacity) == -1)
				goto err;
		}

		decl->attribs[num].name = name;
		decl->attribs[num].form = form;
		num++;
	}

	if (AbbrevDecl_Realloc(&decl, num) == -1)
		goto err;
	return (PyObject *)PyObject_InitVar((PyVarObject *)decl,
					    &AbbrevDecl_type, num);

err:
	PyMem_Free(decl);
	return NULL;
}

PyObject *LLDwarf_ParseAbbrevTable(Py_buffer *buffer, Py_ssize_t *offset)
{
	PyObject *table;

	table = PyDict_New();
	if (!table)
		return NULL;

	for (;;) {
		PyObject *key, *value;
		uint64_t code;

		value = LLDwarf_ParseAbbrevDecl(buffer, offset, &code);
		if (!value) {
			if (PyErr_Occurred())
				goto err;
			else
				break;
		}

		key = PyLong_FromUnsignedLongLong(code);
		if (key == NULL) {
			Py_DECREF(value);
			goto err;
		}

		if (PyDict_GetItem(table, key) != NULL) {
			Py_DECREF(key);
			Py_DECREF(value);
			PyErr_Format(PyExc_ValueError, "duplicate abbreviation code %llu\n",
				     (unsigned long long)code);
			goto err;
		}

		if (PyDict_SetItem(table, key, value) == -1) {
			Py_DECREF(key);
			Py_DECREF(value);
			goto err;
		}

		Py_DECREF(value);
	}

	return table;

err:
	Py_DECREF(table);
	return NULL;
}

static PySequenceMethods AbbrevDecl_as_sequence = {
	(lenfunc)AbbrevDecl_length,	/* sq_length */
	NULL,				/* sq_concat */
	NULL,				/* sq_repeat */
	(ssizeargfunc)AbbrevDecl_item,	/* sq_item */
};

static PyMemberDef AbbrevDecl_members[] = {
	{"tag", T_UINT64T, offsetof(AbbrevDecl, tag), 0,
	 "tag of this entry (DW_TAG_*)"},
	{"children", T_BOOL, offsetof(AbbrevDecl, children), 0,
	 "whether this entry has child entries"},
	{},
};

#define AbbrevDecl_DOC	\
	"AbbrevDecl(tag, children, attribs) -> new abbreviation declaration\n\n"	\
	"Create a new DWARF abbreviation declaration. len(decl) is the number of\n"	\
	"attributes and decl[i] is the ith attribute specification.\n\n"		\
	"Arguments:\n"									\
	"tag -- integer tag of the abbreviation declaration\n"				\
	"children -- boolean specifying whether this entry has child entries\n"	\
	"attribs -- iterable of (name, form) pairs"

PyTypeObject AbbrevDecl_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.lldwarf.AbbrevDecl",	/* tp_name */
	sizeof(AbbrevDecl),		/* tp_basicsize */
	sizeof(struct AttribSpec),	/* tp_itemsize */
	(destructor)AbbrevDecl_dealloc,	/* tp_dealloc */
	NULL,				/* tp_print */
	NULL,				/* tp_getattr */
	NULL,				/* tp_setattr */
	NULL,				/* tp_as_async */
	(reprfunc)AbbrevDecl_repr,	/* tp_repr */
	NULL,				/* tp_as_number */
	&AbbrevDecl_as_sequence,	/* tp_as_sequence */
	NULL,				/* tp_as_mapping */
	NULL,				/* tp_hash  */
	NULL,				/* tp_call */
	NULL,				/* tp_str */
	NULL,				/* tp_getattro */
	NULL,				/* tp_setattro */
	NULL,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */
	AbbrevDecl_DOC,			/* tp_doc */
	NULL,				/* tp_traverse */
	NULL,				/* tp_clear */
	(richcmpfunc)AbbrevDecl_richcompare,	/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	NULL,				/* tp_iter */
	NULL,				/* tp_iternext */
	NULL,				/* tp_methods */
	AbbrevDecl_members,		/* tp_members */
	NULL,				/* tp_getset */
	NULL,				/* tp_base */
	NULL,				/* tp_dict */
	NULL,				/* tp_descr_get */
	NULL,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	NULL,				/* tp_init */
	NULL,				/* tp_alloc */
	(newfunc)AbbrevDecl_new,	/* tp_new */
};
