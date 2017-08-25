#include "lldwarf.h"

static const char *type_name(PyTypeObject *type)
{
	const char *p;

	p = strrchr(type->tp_name, '.');
	if (p)
		return p + 1;
	else
		return type->tp_name;
}

#define CONVERTARG(self, member, var)	\
	*(typeof(var) *)((char *)(self) + (member)->offset) = (var);

static int convertarg(PyObject *self, PyMemberDef *member, PyObject *arg)
{
	switch (member->type) {
	case T_SHORT:
	{
		short tmp = PyLong_AsShort(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_INT:
	{
		int tmp = PyLong_AsInt(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_LONG:
	{
		long tmp = PyLong_AsLong(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_FLOAT:
		PyErr_SetString(PyExc_NotImplementedError,
				"T_FLOAT init not implemented");
		return -1;
	case T_DOUBLE:
		PyErr_SetString(PyExc_NotImplementedError,
				"T_DOUBLE init not implemented");
		return -1;
	case T_STRING:
		PyErr_SetString(PyExc_NotImplementedError,
				"T_STRING init not implemented");
		return -1;
	case T_OBJECT:
	case T_OBJECT_EX:
		Py_INCREF(arg);
		CONVERTARG(self, member, arg);
		return 0;
	case T_CHAR:
	{
		Py_UCS4 tmp;

		if (!PyUnicode_Check(arg) || PyUnicode_READY(arg) == -1)
			return -1;
		if (PyUnicode_GET_LENGTH(arg) != 1) {
			PyErr_SetString(PyExc_ValueError,
					"expected a character");
			return -1;
		}
		tmp = PyUnicode_READ_CHAR(arg, 0);
		if (tmp > 0x7f) {
			PyErr_SetString(PyExc_ValueError,
					"character out of range");
			return -1;
		}
		*((char *)self + member->offset) = tmp;
		return 0;
	}
	case T_BYTE:
	{
		char tmp = PyLong_AsChar(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_UBYTE:
	{
		unsigned char tmp = PyLong_AsUnsignedChar(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_UINT:
	{
		unsigned int tmp = PyLong_AsUnsignedInt(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_USHORT:
	{
		unsigned short tmp = PyLong_AsUnsignedShort(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_ULONG:
	{
		unsigned long tmp = PyLong_AsUnsignedLong(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_BOOL:
	{
		bool tmp = PyObject_IsTrue(arg);
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_LONGLONG:
	{
		long long tmp = PyLong_AsLongLong(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_ULONGLONG:
	{
		unsigned long long tmp = PyLong_AsUnsignedLongLong(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	case T_PYSSIZET:
	{
		Py_ssize_t tmp = PyLong_AsSsize_t(arg);
		if (PyErr_Occurred())
			return -1;
		CONVERTARG(self, member, tmp);
		return 0;
	}
	default:
		PyErr_Format(PyExc_NotImplementedError, "member type %d not implemented",
			     member->type);
		return -1;
	}
}

int LLDwarfObject_init(PyObject *self, PyObject *args, PyObject *kwds)
{
	PyTypeObject *type = (PyTypeObject *)Py_TYPE(self);
	Py_ssize_t nmembers, nargs, nkwargs, i;

	if (!PyTuple_Check(args))
		return -1;

	if (kwds && !PyDict_Check(kwds))
		return -1;

	if (kwds && !PyArg_ValidateKeywordArguments(kwds))
		return -1;

	nmembers = 0;
	while (type->tp_members[nmembers].name)
		nmembers++;

	nargs = PyTuple_GET_SIZE(args);
	nkwargs = kwds ? PyDict_Size(kwds) : 0;
	if (nargs + nkwargs > nmembers) {
		PyErr_Format(PyExc_TypeError, "%s() takes at most %zd argument%s (%zd given)",
			     type_name(type), nmembers,
			     nmembers == 1 ? "" : "s", nargs + nkwargs);
		return -1;
	}

	for (i = 0; i < nmembers; i++) {
		PyMemberDef *member = &type->tp_members[i];
		PyObject *arg;

		if (i < nargs) {
			arg = PyTuple_GET_ITEM(args, i);
		} else if (nkwargs) {
			arg = PyDict_GetItemString(kwds, member->name);
			if (arg)
				nkwargs--;
		} else {
			arg = NULL;
		}

		if (!arg) {
                    PyErr_Format(PyExc_TypeError, "Required argument '%s' (pos %d) not found",
				 member->name, i + 1);
		    return -1;
		}

		if (convertarg(self, member, arg) == -1)
			return -1;
	}

	return 0;
}

#define MEMBER(self, member, type)	\
	*(type *)((char *)(self) + (member)->offset)

static PyObject *repr_member(PyObject *self, PyMemberDef *member)
{
	PyObject *object;

	switch (member->type) {
	case T_SHORT:
		return PyUnicode_FromFormat("%s=%d", member->name,
					    (int)MEMBER(self, member, short));
	case T_INT:
		return PyUnicode_FromFormat("%s=%d", member->name,
					    MEMBER(self, member, int));
	case T_LONG:
		return PyUnicode_FromFormat("%s=%ld", member->name,
					    MEMBER(self, member, long));
	case T_FLOAT:
		PyErr_SetString(PyExc_NotImplementedError,
				"T_FLOAT repr not implemented");
		return NULL;
	case T_DOUBLE:
		PyErr_SetString(PyExc_NotImplementedError,
				"T_DOUBLE repr not implemented");
		return NULL;
	case T_STRING:
		PyErr_SetString(PyExc_NotImplementedError,
				"T_STRING repr not implemented");
		return NULL;
	case T_OBJECT:
	case T_OBJECT_EX:
		object = MEMBER(self, member, PyObject *);
		if (object) {
			return PyUnicode_FromFormat("%s=%R", member->name,
						    object);
		} else {
			return PyUnicode_FromFormat("%s=None", member->name);
		}
	case T_CHAR:
	{
		PyObject *tmp, *ret;

		tmp = PyUnicode_FromStringAndSize((char *)self + member->offset,
						  1);
		if (!tmp)
			return NULL;

		ret = PyUnicode_FromFormat("%s=%R", member->name, tmp);
		Py_DECREF(tmp);
		return ret;
	}
	case T_BYTE:
		return PyUnicode_FromFormat("%s=%d", member->name,
					    (int)MEMBER(self, member, char));
	case T_UBYTE:
		return PyUnicode_FromFormat("%s=%u", member->name,
					    (unsigned int)MEMBER(self, member, unsigned char));
	case T_UINT:
		return PyUnicode_FromFormat("%s=%u", member->name,
					    MEMBER(self, member, unsigned int));
	case T_USHORT:
		return PyUnicode_FromFormat("%s=%u", member->name,
					    (unsigned int)MEMBER(self, member, unsigned short));
	case T_ULONG:
		return PyUnicode_FromFormat("%s=%lu", member->name,
					    MEMBER(self, member, unsigned long));
	case T_BOOL:
		if (MEMBER(self, member, char))
			return PyUnicode_FromFormat("%s=True", member->name);
		else
			return PyUnicode_FromFormat("%s=False", member->name);
	case T_LONGLONG:
		return PyUnicode_FromFormat("%s=%lld", member->name,
					    MEMBER(self, member, long long));
	case T_ULONGLONG:
		return PyUnicode_FromFormat("%s=%llu", member->name,
					    MEMBER(self, member, unsigned long long));
	case T_PYSSIZET:
		return PyUnicode_FromFormat("%s=%zd", member->name,
					    MEMBER(self, member, Py_ssize_t));
	default:
		PyErr_Format(PyExc_ValueError, "unknown member type %d",
			     member->type);
		return NULL;
	}
}

PyObject *LLDwarfObject_repr(PyObject *self)
{
	PyTypeObject *type = (PyTypeObject *)Py_TYPE(self);
	PyObject *strs, *ret = NULL, *tmp, *sep;
	Py_ssize_t nmembers, i;
	int enter;

	enter = Py_ReprEnter(self);
	if (enter == -1)
		return NULL;
	else if (enter)
		return PyUnicode_FromFormat("%s(...)", type_name(type));

	nmembers = 0;
	while (type->tp_members[nmembers].name)
		nmembers++;

	strs = PyTuple_New(nmembers);
	if (!strs)
		goto out;

	for (i = 0; i < nmembers; i++) {
		tmp = repr_member(self, &type->tp_members[i]);
		if (!tmp) {
			Py_DECREF(strs);
			goto out;
		}
		PyTuple_SET_ITEM(strs, i, tmp);
	}

	sep = PyUnicode_FromString(", ");
	if (!sep) {
		Py_DECREF(strs);
		goto out;
	}

	tmp = PyUnicode_Join(sep, strs);
	Py_DECREF(strs);
	Py_DECREF(sep);
	if (!tmp)
		goto out;

	ret = PyUnicode_FromFormat("%s(%S)", type_name(type), tmp);
	Py_DECREF(tmp);

out:
	Py_ReprLeave(self);
	return ret;
}

static int member_cmp(PyObject *self, PyObject *other, PyMemberDef *member)
{
	PyObject *self_obj, *other_obj;
	size_t size;

	switch (member->type) {
	case T_SHORT:
		size = sizeof(short);
		break;
	case T_INT:
		size = sizeof(int);
		break;
	case T_LONG:
		size = sizeof(long);
		break;
	case T_FLOAT:
		size = sizeof(float);
		break;
	case T_DOUBLE:
		size = sizeof(double);
		break;
	case T_STRING:
		size = sizeof(char *);
		break;
	case T_OBJECT:
	case T_OBJECT_EX:
		self_obj = MEMBER(self, member, PyObject *);
		other_obj = MEMBER(other, member, PyObject *);
		if (!self_obj || !other_obj)
			return !self_obj && !other_obj;
		return PyObject_RichCompareBool(self_obj, other_obj, Py_EQ);
	case T_CHAR:
	case T_BYTE:
	case T_BOOL:
		size = sizeof(char);
		break;
	case T_UBYTE:
		size = sizeof(unsigned char);
		break;
	case T_UINT:
		size = sizeof(unsigned int);
		break;
	case T_USHORT:
		size = sizeof(unsigned short);
		break;
	case T_ULONG:
		size = sizeof(unsigned long);
	case T_LONGLONG:
		size = sizeof(long long);
		break;
	case T_ULONGLONG:
		size = sizeof(unsigned long long);
		break;
	case T_PYSSIZET:
		size = sizeof(Py_ssize_t);
		break;
	default:
		PyErr_Format(PyExc_ValueError, "unknown member type %d",
			     member->type);
		return -1;
	}

	return !memcmp((char *)self + member->offset,
		       (char *)other + member->offset, size);
}

int LLDwarfObject_RichCompareBool(PyObject *self, PyObject *other, int op)
{
	PyTypeObject *type = (PyTypeObject *)Py_TYPE(self);
	Py_ssize_t nmembers, i;
	int cmp;

	if (op != Py_EQ && op != Py_NE) {
		PyErr_SetString(PyExc_TypeError, "not supported");
		return -1;
	}

	cmp = PyObject_IsInstance(other, (PyObject *)type);
	if (cmp == -1)
		return -1;
	if (!cmp)
		goto out;

	nmembers = 0;
	while (type->tp_members[nmembers].name)
		nmembers++;

	for (i = 0; i < nmembers; i++) {
		cmp = member_cmp(self, other, &type->tp_members[i]);
		if (cmp == -1)
			return -1;
		if (!cmp)
			goto out;
	}

out:
	if (op == Py_NE)
		cmp = !cmp;
	return cmp;
}

PyObject *LLDwarfObject_richcompare(PyObject *self, PyObject *other, int op)
{
	int cmp;

	cmp = LLDwarfObject_RichCompareBool(self, other, op);
	if (cmp == -1)
		return NULL;
	else if (cmp)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

#ifdef TEST_LLDWARFOBJECT
typedef struct {
	PyObject_HEAD
	short m_short;
	int m_int;
	long m_long;
	/* float m_float; */
	/* double m_double; */
	/* char *m_string; */
	PyObject *m_object;
	PyObject *m_object_ex;
	char m_char;
	char m_byte;
	unsigned char m_ubyte;
	unsigned int m_uint;
	unsigned short m_ushort;
	unsigned long m_ulong;
	char m_bool;
	long long m_longlong;
	unsigned long long m_ulonglong;
	Py_ssize_t m_pyssizet;
} TestObject;

static void TestObject_dealloc(TestObject *self)
{
	Py_XDECREF(self->m_object);
	Py_XDECREF(self->m_object_ex);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int TestObject_traverse(TestObject *self, visitproc visit, void *arg)
{
	Py_VISIT(self->m_object);
	Py_VISIT(self->m_object_ex);
	return 0;
}

static PyMemberDef TestObject_members[] = {
	{"m_short", T_SHORT, offsetof(TestObject, m_short), 0, ""},
	{"m_int", T_INT, offsetof(TestObject, m_int), 0, ""},
	{"m_long", T_LONG, offsetof(TestObject, m_long), 0, ""},
	/* {"m_float", T_FLOAT, offsetof(TestObject, m_float), 0, ""}, */
	/* {"m_double", T_DOUBLE, offsetof(TestObject, m_double), 0, ""}, */
	/* {"m_string", T_STRING, offsetof(TestObject, m_string), 0, ""}, */
	{"m_object", T_OBJECT, offsetof(TestObject, m_object), 0, ""},
	{"m_object_ex", T_OBJECT_EX, offsetof(TestObject, m_object_ex), 0, ""},
	{"m_char", T_CHAR, offsetof(TestObject, m_char), 0, ""},
	{"m_byte", T_BYTE, offsetof(TestObject, m_byte), 0, ""},
	{"m_ubyte", T_UBYTE, offsetof(TestObject, m_ubyte), 0, ""},
	{"m_uint", T_UINT, offsetof(TestObject, m_uint), 0, ""},
	{"m_ushort", T_USHORT, offsetof(TestObject, m_ushort), 0, ""},
	{"m_ulong", T_ULONG, offsetof(TestObject, m_ulong), 0, ""},
	{"m_bool", T_BOOL, offsetof(TestObject, m_bool), 0, ""},
	{"m_longlong", T_LONGLONG, offsetof(TestObject, m_longlong), 0, ""},
	{"m_ulonglong", T_ULONGLONG, offsetof(TestObject, m_ulonglong), 0, ""},
	{"m_pyssizet", T_PYSSIZET, offsetof(TestObject, m_pyssizet), 0, ""},
	{},
};

PyTypeObject TestObject_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"drgn.lldwarf._TestObject",		/* tp_name */
	sizeof(TestObject),			/* tp_basicsize */
	0,					/* tp_itemsize */
	(destructor)TestObject_dealloc,		/* tp_dealloc */
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
	"Test object",				/* tp_doc */
	(traverseproc)TestObject_traverse,	/* tp_traverse */
	NULL,					/* tp_clear */
	LLDwarfObject_richcompare,		/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	NULL,					/* tp_iter */
	NULL,					/* tp_iternext */
	NULL,					/* tp_methods */
	TestObject_members,			/* tp_members */
	NULL,					/* tp_getset */
	NULL,					/* tp_base */
	NULL,					/* tp_dict */
	NULL,					/* tp_descr_get */
	NULL,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	LLDwarfObject_init,			/* tp_init */
};
#endif /* TEST_LLDWARFOBJECT */
