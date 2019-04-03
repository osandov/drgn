// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

static PyObject *FaultError;
static PyObject *FileFormatError;

DRGNPY_PUBLIC PyObject *set_drgn_error(struct drgn_error *err)
{
	if (err == DRGN_ERROR_PYTHON)
		return NULL;

	switch (err->code) {
	case DRGN_ERROR_NO_MEMORY:
		PyErr_NoMemory();
		break;
	case DRGN_ERROR_INVALID_ARGUMENT:
		PyErr_SetString(PyExc_ValueError, err->message);
		break;
	case DRGN_ERROR_OVERFLOW:
		PyErr_SetString(PyExc_OverflowError, err->message);
		break;
	case DRGN_ERROR_RECURSION:
		PyErr_SetString(PyExc_RecursionError, err->message);
		break;
	case DRGN_ERROR_OS:
		errno = err->errnum;
		PyErr_SetFromErrnoWithFilename(PyExc_OSError, err->path);
		break;
	case DRGN_ERROR_ELF_FORMAT:
	case DRGN_ERROR_DWARF_FORMAT:
	case DRGN_ERROR_MISSING_DEBUG:
		PyErr_SetString(FileFormatError, err->message);
		break;
	case DRGN_ERROR_SYNTAX:
		PyErr_SetString(PyExc_SyntaxError, err->message);
		break;
	case DRGN_ERROR_LOOKUP:
		PyErr_SetString(PyExc_LookupError, err->message);
		break;
	case DRGN_ERROR_FAULT:
		PyErr_SetString(FaultError, err->message);
		break;
	case DRGN_ERROR_TYPE:
		PyErr_SetString(PyExc_TypeError, err->message);
		break;
	case DRGN_ERROR_ZERO_DIVISION:
		PyErr_SetString(PyExc_ZeroDivisionError, err->message);
		break;
	default:
		PyErr_SetString(PyExc_Exception, err->message);
		break;
	}

	drgn_error_destroy(err);
	return NULL;
}

static PyMethodDef drgn_methods[] = {
	{"cast", (PyCFunction)cast, METH_VARARGS | METH_KEYWORDS,
"cast(type: Union[str, Type], obj: Object) -> Object\n"
"\n"
"Return the value of the given object casted to another type.\n"
"\n"
"Objects with a scalar type (integer, boolean, enumerated,\n"
"floating-point, or pointer) can be casted to a different scalar type.\n"
"Other objects can only be casted to the same type. This always results\n"
"in a value object. See also reinterpret()."},
	{"reinterpret", (PyCFunction)reinterpret, METH_VARARGS | METH_KEYWORDS,
"reinterpret(type: Union[str, Type], obj: Object,\n"
"            byteorder: Optional[str] = None) -> Object\n"
"\n"
"Return a copy of the given object reinterpreted as another type and/or\n"
"byte order. If byte order is None, it defaults to the program byte\n"
"order.\n"
"\n"
"This reinterprets the raw memory of the object, so an object can be\n"
"reinterpreted as any other type. However, value objects with a scalar\n"
"type cannot be reinterpreted, as their memory layout in the program is\n"
"not known. Reinterpreting a reference results in a reference, and\n"
"reinterpreting a value results in a value. See also cast()."},
	{"container_of", (PyCFunction)DrgnObject_container_of,
	 METH_VARARGS | METH_KEYWORDS,
"container_of(ptr: Object, type: Union[str, Type], member: str) -> Object\n"
"\n"
"Return the containing object of the object pointed to by the given\n"
"pointer object. The given type is the type of the containing object, and\n"
"the given member is the name of the member in that type. This\n"
"corresponds to the container_of() macro in C."},
	{"mock_program", (PyCFunction)mock_program,
	 METH_VARARGS | METH_KEYWORDS,
"mock_program(word_size: int, byteorder: str,\n"
"             segments: Optional[Sequence[MockMemorySegment]] = None,\n"
"             types: Optional[Sequence[MockType]] = None,\n"
"             objects: Optional[Sequence[MockObject]] = None) -> Program\n"
"\n"
"Return a \"mock\" Program from the given word size, byteorder, and lists\n"
"of MockMemorySegment, MockType, and MockObject. This is usually used for\n"
"testing."},
	{"program_from_core_dump", (PyCFunction)program_from_core_dump,
	 METH_VARARGS | METH_KEYWORDS,
"program_from_core_dump(path: str, verbose: bool = False) -> Program\n"
"\n"
"Create a Program from a core dump file. The type of program (e.g.,\n"
"userspace or kernel) will be determined automatically.\n"
"\n"
"If verbose is True, this will print messages to stderr about not being\n"
"able to find debugging symbols, etc."},
	{"program_from_kernel", (PyCFunction)program_from_kernel,
	 METH_VARARGS | METH_KEYWORDS,
"program_from_kernel(verbose: bool = False) -> Program\n"
"\n"
"Create a Program from the running operating system kernel. This requires\n"
"root privileges.\n"
"\n"
"If verbose is True, this will print messages to stderr about not being\n"
"able to find kernel modules, debugging symbols, etc."},
	{"program_from_pid", (PyCFunction)program_from_pid,
	 METH_VARARGS | METH_KEYWORDS,
"program_from_pid(pid: int) -> Program\n"
"\n"
"Create a Program from a running program with the given PID. This\n"
"requires appropriate permissions (on Linux, ptrace(2) attach\n"
"permissions)."},
	{"void_type", (PyCFunction)void_type, METH_VARARGS | METH_KEYWORDS,
"void_type(qualifiers: int = 0) -> Type\n"
"\n"
"Return a new void type. It has kind TypeKind.VOID."},
	{"int_type", (PyCFunction)int_type, METH_VARARGS | METH_KEYWORDS,
"int_type(name: str, size: int, is_signed: bool,\n"
"         qualifiers: int = 0) -> Type\n"
"\n"
"Return a new integer type. It has kind TypeKind.INT, a name, a size, and\n"
"a signedness."},
	{"bool_type", (PyCFunction)bool_type, METH_VARARGS | METH_KEYWORDS,
"bool_type(name: str, size: int, qualifiers: int = 0) -> Type\n"
"\n"
"Return a new boolean type. It has kind TypeKind.BOOL, a name, and a\n"
"size."},
	{"float_type", (PyCFunction)float_type, METH_VARARGS | METH_KEYWORDS,
"float_type(name, size, qualifiers=0) -> new floating-point type\n"
"\n"
"Return a new floating-point type. It has kind TypeKind.FLOAT, a string\n"
"name, and an integer size."},
	{"complex_type", (PyCFunction)complex_type,
	 METH_VARARGS | METH_KEYWORDS,
"complex_type(name: str, size: int, type: Type,\n"
"             qualifiers: int = 0) -> Type\n"
"\n"
"Return a new complex type. It has kind TypeKind.COMPLEX, a name, a\n"
"size, and a corresponding real type, which must be an unqualified\n"
"floating-point or integer Type object."},
	{"struct_type", (PyCFunction)struct_type, METH_VARARGS | METH_KEYWORDS,
"struct_type(tag: Optional[str], size: int, members: Optional[Sequence],\n"
"            qualifiers: int = 0) -> Type\n"
"\n"
"Return a new structure type. It has kind TypeKind.STRUCT, a tag, a size,\n"
"and a list of members. The tag may be None, which indicates an anonymous\n"
"type. The members may be None, which indicates an incomplete type; in\n"
"this case, the size must be zero. Otherwise, the members must be a list\n"
"of (type, string name, integer bit offset, integer bit field size)\n"
"tuples. The type of a member must be a Type object or a callable\n"
"returning a Type object. In the latter case, the callable will be called\n"
"the first time that the member is accessed. The name of a member may be\n"
"None, which indicates an unnamed member. The bit field size should be\n"
"non-zero for bit fields and zero otherwise. The name, bit offset, and\n"
"bit field size can be omitted; the name defaults to None and the bit\n"
"offset and bit field size default to zero."},
	{"union_type", (PyCFunction)union_type, METH_VARARGS | METH_KEYWORDS,
"union_type(tag: Optional[str], size: int, members: Optional[Sequence],\n"
"           qualifiers: int = 0) -> Type\n"
"\n"
"Return a new union type. It has kind TypeKind.UNION, a tag, a size, and\n"
"a list of members. See struct_type()."},
	{"enum_type", (PyCFunction)enum_type, METH_VARARGS | METH_KEYWORDS,
"enum_type(tag: Optional[str], type: Optional[Type],\n"
"          enumerators: Optional[Sequence[Tuple[str, int]],\n"
"          qualifiers: int = 0) -> Type\n"
"\n"
"Return a new enumerated type. It has kind TypeKind.ENUM, a tag, a\n"
"compatible integer type, and a list of enumerators. The tag may be None,\n"
"which indicates an anonymous type. The type and enumerators may be None,\n"
"which indicates an incomplete type. Otherwise, the type must be an\n"
"integer Type object and the enumerators must be a list of (string name,\n"
"integer value) tuples."},
	{"typedef_type", (PyCFunction)typedef_type,
	 METH_VARARGS | METH_KEYWORDS,
"typedef_type(name: str, type: Type, qualifiers: int = 0) -> Type\n"
"\n"
"Return a new typedef type. It has kind TypeKind.TYPEDEF, a name, and an\n"
"aliased type."},
	{"pointer_type", (PyCFunction)pointer_type,
	 METH_VARARGS | METH_KEYWORDS,
"pointer_type(size: int, type: Type, qualifiers: int = 0) -> Type\n"
"\n"
"Return a new pointer type. It has kind TypeKind.POINTER, a size, and a\n"
"referenced type."},
	{"array_type", (PyCFunction)array_type, METH_VARARGS | METH_KEYWORDS,
"array_type(length: Optional[int], type: Type,\n"
"           qualifiers: int = 0) -> Type\n"
"\n"
"Return a new array type. It has kind TypeKind.ARRAY, a length, and an\n"
"element type. The length may be None, which indicates an incomplete\n"
"array type."},
	{"function_type", (PyCFunction)function_type,
	 METH_VARARGS | METH_KEYWORDS,
"function_type(type: Type, parameters: Sequence,\n"
"              is_variadic: bool = False, qualifiers: int = 0) -> Type\n"
"\n"
"Return a new function type. It has kind TypeKind.FUNCTION, a return\n"
"type, a list of parameters, and may be variadic. The parameters must be\n"
"a list of (type, string name) tuples. Each parameter type must be a Type\n"
"object or a callable returning a Type object. In the latter case, the\n"
"callable will be called the first time that the parameter is accessed. A\n"
"parameter name may be None, which indicates an unnamed parameter. The\n"
"parameter name is optional and defaults to None."},
	{},
};

static struct PyModuleDef drgnmodule = {
	PyModuleDef_HEAD_INIT,
	"_drgn",
"libdrgn bindings\n"
"\n"
"Don't use this module directly. Instead, use the drgn package.",
	-1,
	drgn_methods,
};

#define FaultError_DOC								\
"Bad memory access.\n"								\
"\n"										\
"This error is raised when a memory access is attempted to an address\n"	\
"which is not valid in a program, or when accessing out of bounds of a\n"	\
"value object."

#define FileFormatError_DOC						\
"Invalid file.\n"							\
"\n"									\
"This is error raised when a file cannot be parsed according to its\n"	\
"expected format (e.g., ELF or DWARF)."

DRGNPY_PUBLIC PyMODINIT_FUNC PyInit__drgn(void)
{
	PyObject *m;
	PyObject *version;

	m = PyModule_Create(&drgnmodule);
	if (!m)
		return NULL;

	if (add_module_constants(m) == -1)
		goto err;

	version = PyUnicode_FromFormat("%u.%u.%u", DRGN_VERSION_MAJOR,
				       DRGN_VERSION_MINOR, DRGN_VERSION_PATCH);
	if (!version)
		goto err;
	PyModule_AddObject(m, "__version__", version);

	FaultError = PyErr_NewExceptionWithDoc("_drgn.FaultError",
					       FaultError_DOC, NULL, NULL);
	if (!FaultError)
		goto err;
	PyModule_AddObject(m, "FaultError", FaultError);

	FileFormatError = PyErr_NewExceptionWithDoc("_drgn.FileFormatError",
						    FileFormatError_DOC, NULL,
						    NULL);
	if (!FileFormatError)
		goto err;
	PyModule_AddObject(m, "FileFormatError", FileFormatError);

	if (PyType_Ready(&DrgnObject_type) < 0)
		goto err;
	Py_INCREF(&DrgnObject_type);
	PyModule_AddObject(m, "Object", (PyObject *)&DrgnObject_type);

	if (PyType_Ready(&ObjectIterator_type) < 0)
		goto err;

	if (PyType_Ready(&Program_type) < 0)
		goto err;
	Py_INCREF(&Program_type);
	PyModule_AddObject(m, "Program", (PyObject *)&Program_type);

	if (PyType_Ready(&DrgnType_type) < 0)
		goto err;
	Py_INCREF(&DrgnType_type);
	PyModule_AddObject(m, "Type", (PyObject *)&DrgnType_type);

	return m;

err:
	Py_DECREF(m);
	return NULL;
}
