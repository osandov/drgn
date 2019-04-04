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
	{"NULL", (PyCFunction)DrgnObject_NULL, METH_VARARGS | METH_KEYWORDS,
	 drgn_NULL_DOC},
	{"cast", (PyCFunction)cast, METH_VARARGS | METH_KEYWORDS,
	 drgn_cast_DOC},
	{"reinterpret", (PyCFunction)reinterpret, METH_VARARGS | METH_KEYWORDS,
	 drgn_reinterpret_DOC},
	{"container_of", (PyCFunction)DrgnObject_container_of,
	 METH_VARARGS | METH_KEYWORDS, drgn_container_of_DOC},
	{"mock_program", (PyCFunction)mock_program,
	 METH_VARARGS | METH_KEYWORDS,
"mock_program(word_size, byteorder, segments=None, types=None, objects=None)\n"
"--\n"
"\n"
"Create a mock :class:`Program` for testing.\n"
"\n"
":param int word_size: :attr:`Program.word_size`\n"
":param str byteorder: :attr:`Program.byteorder`\n"
":param segments: Memory segments.\n"
":type segments: list[MockMemorySegment] or None\n"
":param types: Type definitions.\n"
":type types: list[MockType] or None\n"
":param objects: Object definitions.\n"
":type objects: list[MockObject] or None\n"
":rtype: Program"},
	{"program_from_core_dump", (PyCFunction)program_from_core_dump,
	 METH_VARARGS | METH_KEYWORDS, drgn_program_from_core_dump_DOC},
	{"program_from_kernel", (PyCFunction)program_from_kernel,
	 METH_VARARGS | METH_KEYWORDS, drgn_program_from_kernel_DOC},
	{"program_from_pid", (PyCFunction)program_from_pid,
	 METH_VARARGS | METH_KEYWORDS, drgn_program_from_pid_DOC},
	{"void_type", (PyCFunction)void_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_void_type_DOC},
	{"int_type", (PyCFunction)int_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_int_type_DOC},
	{"bool_type", (PyCFunction)bool_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_bool_type_DOC},
	{"float_type", (PyCFunction)float_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_float_type_DOC},
	{"complex_type", (PyCFunction)complex_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_complex_type_DOC},
	{"struct_type", (PyCFunction)struct_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_struct_type_DOC},
	{"union_type", (PyCFunction)union_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_union_type_DOC},
	{"enum_type", (PyCFunction)enum_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_enum_type_DOC},
	{"typedef_type", (PyCFunction)typedef_type,
	 METH_VARARGS | METH_KEYWORDS,
	 drgn_typedef_type_DOC},
	{"pointer_type", (PyCFunction)pointer_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_pointer_type_DOC},
	{"array_type", (PyCFunction)array_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_array_type_DOC},
	{"function_type", (PyCFunction)function_type,
	 METH_VARARGS | METH_KEYWORDS, drgn_function_type_DOC},
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
					       drgn_FaultError_DOC, NULL, NULL);
	if (!FaultError)
		goto err;
	PyModule_AddObject(m, "FaultError", FaultError);

	FileFormatError = PyErr_NewExceptionWithDoc("_drgn.FileFormatError",
						    drgn_FileFormatError_DOC,
						    NULL, NULL);
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
