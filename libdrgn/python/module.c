// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"

PyObject *FaultError;
PyObject *FileFormatError;
PyObject *MissingDebugInfoError;

static PyObject *filename_matches(PyObject *self, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {"haystack", "needle", NULL};
	struct path_arg haystack_arg = {.allow_none = true};
	struct path_arg needle_arg = {.allow_none = true};
	struct path_iterator haystack = {
		.components = (struct path_iterator_component [1]){},
		.num_components = 0,
	};
	struct path_iterator needle = {
		.components = (struct path_iterator_component [1]){},
		.num_components = 0,
	};
	bool ret;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&:filename_matches",
					 keywords, path_converter,
					 &haystack_arg, path_converter,
					 &needle_arg))
		return NULL;

	if (haystack_arg.path) {
		haystack.components[0].path = haystack_arg.path;
		haystack.components[0].len = haystack_arg.length;
		haystack.num_components = 1;
	}
	if (needle_arg.path) {
		needle.components[0].path = needle_arg.path;
		needle.components[0].len = needle_arg.length;
		needle.num_components = 1;
	}
	ret = path_ends_with(&haystack, &needle);
	path_cleanup(&haystack_arg);
	path_cleanup(&needle_arg);
	if (ret)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

static PyMethodDef drgn_methods[] = {
	{"filename_matches", (PyCFunction)filename_matches,
	 METH_VARARGS | METH_KEYWORDS, drgn_filename_matches_DOC},
	{"NULL", (PyCFunction)DrgnObject_NULL, METH_VARARGS | METH_KEYWORDS,
	 drgn_NULL_DOC},
	{"cast", (PyCFunction)cast, METH_VARARGS | METH_KEYWORDS,
	 drgn_cast_DOC},
	{"reinterpret", (PyCFunction)reinterpret, METH_VARARGS | METH_KEYWORDS,
	 drgn_reinterpret_DOC},
	{"container_of", (PyCFunction)DrgnObject_container_of,
	 METH_VARARGS | METH_KEYWORDS, drgn_container_of_DOC},
	{"program_from_core_dump", (PyCFunction)program_from_core_dump,
	 METH_VARARGS | METH_KEYWORDS, drgn_program_from_core_dump_DOC},
	{"program_from_kernel", (PyCFunction)program_from_kernel,
	 METH_NOARGS, drgn_program_from_kernel_DOC},
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
	PyObject *host_platform_obj;

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

	MissingDebugInfoError = PyErr_NewExceptionWithDoc("_drgn.MissingDebugInfoError",
							  drgn_MissingDebugInfoError_DOC,
							  NULL, NULL);
	if (!MissingDebugInfoError)
		goto err;
	PyModule_AddObject(m, "MissingDebugInfoError", MissingDebugInfoError);

	if (PyType_Ready(&DrgnObject_type) < 0)
		goto err;
	Py_INCREF(&DrgnObject_type);
	PyModule_AddObject(m, "Object", (PyObject *)&DrgnObject_type);

	if (PyType_Ready(&ObjectIterator_type) < 0)
		goto err;

	if (PyType_Ready(&Platform_type) < 0)
		goto err;
	Py_INCREF(&Platform_type);
	PyModule_AddObject(m, "Platform", (PyObject *)&Platform_type);

	if (PyType_Ready(&Program_type) < 0)
		goto err;
	Py_INCREF(&Program_type);
	PyModule_AddObject(m, "Program", (PyObject *)&Program_type);

	if (PyType_Ready(&StackFrame_type) < 0)
		goto err;
	Py_INCREF(&StackFrame_type);
	PyModule_AddObject(m, "StackFrame", (PyObject *)&StackFrame_type);

	if (PyType_Ready(&StackTrace_type) < 0)
		goto err;
	Py_INCREF(&StackTrace_type);
	PyModule_AddObject(m, "StackTrace", (PyObject *)&StackTrace_type);

	if (PyType_Ready(&Symbol_type) < 0)
		goto err;
	Py_INCREF(&Symbol_type);
	PyModule_AddObject(m, "Symbol", (PyObject *)&Symbol_type);

	if (PyType_Ready(&DrgnType_type) < 0)
		goto err;
	Py_INCREF(&DrgnType_type);
	PyModule_AddObject(m, "Type", (PyObject *)&DrgnType_type);

	host_platform_obj = Platform_wrap(&drgn_host_platform);
	if (!host_platform_obj)
		goto err;
	PyModule_AddObject(m, "host_platform", host_platform_obj);

	return m;

err:
	Py_DECREF(m);
	return NULL;
}
