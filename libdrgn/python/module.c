// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include "drgnpy.h"
#include "../internal.h"
#ifdef WITH_KDUMPFILE
#include <libkdumpfile/kdumpfile.h>
#endif

PyObject *MissingDebugInfoError;
PyObject *OutOfBoundsError;

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

static PyObject *sizeof_(PyObject *self, PyObject *arg)
{
	struct drgn_error *err;
	uint64_t size;

	if (PyObject_TypeCheck(arg, &DrgnType_type)) {
		err = drgn_type_sizeof(((DrgnType *)arg)->type, &size);
	} else if (PyObject_TypeCheck(arg, &DrgnObject_type)) {
		err = drgn_object_sizeof(&((DrgnObject *)arg)->obj, &size);
	} else {
		return PyErr_Format(PyExc_TypeError,
				    "expected Type or Object, not %s",
				    Py_TYPE(arg)->tp_name);
	}
	if (err)
		return set_drgn_error(err);
	return PyLong_FromUnsignedLongLong(size);
}

static PyMethodDef drgn_methods[] = {
	{"filename_matches", (PyCFunction)filename_matches,
	 METH_VARARGS | METH_KEYWORDS, drgn_filename_matches_DOC},
	{"NULL", (PyCFunction)DrgnObject_NULL, METH_VARARGS | METH_KEYWORDS,
	 drgn_NULL_DOC},
	{"sizeof", (PyCFunction)sizeof_, METH_O, drgn_sizeof_DOC},
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
	{"class_type", (PyCFunction)class_type, METH_VARARGS | METH_KEYWORDS,
	 drgn_class_type_DOC},
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
	{"_linux_helper_read_vm", (PyCFunction)drgnpy_linux_helper_read_vm,
	 METH_VARARGS | METH_KEYWORDS},
	{"_linux_helper_radix_tree_lookup",
	 (PyCFunction)drgnpy_linux_helper_radix_tree_lookup,
	 METH_VARARGS | METH_KEYWORDS},
	{"_linux_helper_idr_find", (PyCFunction)drgnpy_linux_helper_idr_find,
	 METH_VARARGS | METH_KEYWORDS},
	{"_linux_helper_find_pid", (PyCFunction)drgnpy_linux_helper_find_pid,
	 METH_VARARGS | METH_KEYWORDS},
	{"_linux_helper_pid_task", (PyCFunction)drgnpy_linux_helper_pid_task,
	 METH_VARARGS | METH_KEYWORDS},
	{"_linux_helper_find_task", (PyCFunction)drgnpy_linux_helper_find_task,
	 METH_VARARGS | METH_KEYWORDS},
	{"_linux_helper_task_state_to_char",
	 (PyCFunction)drgnpy_linux_helper_task_state_to_char,
	 METH_VARARGS | METH_KEYWORDS},
	{"_linux_helper_kaslr_offset",
	 (PyCFunction)drgnpy_linux_helper_kaslr_offset,
	 METH_VARARGS | METH_KEYWORDS},
	{"_linux_helper_pgtable_l5_enabled",
	 (PyCFunction)drgnpy_linux_helper_pgtable_l5_enabled,
	 METH_VARARGS | METH_KEYWORDS},
	{},
};

static struct PyModuleDef drgnmodule = {
	PyModuleDef_HEAD_INIT,
	"_drgn",
	drgn_DOC,
	-1,
	drgn_methods,
};

DRGNPY_PUBLIC PyMODINIT_FUNC PyInit__drgn(void)
{
	PyObject *m;
	PyObject *host_platform_obj;
	PyObject *with_libkdumpfile;

	m = PyModule_Create(&drgnmodule);
	if (!m)
		return NULL;

	if (add_module_constants(m) == -1)
		goto err;

	FaultError_type.tp_base = (PyTypeObject *)PyExc_Exception;
	if (PyType_Ready(&FaultError_type) < 0)
		goto err;
	Py_INCREF(&FaultError_type);
	PyModule_AddObject(m, "FaultError", (PyObject *)&FaultError_type);

	MissingDebugInfoError = PyErr_NewExceptionWithDoc("_drgn.MissingDebugInfoError",
							  drgn_MissingDebugInfoError_DOC,
							  NULL, NULL);
	if (!MissingDebugInfoError)
		goto err;
	PyModule_AddObject(m, "MissingDebugInfoError", MissingDebugInfoError);

	OutOfBoundsError = PyErr_NewExceptionWithDoc("_drgn.OutOfBoundsError",
						     drgn_OutOfBoundsError_DOC,
						     NULL, NULL);
	if (!OutOfBoundsError)
		goto err;
	PyModule_AddObject(m, "OutOfBoundsError", OutOfBoundsError);

	if (PyType_Ready(&Language_type) < 0)
		goto err;
	Py_INCREF(&Language_type);
	PyModule_AddObject(m, "Language", (PyObject *)&Language_type);
	if (add_languages() == -1)
		goto err;

	if (PyStructSequence_InitType2(&Register_type, &Register_desc) == -1)
		goto err;
	PyModule_AddObject(m, "Register", (PyObject *)&Register_type);

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

	if (PyType_Ready(&TypeEnumerator_type) < 0)
		goto err;
	Py_INCREF(&TypeEnumerator_type);
	PyModule_AddObject(m, "TypeEnumerator",
			   (PyObject *)&TypeEnumerator_type);

	if (PyType_Ready(&TypeMember_type) < 0)
		goto err;
	Py_INCREF(&TypeMember_type);
	PyModule_AddObject(m, "TypeMember", (PyObject *)&TypeMember_type);

	if (PyType_Ready(&TypeParameter_type) < 0)
		goto err;
	Py_INCREF(&TypeParameter_type);
	PyModule_AddObject(m, "TypeParameter", (PyObject *)&TypeParameter_type);

	host_platform_obj = Platform_wrap(&drgn_host_platform);
	if (!host_platform_obj)
		goto err;
	PyModule_AddObject(m, "host_platform", host_platform_obj);

#ifdef WITH_LIBKDUMPFILE
	with_libkdumpfile = Py_True;
#else
	with_libkdumpfile = Py_False;
#endif
	Py_INCREF(with_libkdumpfile);
	PyModule_AddObject(m, "_with_libkdumpfile", with_libkdumpfile);

	return m;

err:
	Py_DECREF(m);
	return NULL;
}
