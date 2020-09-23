// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#ifdef WITH_KDUMPFILE
#include <libkdumpfile/kdumpfile.h>
#endif

#include "drgnpy.h"
#include "../path.h"

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

/*
 * These are for type checking and aren't strictly required at runtime, but
 * adding them anyways results in better pydoc output and saves us from fiddling
 * with typing.TYPE_CHECKING/forward references.
 */
static int add_type_aliases(PyObject *m)
{
	/*
	 * This should be a subclass of typing.Protocol, but that is only
	 * available since Python 3.8.
	 */
	PyObject *IntegerLike = PyType_FromSpec(&(PyType_Spec){
		.name = "_drgn.IntegerLike",
		.flags = Py_TPFLAGS_DEFAULT,
		.slots = (PyType_Slot []){{0, NULL}},
	});
       if (!IntegerLike)
	       return -1;
       if (PyModule_AddObject(m, "IntegerLike", IntegerLike) == -1) {
	       Py_DECREF(IntegerLike);
	       return -1;
       }

       PyObject *os_module = PyImport_ImportModule("os");
       if (!os_module)
	       return -1;
       PyObject *os_PathLike = PyObject_GetAttrString(os_module, "PathLike");
       Py_DECREF(os_module);
       if (!os_PathLike)
	       return -1;
       PyObject *item = Py_BuildValue("OOO", &PyUnicode_Type, &PyBytes_Type,
				      os_PathLike);
       Py_DECREF(os_PathLike);
       if (!item)
	       return -1;

       PyObject *typing_module = PyImport_ImportModule("typing");
       if (!typing_module) {
	       Py_DECREF(item);
	       return -1;
       }
       PyObject *typing_Union = PyObject_GetAttrString(typing_module, "Union");
       Py_DECREF(typing_module);
       if (!typing_Union) {
	       Py_DECREF(item);
	       return -1;
       }

       PyObject *Path = PyObject_GetItem(typing_Union, item);
       Py_DECREF(typing_Union);
       Py_DECREF(item);
       if (!Path)
	       return -1;
       if (PyModule_AddObject(m, "Path", Path) == -1) {
	       Py_DECREF(Path);
	       return -1;
       }
       return 0;
}

DRGNPY_PUBLIC PyMODINIT_FUNC PyInit__drgn(void)
{
	PyObject *m;
	PyObject *host_platform_obj;
	PyObject *with_libkdumpfile;

	m = PyModule_Create(&drgnmodule);
	if (!m)
		return NULL;

	if (add_module_constants(m) == -1 || add_type_aliases(m) == -1)
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
