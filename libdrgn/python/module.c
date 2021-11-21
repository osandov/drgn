// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <elfutils/libdwfl.h>
#ifdef WITH_KDUMPFILE
#include <libkdumpfile/kdumpfile.h>
#endif

#include "drgnpy.h"
#include "../path.h"

/* Basically PyModule_AddType(), which is only available since Python 3.9. */
static int add_type(PyObject *module, PyTypeObject *type)
{
	int ret = PyType_Ready(type);
	if (ret)
		return ret;
	const char *name = type->tp_name;
	const char *dot = strrchr(type->tp_name, '.');
	if (dot)
		name = dot + 1;
	Py_INCREF(type);
	ret = PyModule_AddObject(module, name, (PyObject *)type);
	if (ret)
		Py_DECREF(type);
	return ret;
}

PyObject *MissingDebugInfoError;
PyObject *ObjectAbsentError;
PyObject *OutOfBoundsError;

static PyObject *filename_matches(PyObject *self, PyObject *args,
				  PyObject *kwds)
{
	static char *keywords[] = {"haystack", "needle", NULL};
	struct path_arg haystack_arg = {.allow_none = true};
	struct path_arg needle_arg = {.allow_none = true};
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&O&:filename_matches",
					 keywords, path_converter,
					 &haystack_arg, path_converter,
					 &needle_arg))
		return NULL;

	struct path_iterator haystack = {
		.components = (struct nstring [1]){},
		.num_components = 0,
	};
	if (haystack_arg.path) {
		haystack.components[0].str = haystack_arg.path;
		haystack.components[0].len = haystack_arg.length;
		haystack.num_components = 1;
	}
	struct path_iterator needle = {
		.components = (struct nstring [1]){},
		.num_components = 0,
	};
	if (needle_arg.path) {
		needle.components[0].str = needle_arg.path;
		needle.components[0].len = needle_arg.length;
		needle.num_components = 1;
	}
	bool ret = path_ends_with(&haystack, &needle);
	path_cleanup(&haystack_arg);
	path_cleanup(&needle_arg);
	Py_RETURN_BOOL(ret);
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

static PyObject *offsetof_(PyObject *self, PyObject *args, PyObject *kwds)
{
	struct drgn_error *err;

	static char *keywords[] = {"type", "member", NULL};
	DrgnType *type;
	const char *member;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!s:offsetof", keywords,
					 &DrgnType_type, &type, &member))
		return NULL;
	uint64_t offset;
	err = drgn_type_offsetof(type->type, member, &offset);
	if (err)
		return set_drgn_error(err);
	return PyLong_FromUnsignedLongLong(offset);
}

static PyMethodDef drgn_methods[] = {
	{"filename_matches", (PyCFunction)filename_matches,
	 METH_VARARGS | METH_KEYWORDS, drgn_filename_matches_DOC},
	{"NULL", (PyCFunction)DrgnObject_NULL, METH_VARARGS | METH_KEYWORDS,
	 drgn_NULL_DOC},
	{"sizeof", (PyCFunction)sizeof_, METH_O, drgn_sizeof_DOC},
	{"offsetof", (PyCFunction)offsetof_, METH_VARARGS | METH_KEYWORDS,
	 drgn_offsetof_DOC},
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
	PyObject *m = PyModule_Create(&drgnmodule);
	if (!m)
		return NULL;

	if (add_module_constants(m) ||
	    add_type_aliases(m) ||
	    add_type(m, &Language_type) || add_languages() ||
	    add_type(m, &DrgnObject_type) ||
	    PyType_Ready(&ObjectIterator_type) ||
	    add_type(m, &Platform_type) ||
	    add_type(m, &Program_type) ||
	    add_type(m, &Register_type) ||
	    add_type(m, &StackFrame_type) ||
	    add_type(m, &StackTrace_type) ||
	    add_type(m, &Symbol_type) ||
	    add_type(m, &DrgnType_type) ||
	    add_type(m, &TypeEnumerator_type) ||
	    add_type(m, &TypeMember_type) ||
	    add_type(m, &TypeParameter_type) ||
	    add_type(m, &TypeTemplateParameter_type))
		goto err;

	FaultError_type.tp_base = (PyTypeObject *)PyExc_Exception;
	if (add_type(m, &FaultError_type))
		goto err;

	MissingDebugInfoError =
		PyErr_NewExceptionWithDoc("_drgn.MissingDebugInfoError",
					  drgn_MissingDebugInfoError_DOC, NULL,
					  NULL);
	if (!MissingDebugInfoError)
		goto err;
	if (PyModule_AddObject(m, "MissingDebugInfoError",
			       MissingDebugInfoError)) {
		Py_DECREF(MissingDebugInfoError);
		goto err;
	}

	ObjectAbsentError =
		PyErr_NewExceptionWithDoc("_drgn.ObjectAbsentError",
					  drgn_ObjectAbsentError_DOC,
					  NULL, NULL);
	if (!ObjectAbsentError)
		goto err;
	if (PyModule_AddObject(m, "ObjectAbsentError", ObjectAbsentError)) {
		Py_DECREF(ObjectAbsentError);
		goto err;
	}

	OutOfBoundsError = PyErr_NewExceptionWithDoc("_drgn.OutOfBoundsError",
						     drgn_OutOfBoundsError_DOC,
						     NULL, NULL);
	if (!OutOfBoundsError)
		goto err;
	if (PyModule_AddObject(m, "OutOfBoundsError", OutOfBoundsError)) {
		Py_DECREF(OutOfBoundsError);
		goto err;
	}

	PyObject *host_platform_obj = Platform_wrap(&drgn_host_platform);
	if (!host_platform_obj)
		goto err;
	if (PyModule_AddObject(m, "host_platform", host_platform_obj)) {
		Py_DECREF(host_platform_obj);
		goto err;
	}

	if (PyModule_AddStringConstant(m, "_elfutils_version",
				       dwfl_version(NULL)))
		goto err;

	PyObject *with_libkdumpfile;
#ifdef WITH_LIBKDUMPFILE
	with_libkdumpfile = Py_True;
#else
	with_libkdumpfile = Py_False;
#endif
	Py_INCREF(with_libkdumpfile);
	if (PyModule_AddObject(m, "_with_libkdumpfile", with_libkdumpfile)) {
		Py_DECREF(with_libkdumpfile);
		goto err;
	}

	return m;

err:
	Py_DECREF(m);
	return NULL;
}
