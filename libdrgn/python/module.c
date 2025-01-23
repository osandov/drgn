// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../util.h"

static PyObject *WantedSupplementaryFile_class;

int add_WantedSupplementaryFile(PyObject *m)
{
	_cleanup_pydecref_ PyObject *collections =
		PyImport_ImportModule("collections");
	_cleanup_pydecref_ PyObject *namedtuple =
		PyObject_GetAttrString(collections, "namedtuple");
	if (!namedtuple)
		return -1;
	WantedSupplementaryFile_class =
		PyObject_CallFunction(namedtuple, "s[ssss]",
				      "WantedSupplementaryFile", "kind", "path",
				      "supplementary_path", "checksum");
	if (!WantedSupplementaryFile_class)
		return -1;
	Py_INCREF(WantedSupplementaryFile_class);
	if (PyModule_AddObject(m, "WantedSupplementaryFile",
			       WantedSupplementaryFile_class) == -1) {
		Py_DECREF(WantedSupplementaryFile_class);
		Py_DECREF(WantedSupplementaryFile_class);
		return -1;
	}
	return 0;
}

PyObject *Module_wrap(struct drgn_module *module)
{
	PyTypeObject *type;
	SWITCH_ENUM(drgn_module_kind(module)) {
	case DRGN_MODULE_MAIN:
		type = &MainModule_type;
		break;
	case DRGN_MODULE_SHARED_LIBRARY:
		type = &SharedLibraryModule_type;
		break;
	case DRGN_MODULE_VDSO:
		type = &VdsoModule_type;
		break;
	case DRGN_MODULE_RELOCATABLE:
		type = &RelocatableModule_type;
		break;
	case DRGN_MODULE_EXTRA:
		type = &ExtraModule_type;
		break;
	default:
		UNREACHABLE();
	}
	Module *ret = (Module *)type->tp_alloc(type, 0);
	if (ret) {
		struct drgn_program *prog = drgn_module_program(module);
		Py_INCREF(container_of(prog, Program, prog));
		ret->module = module;
	}
	return (PyObject *)ret;
}

PyObject *Module_and_bool_wrap(struct drgn_module *module, bool b)
{
	return Py_BuildValue("NO", Module_wrap(module), b ? Py_True : Py_False);
}

static void Module_dealloc(Module *self)
{
	if (self->module) {
		struct drgn_program *prog = drgn_module_program(self->module);
		Py_DECREF(container_of(prog, Program, prog));
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int append_module_repr_common(PyObject *parts, Module *self,
				     const char *method_name)
{
	if (append_format(parts, "prog.%s_module(name=", method_name) < 0 ||
	    append_attr_repr(parts, (PyObject *)self, "name") < 0)
		return -1;
	return 0;
}

static PyObject *Module_repr(Module *self)
{
	struct drgn_module_key key = drgn_module_key(self->module);

	_cleanup_pydecref_ PyObject *parts = PyList_New(0);
	if (!parts)
		return NULL;

	SWITCH_ENUM(key.kind) {
	case DRGN_MODULE_MAIN:
		if (append_module_repr_common(parts, self, "main") < 0)
			return NULL;
		break;
	case DRGN_MODULE_SHARED_LIBRARY:
		if (append_module_repr_common(parts, self,
					      "shared_library")
		    || append_string(parts, ", dynamic_address=")
		    || append_u64_hex(parts,
				      key.shared_library.dynamic_address))
			return NULL;
		break;
	case DRGN_MODULE_VDSO:
		if (append_module_repr_common(parts, self, "vdso")
		    || append_string(parts, ", dynamic_address=")
		    || append_u64_hex(parts, key.vdso.dynamic_address))
			return NULL;
		break;
	case DRGN_MODULE_RELOCATABLE:
		if (append_module_repr_common(parts, self, "relocatable")
		    || append_string(parts, ", address=")
		    || append_u64_hex(parts, key.relocatable.address))
			return NULL;
		break;
	case DRGN_MODULE_EXTRA:
		if (append_module_repr_common(parts, self, "extra")
		    || append_string(parts, ", id=")
		    || append_u64_hex(parts, key.extra.id))
			return NULL;
		break;
	default:
		UNREACHABLE();
	}
	if (append_string(parts, ")"))
		return NULL;
	return join_strings(parts);
}

static PyObject *Module_richcompare(Module *self, PyObject *other, int op)
{
	if ((op != Py_EQ && op != Py_NE) ||
	    !PyObject_TypeCheck(other, &Module_type))
		Py_RETURN_NOTIMPLEMENTED;
	int ret = self->module == ((Module *)other)->module;
	if (op == Py_NE)
		ret = !ret;
	Py_RETURN_BOOL(ret);
}

static Py_hash_t Module_hash(Module *self)
{
	return _Py_HashPointer(self->module);
}

static PyObject *Module_wanted_supplementary_debug_file(Module *self)
{
	const char *debug_file_path, *supplementary_path;
	const void *checksum;
	size_t checksum_len;
	enum drgn_supplementary_file_kind kind =
		drgn_module_wanted_supplementary_debug_file(self->module,
							    &debug_file_path,
							    &supplementary_path,
							    &checksum,
							    &checksum_len);
	if (kind == DRGN_SUPPLEMENTARY_FILE_NONE) {
		return PyErr_Format(PyExc_ValueError,
				    "module does not want supplementary debug file");
	}
	return PyObject_CallFunction(WantedSupplementaryFile_class,
				     "NO&O&y#",
				     PyObject_CallFunction(SupplementaryFileKind_class,
							   "k",
							   (unsigned long)kind),
				     PyUnicode_DecodeFSDefault, debug_file_path,
				     PyUnicode_DecodeFSDefault,
				     supplementary_path, checksum,
				     (Py_ssize_t)checksum_len);
}

static PyObject *Module_try_file(Module *self, PyObject *args, PyObject *kwds)
{
	struct drgn_error *err;
	static char *keywords[] = { "path", "fd", "force", NULL };
	struct path_arg path = {};
	int fd = -1;
	int force = 0;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O&|$ip:try_file", keywords,
					 path_converter, &path, &fd, &force))
		return NULL;
	err = drgn_module_try_file(self->module, path.path, fd, force);
	path_cleanup(&path);
	if (err)
		return set_drgn_error(err);
	Py_RETURN_NONE;
}

static Program *Module_get_prog(Module *self, void *arg)
{
	Program *prog =
		container_of(drgn_module_program(self->module), Program, prog);
	Py_INCREF(prog);
	return prog;
}

static PyObject *Module_get_name(Module *self, void *arg)
{
	return PyUnicode_DecodeFSDefault(drgn_module_name(self->module));
}

static PyObject *Module_get_address_range(Module *self, void *arg)
{
	uint64_t start, end;
	if (!drgn_module_address_range(self->module, &start, &end))
		Py_RETURN_NONE;
	return Py_BuildValue("KK", (unsigned long long)start,
			     (unsigned long long)end);
}

static int Module_set_address_range(Module *self, PyObject *value, void *arg)
{
	SETTER_NO_DELETE("address_range", value);
	struct drgn_error *err;
	if (value == Py_None) {
		err = drgn_module_set_address_range(self->module, -1, -1);
	} else {
		if (!PyTuple_Check(value) || PyTuple_GET_SIZE(value) != 2) {
			PyErr_SetString(PyExc_TypeError,
					"address_range must be (int, int) or None");
			return -1;
		}
		_cleanup_pydecref_ PyObject *start_obj =
			PyNumber_Index(PyTuple_GET_ITEM(value, 0));
		if (!start_obj)
			return -1;
		_cleanup_pydecref_ PyObject *end_obj =
			PyNumber_Index(PyTuple_GET_ITEM(value, 1));
		if (!end_obj)
			return -1;
		uint64_t start = PyLong_AsUint64(start_obj);
		uint64_t end = PyLong_AsUint64(end_obj);
		if (start == UINT64_MAX && end == UINT64_MAX) {
			PyErr_SetString(PyExc_ValueError,
					"invalid module address range");
			return -1;
		}
		err = drgn_module_set_address_range(self->module, start, end);
	}
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

static PyObject *Module_get_build_id(Module *self, void *arg)
{
	const void *build_id;
	size_t build_id_len;
	if (!drgn_module_build_id(self->module, &build_id, &build_id_len))
		Py_RETURN_NONE;
	return PyBytes_FromStringAndSize(build_id, build_id_len);
}

static int Module_set_build_id(Module *self, PyObject *value, void *arg)
{
	SETTER_NO_DELETE("build_id", value);
	struct drgn_error *err;
	if (value == Py_None) {
		err = drgn_module_set_build_id(self->module, NULL, 0);
	} else {
		Py_buffer buffer;
		int ret = PyObject_GetBuffer(value, &buffer, PyBUF_SIMPLE);
		if (ret)
			return ret;

		if (buffer.len == 0) {
			PyErr_SetString(PyExc_ValueError,
					"build ID cannot be empty");
			PyBuffer_Release(&buffer);
			return -1;
		}

		err = drgn_module_set_build_id(self->module, buffer.buf,
					       buffer.len);
		PyBuffer_Release(&buffer);
	}
	if (err) {
		set_drgn_error(err);
		return -1;
	}
	return 0;
}

#define MODULE_FILE_STATUS_GETSET(which)					\
static PyObject *Module_wants_##which##_file(Module *self)			\
{										\
	Py_RETURN_BOOL(drgn_module_wants_##which##_file(self->module));		\
}										\
										\
static PyObject *Module_get_##which##_file_status(Module *self, void *arg)	\
{										\
	return PyObject_CallFunction(ModuleFileStatus_class, "i",		\
				     (int)drgn_module_##which##_file_status(self->module));\
}										\
										\
static int Module_set_##which##_file_status(Module *self, PyObject *value,	\
					    void *arg)				\
{										\
	SETTER_NO_DELETE(#which, value);					\
	if (!PyObject_TypeCheck(value,						\
				(PyTypeObject *)ModuleFileStatus_class)) {	\
		PyErr_SetString(PyExc_TypeError,				\
				#which "_file_status must be ModuleFileStatus");\
		return -1;							\
	}									\
	_cleanup_pydecref_ PyObject *value_obj =				\
		PyObject_GetAttrString(value, "value");				\
	if (!value_obj)								\
		return -1;							\
	long status = PyLong_AsLong(value_obj);					\
	if (status == -1 && PyErr_Occurred())					\
		return -1;							\
										\
	if (drgn_module_set_##which##_file_status(self->module, status))	\
		return 0;							\
										\
	_cleanup_pydecref_ PyObject *old_status =				\
		Module_get_##which##_file_status(self, NULL);			\
	if (!old_status)							\
		return -1;							\
	PyErr_Format(PyExc_ValueError,						\
		     "cannot change " #which "_file_status from %S to %S",	\
		     old_status, value);					\
	return -1;								\
}
MODULE_FILE_STATUS_GETSET(loaded)
MODULE_FILE_STATUS_GETSET(debug)

static PyObject *Module_get_loaded_file_path(Module *self, void *arg)
{
	const char *path = drgn_module_loaded_file_path(self->module);
	if (!path)
		Py_RETURN_NONE;
	return PyUnicode_DecodeFSDefault(path);
}

static PyObject *Module_get_loaded_file_bias(Module *self, void *arg)
{
	if (!drgn_module_loaded_file_path(self->module))
		Py_RETURN_NONE;
	return PyLong_FromUint64(drgn_module_loaded_file_bias(self->module));
}

static PyObject *Module_get_debug_file_path(Module *self, void *arg)
{
	const char *path = drgn_module_debug_file_path(self->module);
	if (!path)
		Py_RETURN_NONE;
	return PyUnicode_DecodeFSDefault(path);
}

static PyObject *Module_get_debug_file_bias(Module *self, void *arg)
{
	if (!drgn_module_debug_file_path(self->module))
		Py_RETURN_NONE;
	return PyLong_FromUint64(drgn_module_debug_file_bias(self->module));
}

static PyObject *Module_get_supplementary_debug_file_kind(Module *self,
							  void *arg)
{
	enum drgn_supplementary_file_kind kind =
		drgn_module_supplementary_debug_file_kind(self->module);
	if (kind == DRGN_SUPPLEMENTARY_FILE_NONE)
		Py_RETURN_NONE;
	return PyObject_CallFunction(SupplementaryFileKind_class, "k",
				     (unsigned long)kind);
}

static PyObject *Module_get_supplementary_debug_file_path(Module *self,
							  void *arg)
{
	const char *path =
		drgn_module_supplementary_debug_file_path(self->module);
	if (!path)
		Py_RETURN_NONE;
	return PyUnicode_DecodeFSDefault(path);
}

static PyMethodDef Module_methods[] = {
	{"wants_loaded_file", (PyCFunction)Module_wants_loaded_file,
	 METH_NOARGS, drgn_Module_wants_loaded_file_DOC},
	{"wants_debug_file", (PyCFunction)Module_wants_debug_file, METH_NOARGS,
	 drgn_Module_wants_debug_file_DOC},
	{"wanted_supplementary_debug_file",
	 (PyCFunction)Module_wanted_supplementary_debug_file, METH_NOARGS,
	 drgn_Module_wanted_supplementary_debug_file_DOC},
	{"try_file", (PyCFunction)Module_try_file,
	 METH_VARARGS | METH_KEYWORDS, drgn_Module_try_file_DOC},
	{},
};

static PyGetSetDef Module_getset[] = {
	{"prog", (getter)Module_get_prog, NULL, drgn_Module_prog_DOC},
	{"name", (getter)Module_get_name, NULL, drgn_Module_name_DOC},
	{"address_range", (getter)Module_get_address_range,
	 (setter)Module_set_address_range, drgn_Module_address_range_DOC},
	{"build_id", (getter)Module_get_build_id, (setter)Module_set_build_id,
	 drgn_Module_build_id_DOC},
	{"loaded_file_status", (getter)Module_get_loaded_file_status,
	 (setter)Module_set_loaded_file_status,
	 drgn_Module_loaded_file_status_DOC},
	{"loaded_file_path", (getter)Module_get_loaded_file_path, NULL,
	 drgn_Module_loaded_file_path_DOC},
	{"loaded_file_bias", (getter)Module_get_loaded_file_bias, NULL,
	 drgn_Module_loaded_file_bias_DOC},
	{"debug_file_status", (getter)Module_get_debug_file_status,
	 (setter)Module_set_debug_file_status,
	 drgn_Module_debug_file_status_DOC},
	{"debug_file_path", (getter)Module_get_debug_file_path, NULL,
	 drgn_Module_debug_file_path_DOC},
	{"debug_file_bias", (getter)Module_get_debug_file_bias, NULL,
	 drgn_Module_debug_file_bias_DOC},
	{"supplementary_debug_file_kind",
	 (getter)Module_get_supplementary_debug_file_kind, NULL,
	 drgn_Module_supplementary_debug_file_kind_DOC},
	{"supplementary_debug_file_path",
	 (getter)Module_get_supplementary_debug_file_path, NULL,
	 drgn_Module_supplementary_debug_file_path_DOC},
	{},
};

PyTypeObject Module_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.Module",
	.tp_basicsize = sizeof(Module),
	.tp_dealloc = (destructor)Module_dealloc,
	.tp_repr = (reprfunc)Module_repr,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
	.tp_doc = drgn_Module_DOC,
	.tp_richcompare = (richcmpfunc)Module_richcompare,
	.tp_hash = (hashfunc)Module_hash,
	.tp_methods = Module_methods,
	.tp_getset = Module_getset,
};

PyTypeObject MainModule_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.MainModule",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_MainModule_DOC,
	.tp_base = &Module_type,
};

static PyObject *SharedLibraryModule_get_dynamic_address(Module *self, void *arg)
{
	struct drgn_module_key key = drgn_module_key(self->module);
	return PyLong_FromUint64(key.shared_library.dynamic_address);
}

static PyGetSetDef SharedLibraryModule_getset[] = {
	{"dynamic_address", (getter)SharedLibraryModule_get_dynamic_address,
	 NULL, drgn_SharedLibraryModule_dynamic_address_DOC},
	{},
};

PyTypeObject SharedLibraryModule_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.SharedLibraryModule",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_SharedLibraryModule_DOC,
	.tp_getset = SharedLibraryModule_getset,
	.tp_base = &Module_type,
};

static PyObject *VdsoModule_get_dynamic_address(Module *self, void *arg)
{
	struct drgn_module_key key = drgn_module_key(self->module);
	return PyLong_FromUint64(key.vdso.dynamic_address);
}

static PyGetSetDef VdsoModule_getset[] = {
	{"dynamic_address", (getter)VdsoModule_get_dynamic_address, NULL,
	 drgn_VdsoModule_dynamic_address_DOC},
	{},
};

PyTypeObject VdsoModule_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.VdsoModule",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_VdsoModule_DOC,
	.tp_getset = VdsoModule_getset,
	.tp_base = &Module_type,
};

static PyObject *RelocatableModule_get_address(Module *self, void *arg)
{
	struct drgn_module_key key = drgn_module_key(self->module);
	return PyLong_FromUint64(key.relocatable.address);
}

static PyObject *RelocatableModule_get_section_addresses(PyObject *self,
							 void *arg)
{
	return PyObject_CallOneArg(ModuleSectionAddresses_class, self);
}

static PyGetSetDef RelocatableModule_getset[] = {
	{"address", (getter)RelocatableModule_get_address, NULL,
	 drgn_RelocatableModule_address_DOC},
	{"section_addresses", RelocatableModule_get_section_addresses,
	 NULL, drgn_RelocatableModule_section_addresses_DOC},
	{},
};

PyTypeObject RelocatableModule_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.RelocatableModule",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_RelocatableModule_DOC,
	.tp_getset = RelocatableModule_getset,
	.tp_base = &Module_type,
};

static PyObject *ExtraModule_get_id(Module *self, void *arg)
{
	struct drgn_module_key key = drgn_module_key(self->module);
	return PyLong_FromUint64(key.extra.id);
}

static PyGetSetDef ExtraModule_getset[] = {
	{"id", (getter)ExtraModule_get_id, NULL, drgn_ExtraModule_id_DOC},
	{},
};

PyTypeObject ExtraModule_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.ExtraModule",
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_doc = drgn_ExtraModule_DOC,
	.tp_getset = ExtraModule_getset,
	.tp_base = &Module_type,
};

static void ModuleIterator_dealloc(ModuleIterator *self)
{
	if (self->it) {
		struct drgn_program *prog =
			drgn_module_iterator_program(self->it);
		Py_DECREF(container_of(prog, Program, prog));
		drgn_module_iterator_destroy(self->it);
	}
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *ModuleIterator_next(ModuleIterator *self)
{
	struct drgn_error *err;
	struct drgn_module *module;
	err = drgn_module_iterator_next(self->it, &module, NULL);
	if (err)
		return set_drgn_error(err);
	if (!module)
		return NULL;
	return Module_wrap(module);
}

static PyObject *ModuleIteratorWithNew_next(ModuleIterator *self)
{
	struct drgn_error *err;
	struct drgn_module *module;
	bool new;
	err = drgn_module_iterator_next(self->it, &module, &new);
	if (err)
		return set_drgn_error(err);
	if (!module)
		return NULL;
	return Module_and_bool_wrap(module, new);
}

PyTypeObject ModuleIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._ModuleIterator",
	.tp_basicsize = sizeof(ModuleIterator),
	.tp_dealloc = (destructor)ModuleIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)ModuleIterator_next,
};

PyTypeObject ModuleIteratorWithNew_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._ModuleIteratorWithNew",
	.tp_basicsize = sizeof(ModuleIterator),
	.tp_dealloc = (destructor)ModuleIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)ModuleIteratorWithNew_next,
};
