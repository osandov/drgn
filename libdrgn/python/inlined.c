#include "drgnpy.h"
#include "../dwarf_info.h"

static PyObject *InlinedInstance_get_die_addr(InlinedInstance *self)
{
	return PyLong_FromUnsignedLongLong(self->instance.die_addr);
}

static PyObject *InlinedInstance_get_entry_pc(InlinedInstance *self)
{
	return PyLong_FromUnsignedLongLong(self->instance.entry_pc);
}

static PyGetSetDef InlinedInstance_getset[] = {
	{"die_addr", (getter)InlinedInstance_get_die_addr, NULL, NULL},
	{"entry_pc", (getter)InlinedInstance_get_entry_pc, NULL, NULL},
	{},
};

PyTypeObject InlinedInstance_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.InlinedInstance",
	.tp_basicsize = sizeof(InlinedInstance),
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_getset = InlinedInstance_getset,
};

static PyObject *InlinedInstance_wrap(struct drgn_inlined_instance *instance)
{
	InlinedInstance *ret = (InlinedInstance *)InlinedInstance_type.tp_alloc(
		&InlinedInstance_type, 0);
	if (!ret)
		return NULL;
	ret->instance = *instance;
	return (PyObject *)ret;
}

static PyObject *InlinedGroup_get_die_addr(InlinedGroup *self)
{
	return PyLong_FromUnsignedLongLong(self->group.die_addr);
}

static PyObject *InlinedGroup_get_name(InlinedGroup *self)
{
	return PyUnicode_FromString(self->group.name);
}

static PyObject *InlinedGroup_get_linkage_name(InlinedGroup *self)
{
	return PyUnicode_FromString(self->group.linkage_name);
}

static PyObject *InlinedGroup_get_inlined_instances(InlinedGroup *self)
{
	PyObject *inlined_instances =
		PyList_New(self->group.num_inlined_instances);
	if (!inlined_instances)
		return NULL;
	for (Py_ssize_t i = 0; i < self->group.num_inlined_instances; i++) {
		PyObject *instance =
			InlinedInstance_wrap(&self->group.inlined_instances[i]);
		if (!instance) {
			Py_DECREF(inlined_instances);
			return NULL;
		}
		PyList_SET_ITEM(inlined_instances, i, instance);
	}
	return inlined_instances;
}

static void InlinedGroup_dealloc(InlinedGroup *self)
{
	drgn_inlined_group_deinit(&self->group);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyGetSetDef InlinedGroup_getset[] = {
	{"die_addr", (getter)InlinedGroup_get_die_addr, NULL, NULL},
	{"name", (getter)InlinedGroup_get_name, NULL, NULL},
	{"linkage_name", (getter)InlinedGroup_get_linkage_name, NULL, NULL},
	{"inlined_instances", (getter)InlinedGroup_get_inlined_instances, NULL, NULL},
	{},
};

PyTypeObject InlinedGroup_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn.InlinedGroup",
	.tp_basicsize = sizeof(InlinedGroup),
	.tp_dealloc = (destructor)InlinedGroup_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_getset = InlinedGroup_getset,
};

static PyObject *InlinedGroup_wrap(struct drgn_inlined_group *group)
{
	InlinedGroup *ret = (InlinedGroup *)InlinedGroup_type.tp_alloc(
		&InlinedGroup_type, 0);
	if (!ret)
		return NULL;
	struct drgn_error *err =
		drgn_inlined_group_dup_internal(group, &ret->group);
	if (err) {
		Py_DECREF(ret);
		return set_drgn_error(err);
	}
	return (PyObject *)ret;
}

static void InlinedFunctionsIterator_dealloc(InlinedFunctionsIterator *self)
{
	Py_XDECREF(self->prog);
	drgn_inlined_functions_iterator_destroy(self->iterator);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *InlinedFunctionsIterator_next(InlinedFunctionsIterator *self)
{
	struct drgn_inlined_group *group;
	struct drgn_error *err =
		drgn_inlined_functions_iterator_next(self->iterator, &group);
	if (err)
		return set_drgn_error(err);
	if (!group)
		return NULL;
	return InlinedGroup_wrap(group);
}

PyTypeObject InlinedFunctionsIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_drgn._InlinedFunctionsIterator",
	.tp_basicsize = sizeof(InlinedFunctionsIterator),
	.tp_dealloc = (destructor)InlinedFunctionsIterator_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)InlinedFunctionsIterator_next,
};
