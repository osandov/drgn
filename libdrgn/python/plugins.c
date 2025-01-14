// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "drgnpy.h"
#include "../plugins.h"

void drgn_call_plugins_prog(const char *name, struct drgn_program *prog)
{
	PyGILState_guard();

	static PyObject *call_plugins;
	if (!call_plugins) {
		_cleanup_pydecref_ PyObject *_drgn_util_plugins_module =
			PyImport_ImportModule("_drgn_util.plugins");
		if (!_drgn_util_plugins_module) {
			PyErr_WriteUnraisable(NULL);
			return;
		}
		call_plugins = PyObject_GetAttrString(_drgn_util_plugins_module,
						      "call_plugins");
		if (!call_plugins) {
			PyErr_WriteUnraisable(NULL);
			return;
		}
	}

	Program *prog_obj = container_of(prog, Program, prog);
	_cleanup_pydecref_ PyObject *res =
		PyObject_CallFunction(call_plugins, "sO", name, prog_obj);
	if (!res)
		PyErr_WriteUnraisable(call_plugins);
}
