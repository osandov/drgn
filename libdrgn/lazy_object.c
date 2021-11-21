// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>

#include "lazy_object.h"

static_assert(offsetof(union drgn_lazy_object, obj.type) ==
	      offsetof(union drgn_lazy_object, thunk.dummy_type),
	      "drgn_lazy_object layout is invalid");

struct drgn_error *drgn_lazy_object_evaluate(union drgn_lazy_object *lazy_obj)
{
	struct drgn_error *err;
	if (!drgn_lazy_object_is_evaluated(lazy_obj)) {
		struct drgn_program *prog = lazy_obj->thunk.prog;
		drgn_object_thunk_fn *fn = lazy_obj->thunk.fn;
		void *arg = lazy_obj->thunk.arg;
		drgn_object_init(&lazy_obj->obj, prog);
		err = fn(&lazy_obj->obj, arg);
		if (err) {
			/* Oops, revert back to a thunk so it can be retried. */
			drgn_lazy_object_init_thunk(lazy_obj, prog, fn, arg);
			return err;
		}
	}
	return NULL;
}

void drgn_lazy_object_deinit(union drgn_lazy_object *lazy_obj)
{
	if (drgn_lazy_object_is_evaluated(lazy_obj))
		drgn_object_deinit(&lazy_obj->obj);
	else
		lazy_obj->thunk.fn(NULL, lazy_obj->thunk.arg);
}

struct drgn_error *
drgn_lazy_object_check_prog(const union drgn_lazy_object *lazy_obj,
			    struct drgn_program *prog)
{
	if ((drgn_lazy_object_is_evaluated(lazy_obj) ?
	     drgn_object_program(&lazy_obj->obj) : lazy_obj->thunk.prog)
	    != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "object is from different program");
	}
	return NULL;
}
