// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include "lazy_parameter.h"

void drgn_lazy_parameter_deinit(struct drgn_lazy_parameter *lazy_parameter)
{
	if (!drgn_lazy_parameter_is_evaluated(lazy_parameter))
		drgn_type_thunk_free(lazy_parameter->thunk);
}

inline struct drgn_error *
drgn_lazy_parameter_check_prog(struct drgn_lazy_parameter *lazy_parameter,
			       struct drgn_program *prog)
{
	if ((drgn_lazy_parameter_is_evaluated(lazy_parameter) ?
	     drgn_type_program(lazy_parameter->type) :
	     lazy_parameter->thunk->prog) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "type is from different program");
	}
	return NULL;
}

struct drgn_error *drgn_lazy_parameter_get_type(struct drgn_lazy_parameter *lazy_parameter,
						struct drgn_qualified_type *ret)
{
	if (drgn_lazy_parameter_is_evaluated(lazy_parameter)) {
		ret->type = lazy_parameter->type;
		ret->qualifiers = lazy_parameter->qualifiers;
	} else {
		struct drgn_type_thunk *thunk_ptr = lazy_parameter->thunk;
		struct drgn_type_thunk thunk = *thunk_ptr;
		struct drgn_error *err = thunk.evaluate_fn(thunk_ptr, ret);
		if (err)
			return err;
		if (drgn_type_program(ret->type) != thunk.prog) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "type is from different program");
		}
		drgn_lazy_parameter_init_type(lazy_parameter, ret->type,
					      ret->qualifiers);
		thunk.free_fn(thunk_ptr);
	}
	return NULL;
}

