// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

#include "lazy_parameter.h"

void drgn_lazy_parameter_deinit(struct drgn_lazy_parameter *lazy_parameter)
{
	if (lazy_parameter->is_object) {
		if (!drgn_lazy_parameter_is_evaluated(lazy_parameter))
			drgn_object_thunk_free(lazy_parameter->object_thunk);
		else
			free(lazy_parameter->object);
	} else
		if (!drgn_lazy_parameter_is_evaluated(lazy_parameter))
			drgn_type_thunk_free(lazy_parameter->type_thunk);
}

inline struct drgn_error *
drgn_lazy_parameter_check_prog(struct drgn_lazy_parameter *lazy_parameter,
			       struct drgn_program *prog)
{
	if (lazy_parameter->is_object) {
		if ((drgn_lazy_parameter_is_evaluated(lazy_parameter) ?
		     drgn_type_program(lazy_parameter->object->type) :
		     lazy_parameter->object_thunk->prog) != prog) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "object is from different program");
		}
	} else {
		if ((drgn_lazy_parameter_is_evaluated(lazy_parameter) ?
		     drgn_type_program(lazy_parameter->type) :
		     lazy_parameter->type_thunk->prog) != prog) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "type is from different program");
		}
	}
	return NULL;
}

struct drgn_error
*drgn_lazy_parameter_evaluate_type(struct drgn_lazy_parameter *parameter,
				   struct drgn_qualified_type *ret) {
	struct drgn_error *err;
	if (!parameter->is_object)
		return drgn_lazy_parameter_get_type(parameter, ret);
	struct drgn_object obj;
	if ((err = drgn_lazy_parameter_get_object(parameter, &obj)))
		return err;
	ret->type = obj.type;
	ret->qualifiers = parameter->qualifiers;
	return NULL;
}

struct drgn_error *drgn_lazy_parameter_get_type(struct drgn_lazy_parameter *lazy_parameter,
						struct drgn_qualified_type *ret)
{
	if (drgn_lazy_parameter_is_evaluated(lazy_parameter)) {
		ret->type = lazy_parameter->type;
		ret->qualifiers = lazy_parameter->qualifiers;
	} else {
		struct drgn_type_thunk *thunk_ptr = lazy_parameter->type_thunk;
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

struct drgn_error *drgn_lazy_parameter_get_object(struct drgn_lazy_parameter *lazy_parameter,
						  struct drgn_object *ret) {
	if (!drgn_lazy_parameter_is_evaluated(lazy_parameter)) {
		struct drgn_object obj;
		struct drgn_object_thunk *thunk_ptr = lazy_parameter->object_thunk;
		struct drgn_object_thunk thunk = *thunk_ptr;
		drgn_object_init(&obj, thunk.prog);
		struct drgn_error *err = thunk.evaluate_fn(thunk_ptr, &obj);
		if (err)
			return err;
		drgn_lazy_parameter_init_object(lazy_parameter, &obj);
		thunk.free_fn(thunk_ptr);
	}
	drgn_object_init(ret, drgn_object_program(lazy_parameter->object));
	drgn_object_copy(ret, lazy_parameter->object);
	*ret = *lazy_parameter->object;
	return NULL;
}
