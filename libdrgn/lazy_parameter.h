// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Parameter internals.
 *
 * See @ref ParameterInternals.
 */

#ifndef DRGN_LAZY_PARAMETER_H
#define DRGN_LAZY_PARAMETER_H

#include "drgn.h"
#include "type.h"
#include "object.h"

/**
 * @ingroup Internals
 *
 * @defgroup ParameterInternals Parameters
 *
 * Paramter internals.
 *
 * This provides internal helpers for creating and accessing parameters.
 * @{
 */

/**
 * Get whether a @ref drgn_lazy_parameter has been evaluated.
 *
 * @param[in] lazy_parameter Lazy parameter to check.
 * @return Whether the lazy parameter is evaluated.
 */
static inline bool drgn_lazy_parameter_is_evaluated(struct drgn_lazy_parameter *lazy_parameter)
{
	return lazy_parameter->qualifiers != (enum drgn_qualifiers)-1;
}

/**
 * Validate a @ref drgn_program matches the one in a @ref drgn_lazy_parameter.
 *
 * @param[in] lazy_parameter Lazy parameter to validate.
 * @param[in] prog The program to compare against..
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_lazy_parameter_check_prog(struct drgn_lazy_parameter *lazy_parameter,
			       struct drgn_program *prog);

/**
 * Create a @ref drgn_lazy_parameter corresponding to a type from
 * a @ref drgn_type_thunk.
 *
 * @param[out] lazy_parameter Lazy parameter to initialize as a type.
 * @param[in] thunk Type thunk to wrap.
 */
static inline void drgn_lazy_parameter_init_type_thunk(struct drgn_lazy_parameter *lazy_parameter,
						       struct drgn_type_thunk *thunk)
{
	lazy_parameter->type_thunk = thunk;
	lazy_parameter->qualifiers = -1;
	lazy_parameter->is_object = false;
}

/**
 * Create a @ref drgn_lazy_parameter from a @ref drgn_object_thunk.
 *
 * @param[out] lazy_parameter Lazy parameter to initialize as a object.
 * @param[in] thunk Thunk to wrap.
 */
static inline void drgn_lazy_parameter_init_object_thunk(struct drgn_lazy_parameter *lazy_parameter,
							 struct drgn_object_thunk *thunk)
{
	lazy_parameter->object_thunk = thunk;
	lazy_parameter->qualifiers = -1;
	lazy_parameter->is_object = true;
}

/**
 * Create a @ref drgn_lazy_parameter from a @ref drgn_type and qualifiers.
 *
 * @param[out] lazy_parameter Lazy parameter to initialize as a type.
 * @param[in] type Type to wrap. May be @c NULL.
 * @param[in] qualifiers Type qualifiers. Must be 0 if type is @c NULL. Must not
 * be -1.
 */
static inline void
drgn_lazy_parameter_init_type(struct drgn_lazy_parameter *lazy_parameter,
			      struct drgn_type *type,
			      enum drgn_qualifiers qualifiers)
{
	if (!type)
		assert(!qualifiers);
	assert(qualifiers != (enum drgn_qualifiers)-1);
	lazy_parameter->type = type;
	lazy_parameter->qualifiers = qualifiers;
	lazy_parameter->is_object = false;
}

/**
 * Create a @ref drgn_lazy_parameter from a @ref drgn_object and qualifiers.
 *
 * @param[out] lazy_parameter Lazy parameter to initialize as a object.
 * @param[in] object Object to wrap. May be @c NULL.
 * @param[in] qualifiers Object qualifiers. Must be 0 if object is @c NULL. Must not
 * be -1.
 */
static inline struct drgn_error
*drgn_lazy_parameter_init_object(struct drgn_lazy_parameter *lazy_object,
				 struct drgn_object *object)
{
	// Freed by drgn_program_deinit_types
	struct drgn_object *new_obj = malloc(sizeof(*new_obj));
	if (!new_obj)
		return &drgn_enomem;
	drgn_object_init(new_obj, drgn_object_program(object));
	drgn_object_copy(new_obj, object);
	lazy_object->object = new_obj;
	lazy_object->qualifiers = 0;
	lazy_object->is_object = true;
	return NULL;
}

/**
 * Free a @ref drgn_lazy_parameter.
 *
 * If the parameter has not been evaluted, this frees the @ref drgn_type_thunk
 * or @ref drgn_object_thunk. Otherwise, this is a no-op.
 *
 * @param[in] lazy_parameter Lazy parameter to free.
 */
void drgn_lazy_parameter_deinit(struct drgn_lazy_parameter *lazy_parameter);


/**
 * Evaluate a @ref drgn_lazy_parameter to a @ref drgn_qualified_type.
 *
 * If this succeeds, the lazy parameter is considered evaluated and future calls will
 * always succeed and return the cached result. If this fails, the lazy parameter
 * remains in a valid, unevaluated state.
 *
 * @param[in] lazy_parameter Lazy parameter to evaluate.
 * @param[out] ret Evaluated type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_lazy_parameter_get_type(struct drgn_lazy_parameter *lazy_parameter,
						struct drgn_qualified_type *ret);

/**
 * Evaluate a @ref drgn_lazy_parameter to a @ref drgn_object.
 *
 * If this succeeds, the lazy parameter is considered evaluated and future calls will
 * always succeed and return the cached result. If this fails, the lazy parameter
 * remains in a valid, unevaluated state.
 *
 * @param[in] lazy_parameter Lazy parameter to evaluate.
 * @param[out] ret Evaluated object.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_lazy_parameter_get_object(struct drgn_lazy_parameter *lazy_parameter,
						  struct drgn_object *ret);

/**
 * Evaluate a @ref drgn_lazy_parameter to a @ref drgn_qualified_type, converting if needed.
 *
 * If this succeeds, the lazy parameter is considered evaluated and future calls will
 * always succeed and return the cached result. If this fails, the lazy parameter
 * remains in a valid, unevaluated state.
 *
 * @param[in] lazy_parameter Lazy parameter to evaluate.
 * @param[out] ret Evaluated type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error
*drgn_lazy_parameter_evaluate_type(struct drgn_lazy_parameter *parameter,
				   struct drgn_qualified_type *ret);

/** @} */

#endif /* DRGN_LAZY_PARAMETER_H */
