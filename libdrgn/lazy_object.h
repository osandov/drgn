// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Lazy objects.
 *
 * See @ref LazyObjects.
 */

#ifndef DRGN_LAZY_OBJECT_H
#define DRGN_LAZY_OBJECT_H

#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup LazyObjects Lazy objects
 *
 * Lazily-evaluated objects.
 *
 * The graph of objects and types in a program can be very deep (and often
 * cyclical), so drgn lazily evaluates objects in some cases.
 *
 * @{
 */

/**
 * Initialize an unevaluated @ref drgn_lazy_object.
 *
 * @param[out] lazy_obj Lazy object to initialize.
 * @param[in] prog Program owning the lazy object.
 * @param[in] fn Thunk callback.
 * @param[in] arg Argument to pass to @p fn.
 */
static inline void
drgn_lazy_object_init_thunk(union drgn_lazy_object *lazy_obj,
			    struct drgn_program *prog, drgn_object_thunk_fn *fn,
			    void *arg)
{
	lazy_obj->thunk.dummy_type = NULL;
	lazy_obj->thunk.prog = prog;
	lazy_obj->thunk.fn = fn;
	lazy_obj->thunk.arg = arg;
}

/** Return whether a @ref drgn_lazy_object has been evaluated. */
static inline bool
drgn_lazy_object_is_evaluated(const union drgn_lazy_object *lazy_obj)
{
	return lazy_obj->obj.type != NULL;
}

/**
 * Evaluate a @ref drgn_lazy_object.
 *
 * If this success, then the lazy object is considered evaluated and future
 * calls will always succeed. If this fails, then the lazy object remains in a
 * valid, unevaluated state.
 */
struct drgn_error *drgn_lazy_object_evaluate(union drgn_lazy_object *lazy_obj);

/**
 * Free a @ref drgn_lazy_object.
 *
 * If the object has been evaluated, then this deinitializes @ref
 * drgn_lazy_object::obj. Otherwise, this calls @ref drgn_lazy_object::fn to
 * free @ref drgn_lazy_object::arg.
 */
void drgn_lazy_object_deinit(union drgn_lazy_object *lazy_obj);

/**
 * Check whether a @ref drgn_lazy_object belongs to a given @ref drgn_program.
 *
 * @return @c NULL if the program matches, non-@c NULL if not.
 */
struct drgn_error *
drgn_lazy_object_check_prog(const union drgn_lazy_object *lazy_obj,
			    struct drgn_program *prog);

/** @} */

#endif /* DRGN_LAZY_OBJECT_H */
