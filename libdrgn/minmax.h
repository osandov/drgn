// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Minimum/maximum operations.
 *
 * See @ref MinMaxOperations.
 */

#ifndef DRGN_MINMAX_H
#define DRGN_MINMAX_H

#include "pp.h"

/**
 * @ingroup Internals
 *
 * @defgroup MinMaxOperations Minimum/maximum operations
 *
 * Generic minimum/maximum operations.
 *
 * @{
 */

/** Get the minimum of two expressions with compatible types. */
#define min(x, y) cmp_once_impl(x, y, PP_UNIQUE(_x), PP_UNIQUE(_y), <)
/** Get the maximum of two expressions with compatible types. */
#define max(x, y) cmp_once_impl(x, y, PP_UNIQUE(_x), PP_UNIQUE(_y), >)
/** @cond */
#define cmp_once_impl(x, y, unique_x, unique_y, op) ({				\
	__auto_type unique_x = (x);						\
	__auto_type unique_y = (y);						\
	/* Generate a warning if x and y do not have compatible types. */	\
	(void)(&unique_x == &unique_y);						\
	unique_x op unique_y ? unique_x : unique_y;				\
})
/** @endcond */

/**
 * Get the minimum of two integer constant expressions with compatible types,
 * resulting in an integer constant expression.
 */
#define min_iconst(x, y) cmp_iconst_impl(x, y, <)
/**
 * Get the maximum of two integer constant expressions with compatible types,
 * resulting in an integer constant expression.
 */
#define max_iconst(x, y) cmp_iconst_impl(x, y, >)
/** @cond */
#define cmp_iconst_impl(x, y, op)						\
	/*									\
	 * Enforce that the arguments are integer constant expressions. The	\
	 * size of a non-VLA array must be an integer constant expression, and	\
	 * a compound literal cannot be a VLA. Evaluates to non-zero to fall	\
	 * through to the next check.						\
	 */									\
	(sizeof((char [(x) * 0 + (y) * 0 + 1]){0}) &&				\
	/*									\
	 * Generate a warning if x and y do not have compatible types.		\
	 * Evaluates to non-zero to fall through to the comparison.		\
	 */									\
	 sizeof((typeof(x) *)1 == (typeof(y) *)1) &&				\
	 (x) op (y) ? (x) : (y))
/** @endcond */

/** @} */

#endif /* DRGN_MINMAX_H */
