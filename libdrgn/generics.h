// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Helpers for generic programming.
 */

#ifndef DRGN_GENERICS_H
#define DRGN_GENERICS_H

/**
 * Choose a type based on a condition.
 *
 * @param[in] condition Controlling integer constant expression.
 * @param[in] if_true Type if @p condition is non-zero.
 * @param[in] if_false Type if @p condition is zero.
 */
#define type_if(condition, if_true, if_false)			\
__typeof__(							\
       /* + 1 avoids a non-standard zero-length array. */	\
       *_Generic((int (*)[!(condition) + 1])0,			\
		 int (*)[1]: (__typeof__(if_true) *)0,		\
		 int (*)[2]: (__typeof__(if_false) *)0)		\
)

/**
 * Define a typedef based on a condition.
 *
 * @param[in] name Name of type.
 * @param[in] condition Controlling integer constant expression.
 * @param[in] if_true Type if @p condition is non-zero.
 * @param[in] if_false Type if @p condition is zero.
 */
#define typedef_if(name, condition, if_true, if_false)		\
	typedef type_if(condition, if_true, if_false) name

#endif /* DRGN_GENERICS_H */
