// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Helpers for C arrays.
 */

#ifndef DRGN_ARRAY_H
#define DRGN_ARRAY_H

#include "pp.h"
#include "util.h"

/** @cond */
#define array_for_each_impl(var, arr, unique_end)	\
	for (typeof((arr)[0]) *var = (arr),		\
	     *unique_end = var + array_size(arr);	\
	     var < unique_end; var++)
/** @endcond */

/**
 * Return the number of elements in an array.
 *
 * @hideinitializer
 */
#define array_size(arr)							\
	static_assert_expression(is_array(arr),				\
				 "not an array",			\
				 sizeof(arr) / sizeof((arr)[0]))

/**
 * Iterate over every element in an array.
 *
 * The element is declared as `element_type *var` in the scope of the loop.
 *
 * @hideinitializer
 */
#define array_for_each(var, arr)	\
	array_for_each_impl(var, arr, PP_UNIQUE(end))

#endif /* DRGN_ARRAY_H */
