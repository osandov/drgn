// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

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
#define __must_be_array(a) BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

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
#define array_size(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

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
