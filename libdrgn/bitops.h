// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Bitwise operations.
 *
 * See @ref BitwiseOperations.
 */

#ifndef DRGN_BITOPS_H
#define DRGN_BITOPS_H

#include "pp.h"

/**
 * @ingroup Internals
 *
 * @defgroup BitwiseOperations Bitwise operations
 *
 * Generic bitwise operations.
 *
 * @{
 */

/**
 * Count Trailing Zero bits.
 *
 * Return the number of trailing least significant 0-bits in @p x. This is
 * undefined if @p x is zero.
 *
 * ```
 * ctz(1) == ctz(0b1) == 0
 * ctz(2) == ctz(0b10) == 1
 * ctz(12) == ctz(0b1100) == 2
 * ```
 *
 * @param[in] x Integer.
 */
#define ctz(x) generic_bitop(x, PP_UNIQUE(_x), builtin_bitop_impl, ctz)

/**
 * Find Last Set bit.
 *
 * Return the one-based index of the most significant 1-bit of @p x or 0 if @p x
 * is 0.
 *
 * ```
 * fls(0) == fls(0b0) == 0
 * fls(1) == fls(0b1) == 1
 * fls(13) == fls(0b1101) == 4
 * ```
 *
 * For unsigned integers,
 * ```
 * fls(x) = floor(log2(x)) + 1, if x > 0
 *          0, if x == 0
 * ```
 *
 * @param[in] x Integer.
 */
#define fls(x) generic_bitop(x, PP_UNIQUE(_x), fls_impl,)
/** @cond */
/*
 * The straightfoward implementation is bits - clz. However, as noted by the
 * folly implementation: "If X is a power of two, X - Y = 1 + ((X - 1) ^ Y).
 * Doing this transformation allows GCC to remove its own xor that it adds to
 * implement clz using bsr."
 *
 * This doesn't do the normal macro argument safety stuff because it should only
 * be used via generic_bitop() which already does it.
 */
#define fls_impl(arg, suffix, x)	\
	(x ? 1 + ((8 * sizeof(0u##suffix) - 1) ^ __builtin_clz##suffix(x)) : 0)

#define builtin_bitop_impl(arg, suffix, x) __builtin_##arg##suffix(x)
#define generic_bitop(x, unique_x, impl, impl_arg) ({			\
	__auto_type unique_x = (x);					\
	_Static_assert(sizeof(unique_x) <= sizeof(unsigned long long),	\
		       "type is too large");				\
	(unsigned int)(sizeof(unique_x) <= sizeof(unsigned int) ?	\
		       impl(impl_arg, , unique_x) :			\
		       sizeof(unique_x) <= sizeof(unsigned long) ?	\
		       impl(impl_arg, l, unique_x) :			\
		       impl(impl_arg, ll, unique_x));			\
})
/** @endcond */

/**
 * Return the smallest power of two greater than or equal to @p x.
 *
 * ```
 * next_power_of_two(0) == 1 // Zero is not a power of two
 * next_power_of_two(1) == 1
 * next_power_of_two(13) == 16
 * ```
 *
 * @param[in] x Integer.
 */
#define next_power_of_two(x) next_power_of_two_impl(x, PP_UNIQUE(_x))
/** @cond */
#define next_power_of_two_impl(x, unique_x) ({			\
	__auto_type unique_x = (x);				\
	unique_x ? (typeof(unique_x))1 << fls(unique_x - 1) :	\
	(typeof(unique_x))1;					\
})
/** @endcond */

/**
 * Iterate over each 1-bit in @p mask.
 *
 * On each iteration, this sets @p i to the zero-based index of the least
 * significant 1-bit in @p mask and clears that bit in @p mask. It stops
 * iterating when @p mask is zero.
 *
 * ```
 * // Outputs 0 2 3
 * unsigned int mask = 13, i;
 * for_each_bit(i, mask)
 *         printf("%u ", i);
 * ```
 *
 * @param[out] i Iteration variable name.
 * @param[in,out] mask Integer to iterate over. This is modified.
 */
#define for_each_bit(i, mask)	\
	while (mask && (i = ctz(mask), mask &= mask - 1, 1))

/** @} */

#endif /* DRGN_BITOPS_H */
