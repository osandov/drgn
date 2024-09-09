// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Generic binary search macros.
 *
 * See @ref BinarySearch.
 */

#ifndef DRGN_BISECT_H
#define DRGN_BISECT_H

#include <stdbool.h>
#include <stddef.h>

#include "pp.h"

/**
 * @ingroup Internals
 *
 * @defgroup BinarySearch Binary search
 *
 * Generic binary search macros.
 *
 * @{
 */

#if DOXYGEN
/**
 * Return the index of the first element greater than or equal to a given value
 * in a sorted array.
 *
 * If all elements are less than @p value, this returns @p size.
 *
 * This can be used to find an exact match:
 *
 * ```
 * int array[] = { 1, 2, 3 };
 * size_t size = 3;
 * int value = 2;
 * size_t i = binary_search_ge(array, size, &value, scalar_less);
 * if (i < size && array[i] == value)
 *         printf("Found at %zu\n", i);
 * else
 *         printf("Not found\n");
 * ```
 *
 * This is equivalent to Python's
 * [`bisect.bisect_left()`](https://docs.python.org/3/library/bisect.html#bisect.bisect_left)
 * and C++'s
 * [`std::lower_bound()`](https://en.cppreference.com/w/cpp/algorithm/lower_bound).
 *
 * @param[in] array Sorted array. (Technically, this only needs to be
 * partitioned such that all elements where `less(elem, value)` is `true` are
 * before all elements where `less(elem, value)` is `false`.)
 * @param[in] size Number of elements in @p array.
 * @param[in] value Pointer to value to compare elements to.
 * @param[in] less Comparison function or macro taking a pointer to an array
 * element and @p value and returning `true` if and only if the element is
 * ordered before (i.e., less than) the value. This may be evaluated/expanded
 * more than once.
 * @return `i` such that `less(&array[j], value)` is `true` for `0 <= j < i` and
 * `false` for `i <= j < size`.
 */
size_t binary_search_ge(const E *array, size_t size, const V *value,
			bool (*less)(const E *, const V *));
#else
#define binary_search_ge(array_arg, nmemb_arg, key_arg, less)			\
	binary_search_ge_i(array_arg, nmemb_arg, key_arg, less,			\
			   PP_UNIQUE(array), PP_UNIQUE(key), PP_UNIQUE(lo),	\
			   PP_UNIQUE(hi), PP_UNIQUE(mid))
#define binary_search_ge_i(array_arg, nmemb_arg, key_arg, less, array, key, lo,	\
			   hi, mid)						\
({										\
	__auto_type key = (key_arg);						\
	__auto_type array = (array_arg);					\
	size_t lo = 0;								\
	size_t hi = (nmemb_arg);						\
	while (lo < hi) {							\
		size_t mid = lo + (hi - lo) / 2;				\
		if (less(&array[mid], key))					\
			lo = mid + 1;						\
		else								\
			hi = mid;						\
	}									\
	lo;									\
})
#endif

#if DOXYGEN
/**
 * Return the index of the first element greater than a given value in a sorted
 * array.
 *
 * If all elements are less than or equal to @p value, this returns @p size.
 *
 * This can be used to find the range containing a value in an array of range
 * starting points:
 *
 * ```
 * int array[] = { 10, 20, 30 };
 * size_t size = 3;
 * int value = 15;
 * size_t i = binary_search_gt(array, size, &value, scalar_less);
 * if (i > 0)
 *         printf("Found in %zu\n", i - 1);
 * else
 *         printf("Not found\n");
 * ```
 *
 * This is equivalent to Python's
 * [`bisect.bisect_right()`](https://docs.python.org/3/library/bisect.html#bisect.bisect_right)
 * and C++'s
 * [`std::upper_bound()`](https://en.cppreference.com/w/cpp/algorithm/upper_bound).
 *
 * @param[in] array Sorted array. (Technically, this only needs to be
 * partitioned such that all elements where `less(value, elem)` is `false` are
 * before all elements where `less(value, elem)` is `true`.)
 * @param[in] size Number of elements in @p array.
 * @param[in] value Pointer to value to compare elements to.
 * @param[in] less Comparison function or macro taking @p value and a pointer to
 * an array element and returning `true` if and only if the value is ordered
 * before (i.e., less than) the element. This may be evaluated/expanded more
 * than once.
 * @return `i` such that `less(value, &array[j])` is `false` for `0 <= j < i`
 * and `true` for `i <= j < size`.
 */
size_t binary_search_gt(const E *array, size_t size, const V *value,
			bool (*less)(const V *, const E *));
#else
#define binary_search_gt(array_arg, size_arg, value_arg, less)			\
	binary_search_gt_i(array_arg, size_arg, value_arg, less,		\
			   PP_UNIQUE(array), PP_UNIQUE(value), PP_UNIQUE(lo),	\
			   PP_UNIQUE(hi), PP_UNIQUE(mid))
#define binary_search_gt_i(array_arg, size_arg, value_arg, less, array, value,	\
			   lo, hi, mid)						\
({										\
	__auto_type array = (array_arg);					\
	__auto_type value = (value_arg);					\
	size_t lo = 0;								\
	size_t hi = (size_arg);							\
	while (lo < hi) {							\
		size_t mid = lo + (hi - lo) / 2;				\
		if (less(value, &array[mid]))					\
			hi = mid;						\
		else								\
			lo = mid + 1;						\
	}									\
	lo;									\
})
#endif

/**
 * Compare two scalars (e.g., integers, floating-point numbers, pointers) for
 * @ref binary_search_ge() or @ref binary_search_gt().
 */
#define scalar_less(a, b) (*(a) < *(b))

/** @} */

#endif /* DRGN_BISECT_H */
