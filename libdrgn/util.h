// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: GPL-3.0+

/**
 * @file
 *
 * Miscellanous utility functions.
 *
 * Several of these are taken from the Linux kernel source.
 */

#ifndef DRGN_UTIL_H
#define DRGN_UTIL_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef NDEBUG
#define UNREACHABLE() __builtin_unreachable()
#else
#define UNREACHABLE() assert(!"reachable")
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#if defined(__GNUC__) && !defined(__clang__) && !defined(__INTEL_COMPILER)
#define __compiletime_error(message) __attribute__((__error__(message)))
#else
#define __compiletime_error(message)
#endif
#ifdef __OPTIMIZE__
# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
#else
# define __compiletime_assert(condition, msg, prefix, suffix) do { } while (0)
#endif
#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)

#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:(-!!(e)); }))
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

#define ___PASTE(a,b) a##b
#define __PASTE(a,b) ___PASTE(a,b)

#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)

#define __typecheck(x, y) \
		(!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))

#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

#define __no_side_effects(x, y) \
	(__is_constexpr(x) && __is_constexpr(y))

#define __safe_cmp(x, y) \
	(__typecheck(x, y) && __no_side_effects(x, y))

#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))

#define __cmp_once(x, y, unique_x, unique_y, op) ({	\
		typeof(x) unique_x = (x);		\
		typeof(y) unique_y = (y);		\
		__cmp(unique_x, unique_y, op); })

#define __careful_cmp(x, y, op) \
	__builtin_choose_expr(__safe_cmp(x, y), \
		__cmp(x, y, op), \
		__cmp_once(x, y, __UNIQUE_ID(__x), __UNIQUE_ID(__y), op))

#define min(x, y)	__careful_cmp(x, y, <)

#define max(x, y)	__careful_cmp(x, y, >)

#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

#define __bitop(x, unique_x, op) ({					\
	__auto_type unique_x = (x);					\
	static_assert(sizeof(unique_x) <= sizeof(unsigned long long),	\
		      "type is too large");				\
	(unsigned int)(sizeof(unique_x) <= sizeof(unsigned int) ?	\
		       op(unique_x) :					\
		       sizeof(unique_x) <= sizeof(unsigned long) ?	\
		       op##l(unique_x) :				\
		       op##ll(unique_x));				\
})

/**
 * Return the number of trailing least significant 0-bits in @p x. This is
 * undefined if @p x is zero.
 */
#define ctz(x) __bitop(x, __UNIQUE_ID(__x), __builtin_ctz)

/*
 * The straightfoward implementation is bits - clz. However, as noted by the
 * folly implementation: "If X is a power of two, X - Y = 1 + ((X - 1) ^ Y).
 * Doing this transformation allows GCC to remove its own xor that it adds to
 * implement clz using bsr."
 *
 * This doesn't do the normal macro argument safety stuff because it should only
 * be used via __bitop() which already does it.
 */
#define ____fls(x, type, suffix)	\
	(x ? 1 + ((8 * sizeof(type) - 1) ^ __builtin_clz##suffix(x)) : 0)
#define __fls(x) ____fls(x, unsigned int,)
#define __flsl(x) ____fls(x, unsigned long, l)
#define __flsll(x) ____fls(x, unsigned long long, ll)

/**
 * Return one plus the index of the most significant 1-bit of @p x or 0 if @p x
 * is 0.
 */
#define fls(x) __bitop(x, __UNIQUE_ID(__x), __fls)

#define __next_power_of_two(x, unique_x) ({			\
	__auto_type unique_x = (x);				\
								\
	unique_x ? (typeof(unique_x))1 << fls(unique_x - 1) :	\
	(typeof(unique_x))1;					\
})

/**
 * Return the smallest power of two greater than or equal to @p x.
 *
 * Note that zero is not a power of two, so <tt>next_power_of_two(0) == 1</tt>.
 */
#define next_power_of_two(x) __next_power_of_two(x, __UNIQUE_ID(__x))

/** Iterate over each 1-bit in @p mask. This modifies @c mask. */
#define for_each_bit(i, mask)	\
	for (i = -1; mask && (i = ctz(mask), mask &= mask - 1, 1);)

static inline bool strstartswith(const char *s, const char *prefix)
{
	return strncmp(s, prefix, strlen(prefix)) == 0;
}

static inline void *malloc_array(size_t nmemb, size_t size)
{
	size_t bytes;

	if (__builtin_mul_overflow(nmemb, size, &bytes)) {
		errno = ENOMEM;
		return NULL;
	}
	return malloc(bytes);
}

static inline void *malloc64(uint64_t size)
{
	if (size > SIZE_MAX)
		return NULL;
	return malloc(size);
}

#endif /* DRGN_UTIL_H */
