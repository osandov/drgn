// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Miscellanous utility functions.
 */

#ifndef DRGN_UTIL_H
#define DRGN_UTIL_H

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef LIBDRGN_PUBLIC
#define LIBDRGN_PUBLIC __attribute__((__visibility__("default")))
#endif

#if defined(__has_attribute) && __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough do {} while (0)
#endif

#ifdef NDEBUG
#define UNREACHABLE() __builtin_unreachable()
#else
#define UNREACHABLE() assert(!"reachable")
#endif

#define HOST_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

/**
 * Switch statement with an enum controlling expression that must have a case
 * for every enumeration value and a default case.
 */
#define SWITCH_ENUM_DEFAULT(expr, ...) {			\
	_Pragma("GCC diagnostic push");				\
	_Pragma("GCC diagnostic error \"-Wswitch-enum\"");	\
	_Pragma("GCC diagnostic error \"-Wswitch-default\"");	\
	switch (expr)  {					\
	__VA_ARGS__						\
	}							\
	_Pragma("GCC diagnostic pop");				\
}

/**
 * Switch statement with an enum controlling expression that must have a case
 * for every enumeration value. The expression is assumed to have a valid
 * enumeration value. Cases which are assumed not to be possible can be placed
 * at the end of the statement.
 */
#define SWITCH_ENUM(expr, ...)		\
	SWITCH_ENUM_DEFAULT(expr,	\
	__VA_ARGS__			\
	default: UNREACHABLE();		\
	)

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/** Return whether two types or expressions have compatible types. */
#define types_compatible(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

/** Return whether an expression is an array. */
#define is_array(x) (!types_compatible(x, &(x)[0]))

/**
 * `static_assert(assert_expression, message)` as an expression that evaluates
 * to `eval_expression`.
 */
#define static_assert_expression(assert_expression, message, eval_expression)	\
	_Generic(sizeof(struct { _Static_assert(assert_expression, message); int _; }),\
		 default: (eval_expression))

#define container_of(ptr, type, member)				\
static_assert_expression(					\
	types_compatible(*(ptr), ((type *)0)->member)		\
	|| types_compatible(*(ptr), void),			\
	"pointer does not match member type",			\
	(type *)((char *)(ptr) - offsetof(type, member))	\
)

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

static inline void *malloc_flexible_array_impl(size_t struct_size,
					       size_t element_size,
					       size_t count)
{
	size_t bytes;
	if (__builtin_mul_overflow(element_size, count, &bytes)
	    || __builtin_add_overflow(bytes, struct_size, &bytes)) {
		errno = ENOMEM;
		return NULL;
	}
	return malloc(bytes);
}

/**
 * Allocate a structure with a flexible array member.
 *
 * @param[in] type Structure type.
 * @param[in] member Name of flexible array member in @p type.
 * @param[in] count Number of flexible array elements to allocate.
 */
#define malloc_flexible_array(type, member, count)						\
	malloc_flexible_array_impl(sizeof(type),						\
				   static_assert_expression(is_array(((type *)0)->member),	\
							    "not an array",			\
							    sizeof(((type *)0)->member[0])),	\
				   count)

static inline void *malloc64(uint64_t size)
{
	if (size > SIZE_MAX)
		return NULL;
	return malloc(size);
}

static inline void *memdup(const void *ptr, size_t size)
{
	void *copy = malloc(size);
	if (copy)
		memcpy(copy, ptr, size);
	return copy;
}

static inline bool alloc_or_reuse(void **buf, size_t *capacity, size_t size)
{
	if (size > *capacity) {
		free(*buf);
		*buf = malloc(size);
		if (!*buf) {
			*capacity = 0;
			return false;
		}
		*capacity = size;
	}
	return true;
}

/** Return the maximum value of an @p n-byte unsigned integer. */
static inline uint64_t uint_max(int n)
{
	assert(n >= 1 && n <= 8);
	return UINT64_MAX >> (64 - 8 * n);
}

/*
 * Calculate the number of decimal digits in 2^n.
 *
 * The number of decimal digits in a positive integer x is floor(log10(x)) + 1.
 * By the power rule of logarithms, log10(2^n) = n * log10(2).
 * Therefore, the number of decimal digits in 2^n is floor(n * log10(2))) + 1.
 * 643 / 2136 is an approximation of log10(2) which is accurate enough that
 * floor(n * 643 / 2136) = floor(n * log10(2))) for 1 <= n <= 15436.
 */
#define max_decimal_length_impl(n) ((n) * 643 / 2136 + 1)

/**
 * Get the maximum number of characters required to format an integer type in
 * base 10. This is an integer constant expression.
 */
#define max_decimal_length(type)						\
	((type)-1 < 0								\
	/*									\
	 * Let f(x) = floor(log10(x)) + 1, which is the number of decimal	\
	 * digits in a positive integer x.					\
	 *									\
	 * For an n-bit two's-complement integer, the worst case is the minimum	\
	 * value, -2^(n - 1), which is f(2^(n - 1)) decimal digits plus the	\
	 * minus sign.								\
	 */									\
	 ? max_decimal_length_impl(sizeof(type) * CHAR_BIT - 1) + 1		\
	/*									\
	 * For an n-bit unsigned integer, the worst case is the maximum value,	\
	 * 2^n - 1. Note that for any positive integer x, 2^x is not a power of	\
	 * 10, so floor(log10(2^x - 1)) = floor(log10(2^x)). Therefore,		\
	 *   f(2^x - 1)								\
	 * = floor(log10(2^x - 1)) + 1						\
	 * = floor(log10(2^x)) + 1						\
	 * = f(2^x).								\
	 */									\
	 : max_decimal_length_impl(sizeof(type) * CHAR_BIT))

/**
 * Safely add to a pointer which may be `NULL`.
 *
 * `NULL + 0` is undefined behavior, but it often arises naturally, like when
 * computing the end of a dynamic array: `arr + length`. This works around the
 * undefined behavior: `add_to_possibly_null_pointer(NULL, 0)` is defined as
 * `NULL`.
 *
 * A more natural definition would be `i == 0 ? ptr : ptr + i`, but some
 * versions of GCC and Clang generate an unnecessary branch or conditional move
 * (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=97225). Note that in standard
 * C, it is undefined behavior to cast to `uintptr_t`, do arithmetic, and cast
 * back, but GCC allows this as long as the result is within the same object:
 * https://gcc.gnu.org/onlinedocs/gcc/Arrays-and-pointers-implementation.html.
 */
#define add_to_possibly_null_pointer(ptr, i)	\
	((typeof(ptr))((uintptr_t)(ptr) + (i) * sizeof(*(ptr))))

#endif /* DRGN_UTIL_H */
