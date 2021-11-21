// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

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

#ifndef LIBDRGN_PUBLIC
#define LIBDRGN_PUBLIC __attribute__((__visibility__("default")))
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

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

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

static inline void *memdup(void *ptr, size_t size)
{
	void *copy = malloc(size);
	if (copy)
		memcpy(copy, ptr, size);
	return copy;
}

/** Return the maximum value of an @p n-byte unsigned integer. */
static inline uint64_t uint_max(int n)
{
	assert(n >= 1 && n <= 8);
	return UINT64_MAX >> (64 - 8 * n);
}

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
 * (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=97225).
 */
#define add_to_possibly_null_pointer(ptr, i)	\
	((typeof(ptr))((uintptr_t)(ptr) + (i) * sizeof(*(ptr))))

#endif /* DRGN_UTIL_H */
