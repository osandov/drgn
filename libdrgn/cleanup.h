// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Cleanup functions.
 */

#ifndef DRGN_CLEANUP_H
#define DRGN_CLEANUP_H

#include <stdio.h>
#include <stdlib.h>

#define _cleanup_(x) __attribute__((__cleanup__(x)))

/** Call @c free() when the variable goes out of scope. */
#define _cleanup_free_ _cleanup_(freep)
static inline void freep(void *p)
{
	free(*(void **)p);
}

/** Call @c fclose() when the variable goes out of scope. */
#define _cleanup_fclose_ _cleanup_(fclosep)
static inline void fclosep(FILE **fp)
{
	if (*fp)
		fclose(*fp);
}

/**
 * Get the value of a pointer variable and reset it to @c NULL.
 *
 * This can be used to avoid freeing a variable declared with @ref
 * _cleanup_free_ or another scope guard that is a no-op for @c NULL.
 */
#define no_cleanup_ptr(p) ({ __auto_type __ptr = (p); (p) = NULL; __ptr; })

/**
 * Return a pointer declared with @ref _cleanup_free_ without freeing it.
 *
 * This can also be used for other scope guards that are a no-op for @c NULL.
 */
#define return_ptr(p) return no_cleanup_ptr(p)

#endif /* DRGN_CLEANUP_H */
