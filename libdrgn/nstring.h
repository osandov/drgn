// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * String with length.
 */

#ifndef DRGN_NSTRING_H
#define DRGN_NSTRING_H

#include <string.h>

/** A string with a stored length. */
struct nstring {
	/**
	 * The string, which is not necessarily null-terminated and may have
	 * embedded null bytes.
	 */
	const char *str;
	/** The length in bytes of the string. */
	size_t len;
};

/** Compare two @ref nstring keys for equality. */
static inline bool nstring_eq(const struct nstring *a, const struct nstring *b)
{
	/*
	 * len == 0 is a special case because memcmp(NULL, NULL, 0) is
	 * technically undefined.
	 */
	return (a->len == b->len &&
		(a->len == 0 || memcmp(a->str, b->str, a->len) == 0));
}

#endif /* DRGN_NSTRING_H */
