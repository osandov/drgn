// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_BITMAP_H
#define DRGN_BITMAP_H

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

#define DRGN_BITMAP_WORD_BITS (sizeof(unsigned long) * CHAR_BIT)

static inline unsigned long *drgn_bitmap_create(size_t num_bits)
{
	return calloc(num_bits / DRGN_BITMAP_WORD_BITS
		      + (num_bits % DRGN_BITMAP_WORD_BITS ? 1 : 0),
		      sizeof(unsigned long));
}

static inline bool drgn_bitmap_test_bit(unsigned long *bitmap, size_t i)
{
	return bitmap[i / DRGN_BITMAP_WORD_BITS]
	       & (1UL << (i % DRGN_BITMAP_WORD_BITS));
}

static inline void drgn_bitmap_set_bit(unsigned long *bitmap, size_t i)
{
	bitmap[i / DRGN_BITMAP_WORD_BITS] |=
		1UL << (i % DRGN_BITMAP_WORD_BITS);
}

static inline void drgn_bitmap_clear_bit(unsigned long *bitmap, size_t i)
{
	bitmap[i / DRGN_BITMAP_WORD_BITS] &=
		~(1UL << (i % DRGN_BITMAP_WORD_BITS));
}

#endif /* DRGN_BITMAP_H */
