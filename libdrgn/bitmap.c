// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "bitmap.h"
#include "bitops.h"

size_t drgn_bitmap_last_set(const unsigned long *bitmap, size_t num_bits)
{
	if (num_bits > 0) {
		size_t idx = (num_bits - 1) / DRGN_BITMAP_WORD_BITS;
		unsigned long word =
			bitmap[idx]
			& (~0UL >> (-num_bits % DRGN_BITMAP_WORD_BITS));
		for (;;) {
			if (word)
				return idx * DRGN_BITMAP_WORD_BITS + ilog2(word);
			if (idx == 0)
				break;
			word = bitmap[--idx];
		}
	}
	return num_bits;
}
