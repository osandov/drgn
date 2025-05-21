# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Bitmaps
-------

The ``drgn.helpers.linux.bitmap`` module provides helpers for working with
bitmaps from :linux:`include/linux/bitmap.h`.

The following helpers from :mod:`drgn.helpers.linux.bitops` also apply to
bitmaps:

* :func:`~drgn.helpers.linux.bitops.for_each_set_bit()`
* :func:`~drgn.helpers.linux.bitops.for_each_clear_bit()`
* :func:`~drgn.helpers.linux.bitops.test_bit()`
"""

import operator
import sys

from drgn import IntegerLike, Object, sizeof

__all__ = ("bitmap_weight",)

if sys.version_info >= (3, 10):
    _bit_count = int.bit_count  # novermin
else:

    # Fallback for old Python versions. Surprisingly, this is faster than any
    # bit manipulation tricks.
    def _bit_count(n: int) -> int:
        return bin(n).count("1")


def bitmap_weight(bitmap: Object, size: IntegerLike) -> int:
    """
    Return the number of set (one) bits in a bitmap

    :param bitmap: ``unsigned long *``
    :param size: Size of *bitmap* in bits.
    """
    size = operator.index(size)
    word_bits = 8 * sizeof(bitmap.type_.type)

    weight = 0
    for i in range(size // word_bits):
        weight += _bit_count(bitmap[i].value_())

    last_word_bits = size % word_bits
    if last_word_bits:
        weight += _bit_count(
            bitmap[size // word_bits].value_() & ((1 << last_word_bits) - 1)
        )

    return weight
