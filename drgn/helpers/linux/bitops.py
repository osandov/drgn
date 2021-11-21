# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Bit Operations
--------------

The ``drgn.helpers.linux.bitops`` module provides helpers for common bit
operations in the Linux kernel.
"""

from typing import Iterator

from drgn import IntegerLike, Object, sizeof

__all__ = (
    "for_each_clear_bit",
    "for_each_set_bit",
    "test_bit",
)


def for_each_set_bit(bitmap: Object, size: IntegerLike) -> Iterator[int]:
    """
    Iterate over all set (one) bits in a bitmap.

    :param bitmap: ``unsigned long *``
    :param size: Size of *bitmap* in bits.
    """
    size = int(size)
    word_bits = 8 * sizeof(bitmap.type_.type)
    for i in range((size + word_bits - 1) // word_bits):
        word = bitmap[i].value_()
        for j in range(min(word_bits, size - word_bits * i)):
            if word & (1 << j):
                yield (word_bits * i) + j


def for_each_clear_bit(bitmap: Object, size: IntegerLike) -> Iterator[int]:
    """
    Iterate over all clear (zero) bits in a bitmap.

    :param bitmap: ``unsigned long *``
    :param size: Size of *bitmap* in bits.
    """
    size = int(size)
    word_bits = 8 * sizeof(bitmap.type_.type)
    for i in range((size + word_bits - 1) // word_bits):
        word = bitmap[i].value_()
        for j in range(min(word_bits, size - word_bits * i)):
            if not (word & (1 << j)):
                yield (word_bits * i) + j


def test_bit(nr: IntegerLike, bitmap: Object) -> bool:
    """
    Return whether a bit in a bitmap is set.

    :param nr: Bit number.
    :param bitmap: ``unsigned long *``
    """
    nr = int(nr)
    word_bits = 8 * sizeof(bitmap.type_.type)
    return ((bitmap[nr // word_bits].value_() >> (nr & (word_bits - 1))) & 1) != 0
