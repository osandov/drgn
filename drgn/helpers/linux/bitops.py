# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Bit Operations
--------------

The ``drgn.helpers.linux.bitops`` module provides helpers for common bit
operations in the Linux kernel. These helpers operate on arrays of, or pointers
to, ``unsigned long``, just as the kernel's helpers do. For little-endian
architectures, they can operate equivalently if the underlying type is any other
unsigned integer type. But for big-endian architectures, this does not hold
true. For broadest compatibility, it is best to ensure the underlying type is
``unsigned long``.
"""

from typing import Iterator, Optional

from drgn import IntegerLike, Object, TypeKind, sizeof

__all__ = (
    "for_each_clear_bit",
    "for_each_set_bit",
    "test_bit",
)


def for_each_set_bit(
    bitmap: Object, size: Optional[IntegerLike] = None
) -> Iterator[int]:
    """
    Iterate over all set (one) bits in a bitmap.

    :param bitmap: pointer to, or array of, ``unsigned long``
    :param size: Size of *bitmap* in bits. When *bitmap* is a sized array type
        (EG: ``unsigned long[2]``), this value will default to the size of the
        array in bits.
    """
    if size is not None:
        size = int(size)
    elif bitmap.type_.kind == TypeKind.ARRAY and bitmap.type_.length is not None:
        size = 8 * sizeof(bitmap)
    else:
        raise ValueError("bitmap is not a complete array type, and size is not given")
    word_bits = 8 * sizeof(bitmap.type_.type)
    for i in range((size + word_bits - 1) // word_bits):
        word = bitmap[i].value_()
        for j in range(min(word_bits, size - word_bits * i)):
            if word & (1 << j):
                yield (word_bits * i) + j


def for_each_clear_bit(
    bitmap: Object, size: Optional[IntegerLike] = None
) -> Iterator[int]:
    """
    Iterate over all clear (zero) bits in a bitmap.

    :param bitmap: pointer to, or array of, ``unsigned long``
    :param size: Size of *bitmap* in bits. When *bitmap* is a sized array type
        (EG: ``unsigned long[2]``), this value will default to the size of the
        array in bits.
    """
    if size is not None:
        size = int(size)
    elif bitmap.type_.kind == TypeKind.ARRAY and bitmap.type_.length is not None:
        size = 8 * sizeof(bitmap)
    else:
        raise ValueError("bitmap is not a complete array type, and size is not given")
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
    :param bitmap: pointer to, or array of, ``unsigned long``
    """
    nr = int(nr)
    word_bits = 8 * sizeof(bitmap.type_.type)
    return ((bitmap[nr // word_bits].value_() >> (nr & (word_bits - 1))) & 1) != 0
