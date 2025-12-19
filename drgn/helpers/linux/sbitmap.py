# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Sbitmaps
--------

The ``drgn.helpers.linux.sbitmap`` module provides helpers for working with
scalable bitmaps from :linux:`include/linux/sbitmap.h`.
"""

from typing import Iterator

from drgn import Object

__all__ = ("sbitmap_for_each_set",)


def sbitmap_for_each_set(sb: Object) -> Iterator[int]:
    """
    Iterate over all set (one) bits in a sbitmap.

    :param sb: ``struct sbitmap *``
    """
    depth = sb.depth.value_()
    shift = sb.shift.value_()
    map_nr = sb.map_nr.value_()
    for i, map in enumerate(sb.map[:map_nr]):
        map_start = i << shift
        if i < map_nr - 1:
            map_depth = 1 << shift
        else:
            map_depth = depth - map_start

        word = map.word.value_()
        # sbitmap_word::cleared was added in Linux kernel commit ("sbitmap:
        # ammortize cost of clearing bits") (in v5.0).
        try:
            word &= ~map.cleared.value_()
        except AttributeError:
            pass
        for j in range(map_depth):
            if word & (1 << j):
                yield map_start + j
