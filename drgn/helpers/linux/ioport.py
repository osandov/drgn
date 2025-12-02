# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
I/O Resources
-------------

The ``drgn.helpers.linux.ioport`` module provides helpers for working with I/O
resources.
"""

from typing import Iterator

from drgn import Object

__all__ = ("for_each_resource",)


def for_each_resource(root: Object) -> Iterator[Object]:
    """
    Iterate over all I/O resources starting from the given root resource.

    :param root: ``struct resource *``
    :return: Iterator of ``struct resource *`` objects.
    """
    yield root
    child = root.child.read_()
    while child:
        yield from for_each_resource(child)
        child = child.sibling.read_()
