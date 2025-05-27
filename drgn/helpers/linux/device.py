# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Devices
-------

The ``drgn.helpers.linux.device`` module provides helpers for working with
Linux devices, including the kernel encoding of ``dev_t``.
"""

import operator
from typing import Iterator, Tuple

from drgn import IntegerLike, Object, Program, cast
from drgn.helpers.common.prog import takes_program_or_default

__all__ = (
    "MAJOR",
    "MINOR",
    "MKDEV",
    "for_each_registered_blkdev",
    "for_each_registered_chrdev",
)


# This hasn't changed since at least v2.6.
_MINORBITS = 20
_MINORMASK = (1 << _MINORBITS) - 1


def MAJOR(dev: IntegerLike) -> int:
    """
    Return the major ID of a kernel ``dev_t``.

    :param dev: ``dev_t`` object or :class:`int`.
    """
    return operator.index(dev) >> _MINORBITS


def MINOR(dev: IntegerLike) -> int:
    """
    Return the minor ID of a kernel ``dev_t``.

    :param dev: ``dev_t`` object or :class:`int`.
    """
    return operator.index(dev) & _MINORMASK


def MKDEV(major: IntegerLike, minor: IntegerLike) -> int:
    """
    Return a kernel ``dev_t`` from the major and minor IDs.

    :param major: Device major ID.
    :param minor: Device minor ID.
    """
    return (operator.index(major) << _MINORBITS) | operator.index(minor)


@takes_program_or_default
def for_each_registered_chrdev(
    prog: Program,
) -> Iterator[Tuple[int, int, bytes, Object]]:
    cdev_map_probes = prog["cdev_map"].probes
    for cd in prog["chrdevs"]:
        while cd := cd.read_():
            major = cd.major.value_()
            dev = MKDEV(major, cd.baseminor)
            cdev = cd.cdev.read_()
            if not cdev:
                probe = cdev_map_probes[major].read_()
                while next := probe.next.read_():
                    if probe.dev.value_() == dev:
                        cdev = cast("struct cdev *", probe.data)
                        break
                    probe = next

            yield dev, cd.minorct.value_(), cd.name.string_(), cdev
            cd = cd.next


@takes_program_or_default
def for_each_registered_blkdev(prog: Program) -> Iterator[Tuple[int, bytes]]:
    for name in prog["major_names"]:
        while name := name.read_():
            yield name.major.value_(), name.name.string_()
            name = name.next
