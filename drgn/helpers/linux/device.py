# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Devices
-------

The ``drgn.helpers.linux.device`` module provides helpers for working with
Linux devices, including the kernel encoding of ``dev_t``.
"""

import operator

from drgn import IntegerLike

__all__ = (
    "MAJOR",
    "MINOR",
    "MKDEV",
)


# This hasn't changed since at least v2.6.
_MINORBITS = 20
_MINORMASK = (1 << _MINORBITS) - 1


def MAJOR(dev: IntegerLike) -> int:
    """
    Return the major ID of a kernel ``dev_t``.

    :param dev: ``dev_t`` object or :class:``int``.
    """
    return operator.index(dev) >> _MINORBITS


def MINOR(dev: IntegerLike) -> int:
    """
    Return the minor ID of a kernel ``dev_t``.

    :param dev: ``dev_t`` object or :class:``int``.
    """
    return operator.index(dev) & _MINORMASK


def MKDEV(major: IntegerLike, minor: IntegerLike) -> int:
    """
    Return a kernel ``dev_t`` from the major and minor IDs.

    :param major: Device major ID.
    :param minor: Device minor ID.
    """
    return (operator.index(major) << _MINORBITS) | operator.index(minor)
