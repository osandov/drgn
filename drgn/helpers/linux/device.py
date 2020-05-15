# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Devices
-------

The ``drgn.helpers.linux.device`` module provides helpers for working with
Linux devices, including the kernel encoding of ``dev_t``.
"""

from drgn import Object, cast

__all__ = (
    "MAJOR",
    "MINOR",
    "MKDEV",
)


# This hasn't changed since at least v2.6.
_MINORBITS = 20
_MINORMASK = (1 << _MINORBITS) - 1


def MAJOR(dev):
    """
    .. c:function:: unsigned int MAJOR(dev_t dev)

    Return the major ID of a kernel ``dev_t``.
    """
    major = dev >> _MINORBITS
    if isinstance(major, Object):
        return cast("unsigned int", major)
    return major


def MINOR(dev):
    """
    .. c:function:: unsigned int MINOR(dev_t dev)

    Return the minor ID of a kernel ``dev_t``.
    """
    minor = dev & _MINORMASK
    if isinstance(minor, Object):
        return cast("unsigned int", minor)
    return minor


def MKDEV(major, minor):
    """
    .. c:function:: dev_t MKDEV(unsigned int major, unsigned int minor)

    Return a kernel ``dev_t`` from the major and minor IDs.
    """
    dev = (major << _MINORBITS) | minor
    if isinstance(dev, Object):
        return cast("dev_t", dev)
    return dev
