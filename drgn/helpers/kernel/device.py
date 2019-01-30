# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel device helpers

This module provides helpers for working with Linux devices, including the
kernel encoding of dev_t.
"""

from drgn import Object

__all__ = [
    'MAJOR',
    'MINOR',
    'MKDEV',
]


# This hasn't changed since at least v2.6.
_MINORBITS = 20
_MINORMASK = ((1 << _MINORBITS) - 1)


def MAJOR(dev):
    """
    unsigned int MAJOR(dev_t)

    Return the major ID of a kernel dev_t.
    """
    major = dev >> _MINORBITS
    if isinstance(major, Object):
        return major.cast_('unsigned int')
    return major


def MINOR(dev):
    """
    unsigned int MINOR(dev_t)

    Return the major ID of a kernel dev_t.
    """
    minor = dev & _MINORMASK
    if isinstance(minor, Object):
        return minor.cast_('unsigned int')
    return minor


def MKDEV(major, minor):
    """
    dev_t MKDEV(unsigned int major, unsigned int minor)

    Return a kernel dev_t from the major and minor IDs.
    """
    dev = (major << _MINORBITS) | minor
    if isinstance(dev, Object):
        return dev.cast_('dev_t')
    return dev
