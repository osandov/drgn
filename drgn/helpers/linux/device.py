# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Devices
-------

The ``drgn.helpers.linux.device`` module provides helpers for working with
Linux devices, including the kernel encoding of ``dev_t``.
"""

import operator
from typing import Iterable

from drgn import NULL, IntegerLike, Object
from drgn.helpers.linux.list import list_for_each_entry

__all__ = (
    "MAJOR",
    "MINOR",
    "MKDEV",
    "bus_for_each_dev",
    "bus_to_subsys",
    "dev_name",
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


def dev_name(dev: Object) -> bytes:
    """
    Get the name of a device.

    :param dev: ``struct device *``
    """
    init_name = dev.init_name.read_()
    if init_name:
        return init_name.string_()
    return dev.kobj.name.string_()


def bus_to_subsys(bus: Object) -> Object:
    """
    Get the private data for a device bus.

    :param bus: ``struct bus_type *``
    :return: ``struct subsys_private *``
    """
    prog = bus.prog_
    # Walk the list of registered busses to find the struct subsys_private
    # matching the given bus. Note that before Linux kernel commit d2bf38c088e0
    # ("driver core: remove private pointer from struct bus_type") (in v6.3),
    # struct subsys_private could also be found in struct bus::p, but it's
    # easier to only maintain the newer code path.
    for sp in list_for_each_entry(
        "struct subsys_private",
        prog["bus_kset"].list.address_of_(),
        "subsys.kobj.entry",
    ):
        if sp.bus == bus:
            return sp
    return NULL(prog, "struct subsys_private *")


def bus_for_each_dev(bus: Object) -> Iterable[Object]:
    """
    Iterate over all devices on a bus.

    :param bus: ``struct bus_type *``
    :return: Iterator of ``struct device *`` objects.
    """
    sp = bus_to_subsys(bus)
    for dev_prv in list_for_each_entry(
        "struct device_private",
        sp.klist_devices.k_list.address_of_(),
        "knode_bus.n_node",
    ):
        yield dev_prv.device.read_()
