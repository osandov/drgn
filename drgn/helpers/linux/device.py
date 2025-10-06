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
    "class_for_each_device",
    "class_to_subsys",
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


def class_to_subsys(class_: Object) -> Object:
    """
    Get the private data for a device class.

    :param bus: ``struct class *``
    :return: ``struct subsys_private *``
    """
    prog = class_.prog_
    # Walk the list of registered classes to find the struct subsys_private
    # matching the given class. Note that before Linux kernel commit
    # 2df418cf4b72 ("driver core: class: remove subsystem private pointer from
    # struct class") (in v6.4), struct subsys_private could also be found in
    # struct class::p, but it's easier to only maintain the newer code path.
    for sp in list_for_each_entry(
        "struct subsys_private",
        prog["class_kset"].list.address_of_(),
        "subsys.kobj.entry",
    ):
        if sp.member_("class") == class_:
            return sp
    return NULL(prog, "struct subsys_private *")


# The naming inconsistency between this and bus_for_each_dev() is inherited
# from the kernel source code :(
def class_for_each_device(class_: Object) -> Iterable[Object]:
    """
    Iterate over all devices of a class.

    :param bus: ``struct class *``
    :return: Iterator of ``struct device *`` objects.
    """
    prog = class_.prog_
    try:
        class_in_device_private = prog.cache["class_in_device_private"]
    except KeyError:
        # Linux kernel commit 570d0200123f ("driver core: move
        # device->knode_class to device_private") (in v5.1) moved the list
        # node.
        class_in_device_private = prog.type("struct device_private").has_member(
            "knode_class"
        )
        prog.cache["class_in_device_private"] = class_in_device_private

    devices = class_to_subsys(class_).klist_devices.k_list.address_of_()
    if class_in_device_private:
        for dev_prv in list_for_each_entry(
            "struct device_private", devices, "knode_class.n_node"
        ):
            yield dev_prv.device.read_()
    else:
        yield from list_for_each_entry("struct device", devices, "knode_class.n_node")
