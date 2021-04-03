# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Block Layer
-----------

The ``drgn.helpers.linux.block`` module provides helpers for working with the
Linux block layer, including disks (``struct gendisk``) and partitions.

Since Linux v5.11, partitions are represented by ``struct block_device``.
Before that, they were represented by ``struct hd_struct``.
"""

from typing import Iterator

from drgn import Object, Program, container_of
from drgn.helpers import escape_ascii_string
from drgn.helpers.linux.device import MAJOR, MINOR, MKDEV
from drgn.helpers.linux.list import list_for_each_entry

__all__ = (
    "disk_devt",
    "disk_name",
    "for_each_disk",
    "for_each_partition",
    "part_devt",
    "part_name",
    "print_disks",
    "print_partitions",
)


def disk_devt(disk: Object) -> Object:
    """
    Get a disk's device number.

    :param disk: ``struct gendisk *``
    :return: ``dev_t``
    """
    return Object(disk.prog_, "dev_t", MKDEV(disk.major, disk.first_minor))


def disk_name(disk: Object) -> bytes:
    """
    Get the name of a disk (e.g., ``sda``).

    :param disk: ``struct gendisk *``
    """
    return disk.disk_name.string_()


def _for_each_block_device(prog: Program) -> Iterator[Object]:
    try:
        class_in_private = prog.cache["knode_class_in_device_private"]
    except KeyError:
        # Linux kernel commit 570d0200123f ("driver core: move
        # device->knode_class to device_private") (in v5.1) moved the list
        # node.
        class_in_private = prog.type("struct device_private").has_member("knode_class")
        prog.cache["knode_class_in_device_private"] = class_in_private
    devices = prog["block_class"].p.klist_devices.k_list.address_of_()
    if class_in_private:
        for device_private in list_for_each_entry(
            "struct device_private", devices, "knode_class.n_node"
        ):
            yield device_private.device
    else:
        yield from list_for_each_entry("struct device", devices, "knode_class.n_node")


def for_each_disk(prog: Program) -> Iterator[Object]:
    """
    Iterate over all disks in the system.

    :return: Iterator of ``struct gendisk *`` objects.
    """
    # Before Linux kernel commit 0d02129e76ed ("block: merge struct
    # block_device and struct hd_struct") (in v5.11), partition devices are in
    # struct hd_struct::__dev. After that commit, they are in struct
    # block_device::bd_device. We start by assuming that the kernel has this
    # commit and fall back to the old path if that fails.
    have_bd_device = True
    for device in _for_each_block_device(prog):
        if have_bd_device:
            try:
                bdev = container_of(device, "struct block_device", "bd_device")
            except LookupError:
                have_bd_device = False
            else:
                if bdev.bd_partno == 0:
                    yield bdev.bd_disk
                continue
        part = container_of(device, "struct hd_struct", "__dev")
        if part.partno == 0:
            yield container_of(part, "struct gendisk", "part0")


def print_disks(prog: Program) -> None:
    """Print all of the disks in the system."""
    for disk in for_each_disk(prog):
        major = disk.major.value_()
        minor = disk.first_minor.value_()
        name = escape_ascii_string(disk_name(disk), escape_backslash=True)
        print(f"{major}:{minor} {name} ({disk.type_.type_name()})0x{disk.value_():x}")


def part_devt(part: Object) -> Object:
    """
    Get a partition's device number.

    :param part: ``struct block_device *`` or ``struct hd_struct *`` depending
        on the kernel version.
    :return: ``dev_t``
    """
    try:
        return part.bd_dev
    except AttributeError:
        return part.__dev.devt


def part_name(part: Object) -> bytes:
    """
    Get the name of a partition (e.g., ``sda1``).

    :param part: ``struct block_device *`` or ``struct hd_struct *`` depending
        on the kernel version.
    """
    try:
        bd_device = part.bd_device
    except AttributeError:
        return part.__dev.kobj.name.string_()
    return bd_device.kobj.name.string_()


def for_each_partition(prog: Program) -> Iterator[Object]:
    """
    Iterate over all partitions in the system.

    :return: Iterator of ``struct block_device *`` or ``struct hd_struct *``
        objects depending on the kernel version.
    """
    # See the comment in for_each_disk().
    have_bd_device = True
    for device in _for_each_block_device(prog):
        if have_bd_device:
            try:
                yield container_of(device, "struct block_device", "bd_device")
                continue
            except LookupError:
                have_bd_device = False
        yield container_of(device, "struct hd_struct", "__dev")


def print_partitions(prog: Program) -> None:
    """Print all of the partitions in the system."""
    for part in for_each_partition(prog):
        devt = part_devt(part).value_()
        name = escape_ascii_string(part_name(part), escape_backslash=True)
        print(
            f"{MAJOR(devt)}:{MINOR(devt)} {name} ({part.type_.type_name()})0x{part.value_():x}"
        )
