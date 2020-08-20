# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Block Layer
-----------

The ``drgn.helpers.linux.block`` module provides helpers for working with the
Linux block layer, including disks (``struct gendisk``) and partitions
(``struct hd_struct``).
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
        # We need a proper has_member(), but this is fine for now.
        class_in_private = any(
            member.name == "knode_class"
            for member in prog.type("struct device_private").members  # type: ignore[union-attr]
        )
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
    disk_type = prog["disk_type"].address_of_()
    for device in _for_each_block_device(prog):
        if device.type == disk_type:
            yield container_of(device, "struct gendisk", "part0.__dev")


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

    :param part: ``struct hd_struct *``
    :return: ``dev_t``
    """
    return part.__dev.devt


def part_name(part: Object) -> bytes:
    """
    Get the name of a partition (e.g., ``sda1``).

    :param part: ``struct hd_struct *``
    """
    return part.__dev.kobj.name.string_()


def for_each_partition(prog: Program) -> Iterator[Object]:
    """
    Iterate over all partitions in the system.

    :return: Iterator of ``struct hd_struct *`` objects.
    """
    for device in _for_each_block_device(prog):
        yield container_of(device, "struct hd_struct", "__dev")


def print_partitions(prog: Program) -> None:
    """Print all of the partitions in the system."""
    for part in for_each_partition(prog):
        devt = part_devt(part).value_()
        name = escape_ascii_string(part_name(part), escape_backslash=True)
        print(
            f"{MAJOR(devt)}:{MINOR(devt)} {name} ({part.type_.type_name()})0x{part.value_():x}"
        )
