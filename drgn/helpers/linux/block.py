# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel block layer helpers

This module provides helpers for working with the Linux block layer, including
disks (struct gendisk) and partitions (struct hd_struct).
"""

import typing

from drgn import Object, container_of
from drgn.helpers import escape_string
from drgn.helpers.linux.device import MAJOR, MINOR
from drgn.helpers.linux.list import list_for_each_entry

__all__ = [
    'Disk',
    'Partition',
    'for_each_disk',
    'print_disks',
    'for_each_partition',
    'print_partitions',
]


class Disk(typing.NamedTuple):
    """A disk. gendisk is a struct gendisk * object."""
    major: int
    minor: int
    name: bytes
    gendisk: Object


def for_each_disk(prog):
    """
    for_each_disk() -> Iterator[Disk]

    Return an iterator over all disks in the system.
    """
    devices = prog['block_class'].p.klist_devices.k_list.address_of_()
    disk_type = prog['disk_type'].address_of_()
    for device in list_for_each_entry('struct device', devices, 'knode_class.n_node'):
        if device.type == disk_type:
            obj = container_of(device, 'struct gendisk', 'part0.__dev')
            dev = device.devt.value_()
            yield Disk(MAJOR(dev), MINOR(dev), device.kobj.name.string_(), obj)


def print_disks(prog):
    """
    print_disks()

    Print all of the disks in the system.
    """
    for major, minor, name, obj in for_each_disk(prog):
        name = escape_string(name, escape_backslash=True)
        print(f'{major}:{minor} {name} ({obj.type_.type_name()})0x{obj.value_():x}')


class Partition(typing.NamedTuple):
    """A disk partition. hd_struct is a struct hd_struct * object."""
    major: int
    minor: int
    name: bytes
    hd_struct: Object


def for_each_partition(prog):
    """
    for_each_partition() -> Iterator[Partition]

    Return an iterator over all partitions in the system.
    """
    devices = prog['block_class'].p.klist_devices.k_list.address_of_()
    for device in list_for_each_entry('struct device', devices, 'knode_class.n_node'):
        obj = container_of(device, 'struct hd_struct', '__dev')
        dev = device.devt.value_()
        yield Partition(MAJOR(dev), MINOR(dev), device.kobj.name.string_(),
                        obj)


def print_partitions(prog):
    """
    print_partitions()

    Print all of the partitions in the system.
    """
    for major, minor, name, obj in for_each_partition(prog):
        name = escape_string(name, escape_backslash=True)
        print(f'{major}:{minor} {name} ({obj.type_.type_name()})0x{obj.value_():x}')
