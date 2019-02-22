# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Linux kernel block layer helpers

This module provides helpers for working with the Linux block layer, including
disks (struct gendisk) and partitions (struct hd_struct).
"""

from drgn import container_of
from drgn.internal.util import escape_string
from drgn.helpers.kernel.device import MAJOR, MINOR
from drgn.helpers.kernel.list import list_for_each_entry

__all__ = [
    'for_each_disk',
    'print_disks',
    'for_each_partition',
    'print_partitions',
]


def for_each_disk(prog):
    """
    for_each_disk()

    Return an iterator over all disks in the system. The generated values are
    (major, minor, name, struct gendisk *) tuples. The name is returned as
    bytes.
    """
    devices = prog['block_class'].p.klist_devices.k_list.address_of_()
    disk_type = prog['disk_type'].address_of_()
    for device in list_for_each_entry('struct device', devices, 'knode_class.n_node'):
        if device.type == disk_type:
            obj = container_of(device, 'struct gendisk', 'part0.__dev')
            dev = device.devt.value_()
            yield MAJOR(dev), MINOR(dev), device.kobj.name.string_(), obj


def print_disks(prog):
    """
    print_disks()

    Print all of the disks in the system.
    """
    for major, minor, name, obj in for_each_disk(prog):
        name = escape_string(name, escape_backslash=True)
        print(f'{major}:{minor} {name} ({obj.type_.type_name()})0x{obj.value_():x}')


def for_each_partition(prog):
    """
    for_each_partition()

    Return an iterator over all partitions in the system. The generated values
    are (major, minor, name, struct hd_struct *) tuples. The name is returned
    as bytes.
    """
    devices = prog['block_class'].p.klist_devices.k_list.address_of_()
    for device in list_for_each_entry('struct device', devices, 'knode_class.n_node'):
        obj = container_of(device, 'struct hd_struct', '__dev')
        dev = device.devt.value_()
        yield MAJOR(dev), MINOR(dev), device.kobj.name.string_(), obj


def print_partitions(prog):
    """
    print_partitions()

    Print all of the partitions in the system.
    """
    for major, minor, name, obj in for_each_partition(prog):
        name = escape_string(name, escape_backslash=True)
        print(f'{major}:{minor} {name} ({obj.type_.type_name()})0x{obj.value_():x}')
