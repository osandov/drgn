# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Block Layer
-----------

The ``drgn.helpers.linux.block`` module provides helpers for working with the
Linux block layer, including disks (``struct gendisk``) and partitions.

Since Linux v5.11, partitions are represented by ``struct block_device``.
Before that, they were represented by ``struct hd_struct``.
"""

from typing import Iterator

from drgn import Object, Program, cast, container_of
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.device import MAJOR, MINOR, MKDEV
from drgn.helpers.linux.list import list_for_each_entry

__all__ = (
    "bdev_partno",
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


def _bdev_partno_flags(bdev: Object) -> Object:
    return cast("u8", bdev.__bd_flags.counter)


def _bdev_partno_old(bdev: Object) -> Object:
    return bdev.bd_partno.read_()


def bdev_partno(bdev: Object) -> Object:
    """
    Get the partition number of a block device.

    :param bdev: ``struct block_device *``
    :return: ``u8``
    """
    try:
        impl = bdev.prog_.cache["bdev_partno"]
    except KeyError:
        # Since Linux kernel commit 1116b9fa15c0 ("bdev: infrastructure for
        # flags") (in v6.10), partno is part of the atomic_t __bd_flags member.
        # Before that, it's its own member.
        bdev.prog_.cache["bdev_partno"] = impl = (
            _bdev_partno_flags
            if bdev.prog_.type("struct block_device").has_member("__bd_flags")
            else _bdev_partno_old
        )
    return impl(bdev)


def _class_to_subsys(class_: Object) -> Object:
    # Walk the list of registered classes to find the struct subsys_private
    # matching the given class. Note that before Linux kernel commit
    # 2df418cf4b72 ("driver core: class: remove subsystem private pointer from
    # struct class") (in v6.4), struct subsys_private could also be found in
    # struct class::p, but it's easier to only maintain the newer code path.
    for sp in list_for_each_entry(
        "struct subsys_private",
        class_.prog_["class_kset"].list.address_of_(),
        "subsys.kobj.entry",
    ):
        if sp.member_("class") == class_:
            return sp
    else:
        raise LookupError("block_class subsys_private not found")


def _for_each_block_device(prog: Program) -> Iterator[Object]:
    try:
        devices, class_in_device_private = prog.cache["_for_each_block_device"]
    except KeyError:
        devices = _class_to_subsys(
            prog["block_class"].address_of_()
        ).klist_devices.k_list.address_of_()
        # Linux kernel commit 570d0200123f ("driver core: move
        # device->knode_class to device_private") (in v5.1) moved the list
        # node.
        class_in_device_private = prog.type("struct device_private").has_member(
            "knode_class"
        )
        prog.cache["_for_each_block_device"] = devices, class_in_device_private

    if class_in_device_private:
        for device_private in list_for_each_entry(
            "struct device_private", devices, "knode_class.n_node"
        ):
            yield device_private.device
    else:
        yield from list_for_each_entry("struct device", devices, "knode_class.n_node")


@takes_program_or_default
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
                if not bdev_partno(bdev):
                    yield bdev.bd_disk
                continue
        part = container_of(device, "struct hd_struct", "__dev")
        if part.partno == 0:
            yield container_of(part, "struct gendisk", "part0")


@takes_program_or_default
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


@takes_program_or_default
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


@takes_program_or_default
def print_partitions(prog: Program) -> None:
    """Print all of the partitions in the system."""
    for part in for_each_partition(prog):
        devt = part_devt(part).value_()
        name = escape_ascii_string(part_name(part), escape_backslash=True)
        print(
            f"{MAJOR(devt)}:{MINOR(devt)} {name} ({part.type_.type_name()})0x{part.value_():x}"
        )
