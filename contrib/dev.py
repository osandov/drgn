#!/usr/bin/env drgn
# Copyright (c) SUSE Linux.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Dump character and block devices using drgn"""

from drgn import Object
from drgn.helpers.linux.device import MAJOR, MINOR
from drgn.helpers.linux.list import list_for_each_entry


# First parse cdev_map.
cdev_map = {}
for cmap in prog['cdev_map'].probes:
    while cmap:
        dev = cmap.dev.value_()
        cdev_map[(MAJOR(dev), MINOR(dev))] = cmap.data.value_()
        cmap = cmap.next

print("Character devices")
print(f"{'Major':>8}  {'Name':18} {'cdev':>22}")

for i, chrdev in enumerate(prog["chrdevs"]):
    if not chrdev:
        continue

    while True:
        name = chrdev.name.string_().decode()
        cdev = chrdev.cdev.value_()
        if not cdev:
            try:
                cdev = cdev_map[(chrdev.major.value_(), chrdev.baseminor.value_())]
            except KeyError:
                pass

        print(f"{i:>8}  {name:18} {cdev:>22x}")
        chrdev = chrdev.next
        if not chrdev:
            break

print()

# See block/bdev.c for more information.
gendisks = {}
blkdev_type = prog.type("struct block_device")
for inode in list_for_each_entry("struct inode", prog["blockdev_superblock"].s_inodes.address_of_(), "i_sb_list"):
    blkdev = Object(prog, blkdev_type, address=int(inode) - blkdev_type.size)
    disk = blkdev.bd_disk
    if disk:
        gendisks[int(disk.major)] = disk

print("Block devices")
print(f"{'Major':>8}  {'Name':18} {'Gendisk':>22}")
for dev in prog["major_names"]:
    if not dev:
        continue
    name = dev.name.string_().decode()
    major = int(dev.major)
    gendisk = 0
    if major in gendisks:
        gendisk = int(gendisks[major])

    print(f"{major:>8}  {name:18} {gendisk:>22x}")
