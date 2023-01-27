#!/usr/bin/env drgn
# Copyright (c) SUSE Linux.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""A simplified implementation of mount(1) using drgn"""

from drgn.helpers.linux.fs import for_each_mount, mount_dst, mount_fstype, mount_src

print("Mount            Type         Devname      Dirname")
for mount in for_each_mount(prog):
    maddr = mount.value_()
    src = mount_src(mount).decode()
    dst = mount_dst(mount).decode()
    type_ = mount_fstype(mount).decode()

    print(f"{maddr:<16x} {type_:<12} {src:<12} {dst}")
