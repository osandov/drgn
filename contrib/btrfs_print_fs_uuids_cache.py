#!/usr/bin/env drgn
# Copyright (c) 2024, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Print key details of the filesystems in the btrfs fs_uuids cache

Usage:
* drgn -s <btrfs.ko.debug> -s <vmlinux> -c <vmcore> btrfs_print_fs_uuids_cache.py
    - This only prints key details of the filesystems
* drgn -s <btrfs.ko.debug> -s <vmlinux> -c <vmcore> btrfs_print_fs_uuids_cache.py -d yes
    - This dumps all the structures. The output will be enormous,
    so it's recommended to redirect it to a file and read it from there.
"""

import drgn
import argparse

from drgn.helpers.common import *
from drgn.helpers.linux import (
    list_for_each_entry,
    for_each_possible_cpu,
    per_cpu_ptr,
)

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dump", required = False, help = "Dump all structure data")

args = parser.parse_args()

def format(uuid_list):
    """Helper to format uuid from list representation"""
    part = ""
    for ele in uuid_list:
        part += "%02x" %ele
    return part

def get_uuid_from_list(uuid_list):
    """Helper to format uuid from list representation"""
    uuid = ""
    uuid += format(uuid_list[0:4]) + "-"
    uuid += format(uuid_list[4:6]) + "-"
    uuid += format(uuid_list[6:8]) + "-"
    uuid += format(uuid_list[8:10]) + "-"
    uuid += format(uuid_list[10:])
    return uuid

def print_mount_info(mnt):
    """Print key fields of `struct mount`"""
    print(f"Mount Info:")
    print(f"\tMount Point: {mnt.mnt_mountpoint.d_iname.string_().decode('utf-8')}")
    print(f"\tVFS Mount Flags: {mnt.mnt.mnt_flags}")
    print(f"\tDevice Name: {mnt.mnt_devname.string_().decode('utf-8')}")
    if mnt.mnt_mp:
        print(f"\tMount Point Count: {mnt.mnt_mp.m_count.value_()}")
    else:
        print("\tMount Point is NULL")
    print(f"\tMount ID: {mnt.mnt_id}")
    print(f"\tMount Group ID: {mnt.mnt_group_id}")
    print(f"\tMount Expiry Mark: {mnt.mnt_expiry_mark}")
    return

def print_super_block_info(sb):
    """Print key fields of `struct super_block`"""
    print("Super Block:")
    if not sb:
        print("\tSuper block is NULL")
        return
    print(f"\tsb ref count: {sb.s_active.counter}")
    print(f"\tsb s_count: {sb.s_count}")
    print(f"\tsb umount rw_sem counter {sb.s_umount.count.counter}")
    print(f"\tsb s_flags: {sb.s_flags}")
    print(f"\tsb s_dev {sb.s_dev}")
    print(f"\tsb s_id {sb.s_id}")
    print(f"\tsb i_flags {sb.s_iflags}")

    for mnt in list_for_each_entry("struct mount", sb.s_mounts.address_of_(), "mnt_instance"):
        if not mnt.mnt_master:
            print_mount_info(mnt)
            break

    return

def print_fs_info(fs_info):
    """Print key fields of `struct btrfs_fs_info`"""
    print("FS Info:")
    if not fs_info:
        print("\tfs_info is NULL")
        return

    print(f"\tFS State: {fs_info.fs_state}")
    print(f"\tFlags: {fs_info.flags}")
    print(f"\tmount opt: {fs_info.mount_opt}")

    print_super_block_info(fs_info.sb)
    return

def print_fs_devices_info(fs_dev):
    """"Print key fields of `struct btrfs_fs_devices`"""
    print("FS Devices:")
    print(f"\tFS UUID: {get_uuid_from_list(list(fs_dev.fsid))}")
    print(f"\tMETADATA UUID: {get_uuid_from_list(list(fs_dev.metadata_uuid))}")
    print(f"\tnum_devices: {fs_dev.num_devices}")
    print(f"\topen_devices: {fs_dev.open_devices}")
    print(f"\trw_devices: {fs_dev.rw_devices}")
    print(f"\tmissing_devices: {fs_dev.missing_devices}")
    print(f"\ttotal_rw_bytes: {fs_dev.total_rw_bytes}")
    print(f"\ttotal_devices: {fs_dev.total_devices}")
    print(f"\tlatest_generation: {fs_dev.latest_generation}")
    print(f"\topened: {fs_dev.opened}")
    try:
        print(f"\tfsid_change: {fs_dev.fsid_change}")
    except AttributeError:
        pass
    return

def print_dev_info(dev):
    """Print key fields of `struct btrfs_device`"""
    print("Device Info:")
    print(f"\tName: {str(dev.name.str)}")
    print(f"\tstate: {dev.dev_state}")
    print(f"\tdevid: {dev.devid}")
    print(f"\tgeneration: {dev.generation}")
    print(f"\ttype: {dev.type}")
    if not dev.bdev:
        print(f"\tbdev: NULL")
    else:
        print(f"\tbd_dev: {dev.bdev.bd_dev}")
        print(f"\tbd_partno: {dev.bdev.bd_partno}")
    return

def dump_mounts(s_mounts):
    """Dump master `struct mount` of a mount point"""
    for mnt in list_for_each_entry("struct mount", s_mounts.address_of_(), "mnt_instance"):
        if not mnt.mnt_master:
            print(f"struct mount:\n{mnt}")
            print(f"Mount Point Dentry:\n{mnt.mnt_mountpoint}")
            print(f"Namespace:\n{mnt.mnt_ns}")
            print(f"Mount Point Struct:\n{mnt.mnt_mp}")
            for cpu in for_each_possible_cpu(prog):
                print(f"mnt_pcp {cpu}:\n{per_cpu_ptr(mnt.mnt_pcp, cpu)}")
            break
    return

def dump_all(fs_uuids):
    """
    Dump all structure data of:
        - struct btrfs_fs_devices
        - struct btrfs_device
        - struct btrfs_fs_info
        - Running transaction => struct btrfs_transaction
        - struct btrfs_super_block
        - struct super_block
        - struct file_system_type
        - Root Dentry => struct dentry
        - Root Inode => struct inode
        - struct user_namespace
    """
    for fs_dev in list_for_each_entry("struct btrfs_fs_devices", fs_uuids.address_of_(), "fs_list"):
        print("-"*30 + f"{get_uuid_from_list(list(fs_dev.fsid))}" + '-'*30)
        print("FS Devices:\n", fs_dev)
        print("fs_dev.latest_bdev:", fs_dev.latest_bdev)
        if fs_dev.fs_info:
            print("FS Info:\n", fs_dev.fs_info)
            print("fs_info Running transaction:\n", fs_dev.fs_info.running_transaction)
            print("Disk superblock:\n", fs_dev.fs_info.super_copy)
            if fs_dev.fs_info.sb:
                print("Superblock:\n", fs_dev.fs_info.sb)
                print("Fs Type:\n", fs_dev.fs_info.sb.s_type)
                print("Root Dentry:\n", fs_dev.fs_info.sb.s_root)
                print("Root Inode:\n", fs_dev.fs_info.sb.s_root.d_inode)
                print("sb user namespace:\n", fs_dev.fs_info.sb.s_user_ns)
                dump_mounts(fs_dev.fs_info.sb.s_mounts)
            else:
                print("Superblock: NULL")
        else:
            print("FS Info: NULL")

        for dev in list_for_each_entry("struct btrfs_device", fs_dev.devices.address_of_(), "dev_list"):
            print("Device:\n", dev)
            print("Block Device:\n", dev.bdev)
            print("dev.flush_bio:\n", dev.flush_bio) 
        print("\n")
    return

def print_btrfs_cache(fs_uuids):
    """
    Iterate through the fs_uuids cache and print the details of each filesystem.
    """
    for fs_dev in list_for_each_entry("struct btrfs_fs_devices", fs_uuids.address_of_(), "fs_list"):
        print("-"*60)
        print_fs_devices_info(fs_dev)
        print_fs_info(fs_dev.fs_info)

        for dev in list_for_each_entry("struct btrfs_device", fs_dev.devices.address_of_(), "dev_list"):
            print_dev_info(dev)
    return

fs_uuids = prog['fs_uuids']

if args.dump == "yes":
    dump_all(fs_uuids)
else:
    print_btrfs_cache(fs_uuids)