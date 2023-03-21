#!/usr/bin/env drgn
# Copyright (c) Western Digital Corporation, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""  Dump all block group caches for a given btrfs file-system """

import sys
import drgn
from enum import Flag
from drgn import NULL, Object, cast, container_of, execscript, \
        reinterpret, sizeof
from drgn.helpers.linux import *
from drgn.helpers.common import decode_flags

BTRFS_BLOCK_GROUP_FLAGS = [
        ("BTRFS_BLOCK_GROUP_DATA", 0),
        ("BTRFS_BLOCK_GROUP_SYSTEM", 1),
        ("BTRFS_BLOCK_GROUP_METADATA", 2),
        ("BTRFS_BLOCK_GROUP_RAID0", 3),
        ("BTRFS_BLOCK_GROUP_RAID1", 4),
        ("BTRFS_BLOCK_GROUP_DUP", 5),
        ("BTRFS_BLOCK_GROUP_RAID10", 6),
        ("BTRFS_BLOCK_GROUP_RAID5", 9),
        ("BTRFS_BLOCK_GROUP_RAID6", 8),
        ("BTRFS_BLOCK_GROUP_RAID1C3", 9),
        ("BTRFS_BLOCK_GROUP_RAID1C4", 10)
        ]

BTRFS_BLOCK_GROUP_RUNTIME_FLAGS = [
        ("BLOCK_GROUP_FLAG_IREF", 0),
        ("BLOCK_GROUP_FLAG_REMOVED", 1),
        ("BLOCK_GROUP_FLAG_TO_COPY", 2),
        ("BLOCK_GROUP_FLAG_RELOCATING_REPAIR", 3),
        ("BLOCK_GROUP_FLAG_CHUNK_ITEM_INSERTED", 4),
        ("BLOCK_GROUP_FLAG_ZONE_IS_ACTIVE", 5),
        ("BLOCK_GROUP_FLAG_ZONED_DATA_RELOC", 6),
        ("BLOCK_GROUP_FLAG_NEEDS_FREE_SPACE", 7),
        ("BLOCK_GROUP_FLAG_SEQUENTIAL_ZONE", 8)
        ]

if len(sys.argv) > 1:
    mnt_path = sys.argv[1]
    mnt_path = mnt_path.rstrip('/')
else:
    mnt_path = "/"

mnt = None

for mnt in for_each_mount(prog, dst = mnt_path):
    pass

if mnt is None:
    sys.stderr.write(f'Error: mount point {mnt_path} not found')
    sys.exit(1)

try:
    fs_info = cast('struct btrfs_fs_info *', mnt.mnt.mnt_sb.s_fs_info)
except LookupError:
    print('cannot find \'struct btrfs_fs_info *\', module not loaded?')
    sys.exit(1)

def dump_bg(bg):
    print(f'BG at {bg.start.value_()}')
    print(f'\tflags: {decode_flags(bg.flags.value_(), BTRFS_BLOCK_GROUP_FLAGS)} ({hex(bg.flags)})')
    print(f'\tlength: {bg.length.value_()}')
    print(f'\tused: {bg.used.value_()}')
    print(f'\tpinned: {bg.pinned.value_()}')
    print(f'\treserved: {bg.reserved.value_()}')
    print(f'\truntime_flags: {decode_flags(bg.runtime_flags.value_(), BTRFS_BLOCK_GROUP_RUNTIME_FLAGS)} ({hex(bg.runtime_flags)})')
    if bg.fs_info.zone_size.value_() > 0:
        print(f'\tzone_unsuable: {bg.zone_unusable.value_()}')
    print()

for bg in rbtree_inorder_for_each_entry("struct btrfs_block_group",\
        fs_info.block_group_cache_tree.rb_root, "cache_node"):
    dump_bg(bg)
