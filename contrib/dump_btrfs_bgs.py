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
