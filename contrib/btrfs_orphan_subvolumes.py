#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Dump Btrfs subvolumes that have been deleted but not cleaned up."""

from drgn import Object, cast
from drgn.helpers.linux.fs import inode_path, path_lookup
from drgn.helpers.linux.radixtree import radix_tree_for_each
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry


def dump_orphan_subvolumes(fs_info: Object) -> None:
    prog = fs_info.prog_
    BTRFS_ROOT_ORPHAN_ITEM_INSERTED = prog["BTRFS_ROOT_ORPHAN_ITEM_INSERTED"]
    for objectid, entry in radix_tree_for_each(fs_info.fs_roots_radix):
        root = cast("struct btrfs_root *", entry)
        if root.state & (1 << BTRFS_ROOT_ORPHAN_ITEM_INSERTED):
            print(f"orphan root {objectid} has the following inodes in memory:")
            for inode in rbtree_inorder_for_each_entry(
                "struct btrfs_inode", root.inode_tree.address_of_(), "rb_node"
            ):
                path = inode_path(inode.vfs_inode.address_of_())
                if path is None:
                    print(f"    inode {inode.vfs_inode.i_ino.value_()} with no cached names")
                else:
                    print(f"    {path.decode()}")


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()

    dump_orphan_subvolumes(
        cast(
            "struct btrfs_fs_info *",
            path_lookup(prog, args.path.resolve()).mnt.mnt_sb.s_fs_info,
        )
    )
