#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""List the paths of all inodes cached in a given filesystem"""

import os
import sys

from drgn.helpers.linux.fs import for_each_mount, inode_path
from drgn.helpers.linux.list import list_for_each_entry

if len(sys.argv) == 1:
    path = "/"
else:
    path = sys.argv[1]

mnt = None
for mnt in for_each_mount(prog, dst=path):
    pass
if mnt is None:
    sys.exit(f"No filesystem mounted at {path}")

sb = mnt.mnt.mnt_sb

for inode in list_for_each_entry(
    "struct inode", sb.s_inodes.address_of_(), "i_sb_list"
):
    try:
        print(os.fsdecode(inode_path(inode)))
    except (TypeError, ValueError):
        continue
