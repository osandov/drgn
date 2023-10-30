#!/usr/bin/env drgn
# Copyright (c) SUSE Linux.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Print memory map of a given task."""

import os
import sys

from drgn.helpers.linux.device import MAJOR, MINOR
from drgn.helpers.linux.fs import d_path
from drgn.helpers.linux.mm import for_each_vma
from drgn.helpers.linux.pid import find_task

if len(sys.argv) != 2:
    sys.exit("Usage: ./vmmap.py PID")
pid = int(sys.argv[1])

task = find_task(prog, int(pid))
if not task:
    sys.exit(f"Cannot find task {pid}")

FLAGS = ((0x1, "r"), (0x2, "w"), (0x4, "x"))
PAGE_SHIFT = prog["PAGE_SHIFT"]

print("Start        End          Flgs   Offset Dev   Inode            File path")

for vma in for_each_vma(task.mm):
    flags = "".join([v if f & vma.vm_flags else "-" for f, v in FLAGS])
    flags += "s" if vma.vm_flags & 0x8 else "p"
    print(f"{vma.vm_start.value_():0x}-{vma.vm_end.value_():0x} {flags} ",
          end="")

    vmfile = vma.vm_file
    if vmfile:
        inode = vmfile.f_inode.i_ino.value_()
        dev = vmfile.f_inode.i_sb.s_dev
        major, minor = MAJOR(dev), MINOR(dev)
        path = os.fsdecode(d_path(vmfile.f_path))
        pgoff = (vma.vm_pgoff << PAGE_SHIFT).value_()
    else:
        inode = 0
        major, minor = 0, 0
        path = ""
        pgoff = 0

    print(f"{pgoff:08x} {major:02x}:{minor:02x} {inode:<16} {path}")
