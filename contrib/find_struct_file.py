#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Print what is using a struct file *, given as an address."""

import os
import sys

from drgn import Object
from drgn.helpers.linux.fs import for_each_file
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.pid import for_each_task


def find_struct_file_fds(file: Object) -> None:
    for task in for_each_task(file.prog_):
        for fd, fd_file in for_each_file(task):
            if fd_file == file:
                print(
                    f"PID {task.pid.value_()} COMM {task.comm.string_().decode()} FD {fd}"
                )


def find_struct_file_binfmt_misc(file: Object) -> None:
    prog = file.prog_
    for node in list_for_each_entry(
        prog.type("Node", filename="binfmt_misc.c"),
        prog.object("entries", filename="binfmt_misc.c").address_of_(),
        "list",
    ):
        if node.interp_file == file:
            print(f"binfmt_misc {os.fsdecode(node.name.string_())}")


def find_struct_file(file: Object) -> None:
    find_struct_file_fds(file)
    find_struct_file_binfmt_misc(file)


if __name__ == "__main__":
    find_struct_file(Object(prog, "struct file *", int(sys.argv[1], 0)))
