#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Find what process is using a struct file *, given as an address."""

import sys

from drgn import Object
from drgn.helpers.linux.fs import for_each_file
from drgn.helpers.linux.pid import for_each_task

file = Object(prog, "struct file *", int(sys.argv[1], 0))
for task in for_each_task(prog):
    for fd, file2 in for_each_file(task):
        if file2 == file:
            break
    else:
        continue
    break
else:
    print("Not found:(")
print(f"PID {task.pid.value_()} COMM {task.comm.string_().decode()} FD {fd}")
