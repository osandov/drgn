# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""A simplified implementation of ps(1) using drgn"""

from drgn.helpers.linux.pid import for_each_task

print("PID        COMM")
for task in for_each_task(prog):
    pid = task.pid.value_()
    comm = task.comm.string_().decode()
    print(f"{pid:<10} {comm}")
