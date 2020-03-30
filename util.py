# Copyright 2020 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import os


def nproc() -> int:
    return len(os.sched_getaffinity(0))


def out_of_date(path: str, *deps: str) -> bool:
    try:
        mtime = os.stat(path).st_mtime
    except FileNotFoundError:
        return True
    return any(os.stat(dep).st_mtime > mtime for dep in deps)
