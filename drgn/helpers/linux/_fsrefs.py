# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Internal helpers for finding task references to files."""

from typing import Iterator, NamedTuple, Optional

from drgn import FaultError, Object
from drgn.helpers.linux.fs import for_each_file
from drgn.helpers.linux.mm import for_each_vma

__all__ = ("for_each_task_file_reference",)


class TaskFileReference(NamedTuple):
    usage: str
    object: Object
    is_path: bool


def for_each_task_file_reference(task: Object) -> Iterator[TaskFileReference]:
    """Iterate over the files referenced by a task's filesystem and memory state."""
    files: Optional[Object] = task.files.read_()
    fs: Optional[Object] = task.fs.read_()
    mm: Optional[Object] = task.mm.read_()

    # Threads usually share these structures with their group leader. Only
    # report shared references once, but still check task-specific state when a
    # thread has unshared one of them.
    group_leader = task.group_leader.read_()
    if task != group_leader:
        if files and files == group_leader.files:
            files = None
        if fs and fs == group_leader.fs:
            fs = None
        if mm and mm == group_leader.mm:
            mm = None

    if files:
        for fd, file in for_each_file(task):
            yield TaskFileReference(f"fd {fd}", file, False)

    if fs:
        yield TaskFileReference("root", fs.root.address_of_(), True)
        yield TaskFileReference("cwd", fs.pwd.address_of_(), True)

    if mm:
        exe_file = mm.exe_file.read_()
        if exe_file:
            yield TaskFileReference("exe", exe_file, False)

        for vma in for_each_vma(mm):
            try:
                file = vma.vm_file.read_()
                if file:
                    usage = f"vma {hex(vma.vm_start)}-{hex(vma.vm_end)}"
                    yield TaskFileReference(usage, file, False)
            except FaultError:
                continue
