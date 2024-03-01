#!/usr/bin/env drgn

import argparse
import os
import typing
from typing import Any, Callable, Optional, Sequence, Union

from drgn import FaultError, Object, Program
from drgn.helpers.linux.fs import fget, for_each_file
from drgn.helpers.linux.mm import for_each_vma
from drgn.helpers.linux.pid import find_task, for_each_task

if typing.TYPE_CHECKING:

    class Visitor(typing.Protocol):  # novermin
        def visit_file(self, file: Object) -> bool:
            ...

        def visit_inode(self, inode: Object) -> bool:
            ...

        def visit_path(self, path: Object) -> bool:
            ...


class InodeVisitor:
    def __init__(self, inode: Object) -> None:
        self._inode = inode.read_()

    def visit_file(self, file: Object) -> bool:
        return file.f_inode == self._inode

    def visit_inode(self, inode: Object) -> bool:
        return inode == self._inode

    def visit_path(self, path: Object) -> bool:
        return path.dentry.d_inode == self._inode


class warn_on_fault:
    def __init__(self, message: Union[str, Callable[[], str]]) -> None:
        self._message = message

    def __enter__(self) -> None:
        pass

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        if exc_type is not None and issubclass(exc_type, FaultError):
            message = (
                self._message if isinstance(self._message, str) else self._message()
            )
            if message:
                print(
                    f"warning: fault while {message}, possibly due to race; results may be incomplete",
                    file=sys.stderr,
                )
            return True
        return False


ignore_fault = warn_on_fault("")

format_args = {
    "dereference": False,
    "symbolize": False,
}


def visit_tasks(prog: Program, visitor: "Visitor") -> None:
    with warn_on_fault("iterating tasks"):
        for task in for_each_task(prog):
            cached_task_id = None

            def task_id() -> str:
                nonlocal cached_task_id
                if cached_task_id is None:
                    pid = task.pid.value_()
                    comm = os.fsdecode(task.comm.string_())
                    cached_task_id = f"pid {pid} ({comm})"
                return cached_task_id

            def task_fault_warning() -> str:
                try:
                    return f"checking {task_id()}"
                except FaultError:
                    return "checking task"

            with warn_on_fault(task_fault_warning):
                files: Optional[Object] = task.files.read_()
                fs: Optional[Object] = task.fs.read_()
                mm: Optional[Object] = task.mm.read_()

                # If this task is not the thread group leader, don't bother
                # checking it again unless it has its own context.
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
                        with ignore_fault:
                            if visitor.visit_file(file):
                                print(
                                    f"{task_id()} fd {fd} {file.format_(**format_args)}"
                                )

                if fs:
                    with ignore_fault:
                        if visitor.visit_path(fs.root):
                            print(
                                f"{task_id()} root {fs.root.address_of_().format_(**format_args)}"
                            )
                    with ignore_fault:
                        if visitor.visit_path(fs.pwd):
                            print(
                                f"{task_id()} cwd {fs.pwd.address_of_().format_(**format_args)}"
                            )

                if mm:
                    exe_file = mm.exe_file.read_()
                    if exe_file and visitor.visit_file(exe_file):
                        print(f"{task_id()} exe {exe_file.format_(**format_args)}")

                    for vma in for_each_vma(mm):
                        with ignore_fault:
                            file = vma.vm_file.read_()
                            if file and visitor.visit_file(file):
                                print(
                                    f"{task_id()} vma {hex(vma.vm_start)}-{hex(vma.vm_end)} {vma.format_(**format_args)}"
                                )


def hexint(x: str) -> int:
    return int(x, 16)


def main(prog: Program, argv: Sequence[str]) -> None:
    parser = argparse.ArgumentParser(
        description="find what is referencing a filesystem object"
    )
    object_group = parser.add_argument_group(
        title="filesystem object selection"
    ).add_mutually_exclusive_group(required=True)
    object_group.add_argument(
        "--inode", metavar="PATH", help="find references to the inode at the given path"
    )
    object_group.add_argument(
        "--inode-pointer",
        metavar="ADDRESS",
        type=hexint,
        help="find references to the given struct inode pointer",
    )
    parser.add_argument(
        "-L",
        "--dereference",
        action="store_true",
        help="if the given path is a symbolic link, follow it",
    )
    args = parser.parse_args(argv)

    if args.inode is not None:
        fd = os.open(args.inode, os.O_PATH | (0 if args.dereference else os.O_NOFOLLOW))
        try:
            visitor = InodeVisitor(fget(find_task(prog, os.getpid()), fd).f_inode)
        finally:
            os.close(fd)
    elif args.inode_pointer is not None:
        visitor = InodeVisitor(Object(prog, "struct inode *", args.inode_pointer))
    else:
        assert False

    visit_tasks(prog, visitor)


if __name__ == "__main__":
    import sys

    prog: Program
    main(prog, sys.argv[1:])
