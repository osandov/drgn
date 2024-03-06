#!/usr/bin/env drgn

import argparse
import os
import sys
import typing
from typing import Any, Callable, Optional, Sequence, Union

from drgn import FaultError, Object, Program, cast, container_of
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.fs import (
    d_path,
    fget,
    for_each_file,
    for_each_mount,
    inode_path,
    mount_dst,
)
from drgn.helpers.linux.idr import idr_for_each_entry
from drgn.helpers.linux.list import (
    hlist_for_each_entry,
    list_empty,
    list_for_each_entry,
)
from drgn.helpers.linux.mm import for_each_vma
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.pid import find_task, for_each_task
from drgn.helpers.linux.plist import plist_for_each_entry
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry


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


if typing.TYPE_CHECKING:

    class Visitor(typing.Protocol):  # novermin
        def visit_file(self, file: Object) -> Optional[str]:
            ...

        def visit_inode(self, inode: Object) -> Optional[str]:
            ...

        def visit_path(self, path: Object) -> Optional[str]:
            ...


class InodeVisitor:
    def __init__(self, inode: Object) -> None:
        self._inode = inode.read_()

    def visit_file(self, file: Object) -> Optional[str]:
        if file.f_inode != self._inode:
            return None
        return file.format_(**format_args)

    def visit_inode(self, inode: Object) -> Optional[str]:
        if inode != self._inode:
            return None
        return inode.format_(**format_args)

    def visit_path(self, path: Object) -> Optional[str]:
        if path.dentry.d_inode != self._inode:
            return None
        return path.format_(**format_args)


class SuperBlockVisitor:
    def __init__(self, sb: Object) -> None:
        self._sb = sb.read_()

    def visit_file(self, file: Object) -> Optional[str]:
        if file.f_inode.i_sb != self._sb:
            return None
        match = file.format_(**format_args)
        with ignore_fault:
            match += " " + os.fsdecode(d_path(file.f_path))
        return match

    def visit_inode(self, inode: Object) -> Optional[str]:
        if inode.i_sb != self._sb:
            return None
        match = inode.format_(**format_args)
        with ignore_fault:
            path = inode_path(inode)
            if path:
                match += " " + os.fsdecode(path)
        return match

    def visit_path(self, path: Object) -> Optional[str]:
        if path.mnt.mnt_sb != self._sb:
            return None
        match = path.format_(**format_args)
        with ignore_fault:
            match += " " + os.fsdecode(d_path(path))
        return match


def visit_tasks(
    prog: Program, visitor: "Visitor", *, check_mounts: bool, check_tasks: bool
) -> None:
    check_mounts = check_mounts and isinstance(visitor, SuperBlockVisitor)
    if check_mounts:
        init_mnt_ns = prog["init_task"].nsproxy.mnt_ns
        checked_mnt_ns = {0}
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

                if check_mounts:
                    nsproxy = task.nsproxy.read_()
                    if nsproxy:
                        mnt_ns = nsproxy.mnt_ns.read_()
                        if mnt_ns.value_() not in checked_mnt_ns:
                            for mount in for_each_mount(mnt_ns):
                                with ignore_fault:
                                    if mount.mnt.mnt_sb == visitor._sb:  # type: ignore [attr-defined]
                                        if mnt_ns == init_mnt_ns:
                                            mnt_ns_note = ""
                                        else:
                                            mnt_ns_note = f" (mount namespace {mnt_ns.ns.inum.value_()})"
                                        print(
                                            f"mount {os.fsdecode(mount_dst(mount))}{mnt_ns_note} "
                                            f"{mount.format_(**format_args)}"
                                        )

                            checked_mnt_ns.add(mnt_ns.value_())

                if check_tasks:
                    if files:
                        for fd, file in for_each_file(task):
                            with ignore_fault:
                                match = visitor.visit_file(file)
                                if match:
                                    print(f"{task_id()} fd {fd} {match}")

                    if fs:
                        with ignore_fault:
                            match = visitor.visit_path(fs.root.address_of_())
                            if match:
                                print(f"{task_id()} root {match}")
                        with ignore_fault:
                            match = visitor.visit_path(fs.pwd.address_of_())
                            if match:
                                print(f"{task_id()} cwd {match}")

                    if mm:
                        exe_file = mm.exe_file.read_()
                        if exe_file:
                            match = visitor.visit_file(exe_file)
                            if match:
                                print(f"{task_id()} exe {match}")

                        for vma in for_each_vma(mm):
                            with ignore_fault:
                                file = vma.vm_file.read_()
                                if file:
                                    match = visitor.visit_file(file)
                                    if match:
                                        print(
                                            f"{task_id()} vma {hex(vma.vm_start)}-{hex(vma.vm_end)} {match}"
                                        )


def visit_binfmt_misc(prog: Program, visitor: "Visitor") -> None:
    try:
        Node = prog.type("Node", filename="binfmt_misc.c")
    except LookupError:
        # If the Node type doesn't exist, then CONFIG_BINFMT_MISC=n or the
        # binfmt_misc module isn't loaded.
        return
    with warn_on_fault("iterating binfmt_misc instances"):
        for sb in hlist_for_each_entry(
            "struct super_block", prog["bm_fs_type"].fs_supers, "s_instances"
        ):
            # Since Linux kernel commit 21ca59b365c0 ("binfmt_misc: enable
            # sandboxed mounts") (in v6.7), each user namespace can have its
            # own binfmt_misc instance. Before that, there is one global
            # instance.
            user_ns = cast("struct user_namespace *", sb.s_fs_info)
            try:
                binfmt_misc = user_ns.binfmt_misc
            except AttributeError:
                entries = prog.object("entries", filename="binfmt_misc.c")
                have_user_ns = False
            else:
                entries = binfmt_misc.entries
                have_user_ns = True

            for node in list_for_each_entry(Node, entries.address_of_(), "list"):
                with ignore_fault:
                    match = visitor.visit_file(node.interp_file)
                    if match:
                        if have_user_ns and user_ns.level:
                            user_ns_note = (
                                f" (user namespace {user_ns.ns.inum.value_()})"
                            )
                        else:
                            user_ns_note = ""
                        print(
                            f"binfmt_misc{user_ns_note} {os.fsdecode(node.name.string_())} {node.format_(**format_args)} {match}"
                        )


def visit_loop_devices(prog: Program, visitor: "Visitor") -> None:
    try:
        loop_index_idr = prog["loop_index_idr"]
    except KeyError:
        # If loop_index_idr doesn't exist, then CONFIG_BLK_DEV_LOOP=n or the
        # loop module isn't loaded.
        return
    with warn_on_fault("iterating loop devices"):
        for i, lo in idr_for_each_entry(
            loop_index_idr.address_of_(), "struct loop_device"
        ):
            with ignore_fault:
                file = lo.lo_backing_file.read_()
                if file:
                    match = visitor.visit_file(file)
                    if match:
                        print(f"loop device {i} {lo.format_(**format_args)} {match}")


def visit_swap_files(prog: Program, visitor: "Visitor") -> None:
    try:
        swap_active_head = prog["swap_active_head"]
    except KeyError:
        # If swap_active_head doesn't exist, then CONFIG_SWAP=n.
        return
    with warn_on_fault("iterating swap files"):
        for swap_info in plist_for_each_entry(
            "struct swap_info_struct", swap_active_head.address_of_(), "list"
        ):
            with ignore_fault:
                match = visitor.visit_file(swap_info.swap_file)
                if match:
                    print(f"swap file {swap_info.format_(**format_args)} {match}")


# call was moved from struct trace_probe to struct trace_event Linux kernel
# commit 60d53e2c3b75 ("tracing/probe: Split trace_event related data from
# trace_probe") (in v5.4).
def _trace_probe_call(tp: Object) -> Object:
    try:
        event = tp.event
    except AttributeError:
        return tp.call
    return event.call


def trace_probe_group_name(tp: Object) -> str:
    return os.fsdecode(_trace_probe_call(tp).member_("class").system.string_())


def trace_probe_name(tp: Object) -> str:
    prog = tp.prog_
    call = _trace_probe_call(tp).read_()

    # TRACE_EVENT_FL_CUSTOM was added in Linux kernel commit 3a73333fb370
    # ("tracing: Add TRACE_CUSTOM_EVENT() macro") (in v5.18).
    try:
        TRACE_EVENT_FL_CUSTOM = prog["TRACE_EVENT_FL_CUSTOM"]
    except KeyError:
        pass
    else:
        if call.flags & TRACE_EVENT_FL_CUSTOM:
            return os.fsdecode(call.name.string_())

    if call.flags & prog["TRACE_EVENT_FL_TRACEPOINT"]:
        tracepoint = call.tp.read_()
        return os.fsdecode(tracepoint.name.string_()) if tracepoint else ""
    else:
        return os.fsdecode(call.name.string_())


def visit_uprobes(prog: Program, visitor: "Visitor") -> None:
    try:
        uprobes_tree = prog["uprobes_tree"]
    except KeyError:
        # If uprobes_tree doesn't exist, then CONFIG_UPROBES=n.
        return
    try:
        uprobe_dispatcher = prog["uprobe_dispatcher"]
    except KeyError:
        # uprobe_dispatcher only exists if CONFIG_UPROBE_EVENTS=y, which is
        # theoretically separate from CONFIG_UPROBES, although as of Linux 6.8
        # they will always be the same.
        uprobe_dispatcher = None
    with warn_on_fault("iterating uprobes"):
        for uprobe in rbtree_inorder_for_each_entry(
            "struct uprobe", uprobes_tree.address_of_(), "rb_node"
        ):
            try:
                match = visitor.visit_inode(uprobe.inode)
            except FaultError:
                continue
            if not match:
                continue
            found_consumer = False
            with warn_on_fault("iterating uprobe consumers"):
                consumer = uprobe.consumers.read_()
                while consumer:
                    handler = consumer.handler.read_()
                    if handler == uprobe_dispatcher:
                        tu = container_of(consumer, "struct trace_uprobe", "consumer")
                        # uprobe events created through tracefs are in a list
                        # anchored on devent.list since Linux kernel commit
                        # 0597c49c69d5 ("tracing/uprobes: Use dyn_event
                        # framework for uprobe events") (in v5.0) and list
                        # before that.
                        try:
                            event_list = tu.devent.list
                        except AttributeError:
                            event_list = tu.list
                        if list_empty(event_list.address_of_()):
                            found_perf_event = False
                            with ignore_fault:
                                call = _trace_probe_call(tu.tp)
                                # uprobes created with perf_event_open have a
                                # struct perf_event in call.perf_events, which
                                # only exists if CONFIG_PERF_EVENTS=y.
                                try:
                                    perf_events = call.perf_events
                                except AttributeError:
                                    pass
                                else:
                                    for cpu in for_each_possible_cpu(prog):
                                        for perf_event in hlist_for_each_entry(
                                            "struct perf_event",
                                            per_cpu_ptr(perf_events, cpu),
                                            "hlist_entry",
                                        ):
                                            owner = perf_event.owner.read_()
                                            if owner:
                                                owner_pid = owner.pid.value_()
                                                owner_comm = os.fsdecode(
                                                    owner.comm.string_()
                                                )
                                                print(
                                                    f"perf uprobe (owned by pid {owner_pid} ({owner_comm})) {perf_event.format_(**format_args)} {match}"
                                                )
                                            else:
                                                print(
                                                    f"perf uprobe (no owner) {perf_event.format_(**format_args)} {match}"
                                                )
                                            found_perf_event = True
                            if not found_perf_event:
                                print(
                                    f"unknown trace uprobe {tu.format_(**format_args)} {match}"
                                )
                        else:
                            c = "r" if tu.consumer.ret_handler else "p"
                            group_name = trace_probe_group_name(tu.tp)
                            event_name = trace_probe_name(tu.tp)
                            print(
                                f"uprobe event {c}:{group_name}/{event_name} {tu.format_(**format_args)} {match}"
                            )
                    else:
                        print(
                            f"unknown uprobe consumer {consumer.format_(**format_args)}"
                        )
                    consumer = consumer.next.read_()
            if not found_consumer:
                print(f"unknown uprobe {uprobe.format_(**format_args)} {match}")


def hexint(x: str) -> int:
    return int(x, 16)


def main(prog: Program, argv: Sequence[str]) -> None:
    parser = argparse.ArgumentParser(
        description="find what is referencing a filesystem object"
    )

    parser.add_argument(
        "-L",
        "--dereference",
        action="store_true",
        help="if the given path is a symbolic link, follow it",
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
    object_group.add_argument(
        "--super-block",
        metavar="PATH",
        help="find references to the filesystem (super block) containing the given path",
    )
    object_group.add_argument(
        "--super-block-pointer",
        metavar="ADDRESS",
        type=hexint,
        help="find references to the given struct super_block pointer",
    )

    CHECKS = [
        "binfmt_misc",
        "loop",
        "mounts",
        "swap",
        "tasks",
        "uprobes",
    ]
    check_group = parser.add_argument_group(
        title="check selection"
    ).add_mutually_exclusive_group()
    check_group.add_argument(
        "--check",
        choices=CHECKS,
        action="append",
        help="only check for references from the given source; may be given multiple times (default: all)",
    )
    check_group.add_argument(
        "--no-check",
        choices=CHECKS,
        action="append",
        help="don't check for references from the given source; may be given multiple times",
    )

    args = parser.parse_args(argv)

    visitor: "Visitor"
    if args.inode is not None:
        fd = os.open(args.inode, os.O_PATH | (0 if args.dereference else os.O_NOFOLLOW))
        try:
            visitor = InodeVisitor(fget(find_task(prog, os.getpid()), fd).f_inode)
        finally:
            os.close(fd)
    elif args.inode_pointer is not None:
        visitor = InodeVisitor(Object(prog, "struct inode *", args.inode_pointer))
    elif args.super_block is not None:
        fd = os.open(
            args.super_block, os.O_PATH | (0 if args.dereference else os.O_NOFOLLOW)
        )
        try:
            visitor = SuperBlockVisitor(
                fget(find_task(prog, os.getpid()), fd).f_inode.i_sb
            )
        finally:
            os.close(fd)
    elif args.super_block_pointer is not None:
        visitor = SuperBlockVisitor(
            Object(prog, "struct super_block *", args.super_block_pointer)
        )
    else:
        assert False

    if args.check:
        enabled_checks = set(args.check)
    else:
        enabled_checks = set(CHECKS)
        if args.no_check:
            enabled_checks -= set(args.no_check)

    if "mounts" in enabled_checks or "tasks" in enabled_checks:
        visit_tasks(
            prog,
            visitor,
            check_mounts="mounts" in enabled_checks,
            check_tasks="tasks" in enabled_checks,
        )

    if "binfmt_misc" in enabled_checks:
        visit_binfmt_misc(prog, visitor)

    if "loop" in enabled_checks:
        visit_loop_devices(prog, visitor)

    if "swap" in enabled_checks:
        visit_swap_files(prog, visitor)

    if "uprobes" in enabled_checks:
        visit_uprobes(prog, visitor)


if __name__ == "__main__":
    prog: Program
    main(prog, sys.argv[1:])
