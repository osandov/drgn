# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash ipcs command."""

import argparse
from typing import Any, Callable, Iterable, Iterator, List, Sequence, Tuple

from drgn import Object, Program
from drgn.commands import argument, argument_group, drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command, crash_get_context
from drgn.helpers.common.format import CellFormat, print_table
from drgn.helpers.linux.ipc import (
    decode_sysv_shm_mode_flags,
    find_sysv_msg_queue,
    find_sysv_sem_array,
    find_sysv_shm,
    for_each_sysv_msg_queue,
    for_each_sysv_sem_array,
    for_each_sysv_shm,
)
from drgn.helpers.linux.user import kuid_val


def _append_shm_code(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.user", "kuid_val")
    code.add_from_import("drgn.helpers.linux.ipc", "decode_sysv_shm_flags")
    code.append(
        """\
    key = shm.shm_perm.key
    id = shm.shm_perm.id
    uid = kuid_val(shm.shm_perm.uid)
    perms = shm.shm_perm.mode & 0o777
    bytes = shm.shm_segsz
    nattch = shm.shm_nattch
    status = decode_sysv_shm_flags(shm)
"""
    )


def _print_shms(shms: Iterable[Object]) -> None:
    rows: List[Sequence[Any]] = [
        (
            "SHMID_KERNEL",
            "KEY",
            "SHMID",
            "UID",
            "PERMS",
            "BYTES",
            "NATTCH",
            "STATUS",
        )
    ]
    for shm in shms:
        mode: int = shm.shm_perm.mode.value_()
        status = decode_sysv_shm_mode_flags(shm.prog_, mode)
        if status == "0":
            status = ""
        rows.append(
            (
                CellFormat(shm.value_(), "x"),
                f"{shm.shm_perm.key.value_():08x}",
                CellFormat(shm.shm_perm.id.value_(), "<"),
                CellFormat(kuid_val(shm.shm_perm.uid), "<"),
                CellFormat(mode & 0o777, "<o"),
                CellFormat(shm.shm_segsz.value_(), "<"),
                CellFormat(shm.shm_nattch.value_(), "<"),
                status,
            )
        )
    print_table(rows)
    if len(rows) == 1:
        print("(none allocated)")


def _append_sem_array_code(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.user", "kuid_val")
    code.append(
        """\
    key = sem_array.sem_perm.key
    id = sem_array.sem_perm.id
    uid = kuid_val(sem_array.sem_perm.uid)
    perms = sem_array.sem_perm.mode
    nsems = sem_array.sem_nsems
"""
    )


def _print_sem_arrays(sem_arrays: Iterable[Object]) -> None:
    rows: List[Sequence[Any]] = [
        (
            "SEM_ARRAY",
            "KEY",
            "SEMID",
            "UID",
            "PERMS",
            "NSEMS",
        )
    ]
    for sem_array in sem_arrays:
        rows.append(
            (
                CellFormat(sem_array.value_(), "x"),
                f"{sem_array.sem_perm.key.value_():08x}",
                CellFormat(sem_array.sem_perm.id.value_(), "<"),
                CellFormat(kuid_val(sem_array.sem_perm.uid), "<"),
                CellFormat(sem_array.sem_perm.mode.value_() & 0o777, "<o"),
                CellFormat(sem_array.sem_nsems.value_(), "<"),
            )
        )
    print_table(rows)
    if len(rows) == 1:
        print("(none allocated)")


def _append_msg_queue_code(code: CrashDrgnCodeBuilder) -> None:
    code.add_from_import("drgn.helpers.linux.user", "kuid_val")
    code.append(
        """\
    key = msg_queue.q_perm.key
    id = msg_queue.q_perm.id
    uid = kuid_val(msg_queue.q_perm.uid)
    perms = msg_queue.q_perm.mode
    used_bytes = msg_queue.q_cbytes
    messages = msg_queue.q_qnum
"""
    )


def _print_msg_queues(msg_queues: Iterable[Object]) -> None:
    rows: List[Sequence[Any]] = [
        (
            "MSG_QUEUE",
            "KEY",
            "MSQID",
            "UID",
            "PERMS",
            "USED-BYTES",
            "MESSAGES",
        )
    ]
    for msg_queue in msg_queues:
        rows.append(
            (
                CellFormat(msg_queue.value_(), "x"),
                f"{msg_queue.q_perm.key.value_():08x}",
                CellFormat(msg_queue.q_perm.id.value_(), "<"),
                CellFormat(kuid_val(msg_queue.q_perm.uid), "<"),
                CellFormat(msg_queue.q_perm.mode.value_() & 0o777, "<o"),
                CellFormat(msg_queue.q_cbytes.value_(), "<"),
                CellFormat(msg_queue.q_qnum.value_(), "<"),
            )
        )
    print_table(rows)
    if len(rows) == 1:
        print("(none allocated)")


@crash_command(
    description="System V IPC",
    arguments=(
        argument_group(
            argument(
                "-s",
                dest="sem_arrays",
                action="store_true",
                help="display semaphore arrays",
            ),
            argument(
                "-m",
                dest="shms",
                action="store_true",
                help="display shared memory segments",
            ),
            argument(
                "-q",
                dest="msg_queues",
                action="store_true",
                help="display message queues",
            ),
            title="types",
            description="IPC types to display. If none are given, all three are displayed.",
        ),
        argument(
            "-n",
            dest="task",
            metavar="pid|task",
            type="pid_or_task",
            help="""
            search in the IPC namespace of a task, given as either a decimal
            process ID or a hexadecimal ``task_struct`` address. Defaults to
            the IPC namespace of the current context
            """,
        ),
        argument(
            "id_or_addr",
            metavar="id|addr",
            nargs="*",
            help="""
            search for IPC instances with the given decimal identifier or
            hexadecimal kernel address. May be given multiple times
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_ipcs(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if not any((args.sem_arrays, args.shms, args.msg_queues)):
        args.sem_arrays = args.shms = args.msg_queues = True

    types: List[
        Tuple[
            str,
            Callable[[CrashDrgnCodeBuilder], None],
            Callable[[Iterable[Object]], None],
            Callable[[Object], Iterator[Object]],
            Callable[[Object, int], Object],
        ]
    ] = []
    if args.shms:
        types.append(
            ("shm", _append_shm_code, _print_shms, for_each_sysv_shm, find_sysv_shm)
        )
    if args.sem_arrays:
        types.append(
            (
                "sem_array",
                _append_sem_array_code,
                _print_sem_arrays,
                for_each_sysv_sem_array,
                find_sysv_sem_array,
            )
        )
    if args.msg_queues:
        types.append(
            (
                "msg_queue",
                _append_msg_queue_code,
                _print_msg_queues,
                for_each_sysv_msg_queue,
                find_sysv_msg_queue,
            )
        )

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)

        # Avoid the context/IPC namespace noise if -n wasn't given and the
        # current context is in the initial IPC namespace.
        if (
            args.task is None
            and crash_get_context(prog).nsproxy.ipc_ns
            == prog["init_ipc_ns"].address_of_()
        ):
            ns_var = ""
            ns_var_with_comma = ""
        else:
            code.append_crash_context(args.task)
            code.append("ipc_ns = task.nsproxy.ipc_ns\n\n")
            ns_var = "ipc_ns"
            ns_var_with_comma = "ipc_ns, "

        first = True
        if args.id_or_addr:
            for id_or_addr in args.id_or_addr:
                try:
                    id = int(id_or_addr, 10)
                except ValueError:
                    addr = int(id_or_addr, 16)
                    code.append(f"addr = {hex(addr)}\n\n")
                    for name, append_fn, _, _, _ in types:
                        if first:
                            first = False
                        else:
                            code.append("\n")
                        code.add_from_import(
                            "drgn.helpers.linux.ipc", "for_each_sysv_" + name
                        )
                        code.append(
                            f"""\
for {name} in for_each_sysv_{name}({ns_var}):
    if {name}.value_() != addr:
        continue
"""
                        )
                        append_fn(code)
                else:
                    for name, append_fn, _, _, _ in types:
                        if first:
                            first = False
                        else:
                            code.append("\n")
                        code.add_from_import(
                            "drgn.helpers.linux.ipc", "find_sysv_" + name
                        )
                        code.append(
                            f"""\
{name} = find_sysv_{name}({ns_var_with_comma}{id})
if {name}:
"""
                        )
                        append_fn(code)
        else:
            for name, append_fn, _, _, _ in types:
                if first:
                    first = False
                else:
                    code.append("\n")
                code.add_from_import("drgn.helpers.linux.ipc", "for_each_sysv_" + name)
                code.append(
                    f"""\
for {name} in for_each_sysv_{name}({ns_var}):
"""
                )
                append_fn(code)

        return code.print()

    ns = crash_get_context(prog, args.task).nsproxy.ipc_ns

    first = True
    if args.id_or_addr:
        for id_or_addr in args.id_or_addr:
            arg_found = False
            try:
                id = int(id_or_addr, 10)
            except ValueError:
                addr = int(id_or_addr, 16)
                for _, _, print_fn, for_each_fn, _ in types:
                    matches = [obj for obj in for_each_fn(ns) if obj.value_() == addr]
                    if matches:
                        arg_found = True
                        if first:
                            first = False
                        else:
                            print()
                        print_fn(matches)
                if not arg_found:
                    if first:
                        first = False
                    else:
                        print()
                    print("invalid address:", hex(addr))
            else:
                for _, _, print_fn, _, find_fn in types:
                    found = find_fn(ns, id)
                    if found:
                        arg_found = True
                        if first:
                            first = False
                        else:
                            print()
                        print_fn((found,))
                if not arg_found:
                    if first:
                        first = False
                    else:
                        print()
                    print("invalid id:", id)
    else:
        for _, _, print_fn, for_each_fn, _ in types:
            if first:
                first = False
            else:
                print()
            print_fn(for_each_fn(ns))
