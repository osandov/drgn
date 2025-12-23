# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands for inspecting structures and unions."""

import argparse
import functools
import sys
from typing import Any, Iterable, List, Optional, Tuple, Union

from drgn import Object, Program, offsetof, sizeof
from drgn.commands import CommandError, _repr_black, argument, drgn_argument
from drgn.commands.crash import (
    _PID_OR_TASK,
    Cpuspec,
    CrashDrgnCodeBuilder,
    _crash_foreach_subcommand,
    _guess_type,
    _guess_type_name,
    _object_format_options,
    _parse_members,
    _parse_type_name_and_members,
    _parse_type_offset_arg,
    _pid_or_task,
    _prefer_object_lookup,
    _sanitize_member_name,
    _TaskSelector,
    crash_command,
    parse_cpuspec,
    print_task_header,
)
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.sched import task_thread_info


# Workaround for https://github.com/python/cpython/issues/80259 from
# https://github.com/python/cpython/issues/80259#issuecomment-1093816101.
@functools.wraps(int)
def _int_or_suppress(s: str) -> Union[int, str]:
    return s if s is argparse.SUPPRESS else int(s)


def _struct_drgn_option(
    prog: Program,
    args: argparse.Namespace,
    *,
    name: str,
    members: List[str],
    type_name: str,
    offset_arg: Union[None, int, Tuple[str, str]],
    address_or_symbol: Optional[str],
    cpuspec: Optional[Cpuspec],
) -> None:
    if address_or_symbol is None:
        if members:
            sys.stdout.write(
                f"""\
from drgn import offsetof
from drgn.helpers.common.type import typeof_member


type = prog.type("{type_name}")
"""
            )
            for member in members:
                sys.stdout.write(
                    f"""
{_sanitize_member_name(member)}_type = typeof_member(type, "{member}")
{_sanitize_member_name(member)}_offset = offsetof(type, "{member}")
"""
                )
        else:
            sys.stdout.write(
                f"""\
from drgn import sizeof


type = prog.type("{type_name}")
size = sizeof(type)
"""
            )
        return

    code = CrashDrgnCodeBuilder(prog)

    object_or_pointer = "object" if args.count == 1 else "pointer"
    per_cpu_helper = "per_cpu" if object_or_pointer == "object" else "per_cpu_ptr"
    pcpu_prefix = "" if cpuspec is None else "pcpu_"

    if isinstance(offset_arg, tuple):

        def initial_object(address: str) -> str:
            return f'offset_pointer = Object(prog, "void *", {address})'

    elif object_or_pointer == "object":

        def initial_object(address: str) -> str:
            return (
                f'{pcpu_prefix}object = Object(prog, "{type_name}", address={address})'
            )

    else:

        def initial_object(address: str) -> str:
            return f'{pcpu_prefix}pointer = Object(prog, "{type_name} *", {address})'

    if isinstance(offset_arg, int):
        subtract_offset = f" - {offset_arg}"
    else:
        subtract_offset = ""

    try:
        address = int(address_or_symbol, 16)
    except ValueError:
        # This command technically always does a symbol lookup, but prefer
        # recommending a prog[] lookup if it is equivalent.
        if offset_arg is None and _prefer_object_lookup(
            prog, type_name, address_or_symbol
        ):
            code.append(
                f"{pcpu_prefix}{object_or_pointer} = prog[{_repr_black(address_or_symbol)}]"
            )
            if object_or_pointer == "pointer":
                code.append(".address_of_()")
            code.append("\n")
        else:
            code.add_from_import("drgn", "Object")
            code.append(
                f"""\
address = prog.symbol({_repr_black(address_or_symbol)}).address{subtract_offset}
{initial_object("address")}
"""
            )
    else:
        code.add_from_import("drgn", "Object")
        code.append(f"{initial_object(hex(address) + subtract_offset)}\n")

    if isinstance(offset_arg, tuple):
        offset_name, offset_member = offset_arg
        after = "[0]" if object_or_pointer == "object" else ""
        code.add_from_import("drgn", "container_of")
        if name == offset_name:
            offset_type_name = type_name
        else:
            code.add_from_import("drgn", "reinterpret")
            offset_type_name = _guess_type_name(prog, offset_name)
            if object_or_pointer == "object":
                after += f'\n{pcpu_prefix}object = reinterpret("{type_name}", {pcpu_prefix}object)'
            else:
                after += f'\n{pcpu_prefix}pointer = cast("{type_name} *", {pcpu_prefix}pointer)'
        code.append(
            f'{pcpu_prefix}{object_or_pointer} = container_of(offset_pointer, "{offset_type_name}", "{offset_member}"){after}\n'
        )

    if cpuspec is not None:
        code.begin_cpuspec_loop(cpuspec)
        code.add_from_import("drgn.helpers.linux.percpu", per_cpu_helper)
        code.append(
            f"{object_or_pointer} = {per_cpu_helper}({pcpu_prefix}{object_or_pointer}, cpu)\n"
        )

    if args.count != 1:
        if args.count >= 0:
            slice_str = f":{args.count}"
        else:
            slice_str = f"{args.count + 1}:1"
        code.begin_block(f"for object in pointer[{slice_str}]:\n")

    code.append(
        "".join(
            [
                f"{_sanitize_member_name(member)} = object.{member}\n"
                for member in members
            ]
        )
    )

    if args.count != 1:
        if not members:
            code.append("...\n")
        code.end_block()

    if cpuspec is not None:
        code.end_block()

    code.print()
    return


@crash_command(
    description="structure contents",
    arguments=(
        argument(
            "name",
            metavar="struct_name[.member[,member]]",
            help="name of structure type; one or more comma-separated members "
            "(each of which can be nested and include array subscripts) "
            "may also be given to limit the output to those members",
        ),
        argument(
            "address_or_symbol",
            metavar="address_or_symbol[:cpuspec]",
            nargs="?",
            help="hexadecimal address or symbol name of structure. "
            "If not given, the type and its size are printed instead. "
            "For per-cpu variables, this may also contain a colon (':') "
            "followed by a specification of which CPUs to print, "
            "which may be a comma-separated string of CPU numbers or ranges "
            "(e.g., '0,3-4'), "
            "'a' or 'all' (meaning all possible CPUs), "
            "or an empty string (meaning the CPU of the current context)",
        ),
        argument(
            "-l",
            dest="offset",
            help="offset from the beginning of the desired structure to the "
            "given address or symbol, either as a number of bytes or a "
            "struct_name.member",
        ),
        argument(
            "-x",
            dest="integer_base",
            action="store_const",
            const=16,
            help="output integers in hexadecimal format regardless of the default",
        ),
        argument(
            "-d",
            dest="integer_base",
            action="store_const",
            const=10,
            help="output integers in decimal format regardless of the default",
        ),
        argument("-c", dest="count", type=int, help="number of consecutive structures"),
        argument(
            "count",
            type=_int_or_suppress,
            nargs="?",
            default=argparse.SUPPRESS,
            help="number of consecutive structures",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_struct(
    prog: Program, kind: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    name, members = _parse_type_name_and_members(args.name)
    offset_arg = None if args.offset is None else _parse_type_offset_arg(args.offset)

    if args.address_or_symbol is None:
        if args.count is not None:
            raise CommandError("-c/count requires address or symbol")
        if args.offset is not None:
            raise CommandError("-l requires address or symbol")
        address_or_symbol = None
        cpuspec = None
    else:
        if args.count is None:
            args.count = 1
        address_or_symbol, sep, cpuspec_str = args.address_or_symbol.partition(":")
        cpuspec = parse_cpuspec(cpuspec_str) if sep else None

    # We look up the type even for --drgn so that we can get the correct type
    # name (e.g., "atomic_t", not "struct atomic_t") if it exists. If it
    # doesn't, then it's only a hard error without --drgn.
    try:
        # If this was run via an implicit type command, then the type should
        # already be smuggled in here.
        try:
            type = kwargs["type"]
        except KeyError:
            type = _guess_type(prog, name, kind)
    except LookupError:
        if not args.drgn:
            raise
        type_name = f"{'struct' if kind == '*' else kind} {name}"
    else:
        type_name = type.type_name()

    if args.drgn:
        _struct_drgn_option(
            prog,
            args,
            name=name,
            members=members,
            type_name=type_name,
            offset_arg=offset_arg,
            address_or_symbol=address_or_symbol,
            cpuspec=cpuspec,
        )
        return

    if address_or_symbol is None:
        if members:
            # Crash doesn't support multiple members here, but we easily can.
            # Crash also doesn't support nested members and silently fails for
            # array subscripts. We can support these by sanitizing the member
            # name and adding a comment with the original name.
            for i, member in enumerate(members):
                obj = Object(prog, type, address=0).subobject_(member)
                sanitized = _sanitize_member_name(member)
                if sanitized == member:
                    sanitized_comment = ""
                else:
                    sanitized_comment = f" /* {member} */"
                print(
                    f"[{obj.address_}] {obj.type_.variable_declaration(sanitized)};{sanitized_comment}"
                )
        else:
            sys.stdout.write(f"{type}\nSIZE: {sizeof(type)}\n")
        return

    if offset_arg is None:
        offset = 0
    elif isinstance(offset_arg, int):
        offset = offset_arg
    else:
        offset_name, offset_member = offset_arg
        if offset_name == name:
            offset_type = type
        else:
            offset_type = _guess_type(prog, offset_name)
        offset = offsetof(offset_type, offset_member)

    try:
        address = int(address_or_symbol, 16)
    except ValueError:
        address = prog.symbol(address_or_symbol).address
    address -= offset

    if args.count >= 0:
        sl = slice(0, args.count)
    else:
        sl = slice(args.count + 1, 1)

    ptr = Object(prog, prog.pointer_type(type), address)

    if cpuspec is None:

        def arrays() -> Iterable[Object]:
            return (ptr[sl],)

    else:

        def arrays() -> Iterable[Object]:
            for cpu in cpuspec.cpus(prog):
                pcpu_ptr = per_cpu_ptr(ptr, cpu)
                print(f"[{cpu}]: {pcpu_ptr.value_():x}")
                yield pcpu_ptr[sl]

    format_options = _object_format_options(prog, args.integer_base)
    for arr in arrays():
        for i, obj in enumerate(arr):
            if i != 0:
                print()

            if members:
                for member in members:
                    print(
                        f"{member} = {obj.subobject_(member).format_(**format_options)}"
                    )
            else:
                print(obj.format_(**format_options))


@crash_command(
    description="union contents",
    arguments=(
        argument(
            "name",
            metavar="union_name[.member[,member]]",
            help="name of union type; one or more comma-separated members "
            "(each of which can be nested and include array subscripts) "
            "may also be given to limit the output to those members",
        ),
        argument(
            "address_or_symbol",
            metavar="address_or_symbol[:cpuspec]",
            nargs="?",
            help="hexadecimal address or symbol name of union. "
            "If not given, the type and its size are printed instead. "
            "For per-cpu variables, this may also contain a colon (':') "
            "followed by a specification of which CPUs to print, "
            "which may be a comma-separated string of CPU numbers or ranges "
            "(e.g., '0,3-4'), "
            "'a' or 'all' (meaning all possible CPUs), "
            "or an empty string (meaning the CPU of the current context)",
        ),
        argument(
            "-l",
            dest="offset",
            help="offset from the beginning of the desired union to the "
            "given address or symbol, either as a number of bytes or a "
            "union_name.member",
        ),
        argument(
            "-x",
            dest="integer_base",
            action="store_const",
            const=16,
            help="output integers in hexadecimal format regardless of the default",
        ),
        argument(
            "-d",
            dest="integer_base",
            action="store_const",
            const=10,
            help="output integers in decimal format regardless of the default",
        ),
        argument("-c", dest="count", type=int, help="number of consecutive unions"),
        argument(
            "count",
            type=_int_or_suppress,
            nargs="?",
            default=argparse.SUPPRESS,
            help="number of consecutive unions",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_union(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    return _crash_cmd_struct(prog, name, args, **kwargs)


@crash_command(
    name="*",
    description="shortcut for struct or union",
    usage=r"\* [*struct or union command arguments*]",
    long_description="""
    This is a shortcut that allows typing, e.g., ``*list_head`` instead of
    ``struct list_head``. Note that if the type name is not also the name of a
    command, then the ``*`` can also be omitted, e.g., ``list_head``.
    """,
    arguments=(
        argument(
            "name", metavar="struct_name[.member[,member]]", help=argparse.SUPPRESS
        ),
        argument(
            "address_or_symbol",
            metavar="address_or_symbol[:cpuspec]",
            nargs="?",
            help=argparse.SUPPRESS,
        ),
        argument("-l", dest="offset", help=argparse.SUPPRESS),
        argument("-c", dest="count", type=int, help=argparse.SUPPRESS),
        argument(
            "-x",
            dest="integer_base",
            action="store_const",
            const=16,
            help=argparse.SUPPRESS,
        ),
        argument(
            "-d",
            dest="integer_base",
            action="store_const",
            const=10,
            help=argparse.SUPPRESS,
        ),
        argument(
            "count",
            type=_int_or_suppress,
            nargs="?",
            default=argparse.SUPPRESS,
            help=argparse.SUPPRESS,
        ),
        argument("--drgn", action="store_true", help=argparse.SUPPRESS),
    ),
)
def _crash_cmd_asterisk(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    return _crash_cmd_struct(prog, name, args, **kwargs)


@_crash_foreach_subcommand(
    arguments=(
        argument(
            "-R",
            dest="members",
            metavar="member[,member]",
            action="append",
        ),
        argument(
            "-x",
            dest="integer_base",
            action="store_const",
            const=16,
        ),
        argument(
            "-d",
            dest="integer_base",
            action="store_const",
            const=10,
        ),
        drgn_argument,
    ),
)
def _crash_foreach_task(task_selector: _TaskSelector, args: argparse.Namespace) -> None:
    prog = task_selector.prog

    members = []
    if args.members:
        for arg in args.members:
            members.extend(_parse_members(arg))

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        with task_selector.begin_task_loop(code):
            code.append_task_header()
            if members:
                for member in members:
                    code.append(f"{_sanitize_member_name(member)} = task.{member}\n")
            else:
                code.add_from_import("drgn.helpers.linux.sched", "task_thread_info")
                code.append("thread_info = task_thread_info(task)\n")
        return code.print()

    format_options = _object_format_options(prog, args.integer_base)

    first = True
    for task in task_selector.tasks():
        if first:
            first = False
        else:
            print()

        print_task_header(task)
        if members:
            for member in members:
                print(
                    f"  {member} = {task[0].subobject_(member).format_(**format_options)}"
                )
        else:
            print(
                task[0].format_(**format_options),
                task_thread_info(task)[0].format_(**format_options),
                sep="\n\n",
            )


@crash_command(
    description="task_struct and thread_info contents",
    arguments=(
        argument(
            "tasks",
            metavar="pid|task",
            nargs="*",
            help="""
            display this task, given as either a decimal process ID or a
            hexadecimal ``task_struct`` address. May be given multiple times.
            Defaults to the current context
            """,
        ),
        argument(
            "-R",
            dest="members",
            metavar="member[,member]",
            action="append",
            help="""
            display only these ``task_struct`` members, given as a
            comma-separated list. Each member can be nested and include array
            subscripts. The **-R** is optional
            """,
        ),
        argument(
            "-x",
            dest="integer_base",
            action="store_const",
            const=16,
            help="output integers in hexadecimal format regardless of the default",
        ),
        argument(
            "-d",
            dest="integer_base",
            action="store_const",
            const=10,
            help="output integers in decimal format regardless of the default",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_task(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    task_args: List[Optional[_PID_OR_TASK]] = []
    for arg in args.tasks:
        try:
            task_args.append(_pid_or_task(arg))
        except ValueError:
            if args.members is None:
                args.members = [arg]
            else:
                args.members.append(arg)

    if not task_args:
        task_args.append(None)
    return _crash_foreach_task(_TaskSelector(prog, task_args), args)
