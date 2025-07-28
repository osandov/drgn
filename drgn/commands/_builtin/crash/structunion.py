# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands for inspecting structures and unions."""

import argparse
import functools
import re
import shutil
import sys
from typing import Any, Iterable, List, Optional, Tuple, Union

from drgn import Object, Program, offsetof, sizeof
from drgn.commands import CommandError, argument, drgn_argument
from drgn.commands.crash import (
    Cpuspec,
    CrashDrgnCodeBuilder,
    _guess_type,
    crash_command,
    parse_cpuspec,
)
from drgn.helpers.linux.percpu import per_cpu_ptr


# Workaround for https://github.com/python/cpython/issues/80259 from
# https://github.com/python/cpython/issues/80259#issuecomment-1093816101.
@functools.wraps(int)
def _int_or_suppress(s: str) -> Union[int, str]:
    return s if s is argparse.SUPPRESS else int(s)


_NAME_PATTERN = r"[a-zA-Z_][a-zA-Z0-9_]*"
_MEMBER_PATTERN = r"[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*|\[[0-9]+\])*"


def _parse_name_and_members(s: str) -> Tuple[str, List[str]]:
    name, sep, members_str = s.partition(".")
    if not re.fullmatch(_NAME_PATTERN, name):
        raise ValueError(f"invalid structure name: {name}")
    if not sep:
        return name, []
    members = members_str.split(",")
    for member in members:
        if not re.fullmatch(_MEMBER_PATTERN, member):
            raise ValueError(f"invalid member name: {member}")
    return name, members


def _parse_offset_arg(s: str) -> Union[int, Tuple[str, str]]:
    if "." not in s:
        try:
            return int(s, 0)
        except ValueError:
            raise ValueError(f"invalid -l option: {s}") from None
    name, sep, member = s.partition(".")
    if not re.fullmatch(_NAME_PATTERN, name):
        raise ValueError(f"invalid structure name: {name}")
    if not re.fullmatch(_MEMBER_PATTERN, member):
        raise ValueError(f"invalid member name: {member}")
    return name, member


def _prefer_object_lookup(prog: Program, type_name: str, symbol: str) -> bool:
    try:
        symbol_address = prog.symbol(symbol).address
    except LookupError:
        # If a symbol isn't found, prefer an object lookup.
        return True

    try:
        object = prog[symbol]
    except KeyError:
        # If an object isn't found but a symbol is, prefer a symbol lookup.
        return False

    # If both a symbol and an object are found, prefer an object lookup iff the
    # addresses are the same and the object has the desired type.
    return object.type_.type_name() == type_name and object.address_ == symbol_address


def _sanitize_member(member: str) -> str:
    return re.sub(r"\.|\[([^]]+)\]", r"_\1", member)


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
{_sanitize_member(member)}_type = typeof_member(type, "{member}")
{_sanitize_member(member)}_offset = offsetof(type, "{member}")
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
                f"{pcpu_prefix}{object_or_pointer} = prog[{address_or_symbol!r}]"
            )
            if object_or_pointer == "pointer":
                code.append(".address_of_()")
            code.append("\n")
        else:
            code.add_from_import("drgn", "Object")
            code.append(
                f"""\
address = prog.symbol({address_or_symbol!r}).address{subtract_offset}
{initial_object("address")}
"""
            )
    else:
        code.add_from_import("drgn", "Object")
        code.append(f"{initial_object(hex(address) + subtract_offset)}\n")

    members_indent = ""
    if isinstance(offset_arg, tuple):
        offset_name, offset_member = offset_arg
        after = "[0]" if object_or_pointer == "object" else ""
        code.add_from_import("drgn", "container_of")
        if name == offset_name:
            offset_type_name = type_name
        else:
            code.add_from_import("drgn", "reinterpret")
            try:
                offset_type_name = _guess_type(prog, "*", offset_name).type_name()
            except LookupError:
                offset_type_name = "struct " + offset_name
            if object_or_pointer == "object":
                after += f'\n{pcpu_prefix}object = reinterpret("{type_name}", {pcpu_prefix}object)'
            else:
                after += f'\n{pcpu_prefix}pointer = cast("{type_name} *", {pcpu_prefix}pointer)'
        code.append(
            f'{pcpu_prefix}{object_or_pointer} = container_of(offset_pointer, "{offset_type_name}", "{offset_member}"){after}\n'
        )

    if args.count == 1:
        object_loop = ""
    else:
        members_indent = "    "
        loop_body = "" if members else "    ...\n"
        if args.count >= 0:
            slice_str = f":{args.count}"
        else:
            slice_str = f"{args.count + 1}:1"
        object_loop = f"for object in pointer[{slice_str}]:\n{loop_body}"

    object_loop += "".join(
        [
            f"{members_indent}{_sanitize_member(member)} = " f"object.{member}\n"
            for member in members
        ]
    )

    if cpuspec is None:
        code.append(object_loop)
    else:
        code.add_from_import("drgn.helpers.linux.percpu", per_cpu_helper)
        code.append_cpuspec(
            cpuspec,
            f"{object_or_pointer} = {per_cpu_helper}({pcpu_prefix}{object_or_pointer}, cpu)\n{object_loop}",
        )

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
    name, members = _parse_name_and_members(args.name)
    offset_arg = None if args.offset is None else _parse_offset_arg(args.offset)

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
            type = _guess_type(prog, kind, name)
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
                sanitized = _sanitize_member(member)
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
            offset_type = _guess_type(prog, "*", offset_name)
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

    format_options = {
        "columns": shutil.get_terminal_size().columns,
        "dereference": False,
        "integer_base": args.integer_base or prog.config.get("crash_radix", 10),
    }
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
