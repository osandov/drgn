# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""TODO"""

import argparse
import re
import sys
from typing import Any, Optional, Tuple

from drgn import Object, Program, Type, offsetof, sizeof
from drgn.commands import CommandError, argument, drgn_argument
from drgn.commands.crash import (
    _merge_imports,
    add_cpuspec,
    crash_command,
    parse_cpuspec,
)
from drgn.helpers.linux.percpu import per_cpu


def _guess_type(prog: Program, name: str) -> Type:
    try:
        return prog.type("struct " + name)
    except LookupError:
        pass
    try:
        return prog.type("union " + name)
    except LookupError:
        pass
    # TODO: check if struct or union, raise LookupError if not
    return prog.type(name)


def _split_struct_member(s: str) -> Tuple[str, Optional[str]]:
    name, sep, member = s.partition(".")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name):
        raise ValueError(f"invalid structure name: {name}")
    if not sep:
        return name, None
    if not re.fullmatch(
        r"[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*|\[[0-9]+\])*", member
    ):
        raise ValueError(f"invalid member name: {member}")
    return name, member


def _prefer_object_lookup(prog: Program, type_name: str, symbol: str) -> bool:
    # TODO: explain {Lookup,Key}Error handling
    try:
        symbol_address = prog.symbol(symbol).address
    except LookupError:
        return True

    try:
        object = prog[symbol]
    except KeyError:
        return False

    return object.type_.type_name() == type_name and object.address_ == symbol_address


@crash_command(
    description="TODO",
    arguments=(
        argument("name", metavar="struct_name[.member]", help="TODO"),
        argument("-l", dest="offset", help="TODO"),
        argument("address_or_symbol", nargs="?", help="TODO"),
        argument("-c", dest="count", type=int, help="TODO"),
        argument("count", type=int, nargs="?", default=argparse.SUPPRESS, help="TODO"),
        drgn_argument,
    ),
)
def _crash_cmd_struct(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    name, member = _split_struct_member(args.name)
    type_name = "struct " + name

    if args.offset is None:
        offset = 0
    else:
        if "." in args.offset:
            offset_name, offset_member = _split_struct_member(args.offset)
        else:
            try:
                offset = int(args.offset, 0)
            except ValueError:
                raise CommandError(f"invalid -l option: {args.offset}") from None

    if not args.drgn:
        type = prog.type(type_name)
        if args.offset is not None and "." in args.offset:
            if offset_name == name:
                offset_type = type
            else:
                offset_type = _guess_type(prog, offset_name)
            offset = offsetof(offset_type, offset_member)

    if args.address_or_symbol is None:
        if args.count is not None:
            raise CommandError("-c/count requires address or symbol")

        if member:
            if args.drgn:
                sys.stdout.write(
                    f"""\
from drgn import offsetof
from drgn.helpers.common.type import typeof_member

type = prog.type("{type_name}")
member_type = typeof_member(type, "{member}")
offset = offsetof(type, "{member}")
"""
                )
                return
            else:
                object = Object(prog, type, address=0).subobject_(member)
                # Crash's output in this case is confusing and often broken, so
                # we do our own thing.
                sys.stdout.write(
                    f"""\
typeof_member({type.type_name()}, {member}) = {object.type_.type_name()}
offsetof({type.type_name()}, {member}) = {object.address_}
"""
                )
                return object.type_
        else:
            if args.drgn:
                sys.stdout.write(
                    f"""\
from drgn import sizeof


type = prog.type("{type_name}")
size = sizeof(type)
"""
                )
                return
            else:
                sys.stdout.write(
                    f"""\
{type}
SIZE: {sizeof(type)}
"""
                )
                return type

    if args.count is None:
        args.count = 1

    address_or_symbol, cpuspec_sep, cpuspec_str = args.address_or_symbol.partition(":")

    if args.drgn:
        if args.offset is None or "." not in args.offset:

            def initial_object(address: str) -> str:
                return f'Object(prog, "{type_name}", address={address})'

        else:

            def initial_object(address: str) -> str:
                return f'Object(prog, "void *", {address})'

        if args.offset and "." not in args.offset:
            subtract_offset = f" - {args.offset}"
        else:
            subtract_offset = ""

        try:
            address = int(address_or_symbol, 16)
        except ValueError:
            # This command technically always does a symbol lookup, but prefer
            # recommending a prog[] lookup if it is equivalent.
            if _prefer_object_lookup(prog, type_name, address_or_symbol):
                # TODO: deal with offset in this case
                source = f"object = prog[{address_or_symbol!r}]\n"
            else:
                source = f"""\
from drgn import Object


address = prog.symbol({address_or_symbol!r}).address{subtract_offset}
object = {initial_object("address")}
"""
        else:
            source = f"""\
from drgn import Object


object = {initial_object(hex(address) + subtract_offset)}
"""

        if args.offset is not None and "." in args.offset:
            if name == offset_name:
                imports = "from drgn import container_of\n"
                after = ""
                offset_type_name = type_name
            else:
                imports = "from drgn import container_of, reinterpret\n"
                try:
                    offset_type_name = _guess_type(prog, offset_name).type_name()
                except LookupError:
                    offset_type_name = "struct " + offset_name
                after = f'object = reinterpret("{type_name}", object)\n'
            source = _merge_imports(
                imports,
                f'{source}object = container_of(object, "{offset_type_name}", "{offset_member}")[0]\n{after}',
            )

        if member:
            source += f"object = object.{member}\n"

        if cpuspec_sep:
            source = add_cpuspec(
                prog,
                cpuspec_str,
                _merge_imports(
                    "from drgn.helpers.linux.percpu import per_cpu\n", source
                ),
                "pcpu_object = per_cpu(object, cpu)\n",
            )

        sys.stdout.write(source)
        return

    try:
        address = int(address_or_symbol, 16)
    except ValueError:
        address = prog.symbol(address_or_symbol).address
    address -= offset
    cpuspec = parse_cpuspec(prog, cpuspec_str) if cpuspec_sep else None

    ptr = Object(prog, prog.pointer_type(type), address)

    # TODO: --drgn count
    if args.count >= 0:
        start = 0
        end = args.count
    else:
        start = args.count + 1
        end = 1
    for i in range(start, end):
        object = ptr[i]
        if member:
            object = object.subobject_(member)

        if i != start:
            print()

        prefix = f"{member} = " if member else ""
        if cpuspec is None:
            print(prefix, object, sep="")
        else:
            for cpu in cpuspec:
                pcpu_object = per_cpu(object, cpu)
                # TODO: is this supposed to be the address of the member or of
                # the object?
                print(f"[{cpu}]: {pcpu_object.address_:x}\n{prefix}{pcpu_object}")
    return ptr[0]
