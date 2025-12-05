# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands for iterating kernel collection types."""

import argparse
import sys
import typing
from typing import Any, Container, Literal, Optional, Sequence, Set, Tuple, Union

if typing.TYPE_CHECKING:
    if sys.version_info < (3, 11):
        from typing_extensions import assert_never
    else:
        from typing import assert_never  # novermin

from drgn import FaultError, Object, Program
from drgn.commands import (
    CommandArgumentError,
    DrgnCodeBuilder,
    _repr_black,
    argument,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _guess_type,
    _guess_type_name,
    _object_format_options,
    _parse_type_name_and_members,
    _parse_type_offset_arg,
    _prefer_object_lookup,
    _resolve_type_offset_arg,
    _sanitize_member_name,
    crash_command,
)
from drgn.helpers.common.type import typeof_member
from drgn.helpers.linux.mapletree import mt_for_each
from drgn.helpers.linux.radixtree import radix_tree_for_each
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each, rbtree_preorder_for_each
from drgn.helpers.linux.xarray import xa_for_each


def _resolve_address_or_symbol(prog: Program, address_or_symbol: str) -> int:
    try:
        return int(address_or_symbol, 16)
    except ValueError:
        return prog.symbol(address_or_symbol).address


def _append_get_members(
    code: DrgnCodeBuilder,
    name: str,
    members: Sequence[str],
    *,
    indent: str = "",
    avoid_names: Container[str] = (),
) -> None:
    if not members:
        code.append(indent + "...\n")
        return

    for member in members:
        sanitized_name = _sanitize_member_name(member)
        while sanitized_name == name or sanitized_name in avoid_names:
            sanitized_name += "_"

        if hasattr(Object, member):
            member = f"member_({_repr_black(member)})"

        code.append(f"{indent}{sanitized_name} = {name}.{member}\n")


def _append_list_head(
    code: DrgnCodeBuilder,
    name: str = "head",
    *,
    start: Union[str, int],
    head_node_offset_arg: Union[None, int, Tuple[str, str]],
    entry_name: Optional[str] = None,
) -> None:
    prog = code._prog

    if head_node_offset_arg is None:
        if isinstance(start, str) and _prefer_object_lookup(
            prog,
            "struct list_head" if entry_name is None else entry_name,
            start,
            strict_type_name=entry_name is None,
        ):
            code.append(f"{name} = prog[{_repr_black(start)}].address_of_()\n")
            return
    elif isinstance(head_node_offset_arg, tuple):
        if isinstance(start, str):
            if _prefer_object_lookup(
                prog, head_node_offset_arg[0], start, strict_type_name=False
            ):
                # Here we're trusting the user that the -O argument refers to a
                # list_head member.
                code.append(
                    f"{name} = prog[{_repr_black(start)}].{head_node_offset_arg[1]}.address_of_()\n"
                )
                return
        else:
            code.add_from_import("drgn", "Object")
            head_type_name = _guess_type_name(prog, head_node_offset_arg[0])
            # Same here, we're trusting the user that the -O argument refers to
            # a list_head member.
            code.append(
                f"{name} = Object(prog, {_repr_black(head_type_name)}, address={start:#x}).{head_node_offset_arg[1]}.address_of_()\n"
            )
            return

    if isinstance(start, str):
        code.append(f"address = prog.symbol({_repr_black(start)}).address\n")
        head_address = "address"
    else:
        head_address = f"{start:#x}"

    if head_node_offset_arg is None:
        head_offset = None
    elif isinstance(head_node_offset_arg, tuple):
        code.add_from_import("drgn", "offsetof")
        head_type_name = _guess_type_name(prog, head_node_offset_arg[0])
        head_offset = f"offsetof({_repr_black(head_type_name)}, {_repr_black(head_node_offset_arg[1])})"
    else:
        head_offset = str(head_node_offset_arg)
    if head_offset is not None:
        code.append(f"offset = {head_offset}\n")

    code.add_from_import("drgn", "Object")
    if entry_name is None:
        type_name = "struct list_head"
    else:
        type_name = _guess_type_name(prog, entry_name)
    code.append(f'{name} = Object(prog, "{type_name} *", {head_address}')
    if head_offset is not None:
        code.append(" + offset")
    code.append(")\n")


def _list_drgn_option_list_for_each(
    code: DrgnCodeBuilder,
    args: argparse.Namespace,
    *,
    start: Union[str, int],
    head_node_offset_arg: Union[None, int, Tuple[str, str]],
    node_member: Optional[str],
    entry_name: Optional[str],
    entry_members: Sequence[str],
) -> None:
    prog = code._prog

    _append_list_head(code, start=start, head_node_offset_arg=head_node_offset_arg)

    helper = "list_for_each"
    if entry_name is not None:
        helper += "_entry"
    if args.reverse:
        helper += "_reverse"

    code.add_from_import("drgn.helpers.linux.list", helper)

    if entry_name is None:
        code.append(
            f"""\
for node in {helper}(head):
    ...
"""
        )
    else:
        assert node_member is not None
        entry_type_name = _guess_type_name(prog, entry_name)
        code.append(
            f"""\
for entry in {helper}({_repr_black(entry_type_name)}, head, {_repr_black(node_member)}):
"""
        )
        _append_get_members(code, "entry", entry_members, indent="    ")

    code.print()


def _list_drgn_option_embedded_list_head(
    code: DrgnCodeBuilder,
    args: argparse.Namespace,
    *,
    start: Union[str, int],
    node_member: Optional[str],
    entry_name: Optional[str],
    entry_members: Sequence[str],
) -> None:
    _append_list_head(
        code,
        "first",
        start=start,
        head_node_offset_arg=None,
        entry_name=entry_name,
    )

    if entry_name is None:
        code.append(
            f"""\
node = first
while True:
    ...

    node = node.{"prev" if args.reverse else "next"}
    if node == first:
        break
"""
        )
    else:
        assert node_member is not None
        helper = f"list_{'prev' if args.reverse else 'next'}_entry"
        code.add_from_import("drgn.helpers.linux.list", helper)
        code.append(
            """\
entry = first
while True:
"""
        )

        _append_get_members(
            code, "entry", entry_members, indent="    ", avoid_names=("first",)
        )

        code.append(
            f"""\

    entry = {helper}(entry, {_repr_black(node_member)})
    if entry == first:
        break
"""
        )

    code.print()


def _list_drgn_option_next_member(
    code: DrgnCodeBuilder,
    args: argparse.Namespace,
    *,
    start: Union[str, int],
    node_member: str,
    entry_name: Optional[str],
    entry_members: Sequence[str],
) -> None:
    _append_list_head(
        code,
        "first",
        start=start,
        head_node_offset_arg=None,
        entry_name=entry_name,
    )

    code.append(
        """\
entry = first
while True:
"""
    )

    _append_get_members(
        code, "entry", entry_members, indent="    ", avoid_names=("first",)
    )

    code.append(
        f"""\

    next_entry = entry.{node_member}
    if not next_entry or next_entry == first or next_entry == entry"""
    )

    if args.end is not None:
        code.append(f" or next_entry.value_() == {args.end:#x}")

    code.append(
        """:
        break
    entry = next_entry
"""
    )

    code.print()


def _list_drgn_option(
    prog: Program,
    args: argparse.Namespace,
    *,
    next_offset_arg: Union[None, int, Tuple[str, str]],
    head_node_offset_arg: Union[None, int, Tuple[str, str]],
    node_offset_arg: Union[None, int, Tuple[str, str]],
    entry_name: Optional[str],
    entry_members: Sequence[str],
) -> None:
    # Note: we don't bother generating code for checking for duplicates or
    # stopping at the second entry.

    code = CrashDrgnCodeBuilder(prog)

    try:
        start: Union[str, int] = int(args.start, 16)
    except ValueError:
        start = args.start

    node_member = None
    if entry_name is None:
        if isinstance(next_offset_arg, tuple):
            # -o without -s prints the entry address but not the entry.
            entry_name, node_member = next_offset_arg
    else:
        # -o prints the entry addresses and -l prints the node addresses, but
        # we ignore that difference.
        if isinstance(next_offset_arg, tuple) and next_offset_arg[0] == entry_name:
            node_member = next_offset_arg[1]
        elif isinstance(node_offset_arg, tuple) and node_offset_arg[0] == entry_name:
            node_member = node_offset_arg[1]

    if args.list_head or head_node_offset_arg is not None:
        if (
            (
                # It makes sense to iterate over list_heads if either the
                # entry type+node member make sense...
                node_member is not None
                # ... or if there is no entry type.
                or (entry_name is None and next_offset_arg is None)
            )
            # Weird end values don't make sense for list_head.
            and args.end is None
        ):
            return _list_drgn_option_list_for_each(
                code,
                args,
                start=start,
                head_node_offset_arg=head_node_offset_arg,
                node_member=node_member,
                entry_name=entry_name,
                entry_members=entry_members,
            )
    elif args.embedded_list_head:
        if (
            node_member is not None or (entry_name is None and next_offset_arg is None)
        ) and args.end is None:
            return _list_drgn_option_embedded_list_head(
                code,
                args,
                start=start,
                node_member=node_member,
                entry_name=entry_name,
                entry_members=entry_members,
            )
    elif node_member is not None:
        return _list_drgn_option_next_member(
            code,
            args,
            start=start,
            node_member=node_member,
            entry_name=entry_name,
            entry_members=entry_members,
        )

    if isinstance(start, str):
        code.append(f"start = prog.symbol({_repr_black(start)}).address\n")
    else:
        code.append(f"start = {start:#x}")

    if entry_name is not None:
        entry_type_name = _guess_type_name(prog, entry_name)

    if isinstance(next_offset_arg, tuple):
        if next_offset_arg[0] == entry_name:
            next_type_name = entry_type_name
        else:
            next_type_name = _guess_type_name(prog, next_offset_arg[0])
        code.add_from_import("drgn", "offsetof")
        next_offset = f"offsetof({_repr_black(next_type_name)}, {_repr_black(next_offset_arg[1])})"
    elif isinstance(next_offset_arg, int):
        next_offset = str(next_offset_arg)
    else:
        next_offset = None

    next_or_prev = "prev" if args.reverse else "next"
    list_head_offset = None
    if args.list_head or args.embedded_list_head:
        list_head_offset = next_offset
        if args.reverse:
            code.add_from_import("drgn", "offsetof")
            next_offset = 'offsetof("struct list_head", "prev")'
        else:
            next_offset = None

    if list_head_offset is not None:
        code.append(f"list_head_offset = {list_head_offset}\n")
    if next_offset is not None:
        code.append(f"{next_or_prev}_offset = {next_offset}\n")

    entry_offset = None
    if node_offset_arg is not None:
        entry_offset = "entry_offset"
        if isinstance(node_offset_arg, tuple):
            if node_offset_arg[0] == entry_name:
                node_type_name = entry_type_name
            else:
                node_type_name = _guess_type_name(prog, node_offset_arg[0])
            code.add_from_import("drgn", "offsetof")
            code.append(
                f"entry_offset = offsetof({_repr_black(node_type_name)}, {_repr_black(node_offset_arg[1])})\n"
            )
        else:
            code.append(f"entry_offset = {node_offset_arg}\n")
    elif list_head_offset is not None:
        entry_offset = "list_head_offset"

    code.append("\n")

    if args.list_head or head_node_offset_arg is not None:
        if isinstance(head_node_offset_arg, tuple):
            if head_node_offset_arg[0] == entry_name:
                next_type_name = entry_type_name
            else:
                next_type_name = _guess_type_name(prog, head_node_offset_arg[0])
            code.add_from_import("drgn", "offsetof")
            code.append(
                f"start += offsetof({_repr_black(next_type_name)}, {_repr_black(head_node_offset_arg[1])})\n"
            )
        elif isinstance(head_node_offset_arg, int):
            code.append(f"start += {head_node_offset_arg}\n")

        code.append("ptr = prog.read_word(start")
        if next_offset is not None:
            code.append(f" + {next_or_prev}_offset")
        code.append(")\nwhile ptr != start:\n")
    else:
        if list_head_offset is not None:
            code.append("start += list_head_offset\n")
        code.append("ptr = start\nwhile True:\n")

    if entry_name:
        code.add_from_import("drgn", "Object")
        code.append(
            f'    entry = Object(prog, {_repr_black(entry_type_name + " *")}, ptr'
        )
        if entry_offset is not None:
            code.append(f" - {entry_offset}")
        code.append(")\n")
        if entry_members:
            _append_get_members(
                code,
                "entry",
                entry_members,
                indent="    ",
                avoid_names={
                    "start",
                    next_or_prev + "_offset",
                    "list_head_offset",
                    "entry_offset",
                },
            )
    elif list_head_offset is not None:
        code.append("    entry_ptr = ptr - list_head_offset\n")
    else:
        code.append("    ...\n")

    code.append(
        f"""\

    {next_or_prev}_ptr = prog.read_word(ptr"""
    )
    if next_offset is not None:
        code.append(f" + {next_or_prev}_offset")
    code.append(")\n    if")
    if not args.list_head and not args.embedded_list_head:
        code.append(f" not {next_or_prev}_ptr or")
    if not args.list_head and head_node_offset_arg is None:
        code.append(f" {next_or_prev}_ptr == start or")
    code.append(f" {next_or_prev}_ptr == ptr")

    if args.end is not None:
        code.append(f" or {next_or_prev}_ptr == {args.end:#x}")

    code.append(
        f""":
        break
    ptr = {next_or_prev}_ptr
"""
    )

    code.print()


@crash_command(
    description="linked list contents",
    arguments=(
        argument(
            "-o",
            dest="offset",
            help="""
            offset from a list entry to the pointer to the next entry, as
            either a number of bytes or a struct_name.member. This can also be
            passed as a positional argument (i.e., without "-o") unless the
            offset could be confused for a kernel virtual address. Defaults to
            0
            """,
        ),
        argument(
            "-s",
            "-S",
            dest="struct",
            metavar="struct_name[.member[,member]]",
            help="""
            type name of list entries. May include one or more comma-separated
            members (each of which can be nested and include array subscripts)
            to limit the output to those members
            """,
        ),
        argument(
            "-l",
            dest="node_offset",
            metavar="OFFSET",
            help="""
            only used with -s. Cannot be used with -o. Offset from a list entry
            to the list_head or similar structure linking entries together, as
            either a number of bytes or a struct_name.member
            """,
        ),
        mutually_exclusive_group(
            argument(
                "-H",
                dest="list_head",
                action="store_true",
                help="""
                treat **start** as the address of an anchor list_head (e.g., a
                standalone LIST_HEAD())
                """,
            ),
            argument(
                "-h",
                dest="embedded_list_head",
                action="store_true",
                help="""
                treat **start** as the address of a list_head embedded in a
                list entry
                """,
            ),
        ),
        argument(
            "-O",
            dest="head_node_offset",
            metavar="OFFSET",
            help="""
            only used with -h. Treat **start** as the address of a structure
            that embeds an anchor list_head at this offset, given as either a
            number of bytes or a struct_name.member
            """,
        ),
        argument(
            "-r",
            dest="reverse",
            action="store_true",
            help="""
            with -h or -H, iterate in reverse order using list_head.prev
            """,
        ),
        argument(
            "-e",
            dest="end",
            type="hexadecimal",
            help="""
            hexadecimal address where to stop iterating in addition to the
            defaults of NULL, the start address, the address of the first
            entry, and the address of the current entry
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
        # offset can be passed positionally either before or after start.
        # argparse can't express this, so we add this hidden positional
        # argument and figure out which is actually which manually.
        argument(
            "posarg",
            nargs="?",
            help=argparse.SUPPRESS,
        ),
        argument(
            "start",
            help="hexadecimal address of first list entry (but see -H, -h, and -O)",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_list(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    *,
    parser: argparse.ArgumentParser,
    **kwargs: Any,
) -> None:
    # In crash, if -H is not given, -r implies -h. I don't know whether this is
    # intentional or whether anyone relies on it, so we preserve that.
    if args.reverse and not args.list_head:
        args.embedded_list_head = True

    posargs = []
    if args.posarg is not None:
        posargs.append(args.posarg)
    posargs.append(args.start)
    args.start = None

    number_posargs = []
    for i, posarg in enumerate(posargs):
        # If the argument contains ".", then it must be the offset.
        if "." in posarg:
            if args.offset is not None:
                parser.error("offset given multiple times")
            args.offset = posarg
            continue

        try:
            # If the argument is numeric, it could be either the offset or the
            # start. Save it so we can decide later.
            #
            # Note that a number that is valid in base 10 is also valid in base
            # 16, so this covers both.
            int(posarg, 16)
            number_posargs.append(posarg)
        except ValueError:
            # The argument isn't numeric and doesn't contain ".". It must be a
            # symbol.
            if args.start is None:
                args.start = posarg
            else:
                parser.error("start given multiple times")

    if len(number_posargs) == 2:
        # There were two numeric positional arguments. If a numeric argument is
        # a valid virtual address, assume that it is the start, and otherwise
        # assume that it is the offset.
        is_virt_addr = []
        for posarg in number_posargs:
            try:
                prog.read_word(int(posarg, 16))
            except FaultError:
                is_virt_addr.append(False)
            else:
                is_virt_addr.append(True)

        if is_virt_addr[0] and is_virt_addr[1]:
            # Two valid virtual addresses were given.
            if args.offset is not None:
                # -o was also given, so assume both were intended as the start.
                parser.error("start given multiple times")
            parser.error(
                f"ambiguous arguments: {number_posargs[0]!r} and {number_posargs[1]!r}: -o is required"
            )

        if (not is_virt_addr[0] and not is_virt_addr[1]) or args.offset is not None:
            # Neither is a valid virtual address, or one is a valid virtual
            # address and -o was also given.
            parser.error("offset given multiple times")

        assert args.start is None
        if is_virt_addr[0]:
            args.start, args.offset = number_posargs
        else:
            args.offset, args.start = number_posargs
    elif len(number_posargs) == 1:
        # There was one numeric argument. If we don't know the start yet, it
        # must be the start. Otherwise, it must be the offset.
        if args.start is None:
            args.start = number_posargs[0]
        else:
            if args.offset is not None:
                parser.error("offset given multiple times")
            args.offset = number_posargs[0]

    if args.start is None:
        parser.error("start address is required")

    if args.offset is None:
        next_offset_arg = None
    else:
        next_offset_arg = _parse_type_offset_arg(args.offset)

    if args.struct is None:
        entry_name = None
        entry_members: Sequence[str] = ()
    else:
        entry_name, entry_members = _parse_type_name_and_members(args.struct)

    if args.head_node_offset is None:
        head_node_offset_arg = None
    else:
        if not args.embedded_list_head:
            parser.error("-O can only be used with -h")
        head_node_offset_arg = _parse_type_offset_arg(args.head_node_offset)

    if args.node_offset is None:
        node_offset_arg = None
    else:
        if args.struct is None:
            parser.error("-l can only be used with -s/-S")
        if args.offset is not None:
            parser.error("-l not allowed with -o/offset")
        node_offset_arg = _parse_type_offset_arg(args.node_offset)

    if args.drgn:
        return _list_drgn_option(
            prog,
            args,
            next_offset_arg=next_offset_arg,
            head_node_offset_arg=head_node_offset_arg,
            node_offset_arg=node_offset_arg,
            entry_name=entry_name,
            entry_members=entry_members,
        )

    start = _resolve_address_or_symbol(prog, args.start)

    if entry_name is None:
        entry_type = None
    else:
        entry_type = _guess_type(prog, entry_name)

    next_offset = _resolve_type_offset_arg(prog, next_offset_arg, entry_type)
    head_node_offset = _resolve_type_offset_arg(
        prog,
        head_node_offset_arg,
        # entry_type isn't expected to match for -O, but pass it anyways in
        # case it does.
        entry_type,
    )
    node_offset = _resolve_type_offset_arg(prog, node_offset_arg, entry_type)

    list_head_offset = 0
    if args.list_head or args.embedded_list_head:
        list_head_offset = next_offset
        # Note: -O -r on crash prints only the first list entry and then stops.
        # That's probably a bug, so we implement the more obvious behavior.
        next_offset = prog.address_size() if args.reverse else 0
        if args.list_head or args.head_node_offset is not None:
            if not args.end:
                args.end = start + head_node_offset
            start = prog.read_word(start + head_node_offset + next_offset)
            if start == args.end:
                print("(empty)")
                return
        else:
            start += list_head_offset

    entry_offset = list_head_offset + node_offset

    ptr = start
    end = {start}
    if args.end is not None:
        end.add(args.end)
    seen: Set[int] = set()
    format_options = _object_format_options(prog, args.integer_base)
    while True:
        # Note: with -H or -h, -l prints the address of the list node, but -o
        # prints the address of the entry.
        print(f"{ptr - list_head_offset:x}")
        if entry_type is not None:
            entry = Object(prog, entry_type, address=ptr - entry_offset)
            if entry_members:
                for member in entry_members:
                    print(
                        f"  {member} = {entry.subobject_(member).format_(**format_options)}"
                    )
            else:
                print(entry.format_(**format_options))

        if ptr - list_head_offset in seen:
            print(f"\nlist: duplicate list entry: {ptr:x}")
            break

        next_ptr = prog.read_word(ptr + next_offset)
        if not next_ptr:
            if args.list_head or args.embedded_list_head:
                print("\ninvalid list entry: 0")
            break
        elif next_ptr in end or next_ptr == ptr:
            break

        if not seen:
            end.add(next_ptr)
        seen.add(ptr - list_head_offset)

        ptr = next_ptr


_TreeType = Literal[
    "rbtree",
    "radix",
    "xarray",
    "maple",
]


def _find_tree_type(name: str) -> _TreeType:
    tree_types = [type for type in typing.get_args(_TreeType) if type.startswith(name)]
    if len(tree_types) != 1:
        raise CommandArgumentError(f"invalid tree type: {name}")
    return tree_types[0]


def _tree_drgn_option(
    prog: Program,
    args: argparse.Namespace,
    *,
    tree_type: _TreeType,
    root_offset_arg: Union[None, int, Tuple[str, str]],
    node_offset_arg: Union[None, int, Tuple[str, str]],
    entry_name: Optional[str],
    entry_members: Sequence[str],
) -> None:
    code = CrashDrgnCodeBuilder(prog)

    if tree_type == "rbtree":
        root_type_name = "struct rb_root"
        helper_module = "drgn.helpers.linux.rbtree"
    elif tree_type == "radix":
        try:
            root_type_name = "struct radix_tree_root"
            prog.type(root_type_name)
        except LookupError:
            root_type_name = "struct xarray"
        helper_module = "drgn.helpers.linux.radixtree"
        helper_name = "radix_tree_for_each"
        target = "index, entry"
    elif tree_type == "xarray":
        root_type_name = "struct xarray"
        helper_module = "drgn.helpers.linux.xarray"
        helper_name = "xa_for_each"
        target = "index, entry"
    elif tree_type == "maple":
        root_type_name = "struct maple_tree"
        helper_module = "drgn.helpers.linux.mapletree"
        helper_name = "mt_for_each"
        target = "first_index, last_index, entry"
    else:
        assert_never(tree_type)

    start_type = None
    if isinstance(root_offset_arg, tuple):
        try:
            start_type = _guess_type(prog, root_offset_arg[0])
        except LookupError:
            start_type = None
            start_type_name = "struct " + root_offset_arg[0]
        else:
            start_type_name = start_type.type_name()

    try:
        address = int(args.start, 16)
    except ValueError:
        if root_offset_arg is None and _prefer_object_lookup(
            prog, root_type_name, args.start
        ):
            code.append(f"root = prog[{_repr_black(args.start)}].address_of_()\n")
        elif (
            isinstance(root_offset_arg, tuple)
            and start_type is not None
            and _prefer_object_lookup(prog, start_type_name, args.start)
            and typeof_member(start_type, root_offset_arg[1]).type_name()
            == root_type_name
        ):
            code.append(
                f"root = prog[{_repr_black(args.start)}].{root_offset_arg[1]}.address_of_()\n"
            )
        else:
            code.append(f"address = prog.symbol({_repr_black(args.start)}).address")

            if isinstance(root_offset_arg, int):
                code.append(f" + {root_offset_arg}\n")
            elif isinstance(root_offset_arg, tuple):
                code.add_from_import("drgn", "offsetof")
                code.append(
                    f'\naddress += offsetof(prog.type("{start_type_name}"), "{root_offset_arg[1]}")\n'
                )
            else:
                code.append("\n")

            code.add_from_import("drgn", "Object")
            code.append(f'root = Object(prog, "{root_type_name} *", address)\n')
    else:
        code.add_from_import("drgn", "Object")
        if isinstance(root_offset_arg, int):
            address_arg = f"{hex(address)} + {root_offset_arg}"
        elif isinstance(root_offset_arg, tuple):
            code.append(f"address = {hex(address)}\n")
            code.add_from_import("drgn", "offsetof")
            code.append(
                f'address += offsetof(prog.type("{start_type_name}"), "{root_offset_arg[1]}")\n'
            )
            address_arg = "address"
        else:
            address_arg = hex(address)
        code.append(f'root = Object(prog, "{root_type_name} *", {address_arg})\n')

    if entry_name is None:
        entry_type_name = None
    else:
        entry_type_name = _guess_type_name(prog, entry_name)

    have_loop_body = False

    if tree_type == "rbtree":
        if isinstance(node_offset_arg, tuple):
            if node_offset_arg[0] == entry_name:
                for_each_entry_type_name = entry_type_name
            else:
                for_each_entry_type_name = _guess_type_name(prog, node_offset_arg[0])
            helper_name = (
                "rbtree_inorder_for_each_entry"
                if args.linear
                else "rbtree_preorder_for_each_entry"
            )
            code.append(
                f"""\
for entry in {helper_name}(
    "{for_each_entry_type_name}", root, "{node_offset_arg[1]}"
):
"""
            )
            if (
                entry_type_name is not None
                and entry_type_name != for_each_entry_type_name
            ):
                code.add_from_import("drgn", "cast")
                code.append(f'    entry = cast("{entry_type_name} *", entry)\n')
                have_loop_body = True
        else:
            helper_name = (
                "rbtree_inorder_for_each" if args.linear else "rbtree_preorder_for_each"
            )
            code.append(f"for node in {helper_name}(root):\n")
            if isinstance(node_offset_arg, int):
                code.add_from_import("drgn", "cast")
                code.append(f'    entry = cast("void *", node) - {node_offset_arg}\n')
                to_cast = "entry"
                have_loop_body = True
            else:
                to_cast = "node"
            if entry_type_name is not None:
                code.add_from_import("drgn", "cast")
                code.append(f'    entry = cast("{entry_type_name} *", {to_cast})\n')
                have_loop_body = True
    else:
        code.append(f"for {target} in {helper_name}(root):\n")
        if entry_type_name is not None:
            code.add_from_import("drgn", "cast")
            code.append(f'    entry = cast("{entry_type_name} *", entry)\n')
            have_loop_body = True

    code.add_from_import(helper_module, helper_name)

    if entry_members:
        _append_get_members(code, "entry", entry_members, indent="    ")
        have_loop_body = True

    if not have_loop_body:
        code.append("    pass\n")

    code.print()


@crash_command(
    description="red-black tree, radix tree, XArray, or maple tree contents",
    arguments=(
        argument(
            "-t",
            dest="type",
            metavar="{rbtree,radix,xarray,maple}",
            default="rbtree",
            help="""
            type of tree. This may also be abbreviated: "rb" for "rbtree", "ra"
            for "radix", "x" for "xarray", or "m" for "maple". Defaults to
            rbtree
            """,
        ),
        argument(
            "-r",
            dest="root_offset",
            metavar="OFFSET",
            help="""
            treat **start** as the address of a structure containing the tree
            root at the given offset as either a number of bytes or a
            struct_name.member
            """,
        ),
        argument(
            "-o",
            dest="node_offset",
            metavar="OFFSET",
            help="""
            for red-black trees, the offset of the rb_node in its containing
            structure as either a number of bytes or a struct_name.member.
            Defaults to 0
            """,
        ),
        argument(
            "-s",
            "-S",
            dest="struct",
            metavar="struct_name[.member[,member]]",
            help="""
            type name of tree entries. May include one or more comma-separated
            members (each of which can be nested and include array subscripts)
            to limit the output to those members
            """,
        ),
        argument(
            "-l",
            dest="linear",
            action="store_true",
            help="""
            for red-black trees, print entries in sorted order instead of the
            default pre-order traversal
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
        argument(
            "start",
            help="""
            address or symbol name of the rb_root, radix_tree_root, xarray, or
            maple_tree (or the structure containing it if **-r** is used)
            """,
        ),
        drgn_argument,
    ),
)
def _crash_cmd_tree(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    tree_type = _find_tree_type(args.type)

    if args.root_offset is None:
        root_offset_arg = None
    else:
        root_offset_arg = _parse_type_offset_arg(args.root_offset)

    if args.node_offset is None:
        node_offset_arg = None
    else:
        if tree_type != "rbtree":
            raise CommandArgumentError(f"-o is not applicable to {tree_type}")
        node_offset_arg = _parse_type_offset_arg(args.node_offset)

    if args.struct is None:
        entry_name = None
        entry_members: Sequence[str] = ()
    else:
        entry_name, entry_members = _parse_type_name_and_members(args.struct)

    if args.linear and tree_type != "rbtree":
        raise CommandArgumentError(f"-l is not applicable to {tree_type}")

    if args.drgn:
        _tree_drgn_option(
            prog,
            args,
            tree_type=tree_type,
            root_offset_arg=root_offset_arg,
            node_offset_arg=node_offset_arg,
            entry_name=entry_name,
            entry_members=entry_members,
        )
        return

    if entry_name is None:
        entry_type = None
    else:
        entry_type = _guess_type(prog, entry_name)

    start = _resolve_address_or_symbol(prog, args.start) + _resolve_type_offset_arg(
        prog, root_offset_arg
    )

    format_options = _object_format_options(prog, args.integer_base)

    def print_entry(address: int) -> None:
        print(f"{address:x}")
        if entry_type is not None:
            entry = Object(prog, entry_type, address=address)
            if entry_members:
                for member in entry_members:
                    print(
                        f"  {member} = {entry.subobject_(member).format_(**format_options)}"
                    )
            else:
                print(entry.format_(**format_options))

    if tree_type == "rbtree":
        node_offset = _resolve_type_offset_arg(prog, node_offset_arg, entry_type)
        root = Object(prog, "struct rb_root *", start)
        helper = rbtree_inorder_for_each if args.linear else rbtree_preorder_for_each
        for node in helper(root):
            print_entry(node.value_() - node_offset)
    elif tree_type == "radix":
        try:
            radix_tree_root_type = prog.type("struct xarray *")
        except LookupError:
            radix_tree_root_type = prog.type("struct radix_tree_root *")
        root = Object(prog, radix_tree_root_type, start)
        for _, entry in radix_tree_for_each(root):
            print_entry(entry.value_())
    elif tree_type == "xarray":
        root = Object(prog, "struct xarray *", start)
        for _, entry in xa_for_each(root):
            print_entry(entry.value_())
    elif tree_type == "maple":
        root = Object(prog, "struct maple_tree *", start)
        for _, _, entry in mt_for_each(root):
            print_entry(entry.value_())
    else:
        assert_never(tree_type)
