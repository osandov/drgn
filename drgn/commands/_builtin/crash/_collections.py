# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands for iterating kernel collection types."""

import argparse
import sys
import typing
from typing import Any, Literal, Optional, Sequence, Tuple, Union

if typing.TYPE_CHECKING:
    if sys.version_info < (3, 11):
        from typing_extensions import assert_never
    else:
        from typing import assert_never  # novermin

from drgn import Object, Program
from drgn.commands import CommandArgumentError, _repr_black, argument, drgn_argument
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
        for member in entry_members:
            code.append(f"    {_sanitize_member_name(member)} = entry.{member}\n")
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
