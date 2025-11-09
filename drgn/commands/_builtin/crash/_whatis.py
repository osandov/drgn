# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Implements the crash "whatis" command for drgn."""

import argparse
from typing import Any

from drgn import ObjectNotFoundError, Program, sizeof
from drgn.commands import CommandError, argument, drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command


@crash_command(
    name="whatis",
    description="search symbol table for data or type information",
    long_description="""
    Displays the definition of structures, unions, typedefs or text/data symbols.
    """,
    arguments=(
        argument(
            "name",
            help="struct/union/typedef/enum/type name or symbol name",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_whatis(
    prog: Program, cmd: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    target = args.name

    typ = None
    try:
        # Try as-is (typedefs and names with prefixes).
        typ = prog.type(target)
    except LookupError:
        # Try C prefixes 'struct', 'union' and 'enum' if not provided.
        if not target.startswith(("struct ", "union ", "enum ")):
            for prefix in ("struct ", "union ", "enum "):
                try:
                    typ = prog.type(prefix + target)
                    break
                except LookupError:
                    continue

    if typ is not None:
        if args.drgn:
            code = CrashDrgnCodeBuilder(prog)
            code.append(f'typ = prog.type("{typ.type_name()}")\n')
            code.append(
                """try:
    size = sizeof(typ)
except TypeError:
    # Type doesn't have size
    pass\n"""
            )
            code.print()
        else:
            try:
                print(f"{typ};\nSIZE: {sizeof(typ)}")
            except TypeError:
                print(f"{typ};")
        return

    # Otherwise, try to resolve as variable or function.
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.append(f'typ = prog["{target}"].type_\n')
        code.print()
        return

    try:
        obj = prog[target]
    except ObjectNotFoundError:
        raise CommandError(f"unknown type or symbol: {target}")

    decl = obj.type_.variable_declaration(target)
    print(f"{decl};")
