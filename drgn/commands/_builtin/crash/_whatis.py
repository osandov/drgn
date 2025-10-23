# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Implements the crash "whatis" command for drgn."""

import argparse
from typing import Any

from drgn import Program, TypeKind, sizeof
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
    except Exception:
        # Try C prefixes 'struct', 'union' and 'enum' if not provided.
        if not target.startswith(("struct ", "union ", "enum ")):
            for prefix in ("struct ", "union ", "enum "):
                try:
                    typ = prog.type(prefix + target)
                    break
                except Exception:
                    continue

    if typ is not None:
        if args.drgn:
            code = CrashDrgnCodeBuilder(prog)
            code.append(f'typ = prog.type("{typ.type_name()}")\n')
            code.append("size = sizeof(typ)\n")
            code.print()
        else:
            kind = typ.kind
            if kind in (TypeKind.STRUCT, TypeKind.UNION):
                print(f"{typ}\nSIZE: {sizeof(typ)}")
            elif kind == TypeKind.TYPEDEF:
                print(f"{typ};\nSIZE: {sizeof(typ)}")
            elif kind == TypeKind.ENUM:
                print(f"{typ};")
            else:
                print(f"{typ};\nSIZE: {sizeof(typ)}")
        return

    # Otherwise, try to resolve as variable or function.
    try:
        obj = prog[target]
    except Exception:
        raise CommandError(f"unknown type or symbol: {target}")

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.append(f'obj = prog["{target}"]\n')
        code.append(f'decl = obj.type_.variable_declaration("{target}")\n')
        code.print()
        return

    decl = obj.type_.variable_declaration(target)
    print(f"{decl};")
