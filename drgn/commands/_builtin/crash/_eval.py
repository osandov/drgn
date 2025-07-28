# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands for evaluating and printing values."""

import argparse
import re
import shutil
from typing import Any, Tuple

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands._builtin.crash.structunion import _MEMBER_PATTERN, _NAME_PATTERN
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command, parse_cpuspec
from drgn.helpers.linux.percpu import per_cpu


def _parse_name_and_optional_member(s: str) -> Tuple[str, str]:
    name, sep, member = s.partition(".")
    if not re.fullmatch(_NAME_PATTERN, name) or not re.fullmatch(
        _MEMBER_PATTERN, member
    ):
        return s, ""
    return name, member


@crash_command(
    description="print the value of an object",
    arguments=(
        argument(
            "object",
            metavar="object[:cpuspec]",
            help="object to print. "
            "This may include member accesses and array subscripts. "
            "It does not support arbitrary expressions yet. "
            "For per-cpu variables, this may also contain a colon (':') "
            "followed by a specification of which CPUs to print, "
            "which may be a comma-separated string of CPU numbers or ranges "
            "(e.g., '0,3-4'), "
            "'a' or 'all' (meaning all possible CPUs), "
            "or an empty string (meaning the CPU of the current context)",
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
def _crash_cmd_p(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    expr, sep, cpuspec_str = args.object.partition(":")
    name, member = _parse_name_and_optional_member(expr)
    cpuspec = parse_cpuspec(cpuspec_str) if sep else None

    if args.drgn:
        if member:
            member = "." + member
        if cpuspec is None:
            print(f"object = prog[{name!r}]{member}")
        else:
            code = CrashDrgnCodeBuilder(prog)
            code.append(f"pcpu_object = prog[{name!r}]{member}\n")
            code.add_from_import("drgn.helpers.linux.percpu", "per_cpu")
            code.append_cpuspec(cpuspec, "object = per_cpu(pcpu_object, cpu)\n")
            code.print()
        return

    format_options = {
        "columns": shutil.get_terminal_size().columns,
        "dereference": False,
        "integer_base": args.integer_base or prog.config.get("crash_radix", 10),
    }
    obj = prog[name]
    if member:
        obj = obj.subobject_(member)
    if cpuspec is None:
        print(f"{expr} = {obj.format_(**format_options)}")
    else:
        for cpu in cpuspec.cpus(prog):
            print(
                f"per_cpu({expr}, {cpu}) = {per_cpu(obj, cpu).format_(**format_options)}"
            )
