# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands for kernel modules and debugging symbols."""

import argparse
import contextlib
import logging
from typing import Any, Iterator, List, Sequence

from drgn import Program, RelocatableModule
from drgn.commands import (
    CommandArgumentError,
    _repr_black,
    argument,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import CellFormat, print_table
from drgn.helpers.linux.module import module_taints


@contextlib.contextmanager
def _log_debug() -> Iterator[None]:
    logger = logging.getLogger("drgn")
    old_level = logger.level
    try:
        logger.setLevel(logging.DEBUG)
        yield
    finally:
        logger.setLevel(old_level)


@crash_command(
    description="module information and loading debugging symbols",
    arguments=(
        mutually_exclusive_group(
            argument(
                "-s",
                dest="load",
                nargs="+",
                metavar=("MODULE", "FILE"),
                help="""
                load debugging symbols for the given module from the given
                file, or from the default locations if no file is given
                """,
            ),
            argument(
                "-S",
                dest="load_all",
                metavar="DIRECTORY",
                nargs="?",
                default=argparse.SUPPRESS,
                help="""
                load debugging symbols for all modules from the given
                directory, or from the default locations if no directory is
                given
                """,
            ),
            argument(
                "-t",
                dest="taints",
                action="store_true",
                help="display tainted modules",
            ),
        ),
        drgn_argument,
    ),
)
def _crash_cmd_mod(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    # argparse doesn't support nargs ranges, so we have to check this manually.
    if args.load is not None and len(args.load) > 2:
        raise CommandArgumentError("-s takes at most one file")

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)

        if hasattr(args, "load_all"):
            if args.load_all is not None:
                code.append(
                    f"""\
old_kernel_directories = prog.debug_info_options.kernel_directories
try:
    prog.debug_info_options.kernel_directories = ({_repr_black(args.load_all)},)
    """
                )
            code.append("prog.load_default_debug_info()\n")
            if args.load_all is None:
                code.append("\n")
            else:
                code.append(
                    """\
finally:
    prog.debug_info_options.kernel_directories = old_kernel_directories

"""
                )

        code.add_from_import("drgn", "RelocatableModule")
        code.append(
            """\
for module, _ in prog.loaded_modules():
    if not isinstance(module, RelocatableModule):
        # Skip vmlinux.
        continue
"""
        )
        if args.load is not None:
            code.append(
                f"""
    if module.name != {_repr_black(args.load[0])}:
        continue

"""
            )
            if len(args.load) == 1:
                code.append("    prog.load_module_debug_info(module)\n\n")
            else:
                code.append(f"    module.try_file({_repr_black(args.load[1])})\n\n")

        code.append("    struct_module = module.object\n")

        if args.taints:
            code.add_from_import("drgn.helpers.linux.module", "module_taints")
            code.append("    taints = module_taints(struct_module)\n")
        else:
            code.append(
                """\
    name = module.name
    text_base = module.address
    size = sum(end - start for start, end in module.address_ranges)
    object_file = module.debug_file_path
"""
            )
        code.print()
        return

    if args.taints:
        rows: List[Sequence[Any]] = [("NAME", "TAINTS")]
        for module, _ in prog.loaded_modules():
            if not isinstance(module, RelocatableModule):
                continue
            taints = module_taints(module.object)
            if taints:
                rows.append((module.name, taints))
        if len(rows) > 1:
            print_table(rows)
        else:
            print("no tainted modules")
        return

    if hasattr(args, "load_all"):
        old_kernel_directories = prog.debug_info_options.kernel_directories
        try:
            if args.load_all is not None:
                prog.debug_info_options.kernel_directories = (args.load_all,)
            with _log_debug():
                prog.load_default_debug_info()
        finally:
            prog.debug_info_options.kernel_directories = old_kernel_directories

    rows = [
        (
            CellFormat("MODULE", "^"),
            "NAME",
            CellFormat("TEXT_BASE", "^"),
            CellFormat("SIZE", ">"),
            "OBJECT FILE",
        ),
    ]
    for module, _ in prog.loaded_modules():
        if not isinstance(module, RelocatableModule):
            continue

        if args.load is not None:
            if args.load[0] != module.name:
                continue
            with _log_debug():
                if len(args.load) == 1:
                    prog.load_module_debug_info(module)
                else:
                    module.try_file(args.load[1])

        object_file = module.debug_file_path
        if object_file is None:
            object_file = "(not loaded)"
            if getattr(module.object, "kallsyms", None):
                object_file += "  [CONFIG_KALLSYMS]"

        if module.address_ranges is None:
            size = 0
        else:
            size = sum(end - start for start, end in module.address_ranges)

        rows.append(
            (
                CellFormat(module.object.value_(), "^x"),
                module.name,
                CellFormat(module.address, "^x"),
                size,
                object_file,
            )
        )
    print_table(rows)
