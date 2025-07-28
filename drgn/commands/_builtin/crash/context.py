# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands related to the current context."""

import argparse
from typing import Any, Callable, NamedTuple, Optional

from drgn import Object, Program
from drgn.commands import (
    CommandArgumentError,
    CommandError,
    argument,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands._builtin.crash.system import _SysPrinter
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _crash_get_panic_context,
    _find_pager,
    _get_pager,
    _pid_or_task,
    crash_command,
    crash_get_context,
)
from drgn.helpers.linux.sched import cpu_curr


def _show_scroll_option(prog: Program) -> None:
    on = "on" if prog.config.get("crash_scroll", True) else "off"
    pager = _get_pager(prog)
    if pager:
        print(f"scroll: {on} ({' '.join(pager)})")
    else:
        print("scroll: off (pager not found)")


def _validate_scroll_option(value: str) -> None:
    if value not in {"on", "off", "less", "more"}:
        raise CommandArgumentError(
            f"set: error: invalid value for scroll: {value!r} "
            "(must be on, off, less, or more)"
        )


def _set_scroll_option(prog: Program, value: str) -> None:
    if value == "on":
        prog.config["crash_scroll"] = True
    elif value == "off":
        prog.config["crash_scroll"] = False
    else:
        pager = _find_pager(value)
        if not pager:
            raise CommandError("pager not found")
        prog.config["crash_pager"] = pager


def _show_radix_option(prog: Program) -> None:
    radix = prog.config.get("crash_radix", 10)
    print(f"output radix: {radix} ({'hex' if radix == 16 else 'decimal'})")


_RADICES = {
    # Crash allows anything starting with "dec", "ten", "hex", or "six". We are
    # stricter.
    "10": 10,
    "dec": 10,
    "decimal": 10,
    "ten": 10,
    "16": 16,
    "hex": 16,
    "hexadecimal": 16,
    "sixteen": 16,
}


def _validate_radix_option(value: str) -> None:
    if value not in _RADICES:
        raise CommandArgumentError(
            f"set: error: invalid value for radix: {value!r} (must be 10 or 16)"
        )


def _set_radix_option(prog: Program, value: str) -> None:
    prog.config["crash_radix"] = _RADICES[value]


class _CrashOption(NamedTuple):
    show: Callable[[Program], None]
    validate: Callable[[str], None]
    set: Callable[[Program, str], None]


_OPTIONS = {
    "scroll": _CrashOption(
        _show_scroll_option, _validate_scroll_option, _set_scroll_option
    ),
    "radix": _CrashOption(
        _show_radix_option, _validate_radix_option, _set_radix_option
    ),
}


@crash_command(
    description="set current context or configuration",
    long_description="""
    Set/show the default context used by commands that target a task, or
    set/show configuration.

    If no options are given, then the current context is displayed.

    If given a configuration option name and a value, then the option is set to
    that value. If given a configuration option name only, then the current
    value is shown. The following options and values are supported:

    * ``scroll on | off``: enable (the default) or disable scrolling of long output.

    * ``scroll less | more``: set the pager program. The default is ``less``.

    * ``radix 10 | 16``: set the default integer output base. The default is 10.
    """,
    usage=r"**set** [*pid* | *task* | **-p** | **-c** *CPU* | *option* [*value*]] [**\-\-drgn**]",
    arguments=(
        mutually_exclusive_group(
            # argparse can't express pid | task | option [value], so we use
            # this hack to consume all of the positional arguments (which we
            # parse manually) and define dummy arguments that are only used for
            # the help string.
            argument(
                "posargs",
                metavar="pid_or_task_or_option",
                nargs="*",
                # Work around https://github.com/python/cpython/issues/72795
                # before Python 3.13.
                default=[],
                help=argparse.SUPPRESS,
            ),
            argument(
                "task",
                metavar="pid",
                nargs="?",
                help="set the current context to the task "
                "with the given decimal process ID",
            ),
            argument(
                "task",
                nargs="?",
                help="set the current context to the task "
                "with the hexadecimal ``task_struct`` address",
            ),
            argument(
                "-c",
                dest="cpu",
                type=int,
                help="set the current context to the active task on the given CPU",
            ),
            argument(
                "-p",
                dest="panic",
                action="store_true",
                help="set the current context to the task that crashed (for core dumps) "
                "or the drgn process itself (for live kernels)",
            ),
            argument("option", nargs="?", help="option to get or set"),
            argument("value", nargs="?", help="value to set option to"),
        ),
        drgn_argument,
    ),
)
def _crash_cmd_set(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> Optional[Object]:
    if args.posargs:
        option = _OPTIONS.get(args.posargs[0])
        if option is not None:
            if args.drgn:
                raise CommandError("no drgn equivalent")

            if len(args.posargs) > 1:
                option.validate(args.posargs[1])

                if len(args.posargs) > 2:
                    raise CommandArgumentError(
                        "set: error: unrecognized arguments: "
                        + " ".join(args.posargs[2:])
                    )

                option.set(prog, args.posargs[1])

            option.show(prog)
            return None

        try:
            args.task = _pid_or_task(args.posargs[0])
        except ValueError:
            raise CommandArgumentError(
                f"set: error: not a pid, task, or option: {args.posargs[0]!r}"
            )

        if len(args.posargs) > 1:
            raise CommandArgumentError(
                "set: error: unrecognized arguments: " + " ".join(args.posargs[1:])
            )

    if args.drgn:
        if args.panic:
            code = CrashDrgnCodeBuilder(prog)
            code._append_crash_panic_context()
            code.print()
        elif args.cpu is not None:
            code = CrashDrgnCodeBuilder(prog)
            code._append_crash_cpu_context(args.cpu)
            code.print()
        elif args.task is not None:
            code = CrashDrgnCodeBuilder(prog)
            code.append_crash_context(args.task)
            code.print()
        else:
            _SysPrinter(prog, True, system_fields=False, context="current").print()
        return None

    if args.panic:
        task = _crash_get_panic_context(prog)
        prog.config.pop("crash_context_origin", None)
    elif args.cpu is not None:
        task = cpu_curr(prog, args.cpu)
        prog.config["crash_context_origin"] = ("cpu", args.cpu)
    elif args.task is not None:
        task = crash_get_context(prog, args.task)
        prog.config["crash_context_origin"] = args.task
    else:
        printer = _SysPrinter(prog, False, system_fields=False, context="current")
        printer.print()
        return printer.task
    prog.config["crash_context"] = task
    return task
