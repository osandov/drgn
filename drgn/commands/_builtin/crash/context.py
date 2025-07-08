# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands related to the current context."""

import argparse
import sys
from typing import Any, Callable, NamedTuple, Optional

from drgn import Object, Program
from drgn.commands import (
    CommandArgumentError,
    CommandError,
    argument,
    drgn_argument,
    mutually_exclusive_group,
)
from drgn.commands.crash import (
    _add_crash_cpu_context,
    _add_crash_panic_context,
    _crash_get_panic_context,
    _find_pager,
    _get_pager,
    _pid_or_task,
    add_crash_context,
    crash_command,
    crash_get_context,
)
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.panic import panic_task
from drgn.helpers.linux.sched import (
    cpu_curr,
    get_task_state,
    task_cpu,
    task_on_cpu,
    task_thread_info,
)


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


class _CrashOption(NamedTuple):
    show: Callable[[Program], None]
    validate: Callable[[str], None]
    set: Callable[[Program, str], None]


_OPTIONS = {
    "scroll": _CrashOption(
        _show_scroll_option, _validate_scroll_option, _set_scroll_option
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
            source = _add_crash_panic_context(prog, "")
        elif args.cpu is not None:
            source = _add_crash_cpu_context("", args.cpu)
        else:
            if args.task is None:
                source = """\
from drgn.helpers.linux.panic import panic_task
from drgn.helpers.linux.sched import (
    get_task_state,
    task_cpu,
    task_on_cpu,
    task_thread_info,
)


pid = task.pid
comm = task.comm
thread_info = task_thread_info(task)
cpu = task_cpu(task)
state = get_task_state(task)  # See also task_state_to_char(task)
active = task_on_cpu(task)  # Is the task running on a CPU?
panic = task == panic_task()  # Is this the task that panicked?
"""
            else:
                source = ""
            source = add_crash_context(prog, source, args.task)
        sys.stdout.write(source)
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
        task = crash_get_context(prog)
        state = get_task_state(task)
        if task == panic_task(prog):
            state += " (PANIC)"
        elif task_on_cpu(task):
            state += " (ACTIVE)"
        print_table(
            [
                (CellFormat("PID", ">"), CellFormat(task.pid.value_(), "<")),
                (
                    CellFormat("COMMAND", ">"),
                    '"'
                    + escape_ascii_string(
                        task.comm.string_(),
                        escape_double_quote=True,
                        escape_backslash=True,
                    )
                    + '"',
                ),
                (
                    CellFormat("TASK", ">"),
                    f"{task.value_():x}  [THREAD_INFO: {task_thread_info(task).value_()}]",
                ),
                (CellFormat("CPU", ">"), CellFormat(task_cpu(task), "<")),
                (CellFormat("STATE", ">"), state),
            ],
            sep=": ",
        )
        return task
    prog.config["crash_context"] = task
    return task
