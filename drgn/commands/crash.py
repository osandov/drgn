# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for porting commands from :doc:`crash <crash_compatibility>`."""

import collections
import contextlib
import os
import re
import shutil
import subprocess
import sys
from typing import Any, List, Literal, Optional, Tuple

from _drgn_util.typingutils import copy_func_params
from drgn import Object, Program, ProgramFlags
from drgn.commands import (
    CommandFuncDecorator,
    CommandNamespace,
    CustomCommandFuncDecorator,
    command,
    custom_command,
)
from drgn.helpers.linux.pid import find_task


def _pid_or_task(s: str) -> Tuple[Literal["pid", "task"], int]:
    try:
        return "pid", int(s)
    except ValueError:
        return "task", int(s, 16)


def _find_pager(which: Optional[str] = None) -> Optional[List[str]]:
    if which is None or which == "less":
        less = shutil.which("less")
        if less:
            return [less, "-E", "-X"]

    if which is None or which == "more":
        more = shutil.which("more")
        if more:
            return [more]

    return None


def _get_pager(prog: Program) -> Optional[List[str]]:
    try:
        return prog.config["crash_pager"]
    except KeyError:
        pager = _find_pager()
        prog.config["crash_pager"] = pager
        return pager


class _CrashCommandNamespace(CommandNamespace):
    def __init__(self) -> None:
        super().__init__(
            func_name_prefix="_crash_cmd_",
            argparse_types=(("pid_or_task", _pid_or_task),),
        )

    def split_command(self, command: str) -> Tuple[str, str]:
        # '*' and '!' may be combined with their first argument.
        match = re.fullmatch(r"\s*([!*])\s*(.*)", command)
        if match:
            return match.group(1), match.group(2)
        return super().split_command(command)

    def run(self, prog: Program, command: str, **kwargs: Any) -> Any:
        if prog.config.get("crash_scroll", True):
            pager = _get_pager(prog)
            if pager:
                # If stdout isn't a file descriptor, we can't actually pipe it
                # to a pager.
                try:
                    stdout_fileno = sys.stdout.fileno()
                except (AttributeError, OSError):
                    pager = None
        else:
            pager = None

        if not pager:
            return super().run(prog, command, **kwargs)

        with subprocess.Popen(
            pager, stdin=subprocess.PIPE, stdout=stdout_fileno, text=True
        ) as pager_process, contextlib.redirect_stdout(pager_process.stdin):
            ret = super().run(prog, command, **kwargs)
            pager_process.stdin.close()  # type: ignore[union-attr]
        return ret


CRASH_COMMAND_NAMESPACE: CommandNamespace = _CrashCommandNamespace()
"""Command namespace used for crash commands."""


@copy_func_params(command)
def crash_command(*args: Any, **kwargs: Any) -> CommandFuncDecorator:
    """
    Decorator to register a :doc:`crash command <crash_compatibility>`.

    This is the same as :func:`~drgn.commands.command()` other than the
    following:

    1. The command is only available as a subcommand of the
       :drgncommand:`crash` command.
    2. If *name* is not given, then the name of the decorated function must
       begin with ``_crash_cmd_`` instead of ``_cmd_``.
    3. The command may use the ``"pid_or_task"`` argparse type to parse a task
       context argument to a ``(type, value)`` tuple, where ``type`` is either
       ``"pid"`` or ``"task"`` and ``value`` is an :class:`int`.
    """
    return command(*args, **kwargs, namespace=CRASH_COMMAND_NAMESPACE)


@copy_func_params(custom_command)
def crash_custom_command(*args: Any, **kwargs: Any) -> CustomCommandFuncDecorator:
    """
    Like :func:`crash_command()` but for
    :func:`~drgn.commands.custom_command()`.
    """
    return custom_command(*args, **kwargs, namespace=CRASH_COMMAND_NAMESPACE)


def _crash_get_panic_context(prog: Program) -> Object:
    if (prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)) == (
        ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
    ):
        return find_task(prog, os.getpid())
    elif not (prog.flags & ProgramFlags.IS_LIVE):
        return prog.crashed_thread().object
    else:
        raise ValueError("no default context")


def crash_get_context(
    prog: Program, arg: Optional[Tuple[Literal["pid", "task"], int]] = None
) -> Object:
    """
    Get the task context to use for a crash command.

    :param arg: Context parsed by the ``"pid_or_task"`` argparse type to use.
        If ``None`` or not given, use the current context.
    :return: ``struct task_struct *``
    """
    if arg is not None:
        if arg[0] == "pid":
            task = find_task(prog, arg[1])
            if not task:
                raise LookupError("no such process")
            return task
        else:
            return Object(prog, "struct task_struct *", arg[1])

    try:
        return prog.config["crash_context"]
    except KeyError:
        pass
    prog.config["crash_context"] = task = _crash_get_panic_context(prog)
    return task


def _merge_imports(*sources: str) -> str:
    # Combine multiple strings of Python source code into one, merging and
    # sorting their imports (which must be at the beginning of each string).
    imports = collections.defaultdict(set)
    other_parts: List[str] = []

    for source in sources:
        for match in re.finditer(
            r"""
            (?P<import>
                ^\s*
                import
                [^\S\n]+
                (?P<import_modules>
                    [\w.]+
                    (?:\s*,\s*[\w.]+)*
                )
                \s*$\n?
            )
            |
            (?P<from_import>
                ^\s*
                from
                [^\S\n]+
                (?P<from_import_module>[\w.]+)
                [^\S\n]+
                import
                (?:
                    [^\S\n]+
                    (?P<from_import_names>
                        \w+
                        (?:[^\S\n]*,[^\S\n]*\w+)*
                    )
                    |
                    [^\S\n]*
                    \(
                    \s*
                    (?P<from_import_names_in_parens>
                        \w+
                        (?:\s*,\s*\w+)*
                        (?:\s*,)?
                    )
                    \s*
                    \)
                )
                \s*$\n?
            )
            |
            (?P<rest>(?s:.+))
            """,
            source,
            flags=re.MULTILINE | re.VERBOSE,
        ):
            if match.lastgroup == "import":
                for module in match.group("import_modules").split(","):
                    imports[module.strip()].add("")
            elif match.lastgroup == "from_import":
                module = imports[match.group("from_import_module")]
                for name in (
                    match.group("from_import_names")
                    or match.group("from_import_names_in_parens")
                ).split(","):
                    name = name.strip()
                    if not name:
                        continue
                    module.add(name)
            else:
                rest = match.group("rest")
                if rest:
                    if other_parts:
                        other_parts.append("\n")
                    other_parts.append(rest)

    parts: List[str] = []
    first_party_imports: List[str] = []
    for module, names in sorted(imports.items()):
        if module == "drgn" or module.startswith("drgn."):
            target = first_party_imports
        else:
            target = parts

        if "" in names:
            names.remove("")
            target.append(f"import {module}\n")

        if names:
            sorted_names = sorted(names)
            line = f"from {module} import {', '.join(sorted_names)}\n"
            # 88 (the default Black line length) + 1 for the newline.
            if len(line) <= 89:
                target.append(line)
            else:
                target.append(f"from {module} import (\n")
                for name in sorted_names:
                    target.append(f"    {name},\n")
                target.append(")\n")

    if parts and first_party_imports:
        parts.append("\n")
    parts.extend(first_party_imports)

    if parts and other_parts:
        parts.append("\n\n")
    parts.extend(other_parts)

    return "".join(parts)


def _add_context(source: str, context: str) -> str:
    if not source:
        return context

    return _merge_imports(context, source)


def _add_crash_panic_context(prog: Program, source: str) -> str:
    if (prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)) == (
        ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
    ):
        context = """\
import os

from drgn.helpers.linux.pid import find_task


task = find_task(os.getpid())
"""
    else:
        context = """\
from drgn.helpers.linux.panic import panic_task


task = panic_task()
"""
    return _add_context(source, context)


def _add_crash_cpu_context(source: str, cpu: int) -> str:
    return _add_context(
        source,
        f"""\
from drgn.helpers.linux.sched import cpu_curr


cpu = {cpu}
task = cpu_curr(cpu)
""",
    )


def add_crash_context(
    prog: Program, source: str, arg: Optional[Tuple[Literal["pid", "task"], int]] = None
) -> str:
    """
    Edit an output string for :func:`drgn_argument` to include code for getting
    the task context.

    :param arg: Context parsed by the ``"pid_or_task"`` argparse type to use.
        If ``None`` or not given, use the current context.
    """
    if arg is None:
        arg = prog.config.get("crash_context_origin")
        if arg is None:
            return _add_crash_panic_context(prog, source)
        elif arg[0] == "cpu":
            return _add_crash_cpu_context(source, arg[1])

    if arg[0] == "pid":
        return _add_context(
            source,
            f"""\
from drgn.helpers.linux.pid import find_task


pid = {arg[1]}
task = find_task(pid)
""",
        )
    else:
        assert arg[0] == "task"
        return _add_context(
            source,
            f"""\
from drgn import Object


address = {hex(arg[1])}
task = Object(prog, "struct task_struct *", address)
""",
        )
