# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Commands for getting system information."""

import argparse
import datetime
import itertools
import logging
import sys
from typing import Any, Callable, Iterable, List, Literal, Optional, Tuple

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import (
    _add_crash_panic_context,
    _crash_get_panic_context,
    _merge_imports,
    add_crash_context,
    crash_command,
    crash_get_context,
)
from drgn.helpers.common.format import (
    CellFormat,
    double_quote_ascii_string,
    escape_ascii_string,
    number_in_binary_units,
    print_table,
)
from drgn.helpers.linux.cpumask import num_online_cpus, num_present_cpus
from drgn.helpers.linux.kconfig import _get_raw_kconfig
from drgn.helpers.linux.mm import totalram_pages
from drgn.helpers.linux.panic import panic_message, panic_task
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import (
    get_task_state,
    loadavg,
    task_cpu,
    task_on_cpu,
    task_thread_info,
)
from drgn.helpers.linux.timekeeping import (
    ktime_get_boottime_seconds,
    ktime_get_real_seconds,
)

logger = logging.getLogger("drgn")


class _SysPrinter:
    def __init__(
        self,
        prog: Program,
        drgn: bool,
        *,
        system_fields: bool = True,
        task: Optional[Literal["panic", "current"]] = None,
    ) -> None:
        self.prog = prog
        self.drgn = drgn
        self.system_fields = system_fields
        if task == "panic":
            if drgn:
                self._add_task_context = _add_crash_panic_context
            else:
                self.task = _crash_get_panic_context(prog)
        elif task == "current":
            if drgn:
                self._add_task_context = add_crash_context
            else:
                self.task = crash_get_context(prog)

    def _print_drgn(self) -> None:
        sources: List[str] = []
        if self.system_fields:
            for getter in self.FIELDS.values():
                sources.append(getter(self))  # type: ignore[arg-type]
        if hasattr(self, "_add_task_context"):
            sources.append(self._add_task_context(self.prog, ""))
            for getter in self.TASK_FIELDS.values():
                sources.append(getter(self))
        sys.stdout.write(_merge_imports(*sources))

    def print(self) -> None:
        if self.drgn:
            self._print_drgn()
            return

        fields: Iterable[Tuple[str, Callable[[_SysPrinter], Optional[str]]]]
        if self.system_fields and hasattr(self, "task"):
            fields = itertools.chain(self.FIELDS.items(), self.TASK_FIELDS.items())
        elif self.system_fields:
            fields = self.FIELDS.items()
        elif hasattr(self, "task"):
            fields = self.TASK_FIELDS.items()
        else:
            fields = ()

        rows = []
        for name, getter in fields:
            try:
                value = getter(self)
            except Exception as e:
                logger.warning("couldn't get %s: %s", name, e)
                continue
            if value is not None:
                rows.append((CellFormat(name, ">"), value))
        print_table(rows, sep=": ")

    def _get_kernel(self) -> Optional[str]:
        if self.drgn:
            return """\
try:
    kernel = prog.main_module().debug_file_path
except LookupError:
    kernel = None
"""

        try:
            return self.prog.main_module().debug_file_path
        except LookupError:
            return None

    def _get_dumpfile(self) -> Optional[str]:
        if self.drgn:
            return "dumpfile = prog.core_dump_path\n"
        return self.prog.core_dump_path

    def _get_cpus(self) -> str:
        if self.drgn:
            return """\
from drgn.helpers.linux.cpumask import num_online_cpus, num_present_cpus


cpus = num_present_cpus()
offline_cpus = cpus - num_online_cpus()
"""

        present = num_present_cpus(self.prog)
        online = num_online_cpus(self.prog)
        cpus = str(present)
        if present > online:
            cpus += f" [OFFLINE: {present - online}]"
        return cpus

    def _get_date(self) -> str:
        if self.drgn:
            return """\
from drgn.helpers.linux.timekeeping import ktime_get_real_seconds


timestamp = ktime_get_real_seconds().value_()
"""

        timestamp = ktime_get_real_seconds(self.prog).value_()
        dt = datetime.datetime.fromtimestamp(timestamp).astimezone()
        return dt.strftime("%a %b %e %T %Z %Y")

    def _get_uptime(self) -> str:
        if self.drgn:
            return """\
from drgn.helpers.linux.timekeeping import uptime


uptime_ = uptime()
"""

        seconds = ktime_get_boottime_seconds(self.prog).value_()

        if seconds >= 24 * 60 * 60:
            days = seconds // (24 * 60 * 60)
            seconds -= days * (24 * 60 * 60)
            days_str = f"{days} days, "
        else:
            days_str = ""

        hours = seconds // (60 * 60)
        seconds -= hours * (60 * 60)

        minutes = seconds // 60
        seconds %= 60

        return f"{days_str}{hours:02}:{minutes:02}:{seconds:02}"

    def _get_load_average(self) -> str:
        if self.drgn:
            return """\
from drgn.helpers.linux.sched import loadavg


load_average = loadavg()
"""
        return ", ".join([f"{v:.2f}" for v in loadavg(self.prog)])

    def _get_tasks(self) -> str:
        if self.drgn:
            return """
from drgn.helpers.linux.pid import for_each_task


num_tasks = sum(1 for _ in for_each_task())
"""
        return str(sum(1 for _ in for_each_task(self.prog)))

    def _get_utsname_field(self, field: str) -> str:
        if self.drgn:
            return f'{field} = prog["init_uts_ns"].name.{field}.string_()\n'
        return escape_ascii_string(
            getattr(self.prog["init_uts_ns"].name, field).string_(),
            escape_backslash=True,
        )

    def _get_nodename(self) -> str:
        return self._get_utsname_field("nodename")

    def _get_release(self) -> str:
        if self.drgn:
            return 'release = prog["UTS_RELEASE"].string_()\n'
        return escape_ascii_string(
            self.prog["UTS_RELEASE"].string_(), escape_backslash=True
        )

    def _get_version(self) -> str:
        return self._get_utsname_field("version")

    def _get_machine(self) -> str:
        return self._get_utsname_field("machine")

    def _get_memory(self) -> str:
        if self.drgn:
            return """\
from drgn.helpers.linux.mm import totalram_pages


memory = totalram_pages() * prog["PAGE_SIZE"].value_()
"""
        return number_in_binary_units(
            totalram_pages(self.prog) * self.prog["PAGE_SIZE"]
        )

    def _get_panic(self) -> Optional[str]:
        if self.drgn:
            return """\
from drgn.helpers.linux.panic import panic_message


panic = panic_message()
"""
        message = panic_message(self.prog)
        if message is None:
            return message
        return double_quote_ascii_string(message)

    def _get_pid(self) -> str:
        if self.drgn:
            return "pid = task.pid\n"
        return str(self.task.pid.value_())

    def _get_command(self) -> str:
        if self.drgn:
            return "comm = task.comm\n"
        return double_quote_ascii_string(self.task.comm.string_())

    def _get_task(self) -> str:
        if self.drgn:
            return """\
from drgn.helpers.linux.sched import task_thread_info


thread_info = task_thread_info(task)
"""
        return f"{self.task.value_():x}  [THREAD_INFO: {task_thread_info(self.task).value_():x}]"

    def _get_cpu(self) -> str:
        if self.drgn:
            return """\
from drgn.helpers.linux.sched import task_cpu


cpu = task_cpu(task)
"""
        return str(task_cpu(self.task))

    def _get_state(self) -> str:
        if self.drgn:
            return """\
from drgn.helpers.linux.panic import panic_task
from drgn.helpers.linux.sched import get_task_state, task_on_cpu


state = get_task_state(task)
is_active = task_on_cpu(task)
is_panic = task == panic_task()
"""
        state = get_task_state(self.task)
        if self.task == panic_task(self.prog):
            state += " (PANIC)"
        elif task_on_cpu(self.task):
            state += " (ACTIVE)"
        return state

    FIELDS = {
        "KERNEL": _get_kernel,
        "DUMPFILE": _get_dumpfile,
        "CPUS": _get_cpus,
        "DATE": _get_date,
        "UPTIME": _get_uptime,
        "LOAD AVERAGE": _get_load_average,
        "TASKS": _get_tasks,
        "NODENAME": _get_nodename,
        "RELEASE": _get_release,
        "VERSION": _get_version,
        "MACHINE": _get_machine,
        "MEMORY": _get_memory,
        "PANIC": _get_panic,
    }

    TASK_FIELDS = {
        "PID": _get_pid,
        "COMMAND": _get_command,
        "TASK": _get_task,
        "CPU": _get_cpu,
        "STATE": _get_state,
    }


@crash_command(
    description="system information",
    arguments=(
        argument(
            "config",
            metavar="config",
            choices=("config",),
            nargs="?",
            help="print kernel configuration (requires ``CONFIG_IKCONFIG``)",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_sys(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.config:
        if args.drgn:
            sys.stdout.write(
                """\
from drgn.helpers.linux.kconfig import get_kconfig


kconfig = get_kconfig()
"""
            )
            return
        sys.stdout.write(_get_raw_kconfig(prog).decode())
        return

    _SysPrinter(prog, args.drgn).print()
