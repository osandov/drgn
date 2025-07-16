# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Commands for getting system information."""

import argparse
import datetime
import itertools
import logging
import sys
from typing import Any, Callable, Iterable, Literal, Optional, Tuple

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import (
    CrashDrgnCodeBuilder,
    _crash_get_panic_context,
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
        context: Optional[Literal["panic", "current"]] = None,
    ) -> None:
        self.prog = prog
        self.drgn = drgn
        self.context = context
        self.system_fields = system_fields
        if self.drgn:
            self.code = CrashDrgnCodeBuilder(prog)
        elif context == "panic":
            self.task = _crash_get_panic_context(prog)
        elif context == "current":
            self.task = crash_get_context(prog)
        else:
            assert context is None
            self.task = None  # type: ignore

    def _print_drgn(self) -> None:
        if self.system_fields:
            for append, _ in self.FIELDS.values():
                append(self)

        if self.context:
            if self.system_fields:
                self.code.append("\n")

            if self.context == "panic":
                self.code._append_crash_panic_context()
            else:
                assert self.context == "current"
                self.code.append_crash_context()

            self.code.append("\n")

            for append, _ in self.TASK_FIELDS.values():
                append(self)

        self.code.print()

    def print(self) -> None:
        if self.drgn:
            self._print_drgn()
            return

        fields: Iterable[Tuple[str, Tuple[Any, Callable[[_SysPrinter], Optional[str]]]]]
        if self.system_fields and self.task is not None:
            fields = itertools.chain(self.FIELDS.items(), self.TASK_FIELDS.items())
        elif self.system_fields:
            fields = self.FIELDS.items()
        elif self.task is not None:
            fields = self.TASK_FIELDS.items()
        else:
            fields = ()

        rows = []
        for name, (_, getter) in fields:
            try:
                value = getter(self)
            except Exception as e:
                logger.warning("couldn't get %s: %s", name, e)
                continue
            if value is not None:
                rows.append((CellFormat(name, ">"), value))
        print_table(rows, sep=": ")

    def _append_kernel(self) -> None:
        self.code.append(
            """\
try:
    kernel = prog.main_module().debug_file_path
except LookupError:
    kernel = None
"""
        )

    def _get_kernel(self) -> Optional[str]:
        try:
            return self.prog.main_module().debug_file_path
        except LookupError:
            return None

    def _append_dumpfile(self) -> None:
        self.code.append("dumpfile = prog.core_dump_path\n")

    def _get_dumpfile(self) -> Optional[str]:
        return self.prog.core_dump_path

    def _append_cpus(self) -> None:
        self.code.add_from_import(
            "drgn.helpers.linux.cpumask", "num_online_cpus", "num_present_cpus"
        )
        self.code.append(
            """\
cpus = num_present_cpus()
offline_cpus = cpus - num_online_cpus()
"""
        )

    def _get_cpus(self) -> str:
        present = num_present_cpus(self.prog)
        online = num_online_cpus(self.prog)
        cpus = str(present)
        if present > online:
            cpus += f" [OFFLINE: {present - online}]"
        return cpus

    def _append_date(self) -> None:
        self.code.add_from_import(
            "drgn.helpers.linux.timekeeping", "ktime_get_real_seconds"
        )
        self.code.append("timestamp = ktime_get_real_seconds().value_()\n")

    def _get_date(self) -> str:
        timestamp = ktime_get_real_seconds(self.prog).value_()
        dt = datetime.datetime.fromtimestamp(timestamp).astimezone()
        return dt.strftime("%a %b %e %T %Z %Y")

    def _append_uptime(self) -> None:
        self.code.add_from_import("drgn.helpers.linux.timekeeping", "uptime")
        self.code.append("uptime_ = uptime()\n")

    def _get_uptime(self) -> str:
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

    def _append_load_average(self) -> None:
        self.code.add_from_import("drgn.helpers.linux.sched", "loadavg")
        self.code.append("load_average = loadavg()\n")

    def _get_load_average(self) -> str:
        return ", ".join([f"{v:.2f}" for v in loadavg(self.prog)])

    def _append_tasks(self) -> None:
        self.code.add_from_import("drgn.helpers.linux.pid", "for_each_task")
        self.code.append("num_tasks = sum(1 for _ in for_each_task())\n")

    def _get_tasks(self) -> str:
        return str(sum(1 for _ in for_each_task(self.prog)))

    def _append_utsname_field(self, field: str) -> None:
        self.code.append(f'{field} = prog["init_uts_ns"].name.{field}.string_()\n')

    def _get_utsname_field(self, field: str) -> str:
        return escape_ascii_string(
            getattr(self.prog["init_uts_ns"].name, field).string_(),
            escape_backslash=True,
        )

    def _append_nodename(self) -> None:
        self._append_utsname_field("nodename")

    def _get_nodename(self) -> str:
        return self._get_utsname_field("nodename")

    def _append_release(self) -> None:
        self.code.append('release = prog["UTS_RELEASE"].string_()\n')

    def _get_release(self) -> str:
        return escape_ascii_string(
            self.prog["UTS_RELEASE"].string_(), escape_backslash=True
        )

    def _append_version(self) -> None:
        self._append_utsname_field("version")

    def _get_version(self) -> str:
        return self._get_utsname_field("version")

    def _append_machine(self) -> None:
        self._append_utsname_field("machine")

    def _get_machine(self) -> str:
        return self._get_utsname_field("machine")

    def _append_memory(self) -> None:
        self.code.add_from_import("drgn.helpers.linux.mm", "totalram_pages")
        self.code.append('memory = totalram_pages() * prog["PAGE_SIZE"].value_()\n')

    def _get_memory(self) -> str:
        return number_in_binary_units(
            totalram_pages(self.prog) * self.prog["PAGE_SIZE"]
        )

    def _append_panic(self) -> None:
        self.code.add_from_import("drgn.helpers.linux.panic", "panic_message")
        self.code.append("panic = panic_message()\n")

    def _get_panic(self) -> Optional[str]:
        message = panic_message(self.prog)
        if message is None:
            return message
        return double_quote_ascii_string(message)

    def _append_pid(self) -> None:
        self.code.append("pid = task.pid\n")

    def _get_pid(self) -> str:
        return str(self.task.pid.value_())

    def _append_command(self) -> None:
        self.code.append("comm = task.comm\n")

    def _get_command(self) -> str:
        return double_quote_ascii_string(self.task.comm.string_())

    def _append_task(self) -> None:
        self.code.add_from_import("drgn.helpers.linux.sched", "task_thread_info")
        self.code.append("thread_info = task_thread_info(task)\n")

    def _get_task(self) -> str:
        return f"{self.task.value_():x}  [THREAD_INFO: {task_thread_info(self.task).value_():x}]"

    def _append_cpu(self) -> None:
        self.code.add_from_import("drgn.helpers.linux.sched", "task_cpu")
        self.code.append("cpu = task_cpu(task)\n")

    def _get_cpu(self) -> str:
        return str(task_cpu(self.task))

    def _append_state(self) -> None:
        self.code.add_from_import("drgn.helpers.linux.panic", "panic_task")
        self.code.add_from_import(
            "drgn.helpers.linux.sched", "get_task_state", "task_on_cpu"
        )
        self.code.append(
            """\
state = get_task_state(task)
is_active = task_on_cpu(task)
is_panic = task == panic_task()
"""
        )

    def _get_state(self) -> str:
        state = get_task_state(self.task)
        if self.task == panic_task(self.prog):
            state += " (PANIC)"
        elif task_on_cpu(self.task):
            state += " (ACTIVE)"
        return state

    FIELDS = {
        "KERNEL": (_append_kernel, _get_kernel),
        "DUMPFILE": (_append_dumpfile, _get_dumpfile),
        "CPUS": (_append_cpus, _get_cpus),
        "DATE": (_append_date, _get_date),
        "UPTIME": (_append_uptime, _get_uptime),
        "LOAD AVERAGE": (_append_load_average, _get_load_average),
        "TASKS": (_append_tasks, _get_tasks),
        "NODENAME": (_append_nodename, _get_nodename),
        "RELEASE": (_append_release, _get_release),
        "VERSION": (_append_version, _get_version),
        "MACHINE": (_append_machine, _get_machine),
        "MEMORY": (_append_memory, _get_memory),
        "PANIC": (_append_panic, _get_panic),
    }

    TASK_FIELDS = {
        "PID": (_append_pid, _get_pid),
        "COMMAND": (_append_command, _get_command),
        "TASK": (_append_task, _get_task),
        "CPU": (_append_cpu, _get_cpu),
        "STATE": (_append_state, _get_state),
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
