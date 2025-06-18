# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# Commands that don't fit anywhere else.

import argparse
import collections
import datetime
import logging
import re
import sys
from typing import TYPE_CHECKING, Any, List, Optional, Sequence, Tuple

if TYPE_CHECKING:
    if sys.version_info >= (3, 11):
        from typing import Self  # novermin
    else:
        from typing_extensions import Self

from drgn import Program
from drgn.commands import drgn_argument
from drgn.commands.crash import crash_command
from drgn.helpers.common.format import (
    CellFormat,
    escape_ascii_string,
    number_in_binary_units,
    print_table,
)
from drgn.helpers.linux.block import for_each_disk
from drgn.helpers.linux.cpumask import num_online_cpus, num_present_cpus
from drgn.helpers.linux.device import (
    MAJOR,
    for_each_registered_blkdev,
    for_each_registered_chrdev,
)
from drgn.helpers.linux.mm import totalram_pages
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import loadavg
from drgn.helpers.linux.timekeeping import (
    ktime_get_boottime_seconds,
    ktime_get_real_seconds,
)

logger = logging.getLogger("drgn")


@crash_command(
    description="devices",
    # TODO: arguments
    arguments=(drgn_argument,),
)
def _crash_cmd_dev(
    prog: Program, command_name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    # TODO: --drgn
    rows: List[Tuple[Any, ...]] = [
        (
            "CHRDEV",
            "NAME",
            CellFormat("CDEV", "^"),
            "OPERATIONS",
        )
    ]
    for dev, _, name, cdev in for_each_registered_chrdev(prog):
        operations_cell: Any = ""
        if cdev:
            cdev_cell = CellFormat(cdev.value_(), "^x")
            ops = cdev.ops.value_()
            try:
                operations_cell = prog.symbol(ops).name
            except LookupError:
                operations_cell = CellFormat(ops, "x")
        else:
            cdev_cell = CellFormat("(none)", "^")
        rows.append(
            (
                MAJOR(dev),
                escape_ascii_string(name, escape_backslash=True),
                cdev_cell,
                operations_cell,
            )
        )

    rows.append(())

    major_to_gendisk = collections.defaultdict(list)
    for disk in for_each_disk(prog):
        major_to_gendisk[disk.major.value_()].append(disk)
    major_to_gendisk.default_factory = None

    rows.append(
        (
            "BLKDEV",
            "NAME",
            CellFormat("GENDISK", "^"),
            "OPERATIONS",
        )
    )

    for major, name in for_each_registered_blkdev(prog):
        name_string = escape_ascii_string(name, escape_backslash=True)
        try:
            gendisks = major_to_gendisk[major]
        except KeyError:
            rows.append((major, name_string, CellFormat("(none)", "^")))
        else:
            cell0 = major
            cell1 = name_string
            for disk in gendisks:
                ops = disk.fops.value_()
                try:
                    operations_cell = prog.symbol(ops).name
                except LookupError:
                    operations_cell = CellFormat(ops, "x")
                rows.append(
                    (cell0, cell1, CellFormat(disk.value_(), "^x"), operations_cell)
                )

    print_table(rows)


# Helper class to reduce boilerplate for sys command.
class _SysRow:
    def __init__(self, rows: List[Sequence[Any]], name: str) -> None:
        self._rows = rows
        self._name = name

    def __enter__(self) -> "Self":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        if exc_value is None:
            if hasattr(self, "_value"):
                self._rows.append(
                    (CellFormat(self._name, ">"), CellFormat(self._value, "<"))
                )
            return True
        elif isinstance(exc_value, Exception):
            logger.warning("couldn't get %s: %s", self._name, exc_value)
            return True
        else:
            return False

    def set(self, value: Any) -> None:
        self._value = value


class _SysOutput:
    def __init__(self) -> None:
        self.rows: List[Sequence[Any]] = []

    def row(self, name: str) -> _SysRow:
        return _SysRow(self.rows, name)


def _date(prog: Program) -> str:
    match = re.search(b"^CRASHTIME=([0-9]+)$", prog["VMCOREINFO"].string_())
    if match:
        timestamp = int(match.group(1))
    else:
        timestamp = ktime_get_real_seconds(prog).value_()

    dt = datetime.datetime.fromtimestamp(timestamp).astimezone()
    return dt.strftime("%a %b %e %T %Z %Y")


def _uptime_str(prog: Program) -> str:
    seconds = ktime_get_boottime_seconds(prog).value_()

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


@crash_command(
    description="system information",
    # TODO: arguments: -c, config, -t, -i
    arguments=(drgn_argument,),
)
def _crash_cmd_sys(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    # TODO: --drgn

    output = _SysOutput()  # TODO: bad name

    with output.row("KERNEL") as row:
        try:
            kernel = prog.main_module().debug_file_path
        except LookupError:
            pass
        else:
            if kernel is not None:
                row.set(kernel)

    # TODO: DUMPFILE

    with output.row("CPUS") as row:
        present = num_present_cpus(prog)
        online = num_online_cpus(prog)
        cpus = str(present)
        if present > online:
            cpus += f" [OFFLINE: {present - online}]"
        row.set(cpus)

    with output.row("DATE") as row:
        row.set(_date(prog))

    with output.row("UPTIME") as row:
        row.set(_uptime_str(prog))

    with output.row("LOAD AVERAGE") as row:
        row.set(", ".join([f"{v:.2f}" for v in loadavg(prog)]))

    with output.row("TASKS") as row:
        row.set(sum(1 for _ in for_each_task(prog)))

    try:
        utsname = prog["init_uts_ns"].name
    except Exception as e:
        # Save the exception so we can log it for everything that uses utsname.
        utsname_exc: Optional[Exception] = e
    else:
        utsname_exc = None
    with output.row("NODENAME") as row:
        if utsname_exc is not None:
            raise utsname_exc
        row.set(escape_ascii_string(utsname.nodename.string_(), escape_backslash=True))
    with output.row("RELEASE") as row:
        row.set(
            escape_ascii_string(prog["UTS_RELEASE"].string_(), escape_backslash=True)
        )
    with output.row("VERSION") as row:
        if utsname_exc is not None:
            raise utsname_exc
        row.set(escape_ascii_string(utsname.version.string_(), escape_backslash=True))
    with output.row("MACHINE") as row:
        if utsname_exc is not None:
            raise utsname_exc
        # TODO: this has (2600 Mhz) on crash
        row.set(escape_ascii_string(utsname.machine.string_(), escape_backslash=True))

    with output.row("MEMORY") as row:
        row.set(number_in_binary_units(prog["PAGE_SIZE"] * totalram_pages(prog)))

    # TODO: PANIC:

    print_table(output.rows, sep=": ")
