# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash timer command."""

import argparse
from typing import Any, List, Sequence

from drgn import FaultError, Object, Program, ProgramFlags
from drgn.commands import argument, drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command, parse_cpuspec
from drgn.helpers.common.format import CellFormat, RowOptions, print_table
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.timekeeping import ktime_get_coarse_ns, ktime_to_ns
from drgn.helpers.linux.timer import (
    hrtimer_clock_base_for_each,
    timer_base_for_each,
    timer_base_names,
)


def _function_cell(function: Object) -> str:
    address = function.value_()
    try:
        function_symbol = function.prog_.symbol(address)
    except LookupError:
        return f"{address:x}"
    else:
        return f"{address:x}  <{function_symbol.name}>"


@crash_command(
    description="list kernel timers",
    arguments=(
        argument(
            "-r",
            dest="hrtimer",
            action="store_true",
            help="display high-resolution timers (hrtimers)",
        ),
        argument(
            "-C",
            dest="cpu",
            default="all",
            help="restrict the output to one or more CPUs, "
            "which may be a comma-separated string of CPU numbers or ranges "
            "(e.g., '0,3-4')",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_timer(
    prog: Program,
    name: str,
    args: argparse.Namespace,
    **kwargs: Any,
) -> None:
    cpuspec = parse_cpuspec(args.cpu)

    if args.hrtimer:
        if args.drgn:
            code = CrashDrgnCodeBuilder(prog)
            code.add_from_import("drgn.helpers.linux.percpu", "per_cpu")
            code.add_from_import(
                "drgn.helpers.linux.timer", "hrtimer_clock_base_for_each"
            )
            code.add_from_import(
                "drgn.helpers.linux.timekeeping", "ktime_get_coarse_ns", "ktime_to_ns"
            )
            code.append("now = ktime_get_coarse_ns()\n\n")
            with code.begin_cpuspec_loop(cpuspec), code.begin_block(
                """\
cpu_base = per_cpu(prog["hrtimer_bases"], cpu)

for clock_base in cpu_base.clock_base:
"""
            ):
                code.append(
                    """\
clock = clock_base.index
current = now + ktime_to_ns(clock_base.offset)

"""
                )
                with code.begin_retry_loop_if_live(1000):
                    code.append(
                        """\
for hrtimer in hrtimer_clock_base_for_each(clock_base.address_of_()):
    softexpires = ktime_to_ns(hrtimer._softexpires)
    expires = ktime_to_ns(hrtimer.node.expires)
    tte = expires - current
    function = hrtimer.function
"""
                    )
            return code.print()

        hrtimer_bases = prog["hrtimer_bases"]
        now = ktime_get_coarse_ns(prog)
        first_cpu = True
        for cpu in cpuspec.cpus(prog):
            if first_cpu:
                first_cpu = False
            else:
                print()
            cpu_base = per_cpu(hrtimer_bases, cpu)
            print(f"CPU: {cpu}  HRTIMER_CPU_BASE: {cpu_base.address_:x}")

            first_clock_base = True
            for clock_base in cpu_base.clock_base:
                if first_clock_base:
                    first_clock_base = False
                else:
                    print()

                index = clock_base.index.read_()
                # Crash shows the name of the hrtimer_clock_base::get_time
                # function, but that was removed in Linux kernel commit
                # 009eb5da29a9 ("hrtimer: Remove hrtimer_clock_base::
                # Get_time") (in v6.18), so we omit it.
                print(
                    f"  CLOCK: {index.value_()}  HRTIMER_CLOCK_BASE: {clock_base.address_:x}"
                )

                current = (now + ktime_to_ns(clock_base.offset)).value_()
                rows: List[Sequence[Any]] = [
                    (
                        "",
                        CellFormat("CURRENT", "^"),
                    ),
                    ("", current),
                    (
                        "",
                        CellFormat("SOFTEXPIRES", "^"),
                        CellFormat("EXPIRES", "^"),
                        CellFormat("TTE", "^"),
                        CellFormat("HRTIMER", "^"),
                        "FUNCTION",
                    ),
                ]
                # Walking the hrtimer queue is racy. Retry a limited number of
                # times on live kernels.
                for _ in range(1000 if (prog.flags & ProgramFlags.IS_LIVE) else 1):
                    try:
                        for hrtimer in hrtimer_clock_base_for_each(clock_base):
                            expires = ktime_to_ns(hrtimer.node.expires).value_()
                            rows.append(
                                (
                                    "",
                                    ktime_to_ns(hrtimer._softexpires).value_(),
                                    expires,
                                    expires - current,
                                    CellFormat(hrtimer.value_(), "^x"),
                                    _function_cell(hrtimer.function),
                                ),
                            )
                        break
                    except FaultError:
                        del rows[3:]
                else:
                    print("  (corrupted)")
                    continue
                if len(rows) > 3:
                    # We print each base separately instead of as one big table
                    # because the timestamp values can differ greatly between
                    # bases and make the formatting look funny if they're all
                    # aligned to the largest one.
                    print_table(rows)
                else:
                    print("  (empty)")
    else:
        if args.drgn:
            code = CrashDrgnCodeBuilder(prog)
            code.append('jiffies = prog["jiffies"]\n\n')
            code.add_from_import("drgn.helpers.linux.percpu", "per_cpu")
            code.add_from_import(
                "drgn.helpers.linux.timer", "timer_base_for_each", "timer_base_names"
            )
            with code.begin_cpuspec_loop(cpuspec), code.begin_block(
                'for name, base in zip(timer_base_names(), per_cpu(prog["timer_bases"], cpu)):\n'
            ), code.begin_retry_loop_if_live(1000):
                code.append(
                    """\
for timer in timer_base_for_each(base):
    expires = timer.expires
    tte = expires - jiffies
    function = timer.function
"""
                )
            return code.print()

        jiffies = prog["jiffies"].value_()
        print(f"JIFFIES\n{jiffies}")

        rows = []
        timer_bases = prog["timer_bases"]
        for cpu in cpuspec.cpus(prog):
            rows.append(())
            for name, base in zip(timer_base_names(prog), per_cpu(timer_bases, cpu)):
                rows.append(
                    RowOptions(
                        (f"TIMER_BASES[{cpu}][{name}]: {base.address_:x}",),
                        group=1,
                    ),
                )

                rows.append(
                    (
                        "",
                        "EXPIRES",
                        CellFormat("TTE", ">"),
                        CellFormat("TIMER_LIST", "^"),
                        "FUNCTION",
                    ),
                )
                timer_rows = []
                # Walking the timer lists is racy. Retry a limited number of
                # times on live kernels.
                for _ in range(1000 if (prog.flags & ProgramFlags.IS_LIVE) else 1):
                    try:
                        for timer in timer_base_for_each(base):
                            expires = timer.expires.value_()
                            timer_rows.append(
                                (
                                    "",
                                    CellFormat(expires, "<"),
                                    expires - jiffies,
                                    CellFormat(timer.value_(), "^x"),
                                    _function_cell(timer.function),
                                )
                            )
                        break
                    except FaultError:
                        timer_rows.clear()
                else:
                    rows.append(("", "(corrupted)"))
                    continue
                if timer_rows:
                    rows.extend(timer_rows)
                else:
                    rows.append(("", "(none)"))
        print_table(rows)
