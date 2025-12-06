# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Implements the crash "log" command for drgn."""

import argparse
from typing import Any

from drgn import Program
from drgn import Object
from drgn import PlatformFlags

from drgn.commands import CommandArgumentError, argument, drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command

from drgn import Program
from drgn.helpers.linux.printk import print_dmesg

def crash_time_stamp(prog: Program) -> None:
    print_dmesg(timestamps="human")

def crash_monotonic_time_stamp(prog: Program) -> None:
    print_dmesg()

def crash_no_time_stamp(prog: Program) -> None:
    print_dmesg(timestamps=False)

@crash_command(
    description="Dump kernel dmesg",
    arguments=(
        argument(
            "-T",
            dest="time_stamp",
	    action="store_true",
            help="Dump kernel dmesg in human readable time",
        ),
        argument(
            "-t",
            dest="no_time_stamp",
            action="store_true",
            help="Dump kernel dmesg without timestamp",
        ),
        drgn_argument,
    ),
)

def _crash_cmd_log(
       prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
       if args.time_stamp:
           crash_time_stamp(prog)
       if args.no_time_stamp:
           crash_no_time_stamp(prog)
       else:
           crash_monotonic_time_stamp(prog)
