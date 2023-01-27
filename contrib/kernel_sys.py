#!/usr/bin/env drgn
# Copyright (c) SUSE Linux.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Display system information and configuration data."""

from datetime import datetime
from datetime import timedelta

from drgn.helpers.common.format import number_in_binary_units
from drgn.helpers.linux import for_each_online_cpu
from drgn.helpers.linux.mm import totalram_pages
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import loadavg


def print_line(key, value):
    print(f"{key:<16} {value}")


uts = prog["init_uts_ns"].name

timekeeper = prog["shadow_timekeeper"]
date = datetime.fromtimestamp(timekeeper.xtime_sec).strftime("%c")
uptime = timedelta(seconds=timekeeper.ktime_sec.value_())
load = ", ".join([f"{v:.2f}" for v in loadavg(prog)])
totalram = (prog['PAGE_SIZE'] * totalram_pages(prog)).value_()


print_line("CPUS", len(list(for_each_online_cpu(prog))))
print_line("DATE", date)
print_line("UPTIME", uptime)
print_line("LOAD AVERAGE", load)
print_line("TASKS", len(list(for_each_task(prog))))
print_line("NODENAME", uts.nodename.string_().decode())
print_line("RELEASE", uts.release.string_().decode())
print_line("VERSION", uts.version.string_().decode())
print_line("MACHINE", uts.machine.string_().decode())
print_line("MEMORY", number_in_binary_units(totalram))
