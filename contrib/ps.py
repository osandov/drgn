#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""An implementation of ps(1) using drgn"""

import sys
from argparse import ArgumentParser
from collections import OrderedDict

from drgn import ProgramFlags
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry, list_count_nodes
from drgn.helpers.linux.mm import cmdline, totalram_pages
from drgn.helpers.linux.percpu import per_cpu, percpu_counter_sum
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import task_cpu, task_state_to_char

PAGE_SIZE = prog["PAGE_SIZE"].value_()


def get_number_of_children(task):
    """
    Returns number of children of a given task
    """
    return list_count_nodes(task.children.address_of_())


def get_cmd(task):
    """
    Return the commandline arguments of a given task
    """
    return b" ".join(cmdline(task)).decode()


def parse_cmdline_args(args):
    """
    Command line argument parser
    """
    parser = ArgumentParser(prog="drgn ps",
                            description="Report process status infromation")
    group = parser.add_mutually_exclusive_group()

    group.add_argument("-a", "--active", action="store_true", default=False,
                        help="Print active thread on each CPU "
                        "(data may be inconsistent for live kernel)")

    group.add_argument("-c", "--children", nargs="*", default=None, type=int,
                        help="Print data about children of the given process(es)")

    group.add_argument("--cpus", nargs="*", default=None, type=int,
                        help="Ready/running processes for given CPUs")

    parser.add_argument("-d", "--detailed", action="store_true", default=False,
                        help="Print additional details about the threads")

    group.add_argument("--hierarchy", metavar="PID", nargs="+", default=None,
                        help="Print parent hierarchy")

    group.add_argument("-k", "--kthread", action='store_true', default=False,
                        help="Print kernel threads only")

    group.add_argument("-t", "--threads", nargs="+", default=None, type=int,
                        help="Print detailed information of a given threads")

    group.add_argument("-u", "--uthread", action="store_true", default=False,
                        help="Print userspace threads only")

    cmd_opts = parser.parse_args(args)

    return cmd_opts


def get_rss(task):
    """
    Returns the Resident Set Size
    """
    try:
        return PAGE_SIZE * sum([percpu_counter_sum(x) for x in task.mm.rss_stat])
    except (AttributeError, TypeError):
        return PAGE_SIZE * sum([x.counter for x in task.mm.rss_stat.count])


def print_active_tasks(cmd_opts):
    """
    Function to print active task on each CPU
    """
    if prog.flags & ProgramFlags.IS_LIVE:
        print("Running on live kernel - The data may be inconsistent\n")

    runqueues = prog["runqueues"]

    print_hdr = True
    for cpu in for_each_online_cpu(prog):
        task = per_cpu(runqueues, cpu).curr
        print_std(task, print_hdr, cmd_opts)
        print_hdr = False


def print_cpu_tasks(cmd_opts):
    """
    Print running and runnable tasks on a given CPU
    """
    for cpu in for_each_online_cpu(prog):
        if cmd_opts.cpus:
            if cpu not in cmd_opts.cpus:
                continue
        print_hdr = True
        for task in for_each_task(prog):
            if task_cpu(task) == cpu:
                print_std(task, print_hdr, cmd_opts)
                print_hdr = False


def hierarchy(cmd_opts):
    """
    Print information of all parent processes
    """
    pids = cmd_opts.hierarchy
    tasks = []
    for task in for_each_task(prog):
        if str(task.pid.value_()) not in pids:
            continue

        pid = task.pid.value_()
        pids.remove(str(pid))
        while (pid > 1):
            pid = task.pid.value_()
            tasks.append(task)
            task = task.parent

        print_hdr = True
        while len(tasks) != 0:
            print_std(tasks.pop(), print_hdr, cmd_opts)
            print_hdr = False

        print("\n")

    if len(pids) != 0:
        print("the following pids are invalid: {0}".format(pids))


def thread_details(cmd_opts):
    """
    Prints details of all the threads including kernel and userspace both.
    """
    print_hdr = True
    for task in for_each_task(prog):
        if cmd_opts.threads:
            if task.pid.value_() in cmd_opts.threads:
                cmd_opts.kthread = 0
                cmd_opts.uthread = 0
            else:
                continue
        if cmd_opts.kthread:
            if task.mm:
                continue
        elif cmd_opts.uthread:
            if not task.mm:
                continue
        print_std(task, print_hdr, cmd_opts)
        print_hdr = False


def process_child_task(cmd_opts):
    """
    Print all child tasks of the given parent tasks
    """
    for task in for_each_task(prog):
        if cmd_opts.children:
            if task.pid not in cmd_opts.children:
                continue

        print("Parent Task:")
        print_hdr = True
        print_std(task, print_hdr, cmd_opts)
        print("Child Tasks:")
        head = task.children.address_of_()

        for c_task in list_for_each_entry("struct task_struct", head, "sibling"):
            print_std(c_task, print_hdr, cmd_opts)
            print_hdr = False

        # No child found
        if print_hdr:
            print("NA")
        print("\n")


def get_task_memory_info(task):
    """
    Return RSS (Resident Set Size) memory and VMS (Virtual Memory Size)
    for a given task. Return None if the task is a kernel thread.
    """
    if not task.mm:
        return None

    vms = PAGE_SIZE * task.mm.total_vm.value_()

    # Since Linux kernel commit f1a7941243c102a44e ("mm: convert mm's rss
    # stats into percpu_counter") (in v6.2), rss_stat is percpu counter.
    try:
        rss = PAGE_SIZE * sum([percpu_counter_sum(x) for x in task.mm.rss_stat])
    except (AttributeError, TypeError):
        rss = PAGE_SIZE * sum([x.counter for x in task.mm.rss_stat.count])

    return (vms, rss)


"""
The headers_and_vals dictionary's entries follow:
    key: (val, <print-spacing>)
"""
headers_and_vals = OrderedDict([
    ("PID", (lambda task: task.pid.value_(), 7)),
    ("PPID", (lambda task: task.parent.pid.value_(), 7)),
    ("CPU", (task_cpu, 4)),
    ("Task Address", (hex, 19)),
    ("Stack Address", (lambda task: hex(task.stack.value_()), 19)),
    ("State", (task_state_to_char, 4)),
    ("VMS", (lambda task: PAGE_SIZE * task.mm.total_vm.value_(), 10)),
    ("RSS", (get_rss, 10)),
    ("MEM%", (lambda task: (round(((get_rss(task) * 100) /
                           (PAGE_SIZE * totalram_pages(prog))), 4)), 8)),
    ("comm", (lambda task: task.comm.string_().decode(), 9))
])


"""
No need to worry about specific spacing here
"""
headers_and_vals_detailed = OrderedDict([
    ("Execution Time (sec)", lambda task: (task.utime + task.stime).value_()/1e9),
    ("mm_struct addr", lambda task: hex(task.mm.value_())),
    ("cmdline", get_cmd),
    ("Number of children", get_number_of_children),
    ("Stack Trace", lambda task: '\n' + str(prog.stack_trace(task)))
])


def print_std(task, need_hdr, cmd_opts):
    """
    The print function is responsible for generating reports
    """
    data_points = []
    detailed = cmd_opts.detailed
    if detailed:
        need_hdr = True

    for header in headers_and_vals.keys():
        try:
            data = (headers_and_vals[header])[0](task)
            data_points.append(data)
        except Exception:
            data_points.append('NA')

    # Print the headers
    header_line = ""
    if need_hdr:
        for header in headers_and_vals.keys():
            width = headers_and_vals[header][1]
            header_line += ''.join(format(str(header), f"<{width+2}"))

        print(header_line)
        print("-" * len(header_line))

    # Print the data rows
    formatted_row = ""
    index = 0
    for header in headers_and_vals.keys():
        width = headers_and_vals[header][1]
        formatted_row += ''.join(format(str(data_points[index]), f"<{width+2}"))
        index += 1

    print(formatted_row + "\n")

    if detailed:
        for header in headers_and_vals_detailed.keys():
            try:
                data = headers_and_vals_detailed[header](task)
            except Exception:
                data = 'NA'

            print(header, ":", data)


def main():
    cmd_opts = parse_cmdline_args(sys.argv[1:])

    if cmd_opts.active:
        print_active_tasks(cmd_opts)
    elif isinstance(cmd_opts.children, list):
        process_child_task(cmd_opts)
    elif isinstance(cmd_opts.cpus, list):
        print_cpu_tasks(cmd_opts)
    elif cmd_opts.hierarchy:
        hierarchy(cmd_opts)
    else:
        thread_details(cmd_opts)


if __name__ == "__main__":
    main()
