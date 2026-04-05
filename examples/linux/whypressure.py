# (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""Sample and analyze PSI states of a cgroup sub-hierarchy"""

import argparse
import os
import re
import signal
import sys
import time
from contextlib import contextmanager

from drgn import cast, container_of
from drgn.helpers.linux import (
    css_for_each_descendant_pre,
    fget,
    find_task,
    list_for_each_entry,
)

DESCRIPTION = r"""
Sample and analyze PSI states of a cgroup sub-hierarchy.

PSI is resource pressure metric reported through
/sys/fs/cgroup/*/{memory,io,cpu}.pressure measured by tracking member task
state in the subhierarchy - ie. if all member tasks in the cgroup
subhierarchy are stalled due to lack of memory, they contribute to the
memory full pressure. For more details on PSI:

  https://facebookmicrosites.github.io/psi/docs/overview

It can sometimes be challenging to undersatnd what's contributing to
specific pressures - e.g. why a given cgroup is reporting really high memory
some pressure while low full pressure while seemingly not making much
progress. This drgn script polls the kernel states to track PSI accounting
to provide more insights into which backtraces and PSI states are
contributing to specific pressures.

Here is an example run:

  # drgn whypressure.py /sys/fs/cgroup/workload.slice
  mem:  51.71/ 92.22 io:   7.45/ 85.17 cpu:  86.30
  mem:  50.73/ 91.55 io:   5.95/ 85.73 cpu:  89.17
  ...
  finishing...
  ...
  [000]  43.9% MEM SOME RUNNING psi=_MR_ count=2479
    shrink_inactive_list+0x199/0x420
    ...

  [001]  15.1% MEM SOME RUNNING psi=_MR_ count=853
    shrink_node+0x14d/0x690
    ...
  
By default, whypressure.py samples data every 50ms for 10s. While data is
being collected, it periodically prints out pressure estimates. These are
rough estimates made from coarse polling and may not match actual pressure
metrics.

Once data collection is complete, it prints out contributors to each
pressure metric - MEM FULL, MEM SOME, IO FULL, IO SOME, and CPU SOME -
ordered first by whether BLOCKING or RUNNING and then the proportion of
contribution. Note that SOME is always superset of FULL. However,
whypressure.py excludes tasks which contribute to FULL from SOME sections so
that it's easier to tell the difference.

In the above, example, we're trying to explain the difference between MEM
FULL and SOME, so we want to look at MEM SOME RUNNING which is what
differntiates SOME from FULL. Let's take a look at the header of the top
entry.

  [000]  43.9% MEM SOME RUNNING psi=_MR_ count=2479
    ^      ^   ----------------   ^           ^
    |      |          |           |           \- Raw count of this entry
    |      |          |            \- PSI state of the contributing tasks
    |      |          \-Pressure and contribution type
    |      \- Contribution %
     \- Rank ordered by contribution % 

It's saying that tasks with this backtrace and PSI states comprise 43.9% of
all sampled tasks which contributed to turning what could otherwise be MEM
FULL state into MEM SOME.

PSI states are represented by four characters - IMRO - mapping to
TSK_IOWAIT, TSK_MEMSTALL, TSK_RUNNING and TSK_ONCPU kernel PSI flags
respectively. In the above _MR_ indicates that the tasks were in memory
stall (MEMSTALL) but not IO wait (!IOWAIT), and was ready to run (RUNNING)
but is still waiting on the runqueue (!ONCPU)

This turned out to be a shortcoming in kernel implementation where MEM FULL
states were being downgraded to MEM SOME on the account of ready-to-run
tasks waiting for CPUs to become available while the CPUs are dominated by
memory reclaiming tasks.
"""

NR_CPU_IDS = prog["nr_cpu_ids"].value_()

NR_IOWAIT = prog["NR_IOWAIT"].value_()
NR_MEMSTALL = prog["NR_MEMSTALL"].value_()
NR_RUNNING = prog["NR_RUNNING"].value_()
NR_ONCPU = prog["NR_ONCPU"].value_()

PSI_TASK_COUNTS = [NR_IOWAIT, NR_MEMSTALL, NR_RUNNING, NR_ONCPU]
NR_PSI_TASK_COUNTS = max(PSI_TASK_COUNTS) + 1

TSK_IOWAIT = 1 << NR_IOWAIT
TSK_MEMSTALL = 1 << NR_MEMSTALL
TSK_RUNNING = 1 << NR_RUNNING
TSK_ONCPU = 1 << NR_ONCPU

PSI_FLAGS = [TSK_IOWAIT, TSK_MEMSTALL, TSK_RUNNING, TSK_ONCPU]

PSI_IO_SOME = prog["PSI_IO_SOME"].value_()
PSI_IO_FULL = prog["PSI_IO_FULL"].value_()
PSI_MEM_SOME = prog["PSI_MEM_SOME"].value_()
PSI_MEM_FULL = prog["PSI_MEM_FULL"].value_()
PSI_CPU_SOME = prog["PSI_CPU_SOME"].value_()
PSI_NONIDLE = prog["PSI_NONIDLE"].value_()
NR_PSI_STATES = prog["NR_PSI_STATES"].value_()

VERBOSITY = 0
NATIVE_BACKTRACER = False
EXIT_REQ = False

BACKTRACES_LOOKUP = {}
BACKTRACES = {}
NR_BACKTRACES = 0


def dbg(s):
    global VERBOSITY
    if VERBOSITY:
        print(f"DBG: {s}", flush=True)


@contextmanager
def open_dir(*args, **kwds):
    # Built-in open() context manager can't deal with directories.
    fd = os.open(*args, **kwds)
    try:
        yield fd
    finally:
        os.close(fd)


def get_cgroup(cgrp):
    task = find_task(prog, os.getpid())
    with open_dir(cgrp, os.O_RDONLY) as fd:
        file_ = fget(task, fd)
        kn = cast("struct kernfs_node *", file_.f_path.dentry.d_inode.i_private)
        return cast("struct cgroup *", kn.priv)


def cgroup_for_each_descendant_task(top):
    for pos in css_for_each_descendant_pre(top.self.address_of_()):
        cgrp = container_of(pos, "struct cgroup", "self")
        for link in list_for_each_entry(
            "struct cgrp_cset_link", cgrp.cset_links.address_of_(), "cset_link"
        ):
            for task in list_for_each_entry(
                "struct task_struct", link.cset.tasks.address_of_(), "cg_list"
            ):
                yield task


# futex_wait_queue_me+0xb7/0x121
def get_backtrace_native(task):
    try:
        bt = ""
        for trace in prog.stack_trace(task.pid):
            sym = trace.symbol()
            bt += f"{sym.name}+{hex(trace.pc - sym.address)}/{hex(sym.size)}\n"
        return bt
    except Exception:
        return "<UNKNOWN>"


def get_backtrace_proc(task):
    try:
        pid = task.pid.value_()
        bt = ""
        with open(f"/proc/{pid}/stack", "r") as f:
            for line in f:
                bt += re.sub(r"^\S*\s*(.*)$", r"\1", line)
        if len(bt) > 0:
            return bt
        else:
            return "<UNKNOWN>"
    except Exception:
        return "<FAILED>"


def get_backtrace(task):
    global NATIVE_BACKTRACER

    if NATIVE_BACKTRACER:
        return get_backtrace_native(task)
    else:
        return get_backtrace_proc(task)


class TaskDesc:
    """
    The information that we care about about a contributing task. Currently,
    only the backtrace and PSI flags.
    """

    def __init__(self, task):
        global BACKTRACES_LOOKUP, BACKTRACES, NR_BACKTRACES

        bt = get_backtrace(task)
        bt_id = BACKTRACES.get(bt)
        if bt_id is None:
            bt_id = NR_BACKTRACES
            NR_BACKTRACES += 1
            BACKTRACES[bt] = bt_id
            BACKTRACES_LOOKUP[bt_id] = bt

        self.bt_id = bt_id
        self.psi_flags = task.psi_flags.value_()

    def __hash__(self):
        return hash((self.bt_id, self.psi_flags))

    def __eq__(self, other):
        return self.bt_id == other.bt_id and self.psi_flags == other.psi_flags


def collect_psi_task_descs(top):
    """
    Returns three dimensional array encoding "these are the tasks contributing
    to this PSI counter on this CPU".

    [ CPU0: [ NR_IOWAIT   : [ TASK_DESC0, TASK_DESC1 ]
              NR_MEMSTALL : [ TASK_DESC0 ]
              ...
              ]
      CPU1: [ NR_IOWAIT   : [ TASK_DESC0, TASK_DESC1, TASK_DESC2 ]
              NR_MEMSTALL : [ TASK_DESC0, TASK_DESC1 ]
              ...
            ]
      ...
    ]
    """
    cpu_tasks = []
    for i in range(NR_CPU_IDS):
        cpu_tasks.append([])
        for _j in range(NR_PSI_TASK_COUNTS):
            cpu_tasks[i].append([])

    try:
        for task in cgroup_for_each_descendant_task(top):
            dbg(
                f"{task.pid.value_()} {task.comm.string_().decode()} {hex(task.psi_flags)}"
            )
            if task.psi_flags.value_() == 0:
                continue
            td = TaskDesc(task)
            psi_flags = task.psi_flags.value_()
            for state in PSI_TASK_COUNTS:
                if psi_flags & (1 << state):
                    cpu = task.cpu.value_()
                    if cpu < NR_CPU_IDS:
                        cpu_tasks[cpu][state].append(td)
    except Exception:
        pass
    return cpu_tasks


def psi_states(cpu_psi_tds):
    """
    Given a CPU's PSI TaskDesc table, determine what PSI states the CPU is in

    Returns an array of NR_PSI_STATES booleans indicating whether the
    matching PSI state is on or off on the cpu.
    """
    states = [False] * NR_PSI_STATES

    # See kernel/sched/psi.c::test_state()
    states[PSI_IO_SOME] = len(cpu_psi_tds[NR_IOWAIT]) > 0
    states[PSI_IO_FULL] = (
        len(cpu_psi_tds[NR_IOWAIT]) > 0 and len(cpu_psi_tds[NR_RUNNING]) == 0
    )
    states[PSI_MEM_SOME] = len(cpu_psi_tds[NR_MEMSTALL]) > 0
    states[PSI_MEM_FULL] = (
        len(cpu_psi_tds[NR_MEMSTALL]) > 0 and len(cpu_psi_tds[NR_RUNNING]) == 0
    )
    states[PSI_CPU_SOME] = len(cpu_psi_tds[NR_RUNNING]) > len(cpu_psi_tds[NR_ONCPU])
    states[PSI_NONIDLE] = (
        len(cpu_psi_tds[NR_IOWAIT]) > 0
        or len(cpu_psi_tds[NR_MEMSTALL]) > 0
        or len(cpu_psi_tds[NR_RUNNING]) > 0
    )

    # See kernel/sched/stats.h::psi_task_tick()
    if states[PSI_MEM_SOME] and not states[PSI_MEM_FULL]:
        for td in cpu_psi_tds[NR_ONCPU]:
            if td.psi_flags & TSK_MEMSTALL:
                states[PSI_MEM_FULL] = True
                break

    return states


def format_psi_flags(psi_flags):
    mapping = (
        (TSK_IOWAIT, "I"),
        (TSK_MEMSTALL, "M"),
        (TSK_RUNNING, "R"),
        (TSK_ONCPU, "O"),
    )
    buf = ""
    for flag, rep in mapping:
        if psi_flags & flag:
            buf += rep
        else:
            buf += "_"
    return buf


class TaskDescAcc:
    """
    Accumulate TaskDesc's according to what PSI state they're contributing to.
    self.acc has the following layout:

    [ PSI_IO_FULL: [ { BLOCKING_TDs }, { RUNNING_TDs } ],
      PSI_IO_SOME...
    ]
    """

    def __init__(self):
        self.acc = []
        for _i in range(NR_PSI_STATES):
            self.acc.append([{}, {}])
        self.nr_samples = [[0, 0] for i in range(NR_PSI_STATES)]

    def count(self, state, is_running, tds, exclude_psi_flags):
        acc = self.acc[state][is_running]
        for td in tds:
            if not (td.psi_flags & exclude_psi_flags):
                self.nr_samples[state][is_running] += 1
                if td in acc:
                    acc[td] += 1
                else:
                    acc[td] = 1

    def deposit(self, states, cpu_psi_tds):
        """
        TaskDesc's in @cpu_psi_tds are contrubing to the PSI states in
        @states. Keep counts of each TD in the contribution category.
        """
        # RUNNING is superset of ONCPU. Exclude ONCPU when counting RUNNING
        # to avoid double counting running tasks. We do this instead of
        # counting all RUNNING and ignoring ONCPU to transparently reflect
        # kernel states.
        #
        # SOME is superset of FULL but we want to track the tasks that
        # differentiates the two states, so the elif's.
        if states[PSI_IO_FULL]:
            self.count(PSI_IO_FULL, 0, cpu_psi_tds[NR_IOWAIT], 0)
            self.count(PSI_IO_FULL, 1, cpu_psi_tds[NR_RUNNING], TSK_IOWAIT | TSK_ONCPU)
            self.count(PSI_IO_FULL, 1, cpu_psi_tds[NR_ONCPU], TSK_IOWAIT)
        elif states[PSI_IO_SOME]:
            self.count(PSI_IO_SOME, 0, cpu_psi_tds[NR_IOWAIT], 0)
            self.count(PSI_IO_SOME, 1, cpu_psi_tds[NR_RUNNING], TSK_IOWAIT | TSK_ONCPU)
            self.count(PSI_IO_SOME, 1, cpu_psi_tds[NR_ONCPU], TSK_IOWAIT)

        if states[PSI_MEM_FULL]:
            self.count(PSI_MEM_FULL, 0, cpu_psi_tds[NR_MEMSTALL], 0)
            self.count(
                PSI_MEM_FULL, 1, cpu_psi_tds[NR_RUNNING], TSK_MEMSTALL | TSK_ONCPU
            )
            self.count(PSI_MEM_FULL, 1, cpu_psi_tds[NR_ONCPU], TSK_MEMSTALL)
        elif states[PSI_MEM_SOME]:
            self.count(PSI_MEM_SOME, 0, cpu_psi_tds[NR_MEMSTALL], 0)
            self.count(
                PSI_MEM_SOME, 1, cpu_psi_tds[NR_RUNNING], TSK_MEMSTALL | TSK_ONCPU
            )
            self.count(PSI_MEM_SOME, 1, cpu_psi_tds[NR_ONCPU], TSK_MEMSTALL)

        if states[PSI_CPU_SOME]:
            # RUNNING is considered blocking for CPU unlike for MEM and IO.
            self.count(PSI_CPU_SOME, 0, cpu_psi_tds[NR_RUNNING], TSK_ONCPU)
            self.count(PSI_CPU_SOME, 1, cpu_psi_tds[NR_ONCPU], 0)

    def print_one_header(self, seq, prefix, psi_flags, cnt, nr_samples):
        print(
            f"[{seq:03}] {cnt / nr_samples * 100:5.1f}% {prefix} "
            f"psi={format_psi_flags(psi_flags)} count={cnt}"
        )

    def print_one(self, seq, prefix, td, cnt, nr_samples):
        global BACKTRACES_LOOKUP

        self.print_one_header(seq, prefix, td.psi_flags, cnt, nr_samples)
        for line in BACKTRACES_LOOKUP[td.bt_id].splitlines():
            print(f"  {line}")

    def report_tds(self, prefix, state, is_running):
        leftovers = []
        for i in range(1 << NR_PSI_TASK_COUNTS):
            leftovers.append([i, 0])

        nr_samples = self.nr_samples[state][is_running]
        tds = self.acc[state][is_running]
        seq = 0
        for td, cnt in sorted(tds.items(), key=lambda pair: pair[1], reverse=True):
            frac = cnt / nr_samples
            if frac >= self.cutoff / 100:
                self.print_one(seq, prefix, td, cnt, nr_samples)
                seq += 1
                print()
            else:
                # Below cutoff, report only by psi_flags ignoring backtrace
                leftovers[td.psi_flags][1] += cnt

        for psi_flags, cnt in sorted(leftovers, key=lambda pair: pair[1], reverse=True):
            if cnt == 0:
                break
            self.print_one_header(seq, prefix, psi_flags, cnt, nr_samples)
            seq += 1

        if seq > 0:
            print()

    def report(self, cutoff):
        self.cutoff = cutoff
        self.report_tds("MEM FULL BLOCKING", PSI_MEM_FULL, 0)
        self.report_tds("MEM FULL RUNNING", PSI_MEM_FULL, 1)

        self.report_tds("MEM SOME BLOCKING", PSI_MEM_SOME, 0)
        self.report_tds("MEM SOME RUNNING", PSI_MEM_SOME, 1)

        self.report_tds("IO FULL BLOCKING", PSI_IO_FULL, 0)
        self.report_tds("IO FULL RUNNING", PSI_IO_FULL, 1)

        self.report_tds("IO SOME BLOCKING", PSI_IO_SOME, 0)
        self.report_tds("IO SOME RUNNING", PSI_IO_SOME, 1)

        self.report_tds("CPU SOME BLOCKING", PSI_CPU_SOME, 0)


def sig_handler(signr, frame):
    print("SIGINT received, ", end="", file=sys.stderr)
    global EXIT_REQ
    EXIT_REQ = True


def main():
    global VERBOSITY, NATIVE_BACKTRACER, EXIT_REQ

    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("cgroup", metavar="PATH", type=str, help="target cgroup")
    parser.add_argument(
        "-d",
        "--dur",
        metavar="DUR",
        type=float,
        default=10,
        help="collection duration (default=%(default)s)",
    )
    parser.add_argument(
        "-c",
        "--cutoff",
        metavar="PCT",
        type=float,
        default=5,
        help="ignore backtrace below this threshold (default=%(default)s)",
    )
    parser.add_argument(
        "-p",
        "--poll-intv",
        metavar="INTV",
        type=float,
        default=0.05,
        help="polling interval (default=%(default)s)",
    )
    parser.add_argument(
        "-n",
        "--native-backtracer",
        action="store_true",
        help="use drgn's backtracer instead of reading /proc/PID/stack,\n"
        "faster under pressure but may lead to more UNKNOWNs",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        help="increase output verbosity",
    )

    args = parser.parse_args()
    VERBOSITY = args.verbose
    NATIVE_BACKTRACER = args.native_backtracer

    end_by = time.time() + args.dur
    signal.signal(signal.SIGINT, sig_handler)

    top = get_cgroup(args.cgroup)

    td_acc = TaskDescAcc()
    next_report_at = time.time() + 1
    states_avg_sum = [0] * NR_PSI_STATES
    nr_avgs = 0

    while time.time() < end_by and not EXIT_REQ:
        psi_tds = collect_psi_task_descs(top)
        dbg(psi_tds)

        states_sum = [0] * NR_PSI_STATES
        nr_active_cpus = 0
        for cpu_psi_tds in psi_tds:
            is_active = False
            states = psi_states(cpu_psi_tds)
            td_acc.deposit(states, cpu_psi_tds)
            for state in range(NR_PSI_STATES):
                if states[state]:
                    is_active = True
                    states_sum[state] += 1
            if is_active:
                nr_active_cpus += 1

        if nr_active_cpus > 0:
            # The number of CPUs in a PSI state over total number of CPUs
            # which weren't idle is (a rough estimate of) the pressure.
            for state in range(NR_PSI_STATES):
                states_avg_sum[state] += states_sum[state] / nr_active_cpus
            nr_avgs += 1

        now = time.time()
        if now >= next_report_at:
            while next_report_at < now:
                next_report_at += 1
            if nr_avgs > 0:
                print(
                    "mem: {:6.2f}/{:6.2f} io: {:6.2f}/{:6.2f} cpu: {:6.2f}".format(
                        states_avg_sum[PSI_MEM_FULL] / nr_avgs * 100.0,
                        states_avg_sum[PSI_MEM_SOME] / nr_avgs * 100.0,
                        states_avg_sum[PSI_IO_FULL] / nr_avgs * 100.0,
                        states_avg_sum[PSI_IO_SOME] / nr_avgs * 100.0,
                        states_avg_sum[PSI_CPU_SOME] / nr_avgs * 100.0,
                    ),
                    file=sys.stderr,
                )
            states_avg_sum = [0] * NR_PSI_STATES
            nr_avgs = 0

        time.sleep(args.poll_intv)

    print("finishing...", file=sys.stderr)
    td_acc.report(args.cutoff)


if __name__ == "__main__":
    main()
