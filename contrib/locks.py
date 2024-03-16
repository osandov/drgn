#!/usr/bin/env drgn
# Copyright (c) 2024, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

""" Script to dump lock information"""

import sys
from argparse import ArgumentParser
from drgn import Object
from drgn.helpers.linux.locks import mutex_is_locked
from drgn.helpers.linux.locks import mutex_owner
from drgn.helpers.linux.locks import mutex_for_each_waiter_task

###############################################
# mutex
###############################################
def dump_mutex_waiters_call_stack(mutex: Object) -> None:
    """
    Dump call stacks for all tasks blocked on a mutex.

    :param lock: ``struct mutex *``
    """
    prog = mutex.prog_
    print(f"Dumping call stack for waiter of mutex: {mutex.value_():x}")
    for task in mutex_for_each_waiter_task(mutex):
        trace = prog.stack_trace(task.pid.value_())
        print(f"\ncall stack for pid: {task.pid.value_()}")
        print(trace)
        print("\n")


def dump_mutex_owner_call_stack(mutex: Object) -> None:
    """
    Dump call stack of mutex owner.

    :param lock: ``struct mutex *``
    """
    prog = mutex.prog_
    if mutex_is_locked(mutex):
        owner = mutex_owner(mutex)
        print(f"Dumping call stack for owner of mutex: {mutex.value_():x}")
        trace = prog.stack_trace(owner.pid.value_())
        print(f"\ncall stack for pid: {owner.pid.value_()}")
        print(trace)
        print("\n")


def parse_cmdline_args(args):
    parser = ArgumentParser()
    parser.add_argument("lock_type", type=str, help="type of lock i.e mutex. semaphore, rwsemaphore etc.")
    parser.add_argument("info_type", type=str, help="\"owner\" or \"waiter\" or \"all\"")
    parser.add_argument("locks", nargs="*", default=None, help="list of lock addresses")
    args = parser.parse_args()
    return args

def main():
    cmd_opts = parse_cmdline_args(sys.argv[1:])
    lock_type = cmd_opts.lock_type
    info_type = cmd_opts.info_type
    if isinstance(cmd_opts.locks, list):
        locks = cmd_opts.locks

    if lock_type == "semaphore" and info_type == "owner":
        print ("Owner info not available for semaphores.")

    if lock_type == "mutex":
        for lock_addr in locks:
            lock = Object(prog, "struct mutex", address=int(lock_addr, 16))
            if (info_type == "all" or info_type == "waiter"):
                dump_mutex_waiters_call_stack(lock.address_of_())
            if (info_type == "all" or info_type == "owner"):
                dump_mutex_owner_call_stack(lock.address_of_())
    else:
        print(f"No information available for {lock_type}.") 


if __name__ == "__main__":
    main()
