# Copyright (c) 2022, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Workqueue
--------------

The ``drgn.helpers.linux.workqueue`` module provides helpers for working with the
Linux workqueues.
"""

from typing import Iterator, Optional, Union

from drgn import NULL, IntegerLike, Object, Program, cast
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.idr import idr_find, idr_for_each
from drgn.helpers.linux.list import (
    hlist_for_each_entry,
    list_empty,
    list_for_each_entry,
)
from drgn.helpers.linux.percpu import per_cpu, per_cpu_ptr
from drgn.helpers.linux.pid import find_task

__all__ = (
    "for_each_workqueue",
    "for_each_pool",
    "for_each_pending_work",
    "for_each_worker",
    "for_each_pool_worker",
    "for_each_pwq",
    "for_each_cpu_worker_pool",
    "for_each_pending_work_on_cpu",
    "for_each_pending_work_in_pool",
    "for_each_pending_work_of_pwq",
    "find_workqueue",
    "get_work_pwq",
    "get_work_pool",
    "print_workqueue_names",
    "show_pwq",
    "show_all_workqueues",
    "show_one_workqueue",
    "show_one_worker_pool",
    "is_task_a_worker",
    "find_worker_executing_work",
    "workqueue_get_pwq",
)


_PF_WQ_WORKER = 0x00000020


def _work_offq_pool_none(prog: Program) -> IntegerLike:
    # Linux kernel commit afa4bb778e48 ("workqueue: clean up WORK_* constant
    # types, clarify masking") (in v6.4) changed WORK_OFFQ_POOL_NONE from
    # constants of type enum to constants of type unsigned long.
    try:
        val = prog["WORK_OFFQ_POOL_NONE"].value_()
    except KeyError:
        val = (
            Object(prog, "unsigned long", 1).value_() << prog["WORK_OFFQ_POOL_BITS"]
        ) - 1
    return val


def _work_struct_wq_data_mask(prog: Program) -> IntegerLike:
    # Linux kernel commit afa4bb778e48 ("workqueue: clean up WORK_* constant
    # types, clarify masking") (in v6.4) changed WORK_STRUCT_WQ_DATA_MASK from
    # constants of type enum to constants of type unsigned long.
    try:
        val = prog["WORK_STRUCT_WQ_DATA_MASK"].value_()
    except KeyError:
        val = ~((Object(prog, "unsigned long", 1) << prog["WORK_STRUCT_FLAG_BITS"]) - 1)
    return val


def _print_work(work: Object) -> None:
    prog = work.prog_
    print(
        f"        ({work.type_.type_name()})0x{work.value_():x}: func: {prog.symbol(work.func.value_()).name}"
    )


def workqueue_get_pwq(workqueue: Object, cpu: int) -> Object:
    """
    Find pool_workqueue of a bound workqueue for a given CPU.

    :param workqueue: ``struct workqueue_struct *``
    :return: ``struct pool_workqueue *``.
    """
    # At first Linux kernel commit ee1ceef72754 ("workqueue: Rename wq->cpu_pwqs to
    # wq->cpu_pwq") (in v6.6) renamed cpu_pwqs to cpu_pwq and then Linux kernel commit
    # 687a9aa56f81("workqueue: Make per-cpu pool_workqueues allocated and released
    # like unbound ones") (in v6.6) changed cpu_pwq to double pointer.
    # As both of the changes were made in v6.6, there are no kernel versions
    # with wq->cpu_pwq as a pointer. Still I have mentioned both the changes so that
    # we can track both name change and type change of this member.
    try:
        pwq = per_cpu_ptr(workqueue.cpu_pwqs, cpu)
    except AttributeError:
        prog = workqueue.prog_
        pwq = Object(
            prog,
            "struct pool_workqueue",
            address=prog.read_word(per_cpu_ptr(workqueue.cpu_pwq, cpu)),
        ).address_of_()

    return pwq


def for_each_workqueue(prog: Program) -> Iterator[Object]:
    """
    Iterate over all workqueues in the system.

    :return: Iterator of ``struct workqueue_struct *`` objects.
    """
    return list_for_each_entry(
        "struct workqueue_struct", prog["workqueues"].address_of_(), "list"
    )


def for_each_pool(prog: Program) -> Iterator[Object]:
    """
    Iterate over all worker_pools in the system.

    :return: Iterator of ``struct worker_pool *`` objects.
    """
    for nr, entry in idr_for_each(prog["worker_pool_idr"].address_of_()):
        yield cast("struct worker_pool *", entry)


def for_each_pending_work(prog: Program) -> Iterator[Object]:
    """
    Iterate over all pending work items (work_struct)

    :return: Iterator of ``struct work_struct *`` objects.
    """
    for nr, entry in idr_for_each(prog["worker_pool_idr"].address_of_()):
        wp = cast("struct worker_pool *", entry)
        for work in list_for_each_entry(
            "struct work_struct", wp.worklist.address_of_(), "entry"
        ):
            yield work


def for_each_pool_worker(pool: Object) -> Iterator[Object]:
    """
    Iterate over all workers in a worker_pool

    :param pool: ``struct worker_pool *``
    :return: Iterator of ``struct worker *`` objects.
    """
    for worker in list_for_each_entry(
        "struct worker", pool.workers.address_of_(), "node"
    ):
        yield worker


def for_each_worker(prog: Program) -> Iterator[Object]:
    """
    Iterate over all workers in a system

    :return: Iterator of ``struct worker *`` objects.
    """
    for nr, entry in idr_for_each(prog["worker_pool_idr"].address_of_()):
        pool = Object(prog, "struct worker_pool", address=entry.value_())
        for worker in for_each_pool_worker(pool):
            yield worker


def for_each_pwq(workqueue: Object) -> Iterator[Object]:
    """
    Iterate over all pool_workqueues(pwq) of a specified workqueue

    :param workqueue: ``struct workqueue_struct *``
    :return: Iterator of ``struct pool_workqueue *`` objects.
    """
    return list_for_each_entry(
        "struct pool_workqueue", workqueue.pwqs.address_of_(), "pwqs_node"
    )


def for_each_cpu_worker_pool(prog: Program, cpu: int) -> Iterator[Object]:
    """
    Iterate over all worker_pool(s) of a CPU

    :param cpu: cpu number
    :return: Iterator of ``struct worker_pool *`` objects.
    """
    worker_pool_list = per_cpu(prog["cpu_worker_pools"], cpu)
    for worker_pool in worker_pool_list:
        yield worker_pool.address_of_()


def for_each_pending_work_in_pool(pool: Object) -> Iterator[Object]:
    """
    Iterate over all works pending in a worker_pool

    :param pool: ``struct worker_pool *``
    :return: Iterator of ``struct work_struct *`` objects.
    """
    return list_for_each_entry(
        "struct work_struct", pool.worklist.address_of_(), "entry"
    )


def for_each_pending_work_on_cpu(prog: Program, cpu: int) -> Iterator[Object]:
    """
    Iterate over all works pending in a CPU's worker_pools

    :param cpu: cpu number
    :return: Iterator of ``struct work_struct *`` objects.
    """
    for worker_pool in for_each_cpu_worker_pool(prog, cpu):
        for work in for_each_pending_work_in_pool(worker_pool):
            yield work


def for_each_pending_work_of_pwq(pwq: Object) -> Iterator[Object]:
    """
    Iterate over all pending works of a pool_workqueue

    :param pwq: ``struct pool_workqueue *``
    :return: Iterator of ``struct work_struct *`` objects.
    """
    pool = pwq.pool
    for work in for_each_pending_work_in_pool(pool):
        if get_work_pwq(work).value_() == pwq.value_():
            yield work


def find_workqueue(prog: Program, name: Union[str, bytes]) -> Optional[Object]:
    """
    Find workqueue with the given name

    :param name: workqueue name.
    :return: ``struct workqueue *``
    """
    if isinstance(name, str):
        name = name.encode()
    for workqueue in for_each_workqueue(prog):
        if workqueue.name.string_() == name:
            return workqueue
    return None


def print_workqueue_names(prog: Program) -> None:
    """Print the name and ``struct workqueue_struct *`` value of all workqueues."""
    for workqueue in for_each_workqueue(prog):
        name = escape_ascii_string(workqueue.name.string_(), escape_backslash=True)
        print(f"{name} ({workqueue.type_.type_name()})0x{workqueue.value_():x}")


def get_work_pwq(work: Object) -> Object:
    """
    Get pool_workqueue associated with a work

    :param work: ``struct work_struct *``
    :return: ``struct pool_workqueue *`` of associated pwq, NULL otherwise
    """

    prog = work.prog_
    data = cast("unsigned long", work.data.counter.read_())
    if data & prog["WORK_STRUCT_PWQ"].value_():
        return cast("struct pool_workqueue *", data & _work_struct_wq_data_mask(prog))
    else:
        return NULL(work.prog_, "struct pool_workqueue *")


def get_work_pool(work: Object) -> Object:
    """
    Get worker_pool associated with a work

    :param work: ``struct work_struct *``
    :return: ``struct worker_pool *`` of associated pool, NULL otherwise
             residing in a worker_pool at the moment
    """

    prog = work.prog_
    data = cast("unsigned long", work.data.counter.read_())

    if data & prog["WORK_STRUCT_PWQ"].value_():
        pwq = data & _work_struct_wq_data_mask(prog)
        pool = Object(prog, "struct pool_workqueue", address=pwq).pool
    else:
        pool_id = data >> prog["WORK_OFFQ_POOL_SHIFT"].value_()

        if pool_id == _work_offq_pool_none(prog):
            return NULL(work.prog_, "struct worker_pool *")

        pool = idr_find(prog["worker_pool_idr"].address_of_(), pool_id)

        pool = cast("struct worker_pool *", pool)

    return pool


def show_pwq_in_flight(pwq: Object) -> None:
    """
    Show in_flight work items of a pwq

    :param pwq: ``struct pool_workqueue *``.
    """
    pool = pwq.pool
    has_in_flight = False
    prog = pwq.prog_

    for bkt in pool.busy_hash:
        for worker in hlist_for_each_entry("struct worker", bkt, "hentry"):
            if worker.current_pwq.value_() == pwq.value_():
                has_in_flight = True
                break

        if has_in_flight:
            break

    if not has_in_flight:
        print("  There are no in-flight work items for this pwq.")
    else:
        print("  in-flight:")
        for bkt in pool.busy_hash:
            for worker in hlist_for_each_entry("struct worker", bkt, "hentry"):
                if worker.current_pwq.value_() == pwq.value_():
                    pid = worker.task.pid.value_()
                    rescuer = "(RESCUER)" if worker.rescue_wq else ""
                    current_work = worker.current_work.value_()
                    current_func = prog.symbol(worker.current_func.value_()).name
                    print(
                        f"    worker pid: {pid} {rescuer} current_work: {hex(current_work)}  current_func: {current_func}"
                    )
                    if list_empty(worker.scheduled.address_of_()):
                        print("    There are no scheduled works for this worker")
                    else:
                        print("    Scheduled work(s): ")
                        for work in list_for_each_entry(
                            "struct work_struct",
                            worker.scheduled.address_of_(),
                            "entry",
                        ):
                            _print_work(work)


def show_pwq_pending(pwq: Object) -> None:
    """
    Show pending work items of a pwq

    :param pwq: ``struct pool_workqueue *``.
    """
    prog = pwq.prog_
    pool = Object(
        pwq.prog_, "struct worker_pool", address=pwq.pool.value_()
    ).address_of_()
    has_pending = False

    for work in for_each_pending_work_in_pool(pool):
        if get_work_pwq(work).value_() == pwq.value_():
            has_pending = True
            break

    if not has_pending:
        print("  There are no pending work items for this pwq.")
    else:
        print("  pending:")
        pool = Object(prog, "struct worker_pool", address=pwq.pool.value_())
        for work in for_each_pending_work_of_pwq(pwq):
            _print_work(work)


def show_pwq_inactive(pwq: Object) -> None:
    """
    Show pending work items of a pwq

    :param pwq: ``struct pool_workqueue *``.
    """

    # Since Linux kernel commit f97a4a1a3f87 ("workqueue: Rename "delayed"
    # (delayed by active management) to "inactive") (in v5.15), the list
    # containing work items, delayed by workqueue active management (i.e
    # the ones that are not of type delayed_work), has been renamed from
    # "delayed_works" to "inactive_works".
    inactive_works_attr = (
        "inactive_works" if hasattr(pwq, "inactive_works") else "delayed_works"
    )
    inactive_works = getattr(pwq, inactive_works_attr).address_of_()

    if list_empty(inactive_works):
        print("  There are no inactive works for this pwq")
    else:
        print("  inactive: ")
        for work in list_for_each_entry("struct work_struct", inactive_works, "entry"):
            _print_work(work)


def show_pwq(pwq: Object) -> None:
    """
    Dump a pool_workqueue

    :param pwq: ``struct pool_workqueue *``.
    """

    mayday = False if list_empty(pwq.pwqs_node.address_of_()) else True

    print(f"pwq: ({pwq.type_.type_name()})0x{pwq.value_():x}")
    print("pool id:", pwq.pool.id.value_())
    print("active/max_active ", pwq.nr_active.value_(), "/", pwq.max_active.value_())
    print(f"refcnt: {pwq.refcnt.value_()} Mayday: {mayday}")

    show_pwq_in_flight(pwq)
    show_pwq_pending(pwq)
    show_pwq_inactive(pwq)


def workqueue_idle(workqueue: Object) -> bool:
    """
    Check if a workqueue is idle
    :param workqueue: ``struct workqueue_struct *``.
    :returns True if workqueue is idle, False otherwise
    """

    for pwq in for_each_pwq(workqueue):
        inactive_works_attr = (
            "inactive_works" if hasattr(pwq, "inactive_works") else "delayed_works"
        )
        inactive_works = getattr(pwq, inactive_works_attr).address_of_()
        if pwq.nr_active or not list_empty(inactive_works):
            return False

    return True


def show_one_workqueue(workqueue: Object) -> None:
    """
    Dump a workqueue
    :param workqueue: ``struct workqueue_struct *``.
    """

    name = escape_ascii_string(workqueue.name.string_(), escape_backslash=True)
    print(f"{name} ({workqueue.type_.type_name()})0x{workqueue.value_():x}")

    idle = workqueue_idle(workqueue)

    if idle:
        print("  workqueue is idle")
    else:
        for pwq in for_each_pwq(workqueue):
            inactive_works_attr = (
                "inactive_works" if hasattr(pwq, "inactive_works") else "delayed_works"
            )
            inactive_works = getattr(pwq, inactive_works_attr).address_of_()
            if pwq.nr_active or not list_empty(inactive_works):
                show_pwq(pwq)


def worker_pool_idle(worker_pool: Object) -> bool:
    """
    Check if all workers of a worker pool are idle
    :param worker_pool: ``struct worker_pool *``.
    :returns True if worker pool has only idle workers, False otherwise
    """

    return worker_pool.nr_workers.value_() == worker_pool.nr_idle.value_()


def show_one_worker_pool(worker_pool: Object) -> None:
    """
    Dump a worker_pool
    :param worker_pool: ``struct worker_pool *``.
    """

    print(
        f"pool: {worker_pool.id.value_()} number of workers: {worker_pool.nr_workers.value_()}"
    )

    if worker_pool_idle(worker_pool):
        print("  All workers idle.")
        return

    if worker_pool.manager:
        print(f"manager pid: {worker_pool.manager.task.pid.value_()}")

    idle_workers = [
        worker.task.pid.value_()
        for worker in list_for_each_entry(
            "struct worker", worker_pool.idle_list.address_of_(), "entry"
        )
    ]
    if idle_workers:
        print("  idle worker pids: ", idle_workers)


def show_all_workqueues(prog: Program, showidle: bool = False) -> None:
    """Dump state of all workqueues and worker_pools"""

    for workqueue in for_each_workqueue(prog):
        if workqueue_idle(workqueue):
            if showidle:
                show_one_workqueue(workqueue)
        else:
            show_one_workqueue(workqueue)

    print("\n")

    for pool in for_each_pool(prog):
        if worker_pool_idle(pool):
            if showidle:
                show_one_worker_pool(pool)
        else:
            show_one_worker_pool(pool)


def is_task_a_worker(prog: Program, pid: int) -> bool:
    """
    Check if specified task is a worker thread.

    :param pid: pid of task
    :return: ``True`` if task is a worker, ``False`` otherwise
    """

    task = find_task(prog, pid)

    ret = True if task.flags.value_() & _PF_WQ_WORKER else False

    return ret


def find_worker_executing_work(work: Object) -> Object:
    """
    Find the worker that is current executing the specified work

    :param work: ``struct work_struct *``.
    :return worker: ``struct worker *``.
    """

    prog = work.prog_
    pool = get_work_pool(work)

    if not pool:
        return pool

    for bkt in pool.busy_hash:
        for worker in hlist_for_each_entry("struct worker", bkt, "hentry"):
            if worker.current_work == work and worker.current_func == work.func:
                return worker

    return NULL(prog, "struct worker *")
