# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
The ``drgn.helpers.linux.rss`` module provides get_task_rss() helper to get
the resident set size in pages of a given task.
"""

from typing import Dict, Iterable, NamedTuple, Optional

from drgn import Object, Program, TypeKind
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import percpu_counter_sum

__all__ = ("get_task_rss",)


class TaskRss(NamedTuple):
    """
    Represent's a task's resident set size in pages. See task_rss().
    """

    rss_file: int
    rss_anon: int
    rss_shmem: int
    swapents: int

    @property
    def total(self) -> int:
        return self.rss_file + self.rss_anon + self.rss_shmem


def for_each_task_in_group(
    task: Object, include_self: bool = False
) -> Iterable[Object]:
    """
    Iterate over all tasks in the thread group

    Or, in the more common userspace terms, iterate over all threads of a
    process.

    :param task: a task whose group to iterate over
    :param include_self: should ``task`` itself be returned
    :returns: an iterable of every thread in the thread group
    """
    if include_self:
        yield task
    if hasattr(task, "thread_group"):
        yield from list_for_each_entry(
            "struct task_struct",
            task.thread_group.address_of_(),
            "thread_group",
        )
    else:
        # Since commit 8e1f385104ac0 ("kill task_struct->thread_group") from
        # 6.7, the thread_group list is gone, replaced by a list inside the
        # task.signal struct. This has an explicit list_head (unlike the
        # thread_group which just linked each task together with no explicit
        # head node).
        for other in list_for_each_entry(
            "struct task_struct",
            task.signal.thread_head.address_of_(),
            "thread_node",
        ):
            # We've already yielded "task" (or not, depending on the caller's
            # preference) so skip it here.
            if other != task:
                yield other


@takes_program_or_default
def get_task_rss(
    prog: Program, task: Object, cache: Optional[Dict[int, TaskRss]]
) -> TaskRss:
    """
    Return the task's resident set size (RSS) in pages

    The task's RSS is the number of pages which are currently resident in
    memory. The RSS values can be broken down into anonymous pages (not bound to
    any file), file pages (those associated with memory mapped files), and
    shared memory pages (those which aren't associated with on-disk files, but
    belonging to shared memory mappings). This function returns a tuple
    containing each category, but the common behavior is to use the "total"
    value which sums them up.

    :param task: ``struct task_struct *`` for which to compute RSS
    :param cache: if provided, we can use this to cache the mapping of
      "mm_struct" to RSS. This helps avoid re-computing the RSS value for
      processes with many threads, but note that it could result in out of date
      values on a live system.
    :returns: the file, anon, and shmem page values
    """
    mmptr = task.mm.value_()
    if mmptr and cache and mmptr in cache:
        return cache[mmptr]

    # Kthreads have a NULL mm, simply skip them, returning 0.
    if not task.mm:
        return TaskRss(0, 0, 0, 0)

    prog = task.prog_
    rss_stat = task.mm.rss_stat

    MM_FILEPAGES = prog.constant("MM_FILEPAGES").value_()
    MM_ANONPAGES = prog.constant("MM_ANONPAGES").value_()
    MM_SWAPENTS = prog.constant("MM_SWAPENTS").value_()
    try:
        MM_SHMEMPAGES = prog.constant("MM_SHMEMPAGES").value_()
    except LookupError:
        MM_SHMEMPAGES = -1

    # Start with the counters from the mm_struct
    filerss = anonrss = shmemrss = swapents = 0

    if rss_stat.type_.kind == TypeKind.ARRAY:
        # Since v6.2, f1a7941243c10 ("mm: convert mm's rss stats into
        # percpu_counter"), the "rss_stat" object is an array of percpu
        # counters. Simply sum them up!
        filerss = percpu_counter_sum(rss_stat[MM_FILEPAGES].address_of_())
        anonrss = percpu_counter_sum(rss_stat[MM_ANONPAGES].address_of_())
        swapents = percpu_counter_sum(rss_stat[MM_SWAPENTS].address_of_())
        shmemrss = 0
        if MM_SHMEMPAGES >= 0:
            shmemrss = percpu_counter_sum(rss_stat[MM_SHMEMPAGES].address_of_())
    else:
        # Prior to this, the "rss_stat" was a structure containing counters that
        # were cached on each task_struct and periodically updated into the
        # mm_struct. We start with the counter values from the mm_struct and
        # then sum up the cached copies from each thread.
        filerss += rss_stat.count[MM_FILEPAGES].counter.value_()
        anonrss += rss_stat.count[MM_ANONPAGES].counter.value_()
        if MM_SHMEMPAGES >= 0:
            shmemrss += rss_stat.count[MM_SHMEMPAGES].counter.value_()

        for gtask in for_each_task_in_group(task, include_self=True):
            filerss += gtask.rss_stat.count[MM_FILEPAGES].value_()
            anonrss += gtask.rss_stat.count[MM_ANONPAGES].value_()
            swapents += gtask.rss_stat.count[MM_SWAPENTS].value_()
            if MM_SHMEMPAGES >= 0:
                shmemrss += gtask.rss_stat.count[MM_SHMEMPAGES].value_()
    rss = TaskRss(filerss, anonrss, shmemrss, swapents)

    if cache is not None:
        cache[mmptr] = rss

    return rss
