# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
CPU Scheduler
-------------

The ``drgn.helpers.linux.sched`` module provides helpers for working with the
Linux CPU scheduler.
"""

from _drgn import _linux_helper_task_state_to_char


__all__ = ("task_state_to_char",)


def task_state_to_char(task):
    """
    .. c:function char task_state_to_char(struct task_struct *task)

    Get the state of the task as a character (e.g., ``'R'`` for running). See
    `ps(1)
    <http://man7.org/linux/man-pages/man1/ps.1.html#PROCESS_STATE_CODES>`_ for
    a description of the process state codes.

    :rtype: str
    """
    return _linux_helper_task_state_to_char(task)
