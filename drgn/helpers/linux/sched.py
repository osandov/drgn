# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CPU Scheduler
-------------

The ``drgn.helpers.linux.sched`` module provides helpers for working with the
Linux CPU scheduler.
"""

from drgn import Object

__all__ = ("task_state_to_char",)

_TASK_NOLOAD = 0x400


def task_state_to_char(task: Object) -> str:
    """
    Get the state of the task as a character (e.g., ``'R'`` for running). See
    `ps(1)
    <http://man7.org/linux/man-pages/man1/ps.1.html#PROCESS_STATE_CODES>`_ for
    a description of the process state codes.

    :param task: ``struct task_struct *``
    """
    prog = task.prog_
    task_state_chars: str
    TASK_REPORT: int
    try:
        task_state_chars, TASK_REPORT = prog.cache["task_state_to_char"]
    except KeyError:
        task_state_array = prog["task_state_array"]
        # Walk through task_state_array backwards looking for the largest state
        # that we know is in TASK_REPORT, then populate the task state mapping.
        chars = None
        for i in range(len(task_state_array) - 1, -1, -1):
            c: int = task_state_array[i][0].value_()
            if chars is None and c in b"RSDTtXZP":
                chars = bytearray(i + 1)
                TASK_REPORT = (1 << i) - 1
            if chars is not None:
                chars[i] = c
        if chars is None:
            raise Exception("could not parse task_state_array")
        task_state_chars = chars.decode("ascii")
        prog.cache["task_state_to_char"] = task_state_chars, TASK_REPORT
    task_state = task.state.value_()
    exit_state = task.exit_state.value_()
    state = (task_state | exit_state) & TASK_REPORT
    char = task_state_chars[state.bit_length()]
    # States beyond TASK_REPORT are special. As of Linux v5.8, TASK_IDLE is the
    # only one; it is defined as TASK_UNINTERRUPTIBLE | TASK_NOLOAD.
    if char == "D" and (task_state & ~state) == _TASK_NOLOAD:
        return "I"
    else:
        return char
