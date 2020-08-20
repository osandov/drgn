# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
CPU Scheduler
-------------

The ``drgn.helpers.linux.sched`` module provides helpers for working with the
Linux CPU scheduler.
"""

from _drgn import _linux_helper_task_state_to_char as task_state_to_char

__all__ = ("task_state_to_char",)
