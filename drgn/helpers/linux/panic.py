# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Panic
-----

The ``drgn.helpers.linux.panic`` module provides helpers for getting kernel
panic information.
"""

from drgn import NULL, Object, Program
from drgn.helpers.common.prog import takes_program_or_default

__all__ = ("panic_task",)


@takes_program_or_default
def panic_task(prog: Program) -> Object:
    """
    Return the task that panicked.

    This is equivalent to:

    .. code-block:: python3

        from drgn import NULL


        try:
            task = prog.crashed_thread().object
        except ValueError:
            task = NULL(prog, "struct task_struct *")

    :return: ``struct task_struct *`` (``NULL`` if the kernel has not panicked)
    """
    try:
        return prog.crashed_thread().object
    except ValueError:
        return NULL(prog, "struct task_struct *")
