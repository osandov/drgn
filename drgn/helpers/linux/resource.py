# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Resource Limits
---------------

The ``drgn.helpers.linux.resource`` module provides helpers for resource limits
(rlimit).
"""

from typing import Dict, NamedTuple, Optional

from drgn import Object

__all__ = ("task_rlimits",)


def task_rlimits(task: Object) -> Dict[str, "Rlimit"]:
    """
    Get the resource limits on a given task.

    >>> task_rlimits(find_task(os.getpid()))
    {'CPU': Rlimit(cur=None, max=None), 'FSIZE': Rlimit(cur=None, max=None), ...}
    >>> task_rlimits(find_task(os.getpid()))["STACK"].cur
    8388608

    :return: Dictionary mapping resource name (`"NOFILE"`, `"CORE"`, etc.) to
        :class:`Rlimit`.
    """
    # XXX: alpha, mips, and sparc have different values for RLIM_INFINITY and
    # RLIMIT_{NOFILE,AS,RSS,NPROC,MEMLOCK}. Once we recognize those
    # architectures, we will have to account for that.
    RLIM_INFINITY = Object(task.prog_, "unsigned long", -1)
    return {
        name: Rlimit(
            None if rlim.rlim_cur == RLIM_INFINITY else rlim.rlim_cur.value_(),
            None if rlim.rlim_max == RLIM_INFINITY else rlim.rlim_max.value_(),
        )
        for name, rlim in zip(
            (
                "CPU",
                "FSIZE",
                "DATA",
                "STACK",
                "CORE",
                "RSS",
                "NPROC",
                "NOFILE",
                "MEMLOCK",
                "AS",
                "LOCKS",
                "SIGPENDING",
                "MSGQUEUE",
                "NICE",
                "RTPRIO",
                "RTTIME",
            ),
            task.signal.rlim.read_(),
        )
    }


class Rlimit(NamedTuple):
    """Resource limit."""

    cur: Optional[int]
    """Soft limit, or ``None`` if unlimited."""

    max: Optional[int]
    """Hard limit, or ``None`` if unlimited."""
