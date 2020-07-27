# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
Boot
----

The ``drgn.helpers.linux.boot`` module provides helpers for inspecting the
Linux kernel boot configuration.
"""

from _drgn import _linux_helper_kaslr_offset, _linux_helper_pgtable_l5_enabled


__all__ = (
    "kaslr_offset",
    "pgtable_l5_enabled",
)


def kaslr_offset(prog):
    """
    .. c:function:: unsigned long kaslr_offset(void)

    Get the kernel address space layout randomization offset (zero if it is
    disabled).
    """
    return _linux_helper_kaslr_offset(prog)


def pgtable_l5_enabled(prog):
    """
    .. c:function:: bool pgtable_l5_enabled(void)

    Return whether 5-level paging is enabled.
    """
    return _linux_helper_pgtable_l5_enabled(prog)
