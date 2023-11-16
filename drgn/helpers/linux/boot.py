# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Boot
----

The ``drgn.helpers.linux.boot`` module provides helpers for inspecting the
Linux kernel boot configuration.
"""

from _drgn import _linux_helper_kaslr_offset, _linux_helper_pgtable_l5_enabled
from drgn import Program
from drgn.helpers.common.prog import takes_program_or_default

__all__ = (
    "kaslr_offset",
    "pgtable_l5_enabled",
)


@takes_program_or_default
def kaslr_offset(prog: Program) -> int:
    """
    Get the kernel address space layout randomization offset (zero if it is
    disabled).
    """
    return _linux_helper_kaslr_offset(prog)


@takes_program_or_default
def pgtable_l5_enabled(prog: Program) -> bool:
    """Return whether 5-level paging is enabled."""
    return _linux_helper_pgtable_l5_enabled(prog)
