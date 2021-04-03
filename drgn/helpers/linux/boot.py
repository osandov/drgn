# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Boot
----

The ``drgn.helpers.linux.boot`` module provides helpers for inspecting the
Linux kernel boot configuration.
"""

from _drgn import (
    _linux_helper_kaslr_offset as kaslr_offset,
    _linux_helper_pgtable_l5_enabled as pgtable_l5_enabled,
)

__all__ = (
    "kaslr_offset",
    "pgtable_l5_enabled",
)
