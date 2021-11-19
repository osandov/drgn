# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
IDR
---

The ``drgn.helpers.linux.idr`` module provides helpers for working with the IDR
data structure in :linux:`include/linux/idr.h`. An IDR provides a mapping from
an ID to a pointer. This currently only supports Linux v4.11+; before this,
IDRs were not based on radix trees.
"""

from _drgn import (
    _linux_helper_idr_find as idr_find,
    _linux_helper_idr_for_each as idr_for_each,
)

__all__ = (
    "idr_find",
    "idr_for_each",
)
