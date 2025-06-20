# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Helpers
-------

The ``drgn.helpers`` package contains subpackages which provide helpers for
working with particular types of programs. Currently, there are common helpers
and helpers for the Linux kernel. In the future, there may be helpers for,
e.g., glibc and libstdc++.
"""


class ValidationError(Exception):
    """
    Error raised by a validator when an inconsistent or invalid state is
    detected.

    Validators are a special category of helpers that check the consistency of
    a data structure. In general, helpers assume that the data structures that
    they examine are valid. Validators do not make this assumption and do
    additional (potentially expensive) checks to detect broken invariants,
    corruption, etc.

    Validators raise :class:`drgn.helpers.ValidationError` if the data
    structure is not valid or :class:`drgn.FaultError` if the data structure is
    invalid in a way that causes a bad memory access. They have names prefixed
    with ``validate_``.
    """
