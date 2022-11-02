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
    Error raised by a :ref:`validator <validators>` when an inconsistent or
    invalid state is detected.
    """
