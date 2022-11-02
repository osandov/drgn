# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
TCP
---

The ``drgn.helpers.linux.tcp`` module provides helpers for working with the TCP
protocol in the Linux kernel.
"""

from drgn import Object, cast

__all__ = ("sk_tcpstate",)


def sk_tcpstate(sk: Object) -> Object:
    """
    Return the TCP protocol state of a socket.

    :param sk: ``struct sock *``
    :return: TCP state enum value.
    """
    return cast(sk.prog_["TCP_ESTABLISHED"].type_, sk.__sk_common.skc_state)
