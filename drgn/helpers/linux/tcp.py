# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
TCP
---

The ``drgn.helpers.linux.tcp`` module provides helpers for working with the TCP
protocol in the Linux kernel.
"""

from drgn import cast

__all__ = ("sk_tcpstate",)


def sk_tcpstate(sk):
    """
    .. c:function:: enum TcpState sk_tcpstate(struct sock *sk)

    Return the TCP protocol state of a socket.
    """
    return cast(sk.prog_["TCP_ESTABLISHED"].type_, sk.__sk_common.skc_state)
