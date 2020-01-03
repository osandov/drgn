# SPDX-License-Identifier: GPL-3.0+

"""
TCP
---

The ``drgn.helpers.linux.tcp`` module provides helpers for working with the TCP
protocol in the Linux kernel.
"""

import enum


__all__ = [
    'get_tcp_states',
    'sk_tcpstate',
]


def _get_tcp_states(prog, enum_name):
    # The enum type is anonymous, but it can be looked up from one of the
    # enumerators.
    raw_enumerators = prog['TCP_ESTABLISHED'].type_.enumerators
    tcp_ = 'TCP_'
    enumerators = [
        (name[len(tcp_):], value) if name.startswith(tcp_) else (name, value)
        for (name, value) in raw_enumerators
        if name != 'TCP_MAX_STATES'
    ]
    return enum.IntEnum(enum_name, enumerators)


def get_tcp_states(prog):
    """
    Get all definitions for the TCP protocol states
    (:linux:`include/net/tcp_states.h`) as an :class:`enum.IntEnum` class.

    :rtype: enum.IntEnum
    """
    enum_name = 'TcpStates'
    try:
        return prog.cache[enum_name]
    except KeyError:
        prog.cache[enum_name] = _get_tcp_states(prog, enum_name)
        return prog.cache[enum_name]


def sk_tcpstate(sk):
    """
    .. c:function:: enum TcpState sk_tcpstate(struct sock *sk)

    Return the TCP protocol state of a socket.
    """
    return get_tcp_states(sk.prog_)(sk.__sk_common.skc_state)
