# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Signals
-------

The ``drgn.helpers.linux.signal`` module provides helpers for working with
signals.
"""

import operator
import types
from typing import Dict, Iterator, List, Mapping, Sequence, Union

import _drgn_util.platform
from drgn import IntegerLike, Object, Program, TypeKind, sizeof
from drgn.helpers.common.format import decode_flags
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.bitops import for_each_set_bit
from drgn.helpers.linux.list import list_for_each_entry

__all__ = (
    "decode_sigaction_flags",
    "decode_sigaction_flags_value",
    "decode_sigset",
    "sigaction_flags",
    "signal_names",
    "signal_numbers",
    "sigpending_for_each",
    "sigset_to_hex",
)


def sigpending_for_each(pending: Object) -> Iterator[Object]:
    """
    Iterate over a queue of pending signals.

    :param pending: ``struct sigpending *``
    :return: Iterator of ``struct sigqueue *`` objects.
    """
    return list_for_each_entry("struct sigqueue", pending.list.address_of_(), "list")


@takes_program_or_default
def signal_names(prog: Program) -> Mapping[str, int]:
    """
    Get a mapping from signal names to numbers on this kernel.

    >>> signal_names()
    {'SIGHUP': 1, 'SIGINT': 2, 'SIGQUIT': 3, ...}

    If there are multiple names for the same number (e.g., ``SIGCHLD`` and
    ``SIGCLD``), then the preferred name comes first.

    Note that ``SIGRTMIN`` and ``SIGRTMAX`` are dynamic in userspace, so the
    values used in the kernel may differ from those in userspace.
    """
    return _drgn_util.platform.SIGNALS_BY_MACHINE_NAME[
        prog.platform.arch.name.lower()  # type: ignore[union-attr]
    ]


@takes_program_or_default
def signal_numbers(prog: Program) -> Mapping[int, Sequence[str]]:
    """
    Get a mapping from signal numbers to names on this kernel.

    >>> signal_numbers()
    {1: ['SIGHUP'], 2: ['SIGINT'], 3: ['SIGQUIT'], ...}

    If there are multiple names for the same number (e.g., ``SIGCHLD`` and
    ``SIGCLD``), then the preferred name comes first.

    Note that ``SIGRTMIN`` and ``SIGRTMAX`` are dynamic in userspace, so the
    values used in the kernel may differ from those in userspace.
    """
    try:
        return prog.cache["signal_numbers"]
    except KeyError:
        pass

    name_to_number = signal_names(prog)
    number_to_names: Dict[int, List[str]] = {}
    for name, number in name_to_number.items():
        if name == "SIGRTMAX":
            rtmin = name_to_number["SIGRTMIN"]
            # This is how crash numbers real-time signals, maybe inherited from
            # the kill -l shell builtin on ksh:
            # https://git.kernel.org/pub/scm/utils/dash/dash.git/tree/src/mksignames.c?h=v0.5.13#n80.
            for rtnumber in range(rtmin + 1, (rtmin + number) // 2 + 1):
                number_to_names.setdefault(rtnumber, []).append(
                    f"SIGRTMIN+{rtnumber - rtmin}"
                )
            for rtnumber in range((rtmin + number) // 2 + 1, number):
                number_to_names.setdefault(rtnumber, []).append(
                    f"SIGRTMAX-{number - rtnumber}"
                )
        number_to_names.setdefault(number, []).append(name)
    result = types.MappingProxyType(number_to_names)
    prog.cache["signal_numbers"] = result
    return result


@takes_program_or_default
def sigaction_flags(prog: Program) -> Mapping[str, int]:
    """
    Get a mapping of :manpage:`sigaction(2)` ``sa_flags`` flag names to values
    on this kernel.

    >>> sigaction_flags()
    {'SA_NOCLDSTOP': 1, 'SA_NOCLDWAIT': 2, 'SA_SIGINFO': 4, ...}

    If there are multiple names for the same value (e.g., ``SA_NODEFER`` and
    ``SA_NOMASK``), then the preferred name comes first.
    """
    return _drgn_util.platform.SIGACTION_FLAGS_BY_MACHINE_NAME[
        prog.platform.arch.name.lower()  # type: ignore[union-attr]
    ]


@takes_program_or_default
def decode_sigset(prog: Program, sigset: Union[Object, IntegerLike]) -> str:
    """
    Get a human-readable representation of a signal set.

    >>> decode_sigset(task.blocked)
    '{SIGINT,SIGTERM}'
    >>> decode_sigset(0x14003)
    '{SIGHUP,SIGINT,SIGTERM,SIGCHLD}'

    :param sigset: ``sigset_t``, ``sigset_t *``, or an integer
    """
    if not isinstance(sigset, Object) or sigset.type_.unaliased_kind() == TypeKind.INT:
        sigset_int = operator.index(sigset)
        if sigset_int < 0:
            raise ValueError("sigset cannot be negative")
        sig_words = []
        sigset_type = prog.type("sigset_t")
        NSIG_BPW: int = sigset_type.member("sig").type.type.size * 8  # type: ignore[operator]
        mask = (1 << NSIG_BPW) - 1
        while sigset_int:
            sig_words.append(sigset_int & mask)
            sigset_int >>= NSIG_BPW
        sigset = Object(prog, sigset_type, {"sig": sig_words})

    number_to_names = signal_numbers(sigset.prog_)
    sig = sigset.sig
    names = [
        number_to_names[bit + 1][0] for bit in for_each_set_bit(sig, sizeof(sig) * 8)
    ]
    return f"{{{','.join(names)}}}"


def sigset_to_hex(sigset: Object) -> str:
    """
    Get a hexadecimal representation of a signal set.

    This matches how signal sets are represented in
    :manpage:`proc_pid_status(5)`.

    >>> sigset_to_hex(task.blocked)
    '0000000000004002'

    :param sigset: ``sigset_t`` or ``sigset_t *``
    """
    NSIG: int = sigset.prog_.type("struct sighand_struct").member("action").type.length  # type: ignore[assignment]
    sig = sigset.sig
    NSIG_BPW: int = sig.type_.type.size * 8  # type: ignore[operator]
    max_width = NSIG_BPW // 4
    if NSIG % NSIG_BPW == 0:
        width = max_width
    else:
        width = (NSIG % NSIG_BPW + 3) // 4

    parts = []
    for word in reversed(sig.value_()):
        parts.append(f"{word:0{width or ''}x}")
        width = max_width
    return "".join(parts)


def decode_sigaction_flags(sigaction: Object) -> str:
    """
    Get a human-readable representation of the ``sa_flags`` of a
    ``struct sigaction``.

    >>> decode_sigaction_flags(task.sighand.action[1].sa)
    'SA_RESTORER|SA_RESTART'

    :param sigaction: ``struct sigaction``
    """
    return decode_sigaction_flags_value(sigaction.prog_, sigaction.sa_flags.value_())


@takes_program_or_default
def decode_sigaction_flags_value(prog: Program, value: IntegerLike) -> str:
    """
    Get a human-readable representation of a :manpage:`sigaction(2)`
    ``sa_flags`` value.

    >>> decode_sigaction_flags_value(0x14000000)
    'SA_RESTORER|SA_RESTART'

    :param value: ``int``
    """
    return decode_flags(
        value, sigaction_flags(prog).items(), bit_numbers=False, aliases=False
    )
