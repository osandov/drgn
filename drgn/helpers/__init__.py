# Copyright 2018-2020 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Helpers
-------

The ``drgn.helpers`` package contains subpackages which provide helpers for
working with particular types of programs. Currently, there are only helpers
for the Linux kernel. In the future, there may be helpers for, e.g., glibc and
libstdc++.

Parameter types and return types are :class:`drgn.Object` unless noted
otherwise. Many helpers include a C function signature indicating the expected
object types.

Generic Helpers
===============

The top-level ``drgn.helpers`` module provides generic helpers that may be
useful for scripts or for implementing other helpers.
"""

from typing import Iterable


def escape_ascii_character(c: int, escape_single_quote: bool = False,
                           escape_double_quote: bool = False,
                           escape_backslash: bool = False) -> str:
    """
    Format an ASCII byte value as a character, possibly escaping it.
    Non-printable characters are always escaped. Non-printable characters other
    than ``\\0``, ``\\a``, ``\\b``, ``\\t``, ``\\n``, ``\\v``, ``\\f``, and
    ``\\r`` are escaped in hexadecimal format (e.g., ``\\x7f``). By default,
    printable characters are never escaped.

    :param c: The character to escape.
    :param escape_single_quote: Whether to escape single quotes to ``\\'``.
    :param escape_double_quote: Whether to escape double quotes to ``\\"``.
    :param escape_backslash: Whether to escape backslashes to ``\\\\``.
    """
    if c == 0:
        return r'\0'
    elif c == 7:
        return r'\a'
    elif c == 8:
        return r'\b'
    elif c == 9:
        return r'\t'
    elif c == 10:
        return r'\n'
    elif c == 11:
        return r'\v'
    elif c == 12:
        return r'\f'
    elif c == 13:
        return r'\r'
    elif escape_double_quote and c == 34:
        return r'\"'
    elif escape_single_quote and c == 39:
        return r"\'"
    elif escape_backslash and c == 92:
        return r'\\'
    elif 32 <= c <= 126:
        return chr(c)
    else:
        return f'\\x{c:02x}'


def escape_ascii_string(buffer: Iterable[int],
                        escape_single_quote: bool = False,
                        escape_double_quote: bool = False,
                        escape_backslash: bool = False) -> str:
    """
    Escape an iterable of ASCII byte values (e.g., :class:`bytes` or
    :class:`bytearray`). See :func:`escape_ascii_character()`.

    :param buffer: The byte array.
    """
    return ''.join(escape_ascii_character(c,
                                          escape_single_quote=escape_single_quote,
                                          escape_double_quote=escape_double_quote,
                                          escape_backslash=escape_backslash)
                   for c in buffer)
