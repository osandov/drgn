# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Helpers
-------

The ``drgn.helpers`` package contains subpackages which provide helpers for
working with particular types of programs. Currently, there are only helpers
for the Linux kernel. In the future, there may be helpers for, e.g., glibc and
libstdc++.

Generic Helpers
===============

The top-level ``drgn.helpers`` module provides generic helpers that may be
useful for scripts or for implementing other helpers.
"""

import enum
import typing
from typing import Container, Iterable, Tuple

from drgn import IntegerLike, Type


class ValidationError(Exception):
    """
    Error raised by a :ref:`validator <validators>` when an inconsistent or
    invalid state is detected.
    """


def escape_ascii_character(
    c: int,
    escape_single_quote: bool = False,
    escape_double_quote: bool = False,
    escape_backslash: bool = False,
) -> str:
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
        return r"\0"
    elif c == 7:
        return r"\a"
    elif c == 8:
        return r"\b"
    elif c == 9:
        return r"\t"
    elif c == 10:
        return r"\n"
    elif c == 11:
        return r"\v"
    elif c == 12:
        return r"\f"
    elif c == 13:
        return r"\r"
    elif escape_double_quote and c == 34:
        return r"\""
    elif escape_single_quote and c == 39:
        return r"\'"
    elif escape_backslash and c == 92:
        return r"\\"
    elif 32 <= c <= 126:
        return chr(c)
    else:
        return f"\\x{c:02x}"


def escape_ascii_string(
    buffer: Iterable[int],
    escape_single_quote: bool = False,
    escape_double_quote: bool = False,
    escape_backslash: bool = False,
) -> str:
    """
    Escape an iterable of ASCII byte values (e.g., :class:`bytes` or
    :class:`bytearray`). See :func:`escape_ascii_character()`.

    :param buffer: The byte array.
    """
    return "".join(
        escape_ascii_character(
            c,
            escape_single_quote=escape_single_quote,
            escape_double_quote=escape_double_quote,
            escape_backslash=escape_backslash,
        )
        for c in buffer
    )


def enum_type_to_class(
    type: Type, name: str, exclude: Container[str] = (), prefix: str = ""
) -> typing.Type[enum.IntEnum]:
    """
    Get an :class:`enum.IntEnum` class from an enumerated :class:`drgn.Type`.

    :param type: The enumerated type to convert.
    :param name: The name of the ``IntEnum`` type to create.
    :param exclude: Container (e.g., list or set) of enumerator names to
        exclude from the created ``IntEnum``.
    :param prefix: Prefix to strip from the beginning of enumerator names.
    """
    if type.enumerators is None:
        raise TypeError("enum type is incomplete")
    enumerators = [
        (name[len(prefix) :] if name.startswith(prefix) else name, value)
        for (name, value) in type.enumerators
        if name not in exclude
    ]
    return enum.IntEnum(name, enumerators)  # type: ignore  # python/mypy#4865


def decode_flags(
    value: IntegerLike,
    flags: Iterable[Tuple[str, int]],
    bit_numbers: bool = True,
) -> str:
    """
    Get a human-readable representation of a bitmask of flags.

    By default, flags are specified by their bit number:

    >>> decode_flags(2, [("BOLD", 0), ("ITALIC", 1), ("UNDERLINE", 2)])
    'ITALIC'

    They can also be specified by their value:

    >>> decode_flags(2, [("BOLD", 1), ("ITALIC", 2), ("UNDERLINE", 4)],
    ...              bit_numbers=False)
    'ITALIC'

    Multiple flags are combined with "|":

    >>> decode_flags(5, [("BOLD", 0), ("ITALIC", 1), ("UNDERLINE", 2)])
    'BOLD|UNDERLINE'

    If there are multiple names for the same bit, they are all included:

    >>> decode_flags(2, [("SMALL", 0), ("BIG", 1), ("LARGE", 1)])
    'BIG|LARGE'

    If there are any unknown bits, their raw value is included:

    >>> decode_flags(27, [("BOLD", 0), ("ITALIC", 1), ("UNDERLINE", 2)])
    'BOLD|ITALIC|0x18'

    Zero is returned verbatim:

    >>> decode_flags(0, [("BOLD", 0), ("ITALIC", 1), ("UNDERLINE", 2)])
    '0'

    :param value: Bitmask to decode.
    :param flags: List of flag names and their bit numbers or values.
    :param bit_numbers: Whether *flags* specifies the bit numbers (where 0 is
        the least significant bit) or values of the flags.
    """
    value = value.__index__()
    if value == 0:
        return "0"

    parts = []
    mask = 0
    for name, flag in flags:
        if bit_numbers:
            flag = 1 << flag
        if value & flag:
            parts.append(name)
            mask |= flag

    if value & ~mask:
        parts.append(hex(value & ~mask))

    return "|".join(parts)


def decode_enum_type_flags(
    value: IntegerLike,
    type: Type,
    bit_numbers: bool = True,
) -> str:
    """
    Get a human-readable representation of a bitmask of flags where the flags
    are specified by an enumerated :class:`drgn.Type`.

    This supports enums where the values are bit numbers:

    >>> print(bits_enum)
    enum style_bits {
            BOLD = 0,
            ITALIC = 1,
            UNDERLINE = 2,
    }
    >>> decode_enum_type_flags(5, bits_enum)
    'BOLD|UNDERLINE'

    Or the values of the flags:

    >>> print(flags_enum)
    enum style_flags {
            BOLD = 1,
            ITALIC = 2,
            UNDERLINE = 4,
    }
    >>> decode_enum_type_flags(5, flags_enum, bit_numbers=False)
    'BOLD|UNDERLINE'

    See :func:`decode_flags()`.

    :param value: Bitmask to decode.
    :param type: Enumerated type with bit numbers for enumerators.
    :param bit_numbers: Whether the enumerator values specify the bit numbers
         or values of the flags.
    """
    enumerators = type.enumerators
    if enumerators is None:
        raise TypeError("cannot decode incomplete enumerated type")
    return decode_flags(
        value,
        enumerators,  # type: ignore  # python/mypy#592
        bit_numbers,
    )
