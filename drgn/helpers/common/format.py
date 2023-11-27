# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Formatting
----------

The ``drgn.helpers.common.format`` module provides generic helpers for
formatting different things as text.
"""

from typing import Iterable, SupportsFloat, Tuple

from drgn import IntegerLike, Type

__all__ = (
    "decode_enum_type_flags",
    "decode_flags",
    "escape_ascii_character",
    "escape_ascii_string",
    "number_in_binary_units",
)


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

    :param c: Character to escape.
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

    :param buffer: Byte array to escape.
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


def number_in_binary_units(n: SupportsFloat, precision: int = 1) -> str:
    """
    Format a number in binary units (i.e., "K" is 1024, "M" is 1024\\ :sup:`2`,
    etc.).

    >>> number_in_binary_units(1280)
    '1.2K'

    A precision can be specified:

    >>> number_in_binary_units(1280, precision=2)
    '1.25K'

    Exact numbers are printed without a fractional part:

    >>> number_in_binary_units(1024 * 1024)
    '1M'

    Numbers less than 1024 are not scaled:

    >>> number_in_binary_units(10)
    '10'

    :param n: Number to format.
    :param precision: Number of digits to include in fractional part.
    """
    n = float(n)
    for prefix in ("", "K", "M", "G", "T", "P", "E", "Z"):
        if abs(n) < 1024:
            break
        n /= 1024.0
    else:
        prefix = "Y"
    if n.is_integer():
        precision = 0
    return f"{n:.{precision}f}{prefix}"
