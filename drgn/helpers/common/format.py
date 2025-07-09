# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Formatting
----------

The ``drgn.helpers.common.format`` module provides generic helpers for
formatting different things as text.
"""

import re
from typing import (
    TYPE_CHECKING,
    Any,
    Iterable,
    List,
    Optional,
    Sequence,
    SupportsFloat,
    Tuple,
)

from drgn import IntegerLike, Type

if TYPE_CHECKING:
    from _typeshed import SupportsWrite

__all__ = (
    "CellFormat",
    "decode_enum_type_flags",
    "decode_flags",
    "double_quote_ascii_string",
    "escape_ascii_character",
    "escape_ascii_string",
    "number_in_binary_units",
    "print_table",
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


def double_quote_ascii_string(buffer: Iterable[int]) -> str:
    """
    Get an iterable of ASCII byte values (e.g., :class:`bytes` or
    :class:`bytearray`) as a double-quoted string.

    This is equivalent to:

    .. code-block:: python3

        '"' + escape_ascii_string(buffer, escape_double_quote=True, escape_backslash=True) + '"'
    """
    parts = [
        escape_ascii_character(c, escape_double_quote=True, escape_backslash=True)
        for c in buffer
    ]
    parts.insert(0, '"')
    parts.append('"')
    return "".join(parts)


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


def print_table(
    rows: Sequence[Sequence[Any]],
    *,
    sep: str = "  ",
    file: "Optional[SupportsWrite[str]]" = None,
) -> None:
    """
    Print data as a table.

    The input is given as a sequence (e.g., :class:`list` or :class:`tuple`) of
    rows, where each row is a sequence of values. Rows can have different
    lengths.

    >>> print_table([[2, 2000, 4], ["", 3, 13, 19]])
    2  2000   4
          3  13  19

    By default, numbers are right-aligned and most other objects are
    left-aligned. This (and other format options) can be changed by wrapping
    the value in a :class:`CellFormat`.

    >>> print_table(
    ...     [
    ...         ["DECIMAL", "HEXADECIMAL"],
    ...         [CellFormat(10, "<"), CellFormat(10, "<x")],
    ...     ]
    ... )
    DECIMAL  HEXADECIMAL
    10       a

    :param rows: Sequence of rows, where each row is a sequence of cells.
    :param sep: Column separator.
    :param file: File to write to (defaults to ``sys.stdout``).
    """
    width: List[int] = []
    for row in rows:
        for i, value in enumerate(row):
            cell_width = len(str(value))
            if i < len(width):
                width[i] = max(width[i], cell_width)
            else:
                width.append(cell_width)

    for row in rows:
        print(
            *(
                f"{value:{width[i]}}".rstrip(" " if i == len(row) - 1 else "")
                for i, value in enumerate(row)
            ),
            sep=sep,
            file=file,
        )


class CellFormat:
    _FORMAT_SPEC_RE = re.compile(
        r"""
        (?P<options>
            (?:
                .?      # fill
                [<>=^]  # align
            )?
            [-+ ]?  # sign
            z?
            [#]?
            0?
        )
        (?P<width>[0-9]+)?
        (?P<rest>
            [,_]?               # grouping
            (?:\.[0-9])?        # precision
            [bcdeEfFgGnosxX%]?  # type
        )
        """,
        flags=re.VERBOSE,
    )

    def __init__(self, value: Any, format_spec: str) -> None:
        """
        Wrap a value with additional format options to apply when it is
        formatted by :func:`print_table()`.

        :param value: Value to wrap.
        :param format_spec: :ref:`Format specification <formatspec>`. It may
            not specify a width.
        """
        self._value = value
        match = self._FORMAT_SPEC_RE.fullmatch(format_spec)
        if not match:
            raise ValueError(f"invalid format_spec {format_spec!r}")
        if match.group("width"):
            raise ValueError("format_spec must not have width")
        self._options = match.group("options")
        self._rest = match.group("rest")

    def __str__(self) -> str:
        return f"{self._value:{self._options}{self._rest}}"

    def __format__(self, format_spec: str) -> str:
        return f"{self._value:{self._options}{format_spec}{self._rest}}"
