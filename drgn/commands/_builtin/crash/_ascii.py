# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Implements the crash "ascii" command for drgn."""

import argparse
import contextlib
import logging
from typing import Any, Iterator

from drgn import Program
from drgn.commands import (
    CommandArgumentError,
    argument,
    drgn_argument,
)
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command


@contextlib.contextmanager
def _log_debug() -> Iterator[None]:
    logger = logging.getLogger("drgn")
    old_level = logger.level
    try:
        logger.setLevel(logging.DEBUG)
        yield
    finally:
        logger.setLevel(old_level)


@crash_command(
    description="translate a hexadecimal value to ASCII",
    long_description="""
    Translates 32-bit or 64-bit hexadecimal values to ASCII.
    If no argument is entered, an ASCII chart is displayed.
    """,
    arguments=(
        argument(
            "value",
            type="hexadecimal",
            nargs="*",
            help="hexadecimal value",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_ascii(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    # Common constants for both --drgn and non-drgn paths.
    CONTROL_NAMES = [
        "NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL",
        "BS", "HT", "LF", "VT", "FF", "CR", "SO", "SI",
        "DLE", "DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB",
        "CAN", "EM", "SUB", "ESC", "FS", "GS", "RS", "US"
    ]

    ASCII_TABLE_TEXT = """      0    1   2   3   4   5   6   7
        +-------------------------------
    0 | NUL DLE  SP  0   @   P   '   p
    1 | SOH DC1  !   1   A   Q   a   q
    2 | STX DC2  "   2   B   R   b   r
    3 | ETX DC3  #   3   C   S   c   s
    4 | EOT DC4  $   4   D   T   d   t
    5 | ENQ NAK  %   5   E   U   e   u
    6 | ACK SYN  &   6   F   V   f   v
    7 | BEL ETB  `   7   G   W   g   w
    8 |  BS CAN  (   8   H   X   h   x
    9 |  HT  EM  )   9   I   Y   i   y
    A |  LF SUB  *   :   J   Z   j   z
    B |  VT ESC  +   ;   K   [   k   {
    C |  FF  FS  ,   <   L   \\   l   |
    D |  CR  GS  _   =   M   ]   m   }
    E |  SO  RS  .   >   N   ^   n   ~
    F |  SI  US  /   ?   O   -   o  DEL"""

    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        if not args.value:
            code.append(ASCII_TABLE_TEXT)
            code.print()
            return

        code.append(f"CONTROL_NAMES = {CONTROL_NAMES}\n")
        code.append(
"""
def fmt_byte(b: int) -> str:
    if b == 0x20:
        return " "
    if 0x21 <= b <= 0x7E:
        return chr(b)
    if b < 0x20:
        return f"<{CONTROL_NAMES[b]}>"
    if b == 0x7F:
        return "<DEL>"
    return f"<{b:02x}>"

def ascii_from_value(val: int) -> None:
    try:
        sizeof_long = int(prog.type("unsigned long").size)
    except Exception:
        sizeof_long = 8
    try:
        sizeof_ull = int(prog.type("unsigned long long").size)
    except Exception:
        sizeof_ull = sizeof_long
    prlen_long = sizeof_long * 2
    prlen_ll = sizeof_ull * 2
    digits = max(1, (val.bit_length() + 3) // 4)
    if digits > prlen_ll:
        raise ValueError(f"value too large: 0x{val:x} ({digits} hex digits vs {prlen_ll})")
    prlen = prlen_ll if digits > prlen_long else prlen_long
    out = []
    for i in range(prlen // 2):
        b = (val >> (8 * i)) & 0xFF
        out.append(fmt_byte(b))
    print(f"{val:0{prlen}x}: {''.join(out)}")
"""
        )
        hex_values = ", ".join(hex(v) for v in args.value)
        code.append(f"\nvalues = [{hex_values}]\n")
        code.append("for _v in values:\n    ascii_from_value(_v)\n")
        code.print()
        return

    if not args.value:
        print(ASCII_TABLE_TEXT)
        return

    for value in args.value:
        # Choose padding width based on values of sizeof(long)/sizeof(long long)
        try:
            sizeof_long = prog.type("unsigned long").size
            sizeof_ull = prog.type("unsigned long long").size
        except Exception:
            sizeof_long = 8
            sizeof_ull = 8
        prlen_long = (sizeof_long or 8) * 2
        prlen_ll = (sizeof_ull or 8) * 2

        digits = max(1, (value.bit_length() + 3) // 4)
        if digits > prlen_ll:
            raise CommandArgumentError(
                f"value too large: 0x{value:x} ({digits} hex digits vs {prlen_ll})"
            )

        prlen = prlen_ll if digits > prlen_long else prlen_long

        bytes_ = prlen // 2
        out = []
        for i in range(bytes_):
            c = (value >> (8 * i)) & 0xFF
            if c == 0x20:
                out.append(" ")
            elif 0x21 <= c <= 0x7E:
                out.append(chr(c))
            elif c < 0x20:
                out.append(f"<{CONTROL_NAMES[c]}>")
            elif c == 0x7F:
                out.append("<DEL>")
            else:
                out.append(f"<{c:02x}>")

        # Left-pad hex output to 8 or 16 digits based on prlen, matching crash.
        print(f"{value:0{prlen}x}: {''.join(out)}")
