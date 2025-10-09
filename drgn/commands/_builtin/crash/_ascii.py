# Copyright (c) 2025 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Implements the crash "ascii" command for drgn."""

import argparse
from typing import Any

from drgn import Program
from drgn.commands import CommandArgumentError, argument, drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command


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
    CONTROL_NAMES = [
        "NUL",
        "SOH",
        "STX",
        "ETX",
        "EOT",
        "ENQ",
        "ACK",
        "BEL",
        "BS",
        "HT",
        "LF",
        "VT",
        "FF",
        "CR",
        "SO",
        "SI",
        "DLE",
        "DC1",
        "DC2",
        "DC3",
        "DC4",
        "NAK",
        "SYN",
        "ETB",
        "CAN",
        "EM",
        "SUB",
        "ESC",
        "FS",
        "GS",
        "RS",
        "US",
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
        code.append(
            """\
unsigned_long_size = prog.type("unsigned long").size
unsigned_long_long_size = prog.type("unsigned long long").size
for value in ["""
        )
        code.append(", ".join([hex(value) for value in args.value]))
        code.append(
            """]:
    bit_length = value.bit_length()
    if bit_length <= unsigned_long_size * 8:
        size = unsigned_long_size
    elif bit_length <= unsigned_long_long_size * 8:
        size = unsigned_long_long_size
    else:
        raise ValueError("value too large")
    bytestring = value.to_bytes(size, byteorder="little")
"""
        )

        code.print()
        return

    if not args.value:
        print(ASCII_TABLE_TEXT)
        return

    for value in args.value:
        # Choose padding width based on values of sizeof(long)/sizeof(long long)
        sizeof_long: int = prog.type("unsigned long").size  # type: ignore[assignment]
        sizeof_ull: int = prog.type("unsigned long long").size  # type: ignore[assignment]

        bit_length = value.bit_length()
        if bit_length <= sizeof_long * 8:
            prlen = sizeof_long * 2
        elif bit_length <= sizeof_ull * 8:
            prlen = sizeof_ull * 2
        else:
            raise CommandArgumentError(
                f"value too large: 0x{value:x} ({bit_length} bits vs {sizeof_ull * 8})"
            )

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
