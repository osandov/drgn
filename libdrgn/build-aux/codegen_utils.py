# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
from typing import Optional


class CodeGenError(Exception):
    def __init__(
        self,
        message: str,
        filename: str,
        lineno: Optional[int] = None,
        columnno: Optional[int] = None,
    ) -> None:
        self.message = message
        self.filename = filename
        self.lineno = lineno
        self.columnno = columnno

    def __str__(self) -> str:
        parts = [self.filename]
        if self.lineno is not None:
            parts.append(str(self.lineno))
            if self.columnno is not None:
                parts.append(str(self.columnno))
        return f"{':'.join(parts)}: error: {self.message}"


_C_ESCAPE_CHAR = []
for c in range(256):
    if c == 0:
        e = r"\0"
    elif c == 7:
        e = r"\a"
    elif c == 8:
        e = r"\b"
    elif c == 9:
        e = r"\t"
    elif c == 10:
        e = r"\n"
    elif c == 11:
        e = r"\v"
    elif c == 12:
        e = r"\f"
    elif c == 13:
        e = r"\r"
    elif c == 34:
        e = r"\""
    elif c == 39:
        e = r"\'"
    elif c == 92:
        e = r"\\"
    elif 32 <= c <= 126:
        e = chr(c)
    else:
        e = f"\\x{c:02x}"
    _C_ESCAPE_CHAR.append(e)


def c_char_ord_literal(o: int) -> str:
    """Return a C character literal for a Unicode code point."""
    if o == 34:  # ord('"')
        return "'\"'"
    elif o <= 0xFF:
        return "'" + _C_ESCAPE_CHAR[o] + "'"
    elif o <= 0xFFFF:
        return f"'\\u{o:04x}'"
    else:
        return f"'\\u{o:08x}'"


def c_bytes_literal(s: bytes) -> str:
    """Return a C string literal for a byte string."""
    result = ['"']
    for c in s:
        if c == 39:  # ord("'")
            result.append("'")
        else:
            result.append(_C_ESCAPE_CHAR[c])
    result.append('"')
    return "".join(result)


def c_string_literal(s: str) -> str:
    """Return a C string literal for a string."""
    result = ['"']
    for c in s:
        o = ord(c)
        if o == 39:  # ord("'")
            result.append("'")
        elif o <= 0xFF:
            result.append(_C_ESCAPE_CHAR[o])
        elif o <= 0xFFFF:
            result.append(f"\\u{o:04x}")
        else:
            result.append(f"\\u{o:08x}")
    result.append('"')
    return "".join(result)


def parse_c_string_literal(s: str) -> str:
    # Python string literals are close enough to C string literals for now.
    return ast.literal_eval(s)  # type: ignore[no-any-return]
