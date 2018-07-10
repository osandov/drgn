# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import re
from typing import Iterable, List, NamedTuple


class FileMapping(NamedTuple):
    path: str
    start: int
    end: int
    file_offset: int


def parse_proc_maps(path: str) -> List[FileMapping]:
    with open(path, 'r') as f:
        s = f.read()

    l = []
    for match in re.finditer(r'^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+\S+\s+([0-9a-fA-F]+)\s+\S+\s+\S+\s+(\S+)$',
                             s, re.MULTILINE):
        path = match.group(4)
        if not path.startswith('/'):
            continue
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        file_offset = int(match.group(3), 16)
        l.append(FileMapping(path, start, end, file_offset))
    return l


def escape_character(c: int, escape_single_quote: bool = False,
                     escape_double_quote: bool = False,
                     escape_backslash: bool = False) -> str:
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


def escape_string(buffer: Iterable[int], escape_single_quote: bool = False,
                  escape_double_quote: bool = False,
                  escape_backslash: bool = False) -> str:
    return ''.join(escape_character(c, escape_single_quote=escape_single_quote,
                                    escape_double_quote=escape_double_quote,
                                    escape_backslash=escape_backslash)
                   for c in buffer)


def c_string(buffer: Iterable[int]) -> str:
    parts = ['"']
    parts.extend(escape_character(c, escape_double_quote=True,
                                  escape_backslash=True)
                 for c in buffer)
    parts.append('"')
    return ''.join(parts)
