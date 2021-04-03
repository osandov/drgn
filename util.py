# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import total_ordering
import os
from pathlib import Path
import re
from typing import Union


def nproc() -> int:
    return len(os.sched_getaffinity(0))


def out_of_date(path: Union[str, Path], *deps: Union[str, Path]) -> bool:
    try:
        mtime = os.stat(path).st_mtime
    except FileNotFoundError:
        return True
    return any(os.stat(dep).st_mtime > mtime for dep in deps)


def _c_isdigit(c: int) -> bool:
    # '0' <= c <= '9'
    return 0x30 <= c <= 0x39


def _c_isalpha(c: int) -> bool:
    # ('A' <= c <= 'Z') or ('a' <= c <= 'z')
    return (0x41 <= c <= 0x5A) or (0x61 <= c <= 0x7A)


def _order(c: int) -> int:
    if _c_isdigit(c):
        return 0
    elif _c_isalpha(c):
        return c
    elif c == 0x7E:  # '~'
        return -1
    else:
        return c + 0x100


def verrevcmp(v1: str, v2: str) -> int:
    """
    Compare two versions according to the coreutils version sort rules
    (https://www.gnu.org/software/coreutils/manual/html_node/Version_002dsort-ordering-rules.html).
    Returns 0 if v1 == v2 by this definition, < 0 if v1 < v2, and > 0 if v1 >
    v2.

    Adapted from
    https://git.savannah.gnu.org/cgit/gnulib.git/tree/lib/filevercmp.c.
    """
    # By definition, version sort compares ASCII, not Unicode:
    # https://www.gnu.org/software/coreutils/manual/html_node/Version-sort-ignores-locale.html.
    s1 = bytearray(v1, "utf-8")
    s2 = bytearray(v2, "utf-8")
    s1_len = len(s1)
    s2_len = len(s2)
    # Add sentinels to avoid some length checks.
    s1.append(0)
    s2.append(0)
    s1_pos = s2_pos = 0
    while s1_pos < s1_len or s2_pos < s2_len:
        while (s1_pos < s1_len and not _c_isdigit(s1[s1_pos])) or (
            s2_pos < s2_len and not _c_isdigit(s2[s2_pos])
        ):
            s1_c = _order(s1[s1_pos]) if s1_pos < s1_len else 0
            s2_c = _order(s2[s2_pos]) if s2_pos < s2_len else 0
            if s1_c != s2_c:
                return s1_c - s2_c
            s1_pos += 1
            s2_pos += 1
        while s1[s1_pos] == 0x30:  # '0'
            s1_pos += 1
        while s2[s2_pos] == 0x30:  # '0'
            s2_pos += 1
        first_diff = 0
        while _c_isdigit(s1[s1_pos]) and _c_isdigit(s2[s2_pos]):
            if not first_diff:
                first_diff = s1[s1_pos] - s2[s2_pos]
            s1_pos += 1
            s2_pos += 1
        if _c_isdigit(s1[s1_pos]):
            return 1
        if _c_isdigit(s2[s2_pos]):
            return -1
        if first_diff:
            return first_diff
    return 0


@total_ordering
class KernelVersion:
    """
    Version ordered by verrevcmp(), with -rc releases before the final release.
    """

    def __init__(self, release: str) -> None:
        # ~ sorts before anything, including the end of the version.
        self._key = re.sub(r"-(rc[0-9])", r"~\1", release)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KernelVersion):
            return NotImplemented
        return self._key == other._key

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, KernelVersion):
            return NotImplemented
        return verrevcmp(self._key, other._key) < 0
