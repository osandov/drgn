# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import re
import textwrap
from typing import Any, List

from _drgn_util.typingutils import copy_func_params


def multiline_wrap(text: str, width: int, *, indent: str = "") -> List[str]:
    """
    Wrap text containing multiple paragraphs or line blocks, returning lines.

    This dedents *text* and splits it into paragraphs, which are wrapped, and
    line blocks, which are not wrapped and have their line breaks preserved.

    Paragraphs are groups of lines separated by one or more blank lines.

    Line blocks are groups of lines starting with the '|' character.

    >>> s = '''
    ... This is a paragraph, which will
    ... be wrapped.
    ...
    ... |This is a line block.
    ... |It will not be wrapped.
    ... '''
    ...
    >>> multiline_wrap(s, width=80)
    ['This is a paragraph, which will be wrapped.', '', 'This is a line block.', 'It will not be wrapped.']

    :param text: Text to wrap.
    :param width: Maximum width of lines.
    :param indent: String to prepend to each line.
    :return: List of lines (without newlines).
    """
    lines = []
    blank = False
    for match in re.finditer(
        r"""
        (?P<paragraph>
            # A paragraph is one or more lines not starting with '|' and
            # containing at least one non-whitespace character.
            (?:
                (?:
                    # Each line must start with either a non-whitespace,
                    # non-'|' character...
                    [^\s|]
                    |
                    # ... or any amount of non-newline whitespace followed by a
                    # non-whitespace character.
                    [^\S\n]+\S
                ).*(?:\n|$)
            )+
        )
        |
        (?P<lineblock>
            # A line block is one or more lines starting with '|'.
            (?:\|.*(?:\n|$))+
        )
        |
        (?:
            # Ignore one or more lines consisting of only whitespace.
            \s*(?:\n|$)
        )
        """,
        textwrap.dedent(text),
        flags=re.X,
    ):
        lastgroup = match.lastgroup
        if lastgroup == "lineblock":
            if blank:
                lines.append("")
                blank = False
            lines.extend(
                re.sub(r"^\|", "", match.group(lastgroup), flags=re.M).splitlines()
            )
        elif lastgroup == "paragraph":
            if blank:
                lines.append("")
                blank = False
            lines.extend(
                textwrap.wrap(
                    match.group(lastgroup),
                    width,
                    initial_indent=indent,
                    subsequent_indent=indent,
                )
            )
        elif lines:
            blank = True
    return lines


@copy_func_params(multiline_wrap)
def multiline_fill(*args: Any, **kwargs: Any) -> str:
    r"""
    Wrap text containing multiple paragraphs or line blocks, returning a
    string.

    This is equivalent to

    .. code-block:: python3

        "\n".join(multiline_wrap(text, ...))

    >>> s = '''
    ... This is a paragraph, which will
    ... be wrapped.
    ...
    ... |This is a line block.
    ... |It will not be wrapped.
    ... '''
    ...
    >>> print(multiline_fill(s, width=80))
    This is a paragraph, which will be wrapped.

    This is a line block.
    It will not be wrapped.

    :return: Wrapped string (without trailing newline).
    """
    return "\n".join(multiline_wrap(*args, **kwargs))
