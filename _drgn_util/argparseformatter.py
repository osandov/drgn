# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from typing import List


class MultilineHelpFormatter(argparse.HelpFormatter):
    """
    argparse help formatter that supports multiple paragraphs/line blocks and
    doesn't collapse consecutive whitespace.

    '''
    This is a paragraph, which will
    be wrapped.

    |This is a line block.
    |It will not be wrapped.
    '''

    See :func:`_drgn_util.multilinewrap.multiline_wrap()` for details.
    """

    def _split_lines(self, text: str, width: int) -> List[str]:
        # argparse makes a point of not importing textwrap unless necessary, so
        # we do the same.
        from _drgn_util.multilinewrap import multiline_wrap

        return multiline_wrap(text, width, indent="")

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        from _drgn_util.multilinewrap import multiline_fill

        return multiline_fill(text, width, indent=indent)
