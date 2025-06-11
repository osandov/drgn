# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import re

from _drgn_util.argparseformatter import MultilineHelpFormatter
from tests import TestCase


# We have separate unit tests for multiline_{wrap,fill}(), so just test that
# the integration with argparse works. This is especially important since all
# of HelpFormatter is considered an implementation detail.
class TestMultilineHelpFormatter(TestCase):
    LINES = [
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
        "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
    ]

    def test_description(self):
        parser = argparse.ArgumentParser(
            description="\n".join(["|" + line for line in self.LINES]),
            formatter_class=MultilineHelpFormatter,
        )
        regex = re.compile(
            r"\n".join([f" *{re.escape(line)} *" for line in self.LINES]),
            flags=re.MULTILINE,
        )
        self.assertRegex(parser.format_help(), regex)

    def test_argument_help(self):
        parser = argparse.ArgumentParser(formatter_class=MultilineHelpFormatter)
        parser.add_argument(
            "--foo", help="\n".join(["|" + line for line in self.LINES])
        )
        regex = re.compile(
            r"\n".join([f" *{re.escape(line)} *" for line in self.LINES]),
            flags=re.MULTILINE,
        )
        self.assertRegex(parser.format_help(), regex)
