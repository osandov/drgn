# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from _drgn_util.multilinewrap import multiline_fill, multiline_wrap
from tests import TestCase


class TestMultilineWrap(TestCase):
    def assert_wrap(self, text, lines, *, width, indent=""):
        self.assertEqual(multiline_wrap(text, width, indent=indent), lines)

    def test_one_line(self):
        self.assert_wrap(
            "Sphinx of black quartz, judge my vow.",
            [
                "Sphinx of black quartz,",
                "judge my vow.",
            ],
            width=25,
        )

    def test_one_paragraph(self):
        self.assert_wrap(
            "Sphinx of black\nquartz, judge\nmy vow.",
            [
                "Sphinx of black quartz,",
                "judge my vow.",
            ],
            width=25,
        )

    def test_dedent(self):
        self.assert_wrap(
            """
            Sphinx of black
            quartz, judge
            my vow.
            """,
            [
                "Sphinx of black quartz,",
                "judge my vow.",
            ],
            width=25,
        )

    def test_one_character_words(self):
        self.assert_wrap("A\nB\nC", ["A B C"], width=25)

    def test_leading_whitespace(self):
        self.assert_wrap("A\n B\nC", ["A  B C"], width=25)

    def test_multiple_paragraphs(self):
        self.assert_wrap(
            """
            Sphinx of black quartz, judge my vow.

            The quick brown fox jumps over the lazy dog.
            """,
            [
                "Sphinx of black quartz,",
                "judge my vow.",
                "",
                "The quick brown fox jumps",
                "over the lazy dog.",
            ],
            width=25,
        )

    def test_multiple_paragraphs_extra_whitespace(self):
        self.assert_wrap(
            """

            Sphinx of black
            quartz, judge
            my vow.


            The quick brown
            fox jumps over
            the lazy dog.

            """,
            [
                "Sphinx of black quartz,",
                "judge my vow.",
                "",
                "The quick brown fox jumps",
                "over the lazy dog.",
            ],
            width=25,
        )

    def test_line_block(self):
        self.assert_wrap(
            """
            |A B C
            |      D E F
            |G H I
            """,
            [
                "A B C",
                "      D E F",
                "G H I",
            ],
            width=1,
        )

    def test_line_block_whitespace(self):
        self.assert_wrap(
            # Use "\x20" to avoid trailing whitespace warnings.
            """
            |A B C
            |\x20
            |      D E F
            |
            |G H I
            """,
            [
                "A B C",
                " ",
                "      D E F",
                "",
                "G H I",
            ],
            width=1,
        )

    def test_line_block_and_paragraphs(self):
        self.assert_wrap(
            """
            Sphinx of black quartz, judge my vow.

            |A B C
            |      D E F
            |G H I

            The quick brown fox jumps over the lazy dog.
            """,
            [
                "Sphinx of",
                "black",
                "quartz,",
                "judge my",
                "vow.",
                "",
                "A B C",
                "      D E F",
                "G H I",
                "",
                "The quick",
                "brown fox",
                "jumps over",
                "the lazy",
                "dog.",
            ],
            width=10,
        )

    def test_line_block_in_paragraph(self):
        self.assert_wrap(
            """
            Sphinx of black quartz, judge my vow.
            |A B C
            |      D E F
            |G H I
            The quick brown fox jumps over the lazy dog.
            """,
            [
                "Sphinx of",
                "black",
                "quartz,",
                "judge my",
                "vow.",
                "A B C",
                "      D E F",
                "G H I",
                "The quick",
                "brown fox",
                "jumps over",
                "the lazy",
                "dog.",
            ],
            width=10,
        )

    def test_fill(self):
        self.assertEqual(
            multiline_fill("Sphinx of black\nquartz, judge\nmy vow.", 25),
            "Sphinx of black quartz,\njudge my vow.",
        )
