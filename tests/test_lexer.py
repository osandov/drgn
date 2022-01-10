# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later
from tests import TestCase
from tests.libdrgn import Lexer, drgn_test_lexer_func


class TestLexer(TestCase):
    def test_pop(self):
        lexer = Lexer(drgn_test_lexer_func, "12345")
        for i in range(5):
            self.assertEqual(lexer.pop().kind, ord("1") + i)
        self.assertEqual(lexer.pop().kind, 0)

    def test_push(self):
        lexer = Lexer(drgn_test_lexer_func, "12345")
        tokens = []
        for i in range(4):
            tokens.append(lexer.pop())
        while tokens:
            lexer.push(tokens.pop())
        for i in range(5):
            self.assertEqual(lexer.pop().kind, ord("1") + i)
        self.assertEqual(lexer.pop().kind, 0)

    def test_peek(self):
        lexer = Lexer(drgn_test_lexer_func, "12345")
        for i in range(5):
            self.assertEqual(lexer.peek().kind, ord("1") + i)
            self.assertEqual(lexer.pop().kind, ord("1") + i)
        self.assertEqual(lexer.peek().kind, 0)
        self.assertEqual(lexer.pop().kind, 0)
