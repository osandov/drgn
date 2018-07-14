# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Simple lexer (tokenizer) library"""

import re
from typing import List, NamedTuple, Pattern, Union


class Token(NamedTuple):
    kind: str
    value: Union[str, int, None]


class Lexer:
    """
    This class implements a lexer from a regular expression and an input
    string. It is represented as a stack of tokens, where the top of the stack
    is next token in the input or a previously pushed token.

    See drgn.internal.memberdesignator and drgn.typename for examples.
    """

    def __init__(self, pattern: Pattern, string: str) -> None:
        self._tokens = pattern.finditer(string)
        self._stack: List[Token] = []

    def pop(self) -> Token:
        """Pop the token at the top of the stack and return it."""
        if self._stack:
            return self._stack.pop()

        while True:
            try:
                match = next(self._tokens)
            except StopIteration:
                return Token('EOF', None)
            kind = match.lastgroup
            value = match.group(kind)
            if kind == 'SKIP':
                pass
            elif kind == 'MISMATCH':
                raise ValueError('invalid character')
            else:
                if kind == 'NUMBER':
                    if value.startswith('0x'):
                        number = int(value, 16)
                    elif value.startswith('0'):
                        number = int(value, 8)
                    else:
                        number = int(value, 10)
                    return Token(kind, number)
                else:
                    return Token(kind, value)

    def push(self, token: Token) -> None:
        """Push a previously popped token onto the top of the stack."""
        self._stack.append(token)

    def peek(self) -> Token:
        """Return the token at the top of the stack without removing it."""
        token = self.pop()
        self.push(token)
        return token
