# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import re
from typing import List, NamedTuple, Pattern, Union


class Token(NamedTuple):
    kind: str
    value: Union[str, int, None]


class Lexer:
    def __init__(self, pattern: Pattern, string: str) -> None:
        self._tokens = pattern.finditer(string)
        self._stack: List[Token] = []

    def pop(self) -> Token:
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
        self._stack.append(token)

    def peek(self) -> Token:
        token = self.pop()
        self.push(token)
        return token
