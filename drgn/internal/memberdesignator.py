# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""C syntax member designator parser"""

import enum
import re
from typing import cast, List, Tuple, Union

from drgn.internal.lexer import Lexer


@enum.unique
class _State(enum.IntEnum):
    START = 0
    IDENTIFIER = 1
    DOT = 2
    LBRACKET = 3
    NUMBER = 4
    RBRACKET = 5


_TOKEN_REGEX = re.compile('|'.join('(?P<%s>%s)' % pair for pair in [
    ('IDENTIFIER', r'[a-zA-Z_][a-zA-Z0-9_]*'),
    ('NUMBER',     r'(?:0x)?[0-9]+'),
    ('DOT',        r'\.'),
    ('LBRACKET',   r'\['),
    ('RBRACKET',   r']'),
    ('SKIP',       r'[ \t\n\r\f\v]+'),
    ('MISMATCH',   r'.'),
]))


def parse_member_designator(string: str) -> List[Tuple[str, Union[str, int]]]:
    lexer = Lexer(_TOKEN_REGEX, string)
    state = _State.START
    designator: List[Tuple[str, Union[str, int]]] = []
    while True:
        token = lexer.pop()
        if state == _State.START or state == _State.DOT:
            if token.kind == 'IDENTIFIER':
                designator.append(('.', cast(str, token.value)))
                state = _State.IDENTIFIER
            elif state == _State.DOT:
                raise ValueError("expected identifier after '.'")
            else:
                raise ValueError('expected identifier')
        elif state == _State.IDENTIFIER or state == _State.RBRACKET:
            if token.kind == 'EOF':
                break
            elif token.kind == 'DOT':
                state = _State.DOT
            elif token.kind == 'LBRACKET':
                state = _State.LBRACKET
            elif state == _State.IDENTIFIER:
                raise ValueError("expected '.' or '[' after identifier")
            else:
                raise ValueError("expected '.' or '[' after ']'")
        elif state == _State.LBRACKET:
            if token.kind == 'NUMBER':
                designator.append(('[]', cast(int, token.value)))
                state = _State.NUMBER
            else:
                raise ValueError("expected number after '['")
        elif state == _State.NUMBER:
            if token.kind == 'RBRACKET':
                state = _State.RBRACKET
            else:
                raise ValueError("expected '.' or '[' after identifier")
        else:
            assert False
    return designator
