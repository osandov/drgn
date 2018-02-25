from collections import namedtuple
import re


class TypeSpecifier:
    def __init__(self, data_type=None, size=None, sign=None, qualifiers=None):
        self.data_type = data_type
        self.size = size
        self.sign = sign
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

    def __repr__(self):
        parts = ['TypeSpecifier(', repr(self.data_type)]
        if self.size is not None:
            parts.append(', size=')
            parts.append(repr(self.size))
        if self.sign is not None:
            parts.append(', sign=')
            parts.append(repr(self.sign))
        if self.qualifiers:
            parts.append(', qualifiers=')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self):
        parts = []
        if self.qualifiers:
            parts.append(' '.join(sorted(self.qualifiers)))
        if self.size is not None:
            parts.append(self.size)
        if self.sign is not None:
            parts.append(self.sign)
        parts.append(self.data_type)
        return ' '.join(parts)

    def __bool__(self):
        return (self.data_type is not None or self.size is not None or
                self.sign is not None or bool(self.qualifiers))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__

    @staticmethod
    def SpecifierError(old_specifier, new_specifier):
        return ValueError(f"cannot combine {new_specifier!r} with {old_specifier!r}")

    def add_specifier(self, specifier):
        if specifier == 'long' or specifier == 'short':
            if self.data_type is not None and self.data_type != 'int':
                raise self.SpecifierError(self.data_type, specifier)
            elif self.size == 'long' and specifier == 'long':
                self.size = 'long long'
            elif self.size is None:
                self.size = specifier
            else:
                raise self.SpecifierError(self.size, specifier)
        elif specifier == 'signed' or specifier == 'unsigned':
            if (self.data_type is not None and self.data_type != 'int' and
                self.data_type != 'char' and self.data_type != '_Complex'):
                raise self.SpecifierError(self.data_type, specifier)
            elif self.sign is None:
                self.sign = specifier
            else:
                raise self.SpecifierError(self.sign, specifier)
        else:
            if self.data_type is not None:
                raise self.SpecifierError(self.data_type, specifier)
            elif self.size is not None and specifier != 'int':
                raise self.SpecifierError(self.size, specifier)
            elif (self.sign is not None and specifier != 'int' and
                  specifier != 'char' and specifier != '_Complex'):
                raise self.SpecifierError(self.sign, specifier)
            self.data_type = specifier


def _type_str(type_, suffix=''):
    if isinstance(type_, ArrayType):
        if type_.size is None:
            suffix += '[]'
        else:
            suffix += f'[{type_.size}]'
        return _type_str(type_.type, suffix)
    elif isinstance(type_, PointerType):
        if type_.qualifiers:
            if suffix:
                suffix = ' ' + suffix
            suffix = '* ' + ''.join(sorted(type_.qualifiers)) + suffix
        else:
            suffix = '*' + suffix
        if isinstance(type_.type, ArrayType):
            suffix = '(' + suffix + ')'
        return _type_str(type_.type, suffix)
    else:
        assert isinstance(type_, TypeSpecifier)
        return str(type_) + ' ' + suffix


class PointerType:
    def __init__(self, type, qualifiers=None):
        self.type = type
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

    def __repr__(self):
        parts = ['PointerType(', repr(self.type)]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self):
        return _type_str(self)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__


class ArrayType:
    def __init__(self, type, size=None):
        self.type = type
        self.size = size

    def __repr__(self):
        parts = ['ArrayType(', repr(self.type)]
        if self.size is not None:
            parts.append(', ')
            parts.append(repr(self.size))
        parts.append(')')
        return ''.join(parts)

    def __str__(self):
        return _type_str(self)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__dict__ == other.__dict__


class _TypeNameLexer:
    TOKEN_REGEX = re.compile('|'.join('(?P<%s>%s)' % pair for pair in [
        ('SPECIFIER',  r'void|char|short|int|long|float|double|signed|unsigned|_Bool|_Complex'),
        ('QUALIFIER',  r'const|restrict|volatile|_Atomic'),
        ('TAG',        r'enum|struct|union'),
        ('IDENTIFIER', r'[a-zA-Z_][a-zA-Z0-9_]*'),
        ('NUMBER',     r'(?:0x)?[0-9]+'),
        ('LPAREN',     r'\('),
        ('RPAREN',     r'\)'),
        ('LBRACKET',   r'\['),
        ('RBRACKET',   r']'),
        ('ASTERISK',   r'\*'),
        ('SKIP',       r'[ \t\n\r\f\v]+'),
        ('MISMATCH',   r'.'),
    ]))
    Token = namedtuple('Token', ['kind', 'value'])

    def __init__(self, str):
        self._tokens = _TypeNameLexer.TOKEN_REGEX.finditer(str)
        self._stack = []

    def pop(self):
        if self._stack:
            return self._stack.pop()

        while True:
            try:
                match = next(self._tokens)
            except StopIteration:
                return _TypeNameLexer.Token('EOF', None)
            kind = match.lastgroup
            value = match.group(kind)
            if kind == 'SKIP':
                pass
            elif kind == 'MISMATCH':
                raise ValueError('invalid character')
            else:
                if kind == 'NUMBER':
                    if value.startswith('0x'):
                        value = int(value, 16)
                    elif value.startswith('0'):
                        value = int(value, 8)
                    else:
                        value = int(value, 10)
                return _TypeNameLexer.Token(kind, value)

    def push(self, token):
        self._stack.append(token)

    def peek(self):
        token = self.pop()
        self.push(token)
        return token


class _TypeNameParser:
    def __init__(self, lexer):
        self._lexer = lexer

    def parse(self):
        type_ = self._parse_specifier_qualifier_list()
        if self._lexer.peek().kind != 'EOF':
            type_ = self._parse_abstract_declarator(type_)[0]
            if self._lexer.peek().kind != 'EOF':
                raise ValueError('extra tokens after type name')
        return type_

    def _parse_specifier_qualifier_list(self):
        specifier = TypeSpecifier()
        while True:
            token = self._lexer.peek()
            # type-qualifier
            if token.kind == 'QUALIFIER':
                self._lexer.pop()
                specifier.qualifiers.add(token.value)
            # type-specifier
            elif token.kind == 'SPECIFIER' or token.kind == 'IDENTIFIER':
                self._lexer.pop()
                specifier.add_specifier(token.value)
            elif token.kind == 'TAG':
                self._lexer.pop()
                token2 = self._lexer.pop()
                if token2.kind != 'IDENTIFIER':
                    raise ValueError(f'expected identifier after {token.value}')
                specifier.add_specifier(token.value + ' ' + token2.value)
            else:
                break
        if not specifier:
            raise ValueError('expected type specifier')
        if specifier.data_type is None:
            specifier.data_type = 'int'
        return specifier

    def _parse_abstract_declarator(self, type_):
        if self._lexer.peek().kind == 'ASTERISK':
            type_, inner_type = self._parse_pointer(type_)
            token = self._lexer.peek()
            if token.kind == 'LPAREN' or token.kind == 'LBRACKET':
                type_ = self._parse_direct_abstract_declarator(type_)[0]
            return type_, inner_type
        else:
            return self._parse_direct_abstract_declarator(type_)

    def _parse_pointer(self, type_):
        if self._lexer.peek().kind != 'ASTERISK':
            raise ValueError("expected '*'")
        inner_type = None
        while self._lexer.peek().kind == 'ASTERISK':
            self._lexer.pop()
            qualifiers = self._parse_optional_type_qualifier_list()
            type_ = PointerType(type_, qualifiers)
            if inner_type is None:
                inner_type = type_
        return type_, inner_type

    def _parse_optional_type_qualifier_list(self):
        qualifiers = set()
        while True:
            token = self._lexer.peek()
            if token.kind != 'QUALIFIER':
                break
            self._lexer.pop()
            qualifiers.add(token.value)
        return qualifiers

    def _parse_direct_abstract_declarator(self, type_):
        inner_type = None
        token = self._lexer.peek()
        if token.kind == 'LPAREN':
            self._lexer.pop()
            token2 = self._lexer.peek()
            if (token2.kind == 'ASTERISK' or token2.kind == 'LPAREN' or
                token2.kind == 'LBRACKET'):
                type_, inner_type = self._parse_abstract_declarator(type_)
                if self._lexer.pop().kind != 'RPAREN':
                    raise ValueError("expected ')'")
            else:
                self._lexer.push(token2)
                self._lexer.push(token)

        while True:
            token = self._lexer.peek()
            if token.kind == 'LBRACKET':
                self._lexer.pop()
                token = self._lexer.peek()
                if token.kind == 'NUMBER':
                    self._lexer.pop()
                    size = token.value
                else:
                    size = None
                if inner_type is None:
                    type_ = inner_type = ArrayType(type_, size)
                else:
                    inner_type.type = ArrayType(inner_type.type, size)
                    inner_type = inner_type.type
                if self._lexer.pop().kind != 'RBRACKET':
                    raise ValueError("expected ']'")
            elif token.kind == 'LPAREN':
                raise NotImplementedError('function pointer types are not implemented')
            elif inner_type is None:
                raise ValueError('expected abstract declarator')
            else:
                return type_, inner_type


def parse_type_name(str):
    return _TypeNameParser(_TypeNameLexer(str)).parse()
