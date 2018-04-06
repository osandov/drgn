from collections import namedtuple
import re
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple, Union


class TypeName:
    def __init__(self, name: str,
                 qualifiers: Optional[Set[str]] = None) -> None:
        self.name = name
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

    def __repr__(self) -> str:
        parts = [self.__class__.__name__, '(', repr(self.name)]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def __str__(self) -> str:
        return self.declaration('')

    def __eq__(self, other: Any) -> bool:
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def declaration(self, name: str) -> str:
        parts = sorted(self.qualifiers)
        parts.append(self.name)
        if name:
            parts.append(name)
        return ' '.join(parts)


class VoidTypeName(TypeName):
    def __init__(self,
                 qualifiers: Optional[Set[str]] = None) -> None:
        super().__init__('void', qualifiers)


class BasicTypeName(TypeName):
    pass


def _tagged_declaration(keyword: str, tag: str, name: str,
                        qualifiers: Set[str]) -> str:
    parts = sorted(qualifiers)
    parts.append(keyword)
    if tag:
        parts.append(tag)
    if name:
        parts.append(name)
    return ' '.join(parts)


class StructTypeName(TypeName):
    def declaration(self, name: str) -> str:
        return _tagged_declaration('struct', self.name, name, self.qualifiers)


class UnionTypeName(TypeName):
    def declaration(self, name: str) -> str:
        return _tagged_declaration('union', self.name, name, self.qualifiers)


class EnumTypeName(TypeName):
    def declaration(self, name: str) -> str:
        return _tagged_declaration('enum', self.name, name, self.qualifiers)


class TypedefTypeName(TypeName):
    pass


class PointerTypeName(TypeName):
    def __init__(self, type: TypeName,
                 qualifiers: Optional[Set[str]] = None) -> None:
        self.type = type
        if qualifiers is None:
            qualifiers = set()
        self.qualifiers = qualifiers

    def __repr__(self) -> str:
        parts = ['PointerTypeName(', repr(self.type)]
        if self.qualifiers:
            parts.append(', ')
            parts.append(repr(self.qualifiers))
        parts.append(')')
        return ''.join(parts)

    def declaration(self, name: str) -> str:
        if self.qualifiers:
            if name:
                name = ' ' + name
            name = '* ' + ''.join(sorted(self.qualifiers)) + name
        else:
            name = '*' + name
        if isinstance(self.type, ArrayTypeName):
            name = '(' + name + ')'
        return self.type.declaration(name)


class ArrayTypeName(TypeName):
    def __init__(self, type: TypeName, size: Optional[int] = None) -> None:
        self.type = type
        self.size = size

    def __repr__(self) -> str:
        parts = ['ArrayTypeName(', repr(self.type)]
        if self.size is not None:
            parts.append(', ')
            parts.append(repr(self.size))
        parts.append(')')
        return ''.join(parts)

    def declaration(self, name: str) -> str:
        if self.size is None:
            name += '[]'
        else:
            name += f'[{self.size}]'
        return self.type.declaration(name)


_TOKEN_REGEX = re.compile('|'.join('(?P<%s>%s)' % pair for pair in [
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


class _Token(NamedTuple):
    kind: str
    value: Union[str, int]


class _TypeNameLexer:

    def __init__(self, s: str) -> None:
        self._tokens = _TOKEN_REGEX.finditer(s)
        self._stack: List[_Token] = []

    def pop(self) -> _Token:
        if self._stack:
            return self._stack.pop()

        while True:
            try:
                match = next(self._tokens)
            except StopIteration:
                return _Token('EOF', None)
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
                    return _Token(kind, number)
                else:
                    return _Token(kind, value)

    def push(self, token: _Token) -> None:
        self._stack.append(token)

    def peek(self) -> _Token:
        token = self.pop()
        self.push(token)
        return token


class _TypeNameParser:
    def __init__(self, lexer: _TypeNameLexer) -> None:
        self._lexer = lexer

    def parse(self) -> TypeName:
        type_name = self._parse_specifier_qualifier_list()
        if self._lexer.peek().kind != 'EOF':
            type_name = self._parse_abstract_declarator(type_name)[0]
            if self._lexer.peek().kind != 'EOF':
                raise ValueError('extra tokens after type name')
        return type_name

    @staticmethod
    def _specifier_error(old_specifier: str, new_specifier: str) -> Exception:
        return ValueError(f"cannot combine {new_specifier!r} with {old_specifier!r}")

    @staticmethod
    def _add_specifier(specifiers: Dict[str, Any], specifier: str) -> None:
        data_type = specifiers.get('data_type')
        size = specifiers.get('size')
        sign = specifiers.get('sign')
        if specifier == 'long' or specifier == 'short':
            if size == 'long' and specifier == 'long':
                specifier = 'long long'
            elif size is not None:
                raise _TypeNameParser._specifier_error(size, specifier)
            if (data_type is not None and data_type != 'int' and
                  (data_type != 'double' or specifier != 'long')):
                raise _TypeNameParser._specifier_error(data_type, specifier)
            specifiers['size'] = specifier
        elif specifier == 'signed' or specifier == 'unsigned':
            if (data_type is not None and data_type != 'int' and
                    data_type != 'char'):
                raise _TypeNameParser._specifier_error(data_type, specifier)
            elif sign is not None:
                raise _TypeNameParser._specifier_error(sign, specifier)
            specifiers['sign'] = specifier
        else:
            if data_type is not None:
                raise _TypeNameParser._specifier_error(data_type, specifier)
            elif (size is not None and specifier != 'int' and
                  (specifier != 'double' or size != 'long')):
                raise _TypeNameParser._specifier_error(size, specifier)
            elif (sign is not None and specifier != 'int' and
                  specifier != 'char'):
                raise _TypeNameParser._specifier_error(sign, specifier)
            specifiers['data_type'] = specifier

    @staticmethod
    def _type_name_from_specifiers(specifiers: Dict[str, Any],
                                   is_typedef: bool) -> TypeName:
        data_type = specifiers['data_type']
        qualifiers = specifiers.get('qualifiers')
        if data_type.startswith('struct '):
            return StructTypeName(data_type[7:], qualifiers)
        elif data_type.startswith('union '):
            return UnionTypeName(data_type[6:], qualifiers)
        elif data_type.startswith('enum '):
            return EnumTypeName(data_type[5:], qualifiers)
        elif is_typedef:
            return TypedefTypeName(data_type, qualifiers)
        elif specifiers['data_type'] == 'void':
            return VoidTypeName(qualifiers)
        else:
            parts = []
            if 'size' in specifiers:
                parts.append(specifiers['size'])
            if ('sign' in specifiers and
                (specifiers['sign'] != 'signed' or data_type == 'char')):
                parts.append(specifiers['sign'])
            parts.append(data_type)
            return BasicTypeName(' '.join(parts), qualifiers)

    def _parse_specifier_qualifier_list(self) -> TypeName:
        specifiers: Dict[str, Any] = {}
        is_typedef = False
        while True:
            token = self._lexer.peek()
            # type-qualifier
            if token.kind == 'QUALIFIER':
                self._lexer.pop()
                try:
                    specifiers['qualifiers'].add(token.value)
                except KeyError:
                    specifiers['qualifiers'] = {token.value}
            # type-specifier
            elif token.kind == 'SPECIFIER':
                self._lexer.pop()
                assert isinstance(token.value, str)
                _TypeNameParser._add_specifier(specifiers, token.value)
            elif token.kind == 'IDENTIFIER':
                self._lexer.pop()
                assert isinstance(token.value, str)
                _TypeNameParser._add_specifier(specifiers, token.value)
                is_typedef = True
            elif token.kind == 'TAG':
                self._lexer.pop()
                token2 = self._lexer.pop()
                if token2.kind != 'IDENTIFIER':
                    raise ValueError(f'expected identifier after {token.value}')
                assert isinstance(token.value, str)
                assert isinstance(token2.value, str)
                _TypeNameParser._add_specifier(specifiers, token.value + ' ' + token2.value)
            else:
                break
        if not specifiers:
            raise ValueError('expected type specifier')
        if 'data_type' not in specifiers:
            specifiers['data_type'] = 'int'
        return _TypeNameParser._type_name_from_specifiers(specifiers, is_typedef)

    def _parse_abstract_declarator(
            self, type_name: TypeName) -> Tuple[TypeName, Union[ArrayTypeName, PointerTypeName, None]]:
        if self._lexer.peek().kind == 'ASTERISK':
            type_name, inner_type = self._parse_pointer(type_name)
            token = self._lexer.peek()
            if token.kind == 'LPAREN' or token.kind == 'LBRACKET':
                type_name = self._parse_direct_abstract_declarator(type_name)[0]
            return type_name, inner_type
        else:
            return self._parse_direct_abstract_declarator(type_name)

    def _parse_pointer(self, type_name: TypeName) -> Tuple[TypeName, Optional[PointerTypeName]]:
        if self._lexer.peek().kind != 'ASTERISK':
            raise ValueError("expected '*'")
        inner_type = None
        while self._lexer.peek().kind == 'ASTERISK':
            self._lexer.pop()
            qualifiers = self._parse_optional_type_qualifier_list()
            type_name = PointerTypeName(type_name, qualifiers)
            if inner_type is None:
                inner_type = type_name
        return type_name, inner_type

    def _parse_optional_type_qualifier_list(self) -> Set[str]:
        qualifiers = set()
        while True:
            token = self._lexer.peek()
            if token.kind != 'QUALIFIER':
                break
            self._lexer.pop()
            assert isinstance(token.value, str)
            qualifiers.add(token.value)
        return qualifiers

    def _parse_direct_abstract_declarator(
            self, type_name: TypeName) -> Tuple[TypeName, Union[ArrayTypeName, PointerTypeName, None]]:
        inner_type = None
        token = self._lexer.peek()
        if token.kind == 'LPAREN':
            self._lexer.pop()
            token2 = self._lexer.peek()
            if (token2.kind == 'ASTERISK' or token2.kind == 'LPAREN' or
                token2.kind == 'LBRACKET'):
                type_name, inner_type = self._parse_abstract_declarator(type_name)
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
                    assert isinstance(token.value, int)
                    size = token.value
                else:
                    size = None
                if inner_type is None:
                    type_name = inner_type = ArrayTypeName(type_name, size)
                else:
                    inner_type.type = ArrayTypeName(inner_type.type, size)
                    inner_type = inner_type.type
                if self._lexer.pop().kind != 'RBRACKET':
                    raise ValueError("expected ']'")
            elif token.kind == 'LPAREN':
                raise NotImplementedError('function pointer types are not implemented')
            elif inner_type is None:
                raise ValueError('expected abstract declarator')
            else:
                return type_name, inner_type


def parse_type_name(s: str) -> TypeName:
    return _TypeNameParser(_TypeNameLexer(s)).parse()
