# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import enum
from enum import auto
import os

import _drgn
import drgn

_drgn_pydll = ctypes.PyDLL(_drgn.__file__)
_drgn_cdll = ctypes.CDLL(_drgn.__file__)


class _drgn_error(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint),
        ("errnum", ctypes.c_int),
        ("path", ctypes.c_char_p),
        ("msg", ctypes.c_char_p),
    ]


_drgn_pydll.set_drgn_error.restype = ctypes.c_void_p
_drgn_pydll.set_drgn_error.argtypes = [ctypes.POINTER(_drgn_error)]


def _check_err(err):
    if err:
        _drgn_pydll.set_drgn_error(err)


class _path_iterator_component(ctypes.Structure):
    _fields_ = [
        ("path", ctypes.c_char_p),
        ("len", ctypes.c_size_t),
    ]


class _path_iterator(ctypes.Structure):
    _fields_ = [
        ("components", ctypes.POINTER(_path_iterator_component)),
        ("num_components", ctypes.c_size_t),
        ("dot_dot", ctypes.c_size_t),
    ]


_drgn_cdll.drgn_test_path_iterator_next.restype = ctypes.c_bool
_drgn_cdll.drgn_test_path_iterator_next.argtypes = [
    ctypes.POINTER(_path_iterator),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_char)),
    ctypes.POINTER(ctypes.c_size_t),
]


class PathIterator:
    def __init__(self, *paths):
        components = (_path_iterator_component * len(paths))()
        for i, path in enumerate(paths):
            path = os.fsencode(path)
            components[i].path = path
            components[i].len = len(path)
        self._it = _path_iterator(components, len(paths))

    def __iter__(self):
        return self

    def __next__(self):
        component = ctypes.POINTER(ctypes.c_char)()
        component_len = ctypes.c_size_t()
        if _drgn_cdll.drgn_test_path_iterator_next(
            ctypes.pointer(self._it),
            ctypes.pointer(component),
            ctypes.pointer(component_len),
        ):
            return os.fsdecode(ctypes.string_at(component, component_len.value))
        else:
            raise StopIteration()


_drgn_cdll.drgn_test_path_ends_with.restype = ctypes.c_bool
_drgn_cdll.drgn_test_path_ends_with.argtypes = [
    ctypes.POINTER(_path_iterator),
    ctypes.POINTER(_path_iterator),
]


def path_ends_with(path1: PathIterator, path2: PathIterator):
    return _drgn_cdll.drgn_test_path_ends_with(
        ctypes.pointer(path1._it), ctypes.pointer(path2._it)
    )


class _drgn_type(ctypes.Structure):
    pass


class _drgn_qualified_type(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.POINTER(_drgn_type)),
        ("qualifiers", ctypes.c_uint),
    ]


class _drgn_token(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_int),
        ("value", ctypes.c_void_p),
        ("len", ctypes.c_size_t),
    ]


class _drgn_lexer(ctypes.Structure):
    _fields_ = [
        ("func", ctypes.c_void_p),
        ("p", ctypes.c_void_p),
        ("stack", ctypes.POINTER(_drgn_token)),
        ("stack_len", ctypes.c_size_t),
        ("stack_capacity", ctypes.c_size_t),
    ]


drgn_lexer_func = ctypes.CFUNCTYPE(
    ctypes.POINTER(_drgn_error),
    ctypes.POINTER(_drgn_lexer),
    ctypes.POINTER(_drgn_token),
)


_drgn_cdll.drgn_test_lexer_init.restype = None
_drgn_cdll.drgn_test_lexer_init.argtypes = [
    ctypes.POINTER(_drgn_lexer),
    ctypes.POINTER(drgn_lexer_func),
    ctypes.c_char_p,
]
_drgn_cdll.drgn_test_lexer_deinit.restype = None
_drgn_cdll.drgn_test_lexer_deinit.argtypes = [ctypes.POINTER(_drgn_lexer)]
_drgn_cdll.drgn_test_lexer_pop.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_lexer_pop.argtypes = [
    ctypes.POINTER(_drgn_lexer),
    ctypes.POINTER(_drgn_token),
]
_drgn_cdll.drgn_test_lexer_push.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_lexer_push.argtypes = [
    ctypes.POINTER(_drgn_lexer),
    ctypes.POINTER(_drgn_token),
]
_drgn_cdll.drgn_test_lexer_peek.restype = ctypes.POINTER(_drgn_error)
_drgn_cdll.drgn_test_lexer_peek.argtypes = [
    ctypes.POINTER(_drgn_lexer),
    ctypes.POINTER(_drgn_token),
]


drgn_lexer_c = drgn_lexer_func.in_dll(_drgn_cdll, "drgn_test_lexer_c")
drgn_test_lexer_func = drgn_lexer_func.in_dll(_drgn_cdll, "drgn_test_lexer_func")


class C_TOKEN(enum.IntEnum):
    EOF = -1
    VOID = auto()
    CHAR = auto()
    SHORT = auto()
    INT = auto()
    LONG = auto()
    SIGNED = auto()
    UNSIGNED = auto()
    BOOL = auto()
    FLOAT = auto()
    DOUBLE = auto()
    COMPLEX = auto()
    CONST = auto()
    RESTRICT = auto()
    VOLATILE = auto()
    ATOMIC = auto()
    STRUCT = auto()
    UNION = auto()
    ENUM = auto()
    LPAREN = auto()
    RPAREN = auto()
    LBRACKET = auto()
    RBRACKET = auto()
    ASTERISK = auto()
    DOT = auto()
    NUMBER = auto()
    IDENTIFIER = auto()


class Token:
    def __init__(self, token):
        self._token = token

    @property
    def kind(self):
        return self._token.kind

    @property
    def value(self):
        return ctypes.string_at(self._token.value, self._token.len).decode()

    def __repr__(self):
        return f"Token({self.kind}, {self.value!r})"


class Lexer:
    def __init__(self, func, str):
        self._lexer = _drgn_lexer()
        self._func = func
        self._str = str.encode()
        _drgn_cdll.drgn_test_lexer_init(
            ctypes.pointer(self._lexer), self._func, self._str
        )

    def __del__(self):
        _drgn_cdll.drgn_test_lexer_deinit(ctypes.pointer(self._lexer))

    def pop(self):
        token = _drgn_token()
        _check_err(
            _drgn_cdll.drgn_test_lexer_pop(
                ctypes.pointer(self._lexer), ctypes.pointer(token)
            )
        )
        return Token(token)

    def push(self, token):
        _check_err(
            _drgn_cdll.drgn_test_lexer_push(
                ctypes.pointer(self._lexer), ctypes.pointer(token._token)
            )
        )

    def peek(self):
        token = _drgn_token()
        _check_err(
            _drgn_cdll.drgn_test_lexer_peek(
                ctypes.pointer(self._lexer), ctypes.pointer(token)
            )
        )
        return Token(token)


_drgn_cdll.drgn_test_serialize_bits.restype = None
_drgn_cdll.drgn_test_serialize_bits.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_uint8,
    ctypes.c_bool,
]
_drgn_cdll.drgn_test_deserialize_bits.restype = ctypes.c_uint64
_drgn_cdll.drgn_test_deserialize_bits.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.c_uint8,
    ctypes.c_bool,
]


def serialize_bits(buf, bit_offset, uvalue, bit_size, little_endian):
    assert (bit_offset + bit_size + 7) // 8 <= len(buf)
    c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
    return _drgn_cdll.drgn_test_serialize_bits(
        c_buf, bit_offset, uvalue, bit_size, little_endian
    )


def deserialize_bits(buf, bit_offset, bit_size, little_endian):
    assert (bit_offset + bit_size + 7) // 8 <= len(buf)
    c_buf = (ctypes.c_char * len(buf)).from_buffer_copy(buf)
    return _drgn_cdll.drgn_test_deserialize_bits(
        c_buf, bit_offset, bit_size, little_endian
    )
