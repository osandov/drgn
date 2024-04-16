# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ctypes
import os

import _drgn

_drgn_cdll = ctypes.CDLL(_drgn.__file__)


class _drgn_error(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint),
        ("errnum", ctypes.c_int),
        ("path", ctypes.c_char_p),
        ("msg", ctypes.c_char_p),
    ]


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
