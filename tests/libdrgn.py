# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ctypes

import _drgn

_drgn_cdll = ctypes.CDLL(_drgn.__file__)


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
