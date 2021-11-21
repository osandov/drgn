# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

from collections import namedtuple


def _append_uleb128(buf, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            buf.append(byte | 0x80)
        else:
            buf.append(byte)
            break


def _append_sleb128(buf, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if (not value and not (byte & 0x40)) or (value == -1 and (byte & 0x40)):
            buf.append(byte)
            break
        else:
            buf.append(byte | 0x80)


U8 = namedtuple("U8", ["value"])
U8._append = lambda self, buf, byteorder: buf.append(self.value)
S8 = namedtuple("S8", ["value"])
S8._append = lambda self, buf, byteorder: buf.append(self.value & 0xFF)
U16 = namedtuple("U16", ["value"])
U16._append = lambda self, buf, byteorder: buf.extend(self.value.to_bytes(2, byteorder))
S16 = namedtuple("S16", ["value"])
S16._append = lambda self, buf, byteorder: buf.extend(
    self.value.to_bytes(2, byteorder, signed=True)
)
U32 = namedtuple("U32", ["value"])
U32._append = lambda self, buf, byteorder: buf.extend(self.value.to_bytes(4, byteorder))
S32 = namedtuple("S32", ["value"])
S32._append = lambda self, buf, byteorder: buf.extend(
    self.value.to_bytes(4, byteorder, signed=True)
)
U64 = namedtuple("U64", ["value"])
U64._append = lambda self, buf, byteorder: buf.extend(self.value.to_bytes(8, byteorder))
S64 = namedtuple("S64", ["value"])
S64._append = lambda self, buf, byteorder: buf.extend(
    self.value.to_bytes(8, byteorder, signed=True)
)
ULEB128 = namedtuple("ULEB128", ["value"])
ULEB128._append = lambda self, buf, byteorder: _append_uleb128(buf, self.value)
SLEB128 = namedtuple("SLEB128", ["value"])
SLEB128._append = lambda self, buf, byteorder: _append_sleb128(buf, self.value)


def assemble(*args, little_endian=True):
    byteorder = "little" if little_endian else "big"
    buf = bytearray()
    for arg in args:
        if isinstance(arg, bytes):
            buf.extend(arg)
        else:
            arg._append(buf, byteorder)
    return buf
