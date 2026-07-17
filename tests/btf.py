# Copyright (c) 2026 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later

import enum
import struct
from typing import NamedTuple, Optional, Sequence


class BTF_KIND(enum.IntEnum):
    UNKN = 0
    INT = 1
    PTR = 2
    ARRAY = 3
    STRUCT = 4
    UNION = 5
    ENUM = 6
    FWD = 7
    TYPEDEF = 8
    VOLATILE = 9
    CONST = 10
    RESTRICT = 11
    FUNC = 12
    FUNC_PROTO = 13
    VAR = 14
    DATASEC = 15
    FLOAT = 16
    DECL_TAG = 17
    TYPE_TAG = 18
    ENUM64 = 19


class BTF_INT(enum.IntFlag):
    SIGNED = 1 << 0
    CHAR = 1 << 1
    BOOL = 1 << 2


class BTF_VAR(enum.IntEnum):
    STATIC = 0
    GLOBAL_ALLOCATED = 1
    GLOBAL_EXTERN = 2


class BTF_FUNC(enum.IntEnum):
    STATIC = 0
    GLOBAL = 1
    EXTERN = 2


class BtfMember(NamedTuple):
    name: Optional[str]
    type: int
    offset: int
    bitfield_size: int = 0


class BtfEnum(NamedTuple):
    name: str
    value: int


class BtfParam(NamedTuple):
    name: Optional[str]
    type: int


class BtfVarSecinfo(NamedTuple):
    type: int
    offset: int
    size: int


class BtfType(NamedTuple):
    kind: BTF_KIND
    name: Optional[str] = None
    size_type: int = 0
    vlen: int = 0
    kflag: bool = False
    data: object = ()


class CompiledBtf(NamedTuple):
    data: bytes
    nr_types: int
    strings_len: int


def btf_int(
    name: str,
    *,
    bits: int,
    signed: bool = False,
    char: bool = False,
    bool: bool = False,
    offset: int = 0,
    size: int = 0,
) -> BtfType:
    encoding = (
        (BTF_INT.SIGNED if signed else 0)
        | (BTF_INT.CHAR if char else 0)
        | (BTF_INT.BOOL if bool else 0)
    )
    # Automatically determine byte size
    if size == 0:
        size = (bits + 7) // 8
    return BtfType(
        BTF_KIND.INT,
        name,
        size,
        data=(int(encoding) << 24) | (offset << 16) | bits,
    )


def btf_ptr(type: int) -> BtfType:
    return BtfType(BTF_KIND.PTR, size_type=type)


def btf_array(type: int, index_type: int, nelems: int) -> BtfType:
    return BtfType(BTF_KIND.ARRAY, data=(type, index_type, nelems))


def btf_member(
    name: Optional[str], type: int, offset: int, *, bitfield_size: int = 0
) -> BtfMember:
    return BtfMember(name, type, offset, bitfield_size)


def _btf_compound(
    kind: BTF_KIND,
    name: str,
    size: int,
    members: Sequence[BtfMember],
    *,
    kflag: bool = False,
) -> BtfType:
    return BtfType(
        kind,
        name,
        size,
        len(members),
        kflag or any(member.bitfield_size for member in members),
        tuple(members),
    )


def btf_struct(
    name: str, size: int, members: Sequence[BtfMember] = (), kflag: bool = False
) -> BtfType:
    return _btf_compound(BTF_KIND.STRUCT, name, size, members, kflag=kflag)


def btf_union(
    name: str, size: int, members: Sequence[BtfMember] = (), kflag: bool = False
) -> BtfType:
    return _btf_compound(BTF_KIND.UNION, name, size, members, kflag=kflag)


def btf_enum(
    name: str, size: int, values: Sequence[BtfEnum] = (), *, signed: bool = False
) -> BtfType:
    return BtfType(BTF_KIND.ENUM, name, size, len(values), signed, tuple(values))


def btf_fwd(name: str, *, is_union: bool = False) -> BtfType:
    return BtfType(BTF_KIND.FWD, name, kflag=is_union)


def btf_typedef(name: str, type: int) -> BtfType:
    return BtfType(BTF_KIND.TYPEDEF, name, type)


def btf_volatile(type: int) -> BtfType:
    return BtfType(BTF_KIND.VOLATILE, None, type)


def btf_const(type: int) -> BtfType:
    return BtfType(BTF_KIND.CONST, None, type)


def btf_restrict(type: int) -> BtfType:
    return BtfType(BTF_KIND.RESTRICT, None, type)


def btf_func(name: str, proto: int, *, vlen: BTF_FUNC = BTF_FUNC.STATIC) -> BtfType:
    return BtfType(BTF_KIND.FUNC, name, proto, int(vlen))


def btf_param(name: Optional[str], type: int) -> BtfParam:
    return BtfParam(name, type)


def btf_func_proto(ret: int, params: Sequence[BtfParam] = ()) -> BtfType:
    return BtfType(
        BTF_KIND.FUNC_PROTO, size_type=ret, vlen=len(params), data=tuple(params)
    )


def btf_var(name: str, type: int, *, linkage: BTF_VAR = BTF_VAR.STATIC) -> BtfType:
    return BtfType(BTF_KIND.VAR, name, type, data=int(linkage))


def btf_var_secinfo(type: int, offset: int, size: int) -> BtfVarSecinfo:
    return BtfVarSecinfo(type, offset, size)


def btf_datasec(
    name: str, size: int, variables: Sequence[BtfVarSecinfo] = ()
) -> BtfType:
    return BtfType(BTF_KIND.DATASEC, name, size, len(variables), data=tuple(variables))


def btf_float(name: str, size: int) -> BtfType:
    return BtfType(BTF_KIND.FLOAT, name, size)


def btf_decl_tag(name: str, type: int, component_idx: int = -1) -> BtfType:
    return BtfType(BTF_KIND.DECL_TAG, name, type, data=component_idx)


def btf_type_tag(name: str, type: int) -> BtfType:
    return BtfType(BTF_KIND.TYPE_TAG, name, type)


def btf_enum64(
    name: str, size: int, values: Sequence[BtfEnum] = (), *, signed: bool = False
) -> BtfType:
    return BtfType(BTF_KIND.ENUM64, name, size, len(values), signed, tuple(values))


def btf_compile(
    types: Sequence[BtfType],
    *,
    little_endian: bool = True,
    base: Optional[CompiledBtf] = None,
) -> CompiledBtf:
    endian = "<" if little_endian else ">"
    u32 = struct.Struct(endian + "I")
    type_struct = struct.Struct(endian + "III")
    strings = bytearray(b"\0")
    string_offsets = {None: 0, "": 0}
    start_str = 0
    if base:
        start_str += base.strings_len

    def string_offset(name: Optional[str]) -> int:
        try:
            return string_offsets[name]
        except KeyError:
            assert name is not None
            offset = start_str + len(strings)
            string_offsets[name] = offset
            strings.extend(name.encode())
            strings.append(0)
            return offset

    type_data = bytearray()
    for type in types:
        info = type.vlen | (int(type.kind) << 24) | (int(type.kflag) << 31)
        type_data.extend(
            type_struct.pack(string_offset(type.name), info, type.size_type)
        )
        if type.kind == BTF_KIND.INT:
            type_data.extend(u32.pack(type.data))
        elif type.kind == BTF_KIND.ARRAY:
            type_data.extend(struct.pack(endian + "III", *type.data))
        elif type.kind in (BTF_KIND.STRUCT, BTF_KIND.UNION):
            for member in type.data:
                offset = member.offset | (member.bitfield_size << 24)
                type_data.extend(
                    struct.pack(
                        endian + "III", string_offset(member.name), member.type, offset
                    )
                )
        elif type.kind in (BTF_KIND.ENUM, BTF_KIND.ENUM64):
            for value in type.data:
                if type.kind == BTF_KIND.ENUM:
                    type_data.extend(
                        struct.pack(
                            endian + "Ii", string_offset(value.name), value.value
                        )
                    )
                else:
                    type_data.extend(
                        struct.pack(
                            endian + "III",
                            string_offset(value.name),
                            value.value & 0xFFFFFFFF,
                            value.value >> 32 & 0xFFFFFFFF,
                        )
                    )
        elif type.kind == BTF_KIND.FUNC_PROTO:
            for param in type.data:
                type_data.extend(
                    struct.pack(endian + "II", string_offset(param.name), param.type)
                )
        elif type.kind in (BTF_KIND.VAR, BTF_KIND.DECL_TAG):
            type_data.extend(
                struct.pack(
                    endian + ("I" if type.kind == BTF_KIND.VAR else "i"), type.data
                )
            )
        elif type.kind == BTF_KIND.DATASEC:
            for variable in type.data:
                type_data.extend(struct.pack(endian + "III", *variable))

    # fmt: off
    header = struct.pack(
        endian + "HBBIIIII",
        0xEB9F,              # BTF_MAGIC
        1,                   # BTF_VERSION == 1
        0,                   # flags... unused?
        24,                  # header length
        0,                   # offset of type section
        len(type_data),      # length of type section
        len(type_data),      # offset of string section
        len(strings),        # length of string section
    )
    # fmt: on
    data = header + type_data + strings
    return CompiledBtf(data, len(types), len(strings))
