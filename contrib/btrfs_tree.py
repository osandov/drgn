# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import enum
import struct
from typing import NamedTuple, Sequence
import uuid

import drgn
from drgn import NULL, cast, offsetof
from drgn.helpers.linux.mm import page_to_virt
from drgn.helpers.linux.radixtree import radix_tree_lookup

"""Helpers for introspecting btrfs btree structures"""

page_address = page_to_virt


_crc32c_table = [0] * 256
for i in range(256):
    fwd = i
    for j in range(8, 0, -1):
        if fwd & 1:
            fwd = (fwd >> 1) ^ 0x82f63b78
        else:
            fwd >>= 1
    _crc32c_table[i] = fwd & 0xffffffff


def crc32c(b: bytes, crc: int = 0) -> int:
    for c in b:
        crc = (crc >> 8) ^ _crc32c_table[(crc ^ c) & 0xff]
    return crc


def btrfs_name_hash(name: bytes) -> int:
    return crc32c(name, 0xfffffffe)


_btrfs_disk_key_fmt = "<QBQ"
_btrfs_disk_key_struct = struct.Struct(_btrfs_disk_key_fmt)
_btrfs_item_struct = struct.Struct(_btrfs_disk_key_fmt + "II")
_btrfs_header_struct = struct.Struct("<32s16sQQ16sQQIB")
_btrfs_key_ptr_struct = struct.Struct(_btrfs_disk_key_fmt + "QQ")


class BtrfsDiskKey(NamedTuple):
    objectid: int
    type: int
    offset: int

    @staticmethod
    def from_bytes(b, offset=0):
        return BtrfsDiskKey(*_btrfs_disk_key_struct.unpack_from(b, offset))

    @staticmethod
    def sizeof():
        return _btrfs_disk_key_struct.size


class BtrfsKeyPtr(NamedTuple):
    key: BtrfsDiskKey
    blockptr: int
    generation: int

    @staticmethod
    def from_bytes(b, offset=0):
        t = _btrfs_key_ptr_struct.unpack_from(b, offset)
        return BtrfsKeyPtr(BtrfsDiskKey(*t[:3]), *t[3:])

    @staticmethod
    def sizeof():
        return _btrfs_key_ptr_struct.size


class BtrfsHeader(NamedTuple):
    csum: bytes
    fsid: bytes
    bytenr: int
    flags: int
    chunk_tree_uuid: bytes
    generation: int
    owner: int
    nritems: int
    level: int

    @staticmethod
    def from_bytes(b, offset=0):
        return BtrfsHeader(*_btrfs_header_struct.unpack_from(b, offset))

    @staticmethod
    def sizeof():
        return _btrfs_header_struct.size


class BtrfsNode(NamedTuple):
    header: BtrfsHeader
    ptrs: Sequence[BtrfsKeyPtr]


class BtrfsType(enum.IntEnum):
    UNTYPED = 0
    # Generated with
    # sed -rn 's/^#\s*define\s+BTRFS_([0-9A-Za-z_]+)_KEY\s+([0-9]+)/    \1 = \2/p' include/uapi/linux/btrfs_tree.h
    INODE_ITEM = 1
    INODE_REF = 12
    INODE_EXTREF = 13
    XATTR_ITEM = 24
    ORPHAN_ITEM = 48
    DIR_LOG_ITEM = 60
    DIR_LOG_INDEX = 72
    DIR_ITEM = 84
    DIR_INDEX = 96
    EXTENT_DATA = 108
    EXTENT_CSUM = 128
    ROOT_ITEM = 132
    ROOT_BACKREF = 144
    ROOT_REF = 156
    EXTENT_ITEM = 168
    METADATA_ITEM = 169
    TREE_BLOCK_REF = 176
    EXTENT_DATA_REF = 178
    EXTENT_REF_V0 = 180
    SHARED_BLOCK_REF = 182
    SHARED_DATA_REF = 184
    BLOCK_GROUP_ITEM = 192
    FREE_SPACE_INFO = 198
    FREE_SPACE_EXTENT = 199
    FREE_SPACE_BITMAP = 200
    DEV_EXTENT = 204
    DEV_ITEM = 216
    CHUNK_ITEM = 228
    QGROUP_STATUS = 240
    QGROUP_INFO = 242
    QGROUP_LIMIT = 244
    QGROUP_RELATION = 246
    BALANCE_ITEM = 248
    TEMPORARY_ITEM = 248
    DEV_STATS = 249
    PERSISTENT_ITEM = 249
    DEV_REPLACE = 250
    STRING_ITEM = 253


_btrfs_types = {
    BtrfsType.INODE_ITEM: "struct btrfs_inode_item",
    BtrfsType.INODE_REF: "struct btrfs_inode_ref",
    # BtrfsType.INODE_EXTREF
    BtrfsType.XATTR_ITEM: "struct btrfs_dir_item",
    # BtrfsType.ORPHAN_ITEM
    # BtrfsType.DIR_LOG_ITEM
    # BtrfsType.DIR_LOG_INDEX
    BtrfsType.DIR_ITEM: "struct btrfs_dir_item",
    BtrfsType.DIR_INDEX: "struct btrfs_dir_item",
    # BtrfsType.EXTENT_DATA
    # BtrfsType.EXTENT_CSUM
    # BtrfsType.ROOT_ITEM
    # BtrfsType.ROOT_BACKREF
    # BtrfsType.ROOT_REF
    # BtrfsType.EXTENT_ITEM
    # BtrfsType.METADATA_ITEM
    # BtrfsType.TREE_BLOCK_REF
    # BtrfsType.EXTENT_DATA_REF
    # BtrfsType.EXTENT_REF_V0
    # BtrfsType.SHARED_BLOCK_REF
    # BtrfsType.SHARED_DATA_REF
    # BtrfsType.BLOCK_GROUP_ITEM
    # BtrfsType.FREE_SPACE_INFO
    # BtrfsType.FREE_SPACE_EXTENT
    # BtrfsType.FREE_SPACE_BITMAP
    # BtrfsType.DEV_EXTENT
    # BtrfsType.DEV_ITEM
    # BtrfsType.CHUNK_ITEM
    # BtrfsType.QGROUP_STATUS
    # BtrfsType.QGROUP_INFO
    # BtrfsType.QGROUP_LIMIT
    # BtrfsType.QGROUP_RELATION
    # BtrfsType.BALANCE_ITEM
    # BtrfsType.TEMPORARY_ITEM
    # BtrfsType.DEV_STATS
    # BtrfsType.PERSISTENT_ITEM
    # BtrfsType.DEV_REPLACE
    # BtrfsType.STRING_ITEM
}


_btrfs_types_with_name = {
    "struct btrfs_inode_ref",
    "struct btrfs_dir_item",
}


class BtrfsKey(NamedTuple):
    objectid: int
    type: BtrfsType
    offset: int


class BtrfsItem(NamedTuple):
    key: BtrfsKey
    offset: int
    size: int


def offset_in_page(p):
    return (p & ~p.prog_["PAGE_MASK"]).value_()


# TODO: these can probably hardcode more offsets and sizes since that's part of
# the on-disk format
_btrfs_leaf_items_offset = 101  # offsetof(struct btrfs_leaf, items)
_btrfs_item_size = 25  # sizeof(struct btrfs_item)
_btrfs_node_ptrs_offset = 101  # offsetof(struct btrfs_node, ptrs)
_btrfs_key_ptr_size = 33  # sizeof(prog.type("struct btrfs_key_ptr"))

def btrfs_header_level(eb):
    return eb.prog_.read_u8(
        page_address(eb.pages[0])
        + offset_in_page(eb.start)
        + offsetof(eb.prog_.type("struct btrfs_header"), "level")
    )


def btrfs_header_nritems(eb):
    return int.from_bytes(
        eb.prog_.read(
            page_address(eb.pages[0])
            + offset_in_page(eb.start)
            + offsetof(eb.prog_.type("struct btrfs_header"), "nritems"),
            4,
        ),
        "little",
    )


def btrfs_node_blockptr(eb, nr):
    prog = eb.prog_
    return int.from_bytes(
        prog.read(
            page_address(eb.pages[0])
            + offset_in_page(eb.start)
            + _btrfs_node_ptrs_offset
            + _btrfs_key_ptr_size * nr
            + offsetof(prog.type("struct btrfs_key_ptr"), "blockptr"),
            8,
        ),
        "little",
    )


def read_extent_buffer(eb, start, len):
    prog = eb.prog_
    PAGE_SIZE = prog["PAGE_SIZE"].value_()
    i = (start >> prog["PAGE_SHIFT"]).value_()
    offset = offset_in_page(eb.start + start)
    ret = []
    while len > 0:
        cur = min(len, PAGE_SIZE - offset)
        ret.append(prog.read(page_address(eb.pages[i]) + offset, cur))
        len -= cur
        offset = 0
        i += 1
    return b"".join(ret)


def _btrfs_bin_search(eb, p, item_size, key: BtrfsKey):
    low = 0
    high = btrfs_header_nritems(eb)

    while low < high:
        mid = (low + high) // 2
        offset = p + mid * item_size
        disk_objectid, disk_type, disk_offset = _btrfs_disk_key_struct.unpack(read_extent_buffer(eb, offset, 17))
        disk_key = BtrfsKey(disk_objectid, BtrfsType(disk_type), disk_offset)
        if disk_key < key:
            low = mid + 1
        elif disk_key > key:
            high = mid
        else:
            return 0, mid
    return 1, low



def _get_block_for_search(fs_info, eb, level, slot):
    blocknr = btrfs_node_blockptr(eb, slot)

    tmp = cast(
        eb.type_,
        radix_tree_lookup(fs_info.buffer_radix.address_of_(),
                          blocknr >> fs_info.sectorsize_bits)
    )
    if not tmp:
        raise Exception(f"extent_buffer {blocknr} is not cached")
    if tmp.refs.counter == 0:
        raise Exception(f"extent_buffer {blocknr} is dead")
    if not tmp.bflags & (1 << fs_info.prog_["EXTENT_BUFFER_UPTODATE"]):
        raise Exception(f"extent_buffer {blocknr} is not up to date")
    # TODO: check transid, level?
    return tmp


def btrfs_search_slot(root, key: BtrfsKey, *, search_commit_root: bool = False):
    prog = root.prog_
    fs_info = root.fs_info.read_()

    nodes = []
    slots = []
    prev_cmp = -1
    if search_commit_root:
        b = root.commit_root.read_()
    else:
        b = root.node.read_()
    try:
        while True:
            nodes.append(b)
            level = btrfs_header_level(b)

            if prev_cmp == 0:
                slot = 0
                ret = 0
            else:
                if level == 0:
                    ret, slot = _btrfs_bin_search(b, _btrfs_leaf_items_offset, _btrfs_item_size, key)
                else:
                    ret, slot = _btrfs_bin_search(b, _btrfs_node_ptrs_offset, _btrfs_key_ptr_size, key)
                prev_cmp = ret

            if level == 0:
                slots.append(slot)
                break

            if ret and slot > 0:
                slot -= 1
            slots.append(slot)

            b = _get_block_for_search(fs_info, b, level, slot)
    except Exception as e:
        print(e)
        ret = -1
    nodes.reverse()
    slots.reverse()
    return ret, nodes, slots


def btrfs_leaf_items(eb):
    if btrfs_header_level(eb) != 0:
        raise ValueError("buffer is not leaf")
    nritems = btrfs_header_nritems(eb)
    buf = read_extent_buffer(eb, _btrfs_leaf_items_offset, nritems * _btrfs_item_size)
    items = []
    for i in range(nritems):
        raw_item = _btrfs_item_struct.unpack_from(buf, i * _btrfs_item_size)
        items.append(
            BtrfsItem(BtrfsKey(raw_item[0], raw_item[1], raw_item[2]), raw_item[3], raw_item[4])
        )
    return items


def _parse_item_from_buf(buf, type, offset):
    while type.kind == drgn.TypeKind.TYPEDEF:
        type = type.type
    if type.kind == drgn.TypeKind.INT:
        return int.from_bytes(buf[offset:offset + type.size], "little")
    elif type.kind == drgn.TypeKind.STRUCT:
        return {
            member.name: _parse_item_from_buf(buf, member.type, offset + member.offset)
            for member in type.members
        }
    elif type.kind == drgn.TypeKind.ARRAY:
        element_type = type.type
        element_size = sizeof(element_type)
        return [
            _parse_item_from_buf(buf, element_type, offset + i * element_size)
            for i in range(type.length)
        ]
    else:
        assert False, type.kind


def btrfs_read_item(eb, slot):
    if btrfs_header_level(eb) != 0:
        raise ValueError("buffer is not leaf")
    if slot >= btrfs_header_nritems(eb):
        raise IndexError("slot is out of bounds")

    item_buf = read_extent_buffer(eb, _btrfs_leaf_items_offset + slot * _btrfs_item_size, _btrfs_item_size)
    objectid, type, offset, data_offset, data_size = _btrfs_item_struct.unpack(item_buf)

    key = BtrfsKey(objectid, BtrfsType(type), offset)

    data_buf = read_extent_buffer(eb, _btrfs_leaf_items_offset + data_offset, data_size)
    try:
        type_name = _btrfs_types[key.type]
    except KeyError:
        return key, data_buf

    item_type = prog.type(type_name)
    data = _parse_item_from_buf(data_buf, item_type, 0)
    pos = sizeof(item_type)
    if type_name in _btrfs_types_with_name:
        data["name"] = data_buf[pos:pos + data["name_len"]]
        pos += data["name_len"]
    if type_name == "struct btrfs_dir_item":
        data["data"] = data_buf[pos:pos + data["data_len"]]
        pos += data["data_len"]
    return key, data


def parse_extent_buffer(eb):
    header = BtrfsHeader.from_bytes(read_extent_buffer(eb, 0, BtrfsHeader.sizeof()))
    if header.level == 0:
        assert False
    else:
        ptrs_buf = read_extent_buffer(eb, BtrfsHeader.sizeof(), header.nritems * BtrfsKeyPtr.sizeof())
        return BtrfsNode(
            header,
            [
                BtrfsKeyPtr.from_bytes(ptrs_buf, i * BtrfsKeyPtr.sizeof())
                for i in range(header.nritems)
            ]
        )


def print_extent_buffer(eb):
    node = parse_extent_buffer(eb)
    print(f"node {node.header.bytenr} level {node.header.level} items {node.header.nritems} generation {node.header.generation} owner {node.header.owner}")
    print(f"node {node.header.bytenr} flags {node.header.flags:#x}")
    print(f"fs uuid {uuid.UUID(bytes=node.header.fsid)}")
    print(f"chunk uuid {uuid.UUID(bytes=node.header.chunk_tree_uuid)}")
    for i, ptr in enumerate(node.ptrs):
        print(f"\tptr {i} key ({ptr.key.objectid}, {ptr.key.type}, {ptr.key.offset}) block {ptr.blockptr} gen {ptr.generation}")
