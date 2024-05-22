# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Helpers for introspecting btrfs btree structures"""

from contextlib import suppress
import enum
import functools
import operator
import struct
import sys
import time
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generic,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)
import uuid

if TYPE_CHECKING:
    from _typeshed import SupportsWrite
    from typing import Final, Self  # novermin

from drgn import IntegerLike, Object, cast
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.mm import page_size, page_to_virt
from drgn.helpers.linux.radixtree import radix_tree_lookup

_T = TypeVar("_T")
_T_co = TypeVar("_T_co", covariant=True)

_NOT_FOUND = object()


class cached_property(Generic[_T_co]):
    def __init__(self, func: Callable[[Any], _T_co]) -> None:
        self.func = func
        self.__doc__ = func.__doc__
        self.__module__ = func.__module__

    def __set_name__(self, owner: Type[Any], name: str) -> None:
        self.attrname = name

    def __get__(self, instance: object, owner: Optional[Type[Any]] = None) -> _T_co:
        cache = instance.__dict__
        val = cache.get(self.attrname, _NOT_FOUND)
        if val is _NOT_FOUND:
            val = self.func(instance)
            cache[self.attrname] = val
        return val


_crc32c_table = [0] * 256
for i in range(256):
    fwd = i
    for j in range(8, 0, -1):
        if fwd & 1:
            fwd = (fwd >> 1) ^ 0x82F63B78
        else:
            fwd >>= 1
    _crc32c_table[i] = fwd & 0xFFFFFFFF


def _crc32c(b: bytes, crc: int = 0) -> int:
    for c in b:
        crc = (crc >> 8) ^ _crc32c_table[(crc ^ c) & 0xFF]
    return crc


def btrfs_name_hash(name: bytes) -> int:
    return _crc32c(name, 0xFFFFFFFE)


def _hash_extent_data_ref(root_objectid: int, owner: int, offset: int) -> int:
    high_crc = _crc32c(root_objectid.to_bytes(8, "little"), 0xFFFFFFFF)
    low_crc = _crc32c(owner.to_bytes(8, "little"), 0xFFFFFFFF)
    low_crc = _crc32c(offset.to_bytes(8, "little"), low_crc)
    return (high_crc << 31) ^ low_crc


class _BtrfsEnum(enum.IntEnum):
    def __str__(self) -> str:
        return self._name_


class _BtrfsFlag(enum.IntFlag):
    def __str__(self) -> str:
        if not self:
            return "0x0(none)"
        # btrfs-progs as of v6.8.1 ignores unknown flags when printing them,
        # but _name_ includes the numeric value of unknown flags.
        return f"{hex(self)}({self._name_})"


EnumT = TypeVar("EnumT", bound=enum.Enum)


def _try_cast_enum(enum_type: Type[EnumT], value: int) -> Union[EnumT, int]:
    try:
        return enum_type(value)
    except ValueError:
        return value


class BtrfsType(_BtrfsEnum):
    # Generated with
    #     sed -rn 's/^#\s*define\s+BTRFS_(([0-9A-Za-z_]+)_KEY|(UUID_KEY_SUBVOL|UUID_KEY_RECEIVED_SUBVOL))\s+([0-9]+).*/    \2\3 = \4/p' include/uapi/linux/btrfs_tree.h |
    #     grep -v -e BALANCE_ITEM -e DEV_STATS
    #
    # UUID_KEY_{,RECEIVED_}SUBVOL broke with the usual naming scheme.
    # BALANCE_ITEM and DEV_STATS are obsolete names for TEMPORARY_ITEM and
    # PERSISTENT_ITEM, respectively.
    INODE_ITEM = 1
    INODE_REF = 12
    INODE_EXTREF = 13
    XATTR_ITEM = 24
    VERITY_DESC_ITEM = 36
    VERITY_MERKLE_ITEM = 37
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
    EXTENT_OWNER_REF = 172
    TREE_BLOCK_REF = 176
    EXTENT_DATA_REF = 178
    SHARED_BLOCK_REF = 182
    SHARED_DATA_REF = 184
    BLOCK_GROUP_ITEM = 192
    FREE_SPACE_INFO = 198
    FREE_SPACE_EXTENT = 199
    FREE_SPACE_BITMAP = 200
    DEV_EXTENT = 204
    DEV_ITEM = 216
    CHUNK_ITEM = 228
    RAID_STRIPE = 230
    QGROUP_STATUS = 240
    QGROUP_INFO = 242
    QGROUP_LIMIT = 244
    QGROUP_RELATION = 246
    TEMPORARY_ITEM = 248
    PERSISTENT_ITEM = 249
    DEV_REPLACE = 250
    UUID_KEY_SUBVOL = 251
    UUID_KEY_RECEIVED_SUBVOL = 252
    STRING_ITEM = 253


class BtrfsObjectid(_BtrfsEnum):
    # Generated with
    #     sed -rn 's/^#\s*define\s+BTRFS_([0-9A-Za-z_]+)_OBJECTID\s+(-?[0-9]+).*/    \1 = \2/p' include/uapi/linux/btrfs_tree.h |
    #     grep -v -e DEV_STATS -e FIRST_FREE -e LAST_FREE -e FIRST_CHUNK_TREE -e DEV_ITEMS -e BTREE_INODE -e EMPTY_SUBVOL_DIR |
    #     sed -r 's/-[0-9]+/& \& 0xffffffffffffffff/'
    #
    # DEV_STATS (0) only applies if the type is PERSISTENT_ITEM.
    # FIRST_FREE (256) and LAST_FREE (-256) define the range of normal
    # objectids and aren't meaningful on their own.
    # FIRST_CHUNK_TREE (256) only applies if the type is CHUNK_ITEM.
    # DEV_ITEMS (1) only applies if the type is DEV_ITEM.
    # BTREE_INODE (1) and EMPTY_SUBVOL_DIR (2) are only used as special inode
    # numbers in memory.
    ROOT_TREE = 1
    EXTENT_TREE = 2
    CHUNK_TREE = 3
    DEV_TREE = 4
    FS_TREE = 5
    ROOT_TREE_DIR = 6
    CSUM_TREE = 7
    QUOTA_TREE = 8
    UUID_TREE = 9
    FREE_SPACE_TREE = 10
    BLOCK_GROUP_TREE = 11
    RAID_STRIPE_TREE = 12
    BALANCE = -4 & 0xFFFFFFFFFFFFFFFF
    ORPHAN = -5 & 0xFFFFFFFFFFFFFFFF
    TREE_LOG = -6 & 0xFFFFFFFFFFFFFFFF
    TREE_LOG_FIXUP = -7 & 0xFFFFFFFFFFFFFFFF
    TREE_RELOC = -8 & 0xFFFFFFFFFFFFFFFF
    DATA_RELOC_TREE = -9 & 0xFFFFFFFFFFFFFFFF
    EXTENT_CSUM = -10 & 0xFFFFFFFFFFFFFFFF
    FREE_SPACE = -11 & 0xFFFFFFFFFFFFFFFF
    FREE_INO = -12 & 0xFFFFFFFFFFFFFFFF


_non_standard_objectid_types = frozenset(
    {
        BtrfsType.PERSISTENT_ITEM,
        BtrfsType.DEV_EXTENT,
        BtrfsType.QGROUP_RELATION,
        BtrfsType.UUID_KEY_SUBVOL,
        BtrfsType.UUID_KEY_RECEIVED_SUBVOL,
        BtrfsType.DEV_ITEM,
    }
)


_BTRFS_QGROUP_LEVEL_SHIFT = 48


def _qgroup_id_str(id: int) -> str:
    level = id >> _BTRFS_QGROUP_LEVEL_SHIFT
    subvolid = id & ((1 << _BTRFS_QGROUP_LEVEL_SHIFT) - 1)
    return f"{level}/{subvolid}"


def _objectid_to_str(objectid: int, type: int) -> str:
    # Based on print_objectid() in btrfs-progs.
    if type == BtrfsType.PERSISTENT_ITEM:
        if objectid == 0:
            return "DEV_STATS"
    elif type == BtrfsType.DEV_EXTENT:
        return str(objectid)
    elif type == BtrfsType.QGROUP_RELATION:
        return _qgroup_id_str(objectid)
    elif type in (BtrfsType.UUID_KEY_SUBVOL, BtrfsType.UUID_KEY_RECEIVED_SUBVOL):
        return f"0x{objectid:016x}"
    elif objectid == 1 and type == BtrfsType.DEV_ITEM:
        return "DEV_ITEMS"
    elif objectid == 256 and type == BtrfsType.CHUNK_ITEM:
        return "FIRST_CHUNK_TREE"
    elif objectid == 0xFFFFFFFFFFFFFFFF:
        return "-1"
    else:
        try:
            return str(BtrfsObjectid(objectid))
        except ValueError:
            pass
    return str(int(objectid))


_btrfs_disk_key_fmt = "<QBQ"
_btrfs_disk_key_struct = struct.Struct(_btrfs_disk_key_fmt)
_btrfs_item_struct = struct.Struct(_btrfs_disk_key_fmt + "II")
_btrfs_key_ptr_struct = struct.Struct(_btrfs_disk_key_fmt + "QQ")


class BtrfsHeaderFlag(_BtrfsFlag):
    WRITTEN = 1 << 0
    RELOC = 1 << 1


_btrfs_header_struct = struct.Struct("<32s16sQQ16sQQIB")


class BtrfsHeader(NamedTuple):
    csum: bytes
    fsid: uuid.UUID
    bytenr: int
    flags: int
    chunk_tree_uuid: uuid.UUID
    generation: int
    owner: int
    nritems: int
    level: int

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsHeader":
        (
            csum,
            fsid,
            bytenr,
            flags,
            chunk_tree_uuid,
            generation,
            owner,
            nritems,
            level,
        ) = _btrfs_header_struct.unpack_from(b)
        return BtrfsHeader(
            csum=csum,
            fsid=uuid.UUID(bytes=fsid),
            bytenr=bytenr,
            flags=BtrfsHeaderFlag(flags),
            chunk_tree_uuid=uuid.UUID(bytes=chunk_tree_uuid),
            generation=generation,
            owner=owner,
            nritems=nritems,
            level=level,
        )


class BtrfsKey(
    NamedTuple(
        "BtrfsKey",
        [
            ("objectid", Union[BtrfsObjectid, int]),
            ("type", Union[BtrfsType, int]),
            ("offset", int),
        ],
    )
):
    def __new__(cls, objectid: int, type: int, offset: int) -> "Self":
        with suppress(ValueError):
            type = BtrfsType(type)
        if type not in _non_standard_objectid_types:
            with suppress(ValueError):
                objectid = BtrfsObjectid(objectid)
        return super().__new__(cls, objectid, type, offset)

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsKey":
        return BtrfsKey._make(_btrfs_disk_key_struct.unpack_from(b))

    def __str__(self) -> str:
        # Based on btrfs_print_key() in btrfs-progs.
        type = (
            self.type._name_
            if isinstance(self.type, BtrfsType)
            else f"UNKNOWN.{self.type}"
        )
        if self.type in (
            BtrfsType.QGROUP_INFO,
            BtrfsType.QGROUP_LIMIT,
            BtrfsType.QGROUP_RELATION,
        ):
            offset = _qgroup_id_str(self.offset)
        elif self.type in (
            BtrfsType.UUID_KEY_SUBVOL,
            BtrfsType.UUID_KEY_RECEIVED_SUBVOL,
        ):
            offset = f"0x{self.offset:016x}"
        elif (
            self.type == BtrfsType.ROOT_ITEM
            and self.objectid == BtrfsObjectid.TREE_RELOC
        ):
            offset = _objectid_to_str(self.offset, self.type)
        elif self.offset == 0xFFFFFFFFFFFFFFFF:
            # btrfs-progs as of v6.8.1 skips this for ROOT_ITEM.
            offset = "-1"
        else:
            offset = str(self.offset)
        return f"({_objectid_to_str(self.objectid, self.type)} {type} {offset})"


BTRFS_MIN_KEY = BtrfsKey(0, 0, 0)
BTRFS_MAX_KEY = BtrfsKey(2**64 - 1, 2**8 - 1, 2**64 - 1)


class BtrfsKeyPtr(NamedTuple):
    key: BtrfsKey
    blockptr: int
    generation: int

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsKeyPtr":
        t = _btrfs_key_ptr_struct.unpack_from(b)
        return BtrfsKeyPtr(BtrfsKey._make(t[:3]), *t[3:])


# class _BtrfsItemHandler(NamedTuple, Generic[_T]) and replacing Any with _T
# would be more accurate, but that fails at runtime on Python 3.6; see
# python/typing#449. This is good enough since it's checked more strictly
# through _register_item_handler().
class _BtrfsItemHandler(NamedTuple):
    parse: Callable[[BtrfsKey, bytes], Any]
    print: Callable[[BtrfsKey, bytes, Any, str, "Optional[SupportsWrite[str]]"], None]


_btrfs_item_handlers = {}


# We could define one big dictionary literal with type
# Dict[int, _BtrfsItemHandler], but then mypy won't enforce that the return
# type of parse() matches the parameter type of print().
def _register_item_handler(
    type: BtrfsType,
    parse: Callable[[BtrfsKey, bytes], _T],
    print: Callable[[BtrfsKey, bytes, _T, str, "Optional[SupportsWrite[str]]"], None],
) -> None:
    assert type not in _btrfs_item_handlers
    _btrfs_item_handlers[int(type)] = _BtrfsItemHandler(parse, print)


def _parse_unknown_item(key: BtrfsKey, raw_data: bytes) -> None:
    return None


def _print_unknown_item(
    key: BtrfsKey,
    raw_data: bytes,
    data: None,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    step = 30
    for i in range(0, len(raw_data), step):
        print(f"{indent}{'raw' if i == 0 else '   '} {raw_data[i:i + step].hex()}")


_unknown_item_type_handler = _BtrfsItemHandler(
    parse=_parse_unknown_item,
    print=_print_unknown_item,
)


def _parse_empty_item(key: BtrfsKey, raw_data: bytes) -> None:
    if raw_data:
        raise ValueError("expected empty item")
    return None


def _parse_raw_item(key: BtrfsKey, raw_data: bytes) -> bytes:
    return raw_data


def _parse_item_from_bytes(
    from_bytes: Callable[[bytes], _T]
) -> Callable[[BtrfsKey, bytes], _T]:
    @functools.wraps(from_bytes)
    def wrapper(key: BtrfsKey, raw_data: bytes) -> _T:
        return from_bytes(raw_data)

    return wrapper


def _print_nothing(
    key: BtrfsKey,
    raw_data: bytes,
    data: None,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    return


def _print_empty_item(
    s: str,
) -> Callable[[BtrfsKey, bytes, None, str, "Optional[SupportsWrite[str]]"], None]:
    def print_empty_item(
        key: BtrfsKey,
        raw_data: bytes,
        data: None,
        indent: str,
        file: "Optional[SupportsWrite[str]]",
    ) -> None:
        print(f"{indent}{s}", file=file)

    return print_empty_item


class BtrfsTimespec(NamedTuple):
    sec: int
    nsec: int

    def __str__(self) -> str:
        # btrfs-progs as of v6.8.1 doesn't zero-pad nsec. This is a bug.
        return f"{self.sec}.{self.nsec:09} ({time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.sec))})"


class BtrfsInodeFlag(_BtrfsFlag):
    NODATASUM = 1 << 0
    NODATACOW = 1 << 1
    READONLY = 1 << 2
    NOCOMPRESS = 1 << 3
    PREALLOC = 1 << 4
    SYNC = 1 << 5
    IMMUTABLE = 1 << 6
    APPEND = 1 << 7
    NODUMP = 1 << 8
    NOATIME = 1 << 9
    DIRSYNC = 1 << 10
    COMPRESS = 1 << 11


_btrfs_inode_item_struct = struct.Struct("<5Q4I3Q32xQIQIQIQI")


class BtrfsInodeItem(
    NamedTuple(
        "BtrfsInodeItem",
        [
            ("generation", int),
            ("transid", int),
            ("size", int),
            ("nbytes", int),
            ("block_group", int),
            ("nlink", int),
            ("uid", int),
            ("gid", int),
            ("mode", int),
            ("rdev", int),
            ("flags", BtrfsInodeFlag),
            ("sequence", int),
            ("atime", BtrfsTimespec),
            ("ctime", BtrfsTimespec),
            ("mtime", BtrfsTimespec),
            ("otime", BtrfsTimespec),
        ],
    )
):
    def __new__(
        cls,
        generation: int,
        transid: int,
        size: int,
        nbytes: int,
        block_group: int,
        nlink: int,
        uid: int,
        gid: int,
        mode: int,
        rdev: int,
        flags: int,
        sequence: int,
        atime: BtrfsTimespec,
        ctime: BtrfsTimespec,
        mtime: BtrfsTimespec,
        otime: BtrfsTimespec,
    ) -> "Self":
        return super().__new__(
            cls,
            generation=generation,
            transid=transid,
            size=size,
            nbytes=nbytes,
            block_group=block_group,
            nlink=nlink,
            uid=uid,
            gid=gid,
            mode=mode,
            rdev=rdev,
            flags=BtrfsInodeFlag(flags),
            sequence=sequence,
            atime=atime,
            ctime=ctime,
            mtime=mtime,
            otime=otime,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsInodeItem":
        (
            generation,
            transid,
            size,
            nbytes,
            block_group,
            nlink,
            uid,
            gid,
            mode,
            rdev,
            flags,
            sequence,
            atime_sec,
            atime_nsec,
            ctime_sec,
            ctime_nsec,
            mtime_sec,
            mtime_nsec,
            otime_sec,
            otime_nsec,
        ) = _btrfs_inode_item_struct.unpack_from(b)
        return BtrfsInodeItem(
            generation=generation,
            transid=transid,
            size=size,
            nbytes=nbytes,
            block_group=block_group,
            nlink=nlink,
            uid=uid,
            gid=gid,
            mode=mode,
            rdev=rdev,
            flags=flags,
            sequence=sequence,
            atime=BtrfsTimespec(atime_sec, atime_nsec),
            ctime=BtrfsTimespec(ctime_sec, ctime_nsec),
            mtime=BtrfsTimespec(mtime_sec, mtime_nsec),
            otime=BtrfsTimespec(otime_sec, otime_nsec),
        )


def _print_inode_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsInodeItem,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"""\
{indent}generation {item.generation} transid {item.transid} size {item.size} nbytes {item.nbytes}
{indent}block group {item.block_group} mode {item.mode:o} links {item.nlink} uid {item.uid} gid {item.gid} rdev {item.rdev}
{indent}sequence {item.sequence} flags {item.flags}
{indent}atime {item.atime}
{indent}ctime {item.ctime}
{indent}mtime {item.mtime}
{indent}otime {item.otime}
""",
        end="",
        file=file,
    )


_register_item_handler(
    BtrfsType.INODE_ITEM,
    _parse_item_from_bytes(BtrfsInodeItem.from_bytes),
    _print_inode_item,
)


_btrfs_inode_ref_struct = struct.Struct("<QH")


class BtrfsInodeRef(NamedTuple):
    index: int  # type: ignore[assignment]  # Conflicts with tuple.index()
    name: bytes

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsInodeRef":
        index, name_len = _btrfs_inode_ref_struct.unpack_from(b)
        name_offset = _btrfs_inode_ref_struct.size
        return BtrfsInodeRef(
            index=index,
            name=b[name_offset : name_offset + name_len],
        )


def _print_inode_ref(
    key: BtrfsKey,
    raw_data: bytes,
    ref: BtrfsInodeRef,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"""\
{indent}index {ref.index} namelen {len(ref.name)} name: {escape_ascii_string(ref.name)}
""",
        end="",
        file=file,
    )


_register_item_handler(
    BtrfsType.INODE_REF,
    _parse_item_from_bytes(BtrfsInodeRef.from_bytes),
    _print_inode_ref,
)


_btrfs_inode_extref_struct = struct.Struct("<QQH")


class BtrfsInodeExtref(NamedTuple):
    parent_objectid: int
    index: int  # type: ignore[assignment]  # Conflicts with tuple.index()
    name: bytes

    # TODO: test
    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsInodeExtref":
        parent_objectid, index, name_len = _btrfs_inode_extref_struct.unpack_from(b)
        name_offset = _btrfs_inode_extref_struct.size
        return BtrfsInodeExtref(
            parent_objectid=parent_objectid,
            index=index,
            name=b[name_offset : name_offset + name_len],
        )


def _parse_inode_extref_array(
    key: BtrfsKey, raw_data: bytes
) -> Sequence[BtrfsInodeExtref]:
    view = memoryview(raw_data)
    offset = 0
    refs = []
    while offset < len(raw_data):
        extref = BtrfsInodeExtref.from_bytes(view[offset:])
        refs.append(extref)
        offset += _btrfs_inode_extref_struct.size + len(extref.name)
    return refs


def _print_inode_extref_array(
    key: BtrfsKey,
    raw_data: bytes,
    refs: Sequence[BtrfsInodeExtref],
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    for ref in refs:
        print(
            f"""\
{indent}index {ref.index} parent {ref.parent_objectid} namelen {len(ref.name)} name {escape_ascii_string(ref.name)}
""",
            end="",
            file=file,
        )


_register_item_handler(
    BtrfsType.INODE_EXTREF,
    _parse_inode_extref_array,
    _print_inode_extref_array,
)


class BtrfsFileType(_BtrfsEnum):
    FILE = 1
    DIR = 2
    CHRDEV = 3
    BLKDEV = 4
    FIFO = 5
    SOCK = 6
    SYMLINK = 7
    XATTR = 8


_btrfs_dir_item_struct = struct.Struct("<QBQQHHB")


class BtrfsDirItem(
    NamedTuple(
        "BtrfsDirItem",
        [
            ("location", BtrfsKey),
            ("transid", int),
            ("type", Union[BtrfsFileType, int]),
            ("name", bytes),
            ("data", bytes),
        ],
    )
):
    def __new__(
        cls, location: BtrfsKey, transid: int, type: int, name: bytes, data: bytes
    ) -> "Self":
        return super().__new__(
            cls,
            location=location,
            transid=transid,
            type=_try_cast_enum(BtrfsFileType, type),
            name=name,
            data=data,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsDirItem":
        (
            location_objectid,
            location_type,
            location_offset,
            transid,
            data_len,
            name_len,
            type,
        ) = _btrfs_dir_item_struct.unpack_from(b)
        name_offset = _btrfs_dir_item_struct.size
        data_offset = name_offset + name_len
        return BtrfsDirItem(
            location=BtrfsKey(location_objectid, location_type, location_offset),
            transid=transid,
            type=type,
            name=b[name_offset:data_offset],
            data=b[data_offset : data_offset + data_len],
        )


def _parse_dir_item_array(key: BtrfsKey, raw_data: bytes) -> Sequence[BtrfsDirItem]:
    view = memoryview(raw_data)
    offset = 0
    items = []
    while offset < len(raw_data):
        di = BtrfsDirItem.from_bytes(view[offset:])
        items.append(di)
        offset += _btrfs_dir_item_struct.size + len(di.name) + len(di.data)
    return items


def _print_dir_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsDirItem,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    type = (
        item.type._name_
        if isinstance(item.type, BtrfsFileType)
        else f"DIR_ITEM.{item.type}"
    )
    # btrfs-progs as of v6.8.1 doesn't escape any strings.
    print(
        f"""\
{indent}location key {item.location} type {type}
{indent}transid {item.transid} data_len {len(item.data)} name_len {len(item.name)}
{indent}name: {escape_ascii_string(item.name)}
""",
        end="",
        file=file,
    )
    if item.data:
        print(f"{indent}data {escape_ascii_string(item.data)}", file=file)


def _print_dir_item_array(
    key: BtrfsKey,
    raw_data: bytes,
    items: Sequence[BtrfsDirItem],
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    for item in items:
        _print_dir_item(key, raw_data, item, indent, file)


_register_item_handler(
    BtrfsType.XATTR_ITEM,
    _parse_dir_item_array,
    _print_dir_item_array,
)
_register_item_handler(
    BtrfsType.DIR_ITEM,
    _parse_dir_item_array,
    _print_dir_item_array,
)
_register_item_handler(
    BtrfsType.DIR_INDEX,
    _parse_dir_item_array,
    _print_dir_item_array,
)


# TODO: VERITY_DESC_ITEM handler
# TODO: VERITY_MERKLE_ITEM handler


_register_item_handler(
    BtrfsType.ORPHAN_ITEM,
    _parse_empty_item,
    _print_empty_item("orphan item"),
)


# TODO: DIR_LOG_ITEM handler
# TODO: DIR_LOG_INDEX handler


class BtrfsCompressionType(_BtrfsEnum):
    NONE = 0
    ZLIB = 1
    LZO = 2
    ZSTD = 3


_compression_type_to_str_dict: Dict[int, str] = {
    BtrfsCompressionType.NONE: "none",
    BtrfsCompressionType.ZLIB: "zlib",
    BtrfsCompressionType.LZO: "lzo",
    BtrfsCompressionType.ZSTD: "zstd",
}


def _compress_type_to_str(compression: int) -> str:
    try:
        return _compression_type_to_str_dict[compression]
    except KeyError:
        return f"UNKNOWN.{int(compression)}"


class BtrfsFileExtentType(_BtrfsEnum):
    INLINE = 0
    REG = 1
    PREALLOC = 2


_file_extent_type_to_str_dict: Dict[int, str] = {
    BtrfsFileExtentType.INLINE: "inline",
    BtrfsFileExtentType.REG: "regular",
    BtrfsFileExtentType.PREALLOC: "prealloc",
}


def _file_extent_type_to_str(type: int) -> str:
    return _file_extent_type_to_str_dict.get(type, "unknown")


class BtrfsFileExtentItem(
    NamedTuple(
        "BtrfsFileExtentItem",
        [
            ("generation", int),
            ("ram_bytes", int),
            ("compression", Union[BtrfsCompressionType, int]),
            ("encryption", int),
            ("other_encoding", int),
            ("type", Union[BtrfsFileExtentType, int]),
            ("disk_bytenr", int),
            ("disk_num_bytes", int),
            ("offset", int),
            ("num_bytes", int),
        ],
    )
):
    def __new__(
        cls,
        generation: int,
        ram_bytes: int,
        compression: int,
        encryption: int,
        other_encoding: int,
        type: int,
        disk_bytenr: int,
        disk_num_bytes: int,
        offset: int,
        num_bytes: int,
    ) -> "Self":
        return super().__new__(
            cls,
            generation=generation,
            ram_bytes=ram_bytes,
            compression=_try_cast_enum(BtrfsCompressionType, compression),
            encryption=encryption,
            other_encoding=other_encoding,
            type=_try_cast_enum(BtrfsFileExtentType, type),
            disk_bytenr=disk_bytenr,
            disk_num_bytes=disk_num_bytes,
            offset=offset,
            num_bytes=num_bytes,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)


class BtrfsInlineFileExtentItem(
    NamedTuple(
        "BtrfsInlineFileExtentItem",
        [
            ("generation", int),
            ("ram_bytes", int),
            ("compression", Union[BtrfsCompressionType, int]),
            ("encryption", int),
            ("other_encoding", int),
            ("type", Union[BtrfsFileExtentType, int]),
            ("data", bytes),
        ],
    )
):
    def __new__(
        cls,
        generation: int,
        ram_bytes: int,
        compression: int,
        encryption: int,
        other_encoding: int,
        type: int,
        data: bytes,
    ) -> "Self":
        return super().__new__(
            cls,
            generation=generation,
            ram_bytes=ram_bytes,
            compression=_try_cast_enum(BtrfsCompressionType, compression),
            encryption=encryption,
            other_encoding=other_encoding,
            type=_try_cast_enum(BtrfsFileExtentType, type),
            data=data,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)


_btrfs_file_extent_item_common_struct = struct.Struct("<QQBBHB")
_btrfs_file_extent_item_not_inline_struct = struct.Struct("<4Q")


def _parse_file_extent_item(
    key: BtrfsKey, raw_data: bytes
) -> Union[BtrfsFileExtentItem, BtrfsInlineFileExtentItem]:
    (
        generation,
        ram_bytes,
        compression,
        encryption,
        other_encoding,
        type,
    ) = _btrfs_file_extent_item_common_struct.unpack_from(raw_data)
    if type == BtrfsFileExtentType.INLINE:
        return BtrfsInlineFileExtentItem(
            generation=generation,
            ram_bytes=ram_bytes,
            compression=compression,
            encryption=encryption,
            other_encoding=other_encoding,
            type=type,
            data=raw_data[_btrfs_file_extent_item_common_struct.size :],
        )
    else:
        (
            disk_bytenr,
            disk_num_bytes,
            offset,
            num_bytes,
        ) = _btrfs_file_extent_item_not_inline_struct.unpack_from(
            raw_data, _btrfs_file_extent_item_common_struct.size
        )
        return BtrfsFileExtentItem(
            generation=generation,
            ram_bytes=ram_bytes,
            compression=compression,
            encryption=encryption,
            other_encoding=other_encoding,
            type=type,
            disk_bytenr=disk_bytenr,
            disk_num_bytes=disk_num_bytes,
            offset=offset,
            num_bytes=num_bytes,
        )


def _print_file_extent_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: Union[BtrfsFileExtentItem, BtrfsInlineFileExtentItem],
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"""\
{indent}generation {item.generation} type {int(item.type)} ({_file_extent_type_to_str(item.type)})
""",
        end="",
        file=file,
    )
    compression = f"compression {int(item.compression)} ({_compress_type_to_str(item.compression)})"
    if isinstance(item, BtrfsInlineFileExtentItem):
        print(
            f"""\
{indent}inline extent data size {len(item.data)} ram_bytes {item.ram_bytes} {compression}
""",
            end="",
            file=file,
        )
    else:
        title = "prealloc" if item.type == BtrfsFileExtentType.PREALLOC else "extent"
        print(
            f"""\
{indent}{title} data disk byte {item.disk_bytenr} nr {item.disk_num_bytes}
{indent}{title} data offset {item.offset} nr {item.num_bytes}\
""",
            end="",
            file=file,
        )
        if item.type == BtrfsFileExtentType.PREALLOC:
            print(file=file)
        else:
            print(
                f"""\
 ram {item.ram_bytes}
{indent}extent {compression}
""",
                end="",
                file=file,
            )


_register_item_handler(
    BtrfsType.EXTENT_DATA,
    _parse_file_extent_item,
    _print_file_extent_item,
)


# TODO: EXTENT_CSUM handler (depends on filesystem csum setting)


class BtrfsRootFlag(_BtrfsFlag):
    # btrfs-progs as of v6.8.1 prints this as RDONLY.
    SUBVOL_RDONLY = 1 << 0


# NB: this doesn't include the inode item.
_btrfs_root_item_struct = struct.Struct("<7QIQBQBBQ16s16s16s5QIQIQIQI64x")


class BtrfsRootItem(
    NamedTuple(
        "BtrfsRootItem",
        [
            ("inode", BtrfsInodeItem),
            ("generation", int),
            ("root_dirid", int),
            ("bytenr", int),
            ("byte_limit", int),
            ("bytes_used", int),
            ("last_snapshot", int),
            ("flags", BtrfsRootFlag),
            ("refs", int),
            ("drop_progress", BtrfsKey),
            ("drop_level", int),
            ("level", int),
            ("generation_v2", int),
            ("uuid", uuid.UUID),
            ("parent_uuid", uuid.UUID),
            ("received_uuid", uuid.UUID),
            ("ctransid", int),
            ("otransid", int),
            ("stransid", int),
            ("rtransid", int),
            ("ctime", BtrfsTimespec),
            ("otime", BtrfsTimespec),
            ("stime", BtrfsTimespec),
            ("rtime", BtrfsTimespec),
        ],
    )
):
    def __new__(
        cls,
        inode: BtrfsInodeItem,
        generation: int,
        root_dirid: int,
        bytenr: int,
        byte_limit: int,
        bytes_used: int,
        last_snapshot: int,
        flags: int,
        refs: int,
        drop_progress: BtrfsKey,
        drop_level: int,
        level: int,
        generation_v2: int,
        uuid: uuid.UUID,
        parent_uuid: uuid.UUID,
        received_uuid: uuid.UUID,
        ctransid: int,
        otransid: int,
        stransid: int,
        rtransid: int,
        ctime: BtrfsTimespec,
        otime: BtrfsTimespec,
        stime: BtrfsTimespec,
        rtime: BtrfsTimespec,
    ) -> "Self":
        return super().__new__(
            cls,
            inode=inode,
            generation=generation,
            root_dirid=root_dirid,
            bytenr=bytenr,
            byte_limit=byte_limit,
            bytes_used=bytes_used,
            last_snapshot=last_snapshot,
            flags=BtrfsRootFlag(flags),
            refs=refs,
            drop_progress=drop_progress,
            drop_level=drop_level,
            level=level,
            generation_v2=generation_v2,
            uuid=uuid,
            parent_uuid=parent_uuid,
            received_uuid=received_uuid,
            ctransid=ctransid,
            otransid=otransid,
            stransid=stransid,
            rtransid=rtransid,
            ctime=ctime,
            otime=otime,
            stime=stime,
            rtime=rtime,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsRootItem":
        inode = BtrfsInodeItem.from_bytes(b)
        (
            generation,
            root_dirid,
            bytenr,
            byte_limit,
            bytes_used,
            last_snapshot,
            flags,
            refs,
            drop_progress_objectid,
            drop_progress_type,
            drop_progress_offset,
            drop_level,
            level,
            generation_v2,
            uuid_,
            parent_uuid,
            received_uuid,
            ctransid,
            otransid,
            stransid,
            rtransid,
            ctime_sec,
            ctime_nsec,
            otime_sec,
            otime_nsec,
            stime_sec,
            stime_nsec,
            rtime_sec,
            rtime_nsec,
        ) = _btrfs_root_item_struct.unpack_from(b, _btrfs_inode_item_struct.size)
        return BtrfsRootItem(
            inode=inode,
            generation=generation,
            root_dirid=root_dirid,
            bytenr=bytenr,
            byte_limit=byte_limit,
            bytes_used=bytes_used,
            last_snapshot=last_snapshot,
            flags=flags,
            refs=refs,
            drop_progress=BtrfsKey(
                drop_progress_objectid, drop_progress_type, drop_progress_offset
            ),
            drop_level=drop_level,
            level=level,
            generation_v2=generation_v2,
            uuid=uuid.UUID(bytes=uuid_),
            parent_uuid=uuid.UUID(bytes=parent_uuid),
            received_uuid=uuid.UUID(bytes=received_uuid),
            ctransid=ctransid,
            otransid=otransid,
            stransid=stransid,
            rtransid=rtransid,
            ctime=BtrfsTimespec(ctime_sec, ctime_nsec),
            otime=BtrfsTimespec(otime_sec, otime_nsec),
            stime=BtrfsTimespec(stime_sec, stime_nsec),
            rtime=BtrfsTimespec(rtime_sec, rtime_nsec),
        )


def _print_root_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsRootItem,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"""\
{indent}generation {item.generation} root_dirid {item.root_dirid} bytenr {item.bytenr} byte_limit {item.byte_limit} bytes_used {item.bytes_used}
{indent}last_snapshot {item.last_snapshot} flags {item.flags} refs {item.refs}
{indent}drop_progress key {item.drop_progress} drop_level {item.drop_level}
{indent}level {item.level} generation_v2 {item.generation_v2}
{indent}uuid {item.uuid}
{indent}parent_uuid {item.parent_uuid}
{indent}received_uuid {item.received_uuid}
{indent}ctransid {item.ctransid} otransid {item.otransid} stransid {item.stransid} rtransid {item.rtransid}
{indent}ctime {item.ctime}
{indent}otime {item.otime}
{indent}stime {item.stime}
{indent}rtime {item.rtime}
""",
        end="",
        file=file,
    )


_register_item_handler(
    BtrfsType.ROOT_ITEM,
    _parse_item_from_bytes(BtrfsRootItem.from_bytes),
    _print_root_item,
)


_btrfs_root_ref_struct = struct.Struct("<QQH")


class BtrfsRootRef(NamedTuple):
    dirid: int
    sequence: int
    name: bytes

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsRootRef":
        dirid, sequence, name_len = _btrfs_root_ref_struct.unpack_from(b)
        name_offset = _btrfs_root_ref_struct.size
        return BtrfsRootRef(
            dirid=dirid,
            sequence=sequence,
            name=b[name_offset : name_offset + name_len],
        )


def _print_root_ref(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsRootRef,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    back = "back" if key.type == BtrfsType.ROOT_BACKREF else ""
    print(
        f"{indent}root {back}ref key dirid {item.dirid} sequence {item.sequence} name {escape_ascii_string(item.name)}",
        file=file,
    )


_register_item_handler(
    BtrfsType.ROOT_BACKREF,
    _parse_item_from_bytes(BtrfsRootRef.from_bytes),
    _print_root_ref,
)
_register_item_handler(
    BtrfsType.ROOT_REF,
    _parse_item_from_bytes(BtrfsRootRef.from_bytes),
    _print_root_ref,
)


class BtrfsExtentFlag(_BtrfsFlag):
    DATA = 1 << 0
    TREE_BLOCK = 1 << 1
    FULL_BACKREF = 1 << 8


_btrfs_tree_block_info_struct = struct.Struct("<QBQB")


class BtrfsTreeBlockInfo(NamedTuple):
    key: BtrfsKey
    level: int

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsTreeBlockInfo":
        (
            key_objectid,
            key_type,
            key_offset,
            level,
        ) = _btrfs_tree_block_info_struct.unpack_from(b)
        return BtrfsTreeBlockInfo(
            key=BtrfsKey(key_objectid, key_type, key_offset),
            level=level,
        )


_btrfs_extent_owner_ref_struct = struct.Struct("<Q")


class BtrfsExtentOwnerRef(
    NamedTuple(
        "BtrfsExtentOwnerRef",
        [
            ("root_id", Union[BtrfsObjectid, int]),
        ],
    )
):
    def __new__(cls, root_id: int) -> "Self":
        return super().__new__(cls, _try_cast_enum(BtrfsObjectid, root_id))

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsExtentOwnerRef":
        return BtrfsExtentOwnerRef._make(_btrfs_extent_owner_ref_struct.unpack_from(b))


def _print_extent_owner_ref(
    key: BtrfsKey,
    raw_data: bytes,
    ref: BtrfsExtentOwnerRef,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(f"{indent}extent owner root {ref.root_id}", file=file)


_btrfs_extent_data_ref_struct = struct.Struct("<3QI")


class BtrfsExtentDataRef(
    NamedTuple(
        "BtrfsExtentDataRef",
        [
            ("root", Union[BtrfsObjectid, int]),
            ("objectid", int),
            ("offset", int),
            ("count", int),
        ],
    )
):
    def __new__(cls, root: int, objectid: int, offset: int, count: int) -> "Self":
        return super().__new__(
            cls,
            _try_cast_enum(BtrfsObjectid, root),
            objectid,
            offset,
            count,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsExtentDataRef":
        return BtrfsExtentDataRef._make(_btrfs_extent_data_ref_struct.unpack_from(b))


def _print_extent_data_ref(
    key: BtrfsKey,
    raw_data: bytes,
    ref: BtrfsExtentDataRef,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"extent data backref root {ref.root} objectid {ref.objectid} offset {ref.offset} count {ref.count}",
        file=file,
    )


_btrfs_shared_data_ref_struct = struct.Struct("<I")


class BtrfsSharedDataRef(NamedTuple):
    count: int  # type: ignore[assignment]  # Conflicts with tuple.count()

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsSharedDataRef":
        return BtrfsSharedDataRef._make(_btrfs_shared_data_ref_struct.unpack_from(b))


def _print_shared_data_ref(
    key: BtrfsKey,
    raw_data: bytes,
    ref: BtrfsSharedDataRef,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(f"shared data backref count {ref.count}", file=file)


class BtrfsExtentInlineRef(NamedTuple):
    type: BtrfsType
    offset: int


class BtrfsExtentInlineOwnerRef(NamedTuple):
    type: BtrfsType
    root_id: Union[BtrfsObjectid, int]


class BtrfsExtentInlineDataRef(NamedTuple):
    type: BtrfsType
    root: Union[BtrfsObjectid, int]
    objectid: int
    offset: int
    count: int  # type: ignore[assignment]  # Conflicts with tuple.count()


class BtrfsExtentInlineSharedDataRef(NamedTuple):
    type: BtrfsType
    offset: int
    count: int  # type: ignore[assignment]  # Conflicts with tuple.count()


_btrfs_extent_item_struct = struct.Struct("<3Q")


class BtrfsExtentItem(
    NamedTuple(
        "BtrfsExtentItem",
        [
            ("refs", int),
            ("generation", int),
            ("flags", BtrfsExtentFlag),
            ("tree_block_info", Optional[BtrfsTreeBlockInfo]),
            (
                "inline_refs",
                Sequence[
                    Union[
                        BtrfsExtentInlineRef,
                        BtrfsExtentInlineOwnerRef,
                        BtrfsExtentInlineDataRef,
                        BtrfsExtentInlineSharedDataRef,
                    ]
                ],
            ),
        ],
    )
):
    def __new__(
        cls,
        refs: int,
        generation: int,
        flags: int,
        tree_block_info: Optional[BtrfsTreeBlockInfo],
        inline_refs: Sequence[
            Union[
                BtrfsExtentInlineRef,
                BtrfsExtentInlineOwnerRef,
                BtrfsExtentInlineDataRef,
                BtrfsExtentInlineSharedDataRef,
            ]
        ],
    ) -> "Self":
        return super().__new__(
            cls,
            refs=refs,
            generation=generation,
            flags=BtrfsExtentFlag(flags),
            tree_block_info=tree_block_info,
            inline_refs=inline_refs,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)


def _parse_extent_item(key: BtrfsKey, raw_data: bytes) -> Optional[BtrfsExtentItem]:
    view = memoryview(raw_data)
    refs, generation, flags = _btrfs_extent_item_struct.unpack_from(raw_data)
    offset = _btrfs_extent_item_struct.size
    if key.type == BtrfsType.EXTENT_ITEM and (flags & BtrfsExtentFlag.TREE_BLOCK):
        tree_block_info = BtrfsTreeBlockInfo.from_bytes(view[offset:])
        offset += _btrfs_tree_block_info_struct.size
    else:
        tree_block_info = None
    inline_refs: List[
        Union[
            BtrfsExtentInlineRef,
            BtrfsExtentInlineOwnerRef,
            BtrfsExtentInlineDataRef,
            BtrfsExtentInlineSharedDataRef,
        ]
    ] = []
    while offset < len(raw_data):
        type = _try_cast_enum(BtrfsType, raw_data[offset])
        offset += 1
        if type == BtrfsType.EXTENT_OWNER_REF:
            inline_refs.append(
                BtrfsExtentInlineOwnerRef(
                    type,
                    *BtrfsExtentOwnerRef.from_bytes(view[offset:]),
                )
            )
            offset += _btrfs_extent_owner_ref_struct.size
        elif type == BtrfsType.EXTENT_DATA_REF:
            inline_refs.append(
                BtrfsExtentInlineDataRef(
                    type,
                    *BtrfsExtentDataRef.from_bytes(view[offset:]),
                )
            )
            offset += _btrfs_extent_data_ref_struct.size
        else:
            ref_offset = int.from_bytes(raw_data[offset : offset + 8], "little")
            offset += 8
            if type == BtrfsType.TREE_BLOCK_REF or type == BtrfsType.SHARED_BLOCK_REF:
                inline_refs.append(BtrfsExtentInlineRef(type, ref_offset))
            elif type == BtrfsType.SHARED_DATA_REF:
                inline_refs.append(
                    BtrfsExtentInlineSharedDataRef(
                        type,
                        ref_offset,
                        *_btrfs_shared_data_ref_struct.unpack_from(raw_data, offset),
                    )
                )
                offset += _btrfs_shared_data_ref_struct.size
            else:
                return None
    return BtrfsExtentItem(
        refs=refs,
        generation=generation,
        flags=flags,
        tree_block_info=tree_block_info,
        inline_refs=inline_refs,
    )


def _print_extent_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: Optional[BtrfsExtentItem],
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    if item is None:
        return _print_unknown_item(key, raw_data, item, indent, file)
    print(
        f"{indent}refs {item.refs} gen {item.generation} flags {item.flags}", file=file
    )
    if item.tree_block_info is not None:
        print(
            f"{indent}tree block {item.tree_block_info.key} level {item.tree_block_info.level}",
            file=file,
        )
    elif key.type == BtrfsType.METADATA_ITEM:
        print(f"{indent}tree block skinny level {key.offset}")
    for ref in item.inline_refs:
        if isinstance(ref, BtrfsExtentInlineRef):
            if ref.type == BtrfsType.TREE_BLOCK_REF:
                print(
                    f"{indent}({int(ref.type)} {hex(ref.offset)}) tree block backref root {_objectid_to_str(ref.offset, 0)}",
                    file=file,
                )
            elif ref.type == BtrfsType.SHARED_BLOCK_REF:
                print(
                    f"{indent}({int(ref.type)} {hex(ref.offset)}) shared block backref parent {ref.offset}",
                    file=file,
                )
            else:
                assert False, ref.type
        elif isinstance(ref, BtrfsExtentInlineOwnerRef):
            print(
                f"{indent}({int(ref.type)} {hex(ref.root_id)}) extent owner root {ref.root_id}",
                file=file,
            )
        elif isinstance(ref, BtrfsExtentInlineDataRef):
            seq = _hash_extent_data_ref(ref.root, ref.objectid, ref.offset)
            print(
                f"{indent}({int(ref.type)} {hex(seq)}) extent data backref root {ref.root} objectid {ref.objectid} offset {ref.offset} count {ref.count}",
                file=file,
            )
        elif isinstance(ref, BtrfsExtentInlineSharedDataRef):
            print(
                f"{indent}({int(ref.type)} {hex(ref.offset)}) shared data backref parent {ref.offset} count {ref.count}",
                file=file,
            )
        else:
            assert False


_register_item_handler(
    BtrfsType.EXTENT_ITEM,
    _parse_extent_item,
    _print_extent_item,
)
_register_item_handler(
    BtrfsType.METADATA_ITEM,
    _parse_extent_item,
    _print_extent_item,
)

_register_item_handler(
    BtrfsType.EXTENT_OWNER_REF,
    _parse_item_from_bytes(BtrfsExtentOwnerRef.from_bytes),
    _print_extent_owner_ref,
)
_register_item_handler(
    BtrfsType.TREE_BLOCK_REF,
    _parse_empty_item,
    _print_empty_item("tree block backref"),
)
_register_item_handler(
    BtrfsType.EXTENT_DATA_REF,
    _parse_item_from_bytes(BtrfsExtentDataRef.from_bytes),
    _print_extent_data_ref,
)
_register_item_handler(
    BtrfsType.SHARED_BLOCK_REF,
    _parse_empty_item,
    _print_empty_item("shared block backref"),
)
_register_item_handler(
    BtrfsType.SHARED_DATA_REF,
    _parse_item_from_bytes(BtrfsSharedDataRef.from_bytes),
    _print_shared_data_ref,
)


# btrfs-progs as of v6.8.1 pretty-prints these flags without their numeric
# value and errantly adds "|single" if no profile flag is set.
class BtrfsBlockGroupFlag(_BtrfsFlag):
    DATA = 1 << 0
    SYSTEM = 1 << 1
    METADATA = 1 << 2
    RAID0 = 1 << 3
    RAID1 = 1 << 4
    DUP = 1 << 5
    RAID10 = 1 << 6
    RAID5 = 1 << 7
    RAID6 = 1 << 8
    RAID1C3 = 1 << 9
    RAID1C4 = 1 << 10
    AVAIL_ALLOC_BIT_SINGLE = 1 << 48


_btrfs_block_group_item_struct = struct.Struct("<3Q")


class BtrfsBlockGroupItem(
    NamedTuple(
        "BtrfsBlockGroupItem",
        [
            ("used", int),
            ("chunk_objectid", int),
            ("flags", BtrfsBlockGroupFlag),
        ],
    )
):
    def __new__(cls, used: int, chunk_objectid: int, flags: int) -> "Self":
        return super().__new__(
            cls,
            used=used,
            chunk_objectid=chunk_objectid,
            flags=BtrfsBlockGroupFlag(flags),
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsBlockGroupItem":
        return BtrfsBlockGroupItem._make(_btrfs_block_group_item_struct.unpack_from(b))


def _print_block_group_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsBlockGroupItem,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"{indent}block group used {item.used} chunk_objectid {item.chunk_objectid} flags {item.flags}",
        file=file,
    )


_register_item_handler(
    BtrfsType.BLOCK_GROUP_ITEM,
    _parse_item_from_bytes(BtrfsBlockGroupItem.from_bytes),
    _print_block_group_item,
)


class BtrfsFreeSpaceFlag(_BtrfsFlag):
    USING_BITMAPS = 1 << 0


_btrfs_free_space_info_struct = struct.Struct("<II")


class BtrfsFreeSpaceInfo(
    NamedTuple(
        "BtrfsFreeSpaceInfo",
        [
            ("extent_count", int),
            ("flags", BtrfsFreeSpaceFlag),
        ],
    )
):
    def __new__(cls, extent_count: int, flags: int) -> "Self":
        return super().__new__(
            cls,
            extent_count=extent_count,
            flags=BtrfsFreeSpaceFlag(flags),
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsFreeSpaceInfo":
        return BtrfsFreeSpaceInfo._make(_btrfs_free_space_info_struct.unpack_from(b))


def _print_free_space_info(
    key: BtrfsKey,
    raw_data: bytes,
    info: BtrfsFreeSpaceInfo,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    # btrfs-progs as of v6.8.1 doesn't pretty-print these flags.
    print(
        f"""\
{indent}free space info extent count {info.extent_count} flags {info.flags}
""",
        end="",
        file=file,
    )


_register_item_handler(
    BtrfsType.FREE_SPACE_INFO,
    _parse_item_from_bytes(BtrfsFreeSpaceInfo.from_bytes),
    _print_free_space_info,
)

_register_item_handler(
    BtrfsType.FREE_SPACE_EXTENT,
    _parse_empty_item,
    _print_empty_item("free space extent"),
)


def _print_free_space_bitmap(
    key: BtrfsKey,
    raw_data: bytes,
    bitmap: bytes,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(f"{indent}free space bitmap", file=file)


_register_item_handler(
    BtrfsType.FREE_SPACE_BITMAP,
    _parse_raw_item,
    _print_free_space_bitmap,
)


_btrfs_dev_extent_struct = struct.Struct("<4Q16s")


class BtrfsDevExtent(NamedTuple):
    chunk_tree: int
    chunk_objectid: int
    chunk_offset: int
    length: int
    chunk_tree_uuid: uuid.UUID

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsDevExtent":
        (
            chunk_tree,
            chunk_objectid,
            chunk_offset,
            length,
            chunk_tree_uuid,
        ) = _btrfs_dev_extent_struct.unpack_from(b)
        return BtrfsDevExtent(
            chunk_tree=chunk_tree,
            chunk_objectid=chunk_objectid,
            chunk_offset=chunk_offset,
            length=length,
            chunk_tree_uuid=uuid.UUID(bytes=chunk_tree_uuid),
        )


def _print_dev_extent(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsDevExtent,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"""\
{indent}dev extent chunk_tree {item.chunk_tree}
{indent}chunk_objectid {item.chunk_objectid} chunk_offset {item.chunk_offset} length {item.length}
{indent}chunk_tree_uuid {item.chunk_tree_uuid}
""",
        end="",
        file=file,
    )


_register_item_handler(
    BtrfsType.DEV_EXTENT,
    _parse_item_from_bytes(BtrfsDevExtent.from_bytes),
    _print_dev_extent,
)


_btrfs_dev_item_struct = struct.Struct("<3Q3I3QIBB16s16s")


class BtrfsDevItem(NamedTuple):
    devid: int
    total_bytes: int
    bytes_used: int
    io_align: int
    io_width: int
    sector_size: int
    type: int
    generation: int
    start_offset: int
    dev_group: int
    seek_speed: int
    bandwidth: int
    uuid: uuid.UUID
    fsid: uuid.UUID

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsDevItem":
        (
            devid,
            total_bytes,
            bytes_used,
            io_align,
            io_width,
            sector_size,
            type,
            generation,
            start_offset,
            dev_group,
            seek_speed,
            bandwidth,
            uuid_,
            fsid,
        ) = _btrfs_dev_item_struct.unpack_from(b)
        return BtrfsDevItem(
            devid=devid,
            total_bytes=total_bytes,
            bytes_used=bytes_used,
            io_align=io_align,
            io_width=io_width,
            sector_size=sector_size,
            type=type,
            generation=generation,
            start_offset=start_offset,
            dev_group=dev_group,
            seek_speed=seek_speed,
            bandwidth=bandwidth,
            uuid=uuid.UUID(bytes=uuid_),
            fsid=uuid.UUID(bytes=fsid),
        )


def _print_dev_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsDevItem,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"""\
{indent}devid {item.devid} total_bytes {item.total_bytes} bytes_used {item.bytes_used}
{indent}io_align {item.io_align} io_width {item.io_width} sector_size {item.sector_size} type {item.type}
{indent}generation {item.generation} start_offset {item.start_offset} dev_group {item.dev_group}
{indent}seek_speed {item.seek_speed} bandwidth {item.bandwidth}
{indent}uuid {item.uuid}
{indent}fsid {item.fsid}
""",
        end="",
        file=file,
    )


_register_item_handler(
    BtrfsType.DEV_ITEM,
    _parse_item_from_bytes(BtrfsDevItem.from_bytes),
    _print_dev_item,
)


_btrfs_stripe_struct = struct.Struct("<QQ16s")


class BtrfsStripe(NamedTuple):
    devid: int
    offset: int
    dev_uuid: uuid.UUID

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsStripe":
        devid, offset, dev_uuid = _btrfs_stripe_struct.unpack_from(b)
        return BtrfsStripe(
            devid=devid,
            offset=offset,
            dev_uuid=uuid.UUID(bytes=dev_uuid),
        )


# NB: this doesn't include the stripes
_btrfs_chunk_struct = struct.Struct("<4Q3IHH")


class BtrfsChunk(
    NamedTuple(
        "BtrfsChunk",
        [
            ("length", int),
            ("owner", int),
            ("stripe_len", int),
            ("type", BtrfsBlockGroupFlag),
            ("io_align", int),
            ("io_width", int),
            ("sector_size", int),
            ("num_stripes", int),
            ("sub_stripes", int),
            ("stripes", Sequence[BtrfsStripe]),
        ],
    )
):
    def __new__(
        cls,
        length: int,
        owner: int,
        stripe_len: int,
        type: int,
        io_align: int,
        io_width: int,
        sector_size: int,
        num_stripes: int,
        sub_stripes: int,
        stripes: Sequence[BtrfsStripe],
    ) -> "Self":
        return super().__new__(
            cls,
            length=length,
            owner=owner,
            stripe_len=stripe_len,
            type=BtrfsBlockGroupFlag(type),
            io_align=io_align,
            io_width=io_width,
            sector_size=sector_size,
            num_stripes=num_stripes,
            sub_stripes=sub_stripes,
            stripes=stripes,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsChunk":
        view = memoryview(b)
        (
            length,
            owner,
            stripe_len,
            type,
            io_align,
            io_width,
            sector_size,
            num_stripes,
            sub_stripes,
        ) = _btrfs_chunk_struct.unpack_from(b)
        return BtrfsChunk(
            length=length,
            owner=owner,
            stripe_len=stripe_len,
            type=type,
            io_align=io_align,
            io_width=io_width,
            sector_size=sector_size,
            num_stripes=num_stripes,
            sub_stripes=sub_stripes,
            stripes=[
                BtrfsStripe.from_bytes(view[stripe_offset:])
                for stripe_offset in range(
                    _btrfs_chunk_struct.size,
                    _btrfs_chunk_struct.size + num_stripes * _btrfs_stripe_struct.size,
                    _btrfs_stripe_struct.size,
                )
            ],
        )


def _print_chunk(
    key: BtrfsKey,
    raw_data: bytes,
    chunk: BtrfsChunk,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"""\
{indent}length {chunk.length} owner {chunk.owner} stripe_len {chunk.stripe_len} type {chunk.type}
{indent}io_align {chunk.io_align} io_width {chunk.io_width} sector_size {chunk.sector_size}
{indent}num_stripes {chunk.num_stripes} sub_stripes {chunk.sub_stripes}
""",
        end="",
        file=file,
    )
    for i, stripe in enumerate(chunk.stripes):
        print(
            f"""\
{indent}\tstripe {i} devid {stripe.devid} offset {stripe.offset}
{indent}\tdev_uuid {stripe.dev_uuid}
""",
            end="",
            file=file,
        )


_register_item_handler(
    BtrfsType.CHUNK_ITEM,
    _parse_item_from_bytes(BtrfsChunk.from_bytes),
    _print_chunk,
)

# TODO: RAID_STRIPE handler


class BtrfsQgroupStatusFlag(_BtrfsFlag):
    ON = 1 << 0
    RESCAN = 1 << 1
    INCONSISTENT = 1 << 2
    SIMPLE_MODE = 1 << 3


_btrfs_qgroup_status_item_simple_quota_struct = struct.Struct("<5Q")
_btrfs_qgroup_status_item_struct = struct.Struct("<4Q")


class BtrfsQgroupStatusItem(NamedTuple):
    version: int
    generation: int
    flags: BtrfsQgroupStatusFlag
    rescan: int
    enable_gen: Optional[int]

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsQgroupStatusItem":
        # TODO: we should technically check the SIMPLE_QGROUP incompat flag instead.
        if len(b) >= _btrfs_qgroup_status_item_simple_quota_struct.size:
            (
                version,
                generation,
                flags,
                rescan,
                enable_gen,
            ) = _btrfs_qgroup_status_item_simple_quota_struct.unpack_from(b)
        else:
            (
                version,
                generation,
                flags,
                rescan,
            ) = _btrfs_qgroup_status_item_struct.unpack_from(b)
            enable_gen = None
        return BtrfsQgroupStatusItem(
            version=version,
            generation=generation,
            flags=BtrfsQgroupStatusFlag(flags),
            rescan=rescan,
            enable_gen=enable_gen,
        )


def _print_qgroup_status_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsQgroupStatusItem,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    enable_gen = "" if item.enable_gen is None else f" enable_gen {item.enable_gen}"
    # btrfs-progs as of v6.8.1 pretty-prints these flags without their numeric
    # value and adds "OFF" if the "ON" flag is not set.
    print(
        f"{indent}version {item.version} generation {item.generation} flags {item.flags} scan {item.rescan}{enable_gen}",
        file=file,
    )


_register_item_handler(
    BtrfsType.QGROUP_STATUS,
    _parse_item_from_bytes(BtrfsQgroupStatusItem.from_bytes),
    _print_qgroup_status_item,
)


_btrfs_qgroup_info_item_struct = struct.Struct("<5Q")


class BtrfsQgroupInfoItem(NamedTuple):
    generation: int
    rfer: int
    rfer_cmpr: int
    excl: int
    excl_cmpr: int

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsQgroupInfoItem":
        return BtrfsQgroupInfoItem._make(_btrfs_qgroup_info_item_struct.unpack_from(b))


def _print_qgroup_info_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsQgroupInfoItem,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"""\
{indent}generation {item.generation}
{indent}referenced {item.rfer} referenced_compressed {item.rfer_cmpr}
{indent}exclusive {item.excl} exclusive_compressed {item.excl_cmpr}
""",
        end="",
        file=file,
    )


_register_item_handler(
    BtrfsType.QGROUP_INFO,
    _parse_item_from_bytes(BtrfsQgroupInfoItem.from_bytes),
    _print_qgroup_info_item,
)


class BtrfsQgroupLimitFlag(_BtrfsFlag):
    MAX_RFER = 1 << 0
    MAX_EXCL = 1 << 1
    RSV_RFER = 1 << 2
    RSV_EXCL = 1 << 3
    RFER_CMPR = 1 << 4
    EXCL_CMPR = 1 << 5


_btrfs_qgroup_limit_item_struct = struct.Struct("<5Q")


class BtrfsQgroupLimitItem(
    NamedTuple(
        "BtrfsQgroupLimitItem",
        [
            ("flags", BtrfsQgroupLimitFlag),
            ("max_rfer", int),
            ("max_excl", int),
            ("rsv_rfer", int),
            ("rsv_excl", int),
        ],
    )
):
    def __new__(
        cls, flags: int, max_rfer: int, max_excl: int, rsv_rfer: int, rsv_excl: int
    ) -> "Self":
        return super().__new__(
            cls,
            flags=BtrfsQgroupLimitFlag(flags),
            max_rfer=max_rfer,
            max_excl=max_excl,
            rsv_rfer=rsv_rfer,
            rsv_excl=rsv_excl,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsQgroupLimitItem":
        return BtrfsQgroupLimitItem._make(
            _btrfs_qgroup_limit_item_struct.unpack_from(b)
        )


def _print_qgroup_limit_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: BtrfsQgroupLimitItem,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    # btrfs-progs as of v6.8.1 doesn't pretty-print these flags.
    print(
        f"""\
{indent}flags {item.flags}
{indent}max_referenced {item.max_rfer} max_exclusive {item.max_excl}
{indent}rsv_referenced {item.rsv_rfer} rsv_exclusive {item.rsv_excl}
""",
        end="",
        file=file,
    )


_register_item_handler(
    BtrfsType.QGROUP_LIMIT,
    _parse_item_from_bytes(BtrfsQgroupLimitItem.from_bytes),
    _print_qgroup_limit_item,
)

_register_item_handler(
    BtrfsType.QGROUP_RELATION,
    _parse_empty_item,
    _print_nothing,
)


class BtrfsBalanceFlag(_BtrfsFlag):
    DATA = 1 << 0
    SYSTEM = 1 << 1
    METADATA = 1 << 2
    FORCE = 1 << 3
    RESUME = 1 << 4


class BtrfsDiskBalanceArgsRange(NamedTuple):
    min: int
    max: int


def _disk_balance_range_from_args(
    min: int, max: int, upper_bound: bool
) -> BtrfsDiskBalanceArgsRange:
    if upper_bound:
        return BtrfsDiskBalanceArgsRange(0, (max << 32) | min)
    else:
        return BtrfsDiskBalanceArgsRange(min, max)


class BtrfsDiskBalanceArgsFlag(_BtrfsFlag):
    PROFILES = 1 << 0
    USAGE = 1 << 1
    DEVID = 1 << 2
    DRANGE = 1 << 3
    VRANGE = 1 << 4
    LIMIT = 1 << 5
    LIMIT_RANGE = 1 << 6
    STRIPES_RANGE = 1 << 7
    CONVERT = 1 << 8
    SOFT = 1 << 9
    USAGE_RANGE = 1 << 10


_btrfs_disk_balance_args_struct = struct.Struct("<QII7Q4I48x")


class BtrfsDiskBalanceArgs(
    NamedTuple(
        "BtrfsDiskBalanceArgs",
        [
            ("profiles", BtrfsBlockGroupFlag),
            ("usage", BtrfsDiskBalanceArgsRange),
            ("devid", int),
            ("pstart", int),
            ("pend", int),
            ("vstart", int),
            ("vend", int),
            ("target", BtrfsBlockGroupFlag),
            ("flags", BtrfsDiskBalanceArgsFlag),
            ("limit", BtrfsDiskBalanceArgsRange),
            ("stripes", BtrfsDiskBalanceArgsRange),
        ],
    )
):
    def __new__(
        cls,
        profiles: int,
        usage: BtrfsDiskBalanceArgsRange,
        devid: int,
        pstart: int,
        pend: int,
        vstart: int,
        vend: int,
        target: int,
        flags: int,
        limit: BtrfsDiskBalanceArgsRange,
        stripes: BtrfsDiskBalanceArgsRange,
    ) -> "Self":
        return super().__new__(
            cls,
            profiles=BtrfsBlockGroupFlag(profiles),
            usage=usage,
            devid=devid,
            pstart=pstart,
            pend=pend,
            vstart=vstart,
            vend=vend,
            target=BtrfsBlockGroupFlag(target),
            flags=BtrfsDiskBalanceArgsFlag(flags),
            limit=limit,
            stripes=stripes,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsDiskBalanceArgs":
        (
            profiles,
            usage_min,
            usage_max,
            devid,
            pstart,
            pend,
            vstart,
            vend,
            target,
            flags,
            limit_min,
            limit_max,
            stripes_min,
            stripes_max,
        ) = _btrfs_disk_balance_args_struct.unpack_from(b)
        return BtrfsDiskBalanceArgs(
            profiles=profiles,
            usage=_disk_balance_range_from_args(
                usage_min, usage_max, flags & BtrfsDiskBalanceArgsFlag.USAGE
            ),
            devid=devid,
            pstart=pstart,
            pend=pend,
            vstart=vstart,
            vend=vend,
            target=target,
            flags=flags,
            limit=_disk_balance_range_from_args(
                limit_min, limit_max, flags & BtrfsDiskBalanceArgsFlag.LIMIT
            ),
            stripes=BtrfsDiskBalanceArgsRange(stripes_min, stripes_max),
        )


_btrfs_balance_item_flags_struct = struct.Struct("<Q")


class BtrfsBalanceItem(
    NamedTuple(
        "BtrfsBalanceItem",
        [
            ("flags", BtrfsBalanceFlag),
            ("data", BtrfsDiskBalanceArgs),
            ("meta", BtrfsDiskBalanceArgs),
            ("sys", BtrfsDiskBalanceArgs),
        ],
    )
):
    def __new__(
        cls,
        flags: int,
        data: BtrfsDiskBalanceArgs,
        meta: BtrfsDiskBalanceArgs,
        sys: BtrfsDiskBalanceArgs,
    ) -> "Self":
        return super().__new__(
            cls,
            flags=BtrfsBalanceFlag(flags),
            data=data,
            meta=meta,
            sys=sys,
        )

    @classmethod
    def _make(cls, iterable: Iterable[Any]) -> "Self":
        return cls.__new__(cls, *iterable)

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsBalanceItem":
        view = memoryview(b)
        return BtrfsBalanceItem(
            *_btrfs_balance_item_flags_struct.unpack_from(b),
            *[
                BtrfsDiskBalanceArgs.from_bytes(
                    view[
                        _btrfs_balance_item_flags_struct.size
                        + i * _btrfs_disk_balance_args_struct.size :
                    ]
                )
                for i in range(3)
            ],
        )


def _parse_temporary_item(
    key: BtrfsKey, raw_data: bytes
) -> Union[BtrfsBalanceItem, None]:
    if key.objectid == BtrfsObjectid.BALANCE:
        return BtrfsBalanceItem.from_bytes(raw_data)
    else:
        return None


def _print_balance_item(
    item: BtrfsBalanceItem, indent: str, file: "Optional[SupportsWrite[str]]"
) -> None:
    # btrfs-progs as of v6.8.1 doesn't pretty-print any of these flags.
    print(f"{indent}balance status flags {item.flags}", file=file)
    for title, args in (
        ("DATA", item.data),
        ("METADATA", item.meta),
        ("SYSTEM", item.sys),
    ):
        # btrfs-progs as of v6.8.1 doesn't handle the USAGE and LIMIT flags
        # when printing {usage,limit}_{min,max}. This is a bug.
        print(
            f"""\
{indent}{title}
{indent}profiles {args.profiles} devid {args.devid} target {args.target} flags {args.flags}
{indent}usage_min {args.usage.min} usage_max {args.usage.max} pstart {args.pstart} pend {args.pend}
{indent}vstart {args.vstart} vend {args.vend} limit_min {args.limit.min} limit_max {args.limit.max}
{indent}stripes_min {args.stripes.min} stripes_max {args.stripes.max}
""",
            end="",
            file=file,
        )


def _print_temporary_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: Union[BtrfsBalanceItem, None],
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"{indent}temporary item objectid {key.objectid} offset {key.offset}", file=file
    )
    if isinstance(item, BtrfsBalanceItem):
        _print_balance_item(item, indent, file)
    else:
        _print_unknown_item(key, raw_data, item, indent, file)


_register_item_handler(
    BtrfsType.TEMPORARY_ITEM,
    _parse_temporary_item,
    _print_temporary_item,
)


_btrfs_dev_stats_item_struct = struct.Struct("<5Q")


class BtrfsDevStatsItem(NamedTuple):
    write_errs: int
    read_errs: int
    flush_errs: int
    corruption_errs: int
    generation_errs: int

    @staticmethod
    def from_bytes(b: bytes) -> "BtrfsDevStatsItem":
        return BtrfsDevStatsItem._make(_btrfs_dev_stats_item_struct.unpack_from(b))


def _parse_persistent_item(
    key: BtrfsKey, raw_data: bytes
) -> Union[BtrfsDevStatsItem, None]:
    if key.objectid == 0:  # BTRFS_DEV_STATS_OBJECTID
        return BtrfsDevStatsItem.from_bytes(raw_data)
    else:
        return None


def _print_dev_stats_item(
    item: BtrfsDevStatsItem, indent: str, file: "Optional[SupportsWrite[str]]"
) -> None:
    print(
        f"""\
{indent}device stats
{indent}write_errs {item.write_errs} read_errs {item.read_errs} flush_errs {item.flush_errs} corruption_errs {item.flush_errs} generation {item.generation_errs}
""",
        end="",
        file=file,
    )


def _print_persistent_item(
    key: BtrfsKey,
    raw_data: bytes,
    item: Union[BtrfsDevStatsItem, None],
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(
        f"{indent}persistent item objectid {_objectid_to_str(key.objectid, key.type)} offset {key.offset}",
        file=file,
    )
    if isinstance(item, BtrfsDevStatsItem):
        _print_dev_stats_item(item, indent, file)
    else:
        _print_unknown_item(key, raw_data, item, indent, file)


_register_item_handler(
    BtrfsType.PERSISTENT_ITEM,
    _parse_persistent_item,
    _print_persistent_item,
)


# TODO: DEV_REPLACE handler


def _parse_uuid_tree_item(key: BtrfsKey, raw_data: bytes) -> Sequence[int]:
    return [x[0] for x in struct.iter_unpack("<Q", raw_data)]


def _print_uuid_tree_item(
    key: BtrfsKey,
    raw_data: bytes,
    ids: Sequence[int],
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    for id in ids:
        print(f"{indent}subvol_id {id}", file=file)


_register_item_handler(
    BtrfsType.UUID_KEY_SUBVOL,
    _parse_uuid_tree_item,
    _print_uuid_tree_item,
)
_register_item_handler(
    BtrfsType.UUID_KEY_RECEIVED_SUBVOL,
    _parse_uuid_tree_item,
    _print_uuid_tree_item,
)


def _print_string_item(
    key: BtrfsKey,
    raw_data: bytes,
    string: bytes,
    indent: str,
    file: "Optional[SupportsWrite[str]]",
) -> None:
    print(f"{indent}item data {escape_ascii_string(string)}", file=file)


_register_item_handler(
    BtrfsType.STRING_ITEM,
    _parse_raw_item,
    _print_string_item,
)


class BtrfsItemData:
    key: "Final[BtrfsKey]"
    offset: "Final[int]"
    size: "Final[int]"
    raw_data: "Final[bytes]"

    def __init__(
        self,
        key: BtrfsKey,
        offset: int,
        size: int,
        raw_data: bytes,
    ) -> None:
        self.key = key
        self.offset = offset
        self.size = size
        self.raw_data = raw_data

    def __repr__(self) -> str:
        return f"BtrfsItemData(key={self.key!r}, offset={self.offset!r}, size={self.size!r}, raw_data={self.raw_data!r})"

    @cached_property
    def data(self) -> Any:
        return _btrfs_item_handlers.get(
            self.key.type, _unknown_item_type_handler
        ).parse(self.key, self.raw_data)


class BtrfsNode(NamedTuple):
    header: BtrfsHeader
    ptrs: Sequence[BtrfsKeyPtr]


class BtrfsLeaf(NamedTuple):
    header: BtrfsHeader
    items: Sequence[BtrfsItemData]


_btrfs_disk_key_size = 17  # sizeof(struct btrfs_disk_key)
_btrfs_leaf_items_offset = 101  # offsetof(struct btrfs_leaf, items)
_btrfs_item_size = 25  # sizeof(struct btrfs_item)
_btrfs_node_ptrs_offset = 101  # offsetof(struct btrfs_node, ptrs)
_btrfs_key_ptr_size = 33  # sizeof(prog.type("struct btrfs_key_ptr"))
_btrfs_key_ptr_blockptr_offset = 17  # offsetof(struct btrfs_key_ptr, blockptr)
_btrfs_header_nritems_offset = 96  # offsetof(struct btrfs_header, nritems)
_btrfs_header_level_offset = 100  # offsetof(struct btrfs_header, level)


def _read_extent_buffer_folios(eb: Object, start: int, len: int) -> bytes:
    prog = eb.prog_

    eb_addr = eb.addr.value_()
    if eb_addr:
        return prog.read(eb_addr + start, len)

    pagep_type = prog.type("struct page *")

    # TODO: we should probably add real folio_size() and folio_address()
    # helpers.
    folios = eb.folios
    unit_size = page_size(cast(pagep_type, folios[0])).value_()
    i = start // unit_size
    offset = (eb.start.value_() + start) & (unit_size - 1)
    ret = []
    while len > 0:
        cur = min(len, unit_size - offset)
        ret.append(
            prog.read(page_to_virt(cast(pagep_type, folios[i])).value_() + offset, cur)
        )
        len -= cur
        offset = 0
        i += 1
    return b"".join(ret)


def _read_extent_buffer_pages(eb: Object, start: int, len: int) -> bytes:
    prog = eb.prog_
    unit_size = prog["PAGE_SIZE"].value_()
    i = start // unit_size
    offset = (eb.start.value_() + start) & (unit_size - 1)
    ret = []
    while len > 0:
        cur = min(len, unit_size - offset)
        ret.append(prog.read(page_to_virt(eb.pages[i]).value_() + offset, cur))
        len -= cur
        offset = 0
        i += 1
    return b"".join(ret)


def read_extent_buffer(eb: Object, start: IntegerLike, len: IntegerLike) -> bytes:
    prog = eb.prog_
    start = operator.index(start)
    len = operator.index(len)
    try:
        impl = prog.cache["read_extent_buffer"]
    except KeyError:
        # Since Linux kernel commit 082d5bb9b336 ("btrfs: migrate
        # extent_buffer::pages[] to folio") (in v6.8), an extent_buffer
        # contains an array of folios. Before that, it's an array of pages.
        if prog.type("struct extent_buffer").has_member("folios"):
            impl = _read_extent_buffer_folios
        else:
            impl = _read_extent_buffer_pages
        prog.cache["read_extent_buffer"] = impl
    return impl(eb, start, len)


def btrfs_header_level(eb: Object) -> int:
    return read_extent_buffer(eb, _btrfs_header_level_offset, 1)[0]


def btrfs_header_nritems(eb: Object) -> int:
    return int.from_bytes(
        read_extent_buffer(eb, _btrfs_header_nritems_offset, 4), "little"
    )


def btrfs_node_blockptr(eb: Object, nr: IntegerLike) -> int:
    return int.from_bytes(
        read_extent_buffer(
            eb,
            _btrfs_node_ptrs_offset
            + _btrfs_key_ptr_size * operator.index(nr)
            + _btrfs_key_ptr_blockptr_offset,
            8,
        ),
        "little",
    )


def _btrfs_bin_search(
    eb: Object, p: int, item_size: int, key: BtrfsKey
) -> Tuple[int, int]:
    low = 0
    high = btrfs_header_nritems(eb)

    while low < high:
        mid = (low + high) // 2
        offset = p + mid * item_size
        disk_key = BtrfsKey.from_bytes(
            read_extent_buffer(eb, offset, _btrfs_disk_key_size)
        )
        if disk_key < key:
            low = mid + 1
        elif disk_key > key:
            high = mid
        else:
            return 0, mid
    return 1, low


class BtrfsTreeError(Exception):
    pass


def find_extent_buffer(fs_info: Object, start: IntegerLike) -> Object:
    return cast(
        "struct extent_buffer *",
        radix_tree_lookup(
            fs_info.buffer_radix.address_of_(), start >> fs_info.sectorsize_bits
        ),
    )


def _get_block_for_search(fs_info: Object, eb: Object, slot: int) -> Object:
    blocknr = btrfs_node_blockptr(eb, slot)

    tmp = cast(
        eb.type_,
        radix_tree_lookup(
            fs_info.buffer_radix.address_of_(), blocknr >> fs_info.sectorsize_bits
        ),
    )
    if not tmp:
        raise BtrfsTreeError(f"extent_buffer {blocknr} is not cached")
    if not tmp.refs.counter:
        raise BtrfsTreeError(f"extent_buffer {blocknr} is dead")
    if not tmp.bflags & (1 << fs_info.prog_["EXTENT_BUFFER_UPTODATE"]):
        raise BtrfsTreeError(f"extent_buffer {blocknr} is not up to date")
    # The kernel also checks the eb's transid and level to detect corruption,
    # but we probably don't need to.
    return tmp


def btrfs_search_slot(
    root: Object,
    key: BtrfsKey,
    *,
    search_commit_root: bool = False,
    allow_partial: bool = False,
) -> Tuple[int, List[Object], List[int]]:
    fs_info = root.fs_info.read_()

    nodes = []
    slots = []
    prev_cmp = -1
    if search_commit_root:
        b = root.commit_root.read_()
    else:
        b = root.node.read_()
    level = btrfs_header_level(b)
    try:
        for level in range(level, -1, -1):
            nodes.append(b)

            if prev_cmp == 0:
                slot = 0
                ret = 0
            else:
                if level == 0:
                    ret, slot = _btrfs_bin_search(
                        b, _btrfs_leaf_items_offset, _btrfs_item_size, key
                    )
                else:
                    ret, slot = _btrfs_bin_search(
                        b, _btrfs_node_ptrs_offset, _btrfs_key_ptr_size, key
                    )
                prev_cmp = ret

            if level == 0:
                slots.append(slot)
                break

            if ret and slot > 0:
                slot -= 1
            slots.append(slot)

            b = _get_block_for_search(fs_info, b, slot)
    except BtrfsTreeError as e:
        if not allow_partial:
            raise
        ret = -1
        print(e, file=sys.stderr)
    nodes.reverse()
    slots.reverse()
    return ret, nodes, slots


def btrfs_next_leaf(nodes: List[Object], slots: List[int]) -> int:
    for i in range(1, len(slots)):
        if slots[i] + 1 < btrfs_header_nritems(nodes[i]):
            break
    else:
        return 1
    fs_info = nodes[0].fs_info.read_()
    slots[i] += 1
    for j in range(i - 1, -1, -1):
        slots[j] = 0
        nodes[j] = _get_block_for_search(fs_info, nodes[j + 1], slots[j + 1])
    return 0


def btrfs_read_item(eb: Object, slot: IntegerLike) -> BtrfsItemData:
    if btrfs_header_level(eb) != 0:
        raise ValueError("buffer is not leaf")
    slot = operator.index(slot)
    if slot >= btrfs_header_nritems(eb):
        raise IndexError("slot is out of bounds")

    item_buf = read_extent_buffer(
        eb, _btrfs_leaf_items_offset + slot * _btrfs_item_size, _btrfs_item_size
    )
    objectid, type, offset, data_offset, data_size = _btrfs_item_struct.unpack(item_buf)

    key = BtrfsKey(objectid, type, offset)

    raw_data = read_extent_buffer(eb, _btrfs_leaf_items_offset + data_offset, data_size)
    return BtrfsItemData(key, data_offset, data_size, raw_data)


def _parse_extent_buffer(buf: bytes) -> Union[BtrfsNode, BtrfsLeaf]:
    header = BtrfsHeader.from_bytes(buf)
    if header.level == 0:
        items = []
        for i in range(header.nritems):
            (
                objectid,
                type,
                offset,
                data_offset,
                data_size,
            ) = _btrfs_item_struct.unpack_from(
                buf, _btrfs_leaf_items_offset + i * _btrfs_item_size
            )
            key = BtrfsKey(objectid, type, offset)
            raw_data = buf[
                _btrfs_leaf_items_offset
                + data_offset : _btrfs_leaf_items_offset
                + data_offset
                + data_size
            ]
            items.append(
                BtrfsItemData(
                    key,
                    data_offset,
                    data_size,
                    raw_data,
                )
            )
        return BtrfsLeaf(header, items)
    else:
        view = memoryview(buf)
        return BtrfsNode(
            header,
            [
                BtrfsKeyPtr.from_bytes(
                    view[_btrfs_node_ptrs_offset + i * _btrfs_key_ptr_size :]
                )
                for i in range(header.nritems)
            ],
        )


def parse_extent_buffer(eb: Object) -> Union[BtrfsNode, BtrfsLeaf]:
    return _parse_extent_buffer(read_extent_buffer(eb, 0, eb.len.value_()))


def _print_btrfs_item(item: BtrfsItemData, indent: str = "") -> None:
    print(f"key {item.key} itemoff {item.offset} itemsize {item.size}")
    _btrfs_item_handlers.get(item.key.type, _unknown_item_type_handler).print(
        item.key,
        item.raw_data,
        item.data,
        indent + "\t",
        None,
    )


def print_btrfs_node(node: Union[BtrfsNode, BtrfsLeaf]) -> None:
    node_or_leaf = "leaf" if isinstance(node, BtrfsLeaf) else "node"
    print(
        f"{node_or_leaf} {node.header.bytenr} level {node.header.level} items {node.header.nritems} generation {node.header.generation} owner {node.header.owner}"
    )
    print(f"{node_or_leaf} {node.header.bytenr} flags {node.header.flags:#x}")
    print(f"fs uuid {node.header.fsid}")
    print(f"chunk uuid {node.header.chunk_tree_uuid}")
    if isinstance(node, BtrfsLeaf):
        for i, item in enumerate(node.items):
            print(f"\titem {i} ", end="")
            _print_btrfs_item(item, "\t")
    else:
        for i, ptr in enumerate(node.ptrs):
            # btrfs-progs as of v6.8.1 doesn't print the "ptr {i}", but it's
            # useful for making sense of slot numbers.
            print(f"\tptr {i} key {ptr.key} block {ptr.blockptr} gen {ptr.generation}")


def print_extent_buffer(eb: Object) -> None:
    print_btrfs_node(parse_extent_buffer(eb))


def btrfs_print_tree_items(
    root: Object,
    *,
    min_key: BtrfsKey = BTRFS_MIN_KEY,
    max_key: BtrfsKey = BTRFS_MAX_KEY,
) -> None:
    ret, nodes, slots = btrfs_search_slot(root, min_key)
    while True:
        node: BtrfsLeaf = parse_extent_buffer(nodes[0])  # type: ignore[assignment]
        for item in node.items:
            if item.key > max_key:
                return
            if item.key >= min_key:
                _print_btrfs_item(item)
        if btrfs_next_leaf(nodes, slots):
            break
