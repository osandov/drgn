# Copyright (c) Western Digital Corporation, and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
BTRFS File System
-----------------

The ``drgn.helpers.linux.btrfs`` module provides helpers for working with the
Linux BTRFS filesystem.
"""

from drgn import Object, Program
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.mm import page_to_virt

__all__ = (
    "BTRFS_BLOCK_GROUP_FLAGS",
    "BTRFS_BLOCK_GROUP_RUNTIME_FLAGS",
    "BTRFS_EXTENT_BUFFER_FLAGS",
    "btrfs_header",
)

BTRFS_BLOCK_GROUP_FLAGS = [
    ("BTRFS_BLOCK_GROUP_DATA", 0),
    ("BTRFS_BLOCK_GROUP_SYSTEM", 1),
    ("BTRFS_BLOCK_GROUP_METADATA", 2),
    ("BTRFS_BLOCK_GROUP_RAID0", 3),
    ("BTRFS_BLOCK_GROUP_RAID1", 4),
    ("BTRFS_BLOCK_GROUP_DUP", 5),
    ("BTRFS_BLOCK_GROUP_RAID10", 6),
    ("BTRFS_BLOCK_GROUP_RAID5", 9),
    ("BTRFS_BLOCK_GROUP_RAID6", 8),
    ("BTRFS_BLOCK_GROUP_RAID1C3", 9),
    ("BTRFS_BLOCK_GROUP_RAID1C4", 10),
]

BTRFS_BLOCK_GROUP_RUNTIME_FLAGS = [
    ("BLOCK_GROUP_FLAG_IREF", 0),
    ("BLOCK_GROUP_FLAG_REMOVED", 1),
    ("BLOCK_GROUP_FLAG_TO_COPY", 2),
    ("BLOCK_GROUP_FLAG_RELOCATING_REPAIR", 3),
    ("BLOCK_GROUP_FLAG_CHUNK_ITEM_INSERTED", 4),
    ("BLOCK_GROUP_FLAG_ZONE_IS_ACTIVE", 5),
    ("BLOCK_GROUP_FLAG_ZONED_DATA_RELOC", 6),
    ("BLOCK_GROUP_FLAG_NEEDS_FREE_SPACE", 7),
    ("BLOCK_GROUP_FLAG_SEQUENTIAL_ZONE", 8),
]


# Extent Buffer Flags used for decoding
# >>> print(hex(eb.bflags))
# 0x85
# >>> decode_flags(eb.bflags, BTRFS_EXTENT_BUFFER_FLAGS)
# 'EXTENT_BUFFER_UPTODATE|EXTENT_BUFFER_TREE_REF|EXTENT_BUFFER_ZONED_ZEROOUT'
BTRFS_EXTENT_BUFFER_FLAGS = [
    ("EXTENT_BUFFER_UPTODATE", 0),
    ("EXTENT_BUFFER_DIRTY", 1),
    ("EXTENT_BUFFER_TREE_REF", 2),
    ("EXTENT_BUFFER_STALE", 3),
    ("EXTENT_BUFFER_WRITEBACK", 4),
    ("EXTENT_BUFFER_UNMAPPED", 5),
    ("EXTENT_BUFFER_WRITE_ERR", 6),
    ("EXTENT_BUFFER_ZONED_ZEROOUT", 7),
    ("EXTENT_BUFFER_READING", 8),
]


def _offset_in_page(prog: Program, p: int) -> int:
    return int(p & ~prog["PAGE_MASK"])


@takes_program_or_default
def btrfs_header(prog: Program, eb: Object) -> Object:
    """
    Lookup ``struct btrfs_header`` from a given exent_buffer

    :param eb: ``struct btrfs_extent_buffer *`` to get the header from.
    :return: ``struct btrfs_header *``
    """
    page = eb.folios[0].page
    addr = page_to_virt(page.address_of_()) + _offset_in_page(prog, int(eb.start))
    return Object(prog, "struct btrfs_header", address=addr)
