# Copyright 2018-2019 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""Mock implementations for testing"""

from typing import NamedTuple, Optional

from _drgn import mock_program, Type


__all__ = [
    'MockMemorySegment',
    'MockObject',
    'MockType',
    'mock_program',
]


class MockMemorySegment(NamedTuple):
    """Memory segment for mock_program()."""
    buf: bytes
    virt_addr: Optional[int] = None
    phys_addr: Optional[int] = None


class MockType(NamedTuple):
    """Type for mock_program()."""
    type: Type
    filename: Optional[str] = None


class MockObject(NamedTuple):
    """Object for mock_program()."""
    type: Type
    name: str
    is_enumerator: bool = False
    address: int = 0
    byteorder: Optional[str] = None
    filename: Optional[str] = None
