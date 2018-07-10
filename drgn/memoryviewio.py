# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import io
from typing import Optional


# Based on BytesIO from Lib/_pyio.py in CPython.
class MemoryViewIO(io.BufferedIOBase):
    def __init__(self, mem: memoryview) -> None:
        self._mem = mem
        self._pos = 0

    def close(self) -> None:
        del self._mem
        super().close()

    # Returns memoryview instead of bytes, which isn't technically correct.
    def read(self, size: Optional[int] = -1) -> memoryview:  # type: ignore
        if self.closed:
            raise ValueError("read from closed file")
        if size is None:
            size = -1
        else:
            try:
                size_index = size.__index__
            except AttributeError:
                raise TypeError(f"{size!r} is not an integer")
            else:
                size = size_index()
        if size < 0:
            size = len(self._mem)
        newpos = min(len(self._mem), self._pos + size)
        m = self._mem[self._pos:newpos]
        self._pos = newpos
        return m

    def read1(self, size: Optional[int] = -1) -> memoryview:  # type: ignore
        return self.read(size)

    def seek(self, pos: int, whence: int = 0) -> int:
        if self.closed:
            raise ValueError("seek on closed file")
        try:
            pos_index = pos.__index__
        except AttributeError:
            raise TypeError(f"{pos!r} is not an integer")
        else:
            pos = pos_index()
        if whence == 0:
            if pos < 0:
                raise ValueError("negative seek position %r" % (pos,))
            self._pos = pos
        elif whence == 1:
            self._pos = max(0, self._pos + pos)
        elif whence == 2:
            self._pos = max(0, len(self._mem) + pos)
        else:
            raise ValueError("unsupported whence value")
        return self._pos

    def tell(self) -> int:
        if self.closed:
            raise ValueError("tell on closed file")
        return self._pos

    def readable(self) -> bool:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return True

    def writable(self) -> bool:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return False

    def seekable(self) -> bool:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return True
