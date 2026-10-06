# Copyright (c) 2026, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
ctypes binding to libbpfwalk -- the in-kernel traversal offload backend.

This is a thin, optional wrapper. If the library is not present or a session
cannot be opened (no BPF privilege, unsupported kernel), the callers fall back
to drgn's own userspace implementation. See _bpfwalk_accel.py for the
integration point.

The library location is resolved as: the LIBBPFWALK environment variable if
set, otherwise the in-tree build at ``<repo>/bpfwalk/build/libbpfwalk.so``,
otherwise the dynamic linker's default search path.
"""

import ctypes
import os
from pathlib import Path
from typing import Iterator, Optional

_lib: "Optional[ctypes.CDLL]" = None
_lib_failed = False

# How many addresses to pull across the boundary per bpfwalk_walk_next() call.
_BATCH = 1024


def _lib_candidates() -> "Iterator[str]":
    env = os.environ.get("LIBBPFWALK")
    if env:
        yield env
    # In-tree build: drgn/helpers/linux/_bpfwalk.py -> repo root is parents[3].
    yield str(
        Path(__file__).resolve().parents[3]
        / "bpfwalk"
        / "build"
        / "libbpfwalk.so"
    )
    yield "libbpfwalk.so"  # dynamic linker search path


def _load() -> "Optional[ctypes.CDLL]":
    global _lib, _lib_failed
    if _lib is not None:
        return _lib
    if _lib_failed:
        return None
    lib = None
    for cand in _lib_candidates():
        try:
            lib = ctypes.CDLL(cand)
            break
        except OSError:
            continue
    if lib is None:
        _lib_failed = True
        return None
    lib.bpfwalk_open.restype = ctypes.c_void_p
    lib.bpfwalk_close.argtypes = [ctypes.c_void_p]
    lib.bpfwalk_has.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.bpfwalk_has.restype = ctypes.c_int
    lib.bpfwalk_walk_open.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    lib.bpfwalk_walk_open.restype = ctypes.c_void_p
    lib.bpfwalk_walk_next.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_size_t,
    ]
    lib.bpfwalk_walk_next.restype = ctypes.c_int
    lib.bpfwalk_walk_close.argtypes = [ctypes.c_void_p]
    _lib = lib
    return lib


class BpfwalkSession:
    """A libbpfwalk session; drives named in-kernel walkers."""

    def __init__(self, lib: "ctypes.CDLL", handle: int) -> None:
        self._lib = lib
        self._handle = handle

    @classmethod
    def open(cls) -> "Optional[BpfwalkSession]":
        """Open a session, or return None if bpfwalk can't run here."""
        lib = _load()
        if lib is None:
            return None
        handle = lib.bpfwalk_open()
        if not handle:
            return None
        return cls(lib, handle)

    def has(self, walker: str) -> bool:
        """Whether the named walker is available (its BPF object loads)."""
        return bool(self._lib.bpfwalk_has(self._handle, walker.encode()))

    def walk(self, walker: str, args: bytes = b"") -> Iterator[int]:
        """Yield the kernel addresses enumerated by the named walker."""
        argp = args if args else None
        cursor = self._lib.bpfwalk_walk_open(
            self._handle, walker.encode(), argp, len(args)
        )
        if not cursor:
            return
        try:
            buf = (ctypes.c_uint64 * _BATCH)()
            while True:
                n = self._lib.bpfwalk_walk_next(
                    cursor, buf, ctypes.sizeof(ctypes.c_uint64), _BATCH
                )
                if n <= 0:
                    break  # 0 = end of iteration; <0 = error (fall short)
                for i in range(n):
                    yield buf[i]
        finally:
            self._lib.bpfwalk_walk_close(cursor)

    def close(self) -> None:
        if self._handle:
            self._lib.bpfwalk_close(self._handle)
            self._handle = 0

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
