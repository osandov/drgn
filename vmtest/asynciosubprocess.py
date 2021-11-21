# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio
from contextlib import contextmanager
import os
from subprocess import CalledProcessError as CalledProcessError
from typing import Any, Iterator, Tuple


async def check_call(*args: Any, **kwds: Any) -> None:
    proc = await asyncio.create_subprocess_exec(*args, **kwds)
    returncode = await proc.wait()
    if returncode != 0:
        raise CalledProcessError(returncode, args)


async def check_output(*args: Any, **kwds: Any) -> bytes:
    kwds["stdout"] = asyncio.subprocess.PIPE
    proc = await asyncio.create_subprocess_exec(*args, **kwds)
    stdout = (await proc.communicate())[0]
    if proc.returncode:
        raise CalledProcessError(proc.returncode, args)
    return stdout


async def check_output_shell(cmd: str, **kwds: Any) -> bytes:
    kwds["stdout"] = asyncio.subprocess.PIPE
    proc = await asyncio.create_subprocess_shell(cmd, **kwds)
    stdout = (await proc.communicate())[0]
    if proc.returncode:
        raise CalledProcessError(proc.returncode, cmd)
    return stdout


@contextmanager
def pipe_context() -> Iterator[Tuple[int, int]]:
    pipe_r = pipe_w = None
    try:
        pipe_r, pipe_w = os.pipe()
        yield pipe_r, pipe_w
    finally:
        if pipe_r is not None:
            os.close(pipe_r)
        if pipe_w is not None:
            os.close(pipe_w)
