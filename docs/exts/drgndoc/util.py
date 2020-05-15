# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

from typing import Optional


def dot_join(*args: Optional[str]) -> str:
    return ".".join([s for s in args if s])
