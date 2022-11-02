# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from typing import Optional


def dot_join(*args: Optional[str]) -> str:
    return ".".join([s for s in args if s])
