# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Types
-----

The ``drgn.helpers.common.type`` module provides generic helpers for working
with types in ways that aren't provided by the core drgn library.
"""

import enum
import typing
from typing import Container

from drgn import Type

__all__ = ("enum_type_to_class",)


def enum_type_to_class(
    type: Type, name: str, exclude: Container[str] = (), prefix: str = ""
) -> typing.Type[enum.IntEnum]:
    """
    Get an :class:`enum.IntEnum` class from an enumerated :class:`drgn.Type`.

    :param type: Enumerated type to convert.
    :param name: Name of the ``IntEnum`` type to create.
    :param exclude: Container (e.g., list or set) of enumerator names to
        exclude from the created ``IntEnum``.
    :param prefix: Prefix to strip from the beginning of enumerator names.
    """
    if type.enumerators is None:
        raise TypeError("enum type is incomplete")
    enumerators = [
        (name[len(prefix) :] if name.startswith(prefix) else name, value)
        for (name, value) in type.enumerators
        if name not in exclude
    ]
    return enum.IntEnum(name, enumerators)  # type: ignore  # python/mypy#4865
