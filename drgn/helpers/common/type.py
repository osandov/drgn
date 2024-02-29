# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Types
-----

The ``drgn.helpers.common.type`` module provides generic helpers for working
with types in ways that aren't provided by the core drgn library.
"""

import enum
import re
import typing
from typing import Container

from drgn import Object, Program, Type

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


def eval_typed_expression(prog: Program, expr: str) -> Object:
    """
    Evaluate a C typed expression and return the resulting Object

    In many cases, drgn may format an Object value like this:

        (type)integer_value

    For example, ``(struct task_struct *)0xffff9ea240dd5640``. This function is
    able to parse strings like these and return an equivalent object.

    :param expr: Expression of the form "(type)int_literal"
    :returns: The equivalent Object
    """
    match = re.fullmatch(r"\s*\(([^\)]+)\)\s*(0x[0-9a-zA-Z]+|[0-9]+)\s*", expr)
    if not match:
        raise ValueError("only expressions of the form (type)integer are allowed")
    type_str, val_str = match.groups()
    val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
    return Object(prog, type_str, val)
