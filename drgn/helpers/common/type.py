# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Types
-----

The ``drgn.helpers.common.type`` module provides generic helpers for working
with types in ways that aren't provided by the core drgn library.
"""

import enum
import inspect
import os
import re
import typing
from typing import Any, Callable, Container, Dict, Optional, TypeVar, Union

from drgn import Object, Type

__all__ = ("enum_type_to_class",)


F = TypeVar("F", bound=Callable[..., Any])


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


def _parse_docstring_c_types(doc: str) -> Dict[str, str]:
    current_param = ""
    params = {}
    expr = re.compile(r":(param (\w+)|returns?|retval):.*``([^`]+)``.*")
    # expr = re.compile(r":param (\w+): (.*)")

    def add_param() -> None:
        m = expr.fullmatch(current_param)
        if m:
            if m.group(1).startswith("param"):
                params[m.group(2)] = m.group(3)
            else:
                params["return"] = m.group(3)

    for line in doc.splitlines():
        line = line.strip()
        # End the previous param with a new one, or blank line
        if (not line or line.startswith(":")) and current_param:
            add_param()
            current_param = ""
        # Continue loading param if we already started one, or at declaration
        if current_param:
            current_param = "{current_param} {line}"
        elif line.startswith(":"):
            current_param = line
    if current_param:
        add_param()
    return params


def _check_simple_type(
    expected: Optional[str],
    strict: bool,
    name: str,
    fname: str,
    required: bool,
) -> Optional[Callable[[Any], None]]:
    if not expected and required:
        raise ValueError(
            f"{fname}: Drgn Type Checking: parameter {name} has a "
            "Python type annotation, but is missing the corresponding "
            "C type annotation in the docstring."
        )
    elif not expected:
        return None

    if os.getenv("DRGN_TYPE_CHECK") == "verbose":
        print(f"{fname}: {name}: simple: {expected}")

    def _check(value: Any) -> None:
        if os.getenv("DRGN_TYPE_CHECK") == "verbose":
            print(f"{fname}: {name}: checking")
        if not isinstance(value, Object):
            if strict:
                raise TypeError(
                    f"{fname}: Drgn Type Error: {name}:\n"
                    "expected an Object of type "
                    f" {expected}, but instead got Python value of "
                    f" type {type(value)}"
                )
            else:
                return

        # At this point, we have a drgn.Object, so do the "type checking" by
        # string comparison.
        drgn_type = value.type_.type_name()
        if drgn_type != expected:
            raise TypeError(
                f"{fname}: Drgn Type Error: {name}:\n"
                f"expected an Object of type '{expected}',"
                f" but the argument has type '{drgn_type}'"
            )

    return _check


def _create_checkers(
    sig: inspect.Signature, doc: str, fname: str, strict: bool
) -> Dict[str, Callable[[Any], None]]:
    c_types = _parse_docstring_c_types(doc)
    if not c_types:
        raise ValueError(
            f"Requested type checking on {fname}, but there are no"
            " C types in the docstring"
        )
    checkers = {}
    for name, param in sig.parameters.items():
        c_type = c_types[name]
        annot = param.annotation
        origin = typing.get_origin(annot)
        args = typing.get_args(annot)
        checker = None
        if annot is Object:
            checker = _check_simple_type(c_type, True, name, fname, strict)
        elif origin is Union and Object in args:
            checker = _check_simple_type(c_type, False, name, fname, strict)
        elif origin is list and args[0] is Object:
            pass
        elif origin is dict:
            pass
        elif origin is tuple:
            pass
        if checker:
            checkers[name] = checker
    return checkers


def drgn_type_check(func: F) -> F:
    """
    Annotation which performs runtime type checking on Drgn Objects

    Use this function annotation, along with a well-formatted docstring
    containing C types, to check the types of Object arguments and return
    values. The docstring should contain lines something like this:

    .. code::

        :param task: object of type ``struct task_struct *``
        :return: current CPU number as an ``int``

    This is the reStructuredText standard docstring format. It is important for
    parameter names to be surrounded by colons, as shown, and for the C type
    information to be enclosed in double-backticks. Parameter documentation may
    span multiple lines, and it is terminated by an empty line, a new line which
    starts with a colon, or the end of the docstring.

    The type checker will be activated when the environment variable
    ``DRGN_TYPE_CHECK`` is set to any value. When the type checker is inactive,
    it has no overhead. The type checker should not be enabled in production,
    but would be useful during interactive debugging, development, and testing.

    When activated, the type checker will examine three sources of information:

    1. The argument passed to the function
    2. The type annotation for the argument
    3. The C type string contained in the documentation

    Currently, the type checker can only handle simple parameters of type
    "Object", or Unions containing the type "Object", such as
    ``Optional[Object]``. The actual type check is done by comparing C type name
    against the string type name included in the docstring. This, of course,
    leaves room for ambiguity: for example, the type name may be
    """
    if not os.getenv("DRGN_TYPE_CHECK"):
        return func
    doc = func.__doc__
    if not doc:
        raise ValueError(
            f"Cannot type check function {func.__name__} without docstring"
        )
    sig = inspect.signature(func)
    checkers = _create_checkers(sig, doc, func.__name__, False)
    ret_checker = checkers.pop("return", None)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        for name, checker in checkers.items():
            checker(bound.arguments[name])
        retval = func(*args, **kwargs)
        if ret_checker:
            ret_checker(retval)
        return retval

    return wrapper  # type: ignore
