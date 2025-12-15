# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, Callable, Protocol, TypeVar, Union, cast

if TYPE_CHECKING:
    if sys.version_info < (3, 10):
        from typing_extensions import Concatenate, ParamSpec
    else:
        from typing import Concatenate, ParamSpec  # novermin

    P = ParamSpec("P")

    class _Method(Protocol[P]):
        def __call__(s, /, self: Any, *args: P.args, **kwargs: P.kwargs) -> Any: ...


A = TypeVar("A")
T = TypeVar("T")
C = TypeVar("C", bound=Callable[..., Any])


# Based on https://github.com/python/cpython/pull/121693.
def copy_func_params(
    source: Callable[P, Any]
) -> Callable[[Callable[..., T]], Callable[P, T]]:
    def decorator(func: Callable[..., T]) -> Callable[P, T]:
        return cast("Callable[P, T]", func)

    return decorator


def copy_func_signature(source: C) -> Callable[[Callable[..., Any]], C]:
    def decorator(func: Callable[..., Any]) -> C:
        return cast(C, func)

    return decorator


def copy_method_params(
    source: Union[
        Callable[Concatenate[Any, P], Any],
        # This covers the case where the method has non-positional-only self
        # and **kwargs. See python/mypy#19051.
        _Method[P],
    ]
) -> Callable[[Callable[Concatenate[A, ...], T]], Callable[Concatenate[A, P], T]]:
    def decorator(
        # For some reason, the same _Method trick we use for source doesn't
        # work here, so if the target takes **kwargs, self must be
        # positional-only.
        func: Callable[Concatenate[Any, ...], T]
    ) -> Callable[Concatenate[A, P], T]:
        return cast("Callable[Concatenate[A, P], T]", func)

    return decorator
