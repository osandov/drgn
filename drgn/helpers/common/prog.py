# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Program Decorators
------------------

The ``drgn.helpers.common.prog`` module provides decorators to transparently
use the :ref:`default program argument <default-program>`.
"""

import functools
import inspect
import typing

from drgn import Object, Program, get_default_prog

__all__ = (
    "takes_object_or_program_or_default",
    "takes_program_or_default",
)

# We don't need any of this at runtime.
if typing.TYPE_CHECKING:
    import sys
    from typing import Any, Optional, Protocol, TypeVar, overload  # novermin

    if sys.version_info < (3, 10):
        from typing_extensions import Callable, Concatenate, ParamSpec
    else:
        from typing import Callable, Concatenate, ParamSpec  # novermin

    P = ParamSpec("P")
    R = TypeVar("R")
    R_co = TypeVar("R_co", covariant=True)

    class TakesProgram(Protocol[P, R_co]):
        def __call__(self, prog: Program, *args: P.args, **kwargs: P.kwargs) -> R_co:
            ...

    class TakesProgramOrDefault(Protocol[P, R_co]):
        @overload
        def __call__(self, prog: Program, *args: P.args, **kwargs: P.kwargs) -> R_co:
            ...

        @overload
        def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R_co:
            ...

    class TakesObjectOrProgramOrDefault(Protocol[P, R_co]):
        @overload
        def __call__(self, prog: Program, *args: P.args, **kwargs: P.kwargs) -> R_co:
            ...

        @overload
        def __call__(self, __obj: Object, *args: P.args, **kwargs: P.kwargs) -> R_co:
            ...

        @overload
        def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R_co:
            ...


def takes_program_or_default(f: "TakesProgram[P, R]") -> "TakesProgramOrDefault[P, R]":
    """
    Wrap a function taking a :class:`~drgn.Program` so that it uses the
    :ref:`default program argument <default-program>` if omitted.

    .. code-block:: python3

        @takes_program_or_default
        def my_helper(prog: Program, n: IntegerLike) -> Foo:
            ...

        my_helper(1)
        # is equivalent to
        my_helper(get_default_prog(), 1)

        obj = Object(...)
        my_helper(obj)
        # is equivalent to
        my_helper(obj.prog_, obj)
    """
    parameters_iter = iter(inspect.signature(f).parameters.values())
    if next(parameters_iter).name != "prog":
        raise TypeError("first parameter must be prog: Program")
    param1 = None
    for parameter in parameters_iter:
        if parameter.kind not in (
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.VAR_KEYWORD,
        ):
            param1 = parameter.name
        break

    if param1 is None:

        @functools.wraps(f)
        def wrapper(*args: "Any", **kwds: "Any") -> "R":
            if (args and isinstance(args[0], Program)) or ("prog" in kwds):
                return f(*args, **kwds)
            else:
                return f(get_default_prog(), *args, **kwds)

    else:

        @functools.wraps(f)
        def wrapper(*args: "Any", **kwds: "Any") -> "R":
            if args:
                if isinstance(args[0], Program):
                    return f(*args, **kwds)
                elif isinstance(args[0], Object):
                    return f(args[0].prog_, *args, **kwds)
            elif "prog" in kwds:
                return f(**kwds)
            elif param1 in kwds:
                arg1 = kwds[param1]
                if isinstance(arg1, Object):
                    return f(arg1.prog_, **kwds)
            return f(get_default_prog(), *args, **kwds)

    # Update the docstring for pydoc.
    if wrapper.__doc__ is not None:
        wrapper.__doc__ += ":param prog: Program, which may be omitted to use the default program argument.\n"
    return wrapper


def takes_object_or_program_or_default(
    # This should be a Protocol instead of Callable, but there's currently no
    # way for a Protocol to express that the second parameter can have any name
    # and then use that name in the return type. See python/typing#1505.
    f: "Callable[Concatenate[Program, Optional[Object], P], R]",
) -> "TakesObjectOrProgramOrDefault[P, R]":
    """
    Wrap a function taking a :class:`~drgn.Program` and an optional
    :class:`~drgn.Object` so that it accepts a ``Program`` *or* an ``Object``
    *or neither*, in which case the :ref:`default program argument
    <default-program>` is used.

    .. code-block:: python3

        @takes_object_or_program_or_default
        def my_helper(prog: Program, obj: Optional[Object], n: IntegerLike) -> Foo:
            ...

        my_helper(prog, 1)
        # is equivalent to
        my_helper.__wrapped__(prog, None, 1)

        obj = Object(...)
        my_helper(obj, 1)
        # is equivalent to
        my_helper.__wrapped__(obj.prog_, obj, 1)

        my_helper(1)
        # is equivalent to
        my_helper.__wrapped__(get_default_prog(), None, 1)

        one_obj = Object(..., 1)
        my_helper(one_obj)
        # is equivalent to
        my_helper.__wrapped__(one_obj.prog_, None, one_obj)

    .. warning::

        This cannot be used with positional parameters with a default value, as
        that would create ambiguity. Keyword-only parameters with a default
        value are OK.

        .. code-block:: python3

            # NOT ALLOWED
            @takes_object_or_program_or_default
            def my_helper(prog: Program, obj: Optional[Object], foo: str = ""): ...

            # OK
            @takes_object_or_program_or_default
            def my_helper(prog: Program, obj: Optional[Object], *, foo: str = ""): ...

    .. note::

        The object parameter can be passed as a keyword, but because of
        `limitations of the Python type system
        <https://github.com/python/typing/issues/1505>`_, type checkers do
        not recognize this.
    """
    signature = inspect.signature(f)
    parameters = list(signature.parameters.values())
    if parameters[0].name != "prog":
        raise TypeError("first parameter must be prog: Program")
    object_param = parameters[1].name
    extra_params = []
    for parameter in parameters[2:]:
        if parameter.kind in (
            inspect.Parameter.KEYWORD_ONLY,
            inspect.Parameter.VAR_KEYWORD,
        ):
            break
        if parameter.default != inspect.Parameter.empty:
            raise ValueError(
                f"{getattr(f, '__name__', str(f))} using @takes_object_or_program_or_default can't have positional parameters with defaults due to ambiguity"
            )
        extra_params.append(parameter.name)

    if extra_params:
        param2 = extra_params[0]

        @functools.wraps(f)
        def wrapper(*args: "Any", **kwds: "Any") -> "R":
            if args:
                if len(args) > len(extra_params) or extra_params[len(args) - 1] in kwds:
                    if isinstance(args[0], Program):
                        return f(args[0], None, *args[1:], **kwds)
                    else:
                        return f(args[0].prog_, *args, **kwds)
                elif isinstance(args[0], Object):
                    return f(args[0].prog_, None, *args, **kwds)
            elif object_param in kwds:
                return f(kwds[object_param].prog_, *args, **kwds)
            elif "prog" in kwds:
                kwds[object_param] = None
                return f(*args, **kwds)
            elif param2 in kwds:
                arg2 = kwds[param2]
                if isinstance(arg2, Object):
                    return f(arg2.prog_, None, *args, **kwds)
            return f(get_default_prog(), None, *args, **kwds)

    else:

        @functools.wraps(f)
        def wrapper(*args: "Any", **kwds: "Any") -> "R":
            if args:
                if isinstance(args[0], Program):
                    return f(args[0], None, *args[1:], **kwds)
                else:
                    return f(args[0].prog_, *args, **kwds)
            elif object_param in kwds:
                return f(kwds[object_param].prog_, *args, **kwds)
            elif "prog" in kwds:
                kwds[object_param] = None
                return f(*args, **kwds)
            return f(get_default_prog(), None, *args, **kwds)

    # Update the signature for pydoc.
    wrapper.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=[
            parameters[1].replace(annotation=typing.Union[Object, Program]),
            *parameters[2:],
        ]
    )
    return wrapper
