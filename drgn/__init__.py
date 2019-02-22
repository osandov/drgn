# Copyright 2018 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Scriptable debugger library

drgn is a scriptable debugger. It is built on top of Python, so if you don't
know at least a little bit of Python, go learn it first.

drgn supports an interactive mode and a script mode. Both are simply a Python
interpreter initialized with a special drgn.Program object named "prog"
that represents the program which is being debugged.

In interactive mode, try

>>> help(prog)

or

>>> help(drgn.Program)

to learn more about how to use it.

Objects in the program (i.e., variables and values) are represented by
drgn.Object. Try

>>> help(drgn.Object)

Types are represented by drgn.type.Type objects. Try

>>> import drgn.type
>>> help(drgn.type)

Various helpers are provided for particular types of programs. Try

>>> import drgn.helpers
>>> help(drgn.helpers)

The drgn.internal package contains the drgn internals. Everything in that
package should be considered implementation details and should not be used.
"""

from typing import Union

from drgn.internal.program import Object, Program
from drgn.type import Type, PointerType
from drgn.typename import TypeName


def cast(type: Union[str, Type, TypeName], obj: Object) -> Object:
        """
        Return a copy of the given object casted to another type. The given
        type is usually a string, but it can also be a Type or TypeName object.
        """
        if not isinstance(type, Type):
            type = obj.prog_.type(type)
        return Object(obj.prog_, type, value=obj._value, address=obj.address_)


def container_of(ptr: Object, type: Union[str, Type, TypeName],
                 member: str) -> Object:
    """
    Return the containing object of the object pointed to by the given pointer
    object. The given type is the type of the containing object, and the given
    member is the name of the member in that type. This corresponds to the
    container_of() macro in C.
    """
    if not isinstance(type, Type):
        type = ptr.prog_.type(type)
    real_type = ptr._real_type
    if not isinstance(real_type, PointerType):
        raise ValueError(f'container_of() argument must be a pointer, not {ptr._real_type.name!r}')
    try:
        # mypy doesn't understand the except AttributeError.
        offset = type.real_type().offsetof(member)  # type: ignore
    except AttributeError:
        raise ValueError(f'container_of() type must be a struct or union type, not {type.name!r}')
    return Object(ptr.prog_,
                  PointerType(real_type.size, type,
                              real_type.qualifiers),
                  value=ptr.value_() - offset)


def NULL(prog: Program, type: Union[str, Type, TypeName]) -> Object:
    """
    Return an Object representing NULL cast to the given type. The type can be
    a string, Type object, or TypeName object.

    This is equivalent to Object(prog, type, value=0).
    """
    return Object(prog, type, value=0)


__version__ = '0.1.0'
