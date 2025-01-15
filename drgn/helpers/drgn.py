# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Development Helpers
-------------------

The ``drgn.helpers.drgn`` module provides drgn helpers for debugging drgn
itself. These are mainly useful to drgn's developers. Debugging drgn is similar
to other targets:

- You must have debuginfo for the drgn extension available. Debuginfo for Python
  isn't necessarily required.
- You can debug a core dump or a running process.

Unlike other debug targets, you can additionally debug the running drgn process
*from the same process*. When that is happening, we use the following naming
convention:

- ``prog`` - an instance of drgn, which you want to debug
- ``self_prog`` - a :class:`drgn.Program` which is debugging the current process
- ``oot`` - "object of testing" representing ``prog``, the program we're
  debugging

For instance, if you have started a drgn instance and would like to debug it,
you could do the following:

    >>> from drgn.helpers.drgn import *
    >>> self_prog = program_from_self()
    >>> oot = get_prog_obj(prog)

Please note that some helpers in this module represent the internal
implementation details of drgn. As such, these helpers should not be considered
a stable API, and they should only be used at your own risk.

"""
import os
from typing import Iterator

from drgn import Object, Program, Type, program_from_pid

__all__ = (
    "for_each_created_type",
    "get_prog_obj",
    "get_type_obj",
    "print_type_report",
    "program_from_self",
    "type_repr",
    "vector_for_each",
)


def program_from_self() -> Program:
    """
    Return a program for debugging the current drgn process
    """
    return program_from_pid(os.getpid())


def get_prog_obj(self_prog: Program, oot_prog: Program) -> Object:
    """
    Return the ``struct drgn_program *`` corresponding to ``oot_prog``

    When debugging drgn in the same process as it is currently running, use this
    function to obtain the :class:`Object` representation of the program that is
    under test. Please see the module docstring for a description of the naming
    conventions used here.

    :param self_prog: a program used to debug the current process
    :param prog: the program we are debugging (may be the same as ``self_prog``)
    :returns: an :class:`Object` representing ``oot_prog``
    """
    return Object(self_prog, "Program *", value=id(oot_prog)).prog


def get_type_obj(self_prog: Program, tp: Type) -> Object:
    """
    Return the ``struct drgn_type *`` corresponding to a type
    :param self_prog: a program used to debug the current instance of drgn
    :param tp: a type object to lookup
    :returns: an :class:`Object` representing ``tp``
    """
    return Object(self_prog, "DrgnType *", value=id(tp)).type


def vector_for_each(obj: Object, start: int = 0) -> Iterator[Object]:
    """
    Iterate over objects in a drgn vector
    :param obj: a pointer to the vector object
    :param start: the starting index to iterate from
    """
    for i in range(start, obj._size.value_()):
        yield obj._data[i]


def for_each_created_type(oot: Object, start: int = 0) -> Iterator[Object]:
    """
    Iterate over every type in a drgn program
    :param oot: an object corresponding to ``struct drgn_program *``
    :param start: starting index to iterate from
    """
    yield from vector_for_each(oot.created_types, start=start)


def type_repr(tp: Object) -> str:
    """
    Format a type's kind, name, and pointer for display

    This is not as complete as :meth:`Type.type_name`, but it is a simple way to
    print information that can help you identify a specific type.

    :param tp: object representing a ``struct drgn_type *``
    """
    spelling = tp.prog_["drgn_type_kind_spelling"][tp._kind].string_().decode()
    name_obj = tp._name
    if name_obj:
        name = name_obj.string_().decode()
    else:
        name = "(anonymous)"
    return f"{spelling} {name} (0x{tp.value_():x})"


def print_type_report(oot: Object, start: int = 0) -> None:
    """
    Print a report of all loaded types for a program
    """
    for i, tp in enumerate(for_each_created_type(oot, start)):
        print(f"{i + start:4d} {type_repr(tp)}")
