# Copyright 2018-2019 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

"""
Scriptable debugger library

drgn is a scriptable debugger. It is built on top of Python, so if you
don't know at least a little bit of Python, go learn it first.

drgn supports an interactive mode and a script mode. Both are simply a
Python interpreter initialized with a special drgn.Program object named
"prog" that represents the program which is being debugged.

In interactive mode, try

>>> help(prog)

or

>>> help(drgn.Program)

to learn more about how to use it.

Objects in the program (e.g., variables and values) are represented by
drgn.Object. Try

>>> help(drgn.Object)

Types are represented by drgn.Type objects. Try

>>> help(drgn.Type)

Various helpers are provided for particular types of programs. Try

>>> import drgn.helpers
>>> help(drgn.helpers)

The drgn.internal package contains the drgn internals. Everything in
that package should be considered implementation details and should not
be used.
"""

from _drgn import (
    FaultError,
    FileFormatError,
    NULL,
    Object,
    PrimitiveType,
    Program,
    ProgramFlags,
    Qualifiers,
    Type,
    TypeKind,
    __version__,
    array_type,
    bool_type,
    cast,
    complex_type,
    container_of,
    enum_type,
    float_type,
    function_type,
    int_type,
    pointer_type,
    program_from_core_dump,
    program_from_kernel,
    program_from_pid,
    reinterpret,
    struct_type,
    typedef_type,
    union_type,
    void_type,
)


__all__ = [
    'FaultError',
    'FileFormatError',
    'NULL',
    'Object',
    'PrimitiveType',
    'Program',
    'ProgramFlags',
    'Qualifiers',
    'Type',
    'TypeKind',
    'array_type',
    'bool_type',
    'cast',
    'complex_type',
    'container_of',
    'enum_type',
    'float_type',
    'function_type',
    'int_type',
    'pointer_type',
    'program_from_core_dump',
    'program_from_kernel',
    'program_from_pid',
    'reinterpret',
    'struct_type',
    'typedef_type',
    'union_type',
    'void_type',
]
