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

import runpy
import sys

from _drgn import (
    Architecture,
    FaultError,
    FileFormatError,
    FindObjectFlags,
    MissingDebugInfoError,
    NULL,
    Object,
    Platform,
    PlatformFlags,
    PrimitiveType,
    Program,
    ProgramFlags,
    Qualifiers,
    Symbol,
    Type,
    TypeKind,
    __version__,
    array_type,
    bool_type,
    cast,
    complex_type,
    container_of,
    enum_type,
    filename_matches,
    float_type,
    function_type,
    host_platform,
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
    'Architecture',
    'FaultError',
    'FileFormatError',
    'FindObjectFlags',
    'MissingDebugInfoError',
    'NULL',
    'Object',
    'Platform',
    'PlatformFlags'
    'PrimitiveType',
    'Program',
    'ProgramFlags',
    'Qualifiers',
    'Symbol',
    'Type',
    'TypeKind',
    'array_type',
    'bool_type',
    'cast',
    'complex_type',
    'container_of',
    'enum_type',
    'filename_matches',
    'float_type',
    'function_type',
    'host_platform',
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


def execscript(path, *args):
    """
    Execute a script.

    The script is executed in the same context as the caller: currently defined
    globals are available to the script, and globals defined by the script are
    added back to the calling context.

    This is most useful for executing scripts from interactive mode. For
    example, you could have a script named ``tasks.py``:

    .. code-block:: python3

        import sys

        \"\"\"
        Get all tasks in a given state.
        \"\"\"

        # From include/linux/sched.h.
        def task_state_index(task):
            task_state = task.state.value_()
            if task_state == 0x402:  # TASK_IDLE
                return 8
            else:
                state = (task_state | task.exit_state.value_()) & 0x7f
                return state.bit_length()

        def task_state_to_char(task):
            return 'RSDTtXZPI'[task_state_index(task)]

        tasks = [
            task for task in for_each_task(prog)
            if task_state_to_char(task) == sys.argv[1]
        ]

    Then, you could execute it and use the defined variables and functions:

    >>> execscript('tasks.py', 'R')
    >>> tasks[0].comm
    (char [16])"python3"
    >>> task_state_to_char(find_task(prog, 1))
    'S'

    :param str path: File path of the script.
    :param str \*args: Zero or more additional arguments to pass to the script.
        This is a :ref:`variable argument list <python:tut-arbitraryargs>`.
    """
    old_argv = sys.argv
    sys.argv = [path]
    sys.argv.extend(args)
    try:
        old_globals = sys._getframe(1).f_globals
        new_globals = runpy.run_path(path, init_globals=old_globals,
                                     run_name='__main__')
        old_globals.clear()
        old_globals.update(new_globals)
    finally:
        sys.argv = old_argv
