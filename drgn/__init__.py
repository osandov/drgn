# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

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

import io
import pkgutil
import sys
import types

from _drgn import (
    NULL,
    Architecture,
    FaultError,
    FindObjectFlags,
    IntegerLike,
    Language,
    MissingDebugInfoError,
    Object,
    ObjectAbsentError,
    OutOfBoundsError,
    Path,
    Platform,
    PlatformFlags,
    PrimitiveType,
    Program,
    ProgramFlags,
    Qualifiers,
    Register,
    StackFrame,
    StackTrace,
    Symbol,
    Type,
    TypeEnumerator,
    TypeKind,
    TypeMember,
    TypeParameter,
    TypeTemplateParameter,
    _with_libkdumpfile as _with_libkdumpfile,
    cast,
    container_of,
    filename_matches,
    host_platform,
    offsetof,
    program_from_core_dump,
    program_from_kernel,
    program_from_pid,
    reinterpret,
    sizeof,
)
from drgn.internal.version import __version__ as __version__

__all__ = (
    "Architecture",
    "FaultError",
    "FindObjectFlags",
    "IntegerLike",
    "Language",
    "MissingDebugInfoError",
    "NULL",
    "Object",
    "ObjectAbsentError",
    "OutOfBoundsError",
    "Path",
    "Platform",
    "PlatformFlags",
    "PrimitiveType",
    "Program",
    "ProgramFlags",
    "Qualifiers",
    "Register",
    "StackFrame",
    "StackTrace",
    "Symbol",
    "Type",
    "TypeEnumerator",
    "TypeKind",
    "TypeMember",
    "TypeParameter",
    "TypeTemplateParameter",
    "cast",
    "container_of",
    "execscript",
    "filename_matches",
    "host_platform",
    "offsetof",
    "program_from_core_dump",
    "program_from_kernel",
    "program_from_pid",
    "reinterpret",
    "sizeof",
)


if sys.version_info >= (3, 8):
    _open_code = io.open_code
else:
    from typing import BinaryIO

    def _open_code(path: str) -> BinaryIO:
        return open(path, "rb")


# From https://docs.python.org/3/reference/import.html#import-related-module-attributes.
_special_globals = frozenset(
    [
        "__name__",
        "__loader__",
        "__package__",
        "__spec__",
        "__path__",
        "__file__",
        "__cached__",
    ]
)


def execscript(path: str, *args: str) -> None:
    """
    Execute a script.

    The script is executed in the same context as the caller: currently defined
    globals are available to the script, and globals defined by the script are
    added back to the calling context.

    This is most useful for executing scripts from interactive mode. For
    example, you could have a script named ``exe.py``:

    .. code-block:: python3

        \"\"\"Get all tasks executing a given file.\"\"\"

        import sys

        from drgn.helpers.linux.fs import d_path
        from drgn.helpers.linux.pid import find_task

        def task_exe_path(task):
            if task.mm:
                return d_path(task.mm.exe_file.f_path).decode()
            else:
                return None

        tasks = [
            task for task in for_each_task(prog)
            if task_exe_path(task) == sys.argv[1]
        ]

    Then, you could execute it and use the defined variables and functions:

    >>> execscript('exe.py', '/usr/bin/bash')
    >>> tasks[0].pid
    (pid_t)358442
    >>> task_exe_path(find_task(prog, 357954))
    '/usr/bin/vim'

    :param path: File path of the script.
    :param args: Zero or more additional arguments to pass to the script. This
        is a :ref:`variable argument list <python:tut-arbitraryargs>`.
    """
    # This is based on runpy.run_code, which we can't use because we want to
    # update globals even if the script throws an exception.
    saved_module = []
    try:
        saved_module.append(sys.modules["__main__"])
    except KeyError:
        pass
    saved_argv = sys.argv
    try:
        module = types.ModuleType("__main__")
        sys.modules["__main__"] = module
        sys.argv = [path]
        sys.argv.extend(args)

        with _open_code(path) as f:
            code = pkgutil.read_code(f)
        if code is None:
            with _open_code(path) as f:
                code = compile(f.read(), path, "exec")
        module.__spec__ = None
        module.__file__ = path
        module.__cached__ = None  # type: ignore[attr-defined]

        caller_globals = sys._getframe(1).f_globals
        caller_special_globals = {
            name: caller_globals[name]
            for name in _special_globals
            if name in caller_globals
        }
        for name, value in caller_globals.items():
            if name not in _special_globals:
                setattr(module, name, value)

        try:
            exec(code, vars(module))
        finally:
            caller_globals.clear()
            caller_globals.update(caller_special_globals)
            for name, value in vars(module).items():
                if name not in _special_globals:
                    caller_globals[name] = value
    finally:
        sys.argv = saved_argv
        if saved_module:
            sys.modules["__main__"] = saved_module[0]
        else:
            del sys.modules["__main__"]
