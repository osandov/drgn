# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Programmable debugger

drgn is a programmable debugger. It is built on top of Python, so if you
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
from typing import Any, Dict, Optional, Tuple, Union, overload

from _drgn import (
    NULL,
    AbsenceReason,
    Architecture,
    DebugInfoOptions,
    ExtraModule,
    FaultError,
    FindObjectFlags,
    IntegerLike,
    KmodSearchMethod,
    Language,
    MainModule,
    MemorySearchIterator,
    MissingDebugInfoError,
    Module,
    ModuleFileStatus,
    NoDefaultProgramError,
    Object,
    ObjectAbsentError,
    ObjectNotFoundError,
    OutOfBoundsError,
    Path,
    Platform,
    PlatformFlags,
    PrimitiveType,
    Program,
    ProgramFlags,
    Qualifiers,
    Register,
    RelocatableModule,
    SharedLibraryModule,
    SourceLocation,
    SourceLocationList,
    StackFrame,
    StackTrace,
    SupplementaryFileKind,
    Symbol,
    SymbolBinding,
    SymbolIndex,
    SymbolKind,
    Thread,
    Type,
    TypeEnumerator,
    TypeKind,
    TypeKindSet,
    TypeMember,
    TypeParameter,
    TypeTemplateParameter,
    VdsoModule,
    WantedSupplementaryFile,
    alignof,
    cast,
    container_of,
    filename_matches,
    get_default_prog,
    host_platform,
    implicit_convert,
    offsetof,
    program_from_core_dump,
    program_from_kernel,
    program_from_pid,
    reinterpret,
    set_default_prog,
    sizeof,
)

# flake8 doesn't honor import X as X. See PyCQA/pyflakes#474.
# isort: split
from _drgn import (  # noqa: F401
    _elfutils_version as _elfutils_version,
    _enable_dlopen_debuginfod as _enable_dlopen_debuginfod,
    _have_debuginfod as _have_debuginfod,
    _with_libkdumpfile as _with_libkdumpfile,
    _with_lzma as _with_lzma,
    _with_pcre2 as _with_pcre2,
)
from drgn.internal.version import __version__ as __version__  # noqa: F401

__all__ = (
    "AbsenceReason",
    "Architecture",
    "DebugInfoOptions",
    "ExtraModule",
    "FaultError",
    "FindObjectFlags",
    "IntegerLike",
    "KmodSearchMethod",
    "Language",
    "MainModule",
    "MemorySearchIterator",
    "MissingDebugInfoError",
    "Module",
    "ModuleFileStatus",
    "NULL",
    "NoDefaultProgramError",
    "Object",
    "ObjectAbsentError",
    "ObjectNotFoundError",
    "OutOfBoundsError",
    "Path",
    "Platform",
    "PlatformFlags",
    "PrimitiveType",
    "Program",
    "ProgramFlags",
    "Qualifiers",
    "Register",
    "RelocatableModule",
    "SharedLibraryModule",
    "SourceLocation",
    "SourceLocationList",
    "StackFrame",
    "StackTrace",
    "SupplementaryFileKind",
    "Symbol",
    "SymbolBinding",
    "SymbolIndex",
    "SymbolKind",
    "Thread",
    "Type",
    "TypeEnumerator",
    "TypeKind",
    "TypeKindSet",
    "TypeMember",
    "TypeParameter",
    "TypeTemplateParameter",
    "VdsoModule",
    "WantedSupplementaryFile",
    "alignof",
    "cast",
    "container_of",
    "execscript",
    "filename_matches",
    "get_default_prog",
    "host_platform",
    "implicit_convert",
    "offsetof",
    "program_from_core_dump",
    "program_from_kernel",
    "program_from_pid",
    "reinterpret",
    "search_memory",
    "search_memory_regex",
    "search_memory_u16",
    "search_memory_u32",
    "search_memory_u64",
    "search_memory_word",
    "set_default_prog",
    "sizeof",
    "source_location",
    "stack_trace",
)


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


def execscript(path: str, *args: str, globals: Optional[Dict[str, Any]] = None) -> None:
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
            task for task in for_each_task()
            if task_exe_path(task) == sys.argv[1]
        ]

    Then, you could execute it and use the defined variables and functions:

    >>> execscript('exe.py', '/usr/bin/bash')
    >>> tasks[0].pid
    (pid_t)358442
    >>> task_exe_path(find_task(357954))
    '/usr/bin/vim'

    :param path: File path of the script.
    :param args: Zero or more additional arguments to pass to the script. This
        is a :ref:`variable argument list <python:tut-arbitraryargs>`.
    :param globals: If provided, globals to use instead of the caller's.
    """
    # This is based on runpy.run_path(), which we can't use because we want to
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

        with io.open_code(path) as f:
            code = pkgutil.read_code(f)
        if code is None:
            with io.open_code(path) as f:
                code = compile(f.read(), path, "exec")
        module.__spec__ = None
        module.__file__ = path
        module.__cached__ = None  # type: ignore[attr-defined]

        if globals is not None:
            caller_globals = globals
        else:
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


def stack_trace(thread: Union[Object, IntegerLike]) -> StackTrace:
    """
    Get the stack trace for the given thread using the :ref:`default program
    argument <default-program>`.

    See :meth:`Program.stack_trace()` for more details.

    :param thread: Thread ID, ``struct pt_regs`` object, or
        ``struct task_struct *`` object.
    """
    if isinstance(thread, Object):
        return thread.prog_.stack_trace(thread)
    else:
        return get_default_prog().stack_trace(thread)


def source_location(address: Union[IntegerLike, str], /) -> SourceLocationList:
    """
    Find the source code location containing a code address, similarly to
    :manpage:`addr2line(1)`, using the :ref:`default program argument
    <default-program>`.

    >>> source_location("__schedule")
    __schedule at kernel/sched/core.c:6646:1
    >>> source_location("__schedule+0x2b6")
    #0  context_switch at kernel/sched/core.c:5381:9
    #1  __schedule at kernel/sched/core.c:6765:8
    >>> source_location(0xffffffffb64d70a6)
    #0  context_switch at kernel/sched/core.c:5381:9
    #1  __schedule at kernel/sched/core.c:6765:8

    See :meth:`Program.source_location()` for more details.

    :param address: Code address as an integer, symbol name, or
        ``"symbol_name+offset"`` string.
    """
    if isinstance(address, Object):
        return address.prog_.source_location(address)
    else:
        return get_default_prog().source_location(address)


@overload
def search_memory(
    value: Union[bytes, str], *, alignment: int = 1
) -> MemorySearchIterator[int]:
    """
    Search for all non-overlapping occurrences of a byte string in the
    :ref:`default program's <default-program>` memory.

    .. code-block:: python3

        for address in search_memory(b"VMCOREINFO"):
            print(hex(address))

    :param value: Byte string to search for. If given as a :class:`str`, then
        this searches for its UTF-8 encoding.
    :param alignment: Only consider addresses aligned to this value (i.e.,
        ``address % alignment == 0``). Must be a power of two.
    :return: Iterator of addresses where the string is found.
    """
    ...


@overload
def search_memory(value: Union[IntegerLike, Object]) -> MemorySearchIterator[int]:
    """
    Search for all occurrences of a value in the :ref:`default program's
    <default-program>` memory.

    .. code-block:: python3

        ptr = stack_trace(pid)[2]["ptr"]
        for address in search_memory(ptr):
            print(hex(address))

    :param value: Value to search for. If given as an :class:`int`, then it is
        interpreted as a program word-sized, naturally aligned unsigned
        integer. If given as an :class:`Object`, then its size and alignment
        are determined from its type.
    :return: Iterator of addresses where the value is found.
    """
    ...


def search_memory(
    value: Union[bytes, str, IntegerLike, Object], **kwargs: Any
) -> MemorySearchIterator[int]:
    if isinstance(value, Object):
        return value.prog_.search_memory(value)
    else:
        return get_default_prog().search_memory(value)


def search_memory_u16(
    *values: Union[IntegerLike, Tuple[IntegerLike, IntegerLike]],
    ignore_mask: IntegerLike = 0,
) -> MemorySearchIterator[Tuple[int, int]]:
    """"""
    return get_default_prog().search_memory_u16(*values, ignore_mask=ignore_mask)


def search_memory_u32(
    *values: Union[IntegerLike, Tuple[IntegerLike, IntegerLike]],
    ignore_mask: IntegerLike = 0,
) -> MemorySearchIterator[Tuple[int, int]]:
    """"""
    return get_default_prog().search_memory_u32(*values, ignore_mask=ignore_mask)


def search_memory_u64(
    *values: Union[IntegerLike, Tuple[IntegerLike, IntegerLike]],
    ignore_mask: IntegerLike = 0,
) -> MemorySearchIterator[Tuple[int, int]]:
    """"""
    return get_default_prog().search_memory_u64(*values, ignore_mask=ignore_mask)


def search_memory_word(
    *values: Union[IntegerLike, Tuple[IntegerLike, IntegerLike]],
    ignore_mask: IntegerLike = 0,
) -> MemorySearchIterator[Tuple[int, int]]:
    """
    Search for all occurrences of one or more unsigned integers in the
    :ref:`default program's <default-program>` memory.

    :func:`search_memory_u16()`, :func:`search_memory_u32()`, and
    :func:`search_memory_u64()` search for 16-, 32- or 64-bit unsigned
    integers, respectively. :func:`search_memory_word()` searches for program
    word-sized unsigned integers. Natural alignment is assumed (i.e., 2-byte
    alignment for 16-bit integers, 4-byte alignment for 32-bit integers, 8-byte
    alignment for 64-bit integers).

    .. code-block:: python3

        for address, value in search_memory_word(
            0xdead000000000100, 0xdead000000000122
        ):
            print(hex(address), hex(value))

        for address, value in search_memory_word(
            0xdead000000000000, ignore_mask=0xffff
        ):
            print(hex(address), hex(value))

        obj = prog["obj"]
        for address, value in search_memory_word(
            (obj.address_, obj.address_ + sizeof(obj) - 1)
        ):
            print(hex(address), hex(value))

    :param values: Values to search for. Each value may be a single integer or
        a ``(min, max)`` range (where both ends are included).
    :param ignore_mask: Mask of bits to ignore when comparing to single
        integers given in *values*. This is not used when comparing to ranges.
    :return: Iterator of addresses where the value is found and the found
        value.
    """
    return get_default_prog().search_memory_word(*values, ignore_mask=ignore_mask)


@overload
def search_memory_regex(pattern: bytes) -> MemorySearchIterator[Tuple[int, bytes]]:
    """"""
    ...


@overload
def search_memory_regex(pattern: str) -> MemorySearchIterator[Tuple[int, str]]:
    r"""
    Search for all non-overlapping matches of a regular expression pattern in
    the program's memory.

    .. code-block:: python3

        # Search for anything that looks like root's password encrypted in
        # /etc/shadow.
        for address, match in search_memory_regex(rb"root:\$\w+\$[ -9;-~]+:"):
            print(hex(address), match)

    :param pattern: PCRE regular expression to search for. If given as
        :class:`bytes`, then search for 8-bit strings. If given as
        :class:`str`, then search for Unicode strings. Note that lookbehind
        assertions are not allowed.
    :return: Iterator of addresses where a match is found and the matching
        string.
    """
    ...


def search_memory_regex(
    pattern: Union[bytes, str]
) -> Union[
    MemorySearchIterator[Tuple[int, bytes]], MemorySearchIterator[Tuple[int, str]]
]:
    return get_default_prog().search_memory_regex(pattern)
