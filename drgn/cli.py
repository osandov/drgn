# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for embedding the drgn CLI."""

import argparse
import builtins
import code
import importlib
import os
import os.path
import pkgutil
import readline
import runpy
import shutil
import sys
from typing import Any, Callable, Dict, Optional

import drgn
from drgn.internal.rlcompleter import Completer

__all__ = ("run_interactive", "version_header")


def version_header() -> str:
    """
    Return the version header printed at the beginning of a drgn session.

    The :func:`run_interactive()` function does not include this banner at the
    beginning of an interactive session. Use this function to retrieve one line
    of text to add to the beginning of the drgn banner, or print it before
    calling :func:`run_interactive()`.
    """
    python_version = ".".join(str(v) for v in sys.version_info[:3])
    libkdumpfile = f'with{"" if drgn._with_libkdumpfile else "out"} libkdumpfile'
    return f"drgn {drgn.__version__} (using Python {python_version}, elfutils {drgn._elfutils_version}, {libkdumpfile})"


def _identify_script(path: str) -> str:
    EI_NIDENT = 16
    SIZEOF_E_TYPE = 2

    with open(path, "rb") as f:
        header = f.read(EI_NIDENT + SIZEOF_E_TYPE)

    ELFMAG = b"\177ELF"
    EI_DATA = 5
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2
    ET_CORE = 4

    if len(header) < EI_NIDENT + SIZEOF_E_TYPE or header[:4] != ELFMAG:
        return "other"

    if header[EI_DATA] == ELFDATA2LSB:
        byteorder = "little"
    elif header[EI_DATA] == ELFDATA2MSB:
        byteorder = "big"
    else:
        return "elf"

    e_type = int.from_bytes(
        header[EI_NIDENT : EI_NIDENT + SIZEOF_E_TYPE],
        byteorder,  # type: ignore[arg-type]  # python/mypy#9057
    )
    return "core" if e_type == ET_CORE else "elf"


def _displayhook(value: Any) -> None:
    if value is None:
        return
    setattr(builtins, "_", None)
    if isinstance(value, drgn.Object):
        text = value.format_(columns=shutil.get_terminal_size((0, 0)).columns)
    elif isinstance(value, (drgn.StackFrame, drgn.StackTrace, drgn.Type)):
        text = str(value)
    else:
        text = repr(value)
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        encoded = text.encode(sys.stdout.encoding, "backslashreplace")
        if hasattr(sys.stdout, "buffer"):
            sys.stdout.buffer.write(encoded)
        else:
            text = encoded.decode(sys.stdout.encoding, "strict")
            sys.stdout.write(text)
    sys.stdout.write("\n")
    setattr(builtins, "_", value)


def _main() -> None:
    version = version_header()
    parser = argparse.ArgumentParser(prog="drgn", description="Programmable debugger")

    program_group = parser.add_argument_group(
        title="program selection",
    ).add_mutually_exclusive_group()
    program_group.add_argument(
        "-k", "--kernel", action="store_true", help="debug the running kernel (default)"
    )
    program_group.add_argument(
        "-c", "--core", metavar="PATH", type=str, help="debug the given core dump"
    )
    program_group.add_argument(
        "-p",
        "--pid",
        metavar="PID",
        type=int,
        help="debug the running process with the given PID",
    )

    symbol_group = parser.add_argument_group("debugging symbols")
    symbol_group.add_argument(
        "-s",
        "--symbols",
        metavar="PATH",
        type=str,
        action="append",
        help="load additional debugging symbols from the given file; this option may be given more than once",
    )
    default_symbols_group = symbol_group.add_mutually_exclusive_group()
    default_symbols_group.add_argument(
        "--main-symbols",
        dest="default_symbols",
        action="store_const",
        const={"main": True},
        help="only load debugging symbols for the main executable and those added with -s; "
        "for userspace programs, this is currently equivalent to --no-default-symbols",
    )
    default_symbols_group.add_argument(
        "--no-default-symbols",
        dest="default_symbols",
        action="store_const",
        const={},
        help="don't load any debugging symbols that were not explicitly added with -s",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="don't print download progress or non-fatal warnings "
        "(e.g., about missing debugging information)",
    )
    parser.add_argument(
        "script",
        metavar="ARG",
        type=str,
        nargs=argparse.REMAINDER,
        help="script to execute instead of running in interactive mode",
    )
    parser.add_argument("--version", action="version", version=version)

    args = parser.parse_args()

    if args.script:
        # A common mistake users make is running drgn $core_dump, which tries
        # to run $core_dump as a Python script. Rather than failing later with
        # some inscrutable syntax or encoding error, try to catch this early
        # and provide a helpful message.
        try:
            script_type = _identify_script(args.script[0])
        except OSError as e:
            sys.exit(e)
        if script_type == "core":
            sys.exit(
                f"error: {args.script[0]} is a core dump\n"
                f'Did you mean "-c {args.script[0]}"?'
            )
        elif script_type == "elf":
            sys.exit(f"error: {args.script[0]} is a binary, not a drgn script")
    else:
        print(version, file=sys.stderr, flush=True)
    if not args.quiet:
        os.environ["DEBUGINFOD_PROGRESS"] = "1"

    prog = drgn.Program()
    try:
        if args.core is not None:
            prog.set_core_dump(args.core)
        elif args.pid is not None:
            prog.set_pid(args.pid or os.getpid())
        else:
            prog.set_kernel()
    except PermissionError as e:
        print(e, file=sys.stderr)
        if args.pid is not None:
            print(
                "error: attaching to live process requires ptrace attach permissions",
                file=sys.stderr,
            )
        elif args.core is None:
            print(
                "error: drgn debugs the live kernel by default, which requires root",
                file=sys.stderr,
            )
        sys.exit(1)
    except OSError as e:
        sys.exit(e)
    except ValueError as e:
        # E.g., "not an ELF core file"
        sys.exit(f"error: {e}")

    if args.default_symbols is None:
        args.default_symbols = {"default": True, "main": True}
    missing_debug_info_warning = None
    try:
        prog.load_debug_info(args.symbols, **args.default_symbols)
    except drgn.MissingDebugInfoError as e:
        if not args.quiet:
            prefix = "warning:"
            if hasattr(sys.stderr, "fileno") and os.isatty(sys.stderr.fileno()):
                prefix = f"\033[33m{prefix}\033[0m"
            missing_debug_info_warning = f"{prefix} {e}"

    if args.script:
        sys.argv = args.script
        script = args.script[0]
        if pkgutil.get_importer(script) is None:
            sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
        if missing_debug_info_warning is not None:
            print(missing_debug_info_warning, file=sys.stderr)
        runpy.run_path(script, init_globals={"prog": prog}, run_name="__main__")
    else:

        def banner_func(banner: str) -> str:
            if missing_debug_info_warning is not None:
                return f"{banner}\n{missing_debug_info_warning}"
            else:
                return banner

        run_interactive(prog, banner_func=banner_func, quiet=args.quiet)


def run_interactive(
    prog: drgn.Program,
    banner_func: Optional[Callable[[str], str]] = None,
    globals_func: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    quiet: bool = False,
) -> None:
    """
    Run drgn's :ref:`interactive-mode` until the user exits.

    This function allows your application to embed the same REPL that drgn
    provides when it is run on the command line in interactive mode.

    :param prog: Pre-configured program to run against. Available as a global
        named ``prog`` in the CLI.
    :param banner_func: Optional function to modify the printed banner. Called
        with the default banner, and must return a string to use as the new
        banner. The default banner does not include the drgn version, which can
        be retrieved via :func:`version_header()`.
    :param globals_func: Optional function to modify globals provided to the
        session. Called with a dictionary of default globals, and must return a
        dictionary to use instead.
    :param quiet: Whether to suppress non-fatal warnings.

    .. note::

        This function uses :mod:`readline` and modifies some settings.
        Unfortunately, it is not possible for it to restore all settings. In
        particular, it clears the ``readline`` history and resets the TAB
        keybinding to the default.

        Applications using ``readline`` should save their history and clear any
        custom settings before calling this function. After calling this
        function, applications should restore their history and settings before
        using ``readline``.
    """
    init_globals: Dict[str, Any] = {
        "prog": prog,
        "drgn": drgn,
        "__name__": "__main__",
        "__doc__": None,
    }
    drgn_globals = [
        "NULL",
        "Object",
        "cast",
        "container_of",
        "execscript",
        "offsetof",
        "reinterpret",
        "sizeof",
    ]
    for attr in drgn_globals:
        init_globals[attr] = getattr(drgn, attr)

    old_path = list(sys.path)
    old_displayhook = sys.displayhook
    old_history_length = readline.get_history_length()
    old_completer = readline.get_completer()
    try:
        sys.path.insert(0, "")
        sys.displayhook = _displayhook

        readline.clear_history()
        histfile = os.path.expanduser("~/.drgn_history")
        try:
            readline.read_history_file(histfile)
        except OSError as e:
            if not isinstance(e, FileNotFoundError) and not quiet:
                print("could not read history:", str(e), file=sys.stderr)

        readline.set_history_length(1000)
        readline.parse_and_bind("tab: complete")
        readline.set_completer(Completer(init_globals).complete)

        banner = f"""\
For help, type help(drgn).
>>> import drgn
>>> from drgn import {", ".join(drgn_globals)}
>>> from drgn.helpers.common import *"""
        module = importlib.import_module("drgn.helpers.common")
        for name in module.__dict__["__all__"]:
            init_globals[name] = getattr(module, name)
        if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
            banner += "\n>>> from drgn.helpers.linux import *"
            module = importlib.import_module("drgn.helpers.linux")
            for name in module.__dict__["__all__"]:
                init_globals[name] = getattr(module, name)
        if banner_func:
            banner = banner_func(banner)
        if globals_func:
            init_globals = globals_func(init_globals)
        code.interact(banner=banner, exitmsg="", local=init_globals)
    finally:
        sys.displayhook = old_displayhook
        sys.path[:] = old_path
        readline.set_history_length(old_history_length)
        readline.parse_and_bind("tab: self-insert")
        readline.set_completer(old_completer)
        try:
            readline.write_history_file(histfile)
        except OSError as e:
            if not quiet:
                print("could not write history:", str(e), file=sys.stderr)
        readline.clear_history()
