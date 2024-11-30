# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for embedding the drgn CLI."""

import argparse
import builtins
import importlib
import logging
import os
import os.path
import pkgutil
import runpy
import shutil
import sys
import textwrap
from typing import Any, Callable, Dict, Iterable, Optional

import drgn
from drgn import Program
from drgn.internal.repl import interact, readline
from drgn.internal.rlcompleter import Completer
from drgn.internal.sudohelper import open_via_sudo

__all__ = ("run_interactive", "version_header")

logger = logging.getLogger("drgn")

Command = Callable[[Program, str, Dict[str, Any]], Any]
"""
A command which can be executed in the drgn CLI

The drgn CLI allows for shell-like commands to be executed. Any input to the CLI
which begins with a ``.`` is interpreted as a command rather than a Python
statement. Commands are simply callables which take three arguments:

- a :class:`drgn.Program`
- a ``str`` which contains the command line, and
- a dictionary of local variables in the CLI (``Dict[str, Any]``)

For example, the following is a command function::

    def hello_world(prog, cmdline, locals_):
        print("hello world!")
        print(f"your command: {cmdline}")
        print(f"kernel command line: {prog['saved_command_line']}")
        locals_["secret"] = 42

The command, if registered with the drgn CLI, might be used like so:

    >>> .hello
    hello world!
    your command: .hello
    kernel command line: (char *)0xffff9ea9cf7c3600 = "quiet splash"

User-defined commands may be provided to :func:`run_interactive()` via the
``commands_func`` argument. Commands can also be registered so that they are
included in drgn's default command set using the :func:`command` decorator.
"""

_COMMANDS: Dict[str, Command] = {}


def command(name: str) -> Callable[[Command], Command]:
    """
    A decorator for registering a command function

    Example usage:

    >>> @drgn.cli.command("hello")
    ... def hello(prog, line, locals_):
    ...     print("hello world")

    The decorator will be added to Drgn's default command set. Please keep in
    mind that the decorator is evaluated when your module is imported. If you'd
    like to extend drgn's default set of commands, then you should ensure your
    module is imported before the CLI starts.
    """

    def decorator(cmd: Command) -> Command:
        _COMMANDS[name] = cmd
        return cmd

    return decorator


def all_commands() -> Dict[str, Command]:
    """
    Returns all registered drgn CLI commands

    By default, only the commands which are built-in to drgn, or registered via
    :func:`command`, are returned. Since decorators are evaluated at module load
    time, any command defined in a module which is not imported prior to the
    drgn CLI being run, will not be loaded.

    However, drgn can allow user command modules to be loaded and registered by
    using the ``drgn.command.v1`` `entry point
    <https://setuptools.pypa.io/en/latest/pkg_resources.html#entry-points>`_.
    Third-party packages can define a module as an entry point which should be
    imported, typically in the setup.py::

        setup(
            ...,
            entry_points={
                "drgn.command.v1": {
                    "my_module = fully_qualified.module_path",
                },
            }
        )

    In the above example, a function defined within the module
    ``fully_qualified.module_path`` and registered with :func:`command`, would
    always be included in the drgn CLI and this functon if the relevant package
    is installed.
    """
    import drgn.helpers.common.commands  # noqa

    # The importlib.metadata API is included in Python 3.8+. Normally, one might
    # simply try to import it, catching the ImportError and falling back to the
    # older API. However, the API was _transitional_ in 3.8 and 3.9, and it is
    # different enough to break callers compared to the non-transitional API. So
    # here we are, using sys.version_info like heathens.
    if sys.version_info >= (3, 10):
        from importlib.metadata import entry_points  # novermin
    else:
        import pkg_resources

        def entry_points(group: str) -> Iterable[pkg_resources.EntryPoint]:
            return pkg_resources.iter_entry_points(group)

    # Drgn command "entry points" are simply modules. The act of loading /
    # importing them will result in their @command decorators being executed,
    # and _COMMANDS will be updated properly.
    for entry_point in entry_points(group="drgn.command.v1"):  # type: ignore
        entry_point.load()  # type: ignore

    return _COMMANDS.copy()


def help_command(commands: Dict[str, Command]) -> Command:
    def help(prog: drgn.Program, line: str, locals_: Dict[str, Any]) -> None:
        try:
            width = os.get_terminal_size().columns
        except OSError:
            width = 80
        print("Drgn CLI commands:\n")
        print(textwrap.fill(" ".join(commands.keys()), width=width))

    return help


class _LogFormatter(logging.Formatter):
    _LEVELS = (
        (logging.DEBUG, "debug", "36"),
        (logging.INFO, "info", "32"),
        (logging.WARNING, "warning", "33"),
        (logging.ERROR, "error", "31"),
        (logging.CRITICAL, "critical", "31;1"),
    )

    def __init__(self, color: bool) -> None:
        if color:
            level_prefixes = {
                level: f"\033[{level_color}m{level_name}:\033[0m"
                for level, level_name, level_color in self._LEVELS
            }
        else:
            level_prefixes = {
                level: f"{level_name}:" for level, level_name, _ in self._LEVELS
            }
        default_prefix = "%(levelname)s:"

        self._drgn_formatters = {
            level: logging.Formatter(f"{prefix} %(message)s")
            for level, prefix in level_prefixes.items()
        }
        self._default_drgn_formatter = logging.Formatter(
            f"{default_prefix} %(message)s"
        )

        self._other_formatters = {
            level: logging.Formatter(f"{prefix}%(name)s: %(message)s")
            for level, prefix in level_prefixes.items()
        }
        self._default_other_formatter = logging.Formatter(
            f"{default_prefix}%(name)s: %(message)s"
        )

    def format(self, record: logging.LogRecord) -> str:
        if record.name == "drgn":
            formatter = self._drgn_formatters.get(
                record.levelno, self._default_drgn_formatter
            )
        else:
            formatter = self._other_formatters.get(
                record.levelno, self._default_other_formatter
            )
        return formatter.format(record)


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


class _QuietAction(argparse.Action):
    def __init__(
        self, option_strings: Any, dest: Any, nargs: Any = 0, **kwds: Any
    ) -> None:
        super().__init__(option_strings, dest, nargs=nargs, **kwds)

    def __call__(
        self, parser: Any, namespace: Any, values: Any, option_string: Any = None
    ) -> None:
        setattr(namespace, self.dest, True)
        namespace.log_level = "none"


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
        try:
            text = value.format_(columns=shutil.get_terminal_size((0, 0)).columns)
        except drgn.FaultError as e:
            logger.warning("can't print value: %s", e)
            text = repr(value)
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
    handler = logging.StreamHandler()
    handler.setFormatter(
        _LogFormatter(hasattr(sys.stderr, "fileno") and os.isatty(sys.stderr.fileno()))
    )
    logging.getLogger().addHandler(handler)

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

    advanced_group = parser.add_argument_group("advanced")
    advanced_group.add_argument(
        "--architecture",
        metavar="ARCH",
        choices=[a.name for a in drgn.Architecture]
        + [a.name.lower() for a in drgn.Architecture],
        help="set the program architecture, in case it can't be auto-detected",
    )
    advanced_group.add_argument(
        "--vmcoreinfo",
        type=str,
        metavar="PATH",
        help="path to vmcoreinfo file (overrides any already present in the file)",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical", "none"],
        default="warning",
        help="log messages of at least the given level to standard error (default: warning)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action=_QuietAction,
        help="don't print any logs or download progress",
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
            sys.exit(str(e))
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
    if args.log_level == "none":
        logger.setLevel(logging.CRITICAL + 1)
    else:
        logger.setLevel(args.log_level.upper())

    platform = None
    if args.architecture:
        platform = drgn.Platform(drgn.Architecture[args.architecture.upper()])

    vmcoreinfo = None
    if args.vmcoreinfo is not None:
        with open(args.vmcoreinfo, "rb") as f:
            vmcoreinfo = f.read()

    prog = drgn.Program(platform=platform, vmcoreinfo=vmcoreinfo)
    try:
        if args.core is not None:
            prog.set_core_dump(args.core)
        elif args.pid is not None:
            try:
                prog.set_pid(args.pid or os.getpid())
            except PermissionError as e:
                sys.exit(
                    f"{e}\nerror: attaching to live process requires ptrace attach permissions"
                )
        else:
            try:
                prog.set_kernel()
            except PermissionError as e:
                if shutil.which("sudo") is None:
                    sys.exit(
                        f"{e}\ndrgn debugs the live kernel by default, which requires root"
                    )
                else:
                    prog.set_core_dump(open_via_sudo("/proc/kcore", os.O_RDONLY))
    except OSError as e:
        sys.exit(str(e))
    except ValueError as e:
        # E.g., "not an ELF core file"
        sys.exit(f"error: {e}")

    if args.default_symbols is None:
        args.default_symbols = {"default": True, "main": True}
    try:
        prog.load_debug_info(args.symbols, **args.default_symbols)
    except drgn.MissingDebugInfoError as e:
        logger.warning("%s", e)

    if args.script:
        sys.argv = args.script
        script = args.script[0]
        if pkgutil.get_importer(script) is None:
            sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
        drgn.set_default_prog(prog)
        runpy.run_path(script, init_globals={"prog": prog}, run_name="__main__")
    else:
        run_interactive(prog)


def run_interactive(
    prog: drgn.Program,
    banner_func: Optional[Callable[[str], str]] = None,
    globals_func: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    commands_func: Optional[Callable[[Dict[str, Command]], Dict[str, Command]]] = None,
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
    :param commands_func: Optional function to modify the command list which is
        used for the session. Called with a dictionary of commands, and must
        return a dictionary to use instead.
    :param quiet: Ignored. Will be removed in the future.

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
        "FaultError",
        "NULL",
        "Object",
        "alignof",
        "cast",
        "container_of",
        "execscript",
        "implicit_convert",
        "offsetof",
        "reinterpret",
        "sizeof",
        "stack_trace",
    ]
    for attr in drgn_globals:
        init_globals[attr] = getattr(drgn, attr)

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

    commands = all_commands()
    if commands_func:
        commands = commands_func(commands)
    commands["help"] = help_command(commands)

    old_path = list(sys.path)
    old_displayhook = sys.displayhook
    old_history_length = readline.get_history_length()
    old_completer = readline.get_completer()
    try:
        old_default_prog = drgn.get_default_prog()
    except drgn.NoDefaultProgramError:
        old_default_prog = None
    histfile = os.path.expanduser("~/.drgn_history")
    try:
        readline.clear_history()
        try:
            readline.read_history_file(histfile)
        except OSError as e:
            if not isinstance(e, FileNotFoundError):
                logger.warning("could not read history: %s", e)

        readline.set_history_length(1000)
        readline.parse_and_bind("tab: complete")
        readline.set_completer(Completer(init_globals, commands).complete)

        sys.path.insert(0, "")
        sys.displayhook = _displayhook

        drgn.set_default_prog(prog)

        try:
            interact(init_globals, banner, commands)
        finally:
            try:
                readline.write_history_file(histfile)
            except OSError as e:
                logger.warning("could not write history: %s", e)
    finally:
        drgn.set_default_prog(old_default_prog)
        sys.displayhook = old_displayhook
        sys.path[:] = old_path
        readline.set_history_length(old_history_length)
        readline.parse_and_bind("tab: self-insert")
        readline.set_completer(old_completer)
        readline.clear_history()
