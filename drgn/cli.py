# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright (c) 2023, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for embedding the drgn CLI."""

import argparse
import builtins
import contextlib
import importlib
import logging
import os
import os.path
from pathlib import Path
import pkgutil
import runpy
import shutil
import sys
from typing import IO, Any, Callable, Dict, Iterator, Optional, Tuple

import drgn
from drgn.internal.repl import interact, readline
from drgn.internal.rlcompleter import Completer
from drgn.internal.sudohelper import open_via_sudo

__all__ = ("default_globals", "run_interactive", "version_header")

logger = logging.getLogger("drgn")

# The list of attributes from the drgn module which are imported and inserted
# into the global namespace for interactive debugging.
_DRGN_GLOBALS = [
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
    "source_location",
    "stack_trace",
]


def _is_tty(file: IO[Any]) -> bool:
    try:
        return os.isatty(file.fileno())
    except (AttributeError, OSError):
        return False


class _LogFormatter(logging.Formatter):
    _LEVELS = (
        (logging.DEBUG, "debug", "\033[36m", "\033[m", ""),
        (logging.INFO, "info", "\033[32m", "\033[m", ""),
        (logging.WARNING, "warning", "\033[33m", "\033[m", ""),
        (logging.ERROR, "error", "\033[31m", "\033[m", ""),
        (logging.CRITICAL, "critical", "\033[31;1m", "\033[0;1m", "\033[m"),
    )

    def __init__(self, color: bool) -> None:
        if color:
            levels = {
                level: (f"{level_prefix}{level_name}:{message_prefix}", message_suffix)
                for level, level_name, level_prefix, message_prefix, message_suffix in self._LEVELS
            }
        else:
            levels = {
                level: (f"{level_name}:", "")
                for level, level_name, _, _, _ in self._LEVELS
            }
        default_prefix = "%(levelname)s:"

        self._drgn_formatters = {
            level: logging.Formatter(f"{prefix} %(message)s{suffix}")
            for level, (prefix, suffix) in levels.items()
        }
        self._default_drgn_formatter = logging.Formatter(
            f"{default_prefix} %(message)s"
        )

        self._other_formatters = {
            level: logging.Formatter(f"{prefix}%(name)s: %(message)s{suffix}")
            for level, (prefix, suffix) in levels.items()
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
    debuginfod = f'with{"" if drgn._have_debuginfod else "out"} debuginfod'
    if drgn._enable_dlopen_debuginfod:
        debuginfod += " (dlopen)"
    libkdumpfile = f'with{"" if drgn._with_libkdumpfile else "out"} libkdumpfile'
    lzma = f'with{"" if drgn._with_lzma else "out"} lzma'
    return f"drgn {drgn.__version__} (using Python {python_version}, elfutils {drgn._elfutils_version}, {debuginfod}, {libkdumpfile}, {lzma})"


def default_globals(prog: drgn.Program) -> Dict[str, Any]:
    """
    Return the default globals for an interactive drgn session

    :param prog: the program which will be debugged
    :return: a dict of globals
    """
    # Don't forget to update the default banner in run_interactive()
    # with any new additions.
    init_globals: Dict[str, Any] = {
        "prog": prog,
        "drgn": drgn,
        "__name__": "__main__",
        "__doc__": None,
    }
    for attr in _DRGN_GLOBALS:
        init_globals[attr] = getattr(drgn, attr)
    module = importlib.import_module("drgn.helpers.common")
    for name in module.__dict__["__all__"]:
        init_globals[name] = getattr(module, name)
    if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
        module = importlib.import_module("drgn.helpers.linux")
        for name in module.__dict__["__all__"]:
            init_globals[name] = getattr(module, name)
    return init_globals


def _set_kernel_with_sudo_fallback(prog: drgn.Program) -> None:
    try:
        prog.set_kernel()
        return
    except PermissionError as e:
        if shutil.which("sudo") is None:
            sys.exit(
                f"{e}\ndrgn debugs the live kernel by default, which requires root"
            )
    prog.set_core_dump(open_via_sudo("/proc/kcore", os.O_RDONLY))


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
    elif isinstance(
        value,
        (
            drgn.SourceLocation,
            drgn.SourceLocationList,
            drgn.StackFrame,
            drgn.StackTrace,
            drgn.Type,
        ),
    ):
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


def _bool_options(value: bool) -> Dict[str, Tuple[str, bool]]:
    return {
        option: ("try_" + option.replace("-", "_"), value)
        for option in (
            "module-name",
            "build-id",
            "debug-link",
            "procfs",
            "embedded-vdso",
            "reuse",
            "supplementary",
        )
    }


class _TrySymbolsByBaseAction(argparse.Action):
    _enable: bool
    _finder = ("disable_debug_info_finders", "enable_debug_info_finders")

    _options = (
        {
            **_bool_options(False),
            "kmod": ("try_kmod", drgn.KmodSearchMethod.NONE),
        },
        {
            **_bool_options(True),
            "kmod=depmod": ("try_kmod", drgn.KmodSearchMethod.DEPMOD),
            "kmod=walk": ("try_kmod", drgn.KmodSearchMethod.WALK),
            "kmod=depmod-or-walk": ("try_kmod", drgn.KmodSearchMethod.DEPMOD_OR_WALK),
            "kmod=depmod-and-walk": ("try_kmod", drgn.KmodSearchMethod.DEPMOD_AND_WALK),
        },
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["dest"] = argparse.SUPPRESS
        super().__init__(*args, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        for value in values.split(","):
            try:
                option_name, option_value = self._options[self._enable][value]
            except KeyError:
                # Raise an error if passed an option meant for the opposite
                # argument.
                if value in self._options[not self._enable]:
                    raise argparse.ArgumentError(self, f"invalid option: {value!r}")

                if not hasattr(namespace, self._finder[self._enable]):
                    setattr(namespace, self._finder[self._enable], {})
                getattr(namespace, self._finder[self._enable])[value] = None

                if hasattr(namespace, self._finder[not self._enable]):
                    getattr(namespace, self._finder[not self._enable]).pop(value, None)
            else:
                if not hasattr(namespace, "debug_info_options"):
                    namespace.debug_info_options = {}
                namespace.debug_info_options[option_name] = option_value


class _TrySymbolsByAction(_TrySymbolsByBaseAction):
    _enable = True


class _NoSymbolsByAction(_TrySymbolsByBaseAction):
    _enable = False


def _load_debugging_symbols(prog: drgn.Program, args: argparse.Namespace) -> None:
    enable_debug_info_finders = getattr(args, "enable_debug_info_finders", ())
    disable_debug_info_finders = getattr(args, "disable_debug_info_finders", ())
    if enable_debug_info_finders or disable_debug_info_finders:
        debug_info_finders = prog.enabled_debug_info_finders()
        registered_debug_info_finders = prog.registered_debug_info_finders()

        unknown_finders = []

        for finder in enable_debug_info_finders:
            if finder not in debug_info_finders:
                if finder in registered_debug_info_finders:
                    debug_info_finders.append(finder)
                else:
                    unknown_finders.append(finder)

        for finder in disable_debug_info_finders:
            try:
                debug_info_finders.remove(finder)
            except ValueError:
                if finder not in registered_debug_info_finders:
                    unknown_finders.append(finder)

        if unknown_finders:
            if len(unknown_finders) == 1:
                unknown_finders_repr = repr(unknown_finders[0])
            elif len(unknown_finders) == 2:
                unknown_finders_repr = (
                    f"{unknown_finders[0]!r} or {unknown_finders[1]!r}"
                )
            elif len(unknown_finders) > 2:
                unknown_finders = [repr(finder) for finder in unknown_finders]
                unknown_finders[-1] = "or " + unknown_finders[-1]
                unknown_finders_repr = ", ".join(unknown_finders)
            logger.warning(
                "no matching debugging information finders or options for %s",
                unknown_finders_repr,
            )

        prog.set_enabled_debug_info_finders(debug_info_finders)

    debug_info_options = getattr(args, "debug_info_options", None)
    if debug_info_options:
        for option, value in debug_info_options.items():
            setattr(prog.debug_info_options, option, value)

    def directories_option(arg_name: str, option_name: Optional[str] = None) -> None:
        if option_name is None:
            option_name = arg_name
        arg = getattr(args, arg_name)
        no_default = getattr(args, "no_default_" + arg_name)
        if arg is not None:
            if no_default:
                setattr(prog.debug_info_options, option_name, arg)
            else:
                setattr(
                    prog.debug_info_options,
                    option_name,
                    tuple(arg) + getattr(prog.debug_info_options, option_name),
                )
        elif no_default:
            setattr(prog.debug_info_options, option_name, ())

    directories_option("debug_directories", "directories")
    directories_option("debug_link_directories")
    directories_option("kernel_directories")

    if args.default_symbols is None:
        args.default_symbols = {"default": True, "main": True}
    try:
        prog.load_debug_info(args.symbols, **args.default_symbols)
    except drgn.MissingDebugInfoError as e:
        if args.default_symbols.get("main"):
            try:
                main_module = prog.main_module()
                critical = (
                    main_module.wants_debug_file() or main_module.wants_loaded_file()
                )
            except LookupError:
                critical = True
        else:
            critical = False
        logger.log(logging.CRITICAL if critical else logging.WARNING, "%s", e)

    if args.extra_symbols:
        for extra_symbol_path in args.extra_symbols:
            extra_symbol_path = os.path.abspath(extra_symbol_path)
            prog.extra_module(extra_symbol_path, create=True).try_file(
                extra_symbol_path
            )


def _main() -> None:
    handler = logging.StreamHandler()
    color = _is_tty(sys.stderr)
    handler.setFormatter(_LogFormatter(color))
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
        help="load debugging symbols from the given file. "
        "If the file does not correspond to a loaded executable, library, or module, "
        "then it is ignored. This option may be given more than once",
    )
    default_symbols_group = symbol_group.add_mutually_exclusive_group()
    default_symbols_group.add_argument(
        "--main-symbols",
        dest="default_symbols",
        action="store_const",
        const={"main": True},
        help="only load debugging symbols for the main executable "
        "and those added with -s or --extra-symbols",
    )
    default_symbols_group.add_argument(
        "--no-default-symbols",
        dest="default_symbols",
        action="store_const",
        const={},
        help="don't load any debugging symbols that were not explicitly added "
        "with -s or --extra-symbols",
    )
    symbol_group.add_argument(
        "--extra-symbols",
        metavar="PATH",
        type=str,
        action="append",
        help="load additional debugging symbols from the given file, "
        "which is assumed not to correspond to a loaded executable, library, or module. "
        "This option may be given more than once",
    )
    symbol_group.add_argument(
        "--try-symbols-by",
        metavar="METHOD[,METHOD...]",
        action=_TrySymbolsByAction,
        help="enable loading debugging symbols using the given methods. "
        "Choices are debugging information finder names "
        "(standard, debuginfod, or any added by plugins) "
        "or debugging information options ("
        + ", ".join(_TrySymbolsByBaseAction._options[True])
        + "). "
        "This option may be given more than once",
    )
    symbol_group.add_argument(
        "--no-symbols-by",
        metavar="METHOD[,METHOD...]",
        action=_NoSymbolsByAction,
        help="disable loading debugging symbols using the given methods. "
        "Choices are debugging information finder names "
        "(standard, debuginfod, or any added by plugins) "
        "or debugging information options ("
        + ", ".join(_TrySymbolsByBaseAction._options[False])
        + "). "
        "This option may be given more than once",
    )

    directories_group = parser.add_argument_group("debugging symbol directories")
    directories_group.add_argument(
        "--debug-directory",
        dest="debug_directories",
        metavar="PATH",
        type=str,
        action="append",
        help="search for debugging symbols in the given directory. "
        "This option may be given more than once",
    )
    directories_group.add_argument(
        "--no-default-debug-directories",
        action="store_true",
        help="don't search for debugging symbols "
        "in the standard directories or those added by plugins",
    )
    directories_group.add_argument(
        "--debug-link-directory",
        dest="debug_link_directories",
        metavar="PATH",
        type=str,
        action="append",
        help="search for debugging symbols by debug link in the given directory. "
        "$ORIGIN is replaced with the directory containing the loaded file. "
        "This option may be given more than once",
    )
    directories_group.add_argument(
        "--no-default-debug-link-directories",
        action="store_true",
        help="don't search for debugging symbols by debug link "
        "in the standard directories or those added by plugins",
    )
    directories_group.add_argument(
        "--kernel-directory",
        dest="kernel_directories",
        metavar="PATH",
        type=str,
        action="append",
        help="search for the kernel image and loadable kernel modules in the given directory. "
        "This option may be given more than once",
    )
    directories_group.add_argument(
        "--no-default-kernel-directories",
        action="store_true",
        help="don't search for the kernel image and loadable kernel modules "
        "in the standard directories or those added by plugins",
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
        dest="log_level",
        action="store_const",
        const="none",
        help="don't print any logs or download progress",
    )
    parser.add_argument(
        "-e",
        dest="exec",
        metavar="CODE",
        help="an expression or statement to evaluate, instead of running in interactive mode",
    )
    parser.add_argument(
        "args",
        metavar="ARG",
        type=str,
        nargs=argparse.REMAINDER,
        help="script to execute instead of running in interactive mode "
        "(unless -e is given) and arguments to pass",
    )
    parser.add_argument("--version", action="version", version=version)

    args = parser.parse_args()

    script = bool(args.exec is None and args.args)
    interactive = bool(args.exec is None and not args.args and _is_tty(sys.stdin))
    if script:
        # A common mistake users make is running drgn $core_dump, which tries
        # to run $core_dump as a Python script. Rather than failing later with
        # some inscrutable syntax or encoding error, try to catch this early
        # and provide a helpful message.
        try:
            script_type = _identify_script(args.args[0])
        except OSError as e:
            sys.exit(str(e))
        if script_type == "core":
            sys.exit(
                f"error: {args.args[0]} is a core dump\n"
                f'Did you mean "-c {args.args[0]}"?'
            )
        elif script_type == "elf":
            sys.exit(f"error: {args.args[0]} is a binary, not a drgn script")
    elif interactive:
        print(version, file=sys.stderr, flush=True)

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
            _set_kernel_with_sudo_fallback(prog)
    except OSError as e:
        sys.exit(str(e))
    except ValueError as e:
        # E.g., "not an ELF core file"
        sys.exit(f"error: {e}")

    _load_debugging_symbols(prog, args)

    if interactive:
        run_interactive(prog)
    else:
        drgn.set_default_prog(prog)
        if script:
            sys.argv = args.args
            script_path = args.args[0]
            if pkgutil.get_importer(script_path) is None:
                sys.path.insert(0, os.path.dirname(os.path.abspath(script_path)))
            runpy.run_path(
                script_path, init_globals={"prog": prog}, run_name="__main__"
            )
        else:
            sys.path.insert(0, "")
            exec_globals = default_globals(prog)
            if args.exec is None:
                sys.argv = [""]
                exec_globals["__file__"] = "<stdin>"
                exec(compile(sys.stdin.read(), "<stdin>", "exec"), exec_globals)
            else:
                sys.argv = ["-e"] + args.args
                exec(args.exec, exec_globals)


def _history_file() -> str:
    # Historically, our history file was directly in ~. However, the May 2021
    # XDG Base Directory Specification [1] added a dedicated directory for
    # things like history files: $XDG_STATE_HOME, which defaults to
    # ~/.local/state.
    #
    # We don't move existing history files, but we create new ones in the new
    # location.
    #
    # Note that we use pathlib because it raises an error if a home directory
    # can't be resolved instead of failing silently like os.path.expanduser().
    #
    # [1]: https://specifications.freedesktop.org/basedir/latest/
    path = Path("~/.drgn_history").expanduser()
    if path.exists():
        return str(path)
    return _state_file("history")


def _state_file(name: str) -> str:
    xdg_state_home = os.getenv("XDG_STATE_HOME")
    if xdg_state_home is None:
        path = Path("~/.local/state").expanduser()
    else:
        path = Path(xdg_state_home)
    return str(path / "drgn" / name)


def _read_history(history_file: str) -> None:
    try:
        readline.read_history_file(history_file)
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.warning("could not read history: %s", e)


def _write_history(history_file: str) -> None:
    try:
        os.makedirs(os.path.dirname(history_file), exist_ok=True)
        readline.write_history_file(history_file)
    except OSError as e:
        logger.warning("could not write history: %s", e)


current_history_file = None


@contextlib.contextmanager
def _setup_readline(
    history_file: str, completer: Optional[Callable[[str, int], Optional[str]]] = None
) -> Iterator[None]:
    global current_history_file
    old_history_file = current_history_file
    old_history_length = readline.get_history_length()
    old_completer = readline.get_completer()

    try:
        if current_history_file is not None:
            _write_history(current_history_file)
        readline.clear_history()
        _read_history(history_file)
        current_history_file = history_file

        readline.set_history_length(1000)

        if completer is None:
            readline.parse_and_bind("tab: self-insert")
        else:
            readline.parse_and_bind("tab: complete")
        readline.set_completer(completer)

        try:
            yield
        finally:
            _write_history(history_file)
    finally:
        readline.set_completer(old_completer)
        if old_completer is None:
            readline.parse_and_bind("tab: self-insert")
        else:
            readline.parse_and_bind("tab: complete")

        readline.set_history_length(old_history_length)

        readline.clear_history()
        if old_history_file is not None:
            _read_history(old_history_file)
        current_history_file = old_history_file


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
    init_globals = default_globals(prog)
    banner = f"""\
For help, type help(drgn).
>>> import drgn
>>> from drgn import {", ".join(_DRGN_GLOBALS)}
>>> from drgn.helpers.common import *"""
    if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
        banner += "\n>>> from drgn.helpers.linux import *"
    if banner_func:
        banner = banner_func(banner)
    if globals_func:
        init_globals = globals_func(init_globals)

    old_path = list(sys.path)
    old_displayhook = sys.displayhook
    try:
        old_default_prog = drgn.get_default_prog()
    except drgn.NoDefaultProgramError:
        old_default_prog = None
    had_outer_repl = "outer_repl" in prog.config

    with _setup_readline(_history_file(), Completer(init_globals).complete):
        try:
            sys.path.insert(0, "")
            sys.displayhook = _displayhook

            drgn.set_default_prog(prog)

            if not had_outer_repl:
                prog.config["outer_repl"] = "drgn"

            interact(init_globals, banner)
        finally:
            if not had_outer_repl:
                prog.config.pop("outer_repl", None)
            drgn.set_default_prog(old_default_prog)
            sys.displayhook = old_displayhook
            sys.path[:] = old_path
