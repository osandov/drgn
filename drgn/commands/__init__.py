# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
Functions for defining drgn CLI commands and running them programmatically.

For documentation of available commands and command syntax, see
:doc:`commands`.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import re
import shutil
import subprocess
import sys
import textwrap
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Literal,
    NamedTuple,
    NoReturn,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Union,
    overload,
)

if TYPE_CHECKING:
    if sys.version_info < (3, 11):
        from typing_extensions import assert_never
    else:
        from typing import assert_never  # novermin
    from _typeshed import SupportsWrite

import _drgn_util.argparseformatter
from _drgn_util.multilinewrap import multiline_fill
from _drgn_util.typingutils import copy_method_params
from drgn import Program

_WORD_CHARACTER = r"""[^\s"#&'();<>\\`|]"""
_WORD_CHARACTER_OR_HASH = _WORD_CHARACTER.replace("#", "")
_ESCAPED_OR_QUOTED_WORD = r"""\\.|"(?:\\.|[^"])*"|'[^']*'"""

_SHELL_TOKEN_REGEX = re.compile(
    "|".join(
        "(?P<%s>%s)" % pair
        for pair in (
            ("REDIRECT", "(?P<redirect_fd>[0-9]*)(?P<redirect_op><|>>|>)"),
            (
                "WORD",
                r"(?:" + _WORD_CHARACTER + r"|" + _ESCAPED_OR_QUOTED_WORD + r")(?:"
                # '#' in the middle of a word doesn't start a comment.
                + _WORD_CHARACTER_OR_HASH + r"|" + _ESCAPED_OR_QUOTED_WORD + r")*",
            ),
            # We pass everything after a '|' to the shell, so capture the rest.
            ("PIPELINE", r"\|.*"),
            ("WHITESPACE", r"\s+"),
            ("COMMENT", r"#.*"),
            ("MISMATCH", r"."),
        )
    )
)


def _unquote_repl(match: "re.Match[str]") -> str:
    s = match.group()
    if s[0] == "\\":
        return s[1]
    elif s[0] == '"':
        return re.sub(r'\\([$`"\\\n])', r"\1", s[1:-1])
    else:
        assert s[0] == "'"
        return s[1:-1]


def _unquote(s: str) -> str:
    return re.sub(_ESCAPED_OR_QUOTED_WORD, _unquote_repl, s)


_RedirectOp = Literal["<", ">", ">>"]


class _ShellRedirection(NamedTuple):
    fd: int
    op: _RedirectOp
    path: str


class _ParsedShellCommand(NamedTuple):
    args: Sequence[str]
    redirections: Sequence[_ShellRedirection]
    pipeline: Optional[str]


def _parse_shell_command(source: str) -> _ParsedShellCommand:
    args: List[str] = []
    redirections: List[_ShellRedirection] = []
    pipeline = None
    redirection = None

    for match in _SHELL_TOKEN_REGEX.finditer(source):
        kind = match.lastgroup
        value = match.group()
        if kind == "WORD":
            value = _unquote(value)
            if redirection is None:
                args.append(value)
            else:
                redirections.append(
                    _ShellRedirection(fd=redirection[0], op=redirection[1], path=value)
                )
                redirection = None
        elif kind == "PIPELINE":
            # NB: since this is called with the substring after the command
            # name, unlike sh, we allow a string starting with '|'.
            if redirection is not None:
                raise SyntaxError("unexpected '|'")
            pipeline = value[1:].strip()
            if not pipeline:
                raise SyntaxError("unexpected end of input")
        elif kind == "REDIRECT":
            if redirection is not None:
                raise SyntaxError(f"unexpected {value!r}")
            redirect_op: _RedirectOp = match.group("redirect_op")  # type: ignore[assignment]
            if match.group("redirect_fd"):
                redirect_fd = int(match.group("redirect_fd"))
            elif redirect_op == "<":
                redirect_fd = 0
            elif redirect_op == ">" or redirect_op == ">>":
                redirect_fd = 1
            else:
                assert_never(redirect_op)
            redirection = (redirect_fd, redirect_op)
        elif kind in ("WHITESPACE", "COMMENT"):
            pass
        else:
            raise SyntaxError(f"unexpected {value!r}")
    if redirection is not None:
        raise SyntaxError("unexpected end of input")
    return _ParsedShellCommand(args, redirections, pipeline)


@contextlib.contextmanager
def _shell_command(source: str) -> Iterator[_ParsedShellCommand]:
    parsed = _parse_shell_command(source)

    saved = {
        "stdin": sys.stdin,
        "stdout": sys.stdout,
        "stderr": sys.stderr,
    }
    pipe_process = None
    exceptions = []
    try:
        if parsed.pipeline is not None:
            pipe_process = subprocess.Popen(
                parsed.pipeline,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=sys.stdout,
                text=True,
            )
            sys.stdout = pipe_process.stdin

        for fd, op, path in parsed.redirections:
            if op == "<":
                if fd != 0:
                    raise NotImplementedError(
                        f"redirecting input fd {fd} is not supported"
                    )
                attr = "stdin"
                mode = "r"
            elif op == ">" or op == ">>":
                if fd == 1:
                    attr = "stdout"
                elif fd == 2:
                    attr = "stderr"
                else:
                    raise NotImplementedError(
                        f"redirecting output fd {fd} is not supported"
                    )
                if op == ">":
                    mode = "w"
                elif op == ">>":
                    mode = "a"
                else:
                    assert_never(op)
            else:
                assert_never(op)
            if getattr(sys, attr) != saved[attr]:
                try:
                    getattr(sys, attr).close()
                except BrokenPipeError:
                    pass
            setattr(sys, attr, open(path, mode))

        try:
            yield parsed
        except BrokenPipeError:
            pass
    except Exception as e:
        exceptions.append(e)
    finally:
        for attr, file in saved.items():
            if getattr(sys, attr) != file:
                try:
                    getattr(sys, attr).close()
                except BrokenPipeError:
                    pass
                except Exception as e:
                    exceptions.append(e)
                setattr(sys, attr, file)

        if pipe_process is not None:
            try:
                if pipe_process.wait() != 0:
                    raise CommandExitStatusError(
                        pipe_process.args,  # type: ignore[arg-type]
                        pipe_process.returncode,
                    )
            except Exception as e:
                exceptions.append(e)

        # Since Python 3.11, we can raise an exception group with multiple
        # exceptions. Otherwise, just raise the first one.
        if sys.version_info >= (3, 11) and len(exceptions) > 1:
            raise ExceptionGroup("errors while running command", exceptions)  # novermin
        elif exceptions:
            raise exceptions[0]


def _write_command_error(
    writer: SupportsWrite[str], e: Exception, *, prefix: str = "drgn"
) -> None:
    if isinstance(
        e, (CommandArgumentError, CommandExitStatusError, CommandNotFoundError)
    ):
        # These errors are already formatted, so don't add the "error:" prefix.
        writer.write(f"{prefix}: {e}\n")
    elif isinstance(e, SyntaxError):
        writer.write(f"{prefix}: syntax error: {e}\n")
    else:
        writer.write(f"{prefix}: error: {e}\n")


def run_command(
    prog: Program,
    command: str,
    *,
    globals: Optional[Dict[str, Any]] = None,
    onerror: Optional[Callable[[Exception], None]] = None,
) -> Any:
    """
    Run a drgn command.

    :param prog: Program to run command on.
    :param command: Command string (including arguments, redirections, pipes,
        etc.) to run.
    :param globals: Global variables to run command with. Defaults to the
        caller's global variables.
    :param onerror: Callback for handling errors (e.g., logging them). By
        default, errors are raised as exceptions.
    :return: The command's return value. Note that most commands return
        ``None``.
    """
    if globals is None:
        globals = sys._getframe(1).f_globals
    return DEFAULT_COMMAND_NAMESPACE.run(
        prog, command, globals=globals, onerror=onerror
    )


class CommandError(Exception):
    """Error raised when a command fails."""

    pass


class CommandArgumentError(CommandError):
    """Error raised when a command's arguments cannot be parsed."""

    pass


class CommandExitStatusError(CommandError):
    """Error raised when a command pipeline exits with a non-zero status."""

    command: str
    """Command pipeline that failed."""

    exit_status: int
    """Exit status, or negative signal number if terminated by a signal."""

    def __init__(self, command: str, exit_status: int) -> None:
        self.command = command
        self.exit_status = exit_status

    def __str__(self) -> str:
        return f"{self.command!r} exited with status {self.exit_status}"


class CommandNotFoundError(CommandError):
    """Error raised when a command cannot be found."""

    name: str
    """Command name that could not be found."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __str__(self) -> str:
        return f"{self.name}: command not found"


class CommandNamespace:
    """
    Command namespace.

    Commands are registered to a specific namespace and can only be found or
    run in that namespace. This allows reusing drgn's command system for
    commands that shouldn't be exposed directly to the CLI.
    """

    def __init__(
        self,
        *,
        func_name_prefix: str = "_cmd_",
        argparse_types: Sequence[Tuple[str, Callable[[str], Any]]] = (),
    ) -> None:
        """
        Create a command namespace.

        :param func_name_prefix: Function name prefix expected by
            :func:`command()` and :func:`custom_command()`.
        :param argparse_types: ``(name, callable)`` tuples to register as
            argparse types for commands in this namespace. See
            :meth:`argparse.ArgumentParser.register()`.
        """

        self._commands: Dict[str, Command] = {}
        self._func_name_prefix = func_name_prefix
        self._argparse_types = argparse_types

    def register(self, name: str, command: Command) -> None:
        """Register a command in this namespace."""
        self._commands[name] = command

    def lookup(self, prog: Program, name: str) -> Command:
        """
        Find a command in this namespace.

        :param name: Command name.
        :raises CommandNotFoundError: if a command with the given name is not found
        """
        command = self._commands.get(name)
        if command is None or not command.enabled(prog):
            raise CommandNotFoundError(name)
        return command

    def enabled(self, prog: Program) -> Iterable[Tuple[str, Command]]:
        """
        Get all enabled commands in this namespace.

        :return: Iterable of ``(name, command)`` tuples.
        """
        return (
            (name, command)
            for name, command in self._commands.items()
            if command.enabled(prog)
        )

    def _run(self, prog: Program, command: str, *, globals: Dict[str, Any]) -> Any:
        command = command.lstrip()
        match = _SHELL_TOKEN_REGEX.match(command)
        if not match or match.lastgroup != "WORD":
            raise SyntaxError("expected command name")

        command_name = _unquote(match.group())
        args = command[match.end() :].lstrip()
        return self.lookup(prog, command_name).run(
            prog, command_name, args, globals=globals
        )

    def run(
        self,
        prog: Program,
        command: str,
        *,
        globals: Optional[Dict[str, Any]] = None,
        onerror: Optional[Callable[[Exception], None]] = None,
    ) -> Any:
        """
        Run a drgn command in this namespace.

        Arguments and return value are the same as :func:`run_command()`.
        """
        if globals is None:
            globals = sys._getframe(1).f_globals

        try:
            return self._run(prog, command, globals=globals)
        except Exception as e:
            if onerror is None:
                raise
            if sys.version_info >= (3, 11) and isinstance(
                e, ExceptionGroup
            ):  # novermin
                for e2 in e.exceptions:
                    onerror(e2)
            else:
                onerror(e)


DEFAULT_COMMAND_NAMESPACE: CommandNamespace = CommandNamespace()
"""Default command namespace used by the drgn CLI."""


class Command(Protocol):
    """
    Command implementation.

    Commands can usually be defined with :func:`command()` or
    :func:`custom_command()`, but this can be used when even more control is
    needed.
    """

    def description(self) -> str:
        """Return a one-line description of the command."""
        ...

    def format_usage(self) -> str:
        """Return the usage string."""
        ...

    def format_help(self, *, indent: str = "") -> str:
        """
        Return the help string.

        :param indent: String to prepend to each line.
        """
        ...

    def enabled(self, prog: Program) -> bool:
        """
        Return whether the command should be enabled for the given program.
        """
        ...

    def run(
        self,
        prog: Program,
        name: str,
        args: str,
        /,
        *,
        globals: Dict[str, Any],
    ) -> Any:
        """
        Run the command.

        :param prog: Program.
        :param name: Name that the command was invoked as.
        :param args: Command arguments as a string.

        Additional keyword arguments may also be passed. To allow for future
        extensions, implementations of this method should add a variable
        keyword parameter (i.e., ``**kwargs``) and ignore unneeded keyword
        arguments:

        .. code-block:: python3

            class MyCommand:
                ...
                def run(self, prog: Program, name: str, args: str, **kwargs: Any) -> None:
                    ...

        The current keyword parameters are:

        :param globals: Dictionary of global variables.

        :return: Anything, but usually ``None``.
        """
        ...


@overload
def _sanitize_rst(s: str) -> str: ...


@overload
def _sanitize_rst(s: None) -> None: ...


def _sanitize_rst(s: Optional[str]) -> Optional[str]:
    if not s:
        return s
    return re.sub(r"\\(.)|[*\\]", r"\1", s)


class _DrgnCommandArgumentParser(argparse.ArgumentParser):
    def exit(self, status: int = 0, message: Optional[str] = None) -> NoReturn:
        if message is None:
            raise CommandArgumentError()
        else:
            raise CommandArgumentError(message.rstrip("\n"))


def _add_argument(
    parser: Any, arg: Union[argument, argument_group, mutually_exclusive_group]
) -> None:
    if isinstance(arg, argument):
        parser.add_argument(*arg.args, **arg.kwargs)
    elif isinstance(arg, argument_group):
        group = parser.add_argument_group(title=arg.title, description=arg.description)
        for arg in arg.arguments:
            _add_argument(group, arg)
    elif isinstance(arg, mutually_exclusive_group):
        group = parser.add_mutually_exclusive_group(required=arg.required)
        for arg in arg.arguments:
            _add_argument(group, arg)
    else:
        assert_never(arg)


def _command_name(
    name: Optional[str], func: Callable[..., Any], namespace: CommandNamespace
) -> str:
    if name is None:
        if not hasattr(func, "__name__"):
            raise ValueError("callable doesn't have __name__; pass name explicitly")
        match = re.fullmatch(namespace._func_name_prefix + r"(\w+)", func.__name__)
        if not match:
            raise ValueError(
                f"{func.__name__!r} doesn't start with {namespace._func_name_prefix}; "
                "rename it or pass name explicitly"
            )
        name = match.group(1)

    return name


def _decimal_or_hexadecimal(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return int(s, 16)


def command(
    *,
    name: Optional[str] = None,
    description: str,
    usage: Optional[str] = None,
    long_description: Optional[str] = None,
    epilog: Optional[str] = None,
    arguments: Sequence[Union[argument, argument_group, mutually_exclusive_group]] = (),
    enabled: Optional[Callable[[Program], bool]] = None,
    namespace: CommandNamespace = DEFAULT_COMMAND_NAMESPACE,
) -> CommandFuncDecorator:
    """
    Decorator to register a command.

    Commands registered with this decorator parse options specified in
    *arguments* using :mod:`argparse`. See :func:`custom_command()` for an
    alternative that doesn't use :mod:`argparse`.

    See :class:`CommandFunc` for the signature of the command function.

    Descriptions and help strings may have multiple lines (unlike the default
    :mod:`argparse` formatting).

    There are also a couple of argparse argument types provided for convenience:

    1. ``"hexadecimal"``: a hexadecimal integer.
    2. ``"decimal_or_hexadecimal``: a decimal or hexadecimal integer,
       preferring decimal if ambiguous.

    .. code-block:: python3

        import argparse
        from typing import Any

        from drgn import Program
        from drgn.commands import command


        @command(description="do nothing")
        def _cmd_true(
            prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
        ) -> None:
            pass

    :param name: Command name. If not given, the name of the decorated function
        must begin with ``_cmd_``, and the command name is the function name
        with that prefix removed.
    :param description: Mandatory one-line description of the command.
    :param usage: Usage string in reStructuredText format. Generated from
        arguments automatically if not given.
    :param long_description: Optional longer description of the command.
    :param epilog: Optional additional information to show at the end of help
        output.
    :param arguments: Arguments, argument groups, and mutually exclusive groups
        accepted by the command.
    :param enabled: Callback returning whether the command should be enabled
        for a given program. Defaults to always enabled.
    :param namespace: Namespace to register command to.
    """

    def decorator(func: CommandFunc) -> CommandFunc:
        command_name = _command_name(name, func, namespace)

        parser = _DrgnCommandArgumentParser(
            prog=command_name,
            description=long_description,
            usage=_sanitize_rst(usage),
            epilog=epilog,
            formatter_class=_drgn_util.argparseformatter.MultilineHelpFormatter,
            add_help=False,
            allow_abbrev=False,
        )
        parser.register("type", "hexadecimal", lambda s: int(s, 16))
        parser.register("type", "decimal_or_hexadecimal", _decimal_or_hexadecimal)
        for type_name, type_func in namespace._argparse_types:
            parser.register("type", type_name, type_func)
        for arg in arguments:
            _add_argument(parser, arg)

        namespace.register(
            command_name,
            _ArgparseCommand(
                func=func, parser=parser, description=description, enabled=enabled
            ),
        )

        return func

    return decorator


class CommandFunc(Protocol):
    """Signature of a command function for :func:`command()`."""

    def __call__(
        self,
        prog: Program,
        name: str,
        args: argparse.Namespace,
        /,
        *,
        globals: Dict[str, Any],
    ) -> Any:
        """
        :param prog: Program.
        :param name: Name that the command was invoked as.
        :param args: Parsed arguments as an :class:`argparse.Namespace`.

        See :meth:`Command.run()` for keyword parameters.

        :return: Anything, but usually ``None``.
        """
        ...


CommandFuncDecorator = Callable[[CommandFunc], CommandFunc]


class argument:
    @copy_method_params(argparse.ArgumentParser.add_argument)
    def __init__(self, /, *args: Any, **kwargs: Any) -> None:
        """
        Command line argument for :func:`command()`.

        Arguments are the same as :meth:`argparse.ArgumentParser.add_argument()`.

        .. code-block:: python3

            import argparse
            from typing import Any

            from drgn import Program
            from drgn.commands import argument, command


            @command(
                description="concatenate and print files",
                arguments=(
                    argument("-n", help="number output lines"),
                    argument("file", nargs="*", help="input files"),
                ),
            )
            def _cmd_cat(
                prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
            ) -> None:
                ...
        """
        self.args = args
        self.kwargs = kwargs


drgn_argument: argument = argument(
    "--drgn",
    action="store_true",
    help="print how to do the equivalent operation using drgn APIs",
)
"""
Command line argument for :func:`command()` named ``--drgn`` indicating that
the command should print how to do the equivalent operation using drgn APIs.

This helps onboard users from simple commands to more complex use cases
requiring programmability.

By convention, it should normally be the last argument.

.. code-block:: python3

    import argparse
    from typing import Any

    from drgn import Program
    from drgn.commands import argument, command, drgn_argument


    @command(
        description="print a stack trace"
        arguments=(
            argument("tid", type=int, help="thread ID"),
            drgn_argument,
        ),
    )
    def _cmd_bt(
        prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
    ) -> None:
        if args.drgn:
            print("trace = stack_trace(tid)")
            print("print(trace)")
            return
        print(prog.stack_trace(args.tid))
"""


class argument_group:
    def __init__(
        self,
        /,
        *arguments: Union[argument, mutually_exclusive_group],
        title: str,
        description: Optional[str] = None,
    ) -> None:
        """
        Group of arguments for :func:`command()`.

        See :meth:`argparse.ArgumentParser.add_argument_group()`.

        .. code-block:: python3

            import argparse
            from typing import Any

            from drgn import Program
            from drgn.commands import argument, argument_group, command


            @command(
                description="print matching lines",
                arguments=(
                    argument_group(
                        argument("-A", type=int, help="print lines after match"),
                        argument("-B", type=int, help="print lines before match"),
                        title="context line options",
                    )
                    argument("pattern", help="pattern to search for"),
                ),
            )
            def _cmd_grep(
                prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
            ) -> None:
                ...

        :param arguments: Arguments and mutually exclusive groups in the group.
        :param title: Title to group arguments under.
        :param description: Description of group.
        """
        self.arguments = arguments
        self.title = title
        self.description = description


class mutually_exclusive_group:
    def __init__(self, /, *arguments: argument, required: bool = False) -> None:
        """
        Mutually exclusive group of arguments for :func:`command()`.

        See :meth:`argparse.ArgumentParser.add_mutually_exclusive_group()`.

        This is often nested in an :func:`argument_group()`:

        .. code-block:: python3

            import argparse
            from typing import Any

            from drgn import Program
            from drgn.commands import (
                argument,
                argument_group,
                command,
                mutually_exclusive_group,
            )


            @command(
                description="print matching lines",
                arguments=(
                    argument_group(
                        mutually_exclusive_group(
                            argument(
                                "-E",
                                action="store_true",
                                help="use extended regular expressions",
                            ),
                            argument(
                                "-F",
                                action="store_true",
                                help="match a fixed string",
                            ),
                        ),
                        title="pattern syntax",
                    )
                    argument("pattern", help="pattern to search for"),
                ),
            )
            def _cmd_grep(
                prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
            ) -> None:
                ...

        It can also be passed directly to :func:`command()`:

        .. code-block:: python3

            @command(
                description="print matching lines",
                arguments=(
                    mutually_exclusive_group(
                        argument(
                            "-E",
                            action="store_true",
                            help="use extended regular expressions",
                        ),
                        argument(
                            "-F",
                            action="store_true",
                            help="match a fixed string",
                        ),
                    ),
                    argument("pattern", help="pattern to search for"),
                ),
            )
            def _cmd_grep(
                prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
            ) -> None:
                ...

        :param arguments: Arguments in the group.
        :param required: Whether exactly one of the arguments is required.
        """
        self.required = required
        self.arguments = arguments


def custom_command(
    *,
    name: Optional[str] = None,
    description: str,
    usage: str,
    help: str,
    enabled: Optional[Callable[[Program], bool]] = None,
    namespace: CommandNamespace = DEFAULT_COMMAND_NAMESPACE,
) -> CustomCommandFuncDecorator:
    """
    Decorator to register a command with its own custom syntax (instead of
    command line options).

    See :class:`CustomCommandFunc` for the signature of the command function.

    .. code-block:: python3

        import ast
        from typing import Any

        from drgn import Program
        from drgn.commands import custom_command


        @custom_command(
            description="evaluate a Python literal",
            usage="**literal_eval** *EXPR*",
            help="This evaluates and returns a Python literal"
            " (for example, a string, integer, list, etc.).",
        )
        def _cmd_literal_eval(
            prog: Program, name: str, args: str, **kwargs: Any
        ) -> Any:
            return ast.literal_eval(args)

    :param name: Command name. If not given, the name of the decorated function
        must begin with ``_cmd_``, and the command name is the function name
        with that prefix removed.
    :param description: Mandatory one-line description of the command.
    :param usage: Mandatory usage string in reStructuredText format.
    :param help: Mandatory help string.
    :param enabled: Callback returning whether the command should be enabled
        for a given program. Defaults to always enabled.
    :param namespace: Namespace to register command to.
    """

    def decorator(func: CustomCommandFunc) -> CustomCommandFunc:
        namespace.register(
            _command_name(name, func, namespace),
            _CustomCommand(
                func=func,
                description=description,
                help=help,
                usage=_sanitize_rst(usage),
                enabled=enabled,
            ),
        )

        return func

    return decorator


class CustomCommandFunc(Protocol):
    """Signature of a custom command function for :func:`custom_command()`."""

    def __call__(
        self,
        prog: Program,
        name: str,
        args: str,
        /,
        *,
        globals: Dict[str, Any],
    ) -> Any:
        """
        :param prog: Program.
        :param name: Name that the command was invoked as.
        :param args: Command arguments as a string.

        See :meth:`Command.run()` for keyword parameters.

        :return: Anything, but usually ``None``.
        """
        ...


CustomCommandFuncDecorator = Callable[[CustomCommandFunc], CustomCommandFunc]


class _ArgparseCommand:
    def __init__(
        self,
        func: CommandFunc,
        parser: argparse.ArgumentParser,
        description: str,
        enabled: Optional[Callable[[Program], bool]] = None,
    ) -> None:
        self._func = func
        self._parser = parser
        self._description = description
        self.enabled = (lambda prog: True) if enabled is None else enabled

    def description(self) -> str:
        return self._description

    def format_usage(self) -> str:
        usage = self._parser.format_usage()
        if usage.startswith("usage: "):
            usage = usage[len("usage: ") :]
        return usage.rstrip()

    def format_help(self, *, indent: str = "") -> str:
        usage = self._parser.format_usage()
        help = self._parser.format_help()
        if help.startswith(usage):
            help = help[len(usage) :].lstrip()
        return textwrap.indent(help, indent).rstrip()

    def run(self, prog: Program, name: str, args: str, **kwargs: Any) -> Any:
        with _shell_command(args) as parsed:
            parsed_args = self._parser.parse_args(parsed.args)
            return self._func(prog, name, parsed_args, **kwargs)


class _CustomCommand:
    def __init__(
        self,
        func: CustomCommandFunc,
        description: str,
        help: str,
        usage: str,
        enabled: Optional[Callable[[Program], bool]] = None,
    ) -> None:
        self._func = func
        self._description = description
        self._help = help
        self._usage = usage
        self.enabled = (lambda prog: True) if enabled is None else enabled
        self.run = func

    def description(self) -> str:
        return self._description

    def format_usage(self) -> str:
        return self._usage

    def format_help(self, *, indent: str = "") -> str:
        return multiline_fill(
            self._help,
            width=shutil.get_terminal_size().columns,
            indent=indent,
        )


class DrgnCodeBuilder:
    """
    Helper class for generating code for :func:`drgn_argument`.

    This handles joining multiple fragments of code and adding imports. Imports
    are deduplicated, sorted, and prepended to the final output.
    """

    def __init__(self) -> None:
        self._code: List[str] = []
        self._imports: Dict[str, Set[str]] = collections.defaultdict(set)

    def append(self, code: str) -> None:
        """Append a code fragment to the output."""
        if code:
            self._code.append(code)

    def add_import(self, module: str) -> None:
        """
        Add an import to the output.

        :param modules: Module to import.
        """
        self._imports[module].add("")

    def add_from_import(self, module: str, *names: str) -> None:
        """
        Add a ``from module import name1, name2, ...`` import to the output.

        :param module: Module name.
        :param names: Names to import from *module*.
        """
        self._imports[module].update(names)

    def get(self) -> str:
        """Get the output as a string."""
        parts: List[str] = []
        first_party_imports: List[str] = []
        for module, names in sorted(self._imports.items()):
            if module == "drgn" or module.startswith("drgn."):
                target = first_party_imports
            else:
                target = parts

            if "" in names:
                names.remove("")
                target.append(f"import {module}\n")

            if names:
                sorted_names = sorted(names)
                line = f"from {module} import {', '.join(sorted_names)}\n"
                # 88 (the default Black line length) + 1 for the newline.
                if len(line) <= 89:
                    target.append(line)
                else:
                    target.append(f"from {module} import (\n")
                    for name in sorted_names:
                        target.append(f"    {name},\n")
                    target.append(")\n")

        if parts and first_party_imports:
            parts.append("\n")
        parts.extend(first_party_imports)

        if parts and self._code:
            parts.append("\n\n")
        parts.extend(self._code)

        return "".join(parts)

    def print(self) -> None:
        """Write the output to standard output."""
        sys.stdout.write(self.get())
