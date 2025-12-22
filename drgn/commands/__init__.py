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
import dataclasses
import functools
import re
import subprocess
import sys
import textwrap
import traceback
import types
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generic,
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
    TypeVar,
    Union,
    overload,
)

if TYPE_CHECKING:
    if sys.version_info < (3, 11):
        from typing_extensions import Self, assert_never
    else:
        from typing import Self, assert_never  # novermin
    from _typeshed import SupportsWrite

import _drgn_util.argparseformatter
from _drgn_util.typingutils import copy_method_params
from drgn import Program, ProgramFlags

T = TypeVar("T")
T_co = TypeVar("T_co", covariant=True)
T_contra = TypeVar("T_contra", contravariant=True)


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


@contextlib.contextmanager
def _redirect_and_pipe(
    redirections: Sequence[ShellRedirection], pipeline: Optional[str]
) -> Iterator[None]:
    saved = {
        "stdin": sys.stdin,
        "stdout": sys.stdout,
        "stderr": sys.stderr,
    }
    pipe_process = None
    exceptions = []
    try:
        if pipeline is not None:
            pipe_process = subprocess.Popen(
                pipeline,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=sys.stdout,
                text=True,
            )
            sys.stdout = pipe_process.stdin

        for fd, op, path in redirections:
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
            yield
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
            :func:`command()`, :func:`custom_command()`, and
            :func:`raw_command()`.
        :param argparse_types: ``(name, callable)`` tuples to register as
            argparse types for commands in this namespace. See
            :meth:`argparse.ArgumentParser.register()`.
        """

        self._commands: Dict[str, Command[object]] = {}
        self._func_name_prefix = func_name_prefix
        self._argparse_types = argparse_types

    def register(self, name: str, command: Command[Any]) -> None:
        """Register a command in this namespace."""
        self._commands[name] = command

    def lookup(self, prog: Program, name: str) -> Command[object]:
        """
        Find a command in this namespace.

        :param name: Command name.
        :raises CommandNotFoundError: if a command with the given name is not found
        """
        command = self._commands.get(name)
        if command is None or not command.enabled(prog):
            raise CommandNotFoundError(name)
        return command

    def enabled(self, prog: Program) -> Iterable[Tuple[str, Command[object]]]:
        """
        Get all enabled commands in this namespace.

        :return: Iterable of ``(name, command)`` tuples.
        """
        return (
            (name, command)
            for name, command in self._commands.items()
            if command.enabled(prog)
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
            kwargs = {"globals": globals}
            name, tail, command_obj, pager = self._resolve(prog, command, kwargs)
            parsed = command_obj.parse(tail)

            pipeline = parsed.pipeline
            if (
                pipeline is None
                and not any(redirection.fd == 1 for redirection in parsed.redirections)
                and pager is not None
            ):
                # We can only pipe to a pager if stdout is a file descriptor.
                try:
                    sys.stdout.fileno()
                except (AttributeError, OSError):
                    pass
                else:
                    pipeline = pager

            with _redirect_and_pipe(parsed.redirections, pipeline):
                return command_obj.run(prog, name, parsed.args, **kwargs)
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

    def _resolve(
        self, prog: Program, command: str, kwargs: Dict[str, Any]
    ) -> Tuple[str, str, Command[object], Optional[str]]:
        command = command.lstrip()
        match = _SHELL_TOKEN_REGEX.match(command)
        if not match or match.lastgroup != "WORD":
            raise SyntaxError("expected command name")

        name = unquote_shell_word(match.group())
        return name, command[match.end() :].lstrip(), self.lookup(prog, name), None


DEFAULT_COMMAND_NAMESPACE: CommandNamespace = CommandNamespace()
"""Default command namespace used by the drgn CLI."""


class Command(Protocol[T]):
    """
    Command implementation.

    Commands can usually be defined with :func:`command()`,
    :func:`custom_command()`, or :func:`raw_command()`, but this can be used
    when even more control is needed.
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

    def parse(self, source: str, /) -> ParsedCommand[T]:
        """
        Parse the command string after the command name.

        This must separate redirections and pipes from arguments.

        :param source: Command string after command name (arguments,
            redirections, pipes, etc.).
        """
        ...

    def run(
        self,
        prog: Program,
        name: str,
        args: T,
        /,
        *,
        globals: Dict[str, Any],
    ) -> Any:
        """
        Run the command.

        :param prog: Program.
        :param name: Name that the command was invoked as.
        :param args: Command arguments returned in :attr:`ParsedCommand.args`
            by :meth:`parse()`.

        Additional keyword arguments may also be passed. To allow for future
        extensions, implementations of this method should add a variable
        keyword parameter (i.e., ``**kwargs``) and ignore unneeded keyword
        arguments:

        .. code-block:: python3

            class MyCommand:
                ...
                def run(
                    self, prog: Program, name: str, args: Sequence[str], **kwargs: Any
                ) -> None:
                    ...

        The current keyword parameters are:

        :param globals: Dictionary of global variables.

        :return: Anything, but usually ``None``.
        """
        ...


@dataclasses.dataclass(frozen=True)
class ParsedCommand(Generic[T]):
    """Parsed command string."""

    args: T
    """Arguments."""

    redirections: Sequence[ShellRedirection] = ()
    """Shell redirections."""

    pipeline: Optional[str] = None
    """Pipeline."""


class ShellRedirection(NamedTuple):
    """Shell redirection."""

    fd: int
    """File descriptor to redirect."""

    op: RedirectOp
    """Redirection operator (``"<"``, ``">"``, etc.)."""

    path: str
    """Path to redirect to."""


RedirectOp = Literal["<", ">", ">>"]


def parse_shell_command(
    source: str, unquote: bool = True
) -> ParsedCommand[Sequence[str]]:
    """
    Parse a shell command string.

    :param source: Command string after command name (arguments,
        redirections, pipes, etc.).
    :param unquote: Whether to unquote/unescape arguments.
    """
    args: List[str] = []
    redirections: List[ShellRedirection] = []
    pipeline = None
    redirection = None

    for match in _SHELL_TOKEN_REGEX.finditer(source):
        kind = match.lastgroup
        value = match.group()
        if kind == "WORD":
            if redirection is None:
                if unquote:
                    value = unquote_shell_word(value)
                args.append(value)
            else:
                redirections.append(
                    ShellRedirection(
                        fd=redirection[0],
                        op=redirection[1],
                        path=unquote_shell_word(value),
                    )
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
            redirect_op: RedirectOp = match.group("redirect_op")  # type: ignore[assignment]
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
    return ParsedCommand(args, redirections, pipeline)


def _unquote_repl(match: "re.Match[str]") -> str:
    s = match.group()
    if s[0] == "\\":
        return s[1]
    elif s[0] == '"':
        return re.sub(r'\\([$`"\\\n])', r"\1", s[1:-1])
    else:
        assert s[0] == "'"
        return s[1:-1]


def unquote_shell_word(word: str) -> str:
    r"""
    Unquote/unescape a quoted and/or escaped word in shell syntax.

    >>> print(unquote_shell_word(r"f'o'o\ bar"))
    foo bar
    """
    return re.sub(_ESCAPED_OR_QUOTED_WORD, _unquote_repl, word)


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
        kwargs = arg.kwargs
        # argparse needs % to be escaped in help strings.
        if "%" in (help := kwargs.get("help", "")):
            kwargs = dict(kwargs, help=help.replace("%", "%%"))
        parser.add_argument(*arg.args, **kwargs)
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
    name: Optional[str],
    func: Callable[..., Any],
    prefix: str,
) -> str:
    if name is None:
        if not hasattr(func, "__name__"):
            raise ValueError("callable doesn't have __name__; pass name explicitly")
        match = re.fullmatch(prefix + r"(\w+)", func.__name__)
        if not match:
            raise ValueError(
                f"{func.__name__!r} doesn't start with {prefix}; "
                "rename it or pass name explicitly"
            )
        name = match.group(1)

    return name


def _decimal_or_hexadecimal(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return int(s, 16)


def _create_parser(
    *,
    name: str,
    usage: Optional[str] = None,
    description: Optional[str] = None,
    epilog: Optional[str] = None,
    arguments: Sequence[Union[argument, argument_group, mutually_exclusive_group]],
    types: Sequence[Tuple[str, Callable[[str], Any]]],
) -> argparse.ArgumentParser:
    parser = _DrgnCommandArgumentParser(
        prog=name,
        description=description,
        usage=_sanitize_rst(usage),
        epilog=epilog,
        formatter_class=_drgn_util.argparseformatter.MultilineHelpFormatter,
        add_help=False,
        allow_abbrev=False,
    )
    parser.register("type", "hexadecimal", lambda s: int(s, 16))
    parser.register("type", "decimal_or_hexadecimal", _decimal_or_hexadecimal)
    for type_name, type_func in types:
        parser.register("type", type_name, type_func)
    for arg in arguments:
        _add_argument(parser, arg)
    return parser


def _always_enabled(prog: Program) -> bool:
    return True


def command(
    *,
    name: Optional[str] = None,
    description: str,
    usage: Optional[str] = None,
    long_description: Optional[str] = None,
    epilog: Optional[str] = None,
    arguments: Sequence[Union[argument, argument_group, mutually_exclusive_group]] = (),
    enabled: Callable[[Program], bool] = _always_enabled,
    namespace: CommandNamespace = DEFAULT_COMMAND_NAMESPACE,
) -> CommandFuncDecorator:
    """
    Decorator to register a command.

    Commands registered with this decorator parse options specified in
    *arguments* using :mod:`argparse`. See :func:`custom_command()` and
    :func:`raw_command()` for alternatives that doesn't use :mod:`argparse`.

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
        *arguments* automatically if not given.
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
        command_name = _command_name(name, func, namespace._func_name_prefix)

        parser = _create_parser(
            name=command_name,
            usage=usage,
            description=long_description,
            epilog=epilog,
            arguments=arguments,
            types=namespace._argparse_types,
        )

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
        parser: argparse.ArgumentParser,
        globals: Dict[str, Any],
    ) -> Any:
        """
        :param prog: Program.
        :param name: Name that the command was invoked as.
        :param args: Parsed arguments as an :class:`argparse.Namespace`.
        :param parser: Argument parser.

        See :meth:`Command.run()` for other keyword parameters.

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
    usage: Optional[str] = None,
    long_description: Optional[str] = None,
    epilog: Optional[str] = None,
    arguments: Optional[
        Sequence[Union[argument, argument_group, mutually_exclusive_group]]
    ] = None,
    parse: Callable[[str], ParsedCommand[T]],
    enabled: Callable[[Program], bool] = _always_enabled,
    namespace: CommandNamespace = DEFAULT_COMMAND_NAMESPACE,
) -> CustomCommandFuncDecorator[T]:
    """
    Decorator to register a command with its own custom syntax (instead of
    command line options).

    See :class:`CustomCommandFunc` for the signature of the command function.

    .. code-block:: python3

        import ast
        import dataclasses
        import re
        from typing import Any

        from drgn import Program
        from drgn.commands import ParsedCommand, custom_command, parse_shell_command


        def _parse_literal_eval(source: str) -> ParsedCommand[str]:
            match = re.fullmatch(r"([^<>|]*)(.*)", source)
            parsed = parse_shell_command(match.group(2))
            if parsed.args:
                raise SyntaxError("arguments after redirections are not supported")
            return dataclasses.replace(parsed, args=match.group(1))


        @custom_command(
            description="evaluate a Python literal",
            usage="**literal_eval** *EXPR*",
            long_description="This evaluates and returns a Python literal"
            " (for example, a string, integer, list, etc.).",
            parse=_parse_literal_eval,
        )
        def _cmd_literal_eval(
            prog: Program, name: str, args: str, **kwargs: Any
        ) -> Any:
            return ast.literal_eval(args)

    :param name: Command name. If not given, the name of the decorated function
        must begin with ``_cmd_``, and the command name is the function name
        with that prefix removed.
    :param description: Mandatory one-line description of the command.
    :param usage: Usage string in reStructuredText format. Mandatory if
        *arguments* not given, otherwise generated from *arguments*
        automatically if not given.
    :param long_description: Longer description of the command. Mandatory if
        *arguments* not given, optional otherwise.
    :param epilog: Optional additional information to show at the end of help
        output.
    :param arguments: Arguments, argument groups, and mutually exclusive groups
        accepted by the command. Used **only** for generating help output.
    :param parse: Callback to parse the command string after the command name.
        This must separate redirections and pipes from arguments.
    :param enabled: Callback returning whether the command should be enabled
        for a given program. Defaults to always enabled.
    :param namespace: Namespace to register command to.
    """

    if arguments is None:
        if usage is None:
            raise TypeError("usage is mandatory if arguments not given")
        if long_description is None:
            raise TypeError("long_description is mandatory if arguments not given")
        arguments = ()

    def decorator(func: CustomCommandFunc[Any]) -> CustomCommandFunc[Any]:
        command_name = _command_name(name, func, namespace._func_name_prefix)

        parser = _create_parser(
            name=command_name,
            usage=usage,
            description=long_description,
            epilog=epilog,
            arguments=arguments,
            types=namespace._argparse_types,
        )

        namespace.register(
            command_name,
            _CustomCommand(
                func=func,
                parser=parser,
                description=description,
                parse=parse,
                enabled=enabled,
            ),
        )

        return func

    return decorator


class CustomCommandFunc(Protocol[T_contra]):
    """Signature of a custom command function for :func:`custom_command()`."""

    def __call__(
        self,
        prog: Program,
        name: str,
        args: T_contra,
        /,
        *,
        parser: argparse.ArgumentParser,
        globals: Dict[str, Any],
    ) -> Any:
        """
        :param prog: Program.
        :param name: Name that the command was invoked as.
        :param args: Command arguments parsed by *parse* argument to
            :func:`custom_command()`.
        :param parser: Argument parser.

        See :meth:`Command.run()` for other keyword parameters.

        :return: Anything, but usually ``None``.
        """
        ...


CustomCommandFuncDecorator = Callable[[CustomCommandFunc[T]], CustomCommandFunc[T]]


raw_command = functools.partial(custom_command, parse=ParsedCommand)
"""
Special case of :class:`custom_command()` where the arguments are the command
string verbatim.

Note that this cannot support redirections or pipes.

.. code-block:: python3

    from typing import Any

    from drgn import Program
    from drgn.commands import argument, raw_command


    @raw_command(
        description="display text verbatim",
        arguments=(
            argument("text", help="text to display"),
        ),
    )
    def _cmd_echo(
        prog: Program, name: str, args: str, **kwargs: Any
    ) -> Any:
        print(args)
"""


class _CustomCommand(Generic[T]):
    def __init__(
        self,
        func: CustomCommandFunc[T],
        parser: argparse.ArgumentParser,
        description: str,
        parse: Callable[[str], ParsedCommand[T]],
        enabled: Callable[[Program], bool],
    ) -> None:
        self._func = func
        self._parser = parser
        self._description = description
        self.parse = parse
        self.enabled = enabled

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

    def run(self, prog: Program, name: str, args: T, **kwargs: Any) -> Any:
        return self._func(prog, name, args, **kwargs, parser=self._parser)


class _ArgparseCommand(_CustomCommand[Sequence[str]]):
    def __init__(
        self,
        func: CommandFunc,
        parser: argparse.ArgumentParser,
        description: str,
        enabled: Callable[[Program], bool],
    ) -> None:
        super().__init__(
            self._run_argparse, parser, description, parse_shell_command, enabled
        )
        self._argparse_func = func

    def _run_argparse(
        self,
        prog: Program,
        name: str,
        args: Sequence[str],
        parser: argparse.ArgumentParser,
        **kwargs: Any,
    ) -> Any:
        return self._argparse_func(
            prog, name, parser.parse_args(args), **kwargs, parser=parser
        )


# Variant of repr() that prefers double-quoted strings (like Black).
def _repr_black(obj: Any) -> str:
    if not isinstance(obj, str):
        return repr(obj)
    r = repr(obj + "'")
    if r.endswith("'\""):
        return r[:-2] + '"'
    else:
        assert r.endswith(r"\''")
        return r[:-3] + "'"


class DrgnCodeBuilder:
    """
    Helper class for generating code for :func:`drgn_argument`.

    This handles joining multiple fragments of code and adding imports. Imports
    are deduplicated, sorted, and prepended to the final output.
    """

    def __init__(self, prog: Program) -> None:
        self._prog = prog
        self._code: List[str] = []
        self._imports: Dict[str, Set[str]] = collections.defaultdict(set)
        self._blocks: List[DrgnCodeBlockContext] = []

    def append(self, code: str) -> None:
        """Append a code fragment to the output."""
        if not code:
            return

        if not self._blocks:
            self._code.append(code)
            return

        indent = self._blocks[-1]._indent
        should_indent = not self._code or self._code[-1].endswith("\n")
        for line in code.splitlines(keepends=True):
            if should_indent and line != "\n":
                self._code.append(indent)

            self._code.append(line)
            should_indent = True

    def begin_block(self, code: str, end: str = "") -> DrgnCodeBlockContext:
        """
        Append a code fragment that begins an indented block.

        This can be used to wrap code that may or may not need to be executed
        in a conditional or loop.

        Subsequent lines added with :meth:`append()` will be indented
        accordingly until the block is ended with :meth:`end_block()`:

        .. code-block:: python3

            if condition:
                code.begin_block(f"if {condition}:\\n")
            code.append("do_something()\\n")
            if condition:
                code.end_block()

        Alternatively, this can be used as a context manager:

        .. code-block:: python3

            with code.begin_block(f"while {condition}:\\n")
                code.append("do_something()\\n")

        :param code: Code fragment whose last non-whitespace line begins the
            block (e.g., an ``if`` or ``for`` statement). This can also be
            empty to begin a "fake" block that doesn't affect indentation but
            still pairs with a :meth:`end_block()` call.
        :param end: Code fragment to append when the block is ended. This is
            useful for ``try`` statements.
        """
        if code:
            match = re.fullmatch(
                r"""
                # Skip everything until we find...
                (?s:.)*
                # ... the last line that is not only whitespace, and capture
                # its indentation.
                ^([ \t]*)\S.*\n
                # Ignore zero or more trailing lines of only whitespace.
                (?:\s*\n)?
                """,
                code,
                flags=re.MULTILINE | re.VERBOSE,
            )
            if not match:
                if code.endswith("\n"):
                    raise ValueError("code is all whitespace")
                else:
                    raise ValueError("code does not end with newline")
            indent = match.group(1) + "    "

            self.append(code)
        else:
            indent = ""

        if self._blocks:
            indent = self._blocks[-1]._indent + indent
        block = DrgnCodeBlockContext(self, indent, end)
        self._blocks.append(block)
        return block

    def end_block(self) -> None:
        """
        End the most recently begun indented block.

        See :meth:`begin_block()`.
        """
        self._blocks[-1].end()

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

    def begin_retry_loop_if_live(self, num_attempts: int) -> "DrgnCodeBlockContext":
        """
        Begin a loop that retries on transient :class:`~drgn.FaultError` or
        :class:`~drgn.helpers.ValidationError` errors if the program is live.

        This must be paired with :meth:`end_block()` or used as a context
        manager.

        :param num_attempts: Maximum number of attempts.
        """
        if not (self._prog.flags & ProgramFlags.IS_LIVE):
            return self.begin_block("")

        self.add_from_import("drgn", "FaultError")
        self.add_from_import("drgn.helpers", "ValidationError")
        return self.begin_block(
            f"""\
# This is racy. Retry a limited number of times.
for attempts_remaining in range({num_attempts}, 0, -1):
    try:
""",
            """\
        break
    except (FaultError, ValidationError):
        if attempts_remaining == 1:
            raise
""",
        )

    def get(self) -> str:
        """Get the output as a string."""
        assert not self._blocks

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


class DrgnCodeBlockContext:
    def __init__(self, builder: DrgnCodeBuilder, indent: str, end: str) -> None:
        self._builder = builder
        self._indent = indent
        self._end = end

    def end(self) -> None:
        assert self._builder._blocks[-1] is self
        self._builder.append(self._builder._blocks.pop()._end)

    def __enter__(self) -> "Self":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.end()


def _parse_py_command(
    args: str,
) -> ParsedCommand[Union[types.CodeType, SyntaxError, None]]:
    for match in re.finditer(r"[|<>]", args):
        try:
            source = args[: match.start()]
            if not source or source.isspace():
                code = None
            else:
                code = compile(source, "<input>", "single")
        except SyntaxError:
            pass
        else:
            parsed = parse_shell_command(args[match.start() :])
            if parsed.args:
                # Don't allow extra arguments to be mixed in with redirections.
                raise SyntaxError("py does not support arguments after redirections")
            return dataclasses.replace(parsed, args=code)  # type: ignore[arg-type,return-value]
    else:
        # Fallback for no match: compile all the code as a "single" statement
        # so exec() still prints out the result. If there is a syntax error,
        # let the command handle it.
        if not args or args.isspace():
            return ParsedCommand(None)
        try:
            return ParsedCommand(compile(args, "<input>", "single"))
        except SyntaxError as e:
            return ParsedCommand(e)


# Print an exception without our own compile() frame, which could confuse the
# user.
def _print_py_command_exception(exc: BaseException) -> None:
    # Unfortunately, traceback objects are linked lists and there's no built-in
    # functionality to drop the last N frames of a traceback while printing.
    tb = exc.__traceback__
    count = 0
    while tb:
        count += 1
        tb = tb.tb_next
    traceback.print_exception(type(exc), exc, exc.__traceback__, limit=1 - count)
