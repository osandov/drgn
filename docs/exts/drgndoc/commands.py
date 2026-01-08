# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ast
import re
import sys
import typing
from typing import (
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

if typing.TYPE_CHECKING:
    if sys.version_info < (3, 11):
        from typing_extensions import assert_never
    else:
        from typing import assert_never  # novermin

import sphinx.util.logging

from _drgn_util.multilinewrap import multiline_wrap
from drgndoc.namespace import BoundNode, Namespace, ResolvedNode
from drgndoc.parse import Class, Function, Module, Variable

T = TypeVar("T")

logger = sphinx.util.logging.getLogger(__name__)


class UnrecognizedInputError(ValueError):
    pass


def _log_unrecognized_input(e: Union[str, UnrecognizedInputError]) -> None:
    logger.warning("%s", e, type="drgndoc")


class Command(NamedTuple):
    func: ResolvedNode[Function]
    name: str
    decorator: ast.Call
    enabled: str


_ArgumentType = Literal[
    "drgn.commands.argument",
    "drgn.commands.argument_group",
    "drgn.commands.mutually_exclusive_group",
]


def _get_kwarg(node: ast.Call, name: str) -> Optional[ast.expr]:
    for keyword in node.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _get_string_kwarg(node: ast.Call, name: str) -> Optional[str]:
    arg = _get_kwarg(node, name)
    if arg is None:
        return None
    if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
        raise UnrecognizedInputError(f"{name} is not string literal: {ast.dump(arg)}")
    return arg.value


def _get_string_or_none_kwarg(node: ast.Call, name: str) -> Optional[str]:
    arg = _get_kwarg(node, name)
    if arg is None:
        return None
    if not isinstance(arg, ast.Constant) or not isinstance(
        arg.value, (str, type(None))
    ):
        raise UnrecognizedInputError(
            f"{name} is not string literal or None: {ast.dump(arg)}"
        )
    return arg.value


def _get_bool_kwarg(node: ast.Call, name: str) -> Optional[bool]:
    arg = _get_kwarg(node, name)
    if arg is None:
        return None
    if not isinstance(arg, ast.Constant) or not isinstance(arg.value, bool):
        raise UnrecognizedInputError(f"{name} is not bool literal: {ast.dump(arg)}")
    return arg.value


def _parse_metavar(node: ast.expr) -> Sequence[str]:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return (node.value,)
    elif isinstance(node, ast.Tuple):
        values = []
        for elt in node.elts:
            if not isinstance(elt, ast.Constant) or not isinstance(elt.value, str):
                break
            values.append(elt.value)
        else:
            return values
    raise UnrecognizedInputError(f"unrecognized value for metavar: {ast.dump(node)}")


def _is_argparse_constant(node: Optional[ast.expr], name: str) -> bool:
    # Technically we should resolve "argparse" to make sure it's actually the
    # module with that name, but it's very unlikely to matter. We could also
    # try to handle "from argparse import ...", but I'd rather discourage that.
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "argparse"
        and node.attr == name
    )


def _format_text(lines: List[str], text: str, *, indent: str = "") -> None:
    lines.extend(multiline_wrap(text, 100, indent=indent))


# Capitalize the first letter of each word but leave the rest unchanged
# (unlike str.title(), which makes the rest lowercase).
def _capitalize(s: str) -> str:
    return re.sub(r"\b\w", lambda match: match.group().upper(), s)


class CommandFormatter:
    def __init__(self, namespace: Namespace):
        self._namespace = namespace
        self.command_namespaces = self._find_commands()

    def _call_name(
        self,
        modules: Sequence[BoundNode[Module]],
        classes: Sequence[BoundNode[Class]],
        node: ast.Call,
    ) -> Optional[str]:
        if not isinstance(node.func, ast.Name):
            return None

        resolved = self._namespace.resolve_name_in_scope(modules, classes, node.func.id)
        if not isinstance(resolved, ResolvedNode):
            return None

        return resolved.qualified_name()

    @staticmethod
    def _command_name(func_name: str, decorator: ast.Call, namespace: str) -> str:
        name = _get_string_kwarg(decorator, "name")
        if name is not None:
            return name

        prefix = "_crash_cmd_" if namespace == "crash" else "_cmd_"
        if not func_name.startswith(prefix):
            raise UnrecognizedInputError(f"invalid function name {func_name!r}")

        return func_name[len(prefix) :]

    def _get_command(
        self, func: ResolvedNode[Function]
    ) -> Optional[Tuple[str, Command]]:
        if len(func.node.signatures) != 1:
            return None

        for decorator in func.node.signatures[0].decorator_list:
            if isinstance(decorator, ast.Call):
                enabled = ""
                name = self._call_name(func.modules, func.classes, decorator)
                if (
                    name == "drgn.commands.command"
                    or name == "drgn.commands.custom_command"
                    or name == "drgn.commands.raw_command"
                ):
                    namespace = ""
                elif (
                    name == "drgn.commands.linux.linux_kernel_command"
                    or name == "drgn.commands.linux.linux_kernel_custom_command"
                    or name == "drgn.commands.linux.linux_kernel_raw_command"
                ):
                    namespace = ""
                    enabled = "linux"
                elif (
                    name == "drgn.commands.crash.crash_command"
                    or name == "drgn.commands.crash.crash_custom_command"
                    or name == "drgn.commands.crash.crash_raw_command"
                ):
                    namespace = "crash"
                else:
                    continue

                if _get_kwarg(decorator, "namespace"):
                    # Currently, we only use the default namespaces implied by
                    # their respective decorators. If this changes, we can add
                    # an option to map namespace variables to keys.
                    logger.warning("unknown command namespace", type="drgndoc")
                    return None

                command = Command(
                    func=func,
                    name=self._command_name(func.name, decorator, namespace),
                    decorator=decorator,
                    enabled=enabled,
                )
                return namespace, command
        return None

    def _find_commands(self) -> Mapping[str, Mapping[str, Command]]:
        command_namespaces: Dict[str, Dict[str, Command]] = {}

        def aux(resolved: ResolvedNode[Module]) -> None:
            for attr in resolved.attrs():
                if isinstance(attr.node, Module):
                    aux(attr)  # type: ignore[arg-type]
                elif isinstance(attr.node, Function):
                    found = self._get_command(attr)  # type: ignore[arg-type]
                    if found is not None:
                        namespace_name, command = found
                        namespace = command_namespaces.setdefault(namespace_name, {})
                        namespace[command.name] = command

        aux(self._namespace.resolve_global_name("drgn"))  # type: ignore[arg-type]
        return command_namespaces

    def _get_arguments(
        self, command: Command, args: Sequence[ast.expr]
    ) -> Iterable[Tuple[_ArgumentType, ast.Call]]:
        for arg in args:
            modules = command.func.modules
            classes = command.func.classes

            # This handles drgn_argument, which is a variable set to an
            # argument() call.
            if isinstance(arg, ast.Name):
                resolved = self._namespace.resolve_name_in_scope(
                    command.func.modules, command.func.classes, arg.id
                )
                if (
                    isinstance(resolved, ResolvedNode)
                    and isinstance(resolved.node, Variable)
                    and resolved.node.value is not None
                ):
                    modules = resolved.modules
                    classes = resolved.classes
                    arg = resolved.node.value

            if not isinstance(arg, ast.Call):
                _log_unrecognized_input(f"argument is not a call: {ast.dump(arg)}")
                continue

            name = self._call_name(modules, classes, arg)
            if name is None:
                _log_unrecognized_input(
                    f"argument call not recognized: {ast.dump(arg)}"
                )
                continue

            if name not in typing.get_args(_ArgumentType):
                _log_unrecognized_input(f"argument call not recognized: {name}")
                continue

            if name == "drgn.commands.argument" and _is_argparse_constant(
                _get_kwarg(arg, "help"), "SUPPRESS"
            ):
                # Skip arguments with help=argparse.SUPPRESS.
                continue

            yield typing.cast(_ArgumentType, name), arg

    def _group_arguments(
        self, command: Command, group: ast.Call
    ) -> Iterable[Tuple[_ArgumentType, ast.Call]]:
        return self._get_arguments(command, group.args)

    def _command_arguments(
        self, command: Command
    ) -> Iterable[Tuple[_ArgumentType, ast.Call]]:
        try:
            arguments = _get_kwarg(command.decorator, "arguments")
            if arguments is None:
                return
        except UnrecognizedInputError as e:
            _log_unrecognized_input(e)
            return

        if not isinstance(arguments, ast.Tuple):
            _log_unrecognized_input(
                f"arguments is not a tuple literal: {ast.dump(arguments)}"
            )
            return

        yield from self._get_arguments(command, arguments.elts)

    @staticmethod
    def _option_is_positional(node: ast.Call) -> bool:
        for arg in node.args:
            if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                raise UnrecognizedInputError(
                    f"option name is not string literal: {ast.dump(arg)}"
                )
            return not arg.value.startswith("-")
        raise UnrecognizedInputError("option has no names")

    @staticmethod
    def _option_string(
        node: ast.Call, *, usage: bool, in_mutually_exclusive_group: bool = False
    ) -> str:
        if usage:

            def format_option_name(s: str) -> str:
                s = s.replace("-", r"\-")
                return f"**{s}**"

            def format_arg_name(s: str) -> str:
                return f"*{s}*"

            def join(s: Sequence[str]) -> str:
                return s[0] if s else ""

        else:

            def format_option_name(s: str) -> str:
                return s

            def format_arg_name(s: str) -> str:
                return f"{{{s}}}"

            def join(s: Sequence[str]) -> str:
                return ", ".join(s)

        option_names = []
        for arg in node.args:
            if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                raise UnrecognizedInputError(
                    f"option name is not string literal: {ast.dump(arg)}"
                )
            option_names.append(arg.value)
        positional = not option_names[0].startswith("-")

        nargs_node = _get_kwarg(node, "nargs")
        if nargs_node is None:
            action = _get_string_kwarg(node, "action")
            if action is None:
                action = "store"

            if action in {"store", "append", "extend"}:
                nargs: Union[int, str] = 1
            elif action in {
                "store_const",
                "store_true",
                "store_false",
                "append_const",
                "count",
                "help",
                "version",
            }:
                nargs = 0
            else:
                raise UnrecognizedInputError(f"unrecognized action: {action!r}")
        elif isinstance(nargs_node, ast.Constant) and isinstance(
            nargs_node.value, (int, str)
        ):
            nargs = nargs_node.value
        elif _is_argparse_constant(nargs_node, "REMAINDER"):
            # For argparse.REMAINDER, argparse omits the argument name from the
            # usage string, but I don't like that. Format it the same as "*".
            nargs = "*"
        else:
            raise UnrecognizedInputError(
                f"unrecognized value for nargs: {ast.dump(nargs_node)}"
            )

        if nargs == 0:
            if positional:
                # For weird cases like add_argument("foo", action="store_const"),
                # argparse omits the argument from the usage string but includes it
                # in the help string, so we do the same.
                if usage:
                    return ""
            else:
                return join(
                    [format_option_name(option_name) for option_name in option_names]
                )

        metavar_node = _get_kwarg(node, "metavar")
        if metavar_node is None:
            dest_node = _get_kwarg(node, "dest")
            if dest_node is None:
                if positional:
                    arg_names: Sequence[str] = (option_names[0],)
                else:
                    for option_name in option_names:
                        if option_name.startswith("--"):
                            arg_name = option_name[2:]
                            break
                        else:
                            arg_name = option_name[1:]
                    arg_names = (arg_name.replace("-", "_").upper(),)
            elif isinstance(dest_node, ast.Constant) and isinstance(
                dest_node.value, str
            ):
                arg_names = (dest_node.value.upper(),)
            else:
                raise UnrecognizedInputError(
                    f"unrecognized value for dest: {ast.dump(dest_node)}"
                )
        else:
            arg_names = _parse_metavar(metavar_node)

        if positional and not usage:
            return arg_names[0]

        arg_strs = [format_arg_name(arg_name) for arg_name in arg_names]

        if positional and in_mutually_exclusive_group:
            # A positional argument in a mutually exclusive group must be
            # optional based on nargs, but inside of the mutually exclusive
            # group, we want to format it as if it were mandatory.
            if nargs == "?":
                nargs = 1
            elif nargs == "*":
                nargs = "+"
            else:
                raise UnrecognizedInputError(
                    f"unrecognized nargs for positional argument in mutually exclusive group: {nargs!r}"
                )

        # We don't check the length of the metavar tuple; argparse will check
        # that at runtime.
        if nargs == 1:
            arg_str = arg_strs[0]
        else:
            if isinstance(nargs, int):
                arg_str = " ".join([arg_strs[i % len(arg_strs)] for i in range(nargs)])
            elif nargs == "?":
                arg_str = f"[{arg_strs[0]}]"
            elif nargs == "*":
                arg_str = f"[{arg_strs[0]} ...]"
            elif nargs == "+":
                arg_str = f"{arg_strs[0]} [{arg_strs[1 % len(arg_strs)]} ...]"
            else:
                raise UnrecognizedInputError(f"unrecognized nargs: {nargs!r}")

        if positional:
            return arg_str
        else:
            return join(
                [
                    f"{format_option_name(option_name)} {arg_str}"
                    for option_name in option_names
                ]
            )

    def _command_usage(self, command: Command) -> str:
        usage = _get_string_or_none_kwarg(command.decorator, "usage")
        if usage is not None:
            return usage

        parts = [f"**{command.name}**"]
        # Positional arguments go at the end.
        parts_end: List[str] = []

        def append_argument_usage(
            type: _ArgumentType,
            node: ast.Call,
            in_mutually_exclusive_group: bool = False,
        ) -> None:
            if type == "drgn.commands.argument":
                try:
                    option_string = self._option_string(
                        node,
                        usage=True,
                        in_mutually_exclusive_group=in_mutually_exclusive_group,
                    )
                    if not option_string:
                        return
                except UnrecognizedInputError as e:
                    _log_unrecognized_input(e)
                    return

                positional = self._option_is_positional(node)
                # Unlike argparse, we keep positional arguments inside of
                # mutually exclusive groups.
                target = (
                    parts_end
                    if not in_mutually_exclusive_group and positional
                    else parts
                )

                brackets = (
                    not in_mutually_exclusive_group
                    and not positional
                    and not _get_bool_kwarg(node, "required")
                )

                if not in_mutually_exclusive_group:
                    target.append(" ")
                if brackets:
                    target.append("[")
                target.append(option_string)
                if brackets:
                    target.append("]")
            elif type == "drgn.commands.argument_group":
                for type, node in self._group_arguments(command, node):
                    append_argument_usage(type, node)
            elif type == "drgn.commands.mutually_exclusive_group":
                required = _get_bool_kwarg(node, "required")
                parts.append(" (" if required else " [")
                for i, (type, node) in enumerate(self._group_arguments(command, node)):
                    if i != 0:
                        parts.append(" | ")
                    append_argument_usage(type, node, in_mutually_exclusive_group=True)
                parts.append(")" if required else "]")
            else:
                assert_never(type)

        for type, node in self._command_arguments(command):
            append_argument_usage(type, node)

        parts.extend(parts_end)
        return "".join(parts)

    def _format_argument(self, lines: List[str], node: ast.Call) -> None:
        try:
            option_string = self._option_string(node, usage=False)
        except UnrecognizedInputError:
            # We already warned in _command_usage().
            return

        lines.append("")
        lines.append(f".. option:: {option_string}")

        try:
            help = _get_string_kwarg(node, "help")
        except UnrecognizedInputError as e:
            _log_unrecognized_input(e)
        else:
            if help is not None:
                lines.append("")
                _format_text(lines, help, indent="    ")

    def format(self, command: Command) -> List[str]:
        command_name = command.name.replace("*", r"\*")
        lines = [
            command_name,
            "=" * len(command_name),
        ]

        try:
            description = _get_string_kwarg(command.decorator, "description")
            if description is None:
                raise UnrecognizedInputError("no description")
        except UnrecognizedInputError as e:
            _log_unrecognized_input(e)
        else:
            lines.append("")
            lines.append(description)

        try:
            usage = self._command_usage(command)
        except UnrecognizedInputError as e:
            _log_unrecognized_input(e)
        else:
            lines.append("")
            lines.append("Synopsis")
            lines.append("--------")
            lines.append("")
            lines.append(usage)

        try:
            long_description = _get_string_or_none_kwarg(
                command.decorator, "long_description"
            )
        except UnrecognizedInputError as e:
            _log_unrecognized_input(e)
        else:
            if long_description is not None:
                lines.append("")
                lines.append("Description")
                lines.append("-----------")
                lines.append("")
                _format_text(lines, long_description)

        any_positional_arguments = False
        options = []
        groups = []

        # Positional arguments first.
        def visit_positional_argument(type: _ArgumentType, node: ast.Call) -> None:
            nonlocal any_positional_arguments
            try:
                if type == "drgn.commands.argument":
                    if self._option_is_positional(node):
                        if not any_positional_arguments:
                            lines.append("")
                            lines.append("Positional Arguments")
                            lines.append("--------------------")
                            any_positional_arguments = True
                        self._format_argument(lines, node)
                    else:
                        options.append(node)
                elif type == "drgn.commands.argument_group":
                    groups.append(node)
                elif type == "drgn.commands.mutually_exclusive_group":
                    for type, node in self._group_arguments(command, node):
                        visit_positional_argument(type, node)
                else:
                    assert_never(type)
            except UnrecognizedInputError as e:
                _log_unrecognized_input(e)

        for type, node in self._command_arguments(command):
            visit_positional_argument(type, node)

        # Then options not in a group.
        if options:
            lines.append("")
            lines.append("Options")
            lines.append("-------")

            for node in options:
                self._format_argument(lines, node)

        # Then groups.
        for group in groups:
            try:
                title = _get_string_kwarg(group, "title")
                if title is None:
                    raise UnrecognizedInputError("no title")
            except UnrecognizedInputError as e:
                _log_unrecognized_input(e)
            else:
                lines.append("")
                lines.append(_capitalize(title))
                lines.append("-" * len(title))

            try:
                group_description = _get_string_or_none_kwarg(group, "description")
            except UnrecognizedInputError as e:
                _log_unrecognized_input(e)
            else:
                if group_description:
                    lines.append("")
                    _format_text(lines, group_description)

            for type, node in self._group_arguments(command, group):
                if type == "drgn.commands.argument":
                    self._format_argument(lines, node)
                elif type == "drgn.commands.mutually_exclusive_group":
                    for type, node in self._group_arguments(command, node):
                        if type == "drgn.commands.argument":
                            self._format_argument(lines, node)
                        elif type == "drgn.commands.argument_group":
                            _log_unrecognized_input(
                                "argument_group cannot be child of mutually_exclusive_group"
                            )
                        elif type == "drgn.commands.mutually_exclusive_group":
                            _log_unrecognized_input(
                                "mutually_exclusive_group cannot be child of mutually_exclusive_group"
                            )
                        else:
                            assert_never(type)
                elif type == "drgn.commands.argument_group":
                    _log_unrecognized_input(
                        "argument_group cannot be child of argument_group"
                    )
                else:
                    assert_never(type)

        try:
            epilog = _get_string_kwarg(command.decorator, "epilog")
        except UnrecognizedInputError as e:
            _log_unrecognized_input(e)
        else:
            if epilog is not None:
                lines.append("")
                lines.append("Epilogue")
                lines.append("--------")
                lines.append("")
                _format_text(lines, epilog)

        return lines
