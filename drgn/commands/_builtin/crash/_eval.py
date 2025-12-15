# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Crash commands for evaluating and printing values."""

import argparse
import dataclasses
import operator
import re
import sys
from typing import Any, Callable, Dict, Optional, Tuple

from drgn import Object, Program, Type
from drgn.commands import (
    CommandArgumentError,
    ParsedCommand,
    _repr_black,
    argument,
    drgn_argument,
    parse_shell_command,
)
from drgn.commands.crash import (
    _MEMBER_PATTERN,
    _TYPE_NAME_PATTERN,
    CrashDrgnCodeBuilder,
    _object_format_options,
    crash_command,
    crash_custom_command,
    parse_cpuspec,
)
from drgn.helpers.linux.percpu import per_cpu

_UNITS = {
    "k": 1024,
    "K": 1024,
    "m": 1024 * 1024,
    "M": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
    "G": 1024 * 1024 * 1024,
}


_UNARY_OPS: Dict[str, Callable[[Object], Object]] = {
    "-": operator.neg,
    "~": operator.inv,
}


_BINARY_OPS: Dict[str, Callable[[Object, Object], Object]] = {
    "+": operator.add,
    "-": operator.sub,
    "&": operator.and_,
    "|": operator.or_,
    "^": operator.xor,
    "*": operator.mul,
    "%": operator.mod,
    "/": operator.truediv,
    "<<": operator.lshift,
    ">>": operator.rshift,
}


_OPERAND_PATTERN = rf"""
(?P<unary{{n}}>
    (?:{'|'.join([re.escape(op) for op in _UNARY_OPS])}\s*)*
)
(?P<number{{n}}>
    (?:0[xX])?[0-9a-fA-F]+
)
(?:
    \s*
    (?P<unit{{n}}>[{''.join(_UNITS)}])
)?

"""


_EVAL_PATTERN = rf"""
    \s*
    (?P<parenthesis>\(\s*)?
    {_OPERAND_PATTERN.format(n=1)}
    (?:
        \s*
        (?P<operator>{'|'.join([re.escape(op) for op in _BINARY_OPS])})
        \s*
        {_OPERAND_PATTERN.format(n=2)}
    )?
    (?(parenthesis)\s*\))
    \s*
"""


def _eval_operand(type: Type, unary: str, number: str, unit: Optional[str]) -> Object:
    try:
        number_int = int(number, 10)
    except ValueError:
        number_int = int(number, 16)

    value = Object(type.prog, type, number_int)

    if unit is not None:
        value *= _UNITS[unit]

    for op in reversed(unary):
        if op.isspace():
            continue
        value = _UNARY_OPS[op](value)

    return value


def _append_operand(
    code: CrashDrgnCodeBuilder,
    type_name: str,
    unary: str,
    number: str,
    unit: Optional[str],
) -> None:
    for op in unary:
        if not op.isspace():
            code.append(op)

    if unit is not None:
        code.append("(")

    if re.match(r"[0-9]*[a-fA-F]", number):
        number = "0x" + number

    code.append(f'Object(prog, "{type_name}", {number})')

    if unit is not None:
        code.append(f" * {_UNITS[unit]})")


def _parse_eval(args: str) -> ParsedCommand[str]:
    # This command allows redirection and pipelines. To avoid ambiguity with
    # the <<, >>, and | operators, those operators must be parenthesized.
    # Split the arguments from any redirections/pipelines. We count nested
    # parentheses even though the expression syntax currently doesn't support
    # nesting.
    parens = 0
    for i, c in enumerate(args):
        if c == "(":
            parens += 1
        elif parens:
            if c == ")":
                parens -= 1
        elif c in "<>|":
            break
    else:
        i = len(args)

    parsed = parse_shell_command(args[i:])
    if parsed.args:
        # Don't allow extra arguments to be mixed in with redirections.
        raise SyntaxError("eval does not support arguments after redirections")
    return dataclasses.replace(parsed, args=args[:i])  # type: ignore[return-value]


@crash_custom_command(
    description="evaluate an expression",
    usage="**eval** [**-b**] [**-l**] [**--drgn**] (*expression*)",
    long_description="Evaluate an expression and print the result in various formats.",
    arguments=(
        argument(
            "-b",
            action="store_true",
            help="show which bits are set in the result, where 0 is the least significant bit",
        ),
        argument(
            "-l",
            action="store_true",
            help="use 64-bit values even on 32-bit architectures",
        ),
        argument(
            "expression",
            help=r"""
        expression to evaluate.

        Expressions are of the form ``value`` or ``value operator value``,
        where value is a number optionally prefixed by zero or more unary
        operators and optionally suffixed by a unit.

        Numbers may be decimal or hexadecimal. The "0x" prefix is optional for
        hexadecimal numbers.

        The following binary operators are supported:

        ``+  -  &  |  ^  *  %  /  <<  >>``

        The following unary operators are supported:

        ``- ~``

        Units may be "K" or "k" to multiply by 1024, "M" or "m" to multiply by
        1024*1024, and "G" or "g" to multiply by 1024*1024*1024.

        Expressions may be enclosed in parentheses. Parentheses are only
        required when using the ``|``, ``<<``, or ``>>`` operators.
        """,
        ),
        drgn_argument,
    ),
    parse=_parse_eval,
)
def _crash_cmd_eval(prog: Program, name: str, args: str, **kwargs: Any) -> None:
    # Handle (and remove) the --drgn flag after the expression.
    expr, n = re.subn(r"((^|\s+)--drgn)+\s*$", "", args)
    drgn_arg = n > 0

    # Handle (and remove) command line flags (-b, -l, and --drgn) before
    # the expression.
    show_bits_set = False
    long_long = False

    i = 0
    pattern = re.compile(
        r"""
        \s*
        (?:
            # -l and --drgn are unambiguous.
            (-[bl]*l[bl]*|--drgn)(?:\s|$)
            |
            # -b could be a flag or an expression (equivalent to -0xb).
            # Crash treats it as a flag unless it is the last argument, so
            # we do the same.
            (-b)\s+\S
        )
        """,
        flags=re.VERBOSE,
    )
    while match := pattern.match(expr, pos=i):
        flags = match.group(match.lastindex)  # type: ignore[arg-type]  # lastindex cannot be None
        if flags == "--drgn":
            drgn_arg = True
        else:
            show_bits_set |= "b" in flags
            long_long |= "l" in flags
        i = match.end(match.lastindex)  # type: ignore[arg-type]  # lastindex cannot be None
    expr = expr[i:]

    match = re.fullmatch(_EVAL_PATTERN, expr, flags=re.VERBOSE)
    if not match:
        raise CommandArgumentError("bad expression")

    type_name = "unsigned long long" if long_long else "unsigned long"
    op = match.group("operator")

    if drgn_arg:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import("drgn", "Object", "cast")
        code.add_from_import("drgn.helpers.common.format", "number_in_binary_units")
        if op is None:
            code.append("value = ")
            _append_operand(
                code,
                type_name,
                match.group("unary1"),
                match.group("number1"),
                match.group("unit1"),
            )
            code.append("\n")
        else:
            code.append("lhs = ")
            _append_operand(
                code,
                type_name,
                match.group("unary1"),
                match.group("number1"),
                match.group("unit1"),
            )
            code.append("\nrhs = ")
            _append_operand(
                code,
                type_name,
                match.group("unary2"),
                match.group("number2"),
                match.group("unit2"),
            )
            code.append(f"\nvalue = lhs {op} rhs\n")
        code.append(
            f"""
signed = cast("{type_name.replace("unsigned ", "")}", value)
in_units = number_in_binary_units(value)
in_hex = hex(value)
in_octal = oct(value)
in_binary = bin(value)
"""
        )
        if show_bits_set:
            code.add_from_import("drgn", "sizeof")
            code.append(
                """\
bits_set = [
i for i in range(sizeof(value) * 8) if value & (1 << i)
]
"""
            )
        code.print()
        return

    type = prog.type(type_name)
    bit_size = type.size * 8  # type: ignore[operator]  # type.size cannot be None.

    obj = _eval_operand(
        type, match.group("unary1"), match.group("number1"), match.group("unit1")
    )
    if op is not None:
        rhs = _eval_operand(
            type,
            match.group("unary2"),
            match.group("number2"),
            match.group("unit2"),
        )
        obj = _BINARY_OPS[op](obj, rhs)

    value = obj.value_()

    with_units = ""
    if value % (1024 * 1024 * 1024) == 0:
        with_units = f"  ({value // (1024 * 1024 * 1024)}GB)"
    elif value % (1024 * 1024) == 0:
        with_units = f"  ({value // (1024 * 1024)}MB)"
    elif value % 1024 == 0:
        with_units = f"  ({value // 1024}KB)"

    signed = ""
    if value & (1 << (bit_size - 1)):
        signed = f"  ({value - (1 << bit_size)})"

    bits_set = ""
    if show_bits_set:
        bits_set = "\n   bits set:" + "".join(
            [f" {i}" for i in range(bit_size - 1, -1, -1) if value & (1 << i)]
        )

    sys.stdout.write(
        f"""\
hexadecimal: {value:x}{with_units}
    decimal: {value}{signed}
      octal: {value:o}
     binary: {value:0{bit_size}b}{bits_set}
"""
    )


def _parse_name_and_optional_member(s: str) -> Tuple[str, str]:
    name, sep, member = s.partition(".")
    if not re.fullmatch(_TYPE_NAME_PATTERN, name) or not re.fullmatch(
        _MEMBER_PATTERN, member
    ):
        return s, ""
    return name, member


@crash_command(
    description="print the value of an object",
    arguments=(
        argument(
            "object",
            metavar="object[:cpuspec]",
            help="object to print. "
            "This may include member accesses and array subscripts. "
            "It does not support arbitrary expressions yet. "
            "For per-cpu variables, this may also contain a colon (':') "
            "followed by a specification of which CPUs to print, "
            "which may be a comma-separated string of CPU numbers or ranges "
            "(e.g., '0,3-4'), "
            "'a' or 'all' (meaning all possible CPUs), "
            "or an empty string (meaning the CPU of the current context)",
        ),
        argument(
            "-x",
            dest="integer_base",
            action="store_const",
            const=16,
            help="output integers in hexadecimal format regardless of the default",
        ),
        argument(
            "-d",
            dest="integer_base",
            action="store_const",
            const=10,
            help="output integers in decimal format regardless of the default",
        ),
        drgn_argument,
    ),
)
def _crash_cmd_p(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    expr, sep, cpuspec_str = args.object.partition(":")
    name, member = _parse_name_and_optional_member(expr)
    cpuspec = parse_cpuspec(cpuspec_str) if sep else None

    if args.drgn:
        if member:
            member = "." + member
        if cpuspec is None:
            print(f"object = prog[{_repr_black(name)}]{member}")
        else:
            code = CrashDrgnCodeBuilder(prog)
            code.append(f"pcpu_object = prog[{_repr_black(name)}]{member}\n")
            code.add_from_import("drgn.helpers.linux.percpu", "per_cpu")
            with code.begin_cpuspec_loop(cpuspec):
                code.append("object = per_cpu(pcpu_object, cpu)\n")
            code.print()
        return

    format_options = _object_format_options(prog, args.integer_base)
    obj = prog[name]
    if member:
        obj = obj.subobject_(member)
    if cpuspec is None:
        print(f"{expr} = {obj.format_(**format_options)}")
    else:
        for cpu in cpuspec.cpus(prog):
            print(
                f"per_cpu({expr}, {cpu}) = {per_cpu(obj, cpu).format_(**format_options)}"
            )
