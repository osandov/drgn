#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This script generates code for a "string switch", i.e., a switch statement
where the controlling expression is a string rather than an integer.

For example, the following input would generate code that calls handle_foo() if
name is "foo", handle_bar() if name is "bar", and handle_other() otherwise:

@strswitch (name)@
@case "foo"@
        handle_foo();
        break;
@case "bar"@
        handle_bar();
        break;
@default@
        handle_other();
        break;
@endswitch@

strswitch takes a null-terminated const char *string, like strcmp(). This
script also provides memswitch, which takes a const void *string and a
size_t length, analogously to memcmp():

@memswitch (name, name_len)@
@case "asdf"@
        return 1;
@case "jkl"@
        return 2;
@endswitch@

You must #include <string.h> before using strswitch or memswitch.

The generated code is more efficient than an if-else ladder of
strcmp()/memcmp() calls when there are many cases or the cases have common
prefixes. Note that for null-terminated strings, memswitch is usually faster
than strswitch if the length is already available, but strswitch is usually
faster than calling strlen() and using memswitch.

The generated code is compatible with a "normal" switch statement. Namely:

* Cases fall through to the next case.
* Break statements break out of the enclosing string switch.

The arguments to strswitch and memswitch may be arbitrary expressions.
The argument to the case directive is a string literal.
String switches may be nested.
"""

import argparse
import operator
import re
import sys
from typing import Any, Dict, List, NamedTuple, Optional, TextIO, Union

from codegen_utils import (
    CodeGenError,
    c_bytes_literal,
    c_char_ord_literal,
    c_string_literal,
    parse_c_string_literal,
)


class StrSwitchOptions(NamedTuple):
    # These defaults were determined empirically with GCC 11 and Clang 13 on
    # x86-64.

    # GCC and Clang seem to compile constant strcmp() and strncmp() calls to
    # actual function calls except for very short strings (1-3 bytes), but the
    # function call overhead is only worth it for longer strings.
    strcmp_threshold: int = 8
    strncmp_threshold: int = 8
    # GCC and Clang seem to inline all constant memcmp() calls to code that
    # compares multiple bytes at a time, so it's almost always worth it to use
    # memcmp().
    memcmp_threshold: int = 2


class InputLine(NamedTuple):
    line: str
    filename: str
    lineno: int


class OutputWriter:
    def __init__(self, file: TextIO, filename: str) -> None:
        self.file = file
        self.filename = filename
        self.filename_literal = c_string_literal(filename)
        self.lineno = 0
        self.last_filename: Optional[str] = None
        self.last_lineno: Optional[int] = None

    def _sync_line_directive(self) -> None:
        if self.last_filename is not None:
            self.lineno += 1
            self.file.write(f"#line {self.lineno + 1} {self.filename_literal}\n")
            self.last_filename = None
        self.last_lineno = None

    def write_line(self, line: str) -> None:
        self._sync_line_directive()
        self.file.write(line)
        self.file.write("\n")
        self.lineno += 1

    def _write_line_directive(self, filename: str, lineno: int) -> None:
        if filename != self.last_filename:
            self.file.write(f"#line {lineno} {c_string_literal(filename)}\n")
            self.lineno += 1
            self.last_filename = filename
        elif lineno - 1 != self.last_lineno:
            self.file.write(f"#line {lineno}\n")
            self.lineno += 1
        self.last_lineno = lineno

    def echo_line(self, line: InputLine) -> None:
        if line.filename == "-":
            self._sync_line_directive()
        else:
            self._write_line_directive(line.filename, line.lineno)
        self.file.write(line.line)
        self.file.write("\n")
        self.lineno += 1


# A body read from the input file comprises lines copied directly from the
# input file and possible nested string switches.
InputBody = List[Union[InputLine, "StrSwitch"]]


class StrSwitchCase:
    def __init__(self, index: int):
        self.index = index
        self.body: InputBody = []


class StrSwitch:
    def __init__(self, type: str, index: int, indent: str, args: InputLine) -> None:
        # Type of switch (strswitch or memswitch).
        self.type = type
        self._ident_prefix = f"{type}{index}_"
        # Indentation before the first @ of the switch directive.
        self.indent = indent
        # Argument to the switch directive.
        self.args = args

        # Body between the switch directive and the first case or default
        # directive.
        self.switch_body: InputBody = []
        # Mapping from case values to the case itself.
        self.cases: Dict[bytes, StrSwitchCase] = {}
        # Body of the default directive, or None if this switch does not have a
        # default directive.
        self.default_body: Optional[InputBody] = None
        # Index of the case after the default directive or len(self.cases) if
        # there is no case after the default directive.
        self.default_index = -1
        # The body that we're currently reading.
        self.current_body = self.switch_body

    def has_default(self) -> bool:
        return self.default_body is not None

    def ident(self, name: str) -> str:
        return self._ident_prefix + name


def handle_switch_directive(
    line: InputLine,
    directive: str,
    switches: List[StrSwitch],
    switch_counts: Dict[str, int],
) -> None:
    match = re.fullmatch(r"((\s*)@\s*" + directive + r"\s*\()(.*)\)\s*@\s*", line.line)
    if not match:
        raise CodeGenError(f"invalid {directive} directive", line.filename, line.lineno)

    index = switch_counts.setdefault(directive, 0)
    switch_counts[directive] += 1

    # We want to record that the switch arguments came from the input file, so
    # get rid of the directive, but replace it with whitespace so that the
    # arguments are in the same column as in the input file.
    args = InputLine(
        re.sub(r"\S", " ", match.group(1)) + match.group(3), line.filename, line.lineno
    )

    switches.append(StrSwitch(directive, index, match.group(2), args))


def handle_case_directive(line: InputLine, switches: List[StrSwitch]) -> None:
    match = re.fullmatch(r'\s*@\s*case\s*("(?:[^\"]|\\")*")\s*@\s*', line.line)
    error = False
    if match:
        try:
            case_value = parse_c_string_literal(match.group(1)).encode()
        except Exception:
            error = True
    else:
        error = True
    if error:
        raise CodeGenError("invalid case directive", line.filename, line.lineno)

    if not switches:
        raise CodeGenError("case outside of switch", line.filename, line.lineno)
    switch = switches[-1]

    if case_value in switch.cases:
        raise CodeGenError("duplicate case value", line.filename, line.lineno)
    if switch.type == "strswitch" and 0 in case_value:
        raise CodeGenError(
            "null byte in strswitch case value", line.filename, line.lineno
        )
    case = StrSwitchCase(len(switch.cases))
    switch.cases[case_value] = case
    switch.current_body = case.body


def handle_default_directive(line: InputLine, switches: List[StrSwitch]) -> None:
    match = re.fullmatch(r"\s*@\s*default\s*@\s*", line.line)
    if not match:
        raise CodeGenError("invalid default directive", line.filename, line.lineno)

    if not switches:
        raise CodeGenError("default outside of switch", line.filename, line.lineno)
    switch = switches[-1]

    if switch.has_default():
        raise CodeGenError(
            "multiple default directives in one switch", line.filename, line.lineno
        )
    switch.default_body = []
    switch.current_body = switch.default_body
    switch.default_index = len(switch.cases)


def char_eq(switch: StrSwitch, str_index: int, c: int) -> str:
    return f"{switch.ident('str')}[{str_index}] == {c_char_ord_literal(c)}"


def str_eq(
    options: StrSwitchOptions, switch: StrSwitch, str_index: int, s: bytes
) -> str:
    if switch.type == "memswitch" and len(s) >= options.memcmp_threshold:
        literal = c_bytes_literal(s)
        return f"memcmp(&{switch.ident('str')}[{str_index}], {literal}, sizeof({literal}) - 1) == 0"
    elif (
        switch.type == "strswitch" and s[-1] == 0 and len(s) >= options.strcmp_threshold
    ):
        literal = c_bytes_literal(s[:-1])
        return f"strcmp(&{switch.ident('str')}[{str_index}], {literal}) == 0"
    elif (
        switch.type == "strswitch"
        and s[-1] != 0
        and len(s) >= options.strncmp_threshold
    ):
        literal = c_bytes_literal(s)
        return f"strncmp(&{switch.ident('str')}[{str_index}], {literal}, sizeof({literal}) - 1) == 0"
    else:
        char_eqs = [char_eq(switch, i, c) for i, c in enumerate(s, str_index)]
        return " && ".join(char_eqs)


def output_switch_args(output: OutputWriter, switch: StrSwitch, indent: str) -> None:
    output.write_line(f"{indent}{switch.ident('args')}(")
    output.echo_line(switch.args)
    output.write_line(f"{indent})")


def output_body(
    output: OutputWriter, options: StrSwitchOptions, body: InputBody, indent: str
) -> None:
    for fragment in body:
        if isinstance(fragment, StrSwitch):
            output_switch(output, options, fragment, indent)
        else:
            output.echo_line(fragment)


def output_case_body(
    output: OutputWriter,
    options: StrSwitchOptions,
    switch: StrSwitch,
    case: StrSwitchCase,
    indent: str,
) -> None:
    if case.index > 0:
        output.write_line(f"{indent}{switch.ident('case')}{case.index}:")

    output_body(output, options, case.body, indent)

    # Emulate fallthrough.
    if case.index + 1 == switch.default_index:
        output.write_line(f"{indent}goto {switch.ident('default')};")
    elif case.index + 1 < len(switch.cases):
        output.write_line(f"{indent}goto {switch.ident('case')}{case.index + 1};")


def output_default(
    output: OutputWriter,
    options: StrSwitchOptions,
    switch: StrSwitch,
    body: bool,
    indent: str,
) -> None:
    assert switch.default_body is not None
    if body:
        if switch.default_index > 0:
            output.write_line(f"{indent}{switch.ident('default')}:")

        output_body(output, options, switch.default_body, indent)

        # Emulate fallthrough.
        if switch.default_index < len(switch.cases):
            output.write_line(
                f"{indent}goto {switch.ident('case')}{switch.default_index};"
            )
    else:
        output.write_line(f"{indent}goto {switch.ident('default')};")


# This should be Dict[int, TrieNode], but mypy doesn't support recursive types
# (see python/mypy#731).
TrieInternalNode = Dict[int, Any]
# Trie which maps case values to cases.
TrieNode = Union[StrSwitchCase, TrieInternalNode]


def output_trie(
    output: OutputWriter,
    options: StrSwitchOptions,
    switch: StrSwitch,
    node: TrieNode,
    str_index: int,
    indent: str,
) -> None:
    # Compress nodes with only one edge into their children.
    prefix = bytearray()
    while not isinstance(node, StrSwitchCase) and len(node) == 1:
        char, node = next(iter(node.items()))
        prefix.append(char)

    if prefix:
        output.write_line(
            f"{indent}if ({str_eq(options, switch, str_index, prefix)}) {{"
        )
        prefix_indent = "\t"
    else:
        prefix_indent = ""

    if isinstance(node, StrSwitchCase):
        output_case_body(output, options, switch, node, indent + prefix_indent)
    else:
        # We use an if-else ladder here rather than a switch statement so that
        # break statements break out of the enclosing string switch. GCC and
        # Clang generate very similar or identical code for if-else and switch.
        first = True
        for char, child in sorted(node.items(), key=operator.itemgetter(0)):
            else_str = "" if first else "} else "
            first = False
            output.write_line(
                f"{indent}{prefix_indent}{else_str}if ({char_eq(switch, str_index + len(prefix), char)}) {{"
            )
            output_trie(
                output,
                options,
                switch,
                child,
                str_index + len(prefix) + 1,
                indent + prefix_indent + "\t",
            )

        if switch.has_default():
            output.write_line(f"{indent}{prefix_indent}}} else {{")
            output_default(
                output,
                options,
                switch,
                switch.type == "strswitch" and str_index + len(prefix) == 0,
                indent + prefix_indent + "\t",
            )

        output.write_line(f"{indent}{prefix_indent}}}")

    if prefix:
        if switch.has_default():
            output.write_line(f"{indent}}} else {{")
            output_default(
                output,
                options,
                switch,
                switch.type == "strswitch" and str_index == 0,
                indent + "\t",
            )

        output.write_line(f"{indent}}}")


def output_strswitch(
    output: OutputWriter, options: StrSwitchOptions, switch: StrSwitch, indent: str
) -> None:
    # Define a local macro to parse the switch arguments into variables for us.
    # This accomplishes a couple of things:
    # 1. It allows us to accept arbitrary expressions for the switch arguments
    #    without having to parse them ourselves.
    # 2. It ensures that we only evaluate the arguments once.
    output.write_line(f"{indent}\t#define {switch.ident('args')}(str) \\")
    output.write_line(f"{indent}\t\tconst char *{switch.ident('str')} = (str);")
    output_switch_args(output, switch, indent + "\t")
    output.write_line(f"{indent}\t#undef {switch.ident('args')}")

    if switch.cases:
        # Convert the case dictionary into a trie. For strswitch, this includes
        # the null terminator.
        trie: TrieInternalNode = {}
        for key, value in switch.cases.items():
            node = trie
            for c in key:
                if c not in node:
                    node[c] = {}
                node = node[c]
            node[0] = value
        output_trie(output, options, switch, trie, 0, indent + "\t")
    else:
        # Suppress unused variable warnings.
        output.write_line(f"{indent}\t(void){switch.ident('str')};")
        if switch.has_default():
            output_default(output, options, switch, True, indent + "\t")


def output_memswitch_tries(
    output: OutputWriter,
    options: StrSwitchOptions,
    switch: StrSwitch,
    tries: TrieInternalNode,
    indent: str,
) -> None:
    first = True
    for n, trie in sorted(tries.items(), key=operator.itemgetter(0)):
        else_str = "" if first else "} else "
        first = False
        output.write_line(f"{indent}{else_str}if ({switch.ident('len')} == {n}) {{")
        output_trie(output, options, switch, trie, 0, indent + "\t")

    if switch.has_default():
        output.write_line(f"{indent}}} else {{")
        output_default(output, options, switch, True, indent + "\t")

    output.write_line(f"{indent}}}")


def output_memswitch(
    output: OutputWriter, options: StrSwitchOptions, switch: StrSwitch, indent: str
) -> None:
    output.write_line(f"{indent}\t#define {switch.ident('args')}(ptr, len) \\")
    # Implicitly convert ptr to const void * for consistency with memcmp(),
    # then convert it to const char *.
    output.write_line(f"{indent}\t\tconst void *{switch.ident('ptr')} = (ptr); \\")
    output.write_line(
        f"{indent}\t\tconst char *{switch.ident('str')} = {switch.ident('ptr')}; \\"
    )
    output.write_line(f"{indent}\t\tsize_t {switch.ident('len')} = (len);")
    output_switch_args(output, switch, indent + "\t")
    output.write_line(f"{indent}\t#undef {switch.ident('args')}")

    if switch.cases:
        # Convert the case dictionary into a trie. For memswitch, the first
        # edge is the length of the case value, and there is no null
        # terminator.
        tries: TrieInternalNode = {}
        for key, value in switch.cases.items():
            node = tries
            c = len(key)
            for i in range(len(key)):
                if c not in node:
                    node[c] = {}
                node = node[c]
                c = key[i]
            node[c] = value
        output_memswitch_tries(output, options, switch, tries, indent + "\t")
    else:
        # Suppress unused variable warnings.
        output.write_line(f"{indent}\t(void){switch.ident('str')};")
        output.write_line(f"{indent}\t(void){switch.ident('len')};")
        if switch.has_default():
            output_default(output, options, switch, True, indent + "\t")


def output_switch(
    output: OutputWriter, options: StrSwitchOptions, switch: StrSwitch, indent: str
) -> None:
    # This "no-op" switch serves a few purposes:
    # 1. It a makes a string switch statement syntactically equivalent to a normal
    #    switch statement.
    # 2. It makes break statements inside of a string switch work as expected.
    # 3. It gives us somewhere to put the body between the switch directive and
    #    the first case or default directive.
    output.write_line(f"{indent}switch (1) {{")
    output_body(output, options, switch.switch_body, indent)
    output.write_line(f"{indent}default: {{")

    if switch.type == "strswitch":
        output_strswitch(output, options, switch, indent)
    else:  # switch.type == "memswitch"
        output_memswitch(output, options, switch, indent)

    output.write_line(f"{indent}}}")
    output.write_line(f"{indent}}}")


def handle_endswitch_directive(
    line: InputLine,
    switches: List[StrSwitch],
    output: OutputWriter,
    options: StrSwitchOptions,
) -> None:
    match = re.fullmatch(r"\s*@\s*endswitch\s*@\s*", line.line)
    if not match:
        raise CodeGenError("invalid endswitch directive", line.line, line.lineno)
    if not switches:
        raise CodeGenError("unmatched endswitch", line.filename, line.lineno)

    switch = switches.pop()
    if switches:
        switches[-1].current_body.append(switch)
    else:
        output.write_line(
            f"{switch.indent}/* Generated by libdrgn/build-aux/gen_strswitch.py. */"
        )
        output_switch(output, options, switch, switch.indent)


def gen_strswitch(
    in_file: TextIO,
    in_filename: str,
    out_file: TextIO,
    out_filename: str,
    options: StrSwitchOptions,
) -> None:
    switches: List[StrSwitch] = []
    switch_counts: Dict[str, int] = {}
    output = OutputWriter(out_file, out_filename)
    for in_lineno, in_line in enumerate(in_file, 1):
        line = InputLine(in_line.rstrip("\n"), in_filename, in_lineno)
        match = re.match(
            r"\s*@\s*((?:str|mem)switch|case|default|endswitch)", line.line
        )
        if match:
            directive = match.group(1)
            if directive == "strswitch" or directive == "memswitch":
                handle_switch_directive(line, directive, switches, switch_counts)
            elif directive == "case":
                handle_case_directive(line, switches)
            elif directive == "default":
                handle_default_directive(line, switches)
            else:  # directive == "endswitch"
                handle_endswitch_directive(line, switches, output, options)
        elif switches:
            switches[-1].current_body.append(line)
        else:
            output.echo_line(line)

    if switches:
        raise CodeGenError(
            f"unclosed {switches[-1].type}",
            switches[-1].args.filename,
            switches[-1].args.lineno,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate code for string switch statements",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "input", metavar="FILE", help="input file, or - to read standard input"
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        default=argparse.SUPPRESS,
        help="output file, or - to write to standard output (default: input filename with .strswitch suffix removed, or standard output if input file is standard input)",
    )
    codegen_group = parser.add_argument_group("code generation options")
    codegen_group.add_argument(
        "--strcmp-threshold",
        metavar="N",
        type=int,
        default=StrSwitchOptions._field_defaults["strcmp_threshold"],
        help="minimum number of characters to compare using strcmp()",
    )
    codegen_group.add_argument(
        "--strncmp-threshold",
        metavar="N",
        type=int,
        default=StrSwitchOptions._field_defaults["strncmp_threshold"],
        help="minimum number of characters to compare using strncmp()",
    )
    codegen_group.add_argument(
        "--memcmp-threshold",
        metavar="N",
        type=int,
        default=StrSwitchOptions._field_defaults["memcmp_threshold"],
        help="minimum number of characters to compare using memcmp()",
    )
    args = parser.parse_args()

    options = StrSwitchOptions(
        strcmp_threshold=args.strcmp_threshold,
        strncmp_threshold=args.strncmp_threshold,
        memcmp_threshold=args.memcmp_threshold,
    )

    if not hasattr(args, "output"):
        if args.input == "-":
            args.output = "-"
        else:
            if not args.input.endswith(".strswitch"):
                sys.exit("input file name must end in .strswitch unless -o is given")
            args.output = args.input[: -len(".strswitch")]

    in_file = None
    out_file = None
    try:
        if args.input == "-":
            in_file = sys.stdin
        else:
            in_file = open(args.input, "r")
        if args.output == "-":
            out_file = sys.stdout
        else:
            out_file = open(args.output, "w")

        gen_strswitch(in_file, args.input, out_file, args.output, options)
    except CodeGenError as e:
        sys.exit(e)
    finally:
        if args.output != "-" and out_file:
            out_file.close()
        if args.input != "-" and in_file:
            in_file.close()


if __name__ == "__main__":
    main()
