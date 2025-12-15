# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ast
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest.mock

from drgn.commands import (
    CommandArgumentError,
    CommandExitStatusError,
    CommandNamespace,
    CommandNotFoundError,
    DrgnCodeBuilder,
    ParsedCommand,
    _repr_black,
    _sanitize_rst,
    argument,
    command,
    parse_shell_command,
    raw_command,
)
from tests import TestCase


class TestParseShellCommand(TestCase):
    def assert_parses_to(self, source, *, args, redirections=[], pipeline=None):
        self.assertEqual(
            parse_shell_command(source),
            ParsedCommand(args=args, redirections=redirections, pipeline=pipeline),
        )

    def test_one_arg(self):
        self.assert_parses_to("foo", args=["foo"])

    def test_multiple_args(self):
        self.assert_parses_to("foo bar   baz\t qux", args=["foo", "bar", "baz", "qux"])

    def test_escape_space(self):
        self.assert_parses_to(r"foo\ bar baz", args=["foo bar", "baz"])

    def test_escape_backslash(self):
        self.assert_parses_to(r"foo\\ bar", args=["foo\\", "bar"])

    def test_escape_double_quote(self):
        self.assert_parses_to(r"foo\"bar", args=['foo"bar'])

    def test_escape_single_quote(self):
        self.assert_parses_to(r"foo\'bar", args=["foo'bar"])

    def test_escape_other(self):
        self.assert_parses_to(r"foo\a", args=["fooa"])

    def test_double_quotes(self):
        self.assert_parses_to('"foo bar  baz\'qux"', args=["foo bar  baz'qux"])

    def test_double_quotes_empty(self):
        self.assert_parses_to('""', args=[""])

    def test_double_quotes_escape(self):
        # In double quotes, backslash only has special meaning before these
        # characters and newline.
        self.assert_parses_to(r' "\$\`\"\\" ', args=['$`"\\'])

    def test_double_quotes_escape_newline(self):
        self.assert_parses_to('"\\\n"', args=["\n"])

    def test_double_quotes_backslash_single_quote(self):
        self.assert_parses_to(r""" "\'" """, args=[r"\'"])

    def test_double_quotes_backslash_other(self):
        self.assert_parses_to(r'"\a"', args=[r"\a"])

    def test_single_quotes(self):
        self.assert_parses_to("' foo bar  \"baz'", args=[' foo bar  "baz'])

    def test_single_quotes_empty(self):
        self.assert_parses_to("''", args=[""])

    def test_single_quotes_backslash(self):
        # In single quotes, backslash does not have a special meaning.
        self.assert_parses_to(r"'\$'", args=[r"\$"])

    def test_single_quotes_backslash_single_quote(self):
        self.assert_parses_to(r"'\'", args=["\\"])

    def test_concatenate_escapes_and_quotes(self):
        self.assert_parses_to(r""" foo' bar'\ baz"q u x" """, args=["foo bar bazq u x"])

    def test_redirect_input(self):
        for source in (
            "foo < infile",
            "foo <infile",
            "foo< infile",
            "foo<infile",
            "<infile foo",
            "< infile foo",
        ):
            with self.subTest(source=source):
                self.assert_parses_to(
                    source, args=["foo"], redirections=[(0, "<", "infile")]
                )

    def test_redirect_input_fd(self):
        for source in (
            "foo 0< infile",
            "foo 0<infile",
            "0<infile foo",
            "0< infile foo",
        ):
            with self.subTest(source=source):
                self.assert_parses_to(
                    source, args=["foo"], redirections=[(0, "<", "infile")]
                )

    def test_redirect_output(self):
        for source in (
            "foo > outfile",
            "foo >outfile",
            "foo> outfile",
            "foo>outfile",
            ">outfile foo",
            "> outfile foo",
        ):
            with self.subTest(source=source):
                self.assert_parses_to(
                    source, args=["foo"], redirections=[(1, ">", "outfile")]
                )

    def test_redirect_output_fd(self):
        for source in (
            "foo 1> outfile",
            "foo 1>outfile",
            "1>outfile foo",
            "1> outfile foo",
        ):
            with self.subTest(source=source):
                self.assert_parses_to(
                    source, args=["foo"], redirections=[(1, ">", "outfile")]
                )

        for source in (
            "foo 2> outfile",
            "foo 2>outfile",
            "2>outfile foo",
            "2> outfile foo",
        ):
            with self.subTest(source=source):
                self.assert_parses_to(
                    source, args=["foo"], redirections=[(2, ">", "outfile")]
                )

    def test_append_output(self):
        for source in (
            "foo >> outfile",
            "foo >>outfile",
            "foo>> outfile",
            "foo>>outfile",
            ">>outfile foo",
            ">> outfile foo",
        ):
            with self.subTest(source=source):
                self.assert_parses_to(
                    source, args=["foo"], redirections=[(1, ">>", "outfile")]
                )

    def test_append_output_fd(self):
        for source in (
            "foo 1>> outfile",
            "foo 1>>outfile",
            "1>>outfile foo",
            "1>> outfile foo",
        ):
            with self.subTest(source=source):
                self.assert_parses_to(
                    source, args=["foo"], redirections=[(1, ">>", "outfile")]
                )

        for source in (
            "foo 2>> outfile",
            "foo 2>>outfile",
            "2>>outfile foo",
            "2>> outfile foo",
        ):
            with self.subTest(source=source):
                self.assert_parses_to(
                    source, args=["foo"], redirections=[(2, ">>", "outfile")]
                )

    def test_redirect_input_and_output(self):
        self.assert_parses_to(
            "foo < infile > outfile",
            args=["foo"],
            redirections=[(0, "<", "infile"), (1, ">", "outfile")],
        )

    def test_redirect_input_multiple(self):
        self.assert_parses_to(
            "< infile1 foo< infile2 <infile3",
            args=["foo"],
            redirections=[
                (0, "<", "infile1"),
                (0, "<", "infile2"),
                (0, "<", "infile3"),
            ],
        )

    def test_redirect_output_multiple(self):
        self.assert_parses_to(
            "> outfile1 foo>> outfile2 >outfile3",
            args=["foo"],
            redirections=[
                (1, ">", "outfile1"),
                (1, ">>", "outfile2"),
                (1, ">", "outfile3"),
            ],
        )

    def test_pipeline(self):
        self.assert_parses_to(
            "foo | grep 'bar baz' | sort",
            args=["foo"],
            pipeline="grep 'bar baz' | sort",
        )

    def test_pipeline_and_redirect(self):
        self.assert_parses_to(
            "foo < infile | grep 'bar baz' >outfile2",
            args=["foo"],
            redirections=[(0, "<", "infile")],
            pipeline="grep 'bar baz' >outfile2",
        )

    def test_only_redirect(self):
        self.assert_parses_to(
            "< infile >outfile",
            args=[],
            redirections=[(0, "<", "infile"), (1, ">", "outfile")],
        )

    def test_pipeline_empty(self):
        self.assertRaisesRegex(
            SyntaxError, "unexpected end of input", parse_shell_command, "foo | "
        )

    def test_pipe_after_redirect(self):
        for source in (
            "foo < |",
            "foo > |",
            "foo >> |",
        ):
            self.assertRaisesRegex(
                SyntaxError, r"unexpected '\|'", parse_shell_command, source
            )

    def test_nothing_before_pipe(self):
        self.assert_parses_to("| cat", args=[], pipeline="cat")

    def test_redirect_after_redirect(self):
        self.assertRaisesRegex(
            SyntaxError, "unexpected '<'", parse_shell_command, "foo < <"
        )
        self.assertRaisesRegex(
            SyntaxError, "unexpected '>'", parse_shell_command, "foo < >"
        )
        self.assertRaisesRegex(
            SyntaxError, "unexpected '>>'", parse_shell_command, "foo < >>"
        )

    def test_nothing_after_redirect(self):
        self.assertRaisesRegex(
            SyntaxError, "unexpected end of input", parse_shell_command, ">"
        )
        self.assertRaisesRegex(
            SyntaxError, "unexpected end of input", parse_shell_command, "foo >"
        )

    def test_comment(self):
        self.assert_parses_to("foo # bar < infile | baz", args=["foo"])

    def test_hash_in_word(self):
        self.assert_parses_to("foo#bar #baz", args=["foo#bar"])


_COMMANDS = CommandNamespace()


@command(
    description="write arguments to standard output",
    arguments=(argument("string", nargs="*"),),
    namespace=_COMMANDS,
)
def _cmd_echo(prog, name, args, **kwargs):
    print(*args.string)


@command(
    description="write arguments to standard error",
    arguments=(argument("string", nargs="*"),),
    namespace=_COMMANDS,
)
def _cmd_echoerr(prog, name, args, **kwargs):
    print(*args.string, file=sys.stderr)


@command(
    description="reverse standard input",
    namespace=_COMMANDS,
)
def _cmd_tac(prog, name, args, **kwargs):
    lines = sys.stdin.readlines()
    lines.reverse()
    sys.stdout.writelines(lines)


@raw_command(
    description="call ast.literal_eval()",
    usage="literal expr",
    long_description="",
    namespace=_COMMANDS,
)
def _cmd_literal(prog, name, args, **kwargs):
    return ast.literal_eval(args)


class TestRunCommand(TestCase):
    @staticmethod
    def run_command(source, **kwargs):
        return _COMMANDS.run(None, source, globals={}, **kwargs)

    def test_command_not_found(self):
        self.assertRaises(CommandNotFoundError, self.run_command, "asdf")

    def test_redirect_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            self.run_command(f"echo foo bar > {path}")
            self.assertEqual(path.read_text(), "foo bar\n")

    def test_clobber_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            path.write_text("x\n")
            self.run_command(f"echo foo bar > {path}")
            self.assertEqual(path.read_text(), "foo bar\n")

    def test_append_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            path.write_text("foo\n")
            self.run_command(f"echo bar >> {path}")
            self.assertEqual(path.read_text(), "foo\nbar\n")

    def test_redirect_output_multiple(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path1 = Path(temp_dir) / "file1"
            path2 = Path(temp_dir) / "file2"
            self.run_command(f"echo foo bar > {path1} > {path2}")
            # Both files are created, but the output is written to the last
            # one.
            self.assertEqual(path1.read_text(), "")
            self.assertEqual(path2.read_text(), "foo bar\n")

    def test_redirect_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            self.run_command(f"echoerr foo bar 2> {path}")
            self.assertEqual(path.read_text(), "foo bar\n")

    def test_clobber_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            path.write_text("x\n")
            self.run_command(f"echoerr foo bar 2> {path}")
            self.assertEqual(path.read_text(), "foo bar\n")

    def test_append_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            path.write_text("foo\n")
            self.run_command(f"echoerr bar 2>> {path}")
            self.assertEqual(path.read_text(), "foo\nbar\n")

    def test_redirect_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            path.write_text("foo\nbar\n")
            f = io.StringIO()
            with contextlib.redirect_stdout(f):
                self.run_command(f"tac < {path}")
            self.assertEqual(f.getvalue(), "bar\nfoo\n")

    def test_redirect_input_multiple(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path1 = Path(temp_dir) / "file1"
            path2 = Path(temp_dir) / "file2"
            path1.write_text("foo\n")
            path2.write_text("bar\n")
            f = io.StringIO()
            with contextlib.redirect_stdout(f):
                self.run_command(f"tac < {path1} < {path2}")
            # The last redirection wins.
            self.assertEqual(f.getvalue(), "bar\n")

    def test_pipe(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            self.run_command(f"echo hello | grep -o hell > {path}")
            self.assertEqual(path.read_text(), "hell\n")

    def test_redirect_input_and_pipe(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            in_path = Path(temp_dir) / "infile"
            out_path = Path(temp_dir) / "outfile"
            in_path.write_text("foo\nbar\n")
            self.run_command(f"tac < {in_path} | grep foo > {out_path}")
            self.assertEqual(out_path.read_text(), "foo\n")

    def test_redirect_output_and_pipe(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path1 = Path(temp_dir) / "file1"
            path2 = Path(temp_dir) / "file2"
            self.run_command(f"echo foo bar > {path1} | cat > {path2}")
            # Redirection wins over pipe.
            self.assertEqual(path1.read_text(), "foo bar\n")
            self.assertEqual(path2.read_text(), "")

    def test_redirect_input_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "file"
            self.assertRaises(OSError, self.run_command, f"tac < {path}")

    def test_redirect_output_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path1 = Path(temp_dir) / "file"
            path2 = Path(temp_dir) / "dir/file"
            path1.write_text("foo\n")
            self.assertRaises(OSError, self.run_command, f"echo < {path1} > {path2}")

    def test_empty(self):
        self.assertRaisesRegex(
            SyntaxError, "expected command name", self.run_command, ""
        )
        self.assertRaisesRegex(
            SyntaxError, "expected command name", self.run_command, " \t"
        )
        self.assertRaisesRegex(
            SyntaxError, "expected command name", self.run_command, "# comment"
        )

    def test_not_command_name(self):
        self.assertRaisesRegex(
            SyntaxError, "expected command name", self.run_command, "< /dev/null"
        )
        self.assertRaisesRegex(
            SyntaxError, "expected command name", self.run_command, "| cat"
        )

    def test_redirect_invalid_input_fd(self):
        self.assertRaises(NotImplementedError, self.run_command, "echo 1< /dev/null")

    def test_redirect_invalid_output_fd(self):
        self.assertRaises(NotImplementedError, self.run_command, "echo 0> /dev/null")
        self.assertRaises(NotImplementedError, self.run_command, "echo 0>> /dev/null")

    def test_pipe_failure(self):
        self.assertRaises(CommandExitStatusError, self.run_command, "echo foo | false")

    def test_onerror(self):
        onerror = unittest.mock.Mock()
        self.run_command("asdf", onerror=onerror)
        onerror.assert_called_once()

    def test_onerror_raises(self):
        def onerror(e):
            1 / 0

        self.assertRaises(ZeroDivisionError, self.run_command, "asdf", onerror=onerror)

    def test_raw(self):
        self.assertEqual(self.run_command("literal (1, 2)"), (1, 2))

    def test_argument_error(self):
        self.assertRaises(
            CommandArgumentError, self.run_command, "tac --garbage 2> /dev/null"
        )


class TestSanitizeRst(TestCase):
    def test_empty(self):
        self.assertEqual(_sanitize_rst(""), "")

    def test_none(self):
        self.assertEqual(_sanitize_rst(None), None)

    def test_bold(self):
        self.assertEqual(_sanitize_rst("**true**"), "true")

    def test_italic(self):
        self.assertEqual(_sanitize_rst("*CPU*"), "CPU")

    def test_escaped_asterisk(self):
        self.assertEqual(_sanitize_rst(r"\*"), "*")

    def test_bold_escaped_asterisk(self):
        self.assertEqual(_sanitize_rst(r"**\***"), "*")

    def test_escaped_backslash(self):
        self.assertEqual(_sanitize_rst("\\\\"), "\\")

    def test_bold_and_escaped_dash(self):
        self.assertEqual(_sanitize_rst(r"**\-\-drgn**"), "--drgn")


class TestReprBlack(TestCase):
    def test_simple(self):
        self.assertEqual(_repr_black("foo"), '"foo"')

    def test_single_quote(self):
        self.assertEqual(_repr_black("ne'er"), '"ne\'er"')

    def test_double_quote(self):
        self.assertEqual(_repr_black('l"oL'), "'l\"oL'")


class TestDrgnCodeBuilder(TestCase):
    def test_empty(self):
        self.assertEqual(DrgnCodeBuilder(None).get(), "")

    def test_no_imports(self):
        code = DrgnCodeBuilder(None)
        code.append("pass\n")
        self.assertEqual(code.get(), "pass\n")

    def test_sort_imports(self):
        code = DrgnCodeBuilder(None)
        code.add_import("sys")
        code.add_import("os")
        self.assertEqual(
            code.get(),
            """\
import os
import sys
""",
        )

    def test_deduplicate_imports(self):
        code = DrgnCodeBuilder(None)
        code.add_import("os")
        code.add_import("sys")
        code.add_import("os")
        self.assertEqual(
            code.get(),
            """\
import os
import sys
""",
        )

    def test_sort_from_imports(self):
        code = DrgnCodeBuilder(None)
        code.add_import("sys")
        code.add_import("os")
        code.add_from_import("sys", "stdout")
        self.assertEqual(
            code.get(),
            """\
import os
import sys
from sys import stdout
""",
        )

    def test_first_party_imports(self):
        code = DrgnCodeBuilder(None)
        code.add_import("os")
        code.add_import("sys")
        code.add_import("drgn")
        self.assertEqual(
            code.get(),
            """\
import os
import sys

import drgn
""",
        )

    def test_merge_from_imports(self):
        code = DrgnCodeBuilder(None)
        code.add_from_import("drgn", "Object", "Program")
        code.add_from_import("drgn", "Object")
        code.add_from_import("drgn", "Type")
        self.assertEqual(
            code.get(),
            """\
from drgn import Object, Program, Type
""",
        )

    def test_long_from_imports(self):
        code = DrgnCodeBuilder(None)
        code.add_from_import(
            "os",
            "abort",
            "access",
            "chdir",
            "chmod",
            "chown",
            "close",
            "closerange",
            "confstr",
            "copy_file_range",
        )
        self.assertEqual(
            code.get(),
            """\
from os import (
    abort,
    access,
    chdir,
    chmod,
    chown,
    close,
    closerange,
    confstr,
    copy_file_range,
)
""",
        )

    def test_imports_and_code(self):
        code = DrgnCodeBuilder(None)
        code.append("pass\n")
        code.add_import("os")
        self.assertEqual(
            code.get(),
            """\
import os


pass
""",
        )
