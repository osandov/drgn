#!/usr/bin/env python3
import contextlib
import os
from pathlib import Path
import tempfile

import drgn.commands._builtin  # noqa: F401
from tests.commands import CommandTestCase


@contextlib.contextmanager
def temporary_working_directory():
    old_working_directory = os.getcwd()
    with tempfile.TemporaryDirectory() as f:
        try:
            os.chdir(f)
            yield f
        finally:
            os.chdir(old_working_directory)


class RedirectedFile:
    def __init__(self, f):
        self.tempfile = f
        self.value = None


@contextlib.contextmanager
def redirect(stdout=False, stderr=False):
    # To redirect stdout for commands, we need a real file descriptor, not just
    # a StringIO
    with contextlib.ExitStack() as stack:
        f = stack.enter_context(tempfile.TemporaryFile("w+t"))
        if stdout:
            stack.enter_context(contextlib.redirect_stdout(f))
        if stderr:
            stack.enter_context(contextlib.redirect_stderr(f))
        redir = RedirectedFile(f)
        try:
            yield redir
        finally:
            f.seek(0)
            redir.value = f.read()


class TestPyCommand(CommandTestCase):

    def test_py_redirect(self):
        with temporary_working_directory() as temp_dir:
            path = Path(temp_dir) / "6"
            self.run_command("py var = 5; var > 6")
            self.assertEqual(path.read_text(), "5\n")

    def test_py_paren_avoid_redirect(self):
        self.run_command("py var = 5; (var > 6)")
        with redirect(stdout=True) as f:
            self.run_command("py var = 5; (var > 6)")
        self.assertEqual(f.value, "False\n")

    def test_py_pipe(self):
        with redirect(stdout=True) as f:
            self.run_command("py echo = 5; 2 | echo + 5")
        self.assertEqual(f.value, "+ 5\n")

    def test_py_avoid_pipe(self):
        with redirect(stdout=True) as f:
            self.run_command("py echo = 5; (2 | (echo + 5))")
        self.assertEqual(f.value, "10\n")

    def test_py_chooses_first_pipe(self):
        with redirect(stdout=True) as f:
            # If the first | is used to separate the Python from the pipeline
            # (the expected behavior), then we'll get the value 5 written into
            # the "echo" command, which will ignore that and write "+ 6" through
            # the cat process to stdout. If the second | is used to separate the
            # Python from the pipeline, then we'll get "15" written into the cat
            # process. If none of the | were interpreted as a pipeline operator,
            # then the statement would output 31.
            self.run_command("py echo = 5; cat = 16; 5 | echo + 6 | cat")
        self.assertEqual("+ 6\n", f.value)

    def test_py_traceback_on_syntax_error(self):
        with redirect(stderr=True) as f:
            self.run_command("py a +")
        # SyntaxError does not print the "Traceback" header. Rather than trying
        # to assert too much about the format of the traceback, just assert that
        # the incorrect code is shown, as it would be for a traceback.
        self.assertTrue("a +" in f.value)
        self.assertTrue("SyntaxError" in f.value)

    def test_py_traceback_on_exception(self):
        with redirect(stderr=True) as f:
            self.run_command("py raise Exception('text')")
        self.assertTrue(f.value.startswith("Traceback"))
        self.assertTrue("Exception" in f.value)
