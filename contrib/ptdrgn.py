#!/usr/bin/python3
# Copyright (c) 2023, Oracle and/or its affiliates.
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Drgn CLI, but using ptpython rather than the standard code.interact()

NOTE: this is definitely a bit of a hack, using implementation details of Drgn
*and* ptpython. It may break at any time, but it is also quite useful, and this
makes it worth sharing.

Requires: "pip install ptpython" which brings in pygments and prompt_toolkit
"""
import functools
import importlib
import os
import shutil
import sys
from typing import Any, Callable, Dict, Optional, Set

from prompt_toolkit.completion import Completion, Completer
from prompt_toolkit.formatted_text import PygmentsTokens
from prompt_toolkit.formatted_text import fragment_list_to_text, to_formatted_text
from ptpython import embed
from ptpython.completer import DictionaryCompleter
from ptpython.repl import run_config
from pygments.lexers.c_cpp import CLexer

import drgn
import drgn.cli


class DummyForRepr:
    """
    A dummy class to pass back to _format_result_output() that pretends to have
    the given repr()
    """

    def __init__(self, s):
        self.s = s

    def __repr__(self):
        return self.s


class DummyForPtRepr:
    """A similar dummy class for the __pt_repr__() method."""

    def __init__(self, s):
        self.s = s

    def __pt_repr__(self):
        return self.s


def _maybe_c_format(s):
    """Given a string, try to use pygments to highlight it it as a C string."""
    try:
        tokens = CLexer().get_tokens_unprocessed(s)
        formatted = PygmentsTokens([(tokentype, value) for index, tokentype, value in tokens])
        to_format = DummyForPtRepr(formatted)
    except Exception as e:
        to_format = DummyForRepr(s)
    return to_format


@functools.lru_cache(maxsize=1)
def _object_fields() -> Set[str]:
    return set(dir(drgn.Object))


class ReorderDrgnObjectCompleter(Completer):
    """A completer which puts Object member fields above Object defaults"""

    def __init__(self, c: Completer):
        self.c = c

    def get_completions(self, document, complete_event):
        completions = list(self.c.get_completions(document, complete_event))
        if not completions:
            return completions
        text = completions[0].text
        member_fields = []
        # If the first completion is "absent_", it is *very likely* that we are
        # now looking at the completion of on Object.  Move the default Object
        # attributes to the end of the list so that we get the struct attributes
        if text == "absent_":
            fields = _object_fields()
            for i in reversed(range(len(completions))):
                text = completions[i].text
                if text not in fields:
                    member_fields.append(completions[i])
                    del completions[i]
            return list(reversed(member_fields)) + completions
        return completions


def configure(repl) -> None:
    """
    Muck around with the internals of PythonRepl so that we will special case the
    drgn data structures, similar to how drgn messes with sys.displayhook. We can
    do C syntax highlighting too, which is really nice.

    This also automatically runs the default config file:
    ~/.config/ptpython/config.py
    """
    _format_result_output_orig = repl._format_result_output

    def _format_result_output(result: object):
        if isinstance(result, drgn.Object):
            s = result.format_(columns=shutil.get_terminal_size((0, 0)).columns)
            to_format = _maybe_c_format(s)
        elif isinstance(result, (drgn.StackFrame, drgn.StackTrace)):
            to_format = DummyForRepr(str(result))
        elif isinstance(result, drgn.Type):
            to_format = _maybe_c_format(str(result))
        else:
            to_format = result
        return _format_result_output_orig(to_format)

    repl._format_result_output = _format_result_output
    run_config(repl)
    repl._completer = ReorderDrgnObjectCompleter(repl._completer)
    repl.completer = ReorderDrgnObjectCompleter(repl.completer)


def run_interactive(
    prog: drgn.Program,
    banner_func: Optional[Callable[[str], str]] = None,
    globals_func: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    quiet: bool = False,
) -> None:
    """
    Run drgn's :ref:`interactive-mode` via ptpython

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

    old_path = list(sys.path)
    # The ptpython history file format is different from a standard readline
    # history file since it must handle multi-line input, and it includes some
    # metadata as well. Use a separate history format, even though it would be
    # nice to share.
    histfile = os.path.expanduser("~/.drgn_history.ptpython")
    try:
        sys.path.insert(0, "")

        print(banner)
        embed(
            globals=init_globals,
            history_filename=histfile,
            title="drgn",
            configure=configure,
        )
    finally:
        sys.path[:] = old_path


if __name__ == "__main__":
    # Muck around with the internals of drgn: swap out run_interactive() with our
    # ptpython version, and then call main as if nothing happened.
    drgn.cli.run_interactive = run_interactive
    drgn.cli._main()
