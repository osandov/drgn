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
import os
import shutil
from typing import Any, Dict, Set

from prompt_toolkit.completion import Completer
from prompt_toolkit.formatted_text import PygmentsTokens
from ptpython import embed
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
            try:
                s = result.format_(columns=shutil.get_terminal_size((0, 0)).columns)
                to_format = _maybe_c_format(s)
            except drgn.FaultError:
                to_format = DummyForRepr(repr(result))
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


def interact(local: Dict[str, Any], banner: str):
    histfile = os.path.expanduser("~/.drgn_history.ptpython")
    print(banner)
    embed(globals=local, history_filename=histfile, title="drgn", configure=configure)


if __name__ == "__main__":
    # Muck around with the internals of drgn: swap out run_interactive() with our
    # ptpython version, and then call main as if nothing happened.
    drgn.cli.interact = interact
    drgn.cli._main()
