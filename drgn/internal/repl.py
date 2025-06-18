# Copyright (c) 2024, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Compatibility shim between drgn and the pyrepl/code modules"""

import builtins
import os
from typing import TYPE_CHECKING, Any, Dict

from drgn.commands import _write_command_error, run_command

__all__ = ("interact", "readline")

# Python 3.13 introduces a new REPL implemented by the "_pyrepl" internal
# module. It includes features such as colored output and multiline editing.
# Unfortunately, there is no public API exposing these abilities to users, even
# in the "code" module. We'd like to give the best experience possible, so we'll
# detect _pyrepl and try to use it where possible.
try:
    # The official Python interpreter honors this environment variable to
    # disable the new REPL. We do the same, which also gives users an escape
    # hatch if any of the internals we're messing with change.
    if os.environ.get("PYTHON_BASIC_REPL"):
        raise ModuleNotFoundError()

    # Unfortunately, the typeshed library behind mypy explicitly removed type
    # stubs for these modules. This makes sense as they are private APIs, but it
    # means we need to disable mypy checks.
    from _pyrepl import readline  # type: ignore
    from _pyrepl.simple_interact import (  # type: ignore
        run_multiline_interactive_console,
    )

    # Do this instead of type: ignore so that _BaseConsole gets type-checked as
    # code.InteractiveConsole instead of Any.
    if not TYPE_CHECKING:
        from _pyrepl.console import InteractiveColoredConsole as _BaseConsole

    # This _setup() function clobbers the readline completer, but it is
    # protected so it only runs once. Call it early so that our overridden
    # completer doesn't get clobbered.
    readline._setup({})

    def interact(local: Dict[str, Any], banner: str) -> None:
        console = _InteractiveConsoleWithCommand(local)
        console.write(banner + "\n")
        run_multiline_interactive_console(console)

except (ModuleNotFoundError, ImportError):
    from code import InteractiveConsole as _BaseConsole
    import readline

    def interact(local: Dict[str, Any], banner: str) -> None:
        _InteractiveConsoleWithCommand(local).interact(banner, exitmsg="")


class _InteractiveConsoleWithCommand(_BaseConsole):
    def _on_command_error(self, e: Exception) -> None:
        return _write_command_error(self, e)

    def runsource(
        self, source: str, filename: str = "<input>", symbol: str = "single"
    ) -> bool:
        if not source or source[0] != "%":
            return super().runsource(source, filename, symbol)

        ret = run_command(
            self.locals["prog"],
            source[1:],
            # The version of typeshed that we're stuck on says locals is a
            # Mapping[str, Any], but upstream corrected it to dict[str, Any].
            globals=self.locals,  # type: ignore[arg-type]
            onerror=self._on_command_error,
        )
        if ret is not None:
            builtins._ = ret  # type: ignore[attr-defined]
        # In theory, we could allow splitting pipelines over multiple lines
        # like sh, but run_multiline_interactive_console() doesn't support
        # console.runsource() returning True for more lines.
        return False
