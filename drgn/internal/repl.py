# Copyright (c) 2024, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Compatibility shim between drgn and the pyrepl/code modules"""

import builtins
import os
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from drgn.cli import Command

__all__ = ("interact", "readline")

# Python 3.13 introduces a new REPL implemented by the "_pyrepl" internal
# module. It includes features such as colored output and multiline editing.
# Unfortunately, there is no public API exposing these abilities to users, even
# in the "code" module. We'd like to give the best experience possible, so we'll
# detect _pyrepl and try to use it where possible.
try:
    # Since this mucks with internals, add a knob that can be used to disable it
    # and use the traditional REPL.
    if os.environ.get("DRGN_USE_PYREPL") in ("0", "n", "N", "false", "False"):
        raise ModuleNotFoundError()

    # Unfortunately, the typeshed library behind mypy explicitly removed type
    # stubs for these modules. This makes sense as they are private APIs, but it
    # means we need to disable mypy checks.
    from _pyrepl import readline  # type: ignore
    from _pyrepl.console import (  # type: ignore
        InteractiveColoredConsole as _BaseConsole,
    )
    from _pyrepl.simple_interact import (  # type: ignore
        run_multiline_interactive_console,
    )

    # This _setup() function clobbers the readline completer, but it is
    # protected so it only runs once. Call it early so that our overridden
    # completer doesn't get clobbered.
    readline._setup({})

    def interact(
        local: Dict[str, Any], banner: str, commands: Dict[str, "Command"]
    ) -> None:
        console = _InteractiveConsoleWithCommand(commands, local)
        console.write(banner + "\n")
        run_multiline_interactive_console(console)

except (ModuleNotFoundError, ImportError):
    from code import InteractiveConsole as _BaseConsole
    import readline

    def interact(
        local: Dict[str, Any], banner: str, commands: Dict[str, "Command"]
    ) -> None:
        console = _InteractiveConsoleWithCommand(commands, local)
        console.interact(banner, exitmsg="")


class _InteractiveConsoleWithCommand(_BaseConsole):  # type: ignore
    def __init__(self, commands: Dict[str, "Command"], *args: Any, **kwargs: Any):
        self.__commands = commands
        super().__init__(*args, **kwargs)

    def runsource(
        self, source: str, filename: str = "<input>", symbol: str = "single"
    ) -> bool:
        if not source or source[0] != ".":
            return super().runsource(source, filename=filename, symbol=symbol)

        cmd_name = source.split(maxsplit=1)[0][1:]
        if cmd_name not in self.__commands:
            self.write(f"{cmd_name}: drgn command not found\n")
            return False
        cmd = self.__commands[cmd_name]
        prog = self.locals["prog"]
        try:
            setattr(builtins, "_", cmd(prog, source, self.locals))  # type: ignore
        except Exception:
            self.showtraceback()
        return False  # we never require the PS2 ("...") prompt
