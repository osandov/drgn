# Copyright (c) 2024, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Compatibility shim between drgn and the pyrepl/code modules"""

import os
import sys
from typing import Any, Dict

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
    from _pyrepl.console import InteractiveColoredConsole  # type: ignore
    from _pyrepl.simple_interact import (  # type: ignore
        run_multiline_interactive_console,
    )

    # This _setup() function clobbers the readline completer, but it is
    # protected so it only runs once. Call it early so that our overridden
    # completer doesn't get clobbered.
    readline._setup({})

    def interact(local: Dict[str, Any], banner: str) -> None:
        console = InteractiveColoredConsole(local)
        print(banner, file=sys.stderr)
        run_multiline_interactive_console(console)

except (ModuleNotFoundError, ImportError):
    import code
    import readline

    def interact(local: Dict[str, Any], banner: str) -> None:
        code.interact(banner=banner, exitmsg="", local=local)
