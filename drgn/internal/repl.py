# Copyright (c) 2024, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Compatibility shim between drgn and the pyrepl/code modules"""

import builtins
import contextlib
import os
import select
import traceback
from typing import TYPE_CHECKING, Any, Dict, Iterator, Optional

import _drgn
import drgn
from drgn.commands import _write_command_error, run_command

__all__ = ("interact", "poll_program", "print_above_prompt", "readline")

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

    @contextlib.contextmanager
    def poll_program(prog: drgn.Program) -> Iterator[None]:
        prog_fd = prog._poll_fd

        console = readline._get_reader().console
        orig_wait = console.wait

        try:
            console.pollob.register(prog_fd, select.POLLIN)

            def wait(self: Any, timeout: Optional[float] = None) -> bool:
                try:
                    if not self.event_queue.empty():
                        return True
                    ret = False
                    for fd, _ in self.pollob.poll(timeout):
                        if fd == prog_fd:
                            while prog.poll(0):
                                pass
                        else:
                            ret = True
                    return ret
                except Exception:
                    traceback.print_exc()
                    console.wait = orig_wait
                    try:
                        console.pollob.unregister(prog_fd)
                    except KeyError:
                        pass
                    return orig_wait(timeout)

            console.wait = wait.__get__(console)

            yield
        finally:
            console.wait = orig_wait
            try:
                console.pollob.unregister(prog_fd)
            except KeyError:
                pass

    def print_above_prompt(s: str) -> None:
        reader = readline._get_reader()
        console = reader.console

        if reader.finished:
            # Not in prompt right now.
            os.write(console.output_fd, s.encode(console.encoding, "replace") + b"\n")
            return

        _, cy = console.posxy  # cursor's row within the rendered prompt block

        out = bytearray(b"\r")  # Move cursor to column 0.
        if cy:
            out.extend(b"\x1b[%dA" % cy)  # Move cursor up to first row of prompt.
        out.extend(b"\x1b[0J")  # Erase from cursor to end of screen.
        out.extend(s.encode(console.encoding, "replace"))
        out.extend(b"\r\n")
        os.write(console.output_fd, out)

        console.posxy = (0, 0)
        if hasattr(console, "invalidate_render_state"):
            console.invalidate_render_state()  # Python >= 3.15.
        else:
            console.screen = []  # Python < 3.15.
        reader.refresh()

except (ModuleNotFoundError, ImportError):
    from code import InteractiveConsole as _BaseConsole
    import readline

    def interact(local: Dict[str, Any], banner: str) -> None:
        _InteractiveConsoleWithCommand(local).interact(banner, exitmsg="")

    @contextlib.contextmanager
    def poll_program(prog: drgn.Program) -> Iterator[None]:
        try:
            installed = _drgn._install_input_hook(prog)
            yield
        finally:
            if installed:
                _drgn._uninstall_input_hook(prog)

    def print_above_prompt(s: str) -> None:  # TODO
        print(s)


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
