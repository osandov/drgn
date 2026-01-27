# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import logging
import sys

import drgn
import drgn.cli
from drgn.commands._builtin.crash import _cmd_crash


def _main() -> None:
    drgn.cli._set_log_handler()

    parser = argparse.ArgumentParser(description="Run drgn in crash compatibility mode")
    parser.add_argument(
        "vmlinux",
        nargs="?",
        help="path to kernel image (vmlinux) (default: find automatically)",
    )
    parser.add_argument(
        "core",
        nargs="?",
        help="path to kernel core dump (default: debug the running kernel)",
    )
    args = parser.parse_args()

    posargs = []
    if args.vmlinux is not None:
        posargs.append(args.vmlinux)
    if args.core is not None:
        posargs.append(args.core)

    prog = drgn.Program()

    found_core = False
    debug_info_paths = []
    for posarg in posargs:
        if drgn.cli._identify_script(posarg) == "core":
            if found_core:
                sys.exit("too many core dump arguments")
            else:
                prog.set_core_dump(posarg)
                found_core = True
        else:
            debug_info_paths.append(posarg)
    if not found_core:
        drgn.cli._set_kernel_with_sudo_fallback(prog)

    try:
        prog.load_debug_info(debug_info_paths, default=True)
    except drgn.MissingDebugInfoError as e:
        try:
            main_module = prog.main_module()
            critical = main_module.wants_debug_file() or main_module.wants_loaded_file()
        except LookupError:
            critical = True
        drgn.cli.logger.log(logging.CRITICAL if critical else logging.WARNING, "%s", e)

    sys.displayhook = drgn.cli._displayhook
    drgn.set_default_prog(prog)

    _cmd_crash(
        prog,
        "crash",
        "",
        parser=None,  # type: ignore[arg-type]  # The parser isn't needed.
        globals=drgn.cli.default_globals(prog),
    )


if __name__ == "__main__":
    _main()
