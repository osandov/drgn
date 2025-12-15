# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Functions for defining Linux kernel-specific commands."""

from typing import Any, Dict

from _drgn_util.typingutils import copy_func_signature
from drgn import Program, ProgramFlags
from drgn.commands import command, custom_command, raw_command


def _program_is_linux_kernel(prog: Program) -> bool:
    return bool(prog.flags & ProgramFlags.IS_LINUX_KERNEL)


def _set_enabled_if_linux_kernel(kwargs: Dict[str, Any]) -> None:
    if "enabled" in kwargs:
        old_enabled = kwargs["enabled"]
        kwargs["enabled"] = lambda prog: _program_is_linux_kernel(prog) and old_enabled(
            prog
        )
    else:
        kwargs["enabled"] = _program_is_linux_kernel


@copy_func_signature(command)
def linux_kernel_command(*args: Any, **kwargs: Any) -> Any:
    """
    Like :func:`~drgn.commands.command()`, but only enables the command when
    debugging the Linux kernel.

    If *enabled* is given, it is also checked in addition to the Linux kernel
    check.
    """
    _set_enabled_if_linux_kernel(kwargs)
    return command(*args, **kwargs)


@copy_func_signature(custom_command)
def linux_kernel_custom_command(*args: Any, **kwargs: Any) -> Any:
    """
    Like :func:`linux_kernel_command()` but for
    :func:`~drgn.commands.custom_command()`.
    """
    _set_enabled_if_linux_kernel(kwargs)
    return custom_command(*args, **kwargs)


@copy_func_signature(raw_command)
def linux_kernel_raw_command(*args: Any, **kwargs: Any) -> Any:
    """
    Like :func:`linux_kernel_command()` but for
    :func:`~drgn.commands.raw_command()`.
    """
    _set_enabled_if_linux_kernel(kwargs)
    return raw_command(*args, **kwargs)
