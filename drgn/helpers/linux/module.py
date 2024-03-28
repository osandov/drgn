# Copyright (c) 2024 Oracle and/or its affiliates
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Modules
-------

The ``drgn.helpers.linux.module`` module contains helpers for working with
loaded kernel modules.
"""
from typing import Iterable

from drgn import Object, Program
from drgn.helpers.linux.list import list_for_each_entry

__all__ = ("for_each_module",)


def for_each_module(prog: Program) -> Iterable[Object]:
    """
    Returns all loaded kernel modules

    :param prog: Program being debugged
    :returns: Iterable of ``struct module *`` objects
    """
    return list_for_each_entry("struct module", prog["modules"].address_of_(), "list")
