# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Kconfig
-------

The ``drgn.helpers.linux.kconfig`` module provides helpers for reading the
Linux kernel build configuration.
"""

import gzip
import types
from typing import Mapping

from drgn import Program

__all__ = ("get_kconfig",)


def get_kconfig(prog: Program) -> Mapping[str, str]:
    """
    Get the kernel build configuration as a mapping from the option name to the
    value.

    >>> get_kconfig(prog)['CONFIG_SMP']
    'y'
    >>> get_kconfig(prog)['CONFIG_HZ']
    '300'

    This is only supported if the kernel was compiled with ``CONFIG_IKCONFIG``.
    Note that most Linux distributions do not enable this option.
    """
    try:
        return prog.cache["kconfig_map"]
    except KeyError:
        pass

    try:
        start = prog.symbol("kernel_config_data").address
        size = prog.symbol("kernel_config_data_end").address - start
    except LookupError:
        # Before Linux kernel commit 13610aa908dc ("kernel/configs: use .incbin
        # directive to embed config_data.gz") (in v5.1), the data is a variable
        # rather than two symbols.
        try:
            kernel_config_data = prog["kernel_config_data"]
        except KeyError:
            raise LookupError(
                "kernel configuration data not found; kernel must be compiled with CONFIG_IKCONFIG"
            )
        # The data is delimited by the magic strings "IKCFG_ST" and "IKCFG_ED"
        # plus a NUL byte.
        start = kernel_config_data.address_ + 8  # type: ignore[operator]
        size = len(kernel_config_data) - 17

    data = prog.read(start, size)
    kconfig = {}
    for line in gzip.decompress(data).decode().splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.partition("=")
        if value:
            kconfig[name] = value

    # Make result mapping 'immutable', so changes cannot propagate to the cache
    result = types.MappingProxyType(kconfig)
    prog.cache["kconfig_map"] = result
    return result
