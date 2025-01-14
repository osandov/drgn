# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import fnmatch
import importlib  # noqa: F401
import logging
import os
import runpy
import sys
from types import SimpleNamespace
from typing import List, Tuple

logger = logging.getLogger("drgn.plugins")

_plugins = None


def _load_plugins() -> List[Tuple[str, object]]:
    plugins: List[Tuple[str, object]] = []
    enabled_entry_points = {}

    env = os.getenv("DRGN_PLUGINS")
    if env:
        for item in env.split(","):
            if not item:
                # Ignore empty items for convenience.
                continue
            name, sep, value = item.partition("=")
            if sep:
                try:
                    if value.startswith("/") or value.startswith("."):
                        plugin: object = SimpleNamespace(**runpy.run_path(value))
                    else:
                        plugin = importlib.import_module(value)
                except Exception:
                    logger.warning("failed to load %r:", value, exc_info=True)
                else:
                    plugins.append((name, plugin))
                    logger.debug("loaded %r", item)
            else:
                enabled_entry_points[name] = False

    env = os.getenv("DRGN_DISABLE_PLUGINS")
    # If all plugins are disabled, avoid the entry point machinery entirely.
    if env != "*" or enabled_entry_points:
        group = "drgn.plugins"

        if sys.version_info >= (3, 10):
            import importlib.metadata  # novermin

            entry_points = importlib.metadata.entry_points(group=group)  # novermin
        elif sys.version_info >= (3, 8):
            import importlib.metadata  # novermin

            entry_points = importlib.metadata.entry_points()[group]  # novermin
        else:
            import pkg_resources

            entry_points = pkg_resources.iter_entry_points(group)

        disable_plugins = env.split(",") if env else []
        for entry_point in entry_points:
            if entry_point.name in enabled_entry_points:
                enabled_entry_points[entry_point.name] = True
            elif any(
                fnmatch.fnmatch(entry_point.name, disable)
                for disable in disable_plugins
            ):
                continue
            try:
                plugin = entry_point.load()
            except Exception:
                logger.warning("failed to load %r:", entry_point.value, exc_info=True)
            else:
                plugins.append((entry_point.name, plugin))
                logger.debug("loaded %r", entry_point.name)

        missing_entry_points = [
            key for key, value in enabled_entry_points.items() if not value
        ]
        if missing_entry_points:
            missing_entry_points.sort()
            logger.warning(
                "not found: %s",
                ", ".join([repr(name) for name in missing_entry_points]),
            )

    plugins.sort(
        key=lambda plugin: (plugin[0], getattr(plugin[1], "drgn_priority", 50))
    )
    return plugins


def call_plugins(hook_name: str, *args: object) -> None:
    global _plugins
    if _plugins is None:
        _plugins = _load_plugins()

    for name, plugin in _plugins:
        try:
            hook = getattr(plugin, hook_name)
        except AttributeError:
            continue

        try:
            hook(*args)
        except Exception:
            logger.warning("%r %s failed:", name, hook_name, exc_info=True)
