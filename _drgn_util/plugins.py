# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import fnmatch
from importlib import import_module
import logging
import os
import runpy
import sys
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Tuple

logger = logging.getLogger("drgn.plugins")

_plugins = None
_hooks: Dict[str, List[Tuple[str, Callable[..., Any]]]] = {}


def _load_plugins() -> List[Tuple[str, object]]:
    plugins = []
    # Mapping from plugin name requested with DRGN_PLUGINS to whether we found
    # an entry point with that name.
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
                    if "/" in value:
                        plugin: object = SimpleNamespace(**runpy.run_path(value))
                    else:
                        plugin = import_module(value)
                except Exception:
                    logger.warning("failed to load %r:", item, exc_info=True)
                else:
                    plugins.append((name, plugin))
                    logger.debug("loaded %r", item)
            else:
                enabled_entry_points[name] = False

    env = os.getenv("DRGN_DISABLE_PLUGINS")
    # If all plugins are disabled, avoid the entry point machinery entirely.
    if env != "*" or enabled_entry_points:
        disable_plugins = env.split(",") if env else []

        import importlib.metadata

        group = "drgn.plugins"
        if sys.version_info >= (3, 10):
            entry_points = importlib.metadata.entry_points(group=group)
        else:
            entry_points = importlib.metadata.entry_points().get(group, ())

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
                logger.warning(
                    "failed to load %r:",
                    f"{entry_point.name} = {entry_point.value}",
                    exc_info=True,
                )
            else:
                plugins.append((entry_point.name, plugin))
                logger.debug(
                    "loaded entry point %r",
                    f"{entry_point.name} = {entry_point.value}",
                )

        missing_entry_points = [
            key for key, value in enabled_entry_points.items() if not value
        ]
        if missing_entry_points:
            missing_entry_points.sort()
            logger.warning(
                "not found: %s",
                ", ".join([repr(name) for name in missing_entry_points]),
            )

    return plugins


def _load_hook(hook_name: str) -> List[Tuple[str, Callable[..., Any]]]:
    global _plugins
    if _plugins is None:
        _plugins = _load_plugins()

    hooks = []
    for name, plugin in _plugins:
        try:
            hook = getattr(plugin, hook_name)
        except AttributeError:
            continue
        hooks.append((name, hook))

    hooks.sort(key=lambda hook: (getattr(hook[1], "drgn_priority", 50), hook[0]))
    return hooks


def call_plugins(hook_name: str, *args: object) -> None:
    try:
        hooks = _hooks[hook_name]
    except KeyError:
        _hooks[hook_name] = hooks = _load_hook(hook_name)

    for name, hook in hooks:
        try:
            hook(*args)
        except Exception:
            logger.warning("%r %s failed:", name, hook_name, exc_info=True)
