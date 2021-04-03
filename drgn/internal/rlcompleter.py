# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Improved readline completer"""

import builtins
import keyword
import re
import readline
from typing import Any, Dict, List, Optional

_EXPR_RE = re.compile(
    r"""
(
    (?:                              # Expression allowing only .member and [key]
        (?:^|\.)                     # Either beginning of string or .member
        \w+                          # Identifier
        (?:                          # [key], zero or more times
            \[
                (?:
                    \d+|             # Integer key
                    "(?:\\"|[^"])*"| # Double-quoted string key
                    '(?:\\'|[^'])*'  # Single-quoted string key
                )
            \]
        )*
    )+
)
\.(\w*)                              # Attribute to complete
""",
    re.VERBOSE,
)


class Completer:
    """
    This is a readline completer based on rlcompleter.Completer from the
    standard library. It allows expressions containing [key], where key is an
    integer or string.
    """

    def __init__(self, namespace: Dict[str, Any]) -> None:
        self._namespace = namespace
        # _EXPR_RE can match these characters, so don't treat them as
        # delimiters.
        delims = re.sub("[]['\"\\\\]", "", readline.get_completer_delims())
        readline.set_completer_delims(delims)

    def complete(self, text: str, state: int) -> Optional[str]:
        if not text.strip():
            if state == 0:
                readline.insert_text("\t")
                readline.redisplay()
                return ""
            else:
                return None

        if state == 0:
            if "." in text:
                self._matches = self._expr_matches(text)
            else:
                self._matches = self._global_matches(text)

        if 0 <= state < len(self._matches):
            return self._matches[state]
        else:
            return None

    def _expr_matches(self, text: str) -> List[str]:
        m = _EXPR_RE.fullmatch(text)
        if not m:
            return []

        expr, attr = m.group(1, 2)
        try:
            obj = eval(expr, self._namespace)
        except Exception:
            return []

        noprefix: Optional[str]
        if attr == "":
            noprefix = "_"
        elif attr == "_":
            noprefix = "__"
        else:
            noprefix = None

        matches = set()
        for word in dir(obj):
            if word.startswith(attr) and not (noprefix and word.startswith(noprefix)):
                match = expr + "." + word
                try:
                    value = getattr(obj, word)
                except Exception:
                    pass
                else:
                    if callable(value):
                        match += "("
                matches.add(match)
        return sorted(matches)

    def _global_matches(self, text: str) -> List[str]:
        matches = set()
        for word in keyword.kwlist:
            if word.startswith(text):
                if word in {"finally", "try"}:
                    word += ":"
                elif word not in {
                    "False",
                    "None",
                    "True",
                    "break",
                    "continue",
                    "pass",
                    "else",
                }:
                    word += " "
                matches.add(word)
        for nspace in [self._namespace, builtins.__dict__]:
            for word, value in nspace.items():
                if word.startswith(text):
                    if callable(value):
                        word += "("
                    matches.add(word)
        return sorted(matches)
