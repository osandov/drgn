# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import sys
from typing import Any, Optional


class NodeVisitor:
    """
    Node visitor based on ast.NodeVisitor that also passes the parent node and
    (right) sibling node.
    """

    def visit(self, node: ast.AST) -> Any:
        return self._visit(node, None, None)

    def _visit(
        self, node: ast.AST, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> Any:
        method = "visit_" + node.__class__.__name__
        visitor = getattr(self, method, None)
        if visitor is None:
            self.generic_visit(node)
        else:
            return visitor(node, parent, sibling)

    def generic_visit(self, node: ast.AST) -> None:
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                prev = None
                for item in value:
                    if isinstance(item, ast.AST):
                        if prev:
                            self._visit(prev, node, item)
                        prev = item
                if prev:
                    self._visit(prev, node, None)
            elif isinstance(value, ast.AST):
                self._visit(value, node, None)
