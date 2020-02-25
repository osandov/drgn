# Copyright 2020 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

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


class _ConstantNodeTransformer(ast.NodeTransformer):
    def visit_Num(self, node: ast.Num) -> ast.Constant:
        return ast.copy_location(ast.Constant(node.n), node)

    def visit_Str(self, node: ast.Str) -> ast.Constant:
        return ast.copy_location(ast.Constant(node.s), node)

    def visit_Bytes(self, node: ast.Bytes) -> ast.Constant:
        return ast.copy_location(ast.Constant(node.s), node)

    def visit_Ellipsis(self, node: ast.Ellipsis) -> ast.Constant:
        return ast.copy_location(ast.Constant(...), node)

    def visit_NameConstant(self, node: ast.NameConstant) -> ast.Constant:
        return ast.copy_location(ast.Constant(node.value), node)


def transform_constant_nodes(node: ast.AST) -> ast.AST:
    """
    Since Python 3.8, ast.parse() and friends produce Constant nodes instead of
    the more specific constant classes. This replaces occurrences of the old
    nodes with Constant to simplify consumers.
    """
    if sys.version_info >= (3, 8):
        return node
    else:
        return _ConstantNodeTransformer().visit(node)
