# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import re
from typing import Any, List, Optional, Pattern, Sequence, Tuple, cast

from drgndoc.namespace import BoundNode, Namespace, ResolvedNode
from drgndoc.parse import (
    Class,
    DocumentedNode,
    Function,
    FunctionSignature,
    Module,
    Variable,
)
from drgndoc.visitor import NodeVisitor


def _is_name_constant(node: ast.Constant) -> bool:
    return node.value is None or node.value is True or node.value is False


class _FormatVisitor(NodeVisitor):
    def __init__(
        self,
        namespace: Namespace,
        substitutions: Sequence[Tuple[Pattern[str], Any]],
        modules: Sequence[BoundNode[Module]],
        classes: Sequence[BoundNode[Class]],
        context_module: Optional[str],
        context_class: Optional[str],
    ) -> None:
        self._namespace = namespace
        self._substitutions = substitutions
        self._modules = modules
        self._classes = classes
        self._context_module = context_module
        self._context_class = context_class
        self._parts: List[str] = []

    def visit(self, node: ast.AST, rst: bool = True) -> str:
        self._rst = rst
        super().visit(node)
        ret = "".join(self._parts)
        self._parts.clear()
        return ret

    def generic_visit(self, node: ast.AST) -> None:
        raise NotImplementedError(
            f"{node.__class__.__name__} formatting is not implemented"
        )

    @staticmethod
    def _check_ctx_is_load(node: Any) -> None:
        if not isinstance(node.ctx, ast.Load):
            raise NotImplementedError(
                f"{node.ctx.__class__.__name__} formatting is not implemented"
            )

    def visit_Constant(
        self, node: ast.Constant, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        if node.value is ...:
            self._parts.append("...")
        else:
            obj = self._rst and _is_name_constant(node)
            quote = self._rst and not isinstance(node.value, (int, float))
            if obj:
                self._parts.append(":py:obj:`")
            elif quote:
                self._parts.append("``")
            self._parts.append(repr(node.value))
            if obj:
                self._parts.append("`")
            elif quote:
                self._parts.append("``")

    def _append_resolved_name(self, name: str) -> None:
        if self._rst:
            self._parts.append(":py:obj:`")

        resolved = self._namespace.resolve_name_in_scope(
            self._modules, self._classes, name
        )
        if isinstance(resolved, ResolvedNode):
            target = resolved.qualified_name()
        else:
            target = resolved
        for pattern, repl in self._substitutions:
            target, num_subs = pattern.subn(repl, target)
            if num_subs:
                break

        title = target
        if title.startswith("typing."):
            title = title[len("typing.") :]
        elif self._context_module and title.startswith(self._context_module + "."):
            title = title[len(self._context_module) + 1 :]
            if self._context_class and title.startswith(self._context_class + "."):
                title = title[len(self._context_class) + 1 :]
        self._parts.append(title)

        if self._rst:
            if title != target:
                self._parts.append(" <")
                self._parts.append(target)
                self._parts.append(">")
            self._parts.append("`")

    def visit_Name(
        self, node: ast.Name, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        self._check_ctx_is_load(node)
        self._append_resolved_name(node.id)

    def visit_Attribute(
        self, node: ast.Attribute, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        self._check_ctx_is_load(node)
        name_stack = [node.attr]
        while True:
            value = node.value
            if isinstance(value, ast.Attribute):
                name_stack.append(node.attr)
                node = value
                continue
            elif isinstance(value, ast.Name):
                name_stack.append(value.id)
                name_stack.reverse()
                self._append_resolved_name(".".join(name_stack))
            elif isinstance(value, ast.Constant) and _is_name_constant(value):
                name_stack.append(repr(value.value))
                name_stack.reverse()
                self._append_resolved_name(".".join(name_stack))
            elif isinstance(value, ast.Constant) and not isinstance(
                value.value, (type(...), int, float)
            ):
                name_stack.append(repr(value.value))
                name_stack.reverse()
                if self._rst:
                    self._parts.append("``")
                self._parts.append(".".join(name_stack))
                if self._rst:
                    self._parts.append("``")
            else:
                self._visit(value, node, None)
                name_stack.append("")
                name_stack.reverse()
                if isinstance(value, ast.Constant) and isinstance(value.value, int):
                    # "1.foo()" is a syntax error without parentheses or an
                    # extra space.
                    self._parts.append(" ")
                elif self._rst:
                    # Make sure the "``" doesn't get squashed into a previous
                    # special character.
                    self._parts.append("\\ ")
                if self._rst:
                    self._parts.append("``")
                self._parts.append(".".join(name_stack))
                if self._rst:
                    self._parts.append("``")
            break

    def visit_Subscript(
        self, node: ast.Subscript, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        self._check_ctx_is_load(node)
        self._visit(node.value, node, None)
        if self._rst:
            self._parts.append("\\")
        self._parts.append("[")
        self._visit(node.slice, node, None)
        if self._rst:
            self._parts.append("\\")
        self._parts.append("]")

    def visit_Tuple(
        self, node: ast.Tuple, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        self._check_ctx_is_load(node)
        parens = (
            len(node.elts) == 0
            or not isinstance(parent, ast.Subscript)
            or node is not parent.slice
        )
        if parens:
            self._parts.append("(")
        for i, elt in enumerate(node.elts):
            if i > 0:
                self._parts.append(", ")
            self._visit(elt, node, node.elts[i + 1] if i < len(node.elts) - 1 else None)
        if len(node.elts) == 1:
            self._parts.append(",")
        if parens:
            self._parts.append(")")

    def visit_List(
        self, node: ast.List, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        self._check_ctx_is_load(node)
        if self._rst:
            self._parts.append("\\")
        self._parts.append("[")
        for i, elt in enumerate(node.elts):
            if i > 0:
                self._parts.append(", ")
            self._visit(elt, node, node.elts[i + 1] if i < len(node.elts) - 1 else None)
        if self._rst:
            self._parts.append("\\")
        self._parts.append("]")


class Formatter:
    def __init__(
        self,
        namespace: Namespace,
        substitutions: Sequence[Tuple[Pattern[str], Any]] = (),
    ) -> None:
        self._namespace = namespace
        self._substitutions = substitutions

    def _format_function_signature(
        self,
        node: FunctionSignature,
        modules: Sequence[BoundNode[Module]],
        classes: Sequence[BoundNode[Class]],
        context_module: Optional[str],
        context_class: Optional[str],
        rst: bool,
        want_rtype: bool,
    ) -> Tuple[str, List[str]]:
        visitor = _FormatVisitor(
            self._namespace,
            self._substitutions,
            modules,
            classes,
            context_module,
            context_class,
        )
        assert node.docstring is not None
        docstring_lines = node.docstring.splitlines()

        if rst:
            lines = []
            params_need_type = set()
            params_have_type = set()
            for line in docstring_lines:
                lines.append("    " + line)
                match = re.match(r":(param|type)\s+([a-zA-Z0-9_]+):", line)
                if match:
                    if match.group(1) == "param":
                        params_need_type.add(match.group(2))
                    else:
                        params_have_type.add(match.group(2))
                elif line.startswith(":rtype:"):
                    want_rtype = False
            params_need_type -= params_have_type
        else:
            lines = docstring_lines

        signature = ["("]
        need_comma = False
        need_blank_line = bool(lines)

        def visit_arg(
            arg: ast.arg, default: Optional[ast.expr] = None, prefix: str = ""
        ) -> None:
            nonlocal need_comma, need_blank_line
            if need_comma:
                signature.append(", ")
            if prefix:
                signature.append(prefix)
            signature.append(arg.arg)

            default_sep = "="
            if not rst and arg.annotation:
                signature.append(": ")
                signature.append(visitor.visit(arg.annotation, False))
                default_sep = " = "

            if default:
                signature.append(default_sep)
                signature.append(visitor.visit(default, False))
            need_comma = True

            if rst and arg.annotation and arg.arg in params_need_type:
                if need_blank_line:
                    lines.append("")
                    need_blank_line = False
                lines.append(f"    :type {arg.arg}: {visitor.visit(arg.annotation)}")

        posonlyargs = getattr(node.args, "posonlyargs", [])
        num_posargs = len(posonlyargs) + len(node.args.args)
        for i, arg in enumerate(posonlyargs + node.args.args):
            default: Optional[ast.expr]
            if i >= num_posargs - len(node.args.defaults):
                default = node.args.defaults[
                    i - (num_posargs - len(node.args.defaults))
                ]
            else:
                default = None
            if i == 0 and classes and not node.has_decorator("staticmethod"):
                # Skip self for methods and cls for class methods.
                continue
            visit_arg(arg, default)
            if i == len(posonlyargs) - 1:
                signature.append(", /")

        if node.args.vararg:
            visit_arg(node.args.vararg, prefix="*")

        if node.args.kwonlyargs:
            if not node.args.vararg:
                if need_comma:
                    signature.append(", ")
                signature.append("*")
                need_comma = True
            for i, arg in enumerate(node.args.kwonlyargs):
                visit_arg(arg, node.args.kw_defaults[i])

        if node.args.kwarg:
            visit_arg(node.args.kwarg, prefix="**")

        signature.append(")")

        if want_rtype and node.returns:
            if rst:
                if need_blank_line:
                    lines.append("")
                    need_blank_line = False
                lines.append("    :rtype: " + visitor.visit(node.returns))
            else:
                signature.append(" -> ")
                signature.append(visitor.visit(node.returns, False))

        return "".join(signature), lines

    def _format_class(
        self,
        resolved: ResolvedNode[Class],
        name: str,
        context_module: Optional[str] = None,
        context_class: Optional[str] = None,
        rst: bool = True,
    ) -> List[str]:
        node = resolved.node

        lines = []

        if rst:
            lines.append(f".. py:class:: {name}")

        if node.bases:
            visitor = _FormatVisitor(
                self._namespace,
                self._substitutions,
                resolved.modules,
                resolved.classes,
                context_module,
                context_class,
            )
            bases = [visitor.visit(base, rst) for base in node.bases]
            if lines:
                lines.append("")
            lines.append(("    " if rst else "") + "Bases: " + ", ".join(bases))

        if node.docstring:
            docstring_lines = node.docstring.splitlines()
            if lines:
                lines.append("")
            if rst:
                for line in docstring_lines:
                    lines.append("    " + line)
            else:
                lines.extend(docstring_lines)

        init_signatures: Sequence[FunctionSignature] = ()
        try:
            init = resolved.attr("__init__")
        except KeyError:
            pass
        else:
            if isinstance(init.node, Function):
                init_signatures = [
                    signature
                    for signature in init.node.signatures
                    if signature.docstring is not None
                ]

                init_context_class = resolved.name
                if context_class:
                    init_context_class = context_class + "." + init_context_class

        for i, signature_node in enumerate(init_signatures):
            if lines:
                lines.append("")

            signature, signature_lines = self._format_function_signature(
                signature_node,
                init.modules,
                init.classes,
                context_module,
                init_context_class,
                rst,
                False,
            )

            if rst:
                lines.append(f"    .. py:method:: {name}{signature}")
                lines.append("        :noindex:")
            elif signature:
                lines.append(f"{name}{signature}")
            lines.append("")
            if rst:
                for line in signature_lines:
                    lines.append("    " + line)
            else:
                lines.extend(signature_lines)
        return lines

    def _format_function(
        self,
        resolved: ResolvedNode[Function],
        name: str,
        context_module: Optional[str] = None,
        context_class: Optional[str] = None,
        rst: bool = True,
    ) -> List[str]:
        node = resolved.node

        lines = []
        for i, signature_node in enumerate(
            signature
            for signature in node.signatures
            if signature.docstring is not None
        ):
            if i > 0:
                lines.append("")
            signature, signature_lines = self._format_function_signature(
                signature_node,
                resolved.modules,
                resolved.classes,
                context_module,
                context_class,
                rst,
                True,
            )

            if rst:
                directive = "py:method" if resolved.classes else "py:function"
                lines.append(f".. {directive}:: {name}{signature}")
                if i > 0:
                    lines.append("    :noindex:")
                if node.async_:
                    lines.append("    :async:")
                if signature_node.has_decorator("classmethod") or name in (
                    "__init_subclass__",
                    "__class_getitem__",
                ):
                    lines.append("    :classmethod:")
                if signature_node.has_decorator("staticmethod"):
                    lines.append("    :staticmethod:")
            else:
                lines.append(f"{name}{signature}")
            if signature_lines:
                lines.append("")
                lines.extend(signature_lines)
        return lines

    def _format_variable(
        self,
        resolved: ResolvedNode[Variable],
        name: str,
        context_module: Optional[str],
        context_class: Optional[str],
        rst: bool,
    ) -> List[str]:
        node = resolved.node
        assert node.docstring is not None
        docstring_lines = node.docstring.splitlines()

        have_vartype = any(line.startswith(":vartype:") for line in docstring_lines)

        visitor = _FormatVisitor(
            self._namespace,
            self._substitutions,
            resolved.modules,
            resolved.classes,
            context_module,
            context_class,
        )
        if rst:
            directive = "py:attribute" if resolved.classes else "py:data"
            lines = [f".. {directive}:: {name}"]
            if docstring_lines:
                lines.append("")
            for line in docstring_lines:
                lines.append("    " + line)
            if node.annotation and not have_vartype:
                lines.append("")
                lines.append("    :vartype: " + visitor.visit(node.annotation))
            return lines
        else:
            if node.annotation and not have_vartype:
                if docstring_lines:
                    docstring_lines.insert(0, "")
                docstring_lines.insert(0, visitor.visit(node.annotation, False))
            return docstring_lines

    def format(
        self,
        resolved: ResolvedNode[DocumentedNode],
        name: Optional[str] = None,
        context_module: Optional[str] = None,
        context_class: Optional[str] = None,
        rst: bool = True,
    ) -> List[str]:
        node = resolved.node
        if not node.has_docstring():
            return []

        if name is None:
            name = resolved.name
        if context_module is None and resolved.modules:
            context_module = ".".join([module.name for module in resolved.modules])
        if context_class is None and resolved.classes:
            context_module = ".".join([class_.name for class_ in resolved.classes])

        if isinstance(node, Class):
            return self._format_class(
                cast(ResolvedNode[Class], resolved),
                name,
                context_module,
                context_class,
                rst,
            )
        elif isinstance(node, Function):
            return self._format_function(
                cast(ResolvedNode[Function], resolved),
                name,
                context_module,
                context_class,
                rst,
            )
        elif isinstance(node, Variable):
            return self._format_variable(
                cast(ResolvedNode[Variable], resolved),
                name,
                context_module,
                context_class,
                rst,
            )
        else:
            assert isinstance(node, Module)
            assert node.docstring is not None
            return node.docstring.splitlines()
