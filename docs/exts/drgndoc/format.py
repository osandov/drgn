# Copyright 2020 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import ast
import re
from typing import Any, List, Optional, Pattern, Sequence, Tuple, cast

from drgndoc.namespace import BoundNode, Namespace, ResolvedNode
from drgndoc.parse import Class, DocumentedNode, Function, Module, Variable
from drgndoc.visitor import NodeVisitor


class _FormatVisitor(NodeVisitor):
    def __init__(
        self,
        namespace: Namespace,
        substitutions: Sequence[Tuple[Pattern[str], Any]],
        module: Optional[BoundNode[Module]],
        class_: Optional[BoundNode[Class]],
        context_module: Optional[str],
        context_class: Optional[str],
    ) -> None:
        self._namespace = namespace
        self._substitutions = substitutions
        self._module = module
        self._class = class_
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
            quote = self._rst and not isinstance(node.value, (int, float))
            if quote:
                self._parts.append("``")
            self._parts.append(repr(node.value))
            if quote:
                self._parts.append("``")

    def _append_resolved_name(self, name: str) -> None:
        if self._rst:
            self._parts.append(":py:obj:`")

        resolved = self._namespace.resolve_name_in_scope(
            self._module, self._class, name
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

    def visit_Index(
        self, node: ast.Index, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        self._visit(node.value, node, None)

    def visit_Tuple(
        self, node: ast.Tuple, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        self._check_ctx_is_load(node)
        parens = not isinstance(parent, ast.Index)
        if parens:
            self._parts.append("(")
        for i, elt in enumerate(node.elts):
            if i > 0:
                self._parts.append(", ")
            self._visit(
                elt, node, node.elts[i + 1] if i < len(node.elts) - 1 else None,
            )
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
            self._visit(
                elt, node, node.elts[i + 1] if i < len(node.elts) - 1 else None,
            )
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

    def _add_class_info(
        self,
        resolved: ResolvedNode[Class],
        context_module: Optional[str],
        context_class: Optional[str],
        rst: bool,
        lines: List[str],
    ) -> str:
        node = resolved.node
        if node.bases:
            visitor = _FormatVisitor(
                self._namespace,
                self._substitutions,
                resolved.module,
                resolved.class_,
                context_module,
                context_class,
            )
            bases = [visitor.visit(base, rst) for base in node.bases]
            lines[0:0] = ["Bases: " + ", ".join(bases), ""]

        extra_argument = ""
        try:
            init = resolved.attr("__init__")
        except KeyError:
            pass
        else:
            if isinstance(init.node, Function):
                init_context_class = resolved.name
                if context_class:
                    init_context_class = context_class + "." + init_context_class
                extra_argument = self._add_function_info(
                    cast(ResolvedNode[Function], init),
                    context_module,
                    init_context_class,
                    rst,
                    False,
                    lines,
                )
        return extra_argument

    def _add_function_info(
        self,
        resolved: ResolvedNode[Function],
        context_module: Optional[str],
        context_class: Optional[str],
        rst: bool,
        want_rtype: bool,
        lines: List[str],
    ) -> str:
        visitor = _FormatVisitor(
            self._namespace,
            self._substitutions,
            resolved.module,
            resolved.class_,
            context_module,
            context_class,
        )
        node = resolved.node

        if rst:
            if node.docstring is None:
                want_rtype = False

            params_need_type = set()
            params_have_type = set()
            for line in lines:
                match = re.match(r":(param|type)\s+([a-zA-Z0-9_]+):", line)
                if match:
                    if match.group(1) == "param":
                        params_need_type.add(match.group(2))
                    else:
                        params_have_type.add(match.group(2))
                elif line.startswith(":rtype:"):
                    want_rtype = False
            params_need_type -= params_have_type
            lines.append("")

        signature = ["("]
        need_comma = False

        def visit_arg(
            arg: ast.arg, default: Optional[ast.expr] = None, prefix: str = ""
        ) -> None:
            nonlocal need_comma
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
                lines.append(f":type {arg.arg}: {visitor.visit(arg.annotation)}")

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
            if i == 0 and resolved.class_ and not node.have_decorator("staticmethod"):
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
                lines.append(":rtype: " + visitor.visit(node.returns))
            else:
                signature.append(" -> ")
                signature.append(visitor.visit(node.returns, False))

        return "".join(signature)

    def _add_variable_info(
        self,
        resolved: ResolvedNode[Variable],
        context_module: Optional[str],
        context_class: Optional[str],
        rst: bool,
        lines: List[str],
    ) -> None:
        annotation = resolved.node.annotation
        if not annotation:
            return
        for line in lines:
            if line.startswith(":vartype:"):
                return

        visitor = _FormatVisitor(
            self._namespace,
            self._substitutions,
            resolved.module,
            resolved.class_,
            context_module,
            context_class,
        )
        if rst:
            lines.append("")
            lines.append(":vartype: " + visitor.visit(annotation))
        else:
            lines[0:0] = [visitor.visit(annotation, False), ""]

    def format(
        self,
        resolved: ResolvedNode[DocumentedNode],
        context_module: Optional[str] = None,
        context_class: Optional[str] = None,
        rst: bool = True,
    ) -> Tuple[str, List[str]]:
        if context_module is None and resolved.module:
            context_module = resolved.module.name
        if context_class is None and resolved.class_:
            context_class = resolved.class_.name

        node = resolved.node
        lines = node.docstring.splitlines() if node.docstring else []

        signature = ""
        if isinstance(node, Class):
            signature = self._add_class_info(
                cast(ResolvedNode[Class], resolved),
                context_module,
                context_class,
                rst,
                lines,
            )
        elif isinstance(node, Function):
            signature = self._add_function_info(
                cast(ResolvedNode[Function], resolved),
                context_module,
                context_class,
                rst,
                True,
                lines,
            )
        elif isinstance(node, Variable):
            self._add_variable_info(
                cast(ResolvedNode[Variable], resolved),
                context_module,
                context_class,
                rst,
                lines,
            )
        return signature, lines
