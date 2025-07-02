# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ast
import dataclasses
import inspect
import operator
import os.path
import re
import stat
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
    overload,
)

from drgndoc.visitor import NodeVisitor


class _PreTransformer(ast.NodeTransformer):
    # Replace string forward references with the parsed expression.
    @overload
    def _visit_annotation(self, node: ast.expr) -> ast.expr: ...

    @overload
    def _visit_annotation(self, node: None) -> None: ...

    def _visit_annotation(self, node: Optional[ast.expr]) -> Optional[ast.expr]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node = self.visit(ast.parse(node.value, "<string>", "eval").body)
        return node

    def visit_arg(self, node: ast.arg) -> ast.arg:
        node = cast(ast.arg, self.generic_visit(node))
        node.annotation = self._visit_annotation(node.annotation)
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node = cast(ast.FunctionDef, self.generic_visit(node))
        node.returns = self._visit_annotation(node.returns)
        return node

    def visit_AsyncFunctionDef(
        self, node: ast.AsyncFunctionDef
    ) -> ast.AsyncFunctionDef:
        node = cast(ast.AsyncFunctionDef, self.generic_visit(node))
        node.returns = self._visit_annotation(node.returns)
        return node

    def visit_AnnAssign(self, node: ast.AnnAssign) -> ast.AnnAssign:
        node = cast(ast.AnnAssign, self.generic_visit(node))
        node.annotation = self._visit_annotation(node.annotation)
        return node

    # Get rid of Index nodes, which are deprecated as of Python 3.9.
    def visit_Index(self, node: Any) -> Any:
        return self.visit(node.value)


@dataclasses.dataclass
class Module:
    path: Optional[str]
    docstring: Optional[str]
    attrs: Mapping[str, "Node"]

    def has_docstring(self) -> bool:
        return self.docstring is not None


@dataclasses.dataclass
class Class:
    bases: Sequence[ast.expr]
    docstring: Optional[str]
    attrs: Mapping[str, "NonModuleNode"]

    def has_docstring(self) -> bool:
        if self.docstring is not None:
            return True
        init = self.attrs.get("__init__")
        return isinstance(init, Function) and init.has_docstring()


@dataclasses.dataclass
class FunctionSignature:
    args: ast.arguments
    returns: Optional[ast.expr]
    decorator_list: Sequence[ast.expr]
    docstring: Optional[str]

    def has_decorator(self, name: str) -> bool:
        return any(
            isinstance(decorator, ast.Name) and decorator.id == name
            for decorator in self.decorator_list
        )


@dataclasses.dataclass
class Function:
    async_: bool
    signatures: Sequence[FunctionSignature]

    def has_docstring(self) -> bool:
        return any(signature.docstring is not None for signature in self.signatures)


@dataclasses.dataclass
class Variable:
    annotation: Optional[ast.expr]
    value: Optional[ast.expr]
    docstring: Optional[str]

    def has_docstring(self) -> bool:
        return self.docstring is not None


@dataclasses.dataclass
class Import:
    module: str
    aliased: bool

    def has_docstring(self) -> bool:
        return False


@dataclasses.dataclass
class ImportFrom:
    name: str
    module: Optional[str]
    level: int
    aliased: bool

    def has_docstring(self) -> bool:
        return False


Node = Union[Module, Class, Function, Variable, Import, ImportFrom]
NonModuleNode = Union[Class, Function, Variable, Import, ImportFrom]
DocumentedNode = Union[Module, Class, Function, Variable]


def _docstring_from_node(node: Optional[ast.AST]) -> Optional[str]:
    if not isinstance(node, ast.Expr):
        return None
    node = node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        text = node.value
    else:
        return None
    return inspect.cleandoc(text)


def _transform_function(node: Function) -> Function:
    signature = node.signatures[-1]

    if (
        signature.has_decorator("takes_program_or_default")
        and signature.docstring is not None
    ):
        match = re.search(
            r"^(\s*):(?:param|return|raises)", signature.docstring, flags=re.M
        )
        if match:
            prefix = match.group(1)
            pos = match.start()
        else:
            prefix = "\n\n"
            pos = len(signature.docstring)
        signature.docstring = "".join(
            (
                signature.docstring[:pos],
                prefix,
                ":param prog: Program, which :ref:`may be omitted to use the default program argument <default-program>`.",
                signature.docstring[pos:],
            )
        )

    if signature.has_decorator("takes_object_or_program_or_default"):
        del signature.args.args[0]
        signature.args.args[0].annotation = ast.Subscript(
            value=ast.Name(id="Union", ctx=ast.Load()),
            slice=ast.Tuple(
                elts=[
                    ast.Name(id="Object", ctx=ast.Load()),
                    ast.Name(id="Program", ctx=ast.Load()),
                ],
                ctx=ast.Load(),
            ),
            ctx=ast.Load(),
        )

    return node


class _ModuleVisitor(NodeVisitor):
    def visit(self, node: ast.AST) -> Tuple[Optional[str], Dict[str, NonModuleNode]]:
        self._attrs: Dict[str, NonModuleNode] = {}
        super().visit(node)
        docstring = self._docstring
        del self._docstring
        return docstring, self._attrs

    def visit_Module(
        self, node: ast.Module, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        self._docstring = ast.get_docstring(node)
        self.generic_visit(node)

    def visit_ClassDef(
        self, node: ast.ClassDef, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        attrs = self._attrs
        self._attrs = {}
        self.generic_visit(node)
        class_node = Class(node.bases, ast.get_docstring(node), self._attrs)
        self._attrs = attrs
        self._attrs[node.name] = class_node

    def _visit_function(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        parent: Optional[ast.AST],
        sibling: Optional[ast.AST],
    ) -> None:
        signature = FunctionSignature(
            node.args, node.returns, node.decorator_list, ast.get_docstring(node)
        )
        async_ = isinstance(node, ast.AsyncFunctionDef)
        func = self._attrs.get(node.name)
        # If we have a previous overload definition, we can add to it.
        # Otherwise, we replace it.
        if (
            func
            and isinstance(func, Function)
            and func.async_ == async_
            and func.signatures[-1].has_decorator("overload")
        ):
            signatures = list(func.signatures)
            signatures.append(signature)
        else:
            signatures = [signature]
        self._attrs[node.name] = _transform_function(Function(async_, signatures))
        # NB: we intentionally don't visit the function body.

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def _add_assign(
        self,
        name: str,
        annotation: Optional[ast.expr],
        value: Optional[ast.expr],
        docstring: Optional[str],
    ) -> None:
        try:
            var = self._attrs[name]
        except KeyError:
            pass
        else:
            # The name was previously defined. If it's a variable, add the
            # annotation, value, and/or docstring. If this is an annotation
            # without a value, don't do anything. Otherwise, replace the
            # previous definition.
            if isinstance(var, Variable):
                if annotation is None:
                    annotation = var.annotation
                if value is None:
                    value = var.value
                if docstring is None:
                    docstring = var.docstring
            elif value is None:
                return
        self._attrs[name] = Variable(annotation, value, docstring)

    def visit_Assign(
        self, node: ast.Assign, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        if len(node.targets) == 1:
            docstring = _docstring_from_node(sibling)
        else:
            docstring = None
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._add_assign(target.id, None, node.value, docstring)

    def visit_AnnAssign(
        self, node: ast.AnnAssign, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        if isinstance(node.target, ast.Name):
            self._add_assign(
                node.target.id,
                node.annotation,
                node.value,
                _docstring_from_node(sibling),
            )

    def visit_Import(
        self, node: ast.Import, parent: Optional[ast.AST], sibling: Optional[ast.AST]
    ) -> None:
        for alias in node.names:
            if alias.asname is None:
                # We don't distinguish between "import foo" and "import
                # foo.bar"; they both add "foo" to the current scope.
                name = module_name = alias.name.partition(".")[0]
            else:
                name = alias.asname
                module_name = alias.name
            self._attrs[name] = Import(module_name, alias.asname is not None)

    def visit_ImportFrom(
        self,
        node: ast.ImportFrom,
        parent: Optional[ast.AST],
        sibling: Optional[ast.AST],
    ) -> None:
        for alias in node.names:
            name = alias.name if alias.asname is None else alias.asname
            self._attrs[name] = ImportFrom(
                alias.name, node.module, node.level, alias.asname is not None
            )


def parse_source(
    source: str, filename: str
) -> Tuple[Optional[str], Dict[str, NonModuleNode]]:
    node = ast.parse(source, filename)
    return _ModuleVisitor().visit(_PreTransformer().visit(node))


def _default_handle_err(e: Exception) -> None:
    raise e


def parse_module(
    path: str, handle_err: Callable[[Exception], None] = _default_handle_err
) -> Optional[Tuple[Optional[str], Dict[str, NonModuleNode]]]:
    try:
        with open(path, "r") as f:
            source = f.read()
    except (OSError, UnicodeError) as e:
        handle_err(e)
        return None
    try:
        return parse_source(source, path)
    except SyntaxError as e:
        handle_err(e)
        return None


def parse_package(
    path: str, handle_err: Callable[[Exception], None] = _default_handle_err
) -> Optional[Module]:
    module_path: Optional[str] = None
    docstring: Optional[str] = None
    attrs: Dict[str, Node] = {}
    init_path = os.path.join(path, "__init__.py")
    if os.path.isfile(init_path):
        module_path = init_path
        result = parse_module(init_path, handle_err)
        if result is not None:
            docstring = result[0]
            attrs = cast(Dict[str, Node], result[1])

    try:
        entries = sorted(os.scandir(path), key=operator.attrgetter("name"))
    except OSError as e:
        handle_err(e)
    else:
        for entry in entries:
            try:
                is_dir = entry.is_dir()
                is_file = entry.is_file()
            except OSError as e:
                handle_err(e)
                continue
            if is_dir:
                subpackage = parse_package(entry.path, handle_err)
                if subpackage:
                    attrs[entry.name] = subpackage
            elif is_file and entry.name != "__init__.py":
                root, ext = os.path.splitext(entry.name)
                if ext == ".py" or ext == ".pyi":
                    result = parse_module(entry.path, handle_err)
                    if result:
                        attrs[root] = Module(entry.path, result[0], result[1])

    if module_path is None and docstring is None and not attrs:
        return None
    return Module(module_path, docstring, attrs)


def parse_paths(
    paths: Iterable[str], handle_err: Callable[[Exception], None] = _default_handle_err
) -> Mapping[str, Module]:
    modules = {}
    for path in paths:
        path = os.path.realpath(path)
        try:
            st = os.stat(path)
        except OSError as e:
            handle_err(e)
            continue
        if stat.S_ISDIR(st.st_mode):
            package = parse_package(path, handle_err)
            if package:
                modules[os.path.basename(path)] = package
            else:
                handle_err(Exception(f"{path}:Not a Python module or package"))
        else:
            result = parse_module(path, handle_err)
            if result:
                name = os.path.splitext(os.path.basename(path))[0]
                modules[name] = Module(path, result[0], result[1])
    return modules
