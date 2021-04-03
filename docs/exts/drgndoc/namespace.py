# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import itertools
from typing import Generic, Iterator, List, Mapping, Optional, Sequence, TypeVar, Union

from drgndoc.parse import (
    Class,
    DocumentedNode,
    Function,
    Import,
    ImportFrom,
    Module,
    Node,
    Variable,
)
from drgndoc.util import dot_join

NodeT_co = TypeVar("NodeT_co", bound=Node, covariant=True)


class BoundNode(Generic[NodeT_co]):
    def __init__(self, name: str, node: NodeT_co) -> None:
        self.name = name
        self.node = node


class ResolvedNode(Generic[NodeT_co]):
    def __init__(
        self,
        modules: Sequence[BoundNode[Module]],
        classes: Sequence[BoundNode[Class]],
        name: str,
        node: NodeT_co,
    ) -> None:
        self.modules = modules
        self.classes = classes
        self.name = name
        self.node = node

    def qualified_name(self) -> str:
        return ".".join(
            itertools.chain(
                (module.name for module in self.modules),
                (class_.name for class_ in self.classes),
                (self.name,),
            )
        )

    def attrs(self) -> Iterator["ResolvedNode[Node]"]:
        if isinstance(self.node, Module):
            modules = list(self.modules)
            modules.append(BoundNode(self.name, self.node))
            for attr, node in self.node.attrs.items():
                yield ResolvedNode(modules, self.classes, attr, node)
        elif isinstance(self.node, Class):
            classes = list(self.classes)
            classes.append(BoundNode(self.name, self.node))
            for attr, node in self.node.attrs.items():
                yield ResolvedNode(self.modules, classes, attr, node)

    def attr(self, attr: str) -> "ResolvedNode[Node]":
        if isinstance(self.node, Module):
            modules = list(self.modules)
            modules.append(BoundNode(self.name, self.node))
            return ResolvedNode(modules, self.classes, attr, self.node.attrs[attr])
        elif isinstance(self.node, Class):
            classes = list(self.classes)
            classes.append(BoundNode(self.name, self.node))
            return ResolvedNode(self.modules, classes, attr, self.node.attrs[attr])
        else:
            raise KeyError(attr)


UnresolvedName = str


class Namespace:
    def __init__(self, modules: Mapping[str, Module]) -> None:
        self.modules = modules

    # NB: this modifies the passed lists.
    def _resolve_name(
        self,
        modules: List[BoundNode[Module]],
        classes: List[BoundNode[Class]],
        name_components: List[str],
    ) -> Union[ResolvedNode[DocumentedNode], UnresolvedName]:
        name_components.reverse()
        while name_components:
            attrs: Mapping[str, Node]
            if classes:
                attrs = classes[-1].node.attrs
            elif modules:
                attrs = modules[-1].node.attrs
            else:
                attrs = self.modules
            name = name_components.pop()
            try:
                node = attrs[name]
            except KeyError:
                break

            if isinstance(node, (Import, ImportFrom)):
                classes.clear()
                if isinstance(node, Import):
                    modules.clear()
                elif isinstance(node, ImportFrom):
                    if node.level >= len(modules):
                        # Relative import beyond top-level package. Bail.
                        break
                    # Absolute import is level 0, which clears the whole list.
                    del modules[-node.level :]
                    name_components.append(node.name)
                if node.module is not None:
                    name_components.extend(reversed(node.module.split(".")))
            elif name_components:
                if isinstance(node, Module):
                    assert not classes
                    modules.append(BoundNode(name, node))
                elif isinstance(node, Class):
                    classes.append(BoundNode(name, node))
                else:
                    break
        else:
            assert isinstance(node, (Module, Class, Function, Variable))
            return ResolvedNode(modules, classes, name, node)
        return ".".join(
            itertools.chain(
                (module.name for module in modules),
                (class_.name for class_ in classes),
                (name,),
                reversed(name_components),
            )
        )

    def resolve_global_name(
        self, name: str
    ) -> Union[ResolvedNode[DocumentedNode], UnresolvedName]:
        return self._resolve_name([], [], name.split("."))

    def resolve_name_in_scope(
        self,
        modules: Sequence[BoundNode[Module]],
        classes: Sequence[BoundNode[Class]],
        name: str,
    ) -> Union[ResolvedNode[DocumentedNode], UnresolvedName]:
        name_components = name.split(".")
        attr = name_components[0]
        if classes and attr in classes[-1].node.attrs:
            classes = list(classes)
        elif modules and attr in modules[-1].node.attrs:
            classes = []
        else:
            return name
        modules = list(modules)
        return self._resolve_name(modules, classes, name_components)
