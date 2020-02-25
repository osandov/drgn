# Copyright 2020 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import itertools
from typing import (
    Generic,
    Iterator,
    List,
    Mapping,
    Optional,
    TypeVar,
    Union,
)

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
        module: Optional[BoundNode[Module]],
        class_: Optional[BoundNode[Class]],
        name: str,
        node: NodeT_co,
    ) -> None:
        self.module = module
        self.class_ = class_
        self.name = name
        self.node = node

    def qualified_name(self) -> str:
        return dot_join(
            self.module.name if self.module else None,
            self.class_.name if self.class_ else None,
            self.name,
        )

    def attrs(self) -> Iterator["ResolvedNode[Node]"]:
        if isinstance(self.node, Module):
            module_name = dot_join(self.module.name if self.module else None, self.name)
            for attr, node in self.node.attrs.items():
                yield ResolvedNode(BoundNode(module_name, self.node), None, attr, node)
        elif isinstance(self.node, Class):
            class_name = dot_join(self.class_.name if self.class_ else None, self.name)
            for attr, node in self.node.attrs.items():
                yield ResolvedNode(
                    self.module, BoundNode(class_name, self.node), attr, node
                )

    def attr(self, attr: str) -> "ResolvedNode[Node]":
        if isinstance(self.node, Module):
            module_name = dot_join(self.module.name if self.module else None, self.name)
            return ResolvedNode(
                BoundNode(module_name, self.node), None, attr, self.node.attrs[attr]
            )
        elif isinstance(self.node, Class):
            class_name = dot_join(self.class_.name if self.class_ else None, self.name)
            return ResolvedNode(
                self.module,
                BoundNode(class_name, self.node),
                attr,
                self.node.attrs[attr],
            )
        else:
            raise KeyError(attr)


UnresolvedName = str


class Namespace:
    def __init__(self, modules: Mapping[str, Module]) -> None:
        self.modules = modules

    def _resolve_name(
        self,
        module_name: Optional[str],
        module: Optional[Module],
        class_name: Optional[str],
        class_: Optional[Class],
        name_components: List[str],
    ) -> Union[ResolvedNode[DocumentedNode], UnresolvedName]:
        assert (module_name is None) == (module is None)
        assert (class_name is None) == (class_ is None)
        module_name_parts = []
        if module_name is not None:
            module_name_parts.append(module_name)
        class_name_parts = []
        if class_name is not None:
            class_name_parts.append(class_name)

        name_components.reverse()
        while name_components:
            attrs: Mapping[str, Node]
            if class_:
                attrs = class_.attrs
            elif module:
                attrs = module.attrs
            else:
                attrs = self.modules
            name = name_components.pop()
            try:
                node = attrs[name]
            except KeyError:
                break

            if isinstance(node, (Import, ImportFrom)):
                module_name_parts.clear()
                class_name_parts.clear()
                module = None
                class_ = None
                if isinstance(node, Import):
                    import_name = node.module
                elif isinstance(node, ImportFrom):
                    if node.module is None or node.level != 0:
                        raise NotImplementedError("TODO: relative imports")
                    import_name = node.module
                    name_components.append(node.name)
                name_components.extend(reversed(import_name.split(".")))
            elif name_components:
                if isinstance(node, Module):
                    assert not class_
                    module = node
                    module_name_parts.append(name)
                elif isinstance(node, Class):
                    class_ = node
                    class_name_parts.append(name)
                else:
                    break
        else:
            assert isinstance(node, (Module, Class, Function, Variable))
            return ResolvedNode(
                BoundNode(".".join(module_name_parts), module) if module else None,
                BoundNode(".".join(class_name_parts), class_) if class_ else None,
                name,
                node,
            )
        return ".".join(
            itertools.chain(
                module_name_parts, class_name_parts, (name,), reversed(name_components)
            )
        )

    def resolve_global_name(
        self, name: str
    ) -> Union[ResolvedNode[DocumentedNode], UnresolvedName]:
        return self._resolve_name(None, None, None, None, name.split("."))

    def resolve_name_in_scope(
        self,
        module: Optional[BoundNode[Module]],
        class_: Optional[BoundNode[Class]],
        name: str,
    ) -> Union[ResolvedNode[DocumentedNode], UnresolvedName]:
        name_components = name.split(".")
        attr = name_components[0]
        if class_ and attr in class_.node.attrs:
            pass
        elif module and attr in module.node.attrs:
            class_ = None
        else:
            return name
        return self._resolve_name(
            module.name if module else None,
            module.node if module else None,
            class_.name if class_ else None,
            class_.node if class_ else None,
            name_components,
        )
