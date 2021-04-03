# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
drgn consists of a core C extension and supporting Python code. It also makes
use of type hints. As a result, its documentation generation has a few
requirements:

1. It must work without compiling the C extension, which can't be done on Read
   the Docs because of missing dependencies.
2. It must support generating documentation from type hints (ideally with
   proper markup rather than by including the raw type annotations).
3. It must support type hint stub files.
4. It must support classes/functions/etc. which are defined in one module but
   should canonically be documented in another. This is common for C extensions
   that are wrapped by a higher-level Python module.

The main existing solutions are ruled out by these requirements:

1. sphinx.ext.autodoc (and other solutions based on runtime introspection)
   require excluding the C extension (e.g., with autodoc_mock_imports) and
   providing the documentation for it elsewhere. Additionally, type hints from
   stub files are not available at runtime, so extensions like
   sphinx-autodoc-typehints and sphinx.ext.autodoc.typehints won't work.
2. sphinx.ext.autoapi doesn't generate markup for type hints and doesn't have
   any support for objects which should documented under a different name than
   they were defined. It also only supports documenting directory trees, not
   individual files.

This extension addresses these requirements. In the future, it may be
worthwhile to make it a standalone package, as I imagine other projects that
make heavy use of C extensions have encountered similar issues.

Overall, it works by parsing Python source code and stub files (drgndoc.parse),
building a tree representing the namespace (drgndoc.namespace), and using that
namespace to resolve definitions and type annotations to generate markup
(drgndoc.format).

This also provides a script that can generate docstring definitions from a stub
file for the C extension itself (drgndoc.docstrings).
"""

import os.path
import re
from typing import Any, Dict, List, cast

import docutils.nodes
import docutils.parsers.rst.directives
import docutils.statemachine
import sphinx.addnodes
import sphinx.application
import sphinx.environment
import sphinx.util.docutils
import sphinx.util.logging
import sphinx.util.nodes

from drgndoc.format import Formatter
from drgndoc.namespace import Namespace, ResolvedNode
from drgndoc.parse import (
    Class,
    DocumentedNode,
    Import,
    ImportFrom,
    Module,
    Node,
    parse_paths,
)
from drgndoc.util import dot_join

logger = sphinx.util.logging.getLogger(__name__)


# Needed for type checking.
class DrgnDocBuildEnvironment(sphinx.environment.BuildEnvironment):
    drgndoc_namespace: Namespace
    drgndoc_formatter: Formatter


def drgndoc_init(app: sphinx.application.Sphinx) -> None:
    env = cast(DrgnDocBuildEnvironment, app.env)

    paths = [
        os.path.join(app.confdir, path)
        for path in app.config.drgndoc_paths  # type: ignore
    ]
    env.drgndoc_namespace = Namespace(parse_paths(paths, logger.warning))
    env.drgndoc_formatter = Formatter(
        env.drgndoc_namespace,
        [
            (re.compile(pattern), repl)
            for pattern, repl in app.config.drgndoc_substitutions  # type: ignore
        ],
    )


class DrgnDocDirective(sphinx.util.docutils.SphinxDirective):
    env: DrgnDocBuildEnvironment

    required_arguments = 1
    optional_arguments = 0
    option_spec = {
        "exclude": docutils.parsers.rst.directives.unchanged,
    }

    def run(self) -> Any:
        parts = []
        py_module = self.env.ref_context.get("py:module")
        if py_module:
            parts.append(py_module)
        py_classes = self.env.ref_context.get("py:classes", [])
        if py_classes:
            parts.extend(py_classes)
        parts.append(self.arguments[0])
        name = ".".join(parts)
        resolved = self.env.drgndoc_namespace.resolve_global_name(name)
        if not isinstance(resolved, ResolvedNode):
            logger.warning("name %r not found", resolved)
            return []
        if not resolved.node.has_docstring():
            logger.warning("name %r is not documented", resolved.qualified_name())
            return []

        docnode = docutils.nodes.section()
        self._run(name, "", self.arguments[0], resolved, docnode)
        return docnode.children

    def _run(
        self,
        top_name: str,
        attr_name: str,
        name: str,
        resolved: ResolvedNode[Node],
        docnode: docutils.nodes.Node,
    ) -> None:
        exclude_pattern = self.options.get("exclude")
        if exclude_pattern is not None and re.fullmatch(exclude_pattern, attr_name):
            return

        if isinstance(resolved.node, (Import, ImportFrom)):
            # Only include imports that are explicitly aliased (i.e., import
            # ... as ... or from ... import ... as ...).
            # TODO: we should also include imports listed in __all__.
            if not resolved.node.aliased:
                return
            imported = self.env.drgndoc_namespace.resolve_name_in_scope(
                resolved.modules, resolved.classes, resolved.name
            )
            if not isinstance(imported, ResolvedNode):
                return
            resolved = imported

        resolved = cast(ResolvedNode[DocumentedNode], resolved)

        if isinstance(resolved.node, Module):
            return self._run_module(
                top_name, attr_name, cast(ResolvedNode[Module], resolved), docnode
            )

        lines = self.env.drgndoc_formatter.format(
            resolved,
            name,
            self.env.ref_context.get("py:module", ""),
            ".".join(self.env.ref_context.get("py:classes", ())),
        )
        if not lines:
            # Not documented. Ignore it.
            return

        sourcename = ""
        if resolved.modules and resolved.modules[-1].node.path:
            sourcename = resolved.modules[-1].node.path
        if sourcename:
            self.env.note_dependency(sourcename)
        contents = docutils.statemachine.StringList(lines, sourcename)
        contents.append("", sourcename)

        self.state.nested_parse(contents, 0, docnode)
        if isinstance(resolved.node, Class):
            for desc in reversed(docnode.children):
                if isinstance(desc, sphinx.addnodes.desc):
                    break
            else:
                logger.warning("desc node not found")
                return
            for desc_content in reversed(desc.children):
                if isinstance(desc_content, sphinx.addnodes.desc_content):
                    break
            else:
                logger.warning("desc_content node not found")
                return

            py_classes = self.env.ref_context.setdefault("py:classes", [])
            py_classes.append(resolved.name)
            self.env.ref_context["py:class"] = resolved.name
            for member in resolved.attrs():
                if member.name != "__init__":
                    self._run(
                        top_name,
                        dot_join(attr_name, member.name),
                        member.name,
                        member,
                        desc_content,
                    )
            py_classes.pop()
            self.env.ref_context["py:class"] = py_classes[-1] if py_classes else None

    def _run_module(
        self,
        top_name: str,
        attr_name: str,
        resolved: ResolvedNode[Module],
        docnode: docutils.nodes.Node,
    ) -> None:
        node = resolved.node
        if node.docstring is None:
            # Not documented. Ignore it.
            return

        sourcename = node.path or ""
        if sourcename:
            self.env.note_dependency(sourcename)
        contents = docutils.statemachine.StringList(
            node.docstring.splitlines(), sourcename
        )

        sphinx.util.nodes.nested_parse_with_titles(self.state, contents, docnode)

        # If the module docstring defines any sections, then the contents
        # should go inside of the last one.
        section = docnode
        for child in reversed(docnode.children):
            if isinstance(child, docutils.nodes.section):
                section = child
                break

        try:
            old_py_module = self.env.ref_context["py:module"]
            have_old_py_module = True
        except KeyError:
            have_old_py_module = False
        self.env.ref_context["py:module"] = dot_join(top_name, attr_name)
        for attr in resolved.attrs():
            self._run(
                top_name, dot_join(attr_name, attr.name), attr.name, attr, section
            )
        if have_old_py_module:
            self.env.ref_context["py:module"] = old_py_module
        else:
            del self.env.ref_context["py:module"]


def setup(app: sphinx.application.Sphinx) -> Dict[str, Any]:
    app.connect("builder-inited", drgndoc_init)
    # List of modules or packages.
    app.add_config_value("drgndoc_paths", [], "env")
    # List of (regex pattern, substitution) to apply to resolved names.
    app.add_config_value("drgndoc_substitutions", [], "env")
    app.add_directive("drgndoc", DrgnDocDirective)
    return {"env_version": 1, "parallel_read_safe": True, "parallel_write_safe": True}
