# Copyright 2018-2019 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import docutils.nodes
from docutils.statemachine import StringList
import importlib
import pkgutil
import sphinx.ext.autodoc
from sphinx.util.docutils import SphinxDirective
from sphinx.util.nodes import nested_parse_with_titles


# sphinx.ext.autodoc doesn't recursively document packages, so we need our own
# directive to do that.
class AutopackageDirective(SphinxDirective):
    required_arguments = 1
    optional_arguments = 0

    def run(self):
        sourcename = ""

        def aux(name):
            module = importlib.import_module(name)

            contents = StringList()
            contents.append(f".. automodule:: {name}", sourcename)
            if hasattr(module, "__all__"):
                module_attrs = [
                    attr_name
                    for attr_name in module.__all__
                    if getattr(module, attr_name).__module__ == name
                ]
                if module_attrs:
                    contents.append(
                        f"    :members: {', '.join(module_attrs)}", sourcename
                    )
            else:
                contents.append("    :members:", sourcename)
            contents.append("", sourcename)

            node = docutils.nodes.section()
            nested_parse_with_titles(self.state, contents, node)

            # If this module defines any sections, then submodules should go
            # inside of the last one.
            section = node
            for child in node.children:
                if isinstance(child, docutils.nodes.section):
                    section = child

            if hasattr(module, "__path__"):
                submodules = sorted(
                    module_info.name
                    for module_info in pkgutil.iter_modules(
                        module.__path__, prefix=name + "."
                    )
                )
                for submodule in submodules:
                    section.extend(aux(submodule))

            return node.children

        with sphinx.ext.autodoc.mock(self.env.config.autodoc_mock_imports):
            return aux(self.arguments[0])


def setup(app):
    app.setup_extension("sphinx.ext.autodoc")
    app.add_directive("autopackage", AutopackageDirective)

    return {"parallel_read_safe": True}
