# Copyright 2017-2019 by Takeshi KOMIYA
# SPDX-License-Identifier: Apache-2.0
# From https://pypi.org/project/sphinxcontrib-details-directive/, patched to
# use the proper name for the :class: option.

from docutils import nodes
from docutils.parsers.rst import Directive, directives
from sphinx.transforms.post_transforms import SphinxPostTransform
from sphinx.util.nodes import NodeMatcher


class details(nodes.Element, nodes.General):
    pass


class summary(nodes.TextElement, nodes.General):
    pass


def visit_details(self, node):
    if node.get('opened'):
        self.body.append(self.starttag(node, 'details', open="open"))
    else:
        self.body.append(self.starttag(node, 'details'))


def depart_details(self, node):
    self.body.append('</details>')


def visit_summary(self, node):
    self.body.append(self.starttag(node, 'summary'))


def depart_summary(self, node):
    self.body.append('</summary>')


class DetailsDirective(Directive):
    required_arguments = 1
    final_argument_whitespace = True
    has_content = True
    option_spec = {
        'class': directives.class_option,
        'name': directives.unchanged,
        'open': directives.flag,
    }

    def run(self):
        admonition = nodes.container('',
                                     classes=self.options.get('class', []),
                                     opened='open' in self.options,
                                     type='details')
        textnodes, messages = self.state.inline_text(self.arguments[0],
                                                     self.lineno)
        admonition += nodes.paragraph(self.arguments[0], '', *textnodes)
        admonition += messages
        self.state.nested_parse(self.content, self.content_offset, admonition)
        self.add_name(admonition)
        return [admonition]


class DetailsTransform(SphinxPostTransform):
    default_priority = 200
    builders = ('html',)

    def run(self):
        matcher = NodeMatcher(nodes.container, type='details')
        for node in self.document.traverse(matcher):
            newnode = details(**node.attributes)
            newnode += summary('', '', *node[0])
            newnode.extend(node[1:])
            node.replace_self(newnode)


def setup(app):
    app.add_node(details, html=(visit_details, depart_details))
    app.add_node(summary, html=(visit_summary, depart_summary))
    app.add_directive('details', DetailsDirective)
    app.add_post_transform(DetailsTransform)

    return {
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
