# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: MIT

"""
Extension to reference Linux kernel code on git.kernel.org.

The linux role links to a file in the Linux kernel code:

    :linux:`include/linux/list.h`

Or a specific line in a file:

    :linux:`include/linux/list.h:100`

By default, it links to Linus Torvald's master branch. This can be overriden
for the rest of the document with the linuxversion directive:

    :linuxversion: v6.7

Or for a specific link:

    :linux:`include/linux/list.h@v6.6`
    :linux:`include/linux/list.h:600@v6.6`

An explicit title can be given:

    :linux:`list_entry() <include/linux/list.h:600@v6.6>`

The linuxt role is the same as the linux role except that it formats the title
as inline text instead of inline code.
"""

import re
from typing import Any, Dict, List, Tuple

from docutils import nodes
from docutils.nodes import Node, system_message
import sphinx.application
import sphinx.util.docutils


class LinuxVersionDirective(sphinx.util.docutils.SphinxDirective):
    required_arguments = 1
    optional_arguments = 0

    def run(self) -> List[Node]:
        self.env.temp_data["linux_version"] = self.arguments[0]
        return []


class LinuxRole(sphinx.util.docutils.ReferenceRole):
    def __init__(self, code: bool) -> None:
        super().__init__()
        self._code = code

    def run(self) -> Tuple[List[Node], List[system_message]]:
        remainder, sep, head = self.target.rpartition("@")
        if not sep:
            remainder = head
            head = ""
        path, sep, line = remainder.rpartition(":")
        if not sep:
            path = line
            line = ""

        if not head:
            head = self.env.temp_data.get("linux_version", "master")

        if re.fullmatch(r"v[0-9]+\.[0-9]+.[0-9]+", head):
            base_url = (
                "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/"
            )
        else:
            base_url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/"

        url_parts = [base_url, path]
        if head != "master":
            url_parts.append("?h=")
            url_parts.append(head)
        if line:
            url_parts.append("#n")
            url_parts.append(line)
        url = "".join(url_parts)

        if self.has_explicit_title:
            title = self.title
        else:
            title_parts = [path]
            if line:
                title_parts.append(":")
                title_parts.append(line)
            title = "".join(title_parts)
        if self._code:
            reference = nodes.reference("", "", internal=False, refuri=url)
            reference += nodes.literal(title, title)
        else:
            reference = nodes.reference(title, title, internal=False, refuri=url)

        return [reference], []


def setup(app: sphinx.application.Sphinx) -> Dict[str, Any]:
    app.add_directive("linuxversion", LinuxVersionDirective)
    app.add_role("linux", LinuxRole(True))
    app.add_role("linuxt", LinuxRole(False))
    return {"env_version": 1, "parallel_read_safe": True, "parallel_write_safe": True}
