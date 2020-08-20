# https://pypi.org/project/jaraco.packaging/
#
# Copyright Jason R. Coombs
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import unicode_literals

import os
import subprocess
import sys

if "check_output" not in dir(subprocess):
    import subprocess32 as subprocess


def setup(app):
    app.add_config_value("package_url", "", "")
    app.connect("builder-inited", load_config_from_setup)
    app.connect("html-page-context", add_package_url)


def load_config_from_setup(app):
    """
    Replace values in app.config from package metadata
    """
    # for now, assume project root is one level up
    root = os.path.join(app.confdir, "..")
    setup_script = os.path.join(root, "setup.py")
    fields = ["--name", "--version", "--url", "--author"]
    dist_info_cmd = [sys.executable, setup_script] + fields
    output = subprocess.check_output(dist_info_cmd, cwd=root, universal_newlines=True)
    outputs = output.strip().split("\n")
    project, version, url, author = outputs
    app.config.project = project
    app.config.version = app.config.release = version
    app.config.package_url = url
    app.config.author = app.config.copyright = author


def add_package_url(app, pagename, templatename, context, doctree):
    context["package_url"] = app.config.package_url
