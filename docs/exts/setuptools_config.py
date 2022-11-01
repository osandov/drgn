# Copyright Jason R. Coombs
# SPDX-License-Identifier: MIT
# From https://pypi.org/project/jaraco.packaging/.

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
