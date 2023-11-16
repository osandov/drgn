# Copyright Jason R. Coombs
# SPDX-License-Identifier: MIT
# Based on https://pypi.org/project/jaraco.packaging/.

import os
import subprocess
import sys


def setup(app):
    app.add_config_value("package_url", "", "")
    app.connect("config-inited", load_config_from_setup)
    app.connect("html-page-context", add_package_url)
    return {"parallel_read_safe": "True"}


def load_config_from_setup(app, config):
    """
    Replace values in config from package metadata
    """
    # for now, assume project root is one level up
    root = os.path.join(app.confdir, "..")
    setup_script = os.path.join(root, "setup.py")
    fields = ["--name", "--version", "--url", "--author"]
    dist_info_cmd = [sys.executable, setup_script] + fields
    output = subprocess.check_output(dist_info_cmd, cwd=root, universal_newlines=True)
    outputs = output.strip().split("\n")
    project, version, url, author = outputs
    config.project = project
    config.version = config.release = version
    config.package_url = url
    config.author = config.copyright = author


def add_package_url(app, pagename, templatename, context, doctree):
    context["package_url"] = app.config.package_url
