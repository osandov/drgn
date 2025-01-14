# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import logging
import os
from pathlib import Path
import sys
import tempfile
import unittest.mock

import _drgn_util.plugins
from _drgn_util.plugins import call_plugins
from tests import TestCase, modifyenv


class TestPlugins(TestCase):
    def setUp(self):
        # Clear the plugin and hook caches before each test.
        _drgn_util.plugins._plugins = None
        _drgn_util.plugins._hooks.clear()

        # pkg_resources caches distributions on import. Delete it before each
        # test so that it is reloaded.
        sys.modules.pop("pkg_resources", None)

        # These tests change these environment variables and sys.path, so
        # restore them after each test.
        self.enterContext(
            modifyenv({"DRGN_PLUGINS": None, "DRGN_DISABLE_PLUGINS": None})
        )
        self.addCleanup(setattr, sys, "path", list(sys.path))

        # Delete modules imported by each test so that we can reuse the same
        # module names.
        def restore_modules(old_modules):
            for new_module in set(sys.modules) - old_modules:
                sys.modules.pop(new_module, None)

        self.addCleanup(restore_modules, set(sys.modules))

    @staticmethod
    def _create_plugin(dir):
        plugin_path = Path(dir) / "test_plugin.py"
        plugin_path.write_text(
            """\
def drgn_test_hook(call_me):
    call_me()
"""
        )
        return plugin_path

    @staticmethod
    def _create_dist_info(dir, module_name="test_plugin", entry_point_name="test"):
        dist_info_dir = Path(dir) / f"{module_name}-1.0.dist-info"
        dist_info_dir.mkdir()
        (dist_info_dir / "METADATA").write_text(
            f"""\
Metadata-Version: 1.1
Name: {module_name}
Version: 1.0
"""
        )
        (dist_info_dir / "entry_points.txt").write_text(
            f"""\
[drgn.plugins]
{entry_point_name} = {module_name}
"""
        )

    def test_entry_point(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._create_plugin(temp_dir)
            self._create_dist_info(temp_dir)
            sys.path.insert(0, temp_dir)

            call_me = unittest.mock.Mock()
            call_plugins("drgn_test_hook", call_me)
            call_me.assert_called_once()

    def test_drgn_disable_plugins_envvar_all(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._create_plugin(temp_dir)
            self._create_dist_info(temp_dir)
            sys.path.insert(0, temp_dir)
            os.environ["DRGN_DISABLE_PLUGINS"] = "*"

            call_me = unittest.mock.Mock()
            call_plugins("drgn_test_hook", call_me)
            call_me.assert_not_called()

    def test_drgn_disable_plugins_envvar_specific(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._create_plugin(temp_dir)
            self._create_dist_info(temp_dir)
            sys.path.insert(0, temp_dir)
            os.environ["DRGN_DISABLE_PLUGINS"] = "foo,test"

            call_me = unittest.mock.Mock()
            call_plugins("drgn_test_hook", call_me)
            call_me.assert_not_called()

    def test_drgn_plugins_envvar_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_path = self._create_plugin(temp_dir)
            os.environ["DRGN_PLUGINS"] = f"test={plugin_path}"

            call_me = unittest.mock.Mock()
            call_plugins("drgn_test_hook", call_me)
            call_me.assert_called_once()

    def test_drgn_plugins_envvar_module(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_path = self._create_plugin(temp_dir)
            sys.path.insert(0, temp_dir)
            os.environ["DRGN_PLUGINS"] = f"test={plugin_path.stem}"

            call_me = unittest.mock.Mock()
            call_plugins("drgn_test_hook", call_me)
            call_me.assert_called_once()

    def test_drgn_plugins_envvar_precedence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self._create_plugin(temp_dir)
            self._create_dist_info(temp_dir)
            sys.path.insert(0, temp_dir)
            os.environ["DRGN_DISABLE_PLUGINS"] = "*"
            os.environ["DRGN_PLUGINS"] = "test"

            call_me = unittest.mock.Mock()
            call_plugins("drgn_test_hook", call_me)
            call_me.assert_called_once()

    def test_priority(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "test_plugin1.py").write_text(
                """\
def drgn_test_hook(call_me):
    call_me(1)
drgn_test_hook.drgn_priority = 75
"""
            )
            (Path(temp_dir) / "test_plugin2.py").write_text(
                """\
def drgn_test_hook(call_me):
    call_me(2)
drgn_test_hook.drgn_priority = 25
"""
            )
            (Path(temp_dir) / "test_plugin3.py").write_text(
                """\
def drgn_test_hook(call_me):
    call_me(3)
"""
            )
            self._create_dist_info(temp_dir, "test_plugin1", "test1")
            self._create_dist_info(temp_dir, "test_plugin2", "test2")
            self._create_dist_info(temp_dir, "test_plugin3", "test3")
            sys.path.insert(0, temp_dir)

            call_me = unittest.mock.Mock()
            call_plugins("drgn_test_hook", call_me)
            self.assertEqual(
                call_me.call_args_list,
                [unittest.mock.call(2), unittest.mock.call(3), unittest.mock.call(1)],
            )

    def test_plugin_exception(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "test_plugin.py").write_text('raise Exception("foo")\n')
            self._create_dist_info(temp_dir)
            sys.path.insert(0, temp_dir)

            with self.assertLogs(logging.getLogger("drgn.plugins"), "WARNING") as cm:
                call_plugins("drgn_test_hook")
            self.assertTrue(
                any(
                    message.startswith("WARNING:drgn.plugins:failed to load 'test")
                    for message in cm.output
                ),
                msg=f"no match in {cm.output}",
            )

    def test_hook_exception(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "test_plugin.py").write_text(
                """\
def drgn_test_hook():
    raise Exception("foo")
"""
            )
            self._create_dist_info(temp_dir)
            sys.path.insert(0, temp_dir)

            with self.assertLogs(logging.getLogger("drgn.plugins"), "WARNING") as cm:
                call_plugins("drgn_test_hook")
            self.assertTrue(
                any(
                    message.startswith(
                        "WARNING:drgn.plugins:'test' drgn_test_hook failed:"
                    )
                    for message in cm.output
                ),
                msg=f"no match in {cm.output}",
            )

    def test_missing_entry_point(self):
        os.environ["DRGN_PLUGINS"] = "__non__existent__entrypoint__"
        with self.assertLogs(logging.getLogger("drgn.plugins"), "WARNING") as cm:
            call_plugins("drgn_test_hook")
        self.assertTrue(
            any(
                message.startswith(
                    "WARNING:drgn.plugins:not found: '__non__existent__entrypoint__'"
                )
                for message in cm.output
            ),
            msg=f"no match in {cm.output}",
        )
