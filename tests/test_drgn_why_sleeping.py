# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path
import runpy
import types
import unittest.mock

from drgn import FaultError
import drgn.helpers.linux.pid  # noqa: F401: load before mocking os.stat
from tests import TestCase


class _GdbCommand:
    def __init__(self, **kwargs):
        pass


class TestGdbWhySleeping(TestCase):
    def _check_pid_namespace_error(self, stat_mock, message, *, kernel_error=None):
        gdb = types.SimpleNamespace(
            GdbError=RuntimeError,
            Command=_GdbCommand,
            COMMAND_STATUS=0,
            selected_thread=lambda: types.SimpleNamespace(
                is_exited=lambda: False,
                is_stopped=lambda: False,
                ptid=(100, 101, 0),
            ),
            selected_inferior=lambda: types.SimpleNamespace(
                connection=types.SimpleNamespace(type="native")
            ),
            string_to_argv=lambda arg: [],
        )

        script = (
            Path(__file__).resolve().parent.parent
            / "drgn/internal/gdb_scripts/drgn_why_sleeping.py"
        )
        with unittest.mock.patch.dict("sys.modules", {"gdb": gdb}):
            namespace = runpy.run_path(str(script))
            with unittest.mock.patch("drgn.Program") as program_class:
                prog = program_class.return_value
                prog.__getitem__.return_value.ns.inum.value_.return_value = 1
                prog.__getitem__.side_effect = kernel_error
                with unittest.mock.patch("os.stat", **stat_mock), unittest.mock.patch(
                    "drgn.helpers.linux.pid.find_task"
                ) as find_task:
                    command = namespace["DrgnWhySleeping"]()
                    with self.assertRaisesRegex(RuntimeError, message):
                        command.invoke("", False)
                    find_task.assert_not_called()

    def test_nested_pid_namespace(self):
        self._check_pid_namespace_error(
            {"return_value": types.SimpleNamespace(st_ino=2)},
            "nested PID namespace",
        )

    def test_pid_namespace_read_error(self):
        self._check_pid_namespace_error(
            {"side_effect": PermissionError("namespace access denied")},
            "Could not verify GDB's PID namespace: namespace access denied",
        )

    def test_pid_namespace_kernel_read_error(self):
        for error in (
            LookupError("init_pid_ns not found"),
            AttributeError("namespace inode unavailable"),
            FaultError("namespace memory unavailable", 0),
        ):
            with self.subTest(error=type(error).__name__):
                self._check_pid_namespace_error(
                    {"return_value": types.SimpleNamespace(st_ino=1)},
                    "Could not verify GDB's PID namespace",
                    kernel_error=error,
                )
