# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from pathlib import Path
import tempfile

from drgn import (
    DebugInfoOptions,
    KmodSearchMethod,
    MainModule,
    Program,
    RelocatableModule,
)
from drgn.helpers.linux.module import find_module
from tests import modifyenv
from tests.linux_kernel import LinuxKernelTestCase, skip_unless_have_test_kmod


def iter_proc_modules():
    try:
        f = open("/proc/modules", "r")
    except FileNotFoundError:
        return
    with f:
        for line in f:
            tokens = line.split()
            yield tokens[0], int(tokens[5], 16)


class TestDebugInfo(LinuxKernelTestCase):
    def test_debug_info(self):
        # This is actually two test cases squished into one to avoid indexing
        # vmlinux another time.
        prog = Program()
        prog.set_kernel()
        prog.set_enabled_debug_info_finders([])

        with self.subTest("vmlinux_no_build_id"):
            for module, _ in prog.loaded_modules():
                if isinstance(module, MainModule):
                    module.build_id = None
                    break
            else:
                self.fail("main module not found")
            prog.load_debug_info([self.prog.main_module().debug_file_path])
            self.assertEqual(
                prog.main_module().debug_file_path,
                self.prog.main_module().debug_file_path,
            )

        with self.subTest("kmod_walk"), tempfile.TemporaryDirectory() as temp_dir:
            temp_dir = Path(temp_dir)
            found_modules = set()
            for i, module in enumerate(self.prog.modules()):
                if isinstance(module, RelocatableModule) and module.debug_file_path:
                    found_modules.add(module.name)
                    link = temp_dir / str(i) / (module.name + ".ko")
                    link.parent.mkdir()
                    link.symlink_to(module.debug_file_path)

            modules = [
                module
                for module, _ in prog.loaded_modules()
                if module.name in found_modules
            ]
            prog.find_standard_debug_info(
                modules,
                options=DebugInfoOptions(
                    kernel_directories=(temp_dir,), try_kmod=KmodSearchMethod.WALK
                ),
            )
            for module in modules:
                with self.subTest(module=module.name):
                    self.assertIsNotNone(module.debug_file_path)


class TestModule(LinuxKernelTestCase):
    def test_loaded_modules(self):
        expected = [("kernel", None), *iter_proc_modules()]

        loaded_modules = []
        for module, _ in self.prog.loaded_modules():
            if isinstance(module, RelocatableModule):
                loaded_modules.append((module.name, module.address))
            else:
                loaded_modules.append((module.name, None))

        self.assertCountEqual(loaded_modules, expected)

    @skip_unless_have_test_kmod
    def test_find(self):
        self.assertEqual(self.prog.main_module().name, "kernel")
        for name, address in iter_proc_modules():
            if name == "drgn_test":
                self.assertEqual(
                    self.prog.relocatable_module(name, address).name, "drgn_test"
                )
                break
        else:
            self.fail("test module not found")

    @skip_unless_have_test_kmod
    def test_find_by_obj(self):
        for module in self.prog.modules():
            if module.name == "drgn_test":
                break
        else:
            self.fail("test module not found")

        module_obj = find_module(self.prog, "drgn_test")
        self.assertEqual(self.prog.linux_kernel_loadable_module(module_obj), module)
        self.assertEqual(
            self.prog.linux_kernel_loadable_module(module_obj, create=True),
            (module, False),
        )

    def test_no_sys_module(self):
        # Test that we get the same modules with and without using /sys/module.

        def module_dict(prog):
            return {
                (module.name, module.address): (
                    module.address_range,
                    module.build_id,
                    dict(module.section_addresses),
                )
                for module, _ in prog.loaded_modules()
                if isinstance(module, RelocatableModule)
            }

        use_sys_module = int(os.environ.get("DRGN_USE_SYS_MODULE", "1")) != 0

        with modifyenv({"DRGN_USE_SYS_MODULE": str(int(not use_sys_module))}):
            prog = Program()
            prog.set_kernel()

            if use_sys_module:
                with_sys_module = module_dict(self.prog)
                without_sys_module = module_dict(prog)
            else:
                with_sys_module = module_dict(prog)
                without_sys_module = module_dict(self.prog)

            self.assertEqual(with_sys_module, without_sys_module)
