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


def module_path_in_depmod_index(path, module_name):
    for line in path.read_text().splitlines():
        module_path = line.partition(":")[0]
        filename = Path(module_path).name
        ko_suffix = filename.find(".ko")
        if ko_suffix >= 0 and filename[:ko_suffix].replace("-", "_") == module_name:
            return module_path[: module_path.find(".ko") + len(".ko")]
    return None


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

    def test_kmod_depmod_multiple_kernel_directories(self):
        modules_dir = Path("/lib/modules") / os.uname().release
        modules_dep = modules_dir / "modules.dep"
        modules_dep_bin = modules_dir / "modules.dep.bin"
        if not modules_dep.is_file() or not modules_dep_bin.is_file():
            self.skipTest("modules.dep and modules.dep.bin are not installed")

        prog = Program()
        prog.set_kernel()
        loaded_modules = {module.name: module for module, _ in prog.loaded_modules()}
        source_module = next(
            (
                module
                for module in self.prog.modules()
                if isinstance(module, RelocatableModule)
                and module.debug_file_path
                and module.name in loaded_modules
            ),
            None,
        )
        if source_module is None:
            self.skipTest("no loaded kernel module with debug information")

        module_path = module_path_in_depmod_index(modules_dep, source_module.name)
        if module_path is None:
            self.skipTest(f"{source_module.name} is not listed in modules.dep")

        module = loaded_modules[source_module.name]

        with tempfile.TemporaryDirectory() as temp_dir:
            first_kernel_dir = Path(temp_dir) / "first"
            second_kernel_dir = Path(temp_dir) / "second"
            first_kernel_dir.mkdir()
            second_kernel_dir.mkdir()
            (first_kernel_dir / "modules.dep.bin").symlink_to(modules_dep_bin)

            module_file = second_kernel_dir / module_path
            module_file.parent.mkdir(parents=True)
            module_file.symlink_to(source_module.debug_file_path)

            prog.find_standard_debug_info(
                [module],
                options=DebugInfoOptions(
                    directories=(),
                    kernel_directories=(str(first_kernel_dir), str(second_kernel_dir)),
                    try_kmod=KmodSearchMethod.DEPMOD,
                ),
            )
            self.assertIsNone(module.debug_file_path)


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
            self.prog.linux_kernel_loadable_module(module_obj, create=True), module
        )

    def test_no_sys_module(self):
        # Test that we get the same modules with and without using /sys/module.

        def module_dict(prog):
            return {
                (module.name, module.address): (
                    (
                        None
                        if module.address_ranges is None
                        else sorted(module.address_ranges)
                    ),
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
