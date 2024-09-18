# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from tests.linux_kernel import LinuxKernelTestCase


class TestLoadedModules(LinuxKernelTestCase):
    def test_loaded_modules(self):
        loaded_modules = list(self.prog.loaded_modules())
        found_modules = [self.prog.find_main_module()]

        try:
            proc_modules_file = open("/proc/modules", "r")
        except FileNotFoundError:
            pass
        else:
            with proc_modules_file:
                for line in proc_modules_file:
                    tokens = line.split()
                    found_modules.append(
                        self.prog.find_linux_kernel_loadable_module(
                            tokens[0], int(tokens[5], 16)
                        )
                    )

        self.assertCountEqual(loaded_modules, found_modules)
