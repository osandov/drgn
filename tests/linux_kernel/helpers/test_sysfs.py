# (C) Copyright IBM Corp. 2026
# SPDX-License-Identifier: LGPL-2.1-or-later

import os

from drgn import NULL
from drgn.helpers.linux.sysfs import (
    sysfs_listdir,
    sysfs_lookup,
    sysfs_lookup_kobject,
    sysfs_lookup_node,
)
from tests.linux_kernel import LinuxKernelTestCase


class TestSysfs(LinuxKernelTestCase):
    @classmethod
    def kernfs_node_from_fd(cls, fd):
        import os

        from drgn import cast
        from drgn.helpers.linux.fs import fget
        from drgn.helpers.linux.pid import find_task

        file = fget(find_task(cls.prog, os.getpid()), fd)
        return cast("struct kernfs_node *", file.f_inode.i_private)

    def test_sysfs_lookup_node(self):
        fds = []
        try:
            for path in ("/sys", "/sys/kernel", "/sys/kernel/vmcoreinfo"):
                fds.append(os.open(path, os.O_RDONLY))

            kns = [self.kernfs_node_from_fd(fd) for fd in fds]

            self.assertEqual(sysfs_lookup_node(self.prog, ""), kns[0])
            self.assertEqual(sysfs_lookup_node(self.prog, "/sys"), kns[0])
            self.assertEqual(sysfs_lookup_node(self.prog, "/sys/"), kns[0])

            self.assertEqual(sysfs_lookup_node(self.prog, "kernel"), kns[1])
            self.assertEqual(sysfs_lookup_node(self.prog, "/sys/kernel"), kns[1])
            self.assertEqual(
                sysfs_lookup_node(self.prog, "sys/kernel"),
                NULL(self.prog, "struct kernfs_node *"),
            )

            self.assertEqual(sysfs_lookup_node(self.prog, "kernel/vmcoreinfo"), kns[2])
            self.assertEqual(
                sysfs_lookup_node(self.prog, "/sys/kernel/vmcoreinfo"), kns[2]
            )
            self.assertEqual(
                sysfs_lookup_node(self.prog, "sys/kernel/vmcoreinfo"),
                NULL(self.prog, "struct kernfs_node *"),
            )

            self.assertEqual(
                sysfs_lookup_node(self.prog, "/kernel"),
                NULL(self.prog, "struct kernfs_node *"),
            )
            self.assertEqual(
                sysfs_lookup_node(self.prog, "kernel/foobar"),
                NULL(self.prog, "struct kernfs_node *"),
            )

        finally:
            for fd in fds:
                os.close(fd)

    def test_sysfs_lookup_kobject(self):
        kernel_kobj = self.prog["kernel_kobj"]

        self.assertEqual(
            sysfs_lookup_kobject(self.prog, ""), NULL(self.prog, "struct kobject *")
        )
        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "/sys"), NULL(self.prog, "struct kobject *")
        )
        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "/sys/"),
            NULL(self.prog, "struct kobject *"),
        )

        self.assertEqual(sysfs_lookup_kobject(self.prog, "kernel"), kernel_kobj)
        self.assertEqual(sysfs_lookup_kobject(self.prog, "/sys/kernel"), kernel_kobj)

        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "kernel/vmcoreinfo"), kernel_kobj
        )
        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "/sys/kernel/vmcoreinfo"), kernel_kobj
        )

        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "kernel"),
            sysfs_lookup_kobject(self.prog, "kernel/vmcoreinfo"),
        )

        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "sys/kernel"),
            NULL(self.prog, "struct kobject *"),
        )
        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "sys/kernel/vmcoreinfo"),
            NULL(self.prog, "struct kobject *"),
        )
        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "/"),
            NULL(self.prog, "struct kobject *"),
        )
        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "/kernel"),
            NULL(self.prog, "struct kobject *"),
        )
        self.assertEqual(
            sysfs_lookup_kobject(self.prog, "kernel/foobar"),
            NULL(self.prog, "struct kobject *"),
        )

    def test_sysfs_lookup(self):
        kernel_kobj = self.prog["kernel_kobj"]

        self.assertEqual(
            sysfs_lookup(self.prog, ""), NULL(self.prog, "struct kobject *")
        )
        self.assertEqual(
            sysfs_lookup(self.prog, "/sys"), NULL(self.prog, "struct kobject *")
        )
        self.assertEqual(
            sysfs_lookup(self.prog, "/sys/"), NULL(self.prog, "struct kobject *")
        )

        self.assertEqual(sysfs_lookup(self.prog, "kernel"), kernel_kobj)
        self.assertEqual(sysfs_lookup(self.prog, "/sys/kernel"), kernel_kobj)

        self.assertEqual(sysfs_lookup(self.prog, "kernel/vmcoreinfo"), kernel_kobj)
        self.assertEqual(sysfs_lookup(self.prog, "/sys/kernel/vmcoreinfo"), kernel_kobj)

        self.assertEqual(
            sysfs_lookup(self.prog, "kernel"),
            sysfs_lookup(self.prog, "kernel/vmcoreinfo"),
        )

        self.assertEqual(
            sysfs_lookup(self.prog, "sys/kernel"),
            NULL(self.prog, "struct kobject *"),
        )
        self.assertEqual(
            sysfs_lookup(self.prog, "sys/kernel/vmcoreinfo"),
            NULL(self.prog, "struct kobject *"),
        )
        self.assertEqual(
            sysfs_lookup(self.prog, "/kernel"), NULL(self.prog, "struct kobject *")
        )
        self.assertEqual(
            sysfs_lookup(self.prog, "kernel/foobar"),
            NULL(self.prog, "struct kobject *"),
        )

        # Device case
        if "device_ktype" in self.prog:
            path = "/sys/block"
            if os.path.exists(path):
                with os.scandir(path) as entries:
                    entry = next((e for e in entries if e.is_dir()), None)
                    if entry:
                        dev = sysfs_lookup(self.prog, entry.path[5:])
                        self.assertTrue(dev)
                        self.assertEqual(dev.type_.type_name(), "struct device *")

        # Module case
        if "module_ktype" in self.prog:
            path = "/sys/module"
            if os.path.exists(path):
                with os.scandir(path) as entries:
                    entry = next((e for e in entries if e.is_dir()), None)
                    if entry:
                        mod = sysfs_lookup(self.prog, entry.path[5:])
                        self.assertTrue(mod)
                        self.assertEqual(
                            mod.type_.type_name(), "struct module_kobject *"
                        )

        # Driver case
        if "driver_ktype" in self.prog:
            path = "/sys/bus"
            if os.path.exists(path):
                with os.scandir(path) as buses:
                    bus = next((b for b in buses if b.is_dir()), None)
                    if bus:
                        drv_dir = os.path.join(bus.path, "drivers")
                        if os.path.exists(drv_dir):
                            with os.scandir(drv_dir) as drivers:
                                drv = next((d for d in drivers if d.is_dir()), None)
                                if drv:
                                    driver = sysfs_lookup(self.prog, drv.path[5:])
                                    self.assertTrue(driver)
                                    self.assertEqual(
                                        driver.type_.type_name(),
                                        "struct device_driver *",
                                    )

        # Class case
        if "class_ktype" in self.prog:
            path = "/sys/class"
            if os.path.exists(path):
                with os.scandir(path) as entries:
                    entry = next((e for e in entries if e.is_dir()), None)
                    if entry:
                        cls = sysfs_lookup(self.prog, entry.path[5:])
                        self.assertTrue(cls)
                        self.assertIn("struct class *", cls.type_.type_name())

        # Bus case
        if "bus_ktype" in self.prog:
            path = "/sys/bus"
            if os.path.exists(path):
                with os.scandir(path) as entries:
                    entry = next((e for e in entries if e.is_dir()), None)
                    if entry:
                        bus = sysfs_lookup(self.prog, entry.path[5:])
                        self.assertTrue(bus)
                        self.assertIn("struct bus_type *", bus.type_.type_name())

    def test_sysfs_listdir(self):
        expected = os.listdir(b"/sys/kernel")

        self.assertCountEqual(sysfs_listdir(self.prog, "kernel"), expected)
        self.assertCountEqual(sysfs_listdir(self.prog, "/sys/kernel"), expected)

        self.assertRaisesRegex(
            ValueError, r": not found$", sysfs_listdir, self.prog, "sys/kernel"
        )
        self.assertRaisesRegex(
            ValueError, r": not found$", sysfs_listdir, self.prog, "kernel/foobar"
        )
        self.assertRaisesRegex(
            ValueError, "not a directory", sysfs_listdir, self.prog, "kernel/vmcoreinfo"
        )
