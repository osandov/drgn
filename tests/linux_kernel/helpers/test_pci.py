# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

from drgn.helpers.linux.pci import (
    for_each_pci_dev,
    for_each_pci_root_bus,
    pci_bus_for_each_child,
    pci_bus_for_each_dev,
    pci_bus_name,
    pci_is_bridge,
    pci_name,
    pci_pcie_type,
)
from tests.linux_kernel import LinuxKernelTestCase


def _pci_root_bus_paths():
    for path in Path("/sys/class/pci_bus").iterdir():
        real_device_path = (path / "device").resolve()
        # For root buses, the device name is "pciDDDD:BB". For other buses, it
        # is the bridge device name (DDDD:BB:dd.F).
        if real_device_path.name.startswith("pci"):
            yield real_device_path


def _pcie_type(config_path) -> int:
    with open(config_path, "rb") as f:
        f.seek(0x34)
        cap_ptr = f.read(1)[0]

        while cap_ptr and cap_ptr < 0xFF:
            f.seek(cap_ptr)
            cap_id = f.read(1)[0]

            if cap_id == 0x10:
                f.seek(cap_ptr + 2)
                pcie_caps = int.from_bytes(f.read(2), byteorder="little")
                return (pcie_caps >> 4) & 0x0F

            f.seek(cap_ptr + 1)
            cap_ptr = f.read(1)[0]

    return None


class TestPci(LinuxKernelTestCase):
    def test_for_each_pci_dev(self):
        # This also tests pci_name().
        self.assertCountEqual(
            [pci_name(dev) for dev in for_each_pci_dev(self.prog)],
            [path.name for path in Path("/sys/bus/pci/devices").iterdir()],
        )

    def test_for_each_pci_root_bus(self):
        # This also tests pci_bus_name().
        self.assertCountEqual(
            [pci_bus_name(bus) for bus in for_each_pci_root_bus(self.prog)],
            [path.name[3:] for path in _pci_root_bus_paths()],
        )

    def test_pci_bus_for_each_child(self):
        bus_path = next(_pci_root_bus_paths())
        bus_name = bus_path.name[3:]
        for bus in for_each_pci_root_bus(self.prog):
            if pci_bus_name(bus) == bus_name:
                break
        else:
            self.fail(f"root bus {bus_path.name} not found")

        self.assertCountEqual(
            [pci_bus_name(child_bus) for child_bus in pci_bus_for_each_child(bus)],
            [child_bus_path.name for child_bus_path in bus_path.glob("*/pci_bus/*")],
        )

    def test_pci_bus_for_each_dev(self):
        bus_path = next(_pci_root_bus_paths())
        bus_name = bus_path.name[3:]
        for bus in for_each_pci_root_bus(self.prog):
            if pci_bus_name(bus) == bus_name:
                break
        else:
            self.fail(f"root bus {bus_path.name} not found")

        self.assertCountEqual(
            [pci_name(dev) for dev in pci_bus_for_each_dev(bus)],
            [dev_path.name for dev_path in bus_path.glob(bus_name + ":*")],
        )

    def test_pci_is_bridge(self):
        bridge_name = None
        non_bridge_name = None
        for path in Path("/sys/bus/pci/devices").iterdir():
            if (path / "secondary_bus_number").exists():
                bridge_name = path.name
                if non_bridge_name is not None:
                    break
            else:
                non_bridge_name = path.name
                if bridge_name is not None:
                    break

        bridge_dev = None
        non_bridge_dev = None
        for dev in for_each_pci_dev(self.prog):
            name = pci_name(dev)
            if name == bridge_name:
                bridge_dev = dev
                if non_bridge_name is None or non_bridge_dev is not None:
                    break
            elif name == non_bridge_name:
                non_bridge_dev = dev
                if bridge_name is None or bridge_dev is not None:
                    break

        with self.subTest("bridge"):
            if bridge_name is None:
                self.skipTest("no bridges found")
            if bridge_dev is None:
                self.fail(f"device {bridge_name} not found")
            self.assertTrue(pci_is_bridge(bridge_dev))

        with self.subTest("non-bridge"):
            if non_bridge_name is None:
                self.skipTest("no non-bridges found")
            if non_bridge_dev is None:
                self.fail(f"device {non_bridge_name} not found")
            self.assertFalse(pci_is_bridge(non_bridge_dev))

    def test_pci_pcie_type(self):
        for path in Path("/sys/bus/pci/devices").iterdir():
            expected = _pcie_type(path / "config")
            if expected is not None:
                break
        else:
            self.skipTest("no PCIe devices found")

        for dev in for_each_pci_dev(self.prog):
            if pci_name(dev) == path.name:
                break
        else:
            self.fail(f"device {path.name} not found")

        self.assertEqual(pci_pcie_type(dev), expected)
