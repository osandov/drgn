# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
PCI
---

The ``drgn.helpers.linux.pci`` module provides helpers for working with PCI
devices and buses.
"""

import enum
import os
from typing import Iterator, Union

from drgn import Object, Program, container_of
from drgn.helpers.common.prog import takes_program_or_default
from drgn.helpers.linux.device import bus_for_each_dev, dev_name
from drgn.helpers.linux.list import list_for_each_entry

__all__ = (
    "for_each_pci_dev",
    "for_each_pci_root_bus",
    "pci_bus_for_each_child",
    "pci_bus_for_each_dev",
    "pci_bus_name",
    "pci_is_bridge",
    "pci_name",
    "pci_pcie_type",
)


@takes_program_or_default
def for_each_pci_dev(prog: Program) -> Iterator[Object]:
    """
    Iterate over all PCI devices.

    :return: Iterator of ``struct pci_dev *`` objects.
    """
    pci_dev_type = prog.type("struct pci_dev")
    for dev in bus_for_each_dev(prog["pci_bus_type"].address_of_()):
        yield container_of(dev, pci_dev_type, "dev")


@takes_program_or_default
def for_each_pci_root_bus(prog: Program) -> Iterator[Object]:
    """
    Iterate over all PCI root buses.

    :return: Iterator of ``struct pci_bus *`` objects.
    """
    return list_for_each_entry(
        "struct pci_bus", prog["pci_root_buses"].address_of_(), "node"
    )


def pci_bus_for_each_child(bus: Object) -> Iterator[Object]:
    """
    Iterate over every child bus of a given PCI bus.

    :param bus: ``struct pci_bus *``
    :return: Iterator of ``struct pci_bus *`` objects.
    """
    return list_for_each_entry("struct pci_bus", bus.children.address_of_(), "node")


def pci_bus_for_each_dev(bus: Object) -> Iterator[Object]:
    """
    Iterate over every device on a given PCI bus.

    :param bus: ``struct pci_bus *``
    :return: Iterator of ``struct pci_dev *`` objects.
    """
    return list_for_each_entry("struct pci_dev", bus.devices.address_of_(), "bus_list")


def pci_name(dev: Object) -> str:
    """
    Get the name (Domain:Bus:Device.Function) of a PCI device.

    :param dev: ``struct pci_dev *``
    """
    return os.fsdecode(dev_name(dev.dev))


def pci_bus_name(bus: Object) -> str:
    """
    Get the name (Domain:Bus) of a PCI bus.

    :param bus: ``struct pci_bus *``
    """
    return os.fsdecode(dev_name(bus.dev))


_PCI_HEADER_TYPE_NORMAL = 0
_PCI_HEADER_TYPE_BRIDGE = 1
_PCI_HEADER_TYPE_CARDBUS = 2


def pci_is_bridge(dev: Object) -> bool:
    """
    Return whether a PCI device is a bridge.

    :param dev: ``struct pci_dev *``
    """
    return dev.hdr_type.value_() in (_PCI_HEADER_TYPE_BRIDGE, _PCI_HEADER_TYPE_CARDBUS)


def pci_pcie_type(dev: Object) -> Union["PCI_EXP_TYPE", int]:
    """
    Return the PCI Express Device/Port Type of a PCI device.

    :param dev: ``struct pci_dev *``
    :return: :class:`PCI_EXP_TYPE` constant, or an ``int`` if the value is not
        recognized.
    """
    type = (dev.pcie_flags_reg.value_() & 0x00F0) >> 4
    try:
        return PCI_EXP_TYPE(type)
    except ValueError:
        return type


class PCI_EXP_TYPE(enum.IntEnum):
    """PCI Express Device/Port Type."""

    ENDPOINT = 0x0
    """Express Endpoint"""
    LEG_END = 0x1
    """Legacy Endpoint"""
    ROOT_PORT = 0x4
    """Root Port"""
    UPSTREAM = 0x5
    """Upstream Port"""
    DOWNSTREAM = 0x6
    """Downstream Port"""
    PCI_BRIDGE = 0x7
    """PCIe to PCI/PCI-X Bridge"""
    PCIE_BRIDGE = 0x8
    """PCI/PCI-X to PCIe Bridge"""
    RC_END = 0x9
    """Root Complex Integrated Endpoint"""
    RC_EC = 0xA
    """Root Complex Event Collector"""
