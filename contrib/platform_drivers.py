# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Print registered platform drivers."""

from drgn import NULL, container_of
from drgn.helpers.linux.list import list_for_each_entry


def bus_to_subsys(bus):
    for sp in list_for_each_entry(
        "struct subsys_private",
        prog["bus_kset"].list.address_of_(),
        "subsys.kobj.entry",
    ):
        if sp.bus == bus:
            return sp
    return NULL(bus.prog_, "struct subsys_private *")


sp = bus_to_subsys(prog["platform_bus_type"].address_of_())
for priv in list_for_each_entry(
    "struct driver_private", sp.drivers_kset.list.address_of_(), "kobj.entry"
):
    driver = priv.driver
    print(driver.name.string_().decode())
    platform_driver = container_of(driver, "struct platform_driver", "driver")
    print(platform_driver)
