# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Print registered platform drivers."""

from drgn import NULL, container_of
from drgn.helpers.linux.device import bus_to_subsys
from drgn.helpers.linux.list import list_for_each_entry


sp = bus_to_subsys(prog["platform_bus_type"].address_of_())
for priv in list_for_each_entry(
    "struct driver_private", sp.drivers_kset.list.address_of_(), "kobj.entry"
):
    driver = priv.driver
    print(driver.name.string_().decode())
    platform_driver = container_of(driver, "struct platform_driver", "driver")
    print(platform_driver)
