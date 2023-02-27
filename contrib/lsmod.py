#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""An implementation of lsmod(8) using drgn"""

from drgn.helpers.linux.list import list_for_each_entry

print("Module                  Size  Used by")
config_module_unload = prog.type("struct module").has_member("refcnt")
for mod in list_for_each_entry("struct module", prog["modules"].address_of_(), "list"):
    name = mod.name.string_().decode()
    size = (mod.init_layout.size + mod.core_layout.size).value_()
    if config_module_unload:
        refcnt = mod.refcnt.counter.value_() - 1
        used_by = [
            use.source.name.string_().decode()
            for use in list_for_each_entry(
                "struct module_use", mod.source_list.address_of_(), "source_list"
            )
        ]
    else:
        refcnt = "-"
        used_by = []

    used = ",".join(used_by)
    if used:
        used = " " + used
    print(f"{name:19} {size:>8}  {refcnt}{used}")
