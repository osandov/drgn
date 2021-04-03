# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

"""An implementation of lsmod(8) using drgn"""

from drgn.helpers.linux.list import list_for_each_entry

print("Module                  Size  Used by")
for mod in list_for_each_entry("struct module", prog["modules"].address_of_(), "list"):
    name = mod.name.string_().decode()
    size = (mod.init_layout.size + mod.core_layout.size).value_()
    refcnt = mod.refcnt.counter.value_() - 1
    print(f"{name:19} {size:>8}  {refcnt}", end="")
    first = True
    for use in list_for_each_entry(
        "struct module_use", mod.source_list.address_of_(), "source_list"
    ):
        if first:
            print(" ", end="")
            first = False
        else:
            print(",", end="")
        print(use.source.name.string_().decode(), end="")
    print()
