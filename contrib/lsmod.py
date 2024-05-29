#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""An implementation of lsmod(8) using drgn"""

from drgn.helpers.linux.list import list_for_each_entry

def module_total_size(mod):
    # Since Linux kernel commit ac3b43283923 ("module: replace module_layout
    # with module_memory") (in v6.4), the memory sizes are in the struct
    # module::mem array. Before that, they are in struct module::init_layout
    # and struct module::core_layout.
    try:
        num_types = mod.prog_["MOD_MEM_NUM_TYPES"]
    except KeyError:
        return (mod.init_layout.size + mod.core_layout.size).value_()
    else:
        return sum(
            mod.mem[type].size.value_()
            for type in range(num_types)
        )


print("Module                  Size  Used by")
config_module_unload = prog.type("struct module").has_member("refcnt")
for mod in list_for_each_entry("struct module", prog["modules"].address_of_(), "list"):
    name = mod.name.string_().decode()
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
    print(f"{name:19} {module_total_size(mod):>8}  {refcnt}{used}")
