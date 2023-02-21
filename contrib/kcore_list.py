#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Dump the list of memory regions exposed by /proc/kcore."""

from drgn import cast
from drgn.helpers.linux.list import list_for_each_entry

kcore_type = prog.type("enum kcore_type")
for entry in list_for_each_entry(
    "struct kcore_list", prog["kclist_head"].address_of_(), "list"
):
    print(
        f"{cast(kcore_type, entry.type).format_(type_name=False)} {hex(entry.addr)} {hex(entry.size)}"
    )
