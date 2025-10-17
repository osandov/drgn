# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# ebpf-related commands.

import argparse
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands import drgn_argument
from drgn.commands.crash import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import CellFormat, print_table
from drgn.helpers.linux.bpf import (
    bpf_map_for_each,
    bpf_prog_for_each,
    bpf_prog_used_maps,
)


@crash_command(
    description="display all eBPF programs and maps",
    arguments=(drgn_argument,),
)
def _crash_cmd_bpf(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    if args.drgn:
        code = CrashDrgnCodeBuilder(prog)
        code.add_from_import(
            "drgn.helpers.linux.bpf",
            "bpf_map_for_each",
            "bpf_prog_for_each",
            "bpf_prog_used_maps",
        )
        code.append(
            """\
for bpf_prog in bpf_prog_for_each(prog):
    aux = bpf_prog.aux
    prog_id = aux.id
    prog_type = bpf_prog.type
    tag = bpf_prog.tag
    for used_map in bpf_prog_used_maps(bpf_prog):
        map_id = used_map.id

for bpf_map in bpf_map_for_each(prog):
    map_id = bpf_map.id
    map_type = bpf_map.map_type
    try:
        map_flags = bpf_map.map_flags
    except AttributeError:
        # map_flags is only available since Linux 4.6.
        pass
    """
        )
        code.print()
        return

    prog_rows: List[Sequence[Any]] = [
        (
            CellFormat("ID", "^"),
            CellFormat("BPF_PROG", "^"),
            CellFormat("BPF_PROG_AUX", "^"),
            CellFormat("BPF_PROG_TYPE", "^"),
            CellFormat("TAG", "^"),
            CellFormat("USED_MAPS", "^"),
        )
    ]

    for bpf_prog in bpf_prog_for_each(prog):
        prog_id = bpf_prog.aux.id.value_()
        prog_type_name = bpf_prog.type.format_(type_name=False).split("BPF_PROG_TYPE_")[
            -1
        ]

        tag = bpf_prog.tag
        prog_tag = "".join(f"{b.value_():02x}" for b in tag)

        used_maps = []
        for map in bpf_prog_used_maps(bpf_prog):
            used_maps.append(map.id.value_())
        used_maps_str = ",".join(str(m) for m in used_maps)

        prog_rows.append(
            (
                prog_id,
                CellFormat(bpf_prog.value_(), "^x"),
                CellFormat(bpf_prog.aux.value_(), "^x"),
                CellFormat(prog_type_name, "^"),
                CellFormat(prog_tag, "^"),
                CellFormat(used_maps_str, "^"),
            )
        )

    print_table(prog_rows)
    print()

    map_rows: List[Sequence[Any]] = [
        (
            CellFormat("ID", "^"),
            CellFormat("BPF_MAP", "^"),
            CellFormat("BPF_MAP_TYPE", "^"),
            CellFormat("MAP_FLAGS", "^"),
        )
    ]

    for bpf_map in bpf_map_for_each(prog):
        map_id = bpf_map.id.value_()

        map_type_name = bpf_map.map_type.format_(type_name=False).split(
            "BPF_MAP_TYPE_"
        )[-1]

        # The 'map_flags' field was added in Linux kernel commit 6c9059817432
        # ("bpf: pre-allocate hash map elements") in version 4.6. Older kernels
        # may not have this field, so we catch LookupError and default to 0.
        try:
            map_flags = f"{bpf_map.map_flags.value_():08x}"
        except AttributeError:
            map_flags = "00000000"

        map_rows.append(
            (
                map_id,
                CellFormat(bpf_map.value_(), "^x"),
                CellFormat(map_type_name, "^"),
                CellFormat(map_flags, "^"),
            )
        )

    print_table(map_rows)
