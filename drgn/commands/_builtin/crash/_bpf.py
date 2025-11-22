# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# ebpf-related commands.

import argparse
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands.crash import crash_command
from drgn.helpers.common.format import CellFormat, print_table
from drgn.helpers.linux.bpf import (
    bpf_map_for_each,
    bpf_prog_for_each,
    bpf_prog_subprogs,
    bpf_prog_trampoline_progs,
    bpf_prog_used_maps,
)


@crash_command(
    description="display all eBPF programs and maps",
)
def _crash_cmd_bpf(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    prog_rows: List[Sequence[Any]] = [
        (
            "ID",
            CellFormat("BPF_PROG", "^"),
            CellFormat("BPF_PROG_AUX", "^"),
            CellFormat("BPF_PROG_TYPE", "^"),
            CellFormat("TAG", "^"),
            "USED_MAPS",
        )
    ]

    for bpf_prog in bpf_prog_for_each(prog):
        prog_id = bpf_prog.aux.id.value_()
        prog_addr = f"{bpf_prog.value_():#016x}"
        aux_addr = f"{bpf_prog.aux.value_():#016x}"

        bpf_prog_type = prog.type("enum bpf_prog_type")
        prog_type = bpf_prog.type.value_()
        prog_type_name = ""
        if bpf_prog_type.enumerators:
            for name, value in bpf_prog_type.enumerators:
                if value == prog_type:
                    prog_type_name = name
        prog_type_name = prog_type_name.split("BPF_PROG_TYPE_")[-1]

        tag = bpf_prog.tag
        prog_tag = "".join(f"{b.value_():02x}" for b in tag)

        used_maps = []
        for map in bpf_prog_used_maps(bpf_prog):
            used_maps.append(map.id.value_())
        used_maps_str = ", ".join(str(m) for m in used_maps)

        prog_rows.append(
            (
                prog_id,
                CellFormat(prog_addr, "^"),
                CellFormat(aux_addr, "^"),
                CellFormat(prog_type_name, "^"),
                CellFormat(prog_tag, "^"),
                used_maps_str,
            )
        )

        for linked in bpf_prog_trampoline_progs(bpf_prog):
            prog_rows.append(
                (
                    "",
                    CellFormat("-> linked", ">"),
                    CellFormat(f"{linked}", "^"),
                    "",
                    "",
                    "",
                )
            )

        for i, subprog in bpf_prog_subprogs(bpf_prog):
            prog_rows.append(
                (
                    "",
                    CellFormat(f"-> func[{i:02}]", ">"),
                    CellFormat(f"{subprog}", "^"),
                    "",
                    "",
                    "",
                )
            )

    print_table(prog_rows)
    print("\n" + ("-" * 80) + "\n")

    map_rows: List[Sequence[Any]] = [
        (
            "ID",
            CellFormat("BPF_MAP", "^"),
            CellFormat("BPF_MAP_TYPE", "^"),
            CellFormat("MAP_FLAGS", "^"),
        )
    ]

    for bpf_map in bpf_map_for_each(prog):
        map_id = bpf_map.id.value_()
        map_addr = f"{bpf_map.value_():#016x}"

        bpf_map_type = prog.type("enum bpf_map_type")
        map_type = bpf_map.map_type.value_()

        map_type_name = ""
        if bpf_map_type.enumerators:
            for name, value in bpf_map_type.enumerators:
                if value == map_type:
                    map_type_name = name
        map_type_name = map_type_name.split("BPF_MAP_TYPE_")[-1]

        try:
            map_flags = f"{bpf_map.map_flags.value_():08x}"
        except LookupError:
            map_flags = "00000000"

        map_rows.append(
            (
                map_id,
                CellFormat(map_addr, "^"),
                CellFormat(map_type_name, "^"),
                CellFormat(map_flags, "^"),
            )
        )

    print_table(map_rows)
