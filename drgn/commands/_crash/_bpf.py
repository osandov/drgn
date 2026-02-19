# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# ebpf-related commands.

import argparse
from datetime import datetime
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands._crash.common import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import CellFormat, escape_ascii_string, print_table
from drgn.helpers.linux.bpf import (
    bpf_map_for_each,
    bpf_prog_by_id,
    bpf_prog_for_each,
    bpf_prog_used_maps,
)
from drgn.helpers.linux.timekeeping import (
    ktime_get_coarse_boottime_ns,
    ktime_get_coarse_real_ns,
)
from drgn.helpers.linux.user import kuid_val


@crash_command(
    description="display loaded eBPF programs and maps",
    arguments=(
        argument(
            "-p",
            dest="prog_id",
            type=int,
            help="display additional information for the specified BPF program ID",
        ),
        drgn_argument,
    ),
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

    if args.prog_id is not None:

        bpf_prog = bpf_prog_by_id(prog, args.prog_id)
        if not bpf_prog:
            print(f"invalid BPF program ID: {args.prog_id}")
            return

        aux = bpf_prog.aux
        prog_id = aux.id.value_()
        prog_type_name = bpf_prog.type.format_(type_name=False).split("BPF_PROG_TYPE_")[
            -1
        ]
        PAGE_SIZE = prog["PAGE_SIZE"].value_()
        INSN_SIZE = prog.type("struct bpf_insn").size

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
                CellFormat(aux.value_(), "^x"),
                CellFormat(prog_type_name, "^"),
                CellFormat(prog_tag, "^"),
                CellFormat(used_maps_str, "^"),
            )
        )
        print_table(prog_rows)

        print(
            f"     XLATED: {bpf_prog.len.value_() * INSN_SIZE}  JITED: {bpf_prog.jited_len.value_()}  MEMLOCK: {bpf_prog.pages.value_() * PAGE_SIZE}"
        )

        # load_time and name were added in Linux kernel commit cb4d2b3f03d8 ("bpf:
        # Add name, load_time, uid and map_ids to bpf_prog_info") (in v4.15).
        # Before that, default to "(unknown)".
        try:
            load_time_ns = aux.load_time.value_()
        except AttributeError:
            load_time_str = "(unknown)"
        else:
            current_boottime_ns = ktime_get_coarse_boottime_ns(prog).value_()
            current_realtime_ns = ktime_get_coarse_real_ns(prog).value_()

            elapsed_ns = current_boottime_ns - load_time_ns
            actual_load_time_ns = current_realtime_ns - elapsed_ns
            actual_load_time = datetime.fromtimestamp(actual_load_time_ns / 1e9)
            load_time_str = actual_load_time.strftime("%a %b %d %H:%M:%S %Y")

        print(f"     LOAD_TIME: {load_time_str}")

        gpl_compat = "yes" if bpf_prog.gpl_compatible else "no"
        uid = kuid_val(aux.user.uid)
        try:
            prog_name = escape_ascii_string(aux.name.string_(), escape_backslash=True)
            if not prog_name:
                prog_name = "(unused)"
        except AttributeError:
            prog_name = "(unknown)"

        print(f"     GPL_COMPATIBLE: {gpl_compat}  NAME: {prog_name}  UID: {uid}")

        return

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
