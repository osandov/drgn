# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# ebpf-related commands.

import argparse
from datetime import datetime
from typing import Any, List, Sequence

from drgn import Program
from drgn.commands import argument, drgn_argument
from drgn.commands._crash.common import CrashDrgnCodeBuilder, crash_command
from drgn.helpers.common.format import (
    CellFormat,
    double_quote_ascii_string,
    escape_ascii_string,
    print_table,
)
from drgn.helpers.linux.bpf import (
    bpf_map_by_id,
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
        argument(
            "-m",
            dest="map_id",
            type=int,
            help="display additional information for the specified BPF map ID",
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
            "bpf_map_by_id",
            "bpf_map_for_each",
            "bpf_prog_by_id",
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

    if args.map_id is not None:

        bpf_map = bpf_map_by_id(prog, args.map_id)
        if not bpf_map:
            print(f"invalid BPF map ID: {args.map_id}")
            return

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

        map_rows: List[Sequence[Any]] = [
            (
                CellFormat("ID", "^"),
                CellFormat("BPF_MAP", "^"),
                CellFormat("BPF_MAP_TYPE", "^"),
                CellFormat("MAP_FLAGS", "^"),
            )
        ]

        map_rows.append(
            (
                map_id,
                CellFormat(bpf_map.value_(), "^x"),
                CellFormat(map_type_name, "^"),
                CellFormat(map_flags, "^"),
            )
        )

        print_table(map_rows)

        key_size = bpf_map.key_size.value_()
        value_size = bpf_map.value_size.value_()
        max_entries = bpf_map.max_entries.value_()

        print(
            f"     KEY_SIZE: {key_size}  VALUE_SIZE: {value_size}  MAX_ENTRIES: {max_entries}",
            end="",
        )

        # The 'name' field was added in Linux kernel commit ad5b177bd73f ("bpf:
        # Add map_name to bpf_map_info") (in v4.15).
        map_name = "(unknown)"
        try:
            name_member = bpf_map.name
        except AttributeError:
            map_name = "(unknown)"
        else:
            raw_name = name_member.string_()
            if raw_name:
                map_name = double_quote_ascii_string(raw_name)
            else:
                map_name = "(unused)"

        uid_str = "(unused)"
        user_ptr = None

        # Linux 5.3 to 5.10: bpf_map.memory.user
        # Commit 3539b96e041c ("bpf: group memory related fields in struct
        # bpf_map_memory") (in v5.3) moved the user field into struct bpf_map_memory.
        # This was removed in v5.11 by commit 80ee81e0403c ("bpf: Eliminate
        # rlimit-based memory accounting infra for bpf maps").
        try:
            user_ptr = bpf_map.memory.user
        except AttributeError:
            # Linux 4.10 to 5.2: bpf_map.user
            # Commit aaac3ba95e4c ("bpf: charge user for creation of BPF maps and
            # programs") (in v4.10) added the user field directly to struct bpf_map.
            # This was moved into struct bpf_map_memory in v5.3.
            try:
                user_ptr = bpf_map.user
            except AttributeError:
                pass

        if user_ptr is not None:
            try:
                uid_val = kuid_val(user_ptr.uid)
                uid_str = str(uid_val)
            except AttributeError:
                uid_str = "(unknown)"

        print(f"     NAME: {map_name}  UID: {uid_str}")

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

    all_map_rows: List[Sequence[Any]] = [
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

        all_map_rows.append(
            (
                map_id,
                CellFormat(bpf_map.value_(), "^x"),
                CellFormat(map_type_name, "^"),
                CellFormat(map_flags, "^"),
            )
        )

    print_table(all_map_rows)
