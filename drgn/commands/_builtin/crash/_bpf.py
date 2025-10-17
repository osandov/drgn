# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

# ebpf-related commands.

import argparse
from typing import Any, Generator, Optional, Tuple

from drgn import Program
from drgn.commands.crash import crash_command
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux import (  # type: ignore[attr-defined]
    bpf_map_for_each,
    bpf_prog_for_each,
    hlist_for_each_entry,
)


class BpfProg(object):
    def __init__(
        self,
        bpf_prog: Any,
        BpfProgType: Any,
        BpfMapType: Any,
        BpfAttachType: Any,
        BpfLinkType: Any,
        BpfProgTrampType: Any,
    ) -> None:
        self.prog = bpf_prog
        self.BpfProgType = BpfProgType
        self.BpfMapType = BpfMapType
        self.BpfAttachType = BpfAttachType
        self.BpfLinkType = BpfLinkType
        self.BpfProgTrampType = BpfProgTrampType

    def is_subprog(self) -> bool:
        return self.prog.aux.func_idx.value_() != 0

    @staticmethod
    def __get_btf_name(btf: Any, btf_id: int) -> str:
        type_ = btf.types[btf_id]
        if type_.name_off < btf.hdr.str_len:
            return btf.strings[type_.name_off].address_of_().string_().decode()
        return ""

    def get_btf_name(self) -> str:
        aux = self.prog.aux
        if aux.btf:
            return self.__get_btf_name(aux.btf, aux.func_info[0].type_id)
        return ""

    def get_ksym_name(self) -> str:
        try:
            ksym = self.prog.aux.member_("ksym")
            return ksym.name.string_().decode()[26:]
        except LookupError:
            return ""

    def get_prog_name(self) -> str:
        if self.is_subprog():
            return self.get_ksym_name() or self.prog.aux.name.string_().decode()
        return self.get_btf_name() or self.prog.aux.name.string_().decode()

    def get_used_maps(self) -> Generator["BpfMap", None, None]:
        for i in range(0, self.prog.aux.used_map_cnt.value_()):
            yield BpfMap(self.prog.aux.used_maps[i], self.BpfProgType, self.BpfMapType)

    def get_subprogs(self) -> Generator[Tuple[int, "BpfProg"], None, None]:
        for i in range(0, self.prog.aux.func_cnt.value_()):
            yield i, BpfProg(
                self.prog.aux.func[i],
                self.BpfProgType,
                self.BpfMapType,
                self.BpfAttachType,
                self.BpfLinkType,
                self.BpfProgTrampType,
            )

    def get_attach_func(self) -> str:
        try:
            func_ = self.prog.aux.attach_func_name
            if func_:
                return func_.string_().decode()
        except LookupError:
            pass

        return ""

    def get_tramp_progs(self) -> Optional[Generator[Any, None, None]]:
        try:
            # Trampoline was changed to dst_trampoline since Linux kernel commit
            # 3aac1ead5eb6 ("bpf: Move prog->aux->linked_prog and trampoline into
            # bpf_link on attach") (in v5.10).
            # Try to get dst_trampoline first.
            tr = self.prog.aux.member_("dst_trampoline")
        except LookupError:
            tr = None

        try:
            tr = self.prog.aux.member_("trampoline") if not tr else tr
        except LookupError:
            # Trampoline is available since Linux kernel commit
            # fec56f5890d9 ("bpf: Introduce BPF trampoline") (in v5.5).
            # Skip trampoline if current kernel doesn't support it.
            return None

        return BpfTramp(tr).get_progs()

    def get_tag_hex(self) -> str:
        try:
            tag = self.prog.tag
            return "".join([f"{b.value_():02x}" for b in tag])
        except LookupError:
            return "0" * 16

    def get_used_map_ids(self) -> str:
        map_ids = []
        try:
            if self.prog.aux.used_map_cnt.value_() > 0:
                for i in range(0, self.prog.aux.used_map_cnt.value_()):
                    map_ids.append(str(self.prog.aux.used_maps[i].id.value_()))
        except LookupError:
            return ""

        return ",".join(map_ids)

    def __repr__(self) -> str:
        id_ = self.prog.aux.id.value_()
        type_ = self.BpfProgType(self.prog.type).name
        name = self.get_prog_name()
        try:
            tail_call_reachable = self.prog.aux.member_("tail_call_reachable").value_()
        except LookupError:
            tail_call_reachable = None

        tail_call_desc = " tail_call_reachable" if tail_call_reachable else ""

        return f"{id_:>6}: {type_:32} {name:32}{tail_call_desc}"


class BpfTramp(object):
    def __init__(self, tr: Any) -> None:
        self.tr = tr

    def get_progs(self) -> Generator[Any, None, None]:
        if not self.tr:
            return

        if self.tr.extension_prog:
            yield self.tr.extension_prog
            return

        try:
            for head in self.tr.progs_hlist:
                for tramp_aux in hlist_for_each_entry(
                    "struct bpf_prog_aux", head, "tramp_hlist"
                ):
                    yield tramp_aux.prog
        except LookupError:
            return


class BpfMap(object):
    def __init__(self, bpf_map: Any, BpfProgType: Any, BpfMapType: Any) -> None:
        self.map = bpf_map
        self.BpfMapType = BpfMapType
        self.BpfProgType = BpfProgType

    def inspect_owner(self, owner: Any) -> str:
        type_ = self.BpfProgType(owner.type).name
        jited = " JITed" if owner.jited.value_() else ""
        return f"{type_:32}{jited}"

    def get_owner(self) -> str:
        try:
            owner = self.map.member_("owner")
            return self.inspect_owner(owner)
        except LookupError:
            return ""

    def get_map_flags_hex(self) -> str:
        try:
            # Map flags are u32, print as 8-digit hex
            return f"{self.map.map_flags.value_():08x}"
        except LookupError:
            return "00000000"

    def __repr__(self) -> str:
        id_ = self.map.id.value_()
        type_ = self.BpfMapType(self.map.map_type).name
        name = self.map.name.string_().decode()

        return f"{id_:>6}: {type_:32} {name:32}"


@crash_command(
    description="display all eBPF programs and maps",
)
def _crash_cmd_bpf(
    prog: Program, name: str, args: argparse.Namespace, **kwargs: Any
) -> None:
    BpfMapType = enum_type_to_class(prog.type("enum bpf_map_type"), "BpfMapType")
    BpfProgType = enum_type_to_class(prog.type("enum bpf_prog_type"), "BpfProgType")
    BpfAttachType = enum_type_to_class(
        prog.type("enum bpf_attach_type"), "BpfAttachType"
    )
    BpfLinkType = enum_type_to_class(prog.type("enum bpf_link_type"), "BpfLinkType")
    BpfProgTrampType = enum_type_to_class(
        prog.type("enum bpf_tramp_prog_type"), "BpfProgTrampType"
    )

    print(
        f"{'ID':>4}  {'BPF_PROG':<18} {'BPF_PROG_AUX':<18} {'BPF_PROG_TYPE':<18} "
        f"{'TAG':<18} {'USED_MAPS'}"
    )

    for bpf_prog_ in bpf_prog_for_each(prog):
        bpf_prog = BpfProg(
            bpf_prog_,
            BpfProgType,
            BpfMapType,
            BpfAttachType,
            BpfLinkType,
            BpfProgTrampType,
        )

        prog_id = bpf_prog.prog.aux.id.value_()
        prog_addr = f"{bpf_prog.prog.value_():#016x}"
        aux_addr = f"{bpf_prog.prog.aux.value_():#016x}"
        prog_type_name = bpf_prog.BpfProgType(bpf_prog.prog.type).name.split(
            "BPF_PROG_TYPE_"
        )[-1]
        prog_tag = bpf_prog.get_tag_hex()
        used_maps = bpf_prog.get_used_map_ids()

        print(
            f"{prog_id:>4}  {prog_addr:<18} {aux_addr:<18} {prog_type_name:<18} "
            f"{prog_tag:<18} {used_maps}"
        )

        linked_progs = bpf_prog.get_tramp_progs()
        if linked_progs:
            for linked_prog in linked_progs:
                linked = BpfProg(
                    linked_prog,
                    BpfProgType,
                    BpfMapType,
                    BpfAttachType,
                    BpfLinkType,
                    BpfProgTrampType,
                )
                print(f"{'':>6}  -> linked: {linked}")

        for index, subprog in bpf_prog.get_subprogs():
            print(f"{'':>6}  -> func[{index:02}]: {subprog}")

    print("\n" + ("-" * 80) + "\n")

    print(f"{'ID':>4}  {'BPF_MAP':<18} {'BPF_MAP_TYPE':<20} {'MAP_FLAGS'}")

    for bpf_map_ in bpf_map_for_each(prog):
        bpf_map = BpfMap(bpf_map_, BpfProgType, BpfMapType)

        map_id = bpf_map.map.id.value_()
        map_addr = f"{bpf_map.map.value_():#016x}"
        map_type_name = bpf_map.BpfMapType(bpf_map.map.map_type).name.split(
            "BPF_MAP_TYPE_"
        )[-1]
        map_flags = bpf_map.get_map_flags_hex()

        print(f"{map_id:>4}  {map_addr:<18} {map_type_name:<20} {map_flags}")
