#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""List BPF programs or maps and their properties unavailable via kernel API."""

import sys
import drgn
import argparse

from drgn import container_of
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux import (
    bpf_map_for_each,
    bpf_prog_for_each,
    bpf_link_for_each,
    list_for_each_entry,
    hlist_for_each_entry,
)

BpfMapType = enum_type_to_class(prog.type("enum bpf_map_type"), "BpfMapType")
BpfProgType = enum_type_to_class(prog.type("enum bpf_prog_type"), "BpfProgType")
BpfAttachType = enum_type_to_class(prog.type("enum bpf_attach_type"), "BpfAttachType")
BpfLinkType = enum_type_to_class(prog.type("enum bpf_link_type"), "BpfLinkType")


def bpf_attach_type_to_tramp(attach_type):
    # bpf_tramp_prog_type is available since linux kernel 5.5, this code should
    # be called only after checking for bpf_prog.aux.trampoline to be present
    # though so no error checking here.
    BpfProgTrampType = enum_type_to_class(
        prog.type("enum bpf_tramp_prog_type"), "BpfProgTrampType"
    )

    at = BpfAttachType(attach_type)

    if at == BpfAttachType.BPF_TRACE_FENTRY:
        return BpfProgTrampType.BPF_TRAMP_FENTRY

    if at == BpfAttachType.BPF_TRACE_FEXIT:
        return BpfProgTrampType.BPF_TRAMP_FEXIT

    return BpfProgTrampType.BPF_TRAMP_REPLACE


class BpfTramp(object):
    def __init__(self, tr):
        self.tr = tr

    def get_progs(self):
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
    def __init__(self, bpf_map):
        self.map = bpf_map

    @staticmethod
    def inspect_owner(owner):
        type_ = BpfProgType(owner.type).name
        jited = " JITed" if owner.jited.value_() else ""
        return f"{type_:32}{jited}"

    def get_owner(self):
        try:
            owner = self.map.member_("owner")
            return self.inspect_owner(owner)
        except LookupError:
            return ""

    def __repr__(self):
        id_ = self.map.id.value_()
        type_ = BpfMapType(self.map.map_type).name
        name = self.map.name.string_().decode()

        return f"{id_:>6}: {type_:32} {name:32}"


class BpfProg(object):
    def __init__(self, bpf_prog):
        self.prog = bpf_prog

    def is_subprog(self):
        return self.prog.aux.func_idx.value_() != 0

    @staticmethod
    def __get_btf_name(btf, btf_id):
        type_ = btf.types[btf_id]
        if type_.name_off < btf.hdr.str_len:
            return btf.strings[type_.name_off].address_of_().string_().decode()
        return ""

    def get_btf_name(self):
        aux = self.prog.aux
        if aux.btf:
            # func_info[0] points to BPF program function itself.
            return self.__get_btf_name(aux.btf, aux.func_info[0].type_id)
        return ""

    def get_ksym_name(self):
        try:
            ksym = self.prog.aux.member_("ksym")
            return ksym.name.string_().decode()[26:]
        except LookupError:
            return ""

    def get_prog_name(self):
        if self.is_subprog():
            return self.get_ksym_name() or self.prog.aux.name.string_().decode()
        return self.get_btf_name() or self.prog.aux.name.string_().decode()

    def get_used_maps(self):
        for i in range(0, self.prog.aux.used_map_cnt.value_()):
            yield BpfMap(self.prog.aux.used_maps[i])

    def get_subprogs(self):
        for i in range(0, self.prog.aux.func_cnt.value_()):
            yield i, BpfProg(self.prog.aux.func[i])

    def get_linked_func(self):
        kind = bpf_attach_type_to_tramp(self.prog.expected_attach_type)

        linked_prog = self.prog.aux.linked_prog
        linked_prog_id = linked_prog.aux.id.value_()
        linked_btf_id = self.prog.aux.attach_btf_id.value_()

        linked_name = (
            f"{BpfProg(linked_prog).get_prog_name()}->"
            f"{self.__get_btf_name(linked_prog.aux.btf, linked_btf_id)}()"
        )

        return f"{linked_prog_id}->{linked_btf_id}: {kind.name} {linked_name}"

    def get_attach_func(self):
        try:
            func_ = self.prog.aux.attach_func_name
            if func_:
                return func_.string_().decode()
        except LookupError:
            pass

        return ""

    def get_tramp_progs(self):
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
            return

        return BpfTramp(tr).get_progs()

    def __repr__(self):
        id_ = self.prog.aux.id.value_()
        type_ = BpfProgType(self.prog.type).name
        name = self.get_prog_name()
        tail_call_reachable = self.prog.aux.tail_call_reachable.value_()

        tail_call_desc = " tail_call_reachable" if tail_call_reachable else ""

        return f"{id_:>6}: {type_:32} {name:32}{tail_call_desc}"


def list_bpf_progs(show_details=False):
    for bpf_prog_ in bpf_prog_for_each(prog):
        bpf_prog = BpfProg(bpf_prog_)
        print(f"{bpf_prog}")

        if not show_details:
            continue

        linked_progs = bpf_prog.get_tramp_progs()
        if linked_progs:
            for linked_prog in linked_progs:
                print(f"\tlinked: {BpfProg(linked_prog)}")

        for map_ in bpf_prog.get_used_maps():
            print(f"\t{'used map:':9} {map_}")

        for index, subprog in bpf_prog.get_subprogs():
            print(f"\t{f'func[{index:>2}]:':9} {subprog}")


def __list_bpf_progs(args):
    list_bpf_progs(args.show_details)


class BpfProgArrayMap(BpfMap):
    def __init__(self, bpf_map):
        super().__init__(bpf_map)
        self.prog_array = container_of(bpf_map, "struct bpf_array", "map")

    def get_owner(self):
        try:
            owner = self.prog_array.aux.member_("owner")
            return super().inspect_owner(owner)
        except LookupError:
            return ""

    def get_prog_array(self):
        for i in range(0, self.map.max_entries):
            prog_ = self.prog_array.ptrs[i]
            if prog_:
                yield i, drgn.cast("struct bpf_prog *", prog_)

    def get_poke_progs(self):
        for poke in list_for_each_entry(
            "struct prog_poke_elem",
            self.prog_array.aux.poke_progs.address_of_(),
            "list",
        ):
            yield poke.aux.prog

    def __repr__(self):
        owner = self.get_owner()
        owner = super().get_owner() if not owner else owner
        array = self.get_prog_array()
        poke_progs = self.get_poke_progs()

        owner_str = f"{'owner:':9} {owner}" if owner else ""
        array_str = (
            "\n\t".join(
                f"{f'idx[{index:>3}]:':9} {BpfProg(prog)}" for index, prog in array
            )
            if array
            else ""
        )
        poke_progs_str = (
            "\n\t".join(f"{'poke:':9} {BpfProg(poke)}" for poke in poke_progs)
            if poke_progs
            else ""
        )

        return "\n\t".join(x for x in [owner_str, array_str, poke_progs_str] if x)


def show_bpf_map_details(bpf_map):
    if bpf_map.map_type == BpfMapType.BPF_MAP_TYPE_PROG_ARRAY:
        r = BpfProgArrayMap(bpf_map).__repr__()
    else:
        r = None

    if r:
        print(f"\t{r}")


def list_bpf_maps(show_details=False):
    for map_ in bpf_map_for_each(prog):
        bpf_map = BpfMap(map_)
        print(f"{bpf_map}")

        if show_details:
            show_bpf_map_details(map_)


def __list_bpf_maps(args):
    list_bpf_maps(args.show_details)


class BpfLink(object):
    def __init__(self, bpf_link):
        self.link = bpf_link

    def __repr__(self):
        id_ = self.link.id.value_()
        type_ = BpfLinkType(self.link.type).name

        return f"{id_:>6}: {type_:32}"


class BpfTracingLink(BpfLink):
    def __init__(self, link):
        super().__init__(link)
        self.tracing = drgn.cast("struct bpf_tracing_link *", link)

    def get_tgt_prog(self):
        return self.tracing.tgt_prog

    def get_linked_progs(self):
        return BpfTramp(self.tracing.trampoline).get_progs()

    def __repr__(self):
        tgt_prog = self.get_tgt_prog()
        linked_progs = self.get_linked_progs()

        tgt_prog_str = f"target: {BpfProg(tgt_prog)}" if tgt_prog else ""
        linked_progs_str = (
            "\n".join(f"linked: {BpfProg(linked_prog)}" for linked_prog in linked_progs)
            if linked_progs
            else ""
        )

        return "\n\t".join(x for x in [tgt_prog_str, linked_progs_str] if x)


class BpfXdpLink(BpfLink):
    def __init__(self, link):
        super().__init__(link)
        self.xdp = drgn.cast("struct bpf_xdp_link *", link)

    def get_dev(self):
        return self.xdp.dev

    XDP_FLAGS_SKB_MODE = 1 << 1
    XDP_FLAGS_DRV_MODE = 1 << 2
    XDP_FLAGS_HW_MODE = 1 << 3

    def get_mode(self):
        flags = self.xdp.flags.value_()
        if flags & self.XDP_FLAGS_HW_MODE:
            return "HARDWARE"
        if flags & self.XDP_FLAGS_DRV_MODE:
            return "DRIVER"
        if flags & self.XDP_FLAGS_SKB_MODE:
            return "GENERIC"
        return "UNKNOWN"

    def __repr__(self):
        dev = self.get_dev()
        mode = self.get_mode()

        ifname, ifindex = dev.name.string_().decode(), dev.ifindex.value_()
        return f"{'netdev:':<9} {ifname}({ifindex})" + f"\n\t{'mode:':<9} {mode}"


def show_bpf_link_details(link):
    if link.type == BpfLinkType.BPF_LINK_TYPE_TRACING:
        r = BpfTracingLink(link).__repr__()
    elif link.type == BpfLinkType.BPF_LINK_TYPE_XDP:
        r = BpfXdpLink(link).__repr__()
    else:
        r = None

    if r:
        print(f"\t{r}")


def list_bpf_links(show_details=False):
    for link in bpf_link_for_each(prog):
        bpf_link = BpfLink(link)
        print(f"{bpf_link}")

        bpf_prog = BpfProg(link.prog)
        print(f"\tprog:   {bpf_prog}")

        attach_func = bpf_prog.get_attach_func()
        if attach_func:
            print(f"\tattach:   {attach_func}")

        if show_details:
            show_bpf_link_details(link)


def __list_bpf_links(args):
    list_bpf_links(args.show_details)


def __run_interactive(args):
    try:
        from drgn.cli import run_interactive
    except ImportError:
        sys.exit("Interactive mode requires drgn 0.0.23+")

    def should_add_to_globals(name):
        if name.startswith("__"):
            return False
        return "bpf" in name or "Bpf" in name or "btf" in name

    globals_keys = globals().keys()

    def globals_func(globals_):
        for key in globals_keys:
            if should_add_to_globals(key):
                globals_[key] = globals()[key]

        return globals_

    run_interactive(prog, globals_func=globals_func)


def main():
    parser = argparse.ArgumentParser(
        description="drgn script to list BPF programs or maps and their properties unavailable via kernel API"
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")
    subparsers.required = True

    prog_parser = subparsers.add_parser("prog", aliases=["p"], help="list BPF programs")
    prog_parser.set_defaults(func=__list_bpf_progs)
    prog_parser.add_argument(
        "--show-details", action="store_true", help="show program internal details"
    )

    map_parser = subparsers.add_parser("map", aliases=["m"], help="list BPF maps")
    map_parser.set_defaults(func=__list_bpf_maps)
    map_parser.add_argument(
        "--show-details", action="store_true", help="show map internal details"
    )

    link_parser = subparsers.add_parser("link", aliases=["l"], help="list BPF links")
    link_parser.set_defaults(func=__list_bpf_links)
    link_parser.add_argument(
        "--show-details", action="store_true", help="show link internal details"
    )

    interact_parser = subparsers.add_parser(
        "interact", aliases=["i"], help="start interactive shell, requires 0.0.23+ drgn"
    )
    interact_parser.set_defaults(func=__run_interactive)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
