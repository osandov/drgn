#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse

from drgn import container_of
from drgn.helpers import enum_type_to_class
from drgn.helpers.linux import (
    bpf_btf_for_each,
    bpf_link_for_each,
    bpf_map_for_each,
    bpf_prog_for_each,
    hlist_for_each_entry,
)

try:
    BpfLinkType = enum_type_to_class(prog.type("enum bpf_link_type"), "BpfLinkType")
except LookupError:
    BpfLinkType = None

BpfMapType = enum_type_to_class(prog.type("enum bpf_map_type"), "BpfMapType")
BpfProgType = enum_type_to_class(prog.type("enum bpf_prog_type"), "BpfProgType")
BpfAttachType = enum_type_to_class(prog.type("enum bpf_attach_type"), "BpfAttachType")


def get_btf_name(btf, btf_id):
    type_ = btf.types[btf_id]
    if type_.name_off < btf.hdr.str_len:
        return btf.strings[type_.name_off].address_of_().string_().decode()
    return ""


def get_prog_btf_name(bpf_prog):
    aux = bpf_prog.aux
    if aux.btf:
        # func_info[0] points to BPF program function itself.
        return get_btf_name(aux.btf, aux.func_info[0].type_id)
    return ""


def get_prog_name(bpf_prog):
    return get_prog_btf_name(bpf_prog) or bpf_prog.aux.name.string_().decode()


def attach_type_to_tramp(attach_type):
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


def get_linked_func(bpf_prog, linked_prog):
    kind = attach_type_to_tramp(bpf_prog.expected_attach_type)

    linked_prog_id = linked_prog.aux.id.value_()
    linked_btf_id = bpf_prog.aux.attach_btf_id.value_()
    linked_name = (
        f"{get_prog_name(linked_prog)}->"
        f"{get_btf_name(linked_prog.aux.btf, linked_btf_id)}()"
    )

    return f"{linked_prog_id}->{linked_btf_id}: {kind.name} {linked_name}"


def get_progs_from_tramp(trampoline):
    if not tr:
        return

    if tr.extension_prog:
        yield tr.extension_prog
    else:
        for head in tr.progs_hlist:
            for tramp_aux in hlist_for_each_entry(
                "struct bpf_prog_aux", head, "tramp_hlist"
            ):
                yield tramp_aux.prog


def get_progs_from_tracing_link(bpf_prog):
    for link in bpf_link_for_each(prog):
        if link.prog.aux.id.value_() == bpf_prog.aux.id.value_():
            tr_link = container_of(link, "struct bpf_tracing_link", "link")
            if tr_link and tr_link.tgt_prog:
                yield tr_link.tgt_prog


def get_tramp_progs(bpf_prog):
    # dst_rampoline replaces "trampoline" since Linux kernel commit
    # 3aac1ead5eb6 ("bpf: Move prog->aux->linked_prog and trampoline into
    # bpf_link on attach") (in v5.10).
    try:
        tramp = bpf_prog.aux.member_("dst_trampoline")
        if tramp:
            yield from get_progs_from_tramp(tramp)
        else:
            yield from get_progs_from_tracing_link(bpf_prog)
    except LookupError:
        # Before that, "trampoline" is available since Linux kernel commit
        # fec56f5890d9 ("bpf: Introduce BPF trampoline") (in v5.5).
        try:
            tramp = bpf_prog.aux.member_("trampoline")
        except LookupError:
            # This kernel doesn't support trampolines at all.
            return
        yield from get_progs_from_tramp(tramp)


def list_bpf_progs(args):
    for bpf_prog in bpf_prog_for_each(prog):
        id_ = bpf_prog.aux.id.value_()
        type_ = BpfProgType(bpf_prog.type).name
        name = get_prog_name(bpf_prog)

        progs = []
        for p in get_tramp_progs(bpf_prog):
            try:
                linked_prog = p.aux.member_("linked_prog")
                caller_prog = p
            except LookupError:
                # Linux 5.10+
                linked_prog = p
                caller_prog = bpf_prog
            progs.append(get_linked_func(caller_prog, linked_prog))

        linked = ", ".join(progs)
        if linked:
            linked = f" linked:[{linked}]"

        print(f"{id_:>6}: {type_:32} {name:32} {linked}")


def list_bpf_maps(args):
    for map_ in bpf_map_for_each(prog):
        id_ = map_.id.value_()
        type_ = BpfMapType(map_.map_type).name
        name = map_.name.string_().decode()

        print(f"{id_:>6}: {type_:32} {name}")


def list_bpf_btf(args):
    for btf in bpf_btf_for_each(prog):
        id_ = btf.id.value_()
        name = btf.name.string_().decode() or "<anon>"
        kernel = "kernel" if btf.kernel_btf.value_() == 1 else ""

        print(f"{id_:>6}: {kernel:6} {name}")


def list_bpf_links(args):
    if BpfLinkType is None:
        # BpfLinkType was not initialized properly, likely because the kernel
        # is too old to support link. So there is no link to list, simply
        # return.
        return

    for link in bpf_link_for_each(prog):
        id_ = link.id.value_()
        type_ = BpfLinkType(link.type).name
        prog_id = ""
        if link.prog:
            prog_id = link.prog.aux.id.value_()

        print(f"{id_:>6}: {type_:32} {prog_id:>6}")


def main():
    parser = argparse.ArgumentParser(
        description="drgn script to list BPF objects and their properties unavailable via kernel API"
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")
    subparsers.required = True

    prog_parser = subparsers.add_parser("prog", aliases=["p"], help="list BPF programs")
    prog_parser.set_defaults(func=list_bpf_progs)

    map_parser = subparsers.add_parser("map", aliases=["m"], help="list BPF maps")
    map_parser.set_defaults(func=list_bpf_maps)

    link_parser = subparsers.add_parser("link", aliases=["l"], help="list BPF links")
    link_parser.set_defaults(func=list_bpf_links)

    btf_parser = subparsers.add_parser("btf", aliases=["b"], help="list BTF objects")
    btf_parser.set_defaults(func=list_bpf_btf)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
