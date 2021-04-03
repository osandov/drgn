#!/usr/bin/env drgn
# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

DESCRIPTION = """
drgn script to list BPF programs or maps and their properties
unavailable via kernel API.
"""

import argparse
import sys

from drgn.helpers import enum_type_to_class
from drgn.helpers.linux import bpf_map_for_each, bpf_prog_for_each, hlist_for_each_entry

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


def get_linked_func(bpf_prog):
    kind = attach_type_to_tramp(bpf_prog.expected_attach_type)

    linked_prog = bpf_prog.aux.linked_prog
    linked_prog_id = linked_prog.aux.id.value_()
    linked_btf_id = bpf_prog.aux.attach_btf_id.value_()
    linked_name = (
        f"{get_prog_name(linked_prog)}->"
        f"{get_btf_name(linked_prog.aux.btf, linked_btf_id)}()"
    )

    return f"{linked_prog_id}->{linked_btf_id}: {kind.name} {linked_name}"


def get_tramp_progs(bpf_prog):
    try:
        tr = bpf_prog.aux.member_("trampoline")
    except LookupError:
        # Trampoline is available since Linux kernel commit
        # fec56f5890d9 ("bpf: Introduce BPF trampoline") (in v5.5).
        # Skip trampoline if current kernel doesn't support it.
        return

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


def list_bpf_progs(args):
    for bpf_prog in bpf_prog_for_each(prog):
        id_ = bpf_prog.aux.id.value_()
        type_ = BpfProgType(bpf_prog.type).name
        name = get_prog_name(bpf_prog)

        linked = ", ".join([get_linked_func(p) for p in get_tramp_progs(bpf_prog)])
        if linked:
            linked = f" linked:[{linked}]"

        print(f"{id_:>6}: {type_:32} {name:32} {linked}")


def list_bpf_maps(args):
    for map_ in bpf_map_for_each(prog):
        id_ = map_.id.value_()
        type_ = BpfMapType(map_.map_type).name
        name = map_.name.string_().decode()

        print(f"{id_:>6}: {type_:32} {name}")


def main():
    parser = argparse.ArgumentParser(
        description=DESCRIPTION, formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")
    subparsers.required = True

    prog_parser = subparsers.add_parser("prog", aliases=["p"], help="list BPF programs")
    prog_parser.set_defaults(func=list_bpf_progs)

    map_parser = subparsers.add_parser("map", aliases=["m"], help="list BPF maps")
    map_parser.set_defaults(func=list_bpf_maps)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
