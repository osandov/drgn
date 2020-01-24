"""List all BPF maps or programs"""

import sys

from drgn.helpers import enum_type_to_class
from drgn.helpers.linux import bpf_map_for_each, bpf_prog_for_each


BpfMapType = enum_type_to_class(prog.type("enum bpf_map_type"), "BpfMapType")
BpfProgType = enum_type_to_class(prog.type("enum bpf_prog_type"), "BpfProgType")


if "prog".startswith(sys.argv[-1]):
    for prog in bpf_prog_for_each(prog):
        id_ = prog.aux.id.value_()
        type_ = BpfProgType(prog.type).name
        name_ = prog.aux.name.string_().decode()
        print("{:>6}: {:37} name {}".format(id_, type_, name_))
elif "map".startswith(sys.argv[-1]):
    for map_ in bpf_map_for_each(prog):
        id_ = map_.id.value_()
        type_ = BpfMapType(map_.map_type).name
        name_ = map_.name.string_().decode()
        print("{:>6}: {:37} name {}".format(id_, type_, name_))
else:
    print("Usage: {} {{ prog | map }}".format(sys.argv[0]))
