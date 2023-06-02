# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import drgn
from drgn import NULL, Object, cast, container_of, execscript, offsetof, reinterpret, sizeof
from drgn.helpers.common import *
from drgn.helpers.linux import *
import collections
import sys

"""Btrfs Tree Mod Log rewind simulator"""

# you can get a tree mod log from fs_info.tree_mod_log

# search for tree mod log entries for the given offset and minimum sequence
# returns a sorted list of matching entries.
def tree_mod_log_search(tml, start, min_seq):
    es = collections.defaultdict(list)
    for e in rbtree_inorder_for_each_entry("struct tree_mod_elem", tml, "node"):
        es[int(e.logical)].append((int(e.seq), e))
    return [p[1] for p in sorted(es[start]) if p[0] >= min_seq]

# apply the tree mod log entries returned by tree_mod_log_search
# in reverse to a model of a blank extent_buffer. Pay extra attention
# to a particular slot.
def tree_mod_log_rewind(tmes, my_slot):
    eb_rewind = {}
    for tme in reversed(tmes):
        print(tme)
        op = int(tme.op)
        slot = int(tme.slot)
        # replace
        if op == 0:
            if slot == my_slot:
                print(f"writing {tme} into {my_slot}!")
            eb_rewind[slot] = (tme.blockptr, tme.generation, tme.key)
        # add
        if op == 1:
            if slot == my_slot:
                print(f"nuking {my_slot}!")
            del(eb_rewind[slot])
        # remove
        if op in [2,3,4]:
            if slot == my_slot:
                print(f"writing {tme} into {my_slot}!")
            eb_rewind[slot] = (int(tme.blockptr), int(tme.generation), tme.key)
        # move
        if op == 5:
            src_slot = int(tme.move.dst_slot)
            nr = int(tme.move.nr_items)
            off = 0
            for src in range(src_slot, src_slot+nr):
                if src in eb_rewind:
                    if slot + off == my_slot:
                        print(f"moving {eb_rewind[src]} into {my_slot}!")
                    eb_rewind[slot + off] = eb_rewind[src]
                else:
                    if slot + off == my_slot:
                        print(f"moving garbage into {my_slot}!")
                    eb_rewind[slot + off] = (0,0,(0,0,0))
                off += 1
    return eb_rewind

# compare the slots of a real eb and a rewound eb
# parsed_eb is the output of 'parse_extent_buffer' in btrfs.py
def diff_eb_rewind(parsed_eb, eb_rewind):
    ebptrs = parsed_eb.ptrs
    mismatch = False
    for i, ptr in enumerate(ebptrs):
        if i in eb_rewind:
            if ptr.blockptr != eb_rewind[i][0]:
                mismatch = True
                print(f"EB {i}: {ptr.blockptr} EB_REWIND {i}: {eb_rewind[i][0]}")
        elif ptr.blockptr != 0 and ptr.blockptr < 1 << 41:
            mismatch = True
            print(f"EB ONLY {i}: {ptr.blockptr}")
    return mismatch
