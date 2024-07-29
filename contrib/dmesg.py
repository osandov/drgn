#!/usr/bin/env drgn
# Copyright (c) Canonical Ltd.
# SPDX-License-Identifier: LGPL-2.1-or-later

""" Script to dump kernel log using drgn """

desc_ring = prog["prb"].desc_ring
text_data_ring = prog["prb"].text_data_ring

descs_count = 1 << desc_ring.count_bits
descs = desc_ring.descs
infos = desc_ring.infos

data_size = 1 << text_data_ring.size_bits
data = text_data_ring.data

desc_committed = prog.type("enum desc_state").enumerators[2].value
desc_finalized = prog.type("enum desc_state").enumerators[3].value

tail_id = desc_ring.tail_id.counter
head_id = desc_ring.head_id.counter

DESC_SV_BITS = prog.type("unsigned long").size * 8
DESC_FLAGS_SHIFT = DESC_SV_BITS - 2
DESC_FLAGS_MASK = 3 << DESC_FLAGS_SHIFT
DESC_ID_MASK = ~DESC_FLAGS_MASK


def DESC_STATE(sv):
    return 3 & (sv >> DESC_FLAGS_SHIFT)


cur_id = tail_id
while True:
    i = cur_id % descs_count
    state = DESC_STATE(descs[i].state_var.counter)
    if state != desc_committed and state != desc_finalized:
        if cur_id == head_id:
            break
        cur_id = (cur_id + 1) & DESC_ID_MASK
        continue
    begin = descs[i].text_blk_lpos.begin % data_size
    end = descs[i].text_blk_lpos.next % data_size

    if begin & 1 == 1:
        text = ""
    else:
        if begin > end:
            begin = 0
        text_start = begin + prog.type("unsigned long").size
        text_len = infos[i].text_len

        if end - text_start < text_len:
            text_len = end - text_start
        text = data[text_start].address_of_().string_()[0:text_len].decode("utf8")
    time_stamp = infos[i].ts_nsec
    for line in text.splitlines():
        time = (time_stamp / 1000000000.0).value_()
        print(f"[{time:12.6f}] {line}")
    if cur_id == head_id:
        break
    cur_id = (cur_id + 1) & DESC_ID_MASK
