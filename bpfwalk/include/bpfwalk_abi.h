/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * bpfwalk ABI: the record contract shared between the BPF walker programs
 * (bpf/walk_*.bpf.c) and the userspace library. Include AFTER vmlinux.h (BPF
 * side) or AFTER <linux/types.h> (userspace side) so __u64 is defined.
 *
 * Baseline walker contract: a walker streams a sequence of bw_ref records, one
 * per node/object/entry it enumerates in-kernel. Turning an address into a
 * typed object is left to the consumer (e.g. drgn Object / container_of), so
 * one walker serves every helper that iterates the same structure.
 */
#ifndef BPFWALK_ABI_H
#define BPFWALK_ABI_H

struct bw_ref {
	__u64 addr;		/* kernel address of the enumerated element */
};

#endif /* BPFWALK_ABI_H */
