// SPDX-License-Identifier: GPL-2.0
/*
 * walk_task - "task" walker: emit the address of every task_struct.
 *
 * This is the traversal behind drgn's for_each_task(), moved into the kernel.
 * The seq "task" iterator (BPF_TRACE_ITER, available since Linux 5.10) drives
 * the program once per task; we emit just the task_struct address into the
 * `refs` ring buffer. The whole enumeration costs one user<->kernel crossing
 * (one read()-to-EOF on the iterator fd) instead of one per task.
 *
 * pid 0 (the per-CPU idle/swapper tasks) is skipped to match drgn's
 * for_each_task(idle=False), which enumerates via the PID idr and therefore
 * excludes them; the caller adds idle tasks separately when asked.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpfwalk_abi.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024 /* 8 MiB ~ 1M refs */);
} refs SEC(".maps");

SEC("iter/task")
int walk_task(struct bpf_iter__task *ctx)
{
	struct task_struct *t = ctx->task;
	struct bw_ref *r;

	if (!t)			/* final call: end of iteration */
		return 0;
	if (BPF_CORE_READ(t, pid) == 0)	/* skip idle/swapper (see file header) */
		return 0;

	r = bpf_ringbuf_reserve(&refs, sizeof(*r), 0);
	if (!r)
		return 0;
	r->addr = (unsigned long long)(long)t;
	bpf_ringbuf_submit(r, 0);
	return 0;
}
