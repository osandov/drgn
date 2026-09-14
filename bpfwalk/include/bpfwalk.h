/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * bpfwalk - in-kernel traversal offload for structure-walking helpers.
 *
 * A drgn helper that enumerates a kernel data structure (for_each_task, slab
 * caches, an xarray, a list, ...) normally walks it in userspace, one memory
 * read per element. bpfwalk lets the whole traversal run in-kernel inside a
 * single BPF iterator invocation and returns the enumerated addresses in O(1)
 * user<->kernel crossings. Type interpretation stays with the caller.
 *
 * A session loads walker programs; a cursor drives one named walker and streams
 * its results in batches. This is the C surface that language bindings (drgn's
 * ctypes wrapper) call. Everything is best-effort: if bpfwalk can't run here
 * (no BPF privilege, unsupported kernel, missing object), the entry points fail
 * cleanly and the caller falls back to its own implementation.
 */
#ifndef BPFWALK_H
#define BPFWALK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bpfwalk;
struct bpfwalk_cursor;

/* Open a session. Returns NULL only on allocation failure; per-walker
 * availability is reported by bpfwalk_has(). */
struct bpfwalk *bpfwalk_open(void);
void bpfwalk_close(struct bpfwalk *bw);

/* Whether the named walker can run in this session (its object loads). This is
 * the gate a caller checks before committing to the fast path. */
int bpfwalk_has(struct bpfwalk *bw, const char *walker);

/* Open a cursor over the named walker. args/args_len carry walker-specific
 * inputs (NULL/0 for parameterless walkers such as "task"). Returns NULL if the
 * walker is unknown or fails to start. */
struct bpfwalk_cursor *bpfwalk_walk_open(struct bpfwalk *bw, const char *walker,
					 const void *args, size_t args_len);

/* Fetch the next batch: up to `max` fixed-size records of `rec_size` bytes into
 * `buf`. For the baseline contract rec_size == 8 and each record is a uint64_t
 * address. Returns the count copied, 0 at end of iteration, or <0 on error. */
int bpfwalk_walk_next(struct bpfwalk_cursor *c, void *buf, size_t rec_size,
		      size_t max);

void bpfwalk_walk_close(struct bpfwalk_cursor *c);

#ifdef __cplusplus
}
#endif

#endif /* BPFWALK_H */
