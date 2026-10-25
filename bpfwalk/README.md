# bpfwalk — in-kernel traversal offload for drgn helpers

On a **live** kernel, a drgn helper that enumerates a data structure
(`for_each_task`, slab caches, an xarray, a list, …) walks it in userspace —
one memory read, i.e. one user↔kernel round trip, **per element**. `bpfwalk`
runs the whole traversal **in-kernel** inside a single BPF iterator invocation
and returns the enumerated addresses in *O(1)* crossings. drgn keeps doing the
type interpretation (`Object`, `container_of`); bpfwalk only supplies the
addresses.

It is strictly an accelerator: on a core dump, a remote target, an old kernel,
or without BPF privilege it does nothing and the helper uses its existing
userspace loop unchanged.

## Layout

```
bpfwalk/
  include/
    bpfwalk.h        public C API (session + cursor)          LGPL-2.1
    bpfwalk_abi.h    record contract shared with the BPF side LGPL-2.1
  src/
    bpfwalk.c        session, cursor, and the walker registry LGPL-2.1
  bpf/
    walk_task.bpf.c  the "task" walker                        GPL-2.0
  Makefile           builds build/libbpfwalk.so + build/*.bpf.o
```

The Python side lives in the drgn package:

```
drgn/helpers/linux/_bpfwalk.py         ctypes binding
drgn/helpers/linux/_bpfwalk_accel.py   the gate + bpfwalk_objects()
drgn/helpers/linux/pid.py              for_each_task() fast-path guard
```

## Build

Needs `clang`, `bpftool`, `llvm-strip`, and libbpf headers.

```
make            # -> build/libbpfwalk.so and build/walk_task.bpf.o
```

`vmlinux.h` is generated from `/sys/kernel/btf/vmlinux` at build time (override
with `BTF_SRC=…`); CO-RE relocates the walkers onto other kernels at load.

## Run

Through drgn, transparently — `for_each_task` uses the offload when it can:

```
sudo drgn -k -e 'from drgn.helpers.linux.pid import for_each_task; \
                 print(sum(1 for _ in for_each_task(prog)))'
```

drgn finds the library via `LIBBPFWALK`, else the in-tree
`bpfwalk/build/libbpfwalk.so`, else the linker path. `BPFWALK_DISABLE=1` forces
the userspace fallback.

## Adding a walker

The walkers are a data-driven registry, so a new one is one BPF file plus one
row — no new C types or glue:

1. `bpf/walk_<x>.bpf.c` — enumerate in-kernel, emit one `struct bw_ref { addr }`
   per element into a ring-buffer map. (Parameterless walkers use the seq
   iterator like `walk_task`; parameterized ones take inputs via the cursor
   `args` and can use `BPF_PROG_RUN`.)
2. Add a row to `WALKERS[]` in `src/bpfwalk.c`:
   `{ "<x>", "walk_<x>.bpf.o", "<prog>", "<map>", BW_DRIVE_ITER }`.
3. In the target drgn helper, add the guard:
   ```python
   it = bpfwalk_objects(prog, "<x>", "<ptr type>")
   if it is not None:
       yield from it
       return
   ```

That third step is the whole integration surface; everything else — loading,
driving, batching, fallback — is shared.

## Runtime flow

Two independent lifetimes: the BPF program loads **once per session (lazily)**,
and the iterator is driven with `read()` **once per walk**.

**Load — lazy, cached, once.** `bpfwalk_open()` touches no BPF; it only
allocates the session and resolves the object directory. The program enters the
kernel in `ensure()`, where `bpf_object__open_file()` parses the `.bpf.o` and
`bpf_object__load()` does the CO-RE relocation, the verifier, and the program
install. The resulting program/map fds are cached on the walker entry (a failed
load is remembered so it is not retried). `ensure()` is reached from
`bpfwalk_has()` and `bpfwalk_walk_open()`, so the load fires on the first use of
a walker and never again for the life of the session. From drgn:

```
for_each_task(prog)                        # helpers/linux/pid.py
 └ bpfwalk_objects(prog, "task", ...)      # helpers/linux/_bpfwalk_accel.py
    ├ _session(prog) -> bpfwalk_open()     # allocates; NO load; cached in prog.cache["bpfwalk"]
    └ session.has("task") -> bpfwalk_has   # -> ensure() -> bpf_object__load()   <-- loads here, once
```

The program then stays resident for the session (freed by `bpfwalk_close()` ->
`bpf_object__close()`), so repeated walks never reload it.

**Drive — `read()` per walk.** The seq iterator is driven in `drive_iter()`:

```c
link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_ITER, NULL);  /* attach as iterator */
iter_fd = bpf_iter_create(link_fd);                           /* materialize an fd  */
do {
    n = read(iter_fd, sink, sizeof(sink));                    /* drives the walk    */
    ring_buffer__consume(rb);                                 /* drain bw_ref records */
} while (n > 0);
```

The `read(iter_fd, ...)` is what makes the kernel invoke the `SEC("iter/task")`
program once per task (plus a final `ctx->task == NULL` call). The program emits
only into the ring buffer, not the seq_file, so one `read()`-to-EOF runs the
whole enumeration. `drive_iter()` runs on the first `bpfwalk_walk_next()` only
(guarded by a `driven` flag); later `walk_next()` calls just hand out batches
from the materialized results. The link and `iter_fd` are created and closed per
walk (a fresh snapshot each time) but reuse the already-loaded program — so a
repeated walk re-does only the cheap link + `read()`, never the load.

## Design note

The offload hooks at drgn's **helper** layer, not its memory-read backend. At
the `drgn_memory_read_fn` seam drgn still owns the loop and calls the backend
once per element, so N reads stay N crossings — merely rerouted. Moving the
*loop* into the kernel is what collapses N crossings into one, and that only
happens when the whole traversal is handed to a walker. Hence: one walker per
structure, addresses out, types stay in drgn.

## Measured

`for_each_task` on a live 5.15 kernel, **993 tasks**. Timing only the
enumeration loop over 1000 passes — drgn's DWARF load and a warmup pass happen
before the clock starts, so this is purely `for_each_task` — bpfwalk vs the
userspace fallback (`BPFWALK_DISABLE=1`) on the same target:

```
mode=fallback tasks=993 reps=1000  enumeration_total=3.223 s  per_pass=3.223 ms
mode=bpfwalk  tasks=993 reps=1000  enumeration_total=0.838 s  per_pass=0.838 ms
```

~3.8x faster (0.84 ms vs 3.22 ms per full task-list walk). The enumeration's
`/proc/kcore` reads drop from ~4540 to ~77 `pread64` per pass — one
`read()`-to-EOF on the iterator fd instead of one read per task. Only
enumeration is offloaded, so reading many members per task narrows the gap.
