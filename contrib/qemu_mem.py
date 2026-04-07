"""
qemu_mem.py - speed up memory access for QEMU programs via /proc/pid/mem

Parsing the QEMU HMP "xp" command is much slower than native reads for multiple
reasons. While that's great to boostrap a debugging session, it may be possible
to speed up the process. If QEMU is creating a single, anonymous memory region
for guest memory, we may be able to create a faster reader via /proc/pid/mem.
While this is not a common configuration for real-world virtualization, it's a
good starting point and could probably be extended to more practical use cases.

Use this in one of two ways:

1. Once drgn has started: execscript("path/to/qemu_mem.py")
2. As a drgn plugin: DRGN_PLUGINS=qemu:path/to/qemu_mem.py drgn ...
"""
import logging
import os
import socket
import struct
from pathlib import Path

from _drgn import _linux_helper_follow_phys
from drgn import Program, ProgramFlags


log = logging.getLogger("drgn.qemu_mem")


def find_qemu_pid_direct():
    """
    Assuming that we're connected via a Unix socket, find the first socket FD we
    have open, and then get the PID associated with it. This is very likely to
    be the QEMU PID we're talking to, but like everything else in this file,
    it's a heuristic.
    """
    for p in Path("/proc/self/fd").iterdir():
        if p.readlink().name.startswith("socket:"):
            fd = int(p.name)
            break
    else:
        return None

    try:
        s = socket.socket(fileno=fd)
        # Ironically, we could omit the buffer size, and Python would treat this
        # as an integer socket option. Since what we care about is the first
        # integer of the structure, the return value would actually just be the
        # PID we care about! But that's super hacky, plus a PID should be
        # *unsigned*, so let's do it the correct way.
        fmt = "=III"
        buf = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize(fmt))
        result = struct.unpack(fmt, buf)
        return result[0]
    except OSError:
        return None
    finally:
        s.detach()


def find_qemu_pids():
    """
    Using the naive assumption that qemu processes (and only qemu processes)
    have commands whose names start with "qemu-", find all candidate QEMU pids.
    NB: drgn might be able to get a specific PID from the Unix socket with
    getsockopt(SO_PEERCRED), which would be vastly preferable to this approach.
    """
    pid = find_qemu_pid_direct()
    if pid is not None:
        return [pid], "sockopt"
    pids = []
    for d in Path("/proc").iterdir():
        try:
            if (d / "comm").open("rb").read().startswith(b"qemu"):
                pids.append(int(d.name))
        except OSError:
            pass
    return pids, "procfs"


def find_matching_phys_map(pid, fd, offset, data):
    """
    Using the naive assumption that qemu processes map guest physical memory in
    one contiguous anonymous VMA, find the base address of this mapping. The
    caller provides some data at a known offset, which we use to help identify
    which anonymous mapping is correct.
    """
    maps = Path(f"/proc/{pid}/maps").open("rt").read()

    min_len = offset + len(data)
    for line in maps.splitlines():
        line = line.strip()
        if line:
            fields = line.split()
            if len(fields) > 5:
                continue
            start, end = fields[0].split("-")
            start, end = int(start, 16), int(end, 16)
            vma_size = end - start
            if vma_size < min_len:
                continue
            try:
                if os.pread(fd, len(data), start + offset) == data:
                    return start, end
            except OSError:
                continue
    log.debug("error: could not find QEMU physical VMA")
    return None


def main(prog: Program):
    # Find the QEMU pid we're targeting, hopefully
    pids, meth = find_qemu_pids()
    if len(pids) != 1:
        log.debug(f"error: looking for one qemu pid via {meth}, found {len(pids)}")
        return
    pid = pids[0]

    # Open its memory if possible
    try:
        fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    except PermissionError:
        log.debug("error: No permission to open QEMU /proc/pid/mem")
        return

    # We need a valid physical address with real data to ensure we pick the
    # right VMA. Drgn has workarounds for both x86_64 and aarch64 that allow us
    # to map virtual to physical addresses without debuginfo or virtual
    # mappings. Other architectures may have those in the future.
    pfx = "SYMBOL(swapper_pg_dir)="
    for line in prog["VMCOREINFO"].string_().decode().splitlines():
        if line.startswith(pfx):
            test_vaddr = int(line[len(pfx):], 16)
            break
    else:
        log.debug("error: could not find init_uts_ns symbol in VMCOREINFO")
        return
    test_paddr = _linux_helper_follow_phys(prog, test_vaddr, test_vaddr)
    expected = prog.read(test_paddr, 2 * prog["PAGE_SIZE"].value_(), True)

    vma = find_matching_phys_map(pid, fd, test_paddr, expected)
    if vma is None:
        return

    log.info(f"found matching VMA @ {vma[0]:x} for QEMU pid {pid} (via {meth}), mapping...")

    def reader(a, c, o, p):
        return os.pread(fd, c, o+vma[0])

    prog.add_memory_segment(0, 0xFFFFFFFFFFFFFFFF, reader, True)


def drgn_prog_set(prog: Program):
    if prog.flags & (
        ProgramFlags.IS_LINUX_KERNEL | ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL
    ) == (ProgramFlags.IS_LINUX_KERNEL | ProgramFlags.IS_LIVE):
        main(prog)


if __name__ == "__main__":
    main(prog)  # noqa
