#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Get a process core dump from drgn running against the kernel."""

import argparse
import contextlib
import functools
import io
from pathlib import Path
import struct
import sys
from typing import Iterator, List, NamedTuple, Sequence, Tuple

from drgn import (
    Architecture,
    FaultError,
    Object,
    PlatformFlags,
    Program,
    ProgramFlags,
    cast,
)
from drgn.helpers.linux.fs import d_path
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import access_remote_vm, cmdline, for_each_vma
from drgn.helpers.linux.pid import find_task

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

PT_LOAD = 1
PT_NOTE = 4
PF_X = 1 << 0
PF_W = 1 << 1
PF_R = 1 << 2

VM_READ = 0x1
VM_WRITE = 0x2
VM_EXEC = 0x4
VM_SHARED = 0x8
VM_IO = 0x4000
VM_DONTDUMP = 0x4000000


class Segment(NamedTuple):
    start: int
    end: int
    p_flags: int
    dump_size: int


class MappedFile(NamedTuple):
    path: bytes
    offset: int
    start: int
    end: int


class Phdr(NamedTuple):
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    # No p_paddr, we always set it to 0.
    p_filesz: int
    p_memsz: int
    p_align: int


def vma_snapshot(
    page_size: int, task: Object
) -> Tuple[Sequence[Segment], Sequence[MappedFile]]:
    gate_vma = task.prog_["gate_vma"].address_of_()
    special_mapping_name = task.prog_["special_mapping_name"]

    segments: List[Segment] = []
    mapped_files: List[MappedFile] = []

    def always_dump_vma(vma: Object) -> bool:
        if vma == gate_vma:
            return True
        # The kernel checks (vma->vm_ops && vma->vm_ops->name && vma->vm_ops->name(vma)).
        # As of Linux 6.9, gate_vma_name() and special_mapping_name() are the
        # only instances of ->name().
        vm_ops = vma.vm_ops.read_()
        if vm_ops:
            if vm_ops.name == special_mapping_name:
                return bool(
                    cast("struct vm_special_mapping *", vma.vm_private_data).name
                )
        return False

    def add_vma(vma: Object) -> None:
        start = vma.vm_start.value_()
        end = vma.vm_end.value_()
        flags = vma.vm_flags.read_()
        file = vma.vm_file.read_()

        p_flags = 0
        if flags & VM_READ:
            p_flags |= PF_R
        if flags & VM_WRITE:
            p_flags |= PF_W
        if flags & VM_EXEC:
            p_flags |= PF_X

        # Dumbed down version of vma_dump_size() assuming
        # (MMF_DUMP_ANON_PRIVATE|MMF_DUMP_ANON_SHARED).
        if always_dump_vma(vma):
            dump_size = end - start
        elif flags & (VM_IO | VM_DONTDUMP):
            dump_size = 0
        elif vma.anon_vma or ((flags & VM_SHARED) and file.f_inode.i_nlink == 0):
            dump_size = end - start
        elif (
            file
            and vma.vm_pgoff == 0
            and (vma.vm_flags & VM_READ)
            and file.f_inode.i_mode & 0o111
        ):
            # Include first page of executables.
            # TODO: this is out of date with Linux kernel commit 84158b7f6a06
            # ("coredump: Also dump first pages of non-executable ELF
            # libraries") (in v5.18).
            dump_size = page_size
        else:
            dump_size = 0

        if (
            segments
            and segments[-1].end == start
            and segments[-1].p_flags == p_flags
            and (
                dump_size == 0
                or segments[-1].dump_size == segments[-1].end - segments[-1].start
            )
        ):
            segments[-1] = Segment(
                start=segments[-1].start,
                end=end,
                p_flags=p_flags,
                dump_size=segments[-1].dump_size + dump_size,
            )
        else:
            segments.append(
                Segment(
                    start=start,
                    end=end,
                    p_flags=p_flags,
                    dump_size=dump_size,
                )
            )

        if file:
            path = d_path(file.f_path)
            offset = vma.vm_pgoff.value_() * page_size
            if (
                mapped_files
                and mapped_files[-1].path == path
                and mapped_files[-1].end == start
                and mapped_files[-1].offset
                + (mapped_files[-1].end - mapped_files[-1].start)
                == offset
            ):
                mapped_files[-1] = MappedFile(
                    path=path,
                    offset=mapped_files[-1].offset,
                    start=mapped_files[-1].start,
                    end=end,
                )
            else:
                mapped_files.append(
                    MappedFile(
                        path=path,
                        offset=offset,
                        start=start,
                        end=end,
                    )
                )

    for vma in for_each_vma(task.mm):
        add_vma(vma)
    add_vma(gate_vma)
    return segments, mapped_files


def _nt_pids(task: Object) -> Tuple[int, int, int, int]:
    return (
        task.pid.value_(),  # pid
        task.real_parent.pid.value_(),  # ppid
        task.tgid.value_(),  # pgrp
        task.signal.pids[prog["PIDTYPE_SID"]].numbers[0].nr.value_(),  # sid
    )


def nt_prstatus(task: Object) -> bytes:
    return struct.pack(
        "3IH2Q4I8Q27QI4x",
        0,  # info.si_signo
        0,  # info.si_code
        0,  # info.si_errno
        # TODO: can we get some of these?
        0,  # cursig
        0,  # sigpend
        0,  # sighold
        *_nt_pids(task),
        0,
        0,  # utime
        0,
        0,  # stime
        0,
        0,  # cutime
        0,
        0,  # cstime
        # reg
        *struct.unpack(
            "21Q",
            prog.read(task.stack.value_() + (4096 << 2) - 21 * 8, 21 * 8),
        ),
        0,
        0,
        0,
        0,
        0,
        0,
        # TODO: floating point registers.
        0,  # fpvalid
    )


MAX_NICE = 19
MIN_NICE = -20
NICE_WIDTH = MAX_NICE - MIN_NICE + 1
MAX_RT_PRIO = 100
DEFAULT_PRIO = MAX_RT_PRIO + NICE_WIDTH // 2


def PRIO_TO_NICE(prio: int) -> int:
    return prio - DEFAULT_PRIO


def nt_prpsinfo(task: Object, use_procfs: bool) -> bytes:
    fname_len = 16
    ELF_PRARGSZ = 80

    try:
        state: int = task.__state.value_()
    except AttributeError:
        state = task.state.value_()
    if state:
        state = (state & -state).bit_length()
    sname = ord(".") if state > 5 else b"RSDTZW"[state]

    cred = task.real_cred.read_()
    uid = cred.uid.val.value_()
    gid = cred.gid.val.value_()
    pids = _nt_pids(task)

    if use_procfs:
        psargs = (
            Path(f"/proc/{pids[0]}/cmdline")
            .read_bytes()
            .rstrip(b"\0")
            .replace(b"\0", b" ")
        )
    else:
        psargs = b" ".join(cmdline(task) or [])

    return struct.pack(
        f"4BQ6I{fname_len}s{ELF_PRARGSZ}s",
        state,
        sname,
        sname == ord("Z"),  # zomb
        PRIO_TO_NICE(task.static_prio.value_()),  # nice
        task.flags.value_(),  # flag
        uid,
        gid,
        *_nt_pids(task),
        task.comm.string_(),  # fname
        psargs,
    )


def nt_auxv(task: Object) -> bytes:
    auxv = task.mm.saved_auxv
    i = 0
    while auxv[i]:
        i += 2
    return prog.read(auxv.address_, auxv[i + 2].address_ - auxv.address_)


def nt_file(mapped_files: Sequence[MappedFile], page_size: int) -> bytes:
    buf = bytearray(16 + 24 * len(mapped_files))
    struct.pack_into("QQ", buf, 0, len(mapped_files), page_size)
    for i, mapped_file in enumerate(mapped_files):
        struct.pack_into(
            "QQQ",
            buf,
            16 + 24 * i,
            mapped_file.start,
            mapped_file.end,
            mapped_file.offset // page_size,
        )
    for mapped_file in mapped_files:
        buf.extend(mapped_file.path)
        buf.append(0)
    return buf


def gen_notes(
    task: Object, mapped_files: Sequence[MappedFile], page_size: int, use_procfs: bool
) -> bytearray:
    notes = []

    def add_nt_prstatus(t: Object) -> None:
        # This is obviously racy for the live kernel, but it's best effort.
        if t.on_cpu:
            print(f"skipping running thread {t.pid.value_()}", file=sys.stderr)
        else:
            notes.append(
                (
                    b"CORE",
                    1,  # NT_PRSTATUS
                    nt_prstatus(t),
                )
            )

    add_nt_prstatus(task)
    for t in list_for_each_entry(
        task.type_.type, task.signal.thread_head.address_of_(), "thread_node"
    ):
        if t != task:
            add_nt_prstatus(t)

    notes.append(
        (
            b"CORE",
            3,  # NT_PRPSINFO
            nt_prpsinfo(task.group_leader.read_(), use_procfs),
        )
    )
    # No NT_SIGINFO since we have no signal.
    notes.append(
        (
            b"CORE",
            6,  # NT_AUXV
            nt_auxv(task),
        )
    )
    notes.append(
        (
            b"CORE",
            0x46494C45,  # NT_FILE
            nt_file(mapped_files, page_size),
        )
    )

    buf = bytearray()
    for name, type_, desc in notes:
        buf.extend(struct.pack("III", len(name) + 1, len(desc), type_))
        buf.extend(name)
        buf.extend(bytes(4 - (len(name) & 3)))
        buf.extend(desc)
        buf.extend(bytes(-len(buf) & 3))
    return buf


def try_read_memory_procfs(
    page_size: int, mem_file: io.FileIO, address: int, size: int
) -> Iterator[Tuple[int, bytes]]:
    # An address may overflow a signed long, but we can still seek to it in
    # increments of sys.maxsize.
    whence = 0
    offset = address
    while offset:
        seek = min(offset, sys.maxsize)
        try:
            mem_file.seek(seek, whence)
        except OSError:
            # The offset returned by the lseek() system call may be negative
            # when interpreted as an off_t, which makes Python think that there
            # was an error even though the seek succeeded.
            pass
        offset -= seek
        whence = 1

    while size > 0:
        try:
            buf = mem_file.read(size)
            yield address, buf
            address += len(buf)
            size -= len(buf)
        except IOError:
            try:
                mem_file.seek(page_size, 1)
            except OSError:
                # See above.
                pass
            address += page_size
            size -= page_size


def try_read_memory_remote(
    page_size: int, mm: Object, address: int, size: int
) -> Iterator[Tuple[int, bytes]]:
    # Reading page by page isn't very efficient, but it's foolproof.
    while size > 0:
        try:
            yield address, access_remote_vm(mm, address, page_size)
        except FaultError:
            pass
        address += page_size
        size -= page_size


def main(prog: Program, argv: Sequence[str]) -> None:
    parser = argparse.ArgumentParser(
        description="Capture a process core dump without stopping it or from a kernel core dump (using drgn)"
    )
    parser.add_argument(
        "--no-procfs",
        dest="use_procfs",
        action="store_false",
        help="don't use the proc filesystem to get information about the process even when the process is local; "
        "this will skip memory that is paged out and is slower, "
        "but it can be useful if the mmap lock is deadlocked",
    )
    parser.add_argument("pid", type=int, help="PID of process to capture")
    parser.add_argument("core", type=str, help="output file")
    args = parser.parse_args(argv)

    args.use_procfs = args.use_procfs and (
        prog.flags & (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)
        == (ProgramFlags.IS_LIVE | ProgramFlags.IS_LOCAL)
    )

    # TODO: these aren't necessarily the same as the kernel (e.g., when running
    # a 32-bit application on a 64-bit kernel).
    platform = prog.platform
    assert platform is not None
    ei_class = ELFCLASS64 if (platform.flags & PlatformFlags.IS_64_BIT) else ELFCLASS32
    ei_data = (
        ELFDATA2LSB
        if (platform.flags & PlatformFlags.IS_LITTLE_ENDIAN)
        else ELFDATA2MSB
    )
    if platform.arch == Architecture.X86_64:
        e_machine = 62  # EM_X86_64
    else:
        # TODO: there are assumptions that the host and target are x86-64
        # throughout this script (in struct.pack() calls, note contents).
        sys.exit("only x86-64 is supported")

    page_size = prog["PAGE_SIZE"].value_()

    ehdr_struct = struct.Struct("16BHHIQQQIHHHHHH")
    phdr_struct = struct.Struct("IIQQQQQQ")

    task = find_task(prog, args.pid)
    if not task:
        sys.exit(f"PID {args.pid} not found")

    segments, mapped_files = vma_snapshot(page_size, task)
    notes = gen_notes(task, mapped_files, page_size, args.use_procfs)

    with contextlib.ExitStack() as exit_stack:
        if args.use_procfs:
            try_read_memory = functools.partial(
                try_read_memory_procfs,
                page_size,
                exit_stack.enter_context(
                    open(f"/proc/{args.pid}/mem", "rb", buffering=0)
                ),
            )
        else:
            try_read_memory = functools.partial(
                try_read_memory_remote, page_size, task.mm.read_()
            )

        f = exit_stack.enter_context(open(args.core, "wb"))

        offset = f.seek(ehdr_struct.size)
        phdrs = [
            Phdr(
                p_type=PT_NOTE,
                p_flags=0,
                p_offset=offset,
                p_vaddr=0,
                p_filesz=len(notes),
                p_memsz=0,
                p_align=0,
            )
        ]
        f.write(notes)
        offset += len(notes)

        # Align up to a page.
        offset = f.seek(-offset % page_size, 1)
        for segment in segments:
            written_start_address = written_end_address = segment.start
            written_offset = offset
            for address, buf in try_read_memory(segment.start, segment.dump_size):
                if address == written_end_address:
                    written_end_address += len(buf)
                else:
                    phdrs.append(
                        Phdr(
                            p_type=PT_LOAD,
                            p_flags=segment.p_flags,
                            p_offset=written_offset,
                            p_vaddr=written_start_address,
                            p_filesz=written_end_address - written_start_address,
                            p_memsz=address - written_start_address,
                            p_align=page_size,
                        )
                    )
                    written_start_address = address
                    written_end_address = address + len(buf)
                    written_offset = offset
                f.write(buf)
                offset += len(buf)
            phdrs.append(
                Phdr(
                    p_type=PT_LOAD,
                    p_flags=segment.p_flags,
                    p_offset=written_offset,
                    p_vaddr=written_start_address,
                    p_filesz=written_end_address - written_start_address,
                    p_memsz=segment.end - written_start_address,
                    p_align=page_size,
                )
            )

        e_phoff = offset
        for phdr in phdrs:
            f.write(
                phdr_struct.pack(
                    phdr.p_type,
                    phdr.p_flags,
                    phdr.p_offset,
                    phdr.p_vaddr,
                    0,  # p_paddr
                    phdr.p_filesz,
                    phdr.p_memsz,
                    phdr.p_align,
                )
            )
        # TODO: >= 2**16 phdrs

        f.seek(0)
        f.write(
            ehdr_struct.pack(
                0x7F,  # ELFMAG0
                ord("E"),  # ELFMAG1
                ord("L"),  # ELFMAG2
                ord("F"),  # ELFMAG3
                ei_class,
                ei_data,
                1,  # EI_VERSION = EV_CURRENT
                0,  # EI_OSABI = ELFOSABI_NONE
                0,  # EI_ABIVERSION
                0,  # EI_PAD
                0,
                0,
                0,
                0,
                0,
                0,
                4,  # e_type = ET_CORE
                e_machine,
                1,  # e_version = EV_CURRENT
                0,  # e_entry
                e_phoff,
                0,  # e_shoff
                0,  # e_flags
                ehdr_struct.size,  # e_ehsize
                phdr_struct.size,  # e_phentsize
                len(phdrs),  # e_phnum
                0,  # e_shentsize,
                0,  # e_shnum,
                0,  # e_shstrndx
            )
        )


if __name__ == "__main__":
    prog: Program
    main(prog, sys.argv[1:])
