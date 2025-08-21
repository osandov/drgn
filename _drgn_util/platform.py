# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import platform
import re

NORMALIZED_MACHINE_NAME = platform.machine()
if NORMALIZED_MACHINE_NAME.startswith("aarch64") or NORMALIZED_MACHINE_NAME == "arm64":
    NORMALIZED_MACHINE_NAME = "aarch64"
elif NORMALIZED_MACHINE_NAME.startswith("arm") or NORMALIZED_MACHINE_NAME == "sa110":
    NORMALIZED_MACHINE_NAME = "arm"
elif re.fullmatch(r"i.86", NORMALIZED_MACHINE_NAME):
    NORMALIZED_MACHINE_NAME = "i386"
elif NORMALIZED_MACHINE_NAME.startswith("ppc64"):
    NORMALIZED_MACHINE_NAME = "ppc64"
elif NORMALIZED_MACHINE_NAME.startswith("ppc"):
    NORMALIZED_MACHINE_NAME = "ppc"
elif NORMALIZED_MACHINE_NAME == "riscv":
    NORMALIZED_MACHINE_NAME = "riscv32"
elif re.match(r"sh[0-9]", NORMALIZED_MACHINE_NAME):
    NORMALIZED_MACHINE_NAME = "sh"
elif NORMALIZED_MACHINE_NAME == "sun4u":
    NORMALIZED_MACHINE_NAME = "sparc64"


SYS = {
    "aarch64": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "alpha": {
        "bpf": 515,
        "finit_module": 507,
        "memfd_create": 512,
        "perf_event_open": 493,
    },
    "arc": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "arm": {
        "bpf": 386,
        "finit_module": 379,
        "kexec_file_load": 401,
        "memfd_create": 385,
        "perf_event_open": 364,
    },
    "csky": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "hexagon": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "i386": {
        "bpf": 357,
        "finit_module": 350,
        "memfd_create": 356,
        "perf_event_open": 336,
    },
    "loongarch": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "loongarch64": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "m68k": {
        "bpf": 354,
        "finit_module": 348,
        "memfd_create": 353,
        "perf_event_open": 332,
    },
    "microblaze": {
        "bpf": 387,
        "finit_module": 380,
        "memfd_create": 386,
        "perf_event_open": 366,
    },
    # TODO: mips is missing here because I don't know how to distinguish
    # between the o32 and n32 ABIs.
    "mips64": {
        "bpf": 315,
        "finit_module": 307,
        "memfd_create": 314,
        "perf_event_open": 292,
    },
    "nios2": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "openrisc": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "parisc": {
        "bpf": 341,
        "finit_module": 333,
        "kexec_file_load": 355,
        "memfd_create": 340,
        "perf_event_open": 318,
    },
    "parisc64": {
        "bpf": 341,
        "finit_module": 333,
        "kexec_file_load": 355,
        "memfd_create": 340,
        "perf_event_open": 318,
    },
    "ppc": {
        "bpf": 361,
        "finit_module": 353,
        "memfd_create": 360,
        "perf_event_open": 319,
    },
    "ppc64": {
        "bpf": 361,
        "finit_module": 353,
        "memfd_create": 360,
        "perf_event_open": 319,
    },
    "riscv32": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "riscv64": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "memfd_create": 279,
        "perf_event_open": 241,
    },
    "s390": {
        "bpf": 351,
        "finit_module": 344,
        "kexec_file_load": 381,
        "memfd_create": 350,
        "perf_event_open": 331,
    },
    "s390x": {
        "bpf": 351,
        "finit_module": 344,
        "kexec_file_load": 381,
        "memfd_create": 350,
        "perf_event_open": 331,
    },
    "sh": {
        "bpf": 375,
        "finit_module": 368,
        "memfd_create": 374,
        "perf_event_open": 336,
    },
    "sparc": {
        "bpf": 349,
        "finit_module": 342,
        "memfd_create": 348,
        "perf_event_open": 327,
    },
    "sparc64": {
        "bpf": 349,
        "finit_module": 342,
        "memfd_create": 348,
        "perf_event_open": 327,
    },
    "x86_64": {
        "bpf": 321,
        "finit_module": 313,
        "kexec_file_load": 320,
        "memfd_create": 319,
        "perf_event_open": 298,
    },
    "xtensa": {
        "bpf": 340,
        "finit_module": 332,
        "memfd_create": 339,
        "perf_event_open": 327,
    },
}.get(NORMALIZED_MACHINE_NAME, {})

_IOC_NONE = {
    "alpha": 1,
    "mips": 1,
    "mips64": 1,
    "ppc": 1,
    "ppc64": 1,
    "sparc": 1,
    "sparc64": 1,
}.get(NORMALIZED_MACHINE_NAME, 0)

_IOC_READ = {
    "parisc": 1,
    "parisc64": 1,
}.get(NORMALIZED_MACHINE_NAME, 2)

_IOC_WRITE = {
    "alpha": 4,
    "mips": 4,
    "mips64": 4,
    "parisc": 2,
    "parisc64": 2,
    "ppc": 4,
    "ppc64": 4,
    "sparc": 4,
    "sparc64": 4,
}.get(NORMALIZED_MACHINE_NAME, 1)

_IOC_NRBITS = 8

_IOC_TYPEBITS = 8

_IOC_SIZEBITS = {
    "alpha": 13,
    "mips": 13,
    "mips64": 13,
    "ppc": 13,
    "ppc64": 13,
    "sparc": 13,
    "sparc64": 13,
}.get(NORMALIZED_MACHINE_NAME, 14)

_IOC_DIRBITS = {
    "alpha": 3,
    "mips": 3,
    "mips64": 3,
    "ppc": 3,
    "ppc64": 3,
    "sparc": 3,
    "sparc64": 3,
}.get(NORMALIZED_MACHINE_NAME, 2)

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS


def _IOC(dir: int, type: int, nr: int, size: int) -> int:
    return (
        (dir << _IOC_DIRSHIFT)
        | (type << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


def _IO(type: int, nr: int) -> int:
    return _IOC(_IOC_NONE, type, nr, 0)


def _IOR(type: int, nr: int, size: int) -> int:
    return _IOC(_IOC_READ, type, nr, size)


def _IOW(type: int, nr: int, size: int) -> int:
    return _IOC(_IOC_WRITE, type, nr, size)


def _IOWR(type: int, nr: int, size: int) -> int:
    return _IOC(_IOC_READ | _IOC_WRITE, type, nr, size)
