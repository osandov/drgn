# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import platform
import re
import sys
import types

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


if NORMALIZED_MACHINE_NAME == "x86_64":
    if sys.maxsize > 2**32:
        SYS = {
            "bpf": 321,
            "finit_module": 313,
            "io_destroy": 207,
            "io_setup": 206,
            "io_submit": 209,
            "kexec_file_load": 320,
            "memfd_create": 319,
            "perf_event_open": 298,
        }
    else:  # x32
        SYS = {
            "bpf": 321,
            "finit_module": 313,
            "io_destroy": 207,
            "io_setup": 543,
            "io_submit": 544,
            "kexec_file_load": 320,
            "memfd_create": 319,
            "perf_event_open": 298,
        }
else:
    SYS = {
        "aarch64": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "alpha": {
            "bpf": 515,
            "finit_module": 507,
            "io_destroy": 399,
            "io_setup": 398,
            "io_submit": 401,
            "memfd_create": 512,
            "perf_event_open": 493,
        },
        "arc": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "arm": {
            "bpf": 386,
            "finit_module": 379,
            "io_destroy": 244,
            "io_setup": 243,
            "io_submit": 246,
            "kexec_file_load": 401,
            "memfd_create": 385,
            "perf_event_open": 364,
        },
        "csky": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "hexagon": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "i386": {
            "bpf": 357,
            "finit_module": 350,
            "io_destroy": 246,
            "io_setup": 245,
            "io_submit": 248,
            "memfd_create": 356,
            "perf_event_open": 336,
        },
        "loongarch": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "loongarch64": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "m68k": {
            "bpf": 354,
            "finit_module": 348,
            "io_destroy": 242,
            "io_setup": 241,
            "io_submit": 244,
            "memfd_create": 353,
            "perf_event_open": 332,
        },
        "microblaze": {
            "bpf": 387,
            "finit_module": 380,
            "io_destroy": 246,
            "io_setup": 245,
            "io_submit": 248,
            "memfd_create": 386,
            "perf_event_open": 366,
        },
        # TODO: mips is missing here because I don't know how to distinguish
        # between the o32 and n32 ABIs.
        "mips64": {
            "bpf": 315,
            "finit_module": 307,
            "io_destroy": 201,
            "io_setup": 200,
            "io_submit": 203,
            "memfd_create": 314,
            "perf_event_open": 292,
        },
        "nios2": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "openrisc": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "parisc": {
            "bpf": 341,
            "finit_module": 333,
            "io_destroy": 216,
            "io_setup": 215,
            "io_submit": 218,
            "kexec_file_load": 355,
            "memfd_create": 340,
            "perf_event_open": 318,
        },
        "parisc64": {
            "bpf": 341,
            "finit_module": 333,
            "io_destroy": 216,
            "io_setup": 215,
            "io_submit": 218,
            "kexec_file_load": 355,
            "memfd_create": 340,
            "perf_event_open": 318,
        },
        "ppc": {
            "bpf": 361,
            "finit_module": 353,
            "io_destroy": 228,
            "io_setup": 227,
            "io_submit": 230,
            "memfd_create": 360,
            "perf_event_open": 319,
        },
        "ppc64": {
            "bpf": 361,
            "finit_module": 353,
            "io_destroy": 228,
            "io_setup": 227,
            "io_submit": 230,
            "memfd_create": 360,
            "perf_event_open": 319,
        },
        "riscv32": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "riscv64": {
            "bpf": 280,
            "finit_module": 273,
            "io_destroy": 1,
            "io_setup": 0,
            "io_submit": 2,
            "kexec_file_load": 294,
            "memfd_create": 279,
            "perf_event_open": 241,
        },
        "s390": {
            "bpf": 351,
            "finit_module": 344,
            "io_destroy": 244,
            "io_setup": 243,
            "io_submit": 246,
            "kexec_file_load": 381,
            "memfd_create": 350,
            "perf_event_open": 331,
        },
        "s390x": {
            "bpf": 351,
            "finit_module": 344,
            "io_destroy": 244,
            "io_setup": 243,
            "io_submit": 246,
            "kexec_file_load": 381,
            "memfd_create": 350,
            "perf_event_open": 331,
        },
        "sh": {
            "bpf": 375,
            "finit_module": 368,
            "io_destroy": 246,
            "io_setup": 245,
            "io_submit": 248,
            "memfd_create": 374,
            "perf_event_open": 336,
        },
        "sparc": {
            "bpf": 349,
            "finit_module": 342,
            "io_destroy": 269,
            "io_setup": 268,
            "io_submit": 270,
            "memfd_create": 348,
            "perf_event_open": 327,
        },
        "sparc64": {
            "bpf": 349,
            "finit_module": 342,
            "io_destroy": 269,
            "io_setup": 268,
            "io_submit": 270,
            "memfd_create": 348,
            "perf_event_open": 327,
        },
        "xtensa": {
            "bpf": 340,
            "finit_module": 332,
            "io_destroy": 240,
            "io_setup": 239,
            "io_submit": 241,
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


_SIGNALS_BY_MACHINE_NAME_TMP = {}
for _name in (
    "aarch64",
    "arc",
    "csky",
    "hexagon",
    "i386",
    "loongarch",
    "loongarch64",
    "m68k",
    "microblaze",
    "nios2",
    "openrisc",
    "ppc",
    "ppc64",
    "riscv32",
    "riscv64",
    "s390",
    "s390x",
    "sh",
    "x86_64",
):
    _SIGNALS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SIGHUP": 1,
            "SIGINT": 2,
            "SIGQUIT": 3,
            "SIGILL": 4,
            "SIGTRAP": 5,
            "SIGABRT": 6,
            "SIGIOT": 6,
            "SIGBUS": 7,
            "SIGFPE": 8,
            "SIGKILL": 9,
            "SIGUSR1": 10,
            "SIGSEGV": 11,
            "SIGUSR2": 12,
            "SIGPIPE": 13,
            "SIGALRM": 14,
            "SIGTERM": 15,
            "SIGSTKFLT": 16,
            "SIGCHLD": 17,
            "SIGCLD": 17,
            "SIGCONT": 18,
            "SIGSTOP": 19,
            "SIGTSTP": 20,
            "SIGTTIN": 21,
            "SIGTTOU": 22,
            "SIGURG": 23,
            "SIGXCPU": 24,
            "SIGXFSZ": 25,
            "SIGVTALRM": 26,
            "SIGPROF": 27,
            "SIGWINCH": 28,
            "SIGIO": 29,
            "SIGPOLL": 29,
            "SIGPWR": 30,
            "SIGSYS": 31,
            "SIGUNUSED": 31,
            "SIGRTMIN": 32,
            "SIGRTMAX": 64,
        }
    )
_SIGNALS_BY_MACHINE_NAME_TMP["alpha"] = types.MappingProxyType(
    {
        "SIGHUP": 1,
        "SIGINT": 2,
        "SIGQUIT": 3,
        "SIGILL": 4,
        "SIGTRAP": 5,
        "SIGABRT": 6,
        "SIGIOT": 6,
        "SIGEMT": 7,
        "SIGFPE": 8,
        "SIGKILL": 9,
        "SIGBUS": 10,
        "SIGSEGV": 11,
        "SIGSYS": 12,
        "SIGUNUSED": 12,
        "SIGPIPE": 13,
        "SIGALRM": 14,
        "SIGTERM": 15,
        "SIGURG": 16,
        "SIGSTOP": 17,
        "SIGTSTP": 18,
        "SIGCONT": 19,
        "SIGCHLD": 20,
        "SIGCLD": 20,
        "SIGTTIN": 21,
        "SIGTTOU": 22,
        "SIGIO": 23,
        "SIGPOLL": 23,
        "SIGXCPU": 24,
        "SIGXFSZ": 25,
        "SIGVTALRM": 26,
        "SIGPROF": 27,
        "SIGWINCH": 28,
        "SIGPWR": 29,
        "SIGINFO": 29,
        "SIGUSR1": 30,
        "SIGUSR2": 31,
        "SIGRTMIN": 32,
        "SIGRTMAX": 64,
    }
)
_SIGNALS_BY_MACHINE_NAME_TMP["arm"] = types.MappingProxyType(
    {
        "SIGHUP": 1,
        "SIGINT": 2,
        "SIGQUIT": 3,
        "SIGILL": 4,
        "SIGTRAP": 5,
        "SIGABRT": 6,
        "SIGIOT": 6,
        "SIGBUS": 7,
        "SIGFPE": 8,
        "SIGKILL": 9,
        "SIGUSR1": 10,
        "SIGSEGV": 11,
        "SIGUSR2": 12,
        "SIGPIPE": 13,
        "SIGALRM": 14,
        "SIGTERM": 15,
        "SIGSTKFLT": 16,
        "SIGCHLD": 17,
        "SIGCLD": 17,
        "SIGCONT": 18,
        "SIGSTOP": 19,
        "SIGTSTP": 20,
        "SIGTTIN": 21,
        "SIGTTOU": 22,
        "SIGURG": 23,
        "SIGXCPU": 24,
        "SIGXFSZ": 25,
        "SIGVTALRM": 26,
        "SIGPROF": 27,
        "SIGWINCH": 28,
        "SIGIO": 29,
        "SIGPOLL": 29,
        "SIGPWR": 30,
        "SIGSYS": 31,
        "SIGUNUSED": 31,
        "SIGRTMIN": 32,
        "SIGSWI": 32,
        "SIGRTMAX": 64,
    }
)
for _name in ("mips", "mips64"):
    _SIGNALS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SIGHUP": 1,
            "SIGINT": 2,
            "SIGQUIT": 3,
            "SIGILL": 4,
            "SIGTRAP": 5,
            "SIGABRT": 6,
            "SIGIOT": 6,
            "SIGEMT": 7,
            "SIGFPE": 8,
            "SIGKILL": 9,
            "SIGBUS": 10,
            "SIGSEGV": 11,
            "SIGSYS": 12,
            "SIGUNUSED": 12,
            "SIGPIPE": 13,
            "SIGALRM": 14,
            "SIGTERM": 15,
            "SIGUSR1": 16,
            "SIGUSR2": 17,
            "SIGCHLD": 18,
            "SIGCLD": 18,
            "SIGPWR": 19,
            "SIGWINCH": 20,
            "SIGURG": 21,
            "SIGIO": 22,
            "SIGPOLL": 22,
            "SIGSTOP": 23,
            "SIGTSTP": 24,
            "SIGCONT": 25,
            "SIGTTIN": 26,
            "SIGTTOU": 27,
            "SIGVTALRM": 28,
            "SIGPROF": 29,
            "SIGXCPU": 30,
            "SIGXFSZ": 31,
            "SIGRTMIN": 32,
            "SIGRTMAX": 128,
        }
    )
for _name in ("parisc", "parisc64"):
    _SIGNALS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SIGHUP": 1,
            "SIGINT": 2,
            "SIGQUIT": 3,
            "SIGILL": 4,
            "SIGTRAP": 5,
            "SIGABRT": 6,
            "SIGIOT": 6,
            "SIGSTKFLT": 7,
            "SIGFPE": 8,
            "SIGKILL": 9,
            "SIGBUS": 10,
            "SIGSEGV": 11,
            "SIGXCPU": 12,
            "SIGPIPE": 13,
            "SIGALRM": 14,
            "SIGTERM": 15,
            "SIGUSR1": 16,
            "SIGUSR2": 17,
            "SIGCHLD": 18,
            "SIGCLD": 18,
            "SIGPWR": 19,
            "SIGVTALRM": 20,
            "SIGPROF": 21,
            "SIGIO": 22,
            "SIGPOLL": 22,
            "SIGWINCH": 23,
            "SIGSTOP": 24,
            "SIGTSTP": 25,
            "SIGCONT": 26,
            "SIGTTIN": 27,
            "SIGTTOU": 28,
            "SIGURG": 29,
            "SIGXFSZ": 30,
            "SIGSYS": 31,
            "SIGUNUSED": 31,
            "SIGRTMIN": 32,
            "SIGRTMAX": 64,
        }
    )
for _name in ("sparc", "sparc64"):
    _SIGNALS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SIGHUP": 1,
            "SIGINT": 2,
            "SIGQUIT": 3,
            "SIGILL": 4,
            "SIGTRAP": 5,
            "SIGABRT": 6,
            "SIGIOT": 6,
            "SIGEMT": 7,
            "SIGFPE": 8,
            "SIGKILL": 9,
            "SIGBUS": 10,
            "SIGSEGV": 11,
            "SIGSYS": 12,
            "SIGUNUSED": 12,
            "SIGPIPE": 13,
            "SIGALRM": 14,
            "SIGTERM": 15,
            "SIGURG": 16,
            "SIGSTOP": 17,
            "SIGTSTP": 18,
            "SIGCONT": 19,
            "SIGCHLD": 20,
            "SIGCLD": 20,
            "SIGTTIN": 21,
            "SIGTTOU": 22,
            "SIGIO": 23,
            "SIGPOLL": 23,
            "SIGXCPU": 24,
            "SIGXFSZ": 25,
            "SIGVTALRM": 26,
            "SIGPROF": 27,
            "SIGWINCH": 28,
            "SIGPWR": 29,
            "SIGLOST": 29,
            "SIGUSR1": 30,
            "SIGUSR2": 31,
            "SIGRTMIN": 32,
            "SIGRTMAX": 64,
        }
    )
_SIGNALS_BY_MACHINE_NAME_TMP["xtensa"] = types.MappingProxyType(
    {
        "SIGHUP": 1,
        "SIGINT": 2,
        "SIGQUIT": 3,
        "SIGILL": 4,
        "SIGTRAP": 5,
        "SIGABRT": 6,
        "SIGIOT": 6,
        "SIGBUS": 7,
        "SIGFPE": 8,
        "SIGKILL": 9,
        "SIGUSR1": 10,
        "SIGSEGV": 11,
        "SIGUSR2": 12,
        "SIGPIPE": 13,
        "SIGALRM": 14,
        "SIGTERM": 15,
        "SIGSTKFLT": 16,
        "SIGCHLD": 17,
        "SIGCLD": 17,
        "SIGCONT": 18,
        "SIGSTOP": 19,
        "SIGTSTP": 20,
        "SIGTTIN": 21,
        "SIGTTOU": 22,
        "SIGURG": 23,
        "SIGXCPU": 24,
        "SIGXFSZ": 25,
        "SIGVTALRM": 26,
        "SIGPROF": 27,
        "SIGWINCH": 28,
        "SIGIO": 29,
        "SIGPOLL": 29,
        "SIGPWR": 30,
        "SIGSYS": 31,
        "SIGUNUSED": 31,
        "SIGRTMIN": 32,
        "SIGRTMAX": 63,
    }
)
SIGNALS_BY_MACHINE_NAME = types.MappingProxyType(_SIGNALS_BY_MACHINE_NAME_TMP)
del _SIGNALS_BY_MACHINE_NAME_TMP

_SIGACTION_FLAGS_BY_MACHINE_NAME_TMP = {}
for _name in (
    "aarch64",
    "arc",
    "nios2",
    "ppc",
    "ppc64",
    "s390",
    "s390x",
    "sh",
    "xtensa",
):
    _SIGACTION_FLAGS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SA_NOCLDSTOP": 0x1,
            "SA_NOCLDWAIT": 0x2,
            "SA_SIGINFO": 0x4,
            "SA_UNSUPPORTED": 0x400,
            "SA_EXPOSE_TAGBITS": 0x800,
            "SA_IMMUTABLE": 0x800000,
            "SA_RESTORER": 0x4000000,
            "SA_ONSTACK": 0x8000000,
            "SA_STACK": 0x8000000,
            "SA_RESTART": 0x10000000,
            "SA_NODEFER": 0x40000000,
            "SA_NOMASK": 0x40000000,
            "SA_RESETHAND": 0x80000000,
            "SA_ONESHOT": 0x80000000,
        }
    )
_SIGACTION_FLAGS_BY_MACHINE_NAME_TMP["alpha"] = types.MappingProxyType(
    {
        "SA_ONSTACK": 0x1,
        "SA_STACK": 0x1,
        "SA_RESTART": 0x2,
        "SA_NOCLDSTOP": 0x4,
        "SA_NODEFER": 0x8,
        "SA_NOMASK": 0x8,
        "SA_RESETHAND": 0x10,
        "SA_ONESHOT": 0x10,
        "SA_NOCLDWAIT": 0x20,
        "SA_SIGINFO": 0x40,
        "SA_UNSUPPORTED": 0x400,
        "SA_EXPOSE_TAGBITS": 0x800,
        "SA_IMMUTABLE": 0x800000,
    }
)
_SIGACTION_FLAGS_BY_MACHINE_NAME_TMP["arm"] = types.MappingProxyType(
    {
        "SA_NOCLDSTOP": 0x1,
        "SA_NOCLDWAIT": 0x2,
        "SA_SIGINFO": 0x4,
        "SA_UNSUPPORTED": 0x400,
        "SA_EXPOSE_TAGBITS": 0x800,
        "SA_IMMUTABLE": 0x800000,
        "SA_THIRTYTWO": 0x2000000,
        "SA_RESTORER": 0x4000000,
        "SA_ONSTACK": 0x8000000,
        "SA_STACK": 0x8000000,
        "SA_RESTART": 0x10000000,
        "SA_NODEFER": 0x40000000,
        "SA_NOMASK": 0x40000000,
        "SA_RESETHAND": 0x80000000,
        "SA_ONESHOT": 0x80000000,
    }
)
for _name in (
    "csky",
    "hexagon",
    "loongarch",
    "loongarch64",
    "m68k",
    "microblaze",
    "openrisc",
    "riscv32",
    "riscv64",
):
    _SIGACTION_FLAGS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SA_NOCLDSTOP": 0x1,
            "SA_NOCLDWAIT": 0x2,
            "SA_SIGINFO": 0x4,
            "SA_UNSUPPORTED": 0x400,
            "SA_EXPOSE_TAGBITS": 0x800,
            "SA_IMMUTABLE": 0x800000,
            "SA_ONSTACK": 0x8000000,
            "SA_STACK": 0x8000000,
            "SA_RESTART": 0x10000000,
            "SA_NODEFER": 0x40000000,
            "SA_NOMASK": 0x40000000,
            "SA_RESETHAND": 0x80000000,
            "SA_ONESHOT": 0x80000000,
        }
    )
for _name in ("i386", "x86_64"):
    _SIGACTION_FLAGS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SA_NOCLDSTOP": 0x1,
            "SA_NOCLDWAIT": 0x2,
            "SA_SIGINFO": 0x4,
            "SA_UNSUPPORTED": 0x400,
            "SA_EXPOSE_TAGBITS": 0x800,
            "SA_IMMUTABLE": 0x800000,
            "SA_X32_ABI": 0x1000000,
            "SA_IA32_ABI": 0x2000000,
            "SA_RESTORER": 0x4000000,
            "SA_ONSTACK": 0x8000000,
            "SA_STACK": 0x8000000,
            "SA_RESTART": 0x10000000,
            "SA_NODEFER": 0x40000000,
            "SA_NOMASK": 0x40000000,
            "SA_RESETHAND": 0x80000000,
            "SA_ONESHOT": 0x80000000,
        }
    )
for _name in ("mips", "mips64"):
    _SIGACTION_FLAGS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SA_NOCLDSTOP": 0x1,
            "SA_SIGINFO": 0x8,
            "SA_UNSUPPORTED": 0x400,
            "SA_EXPOSE_TAGBITS": 0x800,
            "SA_NOCLDWAIT": 0x10000,
            "SA_IMMUTABLE": 0x800000,
            "SA_ONSTACK": 0x8000000,
            "SA_STACK": 0x8000000,
            "SA_RESTART": 0x10000000,
            "SA_NODEFER": 0x40000000,
            "SA_NOMASK": 0x40000000,
            "SA_RESETHAND": 0x80000000,
            "SA_ONESHOT": 0x80000000,
        }
    )
for _name in ("parisc", "parisc64"):
    _SIGACTION_FLAGS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SA_ONSTACK": 0x1,
            "SA_STACK": 0x1,
            "SA_RESETHAND": 0x4,
            "SA_ONESHOT": 0x4,
            "SA_NOCLDSTOP": 0x8,
            "SA_SIGINFO": 0x10,
            "SA_NODEFER": 0x20,
            "SA_NOMASK": 0x20,
            "SA_RESTART": 0x40,
            "SA_NOCLDWAIT": 0x80,
            "SA_UNSUPPORTED": 0x400,
            "SA_EXPOSE_TAGBITS": 0x800,
            "SA_IMMUTABLE": 0x800000,
        }
    )
for _name in ("sparc", "sparc64"):
    _SIGACTION_FLAGS_BY_MACHINE_NAME_TMP[_name] = types.MappingProxyType(
        {
            "SA_ONSTACK": 0x1,
            "SA_STACK": 0x1,
            "SA_RESTART": 0x2,
            "SA_RESETHAND": 0x4,
            "SA_ONESHOT": 0x4,
            "SA_NOCLDSTOP": 0x8,
            "SA_NODEFER": 0x20,
            "SA_NOMASK": 0x20,
            "SA_NOCLDWAIT": 0x100,
            "SA_SIGINFO": 0x200,
            "SA_UNSUPPORTED": 0x400,
            "SA_EXPOSE_TAGBITS": 0x800,
            "SA_IMMUTABLE": 0x800000,
        }
    )
SIGACTION_FLAGS_BY_MACHINE_NAME = types.MappingProxyType(
    _SIGACTION_FLAGS_BY_MACHINE_NAME_TMP
)
del _SIGACTION_FLAGS_BY_MACHINE_NAME_TMP
