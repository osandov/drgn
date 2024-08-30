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
    "alpha": {
        "bpf": 515,
        "finit_module": 507,
        "perf_event_open": 493,
    },
    "arc": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "perf_event_open": 241,
    },
    "arm": {
        "bpf": 386,
        "finit_module": 379,
        "kexec_file_load": 401,
        "perf_event_open": 364,
    },
    "csky": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "perf_event_open": 241,
    },
    "i386": {
        "bpf": 357,
        "finit_module": 350,
        "perf_event_open": 336,
    },
    "m68k": {
        "bpf": 354,
        "finit_module": 348,
        "perf_event_open": 332,
    },
    "microblaze": {
        "bpf": 387,
        "finit_module": 380,
        "perf_event_open": 366,
    },
    "mips64": {
        "bpf": 315,
        "finit_module": 307,
        "perf_event_open": 292,
    },
    "nios2": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "perf_event_open": 241,
    },
    "parisc": {
        "bpf": 341,
        "finit_module": 333,
        "kexec_file_load": 355,
        "perf_event_open": 318,
    },
    "parisc64": {
        "bpf": 341,
        "finit_module": 333,
        "kexec_file_load": 355,
        "perf_event_open": 318,
    },
    "ppc": {
        "bpf": 361,
        "finit_module": 353,
        "perf_event_open": 319,
    },
    "ppc64": {
        "bpf": 361,
        "finit_module": 353,
        "perf_event_open": 319,
    },
    "riscv32": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "perf_event_open": 241,
    },
    "riscv64": {
        "bpf": 280,
        "finit_module": 273,
        "kexec_file_load": 294,
        "perf_event_open": 241,
    },
    "s390": {
        "bpf": 351,
        "finit_module": 344,
        "kexec_file_load": 381,
        "perf_event_open": 331,
    },
    "s390x": {
        "bpf": 351,
        "finit_module": 344,
        "kexec_file_load": 381,
        "perf_event_open": 331,
    },
    "sh": {
        "bpf": 375,
        "finit_module": 368,
        "perf_event_open": 336,
    },
    "sparc": {
        "bpf": 349,
        "finit_module": 342,
        "perf_event_open": 327,
    },
    "sparc64": {
        "bpf": 349,
        "finit_module": 342,
        "perf_event_open": 327,
    },
    "x86_64": {
        "bpf": 321,
        "finit_module": 313,
        "kexec_file_load": 320,
        "perf_event_open": 298,
    },
    "xtensa": {
        "bpf": 340,
        "finit_module": 332,
        "perf_event_open": 327,
    },
}.get(NORMALIZED_MACHINE_NAME, {})
