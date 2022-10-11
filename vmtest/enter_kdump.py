# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import os
import re
import sys

from util import NORMALIZED_MACHINE_NAME, SYS

# Some architectures don't implement kexec_file_load. Note that even if the
# number is defined, it may not be implemented.
if "kexec_file_load" not in SYS:
    sys.exit(f"kexec_file_load is not defined on {NORMALIZED_MACHINE_NAME}")

KEXEC_FILE_ON_CRASH = 2
KEXEC_FILE_NO_INITRAMFS = 4

syscall = ctypes.CDLL(None, use_errno=True).syscall
syscall.restype = ctypes.c_long

with open("/proc/cmdline", "rb") as f:
    cmdline = f.read().rstrip(b"\n")
    cmdline = re.sub(rb"(^|\s)crashkernel=\S+", b"", cmdline)
    # `nokaslr` is required to avoid sporadically failing to reserve space for the
    # capture kernel
    cmdline += b" nokaslr"
    if os.getenv("KDUMP_NEEDS_NOSMP"):
        # `nosmp` is required to avoid QEMU sporadically failing an internal
        # assertion when using emulation.
        cmdline += b" nosmp"

with open(f"/lib/modules/{os.uname().release}/vmlinuz", "rb") as kernel:
    if syscall(
        ctypes.c_long(SYS["kexec_file_load"]),
        ctypes.c_int(kernel.fileno()),
        ctypes.c_int(-1),
        ctypes.c_ulong(len(cmdline) + 1),
        ctypes.c_char_p(cmdline + b"\0"),
        ctypes.c_ulong(KEXEC_FILE_ON_CRASH | KEXEC_FILE_NO_INITRAMFS),
    ):
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

with open("/proc/sysrq-trigger", "w") as f:
    f.write("c")
