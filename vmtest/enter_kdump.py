# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import ctypes
import os
import re
import subprocess

from util import NORMALIZED_MACHINE_NAME, SYS

KEXEC_FILE_ON_CRASH = 2
KEXEC_FILE_NO_INITRAMFS = 4


def main() -> None:
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

    vmlinuz = f"/lib/modules/{os.uname().release}/vmlinuz"

    # On x86-64, kexec_file_load() is supported on all kernel versions we care
    # about, and it's simple enough to call ourselves. On other architectures,
    # we just use kexec(8).
    if NORMALIZED_MACHINE_NAME == "x86_64":
        syscall = ctypes.CDLL(None, use_errno=True).syscall
        syscall.restype = ctypes.c_long

        with open(vmlinuz, "rb") as kernel:
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
    else:
        subprocess.check_call(
            [
                "kexec",
                "--load-panic",
                "--kexec-syscall-auto",
                "--command-line=" + cmdline.decode(),
                vmlinuz,
            ]
        )

    with open("/proc/self/comm", "w") as f:
        f.write("selfdestruct")

    # Avoid panicking from CPU 0 on s390x. See _skip_if_cpu0_on_s390x().
    if NORMALIZED_MACHINE_NAME == "s390x":
        cpus = os.sched_getaffinity(0)
        cpus.remove(0)
        if cpus:
            os.sched_setaffinity(0, cpus)

    with open("/proc/sysrq-trigger", "w") as f:
        f.write("c")


if __name__ == "__main__":
    main()
