# Copyright 2020 - Omar Sandoval
# SPDX-License-Identifier: GPL-3.0+

import os
import os.path
import socket
import subprocess
import tempfile
from typing import Any, Dict, Mapping, Optional, Sequence

from util import nproc


class LostVMError(Exception):
    pass


class VM:
    def __init__(
        self, *, init: str, onoatimehack: str, vmlinux: str, vmlinuz: str,
    ) -> None:
        self._temp_dir = tempfile.TemporaryDirectory("drgn-vmtest-")
        self._server_sock = socket.socket(socket.AF_UNIX)
        socket_path = os.path.join(self._temp_dir.name, "socket")
        self._server_sock.bind(socket_path)
        self._server_sock.listen()
        init = os.path.abspath(init)
        if " " in init:
            init = '"' + init + '"'
        vmlinux = os.path.abspath(vmlinux)
        if " " in vmlinux:
            vmlinux = '"' + vmlinux + '"'
        # This was added in QEMU 4.2.0.
        if (
            "multidevs"
            in subprocess.run(
                ["qemu-system-x86_64", "-help"],
                stdout=subprocess.PIPE,
                universal_newlines=True,
            ).stdout
        ):
            multidevs = ",multidevs=remap"
        else:
            multidevs = ""
        self._qemu = subprocess.Popen(
            [
                # fmt: off
                "qemu-system-x86_64", "-cpu", "kvm64", "-enable-kvm",

                "-smp", str(nproc()), "-m", "2G",

                "-nodefaults", "-display", "none", "-serial", "mon:stdio",

                # This along with -append panic=-1 ensures that we exit on a
                # panic instead of hanging.
                "-no-reboot",

                "-virtfs",
                f"local,id=root,path=/,mount_tag=/dev/root,security_model=none,readonly{multidevs}",

                "-device", "virtio-serial",
                "-chardev", f"socket,id=vmtest,path={socket_path}",
                "-device",
                "virtserialport,chardev=vmtest,name=com.osandov.vmtest.0",

                "-kernel", vmlinuz,
                "-append",
                f"rootfstype=9p rootflags=trans=virtio,cache=loose ro console=0,115200 panic=-1 init={init} VMLINUX={vmlinux}",
                # fmt: on
            ],
            env={
                **os.environ,
                "LD_PRELOAD": f"{onoatimehack}:{os.getenv('LD_PRELOAD', '')}",
            },
        )
        self._server_sock.settimeout(5)
        try:
            self._sock = self._server_sock.accept()[0]
        except socket.timeout:
            raise LostVMError(
                f"QEMU did not connect within {self._server_sock.gettimeout()} seconds"
            )

    def __enter__(self) -> "VM":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if hasattr(self, "_sock"):
            self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()
        if hasattr(self, "_qemu"):
            self._qemu.wait()
        if hasattr(self, "_server_sock"):
            self._server_sock.close()
        if hasattr(self, "_temp_dir"):
            self._temp_dir.cleanup()

    def run(
        self,
        args: Sequence[str],
        *,
        executable: Optional[str] = None,
        cwd: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
        self._sock.sendall(len(args).to_bytes(4, "little"))
        for arg in args:
            self._sock.sendall(arg.encode())
            self._sock.sendall(b"\0")

        if env is None:
            env = {}
        self._sock.sendall(len(env).to_bytes(4, "little"))
        for key, value in env.items():
            self._sock.sendall(key.encode())
            self._sock.sendall(b"=")
            self._sock.sendall(value.encode())
            self._sock.sendall(b"\0")

        if executable is None:
            executable = args[0]
        self._sock.sendall(executable.encode())
        self._sock.sendall(b"\0")

        self._sock.sendall((cwd or "").encode())
        self._sock.sendall(b"\0")

        wstatus_buf = bytearray()
        while len(wstatus_buf) < 2:
            try:
                buf = self._sock.recv(2 - len(wstatus_buf))
            except ConnectionResetError:
                buf = b""
            if not buf:
                raise LostVMError("lost VM")
            wstatus_buf.extend(buf)
        wstatus = int.from_bytes(wstatus_buf, "little")
        if os.WIFEXITED(wstatus):
            returncode = os.WEXITSTATUS(wstatus)
        else:
            returncode = -os.WTERMSIG(wstatus)
        return subprocess.CompletedProcess(args, returncode)


if __name__ == "__main__":
    import argparse
    import sys

    from vmtest.build import build_vmtest
    from vmtest.resolver import KernelResolver

    parser = argparse.ArgumentParser(
        description="run vmtest virtual machine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-d",
        "--directory",
        default="build/vmtest",
        help="directory for build artifacts and downloaded kernels",
    )
    parser.add_argument(
        "--lost-status",
        metavar="STATUS",
        type=int,
        default=128,
        help="exit status if VM is lost",
    )
    parser.add_argument(
        "-k",
        "--kernel",
        default=argparse.SUPPRESS,
        help="kernel to use (default: latest available kernel)",
    )
    parser.add_argument(
        "-w",
        "--wd",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="working directory for command (default: /)",
    )
    parser.add_argument(
        "command",
        type=str,
        nargs=argparse.REMAINDER,
        help="command to run in VM (default: /bin/sh -i)",
    )
    args = parser.parse_args()

    with KernelResolver(
        [getattr(args, "kernel", "*")], download_dir=args.directory
    ) as resolver:
        kernel = next(iter(resolver))
        try:
            with VM(
                **build_vmtest(args.directory),  # type: ignore
                vmlinux=kernel.vmlinux,
                vmlinuz=kernel.vmlinuz,
            ) as vm:
                proc = vm.run(
                    args.command or ["/bin/sh", "-i"], cwd=getattr(args, "wd", None)
                )
                if proc.returncode < 0:
                    sys.exit(128 - proc.returncode)
                else:
                    sys.exit(proc.returncode)
        except LostVMError as e:
            print("error:", e, file=sys.stderr)
            sys.exit(args.lost_status)
