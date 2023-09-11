# Copyright (c) Stephen Brennan <stephen@brennan.io>
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Helper for opening a file as root and transmitting it via unix socket"""
import array
import os
from pathlib import Path
import pickle
import socket
import subprocess
import sys
import tempfile
from typing import Union


def open_via_sudo(
    path: Union[Path, str],
    flags: int,
    mode: int = 0o777,
) -> int:
    """Implements os.open() using sudo to get permissions"""
    # Currently does not support dir_fd argument
    with tempfile.TemporaryDirectory() as td:
        sockpath = Path(td) / "sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.bind(str(sockpath))
            subprocess.check_call(
                [
                    "sudo",
                    "-p",
                    f"[sudo] password for %p to open {path}: ",
                    sys.executable,
                    "-B",
                    __file__,
                    sockpath,
                    path,
                    str(flags),
                    str(mode),
                ],
            )
            fds = array.array("i")
            msg, ancdata, flags, addr = sock.recvmsg(
                4096, socket.CMSG_SPACE(fds.itemsize)
            )
            for level, typ, data in ancdata:
                if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                    data = data[: fds.itemsize]
                    fds.frombytes(data)
                    return fds[0]
            raise pickle.loads(msg)


def main() -> None:
    sockpath = sys.argv[1]
    filename = sys.argv[2]
    flags = int(sys.argv[3])
    mode = int(sys.argv[4])

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(sockpath)
    try:
        fd = os.open(filename, flags, mode)
        fds = array.array("i", [fd])
        sock.sendmsg(
            [b"success"],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)],
        )
    except Exception as e:
        sock.sendmsg([pickle.dumps(e)])


if __name__ == "__main__":
    main()
