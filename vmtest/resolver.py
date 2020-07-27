# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import fnmatch
import glob
import http.client
import os
import os.path
import queue
import re
import shutil
import subprocess
import threading
from typing import Any, Dict, Iterator, NamedTuple, Optional, Sequence, Union
import urllib.request

from util import KernelVersion


# This URL contains a mapping from file names to URLs where those files can be
# downloaded. This is needed because the files under a Dropbox shared folder
# have randomly-generated links.
_INDEX_URL = "https://www.dropbox.com/sh/2mcf2xvg319qdaw/AAC_AbpvQPRrHF-99B2REpXja/x86_64/INDEX?dl=1"


class ResolvedKernel(NamedTuple):
    release: str
    vmlinux: str
    vmlinuz: str


class KernelResolver:
    def __init__(self, kernels: Sequence[str], download_dir: str) -> None:
        self._kernels = kernels
        self._arch_download_dir = os.path.join(download_dir, "x86_64")
        self._cached_index: Optional[Dict[str, str]] = None
        self._index_lock = threading.Lock()
        self._queue: queue.Queue[Union[ResolvedKernel, Exception, None]] = queue.Queue()
        self._thread: Optional[threading.Thread]
        # Don't create the thread if we don't have anything to do.
        if kernels:
            self._thread = threading.Thread(target=self._resolve_all, daemon=True)
            self._thread.start()
        else:
            self._thread = None
            self._queue.put(None)

    def __enter__(self) -> "KernelResolver":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._thread:
            self._thread.join()

    def _resolve_build(self, path: str) -> ResolvedKernel:
        release = subprocess.check_output(
            ["make", "-s", "kernelrelease"], universal_newlines=True, cwd=path,
        ).strip()
        vmlinuz = subprocess.check_output(
            ["make", "-s", "image_name"], universal_newlines=True, cwd=path,
        ).strip()
        return ResolvedKernel(
            release=release,
            vmlinux=os.path.join(path, "vmlinux"),
            vmlinuz=os.path.join(path, vmlinuz),
        )

    @property
    def _index(self) -> Dict[str, str]:
        if self._cached_index is None:
            with self._index_lock:
                if self._cached_index is None:
                    index = {}
                    with urllib.request.urlopen(_INDEX_URL) as u:
                        for line in u:
                            name, url = line.decode().rstrip("\n").split("\t", 1)
                            index[name] = url
                    self._cached_index = index
        return self._cached_index

    def _find_kernel(self, pattern: str) -> str:
        matches = []
        for name, url in self._index.items():
            match = re.fullmatch(r"vmlinux-(.*)\.zst", name)
            if match and fnmatch.fnmatch(match.group(1), pattern):
                matches.append(match.group(1))
        if not matches:
            raise Exception(f"no kernel release matches {pattern!r}")
        return max(matches, key=KernelVersion)

    def _download_file(self, name: str, *, compressed: bool = False) -> str:
        path = os.path.join(self._arch_download_dir, name)
        if not os.path.exists(path):
            dir = os.path.dirname(path)
            os.makedirs(dir, exist_ok=True)
            with open(os.open(dir, os.O_WRONLY | os.O_TMPFILE), "wb") as f:
                if compressed:
                    name += ".zst"
                with urllib.request.urlopen(self._index[name]) as u:
                    if compressed:
                        with subprocess.Popen(
                            ["zstd", "-d", "-", "--stdout"],
                            stdin=subprocess.PIPE,
                            stdout=f,
                        ) as proc:
                            assert proc.stdin is not None
                            shutil.copyfileobj(u, proc.stdin)
                        if proc.returncode != 0:
                            raise subprocess.CalledProcessError(
                                proc.returncode, proc.args
                            )
                    else:
                        shutil.copyfileobj(u, f)
                    if u.length:
                        raise http.client.IncompleteRead(b"", u.length)
                # Passing dst_dir_fd forces Python to use linkat() with
                # AT_SYMLINK_FOLLOW instead of link(). See
                # https://bugs.python.org/msg348086.
                dir_fd = os.open(dir, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.link(
                        f"/proc/self/fd/{f.fileno()}",
                        os.path.basename(path),
                        dst_dir_fd=dir_fd,
                    )
                finally:
                    os.close(dir_fd)
        return path

    def _download(self, release: str) -> ResolvedKernel:
        # Only do the wildcard lookup if the release is a wildcard
        # pattern.
        if release != glob.escape(release):
            release = self._find_kernel(release)
        vmlinux_path = self._download_file(f"vmlinux-{release}", compressed=True)
        vmlinuz_path = self._download_file(f"vmlinuz-{release}")
        return ResolvedKernel(release, vmlinux_path, vmlinuz_path)

    def _resolve_all(self) -> None:
        try:
            for kernel in self._kernels:
                if kernel.startswith(".") or kernel.startswith("/"):
                    resolved = self._resolve_build(kernel)
                else:
                    resolved = self._download(kernel)
                self._queue.put(resolved)
            self._queue.put(None)
        except Exception as e:
            self._queue.put(e)

    def __iter__(self) -> Iterator[ResolvedKernel]:
        while True:
            result = self._queue.get()
            if isinstance(result, Exception):
                raise result
            elif result is None:
                break
            yield result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="resolve and download vmtest kernels",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-d", "--directory", default="build/vmtest", help="directory to download to"
    )
    parser.add_argument("kernels", metavar="KERNEL", nargs="*")
    args = parser.parse_args()

    with KernelResolver(args.kernels, args.directory) as resolver:
        for kernel in resolver:
            print(kernel)
