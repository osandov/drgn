# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import fnmatch
import glob
import http.client
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
from typing import Any, Dict, Iterator, Optional, Sequence, Union
import urllib.request

from util import KernelVersion

# This URL contains a mapping from file names to URLs where those files can be
# downloaded. This is needed because the files under a Dropbox shared folder
# have randomly-generated links.
_INDEX_URL = "https://www.dropbox.com/sh/2mcf2xvg319qdaw/AAC_AbpvQPRrHF-99B2REpXja/x86_64/INDEX?dl=1"


class KernelDownloader:
    def __init__(self, kernels: Sequence[str], download_dir: Path) -> None:
        self._kernels = kernels
        self._arch_download_dir = download_dir / "x86_64"
        self._cached_index: Optional[Dict[str, str]] = None
        self._index_lock = threading.Lock()
        self._queue: queue.Queue[Union[Path, Exception, None]] = queue.Queue()
        self._thread: Optional[threading.Thread]
        # Don't create the thread if we don't have anything to do.
        if kernels:
            self._thread = threading.Thread(target=self._download_all, daemon=True)
            self._thread.start()
        else:
            self._thread = None
            self._queue.put(None)

    def __enter__(self) -> "KernelDownloader":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._thread:
            self._thread.join()

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
            match = re.fullmatch(r"kernel-(.*)\.tar\.zst", name)
            if match and fnmatch.fnmatch(match.group(1), pattern):
                matches.append(match.group(1))
        if not matches:
            raise Exception(f"no kernel release matches {pattern!r}")
        return max(matches, key=KernelVersion)

    def _download(self, release: str) -> Path:
        # Only do the wildcard lookup if the release is a wildcard
        # pattern.
        if release != glob.escape(release):
            release = self._find_kernel(release)
        path = self._arch_download_dir / release
        if not path.exists():
            name = f"kernel-{release}.tar.zst"
            tmp = path.with_name(path.name + ".tmp")
            tmp.mkdir(parents=True)
            remove_tmp = True
            try:
                # Don't assume that the available version of tar has zstd
                # support or the non-standard -I/--use-compress-program option.
                with subprocess.Popen(
                    ["zstd", "-d", "-", "--stdout"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                ) as zstd_proc, subprocess.Popen(
                    ["tar", "-C", str(tmp), "-x"], stdin=zstd_proc.stdout
                ) as tar_proc, urllib.request.urlopen(
                    self._index[name]
                ) as u:
                    assert zstd_proc.stdin is not None
                    shutil.copyfileobj(u, zstd_proc.stdin)
                    zstd_proc.stdin.close()
                if u.length:
                    raise http.client.IncompleteRead(b"", u.length)
                if zstd_proc.returncode != 0:
                    raise subprocess.CalledProcessError(
                        zstd_proc.returncode, zstd_proc.args
                    )
                if tar_proc.returncode != 0:
                    raise subprocess.CalledProcessError(
                        tar_proc.returncode, tar_proc.args
                    )
                tmp.rename(path)
                remove_tmp = False
            finally:
                if remove_tmp:
                    shutil.rmtree(tmp)
        return path

    def _download_all(self) -> None:
        try:
            for kernel in self._kernels:
                self._queue.put(self._download(kernel))
            self._queue.put(None)
        except Exception as e:
            self._queue.put(e)

    def __iter__(self) -> Iterator[Path]:
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
        description="download vmtest kernels",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-d", "--directory", default="build/vmtest", help="directory to download to"
    )
    parser.add_argument("kernels", metavar="KERNEL", nargs="*")
    args = parser.parse_args()

    with KernelDownloader(args.kernels, Path(args.directory)) as downloader:
        for kernel in downloader:
            print(kernel)
