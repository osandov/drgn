# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import ctypes
import io
import mmap
import os
from pathlib import Path
import sys
import tempfile

from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import LinuxKernelTestCase, fork_and_sigwait
from tools.fsrefs import main


class TestFsRefs(LinuxKernelTestCase):
    def setUp(self):
        super().setUp()
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = Path(self._tmpdir.name)

    def tearDown(self):
        try:
            tmpdir = self._tmpdir
        except AttributeError:
            pass
        else:
            tmpdir.cleanup()
        super().tearDown()

    def run_and_capture(self, *args):
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            main(self.prog, args)
        return f.getvalue()

    def test_fd(self):
        path = self._tmp / "file"
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            self.assertRegex(
                self.run_and_capture("--inode", str(path)),
                rf"pid {os.getpid()} \(.*\) fd {fd} ",
            )
        finally:
            os.close(fd)

    def test_dereference(self):
        file = self._tmp / "file"
        link = self._tmp / "link"
        file.touch()
        link.symlink_to("file")

        file_fd = os.open(file, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            link_fd = os.open(link, os.O_PATH | os.O_NOFOLLOW)
            try:
                output = self.run_and_capture("--inode", str(link))
                self.assertNotRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {file_fd} ",
                )
                self.assertRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {link_fd} ",
                )

                output = self.run_and_capture("--inode", str(link), "--dereference")
                self.assertRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {file_fd} ",
                )
                self.assertNotRegex(
                    output,
                    rf"pid {os.getpid()} \(.*\) fd {link_fd} ",
                )
            finally:
                os.close(link_fd)
        finally:
            os.close(file_fd)

    def test_cwd(self):
        def mkdir_and_chdir(path, mode):
            os.mkdir(path, mode)
            os.chdir(path)

        path = self._tmp / "dir"
        with fork_and_sigwait(mkdir_and_chdir, path, 0o600) as pid:
            self.assertRegex(
                self.run_and_capture("--inode", str(path)),
                rf"pid {pid} \(.*\) cwd ",
            )

    def test_root(self):
        def mkdir_and_chroot(path, mode):
            os.mkdir(path, mode)
            os.chroot(path)

        path = self._tmp / "dir"
        with fork_and_sigwait(mkdir_and_chroot, path, 0o600) as pid:
            self.assertRegex(
                self.run_and_capture("--inode", str(path)),
                rf"pid {pid} \(.*\) root ",
            )

    def test_exe(self):
        self.assertRegex(
            self.run_and_capture("--inode", sys.executable, "--dereference"),
            rf"pid {os.getpid()} \(.*\) exe ",
        )

    def test_vma(self):
        path = self._tmp / "file"
        with open(path, "w+b") as f:
            os.ftruncate(f.fileno(), mmap.PAGESIZE)
            # Note: this dups the file descriptor internally.
            with mmap.mmap(f.fileno(), mmap.PAGESIZE) as map:
                f.close()
                start = ctypes.addressof(ctypes.c_char.from_buffer(map))
                end = start + mmap.PAGESIZE
                self.assertRegex(
                    self.run_and_capture("--inode", str(path)),
                    rf"pid {os.getpid()} \(.*\) vma {hex(start)}-{hex(end)} ",
                )

    def test_inode_pointer(self):
        self.assertRegex(
            self.run_and_capture(
                "--inode-pointer",
                hex(find_task(self.prog, os.getpid()).mm.exe_file.f_inode),
                "--dereference",
            ),
            rf"pid {os.getpid()} \(.*\) exe ",
        )
