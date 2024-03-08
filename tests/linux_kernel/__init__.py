# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import ctypes
import errno
from fcntl import ioctl
import mmap
import os
from pathlib import Path
import pickle
import re
import signal
import socket
import sys
import time
import traceback
from typing import NamedTuple
import unittest

import drgn
from tests import TestCase
from util import NORMALIZED_MACHINE_NAME, SYS


class LinuxKernelTestCase(TestCase):
    prog = None
    skip_reason = None

    @staticmethod
    def _load_debug_info(prog):
        paths = []
        try:
            paths.append(os.environ["DRGN_TEST_KMOD"])
        except KeyError:
            pass
        prog.load_debug_info(paths, True)

    @classmethod
    def setUpClass(cls):
        # We only want to create the Program once for all tests, so it's cached
        # as a class variable (in the base class). If we can't run these tests
        # for whatever reason, we also cache that.
        if LinuxKernelTestCase.prog is not None:
            return
        if LinuxKernelTestCase.skip_reason is None:
            try:
                run_tests = int(os.environ["DRGN_RUN_LINUX_KERNEL_TESTS"]) != 0
            except (KeyError, ValueError):
                run_tests = True
                force_run = False
            else:
                force_run = run_tests
            if run_tests:
                prog = drgn.Program()
                try:
                    prog.set_kernel()
                except PermissionError:
                    if force_run:
                        raise
                    LinuxKernelTestCase.skip_reason = (
                        "Linux kernel tests must be run as root "
                        "(run with env DRGN_RUN_LINUX_KERNEL_TESTS=1 to force)"
                    )
                except (FileNotFoundError, ValueError):
                    if force_run:
                        raise
                    LinuxKernelTestCase.skip_reason = (
                        "Linux kernel tests require /proc/kcore "
                        "(run with env DRGN_RUN_LINUX_KERNEL_TESTS=1 to force)"
                    )
                else:
                    # Some of the tests use the loop module. Open loop-control
                    # so that it is loaded.
                    try:
                        with open("/dev/loop-control", "r"):
                            pass
                    except FileNotFoundError:
                        pass
                    try:
                        cls._load_debug_info(prog)
                        LinuxKernelTestCase.prog = prog
                        return
                    except drgn.MissingDebugInfoError as e:
                        if force_run:
                            raise
                        LinuxKernelTestCase.skip_reason = str(e)
            else:
                LinuxKernelTestCase.skip_reason = "env DRGN_RUN_LINUX_KERNEL_TESTS=0"
        raise unittest.SkipTest(LinuxKernelTestCase.skip_reason)


skip_unless_have_test_kmod = unittest.skipUnless(
    "DRGN_TEST_KMOD" in os.environ, "test requires drgn_test Linux kernel module"
)

skip_unless_have_test_disk = unittest.skipUnless(
    "DRGN_TEST_DISK" in os.environ,
    "test requires disk to overwrite; set DRGN_TEST_DISK environment variable (e.g., DRGN_TEST_DISK=/dev/vda)",
)

# Please keep this in sync with docs/support_matrix.rst and the module
# docstring in drgn/helpers/linux/mm.py.
HAVE_FULL_MM_SUPPORT = NORMALIZED_MACHINE_NAME in (
    "aarch64",
    "ppc64",
    "s390x",
    "x86_64",
)

skip_unless_have_full_mm_support = unittest.skipUnless(
    HAVE_FULL_MM_SUPPORT,
    f"mm support is not implemented for {NORMALIZED_MACHINE_NAME}",
)

skip_unless_have_stack_tracing = unittest.skipUnless(
    NORMALIZED_MACHINE_NAME in {"aarch64", "ppc64", "s390x", "x86_64"},
    f"stack tracing is not implemented for {NORMALIZED_MACHINE_NAME}",
)


# PRNG used by the test kernel module.
def prng32(seed):
    seed = seed.encode("ascii")
    assert len(seed) == 4
    x = int.from_bytes(seed, "big")
    while True:
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        yield x


def wait_until(fn, *args, **kwds):
    TIMEOUT = 5
    deadline = time.monotonic() + TIMEOUT
    sleep = 1e-6
    while True:
        if fn(*args, **kwds):
            break
        now = time.monotonic()
        if now >= deadline:
            raise Exception(f"condition was not met in {TIMEOUT} seconds")
        time.sleep(min(deadline - now, sleep))
        sleep *= 2


def proc_state(pid):
    with open(f"/proc/{pid}/status", "r") as f:
        return re.search(r"State:\s*(\S)", f.read(), re.M).group(1)


# Context manager that:
# 1. Forks a process which optionally calls a function and then stops with
#    SIGSTOP.
# 2. Waits for the child process to stop.
# 3. Returns the PID of the child process, and return value of the function if
#    provided, from __enter__().
# 4. Kills the child process in __exit__().
@contextlib.contextmanager
def fork_and_stop(fn=None, *args, **kwds):
    with contextlib.ExitStack() as exit_stack:
        if fn:
            r, w = os.pipe()
            pipe_r = exit_stack.enter_context(open(r, "rb"))
            pipe_w = exit_stack.enter_context(open(w, "wb"))
        pid = os.fork()
        try:
            if pid == 0:
                try:
                    if fn:
                        pipe_r.close()
                        ret = fn(*args, **kwds)
                        pickle.dump(ret, pipe_w)
                        pipe_w.close()
                    while True:
                        os.kill(os.getpid(), signal.SIGSTOP)
                finally:
                    traceback.print_exc()
                    sys.stderr.flush()
                    os._exit(1)
            if fn:
                pipe_w.close()
                ret = pickle.load(pipe_r)
            _, status = os.waitpid(pid, os.WUNTRACED)
            if not os.WIFSTOPPED(status):
                raise Exception("child process exited")
            if fn:
                yield pid, ret
            else:
                yield pid
        finally:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def smp_enabled():
    return bool(re.search(r"\bSMP\b", os.uname().version))


def parse_range_list(s):
    values = set()
    s = s.strip()
    if s:
        for range_str in s.split(","):
            first, sep, last = range_str.partition("-")
            if sep:
                values.update(range(int(first), int(last) + 1))
            else:
                values.add(int(first))
    return values


_c = ctypes.CDLL(None, use_errno=True)

_mount = _c.mount
_mount.restype = ctypes.c_int
_mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
]
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_SYNCHRONOUS = 16
MS_REMOUNT = 32
MS_MANDLOCK = 64
MS_DIRSYNC = 128
MS_NOSYMFOLLOW = 256
MS_NOATIME = 1024
MS_NODIRATIME = 2048
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_SILENT = 32768
MS_POSIXACL = 1 << 16
MS_UNBINDABLE = 1 << 17
MS_PRIVATE = 1 << 18
MS_SLAVE = 1 << 19
MS_SHARED = 1 << 20
MS_RELATIME = 1 << 21
MS_KERNMOUNT = 1 << 22
MS_I_VERSION = 1 << 23
MS_STRICTATIME = 1 << 24
MS_LAZYTIME = 1 << 25


def _check_ctypes_syscall(ret, *args):
    if ret == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), *args)
    return ret


def mount(source, target, fstype, flags=0, data=None):
    _check_ctypes_syscall(
        _mount(
            os.fsencode(source),
            os.fsencode(target),
            fstype.encode(),
            flags,
            None if data is None else data.encode(),
        ),
        source,
        None,
        target,
    )


_umount2 = _c.umount2
_umount2.restype = ctypes.c_int
_umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]


def umount(target, flags=0):
    _check_ctypes_syscall(_umount2(os.fsencode(target), flags), target)


_MOUNTS_RE = re.compile(
    rb"(?P<source>[^ ]+) (?P<mount_point>[^ ]+) (?P<fstype>[^ ]+) "
    rb"(?P<mount_options>[^ ]+) [0-9]+ [0-9]+"
)


class Mount(NamedTuple):
    source: str
    mount_point: Path
    fstype: str
    mount_options: str


def iter_mounts(pid="self"):
    with open(f"/proc/{pid}/mounts", "rb") as f:
        for line in f:
            match = _MOUNTS_RE.match(line)
            assert match
            yield Mount(
                source=match["source"].decode("unicode-escape"),
                mount_point=Path(match["mount_point"].decode("unicode-escape")),
                fstype=match["fstype"].decode("unicode-escape"),
                mount_options=match["mount_options"].decode("unicode-escape"),
            )


_mlock = _c.mlock
_mlock.restype = ctypes.c_int
_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]


_MAPS_RE = re.compile(
    rb"(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+) (?P<flags>\S+) (?P<offset>[0-9a-f]+) (?P<dev_major>[0-9a-f]+):(?P<dev_minor>[0-9a-f]+) (?P<ino>[0-9]+)\s*(?P<path>.*)"
)


class VmMap(NamedTuple):
    start: int
    end: int
    read: bool
    write: bool
    execute: bool
    shared: bool
    offset: int
    dev: int
    ino: int
    path: str

    def is_gate(self) -> bool:
        # Arm has a gate VMA named "vectors", and x86 has one named "vsyscall".
        return self.path in ("[vectors]", "[vsyscall]")


def iter_maps(pid="self"):
    with open(f"/proc/{pid}/maps", "rb") as f:
        for line in f:
            match = _MAPS_RE.match(line)
            flags = match["flags"]
            yield VmMap(
                start=int(match["start"], 16),
                end=int(match["end"], 16),
                read=b"r" in flags,
                write=b"w" in flags,
                execute=b"x" in flags,
                shared=b"s" in flags,
                offset=int(match["offset"], 16),
                dev=os.makedev(
                    int(match["dev_major"], 16), int(match["dev_minor"], 16)
                ),
                ino=int(match["ino"]),
                path=os.fsdecode(match["path"]),
            )


def mlock(addr, len):
    _check_ctypes_syscall(_mlock(addr, len))


CSIGNAL = 0x000000FF
CLONE_VM = 0x00000100
CLONE_FS = 0x00000200
CLONE_FILES = 0x00000400
CLONE_SIGHAND = 0x00000800
CLONE_PIDFD = 0x00001000
CLONE_PTRACE = 0x00002000
CLONE_VFORK = 0x00004000
CLONE_PARENT = 0x00008000
CLONE_THREAD = 0x00010000
CLONE_NEWNS = 0x00020000
CLONE_SYSVSEM = 0x00040000
CLONE_SETTLS = 0x00080000
CLONE_PARENT_SETTID = 0x00100000
CLONE_CHILD_CLEARTID = 0x00200000
CLONE_DETACHED = 0x00400000
CLONE_UNTRACED = 0x00800000
CLONE_CHILD_SETTID = 0x01000000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
CLONE_IO = 0x80000000
CLONE_CLEAR_SIGHAND = 0x100000000
CLONE_INTO_CGROUP = 0x200000000
CLONE_NEWTIME = 0x00000080


_unshare = _c.unshare
_unshare.argtypes = [ctypes.c_int]
_unshare.restype = ctypes.c_int


def unshare(flags):
    _check_ctypes_syscall(_unshare(flags))


_LOOP_SET_FD = 0x4C00
_LOOP_SET_STATUS64 = 0x4C04
_LOOP_GET_STATUS64 = 0x4C05
_LOOP_CONFIGURE = 0x4C0A
_LOOP_CTL_GET_FREE = 0x4C82

_LO_FLAGS_AUTOCLEAR = 4


def losetup(fd):
    have_loop_configure = True
    with open("/dev/loop-control", "r") as loop_control:
        while True:
            index = ioctl(loop_control.fileno(), _LOOP_CTL_GET_FREE)
            loop = open(f"/dev/loop{index}", "rb")
            close_loop = True
            try:
                # Since Linux kernel commit 3448914e8cc5 ("loop: Add
                # LOOP_CONFIGURE ioctl") (in v5.8), we can set the file
                # descriptor and the autoclear flag atomically with the
                # LOOP_CONFIGURE ioctl. Before that, we have to use
                # LOOP_SET_FD, then LOOP_GET_STATUS64 and LOOP_SET_STATUS64.
                config = bytearray(304)  # sizeof(struct loop_config)
                config[:4] = fd.to_bytes(4, sys.byteorder)
                config[60:64] = _LO_FLAGS_AUTOCLEAR.to_bytes(4, sys.byteorder)
                try:
                    if have_loop_configure:
                        ioctl(loop.fileno(), _LOOP_CONFIGURE, config)
                    else:
                        ioctl(loop.fileno(), _LOOP_SET_FD, fd)
                except OSError as e:
                    if e.errno == errno.EBUSY:
                        continue
                    elif have_loop_configure and e.errno == errno.EINVAL:
                        have_loop_configure = False
                        continue
                    raise
                if not have_loop_configure:
                    info = bytearray(232)  # sizeof(struct loop_info64)
                    ioctl(loop.fileno(), _LOOP_GET_STATUS64, info)
                    lo_flags = int.from_bytes(info[52:56], sys.byteorder)
                    lo_flags |= _LO_FLAGS_AUTOCLEAR
                    info[52:56] = lo_flags.to_bytes(4, sys.byteorder)
                    ioctl(loop.fileno(), _LOOP_SET_STATUS64, info, False)
                close_loop = False
                return loop
            finally:
                if close_loop:
                    loop.close()


_swapon = _c.swapon
_swapon.argtypes = [ctypes.c_char_p, ctypes.c_int]
_swapon.restype = ctypes.c_int

_swapoff = _c.swapoff
_swapoff.argtypes = [ctypes.c_char_p]
_swapoff.restype = ctypes.c_int


def swapon(path, flags=0):
    _check_ctypes_syscall(_swapon(os.fsencode(path), flags), path)


def swapoff(path):
    _check_ctypes_syscall(_swapoff(os.fsencode(path)), path)


def mkswap(path, size):
    header = bytearray(mmap.PAGESIZE)
    header[1024:1028] = (1).to_bytes(4, sys.byteorder)  # version
    header[1028:1032] = (size // mmap.PAGESIZE - 1).to_bytes(
        4, sys.byteorder
    )  # last_page
    header[1036:1052] = os.urandom(16)  # sws_uuid
    magic = b"SWAPSPACE2"
    header[-len(magic) :] = magic

    with open(path, "wb") as f:
        os.posix_fallocate(f.fileno(), 0, size)
        f.write(header)


class _perf_event_attr_sample_period_or_freq(ctypes.Union):
    _fields_ = (
        ("sample_period", ctypes.c_uint64),
        ("sample_freq", ctypes.c_uint64),
    )


class _perf_event_attr_wakeup_events_or_watermark(ctypes.Union):
    _fields_ = (
        ("wakeup_events", ctypes.c_uint32),
        ("wakeup_watermark", ctypes.c_uint32),
    )


class _perf_event_attr_config1(ctypes.Union):
    _fields_ = (
        ("bp_addr", ctypes.c_uint64),
        ("kprobe_func", ctypes.c_uint64),
        ("uprobe_path", ctypes.c_uint64),
        ("config1", ctypes.c_uint64),
    )


class _perf_event_attr_config2(ctypes.Union):
    _fields_ = (
        ("bp_len", ctypes.c_uint64),
        ("kprobe_addr", ctypes.c_uint64),
        ("probe_offset", ctypes.c_uint64),
        ("config2", ctypes.c_uint64),
    )


class perf_event_attr(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("_sample_period_or_freq", _perf_event_attr_sample_period_or_freq),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("_bitfields1", ctypes.c_uint64),
        ("_wakeup_events_or_watermark", _perf_event_attr_wakeup_events_or_watermark),
        ("bp_type", ctypes.c_uint32),
        ("_config1", _perf_event_attr_config1),
        ("_config2", _perf_event_attr_config2),
        ("branch_sample_type", ctypes.c_uint64),
        ("sample_regs_user", ctypes.c_uint64),
        ("sample_stack_user", ctypes.c_uint32),
        ("clockid", ctypes.c_int32),
        ("sample_regs_intr", ctypes.c_uint64),
        ("aux_watermark", ctypes.c_uint32),
        ("sample_max_stack", ctypes.c_uint16),
        ("__reserved2", ctypes.c_uint16),
        ("aux_sample_size", ctypes.c_uint32),
        ("__reserved3", ctypes.c_uint32),
        ("sig_data", ctypes.c_uint64),
        ("config3", ctypes.c_uint64),
    )
    _anonymous_ = (
        "_sample_period_or_freq",
        "_wakeup_events_or_watermark",
        "_config1",
        "_config2",
    )


PERF_FLAG_FD_NO_GROUP = 1 << 0
PERF_FLAG_FD_OUTPUT = 1 << 1
PERF_FLAG_PID_CGROUP = 1 << 2
PERF_FLAG_FD_CLOEXEC = 1 << 3


def perf_event_open(attr, pid, cpu, group_fd=-1, flags=PERF_FLAG_FD_CLOEXEC):
    attr.size = ctypes.sizeof(perf_event_attr)
    return _check_ctypes_syscall(
        _syscall(
            SYS["perf_event_open"],
            ctypes.byref(attr),
            ctypes.c_int(pid),
            ctypes.c_int(cpu),
            ctypes.c_int(group_fd),
            ctypes.c_ulong(flags),
        )
    )


_syscall = _c.syscall
_syscall.restype = ctypes.c_long


def create_socket(*args, **kwds):
    try:
        return socket.socket(*args, **kwds)
    except OSError as e:
        if e.errno in (errno.ENOSYS, errno.EAFNOSUPPORT, errno.ESOCKTNOSUPPORT):
            raise unittest.SkipTest("kernel does not support TCP")
        else:
            raise
