# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import ctypes
import enum
import errno
from fcntl import ioctl
import functools
import mmap
import os
from pathlib import Path
import pickle
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback
from typing import NamedTuple
import unittest

from _drgn_util.platform import _IO, _IOR, NORMALIZED_MACHINE_NAME, SYS
import drgn
from tests import TestCase


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
        super().setUpClass()
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
                    # Load modules that are used by test cases.
                    subprocess.check_call(
                        ["modprobe", "-a", "btrfs", "configs", "loop"]
                    )
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

# Please keep this in sync with docs/support_matrix.rst.
HAVE_FULL_MM_SUPPORT = NORMALIZED_MACHINE_NAME in (
    "aarch64",
    "arm",
    "ppc64",
    "s390x",
    "x86_64",
)

skip_unless_have_full_mm_support = unittest.skipUnless(
    HAVE_FULL_MM_SUPPORT,
    f"mm support is not implemented for {NORMALIZED_MACHINE_NAME}",
)


def skip_if_slob(f):
    @skip_unless_have_test_kmod
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        if self.prog["drgn_test_slob"]:
            self.skipTest("test does not support SLOB")

    return wrapper


def skip_if_highmem(f):
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        if self.prog["max_low_pfn"] < self.prog["max_pfn"]:
            self.skipTest("high memory is not supported")

    return wrapper


# This is a false positive if CONFIG_HIGHMEM=y and CONFIG_HIGHPTE=n, but it's
# good enough for now.
skip_if_highpte = skip_if_highmem

# Please keep this in sync with docs/support_matrix.rst.
skip_unless_have_stack_tracing = unittest.skipUnless(
    NORMALIZED_MACHINE_NAME in {"aarch64", "arm", "ppc64", "s390x", "x86_64"},
    f"stack tracing is not implemented for {NORMALIZED_MACHINE_NAME}",
)


skip_unless_have_memory_hotplug = unittest.skipUnless(
    Path("/sys/bus/memory").exists(), "memory hotplug is not supported"
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
# 2. Waits for the child process to stop and unschedule.
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
            # waitpid() can return as soon as the stopped flag is set on the
            # process; see wait_task_stopped() in the Linux kernel source code:
            # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/exit.c?h=v6.17-rc5#n1313
            # However, the process may still be on the CPU for a short window;
            # see do_signal_stop():
            # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/signal.c?h=v6.17-rc5#n2617
            # So, we need to wait for it to fully unschedule. /proc/pid/syscall
            # contains "running" unless the process is unscheduled; see
            # proc_pid_syscall():
            # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/proc/base.c?h=v6.17-rc5#n675
            # task_current_syscall():
            # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/syscall.c?h=v6.17-rc5#n69
            # and wait_task_inactive():
            # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/sched/core.c?h=v6.17-rc5#n2257
            syscall_path = Path(f"/proc/{pid}/syscall")
            while syscall_path.read_text() == "running\n":
                os.sched_yield()

            if fn:
                yield pid, ret
            else:
                yield pid
        finally:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


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


def online_cpus():
    return parse_range_list(Path("/sys/devices/system/cpu/online").read_text())


def possible_cpus():
    return parse_range_list(Path("/sys/devices/system/cpu/possible").read_text())


def meminfo_field_in_pages(name: str) -> int:
    return (
        int(
            re.search(
                rf"^{name}:\s*([0-9]+)\s*kB",
                Path("/proc/meminfo").read_text(),
                flags=re.M,
            ).group(1)
        )
        * 1024
        // mmap.PAGESIZE
    )


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


_prctl = _c.prctl
_prctl.argtypes = [ctypes.c_int]
_prctl.restype = ctypes.c_int


def prctl_set_vma_anon_name(addr, size, name):
    _check_ctypes_syscall(
        _prctl(
            ctypes.c_int(0x53564D41),  # PR_SET_VMA
            ctypes.c_long(0),  # PR_SET_VMA_ANON_NAME,
            ctypes.c_ulong(addr),
            ctypes.c_ulong(size),
            ctypes.c_char_p(None if name is None else os.fsencode(name)),
        )
    )


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


def fallocate(path, offset, len):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o666)
    try:
        os.posix_fallocate(fd, offset, len)
    finally:
        os.close(fd)


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


_BLKRRPART = _IO(0x12, 95)
_BLKSSZGET = _IO(0x12, 104)
_BLKGETSIZE64 = _IOR(0x12, 114, ctypes.sizeof(ctypes.c_size_t))


def mkswap(path, size=None):
    fd = os.open(path, os.O_WRONLY)
    try:
        if size is None:
            st = os.stat(fd)
            if stat.S_ISBLK(st.st_mode):
                size = ctypes.c_uint64()
                ioctl(fd, _BLKGETSIZE64, size)
                size = size.value
            else:
                size = st.st_size

        header = bytearray(mmap.PAGESIZE)
        header[1024:1028] = (1).to_bytes(4, sys.byteorder)  # version
        header[1028:1032] = (size // mmap.PAGESIZE - 1).to_bytes(
            4, sys.byteorder
        )  # last_page
        header[1036:1052] = os.urandom(16)  # sws_uuid
        magic = b"SWAPSPACE2"
        header[-len(magic) :] = magic

        n = os.write(fd, header)
        while n < len(header):
            n += os.write(fd, header[n:])
    finally:
        os.close(fd)


class MbrPartitionType(enum.IntEnum):
    LINUX_SWAP = 0x82
    LINUX = 0x83


class MbrPartition(NamedTuple):
    type: int
    start: int
    size: int
    bootable: bool = False


_MBR_PARTITION_STRUCT = struct.Struct("<8BII")


def write_mbr(path, partitions, sector_size=None):
    fd = os.open(path, os.O_WRONLY)
    try:
        if sector_size is None:
            sector_size = ctypes.c_int()
            ioctl(fd, _BLKSSZGET, sector_size)
            sector_size = sector_size.value

        buf = bytearray(sector_size)

        buf[0x1B8:0x1BC] = os.urandom(4)  # Disk ID.

        offset = 0x01BE
        for partition in partitions:
            if partition.start % sector_size != 0:
                raise ValueError("partition start is not sector-aligned")
            if partition.size % sector_size != 0:
                raise ValueError("partition size is not sector-aligned")
            _MBR_PARTITION_STRUCT.pack_into(
                buf,
                offset,
                0x80 if partition.bootable else 0x0,
                # Placeholder first CHS.
                0xFE,
                0xFF,
                0xFF,
                partition.type,
                # Placeholder last CHS.
                0xFE,
                0xFF,
                0xFF,
                partition.start // sector_size,
                partition.size // sector_size,
            )
            offset += _MBR_PARTITION_STRUCT.size

        buf[0x1FE] = 0x55
        buf[0x1FF] = 0xAA

        n = os.write(fd, buf)
        while n < len(buf):
            n += os.write(fd, buf[n:])
        ioctl(fd, _BLKRRPART)
    finally:
        os.close(fd)


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


IPC_PRIVATE = 0
IPC_CREAT = 0o1000
IPC_EXCL = 0o2000
IPC_NOWAIT = 0o4000

IPC_RMID = 0
IPC_SET = 1
IPC_STAT = 2
IPC_INFO = 3

_key_t = ctypes.c_int

_ftok = _c.ftok
_ftok.argtypes = [ctypes.c_char_p, ctypes.c_int]
_ftok.restype = _key_t


def ftok(path, proj_id: int) -> int:
    return _check_ctypes_syscall(_ftok(os.fsencode(path), proj_id))


_msgget = _c.msgget
_msgget.argtypes = [_key_t, ctypes.c_int]
_msgget.restype = ctypes.c_int


def msgget(key: int, msgflg: int = IPC_CREAT | 0o666) -> int:
    return _check_ctypes_syscall(_msgget(key, msgflg))


_msgctl = _c.msgctl
_msgctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_msgctl.restype = ctypes.c_int


def msgctl(msqid: int, op: int) -> None:
    _check_ctypes_syscall(_msgctl(msqid, op, 0))


_semget = _c.semget
_semget.argtypes = [_key_t, ctypes.c_int, ctypes.c_int]
_semget.restype = ctypes.c_int


def semget(key: int, nsems: int, semflg: int = IPC_CREAT | 0o666) -> int:
    return _check_ctypes_syscall(_semget(key, nsems, semflg))


_semctl = _c.semctl
_semctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
_semctl.restype = ctypes.c_int


def semctl(semid: int, semnum: int, op: int) -> None:
    _check_ctypes_syscall(_semctl(semid, semnum, op))


SHM_LOCK = 11


_shmget = _c.shmget
_shmget.argtypes = [_key_t, ctypes.c_int, ctypes.c_int]
_shmget.restype = ctypes.c_int


def shmget(key: int, size: int, shmflg: int = IPC_CREAT | 0o666) -> int:
    return _check_ctypes_syscall(_shmget(key, size, shmflg))


_shmctl = _c.shmctl
_shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_shmctl.restype = ctypes.c_int


def shmctl(shmid: int, op: int) -> None:
    _check_ctypes_syscall(_shmctl(shmid, op, 0))


_aio_context_t = ctypes.c_ulong


def io_setup(nr_events):
    ctx_id = _aio_context_t()
    _check_ctypes_syscall(
        _syscall(SYS["io_setup"], ctypes.c_uint(nr_events), ctypes.byref(ctx_id))
    )
    return ctx_id.value


def io_destroy(ctx_id):
    _check_ctypes_syscall(_syscall(SYS["io_destroy"], _aio_context_t(ctx_id)))


_aio_key_and_aio_rw_flags = [
    ("aio_key", ctypes.c_uint32),
    ("aio_rw_flags", ctypes.c_int),
]
if sys.byteorder == "big":
    _aio_key_and_aio_rw_flags.reverse()


IOCB_CMD_PREAD = 0
IOCB_CMD_PWRITE = 1
IOCB_CMD_FSYNC = 2
IOCB_CMD_FDSYNC = 3
IOCB_CMD_POLL = 5
IOCB_CMD_NOOP = 6
IOCB_CMD_PREADV = 7
IOCB_CMD_PWRITEV = 8


class iocb(ctypes.Structure):
    _fields_ = (
        ("aio_data", ctypes.c_uint64),
        *_aio_key_and_aio_rw_flags,
        ("aio_lio_opcode", ctypes.c_uint16),
        ("aio_reqprio", ctypes.c_int16),
        ("aio_fildes", ctypes.c_uint32),
        ("aio_buf", ctypes.c_uint64),
        ("aio_nbytes", ctypes.c_uint64),
        ("aio_offset", ctypes.c_int64),
        ("aio_reserved2", ctypes.c_uint64),
        ("aio_flags", ctypes.c_uint32),
        ("aio_resfd", ctypes.c_uint32),
    )


def io_submit(ctx_id, iocbs):
    nr = len(iocbs)
    iocbp = (ctypes.POINTER(iocb) * nr)(*(ctypes.pointer(iocb) for iocb in iocbs))
    return _check_ctypes_syscall(
        _syscall(
            SYS["io_submit"],
            _aio_context_t(ctx_id),
            ctypes.c_long(nr),
            ctypes.byref(iocbp),
        )
    )
