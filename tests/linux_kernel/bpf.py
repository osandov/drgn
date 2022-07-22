# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import array
import ctypes
import platform
import re
from typing import NamedTuple

from tests.linux_kernel import _check_ctypes_syscall, _syscall

# enum bpf_cmd
BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_PROG_LOAD = 5
BPF_OBJ_PIN = 6
BPF_OBJ_GET = 7
BPF_PROG_ATTACH = 8
BPF_PROG_DETACH = 9
BPF_PROG_TEST_RUN = 10
BPF_PROG_RUN = BPF_PROG_TEST_RUN
BPF_PROG_GET_NEXT_ID = 11
BPF_MAP_GET_NEXT_ID = 12
BPF_PROG_GET_FD_BY_ID = 13
BPF_MAP_GET_FD_BY_ID = 14
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_PROG_QUERY = 16
BPF_RAW_TRACEPOINT_OPEN = 17
BPF_BTF_LOAD = 18
BPF_BTF_GET_FD_BY_ID = 19
BPF_TASK_FD_QUERY = 20
BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21
BPF_MAP_FREEZE = 22
BPF_BTF_GET_NEXT_ID = 23
BPF_MAP_LOOKUP_BATCH = 24
BPF_MAP_LOOKUP_AND_DELETE_BATCH = 25
BPF_MAP_UPDATE_BATCH = 26
BPF_MAP_DELETE_BATCH = 27
BPF_LINK_CREATE = 28
BPF_LINK_UPDATE = 29
BPF_LINK_GET_FD_BY_ID = 30
BPF_LINK_GET_NEXT_ID = 31
BPF_ENABLE_STATS = 32
BPF_ITER_CREATE = 33
BPF_LINK_DETACH = 34
BPF_PROG_BIND_MAP = 35

# enum bpf_map_type
BPF_MAP_TYPE_UNSPEC = 0
BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_PROG_ARRAY = 3
BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
BPF_MAP_TYPE_PERCPU_HASH = 5
BPF_MAP_TYPE_PERCPU_ARRAY = 6
BPF_MAP_TYPE_STACK_TRACE = 7
BPF_MAP_TYPE_CGROUP_ARRAY = 8
BPF_MAP_TYPE_LRU_HASH = 9
BPF_MAP_TYPE_LRU_PERCPU_HASH = 10
BPF_MAP_TYPE_LPM_TRIE = 11
BPF_MAP_TYPE_ARRAY_OF_MAPS = 12
BPF_MAP_TYPE_HASH_OF_MAPS = 13
BPF_MAP_TYPE_DEVMAP = 14
BPF_MAP_TYPE_SOCKMAP = 15
BPF_MAP_TYPE_CPUMAP = 16
BPF_MAP_TYPE_XSKMAP = 17
BPF_MAP_TYPE_SOCKHASH = 18
BPF_MAP_TYPE_CGROUP_STORAGE = 19
BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20
BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21
BPF_MAP_TYPE_QUEUE = 22
BPF_MAP_TYPE_STACK = 23
BPF_MAP_TYPE_SK_STORAGE = 24
BPF_MAP_TYPE_DEVMAP_HASH = 25
BPF_MAP_TYPE_STRUCT_OPS = 26
BPF_MAP_TYPE_RINGBUF = 27
BPF_MAP_TYPE_INODE_STORAGE = 28
BPF_MAP_TYPE_TASK_STORAGE = 29
BPF_MAP_TYPE_BLOOM_FILTER = 30

# enum bpf_prog_type
BPF_PROG_TYPE_UNSPEC = 0
BPF_PROG_TYPE_SOCKET_FILTER = 1
BPF_PROG_TYPE_KPROBE = 2
BPF_PROG_TYPE_SCHED_CLS = 3
BPF_PROG_TYPE_SCHED_ACT = 4
BPF_PROG_TYPE_TRACEPOINT = 5
BPF_PROG_TYPE_XDP = 6
BPF_PROG_TYPE_PERF_EVENT = 7
BPF_PROG_TYPE_CGROUP_SKB = 8
BPF_PROG_TYPE_CGROUP_SOCK = 9
BPF_PROG_TYPE_LWT_IN = 10
BPF_PROG_TYPE_LWT_OUT = 11
BPF_PROG_TYPE_LWT_XMIT = 12
BPF_PROG_TYPE_SOCK_OPS = 13
BPF_PROG_TYPE_SK_SKB = 14
BPF_PROG_TYPE_CGROUP_DEVICE = 15
BPF_PROG_TYPE_SK_MSG = 16
BPF_PROG_TYPE_RAW_TRACEPOINT = 17
BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18
BPF_PROG_TYPE_LWT_SEG6LOCAL = 19
BPF_PROG_TYPE_LIRC_MODE2 = 20
BPF_PROG_TYPE_SK_REUSEPORT = 21
BPF_PROG_TYPE_FLOW_DISSECTOR = 22
BPF_PROG_TYPE_CGROUP_SYSCTL = 23
BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24
BPF_PROG_TYPE_CGROUP_SOCKOPT = 25
BPF_PROG_TYPE_TRACING = 26
BPF_PROG_TYPE_STRUCT_OPS = 27
BPF_PROG_TYPE_EXT = 28
BPF_PROG_TYPE_LSM = 29
BPF_PROG_TYPE_SK_LOOKUP = 30
BPF_PROG_TYPE_SYSCALL = 31

# enum bpf_attach_type
BPF_CGROUP_INET_INGRESS = 0
BPF_CGROUP_INET_EGRESS = 1
BPF_CGROUP_INET_SOCK_CREATE = 2
BPF_CGROUP_SOCK_OPS = 3
BPF_SK_SKB_STREAM_PARSER = 4
BPF_SK_SKB_STREAM_VERDICT = 5
BPF_CGROUP_DEVICE = 6
BPF_SK_MSG_VERDICT = 7
BPF_CGROUP_INET4_BIND = 8
BPF_CGROUP_INET6_BIND = 9
BPF_CGROUP_INET4_CONNECT = 10
BPF_CGROUP_INET6_CONNECT = 11
BPF_CGROUP_INET4_POST_BIND = 12
BPF_CGROUP_INET6_POST_BIND = 13
BPF_CGROUP_UDP4_SENDMSG = 14
BPF_CGROUP_UDP6_SENDMSG = 15
BPF_LIRC_MODE2 = 16
BPF_FLOW_DISSECTOR = 17
BPF_CGROUP_SYSCTL = 18
BPF_CGROUP_UDP4_RECVMSG = 19
BPF_CGROUP_UDP6_RECVMSG = 20
BPF_CGROUP_GETSOCKOPT = 21
BPF_CGROUP_SETSOCKOPT = 22
BPF_TRACE_RAW_TP = 23
BPF_TRACE_FENTRY = 24
BPF_TRACE_FEXIT = 25
BPF_MODIFY_RETURN = 26
BPF_LSM_MAC = 27
BPF_TRACE_ITER = 28
BPF_CGROUP_INET4_GETPEERNAME = 29
BPF_CGROUP_INET6_GETPEERNAME = 30
BPF_CGROUP_INET4_GETSOCKNAME = 31
BPF_CGROUP_INET6_GETSOCKNAME = 32
BPF_XDP_DEVMAP = 33
BPF_CGROUP_INET_SOCK_RELEASE = 34
BPF_XDP_CPUMAP = 35
BPF_SK_LOOKUP = 36
BPF_XDP = 37
BPF_SK_SKB_VERDICT = 38
BPF_SK_REUSEPORT_SELECT = 39
BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40
BPF_PERF_EVENT = 41

# Flags for BPF_PROG_ATTACH.
BPF_F_ALLOW_OVERRIDE = 1 << 0
BPF_F_ALLOW_MULTI = 1 << 1
BPF_F_REPLACE = 1 << 2


class _bpf_attr_map_create(ctypes.Structure):
    _fields_ = (
        ("map_type", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
    )


_BPF_OBJ_NAME_LEN = 16


class _bpf_attr_prog_load(ctypes.Structure):
    _fields_ = (
        ("prog_type", ctypes.c_uint32),
        ("insn_cnt", ctypes.c_uint32),
        ("insns", ctypes.c_uint64),
        ("license", ctypes.c_uint64),
        ("log_level", ctypes.c_uint32),
        ("log_size", ctypes.c_uint32),
        ("log_buf", ctypes.c_uint64),
        ("kern_version", ctypes.c_uint32),
        ("prog_flags", ctypes.c_uint32),
        ("prog_name", ctypes.c_char * _BPF_OBJ_NAME_LEN),
        ("prog_ifindex", ctypes.c_uint32),
        ("expected_attach_type", ctypes.c_uint32),
    )


class _bpf_attr_attach(ctypes.Structure):
    _fields_ = (
        ("target_fd", ctypes.c_uint32),
        ("attach_bpf_fd", ctypes.c_uint32),
        ("attach_type", ctypes.c_uint32),
        ("attach_flags", ctypes.c_uint32),
        ("replace_bpf_fd", ctypes.c_uint32),
    )


class _bpf_attr_get_id(ctypes.Structure):
    _fields_ = (
        ("id", ctypes.c_uint32),
        ("next_id", ctypes.c_uint32),
        ("open_flags", ctypes.c_uint32),
    )


class _bpf_attr_obj_get_info_by_fd(ctypes.Structure):
    _fields_ = (
        ("bpf_fd", ctypes.c_uint32),
        ("info_len", ctypes.c_uint32),
        ("info", ctypes.c_uint64),
    )


class _bpf_attr_link_create(ctypes.Structure):
    _fields_ = (
        ("prog_fd", ctypes.c_uint32),
        ("target_fd", ctypes.c_uint32),
        ("attach_type", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
    )


class _bpf_attr(ctypes.Union):
    _fields_ = (
        ("_map_create", _bpf_attr_map_create),
        ("_prog_load", _bpf_attr_prog_load),
        ("_attach", _bpf_attr_attach),
        ("_get_id", _bpf_attr_get_id),
        ("_obj_get_info_by_fd", _bpf_attr_obj_get_info_by_fd),
        ("link_create", _bpf_attr_link_create),
    )
    _anonymous_ = (
        "_map_create",
        "_prog_load",
        "_attach",
        "_get_id",
        "_obj_get_info_by_fd",
    )


_machine = platform.machine()
try:
    if _machine.startswith("aarch64") or _machine.startswith("arm64"):
        _SYS_bpf = 280
    elif _machine.startswith("arm"):
        _SYS_bpf = 386
    elif re.fullmatch(r"i.86", _machine):
        _SYS_bpf = 357
    elif _machine.startswith("parisc"):
        _SYS_bpf = 341
    elif _machine.startswith("ppc"):
        _SYS_bpf = 361
    elif _machine.startswith("s390"):
        _SYS_bpf = 351
    elif _machine.startswith("sh"):
        _SYS_bpf = 375
    elif _machine.startswith("sparc"):
        _SYS_bpf = 349
    else:
        _SYS_bpf = {
            "alpha": 515,
            "ia64": 317,
            "m68k": 354,
            "microblaze": 387,
            "x86_64": 321,
            "xtensa": 340,
        }[_machine]
except KeyError:
    _SYS_bpf = None
else:
    _SYS_bpf = ctypes.c_long(_SYS_bpf)
_sizeof_bpf_attr = ctypes.c_uint(ctypes.sizeof(_bpf_attr))


def _bpf(cmd, attr):
    return _check_ctypes_syscall(
        _syscall(_SYS_bpf, ctypes.c_int(cmd), ctypes.byref(attr), _sizeof_bpf_attr)
    )


def bpf_map_create(map_type, key_size, value_size, max_entries):
    attr = _bpf_attr()
    attr.map_type = map_type
    attr.key_size = key_size
    attr.value_size = value_size
    attr.max_entries = max_entries
    return _bpf(BPF_MAP_CREATE, attr)


def bpf_prog_load(prog_type, insns, license, expected_attach_type=0):
    attr = _bpf_attr()
    attr.prog_type = prog_type
    insns_array = array.array("Q", insns)
    attr.insns, attr.insn_cnt = insns_array.buffer_info()
    ctypes_license = ctypes.c_char_p(license)
    attr.license = ctypes.cast(ctypes_license, ctypes.c_void_p).value
    attr.expected_attach_type = expected_attach_type
    return _bpf(BPF_PROG_LOAD, attr)


def bpf_prog_attach(target_fd, attach_bpf_fd, attach_type, attach_flags=0):
    attr = _bpf_attr()
    attr.target_fd = target_fd
    attr.attach_bpf_fd = attach_bpf_fd
    attr.attach_type = attach_type
    attr.attach_flags = attach_flags
    _bpf(BPF_PROG_ATTACH, attr)


def _bpf_get_ids(cmd):
    attr = _bpf_attr()
    attr.id = 0
    while True:
        try:
            _bpf(cmd, attr)
        except FileNotFoundError:
            break
        yield attr.next_id
        attr.id = attr.next_id


def bpf_map_ids():
    return _bpf_get_ids(BPF_MAP_GET_NEXT_ID)


def bpf_prog_ids():
    return _bpf_get_ids(BPF_PROG_GET_NEXT_ID)


def bpf_btf_ids():
    return _bpf_get_ids(BPF_BTF_GET_NEXT_ID)


def bpf_link_ids():
    return _bpf_get_ids(BPF_LINK_GET_NEXT_ID)


_BPF_TAG_SIZE = 8


class _bpf_prog_info(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("tag", ctypes.c_uint8 * _BPF_TAG_SIZE),
        ("jited_prog_len", ctypes.c_uint32),
        ("xlated_prog_len", ctypes.c_uint32),
        ("jited_prog_insns", ctypes.c_uint64),
        ("xlated_prog_insns", ctypes.c_uint64),
    )


class BpfProgInfo(NamedTuple):
    type: int
    id: int
    tag: bytes


def bpf_prog_get_info_by_fd(bpf_fd):
    attr = _bpf_attr()
    attr.bpf_fd = bpf_fd
    info = _bpf_prog_info()
    attr.info_len = ctypes.sizeof(info)
    attr.info = ctypes.addressof(info)
    _bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    return BpfProgInfo(type=info.type, id=info.id, tag=bytes(info.tag))


def bpf_link_create(prog_fd, target_fd, attach_type, flags=0):
    attr = _bpf_attr()
    attr.link_create.prog_fd = prog_fd
    attr.link_create.target_fd = target_fd
    attr.link_create.attach_type = attach_type
    attr.link_create.flags = flags
    return _bpf(BPF_LINK_CREATE, attr)
