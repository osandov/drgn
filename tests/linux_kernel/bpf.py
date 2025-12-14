# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import array
import ctypes
import os
import re
import sys
from typing import NamedTuple, Tuple

from _drgn_util.platform import SYS
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


# Instruction classes.
BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_JMP32 = 0x06
BPF_MISC = 0x07
BPF_ALU64 = 0x07

# ld/ldx fields.
BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10
BPF_DW = 0x18
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xA0
BPF_MEMSX = 0x80
BPF_ATOMIC = 0xC0
BPF_XADD = 0xC0

# alu/jmp fields.
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_MOD = 0x90
BPF_XOR = 0xA0

BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40
BPF_K = 0x00
BPF_X = 0x08

BPF_MOV = 0xB0
BPF_ARSH = 0xC0

# Change endianness of a register.
BPF_END = 0xD0
BPF_TO_LE = 0x00
BPF_TO_BE = 0x08
BPF_FROM_LE = BPF_TO_LE
BPF_FROM_BE = BPF_TO_BE

# jmp encodings.
BPF_JNE = 0x50
BPF_JLT = 0xA0
BPF_JLE = 0xB0
BPF_JSGT = 0x60
BPF_JSGE = 0x70
BPF_JSLT = 0xC0
BPF_JSLE = 0xD0
BPF_JCOND = 0xE0
BPF_CALL = 0x80
BPF_EXIT = 0x90

# atomic op type fields.
BPF_FETCH = 0x01
BPF_XCHG = 0xE0 | BPF_FETCH
BPF_CMPXCHG = 0xF0 | BPF_FETCH

BPF_LOAD_ACQ = 0x100
BPF_STORE_REL = 0x110

# Register numbers.
BPF_REG_0 = 0
BPF_REG_1 = 1
BPF_REG_2 = 2
BPF_REG_3 = 3
BPF_REG_4 = 4
BPF_REG_5 = 5
BPF_REG_6 = 6
BPF_REG_7 = 7
BPF_REG_8 = 8
BPF_REG_9 = 9
BPF_REG_10 = 10

MAX_BPF_REG = 11


# Instruction encoding.
def bpf_insn(*, code: int, dst_reg: int, src_reg: int, off: int, imm: int) -> int:
    if code < 0 or code > 255:
        raise ValueError(f"code {code} is out of range")
    if dst_reg < 0 or dst_reg > 15:
        raise ValueError(f"dst_reg {dst_reg} is out of range")
    if src_reg < 0 or src_reg > 15:
        raise ValueError(f"src_reg {src_reg} is out of range")
    if off < -32768 or off > 32767:
        raise ValueError(f"off {off} is out of range")
    # Allow signed and unsigned 32-bit values.
    if imm < -(2**31) or imm >= 2**32:
        raise ValueError(f"imm {imm} is out of range")
    if sys.byteorder == "little":
        return (
            code
            | (dst_reg << 8)
            | (src_reg << 12)
            | ((off & 0xFFFF) << 16)
            | ((imm & 0xFFFFFFFF) << 32)
        )
    else:
        return (
            (code << 56)
            | (dst_reg << 52)
            | (src_reg << 48)
            | ((off & 0xFFFF) << 32)
            | (imm & 0xFFFFFFFF)
        )


# Instructions.
def BPF_MOV64_IMM(dst: int, imm: int) -> int:
    return bpf_insn(
        code=BPF_ALU64 | BPF_MOV | BPF_K,
        dst_reg=dst,
        src_reg=0,
        off=0,
        imm=imm,
    )


BPF_PSEUDO_MAP_FD = 1
BPF_PSEUDO_MAP_IDX = 5
BPF_PSEUDO_MAP_VALUE = 2
BPF_PSEUDO_MAP_IDX_VALUE = 6
BPF_PSEUDO_BTF_ID = 3
BPF_PSEUDO_FUNC = 4


def BPF_LD_IMM64_RAW(dst: int, src: int, imm: int) -> Tuple[int, int]:
    # Allow signed and unsigned 64-bit values.
    if imm < -(2**63) or imm >= 2**64:
        raise ValueError(f"imm {imm} is out of range")
    return (
        bpf_insn(
            code=BPF_LD | BPF_DW | BPF_IMM,
            dst_reg=dst,
            src_reg=src,
            off=0,
            imm=imm & 0xFFFFFFFF,
        ),
        bpf_insn(code=0, dst_reg=0, src_reg=0, off=0, imm=(imm >> 32) & 0xFFFFFFFF),
    )


def BPF_LD_MAP_FD(dst: int, map_fd: int) -> int:
    return BPF_LD_IMM64_RAW(dst, BPF_PSEUDO_MAP_FD, map_fd)


def BPF_EXIT_INSN() -> int:
    return bpf_insn(
        code=BPF_JMP | BPF_EXIT,
        dst_reg=0,
        src_reg=0,
        off=0,
        imm=0,
    )


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


try:
    _SYS_bpf = ctypes.c_long(SYS["bpf"])
except KeyError:
    _SYS_bpf = None
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


_LOG_BUF_SIZE = 65536


class BpfVerifierError(OSError):
    def __init__(self, *args, log) -> None:
        super().__init__(*args)
        self.log = log

    def __str__(self) -> str:
        return f"{super().__str__()}\n{self.log}"


def bpf_prog_load(prog_type, insns, license, expected_attach_type=0):
    attr = _bpf_attr()
    attr.prog_type = prog_type
    insns_array = array.array("Q", insns)
    attr.insns, attr.insn_cnt = insns_array.buffer_info()
    ctypes_license = ctypes.c_char_p(license)
    attr.license = ctypes.cast(ctypes_license, ctypes.c_void_p).value

    attr.log_level = 1
    attr.log_size = _LOG_BUF_SIZE
    log_buf = ctypes.create_string_buffer(_LOG_BUF_SIZE)
    attr.log_buf = ctypes.addressof(log_buf)

    if prog_type == BPF_PROG_TYPE_KPROBE:
        # Before Linux kernel commit 6c4fc209fcf9 ("bpf: remove useless version
        # check for prog load") (in v5.0), for BPF_PROG_TYPE_KPROBE,
        # kern_version must match the kernel's LINUX_VERSION_CODE.
        match = re.match(r"([0-9]+)\.([0-9]+)\.([0-9]+)", os.uname().release)
        if match:
            attr.kern_version = (
                (int(match.group(1)) << 16)
                | (int(match.group(2)) << 8)
                | min(int(match.group(3)), 255)
            )

    attr.expected_attach_type = expected_attach_type

    ret = _syscall(
        _SYS_bpf, ctypes.c_int(BPF_PROG_LOAD), ctypes.byref(attr), _sizeof_bpf_attr
    )
    if ret == -1:
        errno = ctypes.get_errno()
        log = log_buf.value
        if log:
            raise BpfVerifierError(errno, os.strerror(errno), log=log.decode())
        else:
            raise OSError(errno, os.strerror(errno))
    return ret


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


class _bpf_map_info(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
        ("name", ctypes.c_char * _BPF_OBJ_NAME_LEN),
        ("ifindex", ctypes.c_uint32),
        ("btf_vmlinux_value_type_id", ctypes.c_uint32),
        ("netns_dev", ctypes.c_uint64),
        ("netns_ino", ctypes.c_uint64),
        ("btf_id", ctypes.c_uint32),
        ("btf_key_type_id", ctypes.c_uint32),
        ("btf_value_type_id", ctypes.c_uint32),
        ("btf_vmlinux_id", ctypes.c_uint32),
        ("map_extra", ctypes.c_uint64),
        ("hash", ctypes.c_uint64),
        ("hash_size", ctypes.c_uint32),
    )


class BpfMapInfo(NamedTuple):
    type: int
    id: int
    key_size: int
    value_size: int
    max_entries: int
    map_flags: int
    name: bytes
    ifindex: int
    btf_vmlinux_value_type_id: int
    netns_dev: int
    netns_ino: int
    btf_id: int
    btf_key_type_id: int
    btf_value_type_id: int
    btf_vmlinux_id: int
    map_extra: int
    hash: int
    hash_size: int


def bpf_map_get_info_by_fd(bpf_fd):
    attr = _bpf_attr()
    attr.bpf_fd = bpf_fd
    info = _bpf_map_info()
    attr.info_len = ctypes.sizeof(info)
    attr.info = ctypes.addressof(info)
    _bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    return BpfMapInfo(
        type=info.type,
        id=info.id,
        key_size=info.key_size,
        value_size=info.value_size,
        max_entries=info.max_entries,
        map_flags=info.map_flags,
        name=info.name,
        ifindex=info.ifindex,
        btf_vmlinux_value_type_id=info.btf_vmlinux_value_type_id,
        netns_dev=info.netns_dev,
        netns_ino=info.netns_ino,
        btf_id=info.btf_id,
        btf_key_type_id=info.btf_key_type_id,
        btf_value_type_id=info.btf_value_type_id,
        btf_vmlinux_id=info.btf_vmlinux_id,
        map_extra=info.map_extra,
        hash=info.hash,
        hash_size=info.hash_size,
    )


def bpf_link_create(prog_fd, target_fd, attach_type, flags=0):
    attr = _bpf_attr()
    attr.link_create.prog_fd = prog_fd
    attr.link_create.target_fd = target_fd
    attr.link_create.attach_type = attach_type
    attr.link_create.flags = flags
    return _bpf(BPF_LINK_CREATE, attr)
