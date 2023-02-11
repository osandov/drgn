# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


from collections import OrderedDict
import inspect
from typing import Mapping, NamedTuple

from util import NORMALIZED_MACHINE_NAME

VMTEST_KERNEL_VERSION = 18


BASE_KCONFIG = """
CONFIG_EXPERT=y
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_CC_OPTIMIZE_FOR_SIZE=y

# We run the tests in KVM.
CONFIG_HYPERVISOR_GUEST=y
CONFIG_KVM_GUEST=y
CONFIG_PARAVIRT=y
CONFIG_PARAVIRT_SPINLOCKS=y

# Minimum requirements for vmtest.
CONFIG_9P_FS=y
CONFIG_DEVTMPFS=y
CONFIG_INET=y
CONFIG_NET=y
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_OVERLAY_FS=y
CONFIG_PCI=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_XATTR=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VIRTIO_PCI=y
CONFIG_HW_RANDOM=m
CONFIG_HW_RANDOM_VIRTIO=m

# Lots of stuff expect Unix sockets.
CONFIG_UNIX=y

# drgn needs debug info.
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF4=y

# For testing live kernel debugging with /proc/kcore.
CONFIG_PROC_KCORE=y
# drgn needs /proc/kallsyms in some cases. Some test cases also need it.
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y

# For testing kernel core dumps with /proc/vmcore.
CONFIG_CRASH_DUMP=y
CONFIG_PROC_VMCORE=y
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
# Needed for CONFIG_KEXEC_FILE.
CONFIG_CRYPTO=y
CONFIG_CRYPTO_SHA256=y

# So that we can trigger a crash with /proc/sysrq-trigger.
CONFIG_MAGIC_SYSRQ=y

# For block tests.
CONFIG_BLK_DEV_LOOP=m

# For BPF tests.
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_CGROUP_BPF=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y

# For cgroup tests.
CONFIG_CGROUPS=y
# To select CONFIG_SOCK_CGROUP_DATA. (CONFIG_CGROUP_BPF also selects
# CONFIG_SOCK_CGROUP_DATA, but that's only present since Linux kernel commit
# 3007098494be ("cgroup: add support for eBPF programs") (in v4.10)).
CONFIG_CGROUP_NET_CLASSID=y

# For kconfig tests.
CONFIG_IKCONFIG=m
CONFIG_IKCONFIG_PROC=y

# For filesystem tests.
CONFIG_BTRFS_FS=m
CONFIG_EXT4_FS=m
CONFIG_XFS_FS=m

# For net tests.
CONFIG_NAMESPACES=y

# For nodemask tests.
CONFIG_NUMA=y

# For slab allocator tests.
CONFIG_SLAB_FREELIST_HARDENED=y

# For Traffic Control tests.
CONFIG_NET_SCHED=y
CONFIG_NET_SCH_PRIO=m
CONFIG_NET_SCH_SFQ=m
CONFIG_NET_SCH_TBF=m
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_CLS_ACT=y
CONFIG_NETDEVICES=y
CONFIG_DUMMY=m

# To enable CONFIG_XARRAY_MULTI for xarray tests.
CONFIG_TRANSPARENT_HUGEPAGE=y
CONFIG_READ_ONLY_THP_FOR_FS=y
"""


class KernelFlavor(NamedTuple):
    name: str
    description: str
    config: str


KERNEL_FLAVORS = OrderedDict(
    (flavor.name, flavor)
    for flavor in (
        KernelFlavor(
            name="default",
            description="Default configuration",
            config="""
                CONFIG_SMP=y
                CONFIG_SLUB=y
                # For slab tests.
                CONFIG_SLUB_DEBUG=y
            """,
        ),
        KernelFlavor(
            name="alternative",
            description="SLAB allocator",
            config="""
                CONFIG_SMP=y
                CONFIG_SLAB=y
            """,
        ),
        KernelFlavor(
            name="tiny",
            description="!SMP, !PREEMPT, and SLOB allocator",
            config="""
                CONFIG_SMP=n
                CONFIG_SLOB=y
                # Linux kernel commit 149b6fa228ed ("mm, slob: rename CONFIG_SLOB to
                # CONFIG_SLOB_DEPRECATED") (in v6.2) renamed the option for SLOB.
                CONFIG_SLOB_DEPRECATED=y
                # CONFIG_PREEMPT_DYNAMIC is not set
                CONFIG_PREEMPT_NONE=y
                # !PREEMPTION && !SMP will also select TINY_RCU.
            """,
        ),
    )
)


class Architecture(NamedTuple):
    # Name matching NORMALIZED_MACHINE_NAME.
    name: str
    # Value of ARCH variable to build the Linux kernel.
    kernel_arch: str
    # Directory under arch/ in the Linux kernel source tree.
    kernel_srcarch: str
    # Linux kernel configuration options.
    kernel_config: str
    # Flavor-specific Linux kernel configuration options.
    kernel_flavor_configs: Mapping[str, str]


ARCHITECTURES = {
    arch.name: arch
    for arch in (
        Architecture(
            name="x86_64",
            kernel_arch="x86_64",
            kernel_srcarch="x86",
            kernel_config="""
                CONFIG_SERIAL_8250=y
                CONFIG_SERIAL_8250_CONSOLE=y
            """,
            kernel_flavor_configs={},
        ),
    )
}


HOST_ARCHITECTURE = ARCHITECTURES.get(NORMALIZED_MACHINE_NAME)


def kconfig_localversion(flavor: KernelFlavor) -> str:
    localversion = f"-vmtest{VMTEST_KERNEL_VERSION}"
    # The default flavor should be the "latest" version.
    localversion += ".1" if flavor.name == "default" else ".0"
    localversion += flavor.name
    return localversion


def kconfig(arch: Architecture, flavor: KernelFlavor) -> str:
    return f"""\
# Minimal Linux kernel configuration for booting into vmtest and running drgn
# tests ({arch.name} {flavor.name} flavor).

CONFIG_LOCALVERSION="{kconfig_localversion(flavor)}"

# base options

{inspect.cleandoc(BASE_KCONFIG)}

# {flavor.name} flavor options

{inspect.cleandoc(flavor.config)}

# {arch.name} options

{inspect.cleandoc(arch.kernel_config)}

# {arch.name} {flavor.name} flavor options

{inspect.cleandoc(arch.kernel_flavor_configs.get(flavor.name, ""))}
"""
