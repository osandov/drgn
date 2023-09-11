# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


from collections import OrderedDict
import inspect
import os
from pathlib import Path
from typing import Dict, Mapping, NamedTuple, Sequence

from util import NORMALIZED_MACHINE_NAME

# Kernel versions that we run tests on and therefore support. Keep this in sync
# with docs/support_matrix.rst.
SUPPORTED_KERNEL_VERSIONS = (
    "6.5",
    "6.4",
    "6.3",
    "6.2",
    "6.1",
    "6.0",
    "5.19",
    "5.18",
    "5.17",
    "5.16",
    "5.15",
    "5.14",
    "5.13",
    "5.12",
    "5.11",
    "5.10",
    "5.4",
    "4.19",
    "4.14",
    "4.9",
)

KERNEL_ORG_COMPILER_VERSION = "12.2.0"
VMTEST_KERNEL_VERSION = 22


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

# For mm tests.
CONFIG_HUGETLBFS=y

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
            description="!SMP, !PREEMPT, and SLUB_TINY or SLOB allocator",
            config="""
                CONFIG_SMP=n
                CONFIG_SLOB=y
                # Linux kernel commit 149b6fa228ed ("mm, slob: rename CONFIG_SLOB to
                # CONFIG_SLOB_DEPRECATED") (in v6.2) renamed the option for SLOB.
                CONFIG_SLOB_DEPRECATED=y
                # Linux kernel commit c9929f0e344a ("mm/slob: remove
                # CONFIG_SLOB") (in v6.4) removed SLOB. Use SLUB_TINY instead,
                # which was introduced in Linux kernel commit e240e53ae0ab
                # ("mm, slub: add CONFIG_SLUB_TINY") (in v6.2).
                CONFIG_SLUB_TINY=y
                # CONFIG_PREEMPT_DYNAMIC is not set
                CONFIG_PREEMPT_NONE=y
                # !PREEMPTION && !SMP will also select TINY_RCU.
            """,
        ),
    )
)


class Architecture(NamedTuple):
    # Architecture name. This matches the names used by
    # util.NORMALIZED_MACHINE_NAME and qemu-system-$arch_name.
    name: str
    # Value of ARCH variable to build the Linux kernel.
    kernel_arch: str
    # Directory under arch/ in the Linux kernel source tree.
    kernel_srcarch: str
    # Name of the architecture in Debian.
    debian_arch: str
    # Linux kernel configuration options.
    kernel_config: str
    # Flavor-specific Linux kernel configuration options.
    kernel_flavor_configs: Mapping[str, str]
    # Name of compiler target on
    # https://mirrors.kernel.org/pub/tools/crosstool/.
    kernel_org_compiler_name: str
    # Options to pass to QEMU.
    qemu_options: Sequence[str]
    # Console device when using QEMU.
    qemu_console: str


ARCHITECTURES = {
    arch.name: arch
    for arch in (
        Architecture(
            name="aarch64",
            kernel_arch="arm64",
            kernel_srcarch="arm64",
            debian_arch="arm64",
            kernel_config="""
                CONFIG_PCI_HOST_GENERIC=y
                CONFIG_RTC_CLASS=y
                CONFIG_RTC_DRV_PL031=y
                CONFIG_SERIAL_AMBA_PL011=y
                CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
            """,
            kernel_flavor_configs={
                "default": """
                    CONFIG_ARM64_4K_PAGES=y
                    CONFIG_ARM64_VA_BITS_48=y
                """,
                "alternative": """
                    CONFIG_ARM64_64K_PAGES=y
                    CONFIG_ARM64_VA_BITS_52=y
                    CONFIG_ARM64_PA_BITS_52=y
                """,
                "tiny": """
                    CONFIG_ARM64_16K_PAGES=y
                """,
            },
            kernel_org_compiler_name="aarch64-linux",
            qemu_options=("-M", "virt", "-cpu", "cortex-a57"),
            qemu_console="ttyAMA0",
        ),
        Architecture(
            name="arm",
            kernel_arch="arm",
            kernel_srcarch="arm",
            debian_arch="armhf",
            kernel_config="""
                CONFIG_NR_CPUS=8
                CONFIG_HIGHMEM=y
                CONFIG_ARM_LPAE=n
                # Debian armhf userspace assumes EABI and VFP.
                CONFIG_AEABI=y
                CONFIG_VFP=y
                CONFIG_ARCH_VIRT=y
                CONFIG_PCI_HOST_GENERIC=y
                CONFIG_RTC_CLASS=y
                CONFIG_RTC_DRV_PL031=y
                CONFIG_SERIAL_AMBA_PL011=y
                CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
                # Before Linux kernel commit f05eb1d24eb5 ("ARM:
                # stackprotector: prefer compiler for TLS based per-task
                # protector") (in v5.18), this enables the
                # arm_ssp_per_task_plugin GCC plugin, which fails to build with
                # the kernel.org cross compiler.
                CONFIG_STACKPROTECTOR_PER_TASK=n
            """,
            kernel_flavor_configs={
                "alternative": """
                    CONFIG_ARM_LPAE=y
                """,
            },
            kernel_org_compiler_name="arm-linux-gnueabi",
            qemu_options=("-M", "virt,highmem=off"),
            qemu_console="ttyAMA0",
        ),
        Architecture(
            name="ppc64",
            kernel_arch="powerpc",
            kernel_srcarch="powerpc",
            debian_arch="ppc64el",
            kernel_config="""
                CONFIG_PPC64=y
                CONFIG_CPU_LITTLE_ENDIAN=y
                # Debian ppc64el userspace assumes AltiVec and VSX support.
                CONFIG_ALTIVEC=y
                CONFIG_VSX=y
                CONFIG_RTC_CLASS=y
                CONFIG_RTC_DRV_GENERIC=y
                CONFIG_HVC_CONSOLE=y
                # This has a missing dependency in v6.5-rc1 that causes a build
                # failure, and we don't need it.
                CONFIG_CRYPTO_AES_GCM_P10=n
            """,
            kernel_flavor_configs={},
            kernel_org_compiler_name="powerpc64-linux",
            qemu_options=(),
            qemu_console="hvc0",
        ),
        Architecture(
            name="s390x",
            kernel_arch="s390",
            kernel_srcarch="s390",
            debian_arch="s390x",
            kernel_config="""
                # Needed for CONFIG_KEXEC_FILE.
                CONFIG_CRYPTO_SHA256_S390=y
            """,
            kernel_flavor_configs={},
            kernel_org_compiler_name="s390-linux",
            qemu_options=(),
            qemu_console="ttysclp0",
        ),
        Architecture(
            name="x86_64",
            kernel_arch="x86_64",
            kernel_srcarch="x86",
            debian_arch="amd64",
            kernel_config="""
                CONFIG_RTC_CLASS=y
                CONFIG_RTC_DRV_CMOS=y
                CONFIG_SERIAL_8250=y
                CONFIG_SERIAL_8250_CONSOLE=y
            """,
            kernel_flavor_configs={},
            kernel_org_compiler_name="x86_64-linux",
            qemu_options=("-nodefaults",),
            qemu_console="ttyS0",
        ),
    )
}


HOST_ARCHITECTURE = ARCHITECTURES.get(NORMALIZED_MACHINE_NAME)


class Kernel(NamedTuple):
    arch: Architecture
    release: str
    path: Path


def local_kernel(arch: Architecture, path: Path) -> Kernel:
    return Kernel(
        arch=arch,
        release=(path / "build/include/config/kernel.release").read_text().strip(),
        path=path,
    )


class Compiler(NamedTuple):
    target: Architecture
    bin: Path
    prefix: str

    def env(self) -> Dict[str, str]:
        path = str(self.bin.resolve())
        try:
            path += ":" + os.environ["PATH"]
        except KeyError:
            pass
        return {
            "PATH": path,
            "CROSS_COMPILE": self.prefix,
        }


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

CONFIG_LOCALVERSION=""
CONFIG_LOCALVERSION_AUTO=n

# base options

{inspect.cleandoc(BASE_KCONFIG)}

# {flavor.name} flavor options

{inspect.cleandoc(flavor.config)}

# {arch.name} options

{inspect.cleandoc(arch.kernel_config)}

# {arch.name} {flavor.name} flavor options

{inspect.cleandoc(arch.kernel_flavor_configs.get(flavor.name, ""))}
"""
