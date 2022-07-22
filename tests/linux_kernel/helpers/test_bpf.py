# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import errno
import os
import platform
import sys
import unittest

from drgn.helpers.linux.bpf import (
    bpf_btf_for_each,
    bpf_link_for_each,
    bpf_map_for_each,
    bpf_prog_for_each,
    cgroup_bpf_prog_for_each,
    cgroup_bpf_prog_for_each_effective,
)
from drgn.helpers.linux.cgroup import cgroup_get_from_path
from tests.linux_kernel import LinuxKernelTestCase
from tests.linux_kernel.bpf import (
    BPF_CGROUP_INET_INGRESS,
    BPF_F_ALLOW_MULTI,
    BPF_MAP_TYPE_HASH,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_SOCKET_FILTER,
    _SYS_bpf,
    bpf_btf_ids,
    bpf_link_create,
    bpf_link_ids,
    bpf_map_create,
    bpf_map_ids,
    bpf_prog_attach,
    bpf_prog_get_info_by_fd,
    bpf_prog_ids,
    bpf_prog_load,
)
from tests.linux_kernel.helpers.test_cgroup import tmp_cgroups


class TestBpf(LinuxKernelTestCase):
    # BPF instructions for:
    # r0 = 0
    # exit
    if sys.byteorder == "little":
        INSNS = (0xB7, 0x95)
    else:
        INSNS = (0xB700000000000000, 0x9500000000000000)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if _SYS_bpf is None:
            raise unittest.SkipTest(
                f"bpf syscall number is not known on {platform.machine()}"
            )
        try:
            os.close(bpf_map_create(BPF_MAP_TYPE_HASH, 8, 8, 8))
        except OSError as e:
            if e.errno != errno.ENOSYS:
                raise
            raise unittest.SkipTest(
                "kernel does not support bpf syscall (CONFIG_BPF_SYSCALL)"
            )

    def test_bpf_btf_for_each(self):
        # BTF was added in Linux kernel commit 69b693f0aefa ("bpf: btf:
        # Introduce BPF Type Format (BTF)") (in v4.18) and had IDs from the
        # start, but there was no API to get them until commit 1b9ed84ecf26
        # ("bpf: add new BPF_BTF_GET_NEXT_ID syscall command") (in v5.4). The
        # only kernel version that we support in between is v4.19, which we can
        # live without testing.
        #
        # Note that before Linux kernel commits 5329722057d4 ("bpf: Assign ID
        # to vmlinux BTF and return extra info for BTF in GET_OBJ_INFO") and
        # 36e68442d1af ("bpf: Load and verify kernel module BTFs") (in v5.11),
        # there won't be any BTF IDs unless they were explicitly added outside
        # of the test suite.
        try:
            expected_ids = list(bpf_btf_ids())
        except OSError as e:
            if e.errno != errno.EINVAL:
                raise
            self.skipTest("kernel does not support BPF_BTF_GET_NEXT_ID")
        self.assertCountEqual(
            [btf.id.value_() for btf in bpf_btf_for_each(self.prog)], expected_ids
        )

    def test_bpf_link_for_each(self):
        with tmp_cgroups() as cgroups:
            fds = []
            try:
                for cgroup in cgroups:
                    fds.append(os.open(cgroup, os.O_RDONLY | os.O_DIRECTORY))
                for i in range(3):
                    # Cgroup BPF programs didn't exist before Linux kernel
                    # commit 3007098494be ("cgroup: add support for eBPF
                    # programs") (in v4.10).
                    try:
                        prog_fd = bpf_prog_load(
                            BPF_PROG_TYPE_CGROUP_SKB,
                            self.INSNS,
                            b"GPL",
                            expected_attach_type=BPF_CGROUP_INET_INGRESS,
                        )
                        fds.append(prog_fd)
                    except OSError as e:
                        if e.errno != errno.EINVAL:
                            raise
                        self.skipTest(
                            "kernel does not support BPF_PROG_TYPE_CGROUP_SKB"
                        )
                    # BPF links didn't exist before Linux kernel commit
                    # 70ed506c3bbc ("bpf: Introduce pinnable bpf_link
                    # abstraction") (in v5.7).
                    try:
                        fds.append(
                            bpf_link_create(
                                prog_fd, fds[i % len(cgroups)], BPF_CGROUP_INET_INGRESS
                            )
                        )
                    except OSError as e:
                        if e.errno != errno.EINVAL:
                            raise
                        self.skipTest("kernel does not support BPF_LINK_CREATE")

                # bpf_link_for_each() isn't supported before Linux v5.8, which
                # added IDs for BPF links in commit a3b80e107894 ("bpf:
                # Allocate ID for bpf_link") and an API to get them in commit
                # 2d602c8cf40d ("bpf: Support GET_FD_BY_ID and GET_NEXT_ID for
                # bpf_link").
                try:
                    expected_ids = list(bpf_link_ids())
                except OSError as e:
                    if e.errno != errno.EINVAL:
                        raise
                    self.skipTest("kernel does not support BPF_LINK_GET_NEXT_ID")
                self.assertCountEqual(
                    [link.id.value_() for link in bpf_link_for_each(self.prog)],
                    expected_ids,
                )
            finally:
                for fd in fds:
                    os.close(fd)

    def test_bpf_map_for_each(self):
        fds = []
        try:
            for i in range(3):
                fds.append(bpf_map_create(BPF_MAP_TYPE_HASH, 8, 8, 8))

            # bpf_map_for_each() isn't supported before Linux v4.13, which
            # added IDs for BPF maps in commit f3f1c054c288 ("bpf: Introduce
            # bpf_map ID") and a API to get them in commit 34ad5580f8f9 ("bpf:
            # Add BPF_(PROG|MAP)_GET_NEXT_ID command").
            try:
                expected_ids = list(bpf_map_ids())
            except OSError as e:
                if e.errno != errno.EINVAL:
                    raise
                self.skipTest("kernel does not support BPF_MAP_GET_NEXT_ID")

            self.assertCountEqual(
                [map.id.value_() for map in bpf_map_for_each(self.prog)], expected_ids
            )
        finally:
            for fd in fds:
                os.close(fd)

    def test_bpf_prog_for_each(self):
        fds = []
        try:
            for i in range(3):
                fds.append(
                    bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, self.INSNS, b"GPL")
                )

            # bpf_prog_for_each() isn't supported before Linux v4.13, which
            # added IDs for BPF programs in commit dc4bb0e23561 ("bpf:
            # Introduce bpf_prog ID") and an API to get them in commit
            # 34ad5580f8f9 ("bpf: Add BPF_(PROG|MAP)_GET_NEXT_ID command").
            try:
                expected_ids = list(bpf_prog_ids())
            except OSError as e:
                if e.errno != errno.EINVAL:
                    raise
                self.skipTest("kernel does not support BPF_PROG_GET_NEXT_ID")

            self.assertCountEqual(
                [prog.aux.id.value_() for prog in bpf_prog_for_each(self.prog)],
                expected_ids,
            )
        finally:
            for fd in fds:
                os.close(fd)

    def test_cgroup_bpf_prog_for_each(self):
        with tmp_cgroups() as (parent_cgroup, child_cgroup):
            fds = []
            try:
                parent_cgroup_fd = os.open(parent_cgroup, os.O_RDONLY | os.O_DIRECTORY)
                fds.append(parent_cgroup_fd)
                child_cgroup_fd = os.open(child_cgroup, os.O_RDONLY | os.O_DIRECTORY)
                fds.append(child_cgroup_fd)
                try:
                    parent_prog_fd = bpf_prog_load(
                        BPF_PROG_TYPE_CGROUP_SKB,
                        self.INSNS,
                        b"GPL",
                        expected_attach_type=BPF_CGROUP_INET_INGRESS,
                    )
                    fds.append(parent_prog_fd)
                except OSError as e:
                    if e.errno != errno.EINVAL:
                        raise
                    # If the kernel doesn't support cgroup BPF programs, the
                    # helpers should return empty lists.
                    parent_ids = child_ids = child_effective_ids = []
                else:
                    parent_prog_id = bpf_prog_get_info_by_fd(parent_prog_fd).id
                    parent_ids = [parent_prog_id]

                    # If the kernel supports BPF_F_ALLOW_MULTI, test with
                    # multiple programs.
                    try:
                        bpf_prog_attach(
                            parent_cgroup_fd,
                            parent_prog_fd,
                            BPF_CGROUP_INET_INGRESS,
                            attach_flags=BPF_F_ALLOW_MULTI,
                        )
                    except OSError as e:
                        if e.errno != errno.EINVAL:
                            raise
                        bpf_prog_attach(
                            parent_cgroup_fd, parent_prog_fd, BPF_CGROUP_INET_INGRESS
                        )
                        child_ids = []
                        child_effective_ids = [parent_prog_id]
                    else:
                        child_prog_fd = bpf_prog_load(
                            BPF_PROG_TYPE_CGROUP_SKB,
                            self.INSNS,
                            b"GPL",
                            expected_attach_type=BPF_CGROUP_INET_INGRESS,
                        )
                        fds.append(child_prog_fd)
                        child_prog_id = bpf_prog_get_info_by_fd(child_prog_fd).id
                        bpf_prog_attach(
                            child_cgroup_fd, child_prog_fd, BPF_CGROUP_INET_INGRESS
                        )
                        child_ids = [child_prog_id]
                        child_effective_ids = [parent_prog_id, child_prog_id]

                parent_cgrp = cgroup_get_from_path(self.prog, parent_cgroup.name)
                child_cgrp = cgroup_get_from_path(
                    self.prog, parent_cgroup.name + "/" + child_cgroup.name
                )

                self.assertCountEqual(
                    [
                        prog.aux.id.value_()
                        for prog in cgroup_bpf_prog_for_each(
                            parent_cgrp, BPF_CGROUP_INET_INGRESS
                        )
                    ],
                    parent_ids,
                )
                self.assertCountEqual(
                    [
                        prog.aux.id.value_()
                        for prog in cgroup_bpf_prog_for_each(
                            child_cgrp, BPF_CGROUP_INET_INGRESS
                        )
                    ],
                    child_ids,
                )

                self.assertCountEqual(
                    [
                        prog.aux.id.value_()
                        for prog in cgroup_bpf_prog_for_each_effective(
                            parent_cgrp, BPF_CGROUP_INET_INGRESS
                        )
                    ],
                    parent_ids,
                )
                self.assertCountEqual(
                    [
                        prog.aux.id.value_()
                        for prog in cgroup_bpf_prog_for_each_effective(
                            child_cgrp, BPF_CGROUP_INET_INGRESS
                        )
                    ],
                    child_effective_ids,
                )
            finally:
                for fd in fds:
                    os.close(fd)
