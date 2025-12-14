# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import errno
import os
import resource
import unittest

from _drgn_util.platform import NORMALIZED_MACHINE_NAME
from drgn import cast
from drgn.helpers.linux.bpf import (
    bpf_btf_for_each,
    bpf_link_for_each,
    bpf_map_for_each,
    bpf_prog_for_each,
    bpf_prog_used_maps,
    cgroup_bpf_prog_for_each,
    cgroup_bpf_prog_for_each_effective,
)
from drgn.helpers.linux.cgroup import cgroup_get_from_path
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.pid import find_task
from tests.linux_kernel import LinuxKernelTestCase
from tests.linux_kernel.bpf import (
    BPF_CGROUP_INET_INGRESS,
    BPF_EXIT_INSN,
    BPF_F_ALLOW_MULTI,
    BPF_LD_MAP_FD,
    BPF_MAP_TYPE_HASH,
    BPF_MOV64_IMM,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_REG_0,
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


class BpfTestCase(LinuxKernelTestCase):
    INSNS = (
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if _SYS_bpf is None:
            raise unittest.SkipTest(
                f"bpf syscall number is not known on {NORMALIZED_MACHINE_NAME}"
            )
        # Before the patch series culminating in Linux kernel commit
        # 3ac1f01b43b6 ("bpf: Eliminate rlimit-based memory accounting for bpf
        # progs") (in v5.11), BPF program and map memory usage was limited by
        # RLIMIT_MEMLOCK. At that time (before Linux kernel commit 9dcc38e2813e
        # ("Increase default MLOCK_LIMIT to 8 MiB") (in v5.16)), the limit was
        # only 64kB. We only allocate a few small objects at a time, but with
        # 64k pages, we can easily blow that limit.
        memlock_limit = 8 * 1024 * 1024
        old_limit = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        if old_limit[0] < memlock_limit:
            resource.setrlimit(
                resource.RLIMIT_MEMLOCK,
                (memlock_limit, max(memlock_limit, old_limit[1])),
            )
            cls.addClassCleanup(resource.setrlimit, resource.RLIMIT_MEMLOCK, old_limit)
        try:
            os.close(bpf_map_create(BPF_MAP_TYPE_HASH, 8, 8, 8))
        except OSError as e:
            if e.errno != errno.ENOSYS:
                raise
            raise unittest.SkipTest(
                "kernel does not support bpf syscall (CONFIG_BPF_SYSCALL)"
            )


class TestBpf(BpfTestCase):
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

    def test_bpf_prog_used_maps(self):
        with contextlib.ExitStack() as exit_stack:
            map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, 8, 8, 8)
            exit_stack.callback(os.close, map_fd)

            prog_fd = bpf_prog_load(
                BPF_PROG_TYPE_SOCKET_FILTER,
                BPF_LD_MAP_FD(BPF_REG_0, map_fd) + self.INSNS,
                b"GPL",
            )
            exit_stack.callback(os.close, prog_fd)

            bpf_prog = cast(
                "struct bpf_prog *",
                fget(find_task(self.prog, os.getpid()), prog_fd).private_data,
            )

            bpf_map = cast(
                "struct bpf_map *",
                fget(find_task(self.prog, os.getpid()), map_fd).private_data,
            )

            self.assertEqual(list(bpf_prog_used_maps(bpf_prog)), [bpf_map])

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
