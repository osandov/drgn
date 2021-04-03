# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0-or-later

import os

from drgn import cast
from drgn.helpers.linux.fs import fget
from drgn.helpers.linux.net import sk_fullsock
from drgn.helpers.linux.pid import find_task
from tests.helpers.linux import LinuxHelperTestCase, create_socket


class TestNet(LinuxHelperTestCase):
    def test_sk_fullsock(self):
        with create_socket() as sock:
            file = fget(find_task(self.prog, os.getpid()), sock.fileno())
            sk = cast("struct socket *", file.private_data).sk.read_()
            self.assertTrue(sk_fullsock(sk))
