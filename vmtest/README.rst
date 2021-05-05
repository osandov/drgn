drgn VM Testing
===============

drgn has a significant amount of code (both core and in helpers) which is
dependent on the Linux kernel version. This code is tested on multiple Linux
kernel versions in a virtual machine. These tests can be run on all supported
kernels with ``python3 setup.py test -K``. This requires QEMU, BusyBox, and
zstd to be installed.

Tests can also be run on specific kernels with ``-k``. This takes a
comma-separated list of kernels which are wildcard patterns (e.g., ``5.6.*``)
matching a kernel release hosted on GitHub (see below).

Architecture
------------

The goal of vmtest is to run tests in the same userspace environment as the
host, but with a different kernel. The host runs the virtual machine with `QEMU
<https://www.qemu.org/>`_ (see the `vmtest.vm <vm.py>`_ module).

The guest mounts the host's root filesystem as its own root filesystem via
`VirtFS <https://www.linux-kvm.org/page/VirtFS>`_. It is mounted read-only for
safety. To support modifications, the guest uses `OverlayFS
<https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt>`_ to
overlay a read-write tmpfs over the VirtFS root. It also mounts the kernel
modules and vmlinux via VirtFS.

The guest runs a `BusyBox <https://www.busybox.net/>`_ shell script as init
which sets up the system and filesystem hierarchy, runs a command, and returns
the exit status via `virtio-serial
<https://fedoraproject.org/wiki/Features/VirtioSerial>`_.

This infrastructure is all generic. The drgn-specific parts are:

1. The kernel builds. These are configured with a minimal configuration
   including everything required to run drgn and the Linux kernel helper tests.
   Each build is packaged as a tarball containing ``vmlinux``, ``vmlinuz``, and
   kernel modules. These packages are hosted in a `GitHub release
   <https://github.com/osandov/drgn/releases/tag/vmtest-assets>`_. They are
   managed via the GitHub API by the `vmtest.manage <manage.py>`_ CLI and
   downloaded by the `vmtest.download <download.py>`_ module.
2. The test command itself. This is just some ``setup.py`` glue and the proper
   invocation of the Python `unittest command line interface
   <https://docs.python.org/3/library/unittest.html#test-discovery>`_.

The ``vmtest.vm`` and ``vmtest.download`` modules also have CLIs for testing
purposes. These are subject to change.
