drgn
====

|pypi badge| |ci badge| |docs badge| |black badge|

.. |pypi badge| image:: https://img.shields.io/pypi/v/drgn
    :target: https://pypi.org/project/drgn/
    :alt: PyPI

.. |ci badge| image:: https://github.com/osandov/drgn/workflows/CI/badge.svg
    :target: https://github.com/osandov/drgn/actions
    :alt: CI Status

.. |docs badge| image:: https://readthedocs.org/projects/drgn/badge/?version=latest
    :target: https://drgn.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. |black badge| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

.. start-introduction

drgn (pronounced "dragon") is a debugger with an emphasis on programmability.
drgn exposes the types and variables in a program for easy, expressive
scripting in Python. For example, you can debug the Linux kernel:

.. code-block:: pycon

    >>> from drgn.helpers.linux import list_for_each_entry
    >>> for mod in list_for_each_entry('struct module',
    ...                                prog['modules'].address_of_(),
    ...                                'list'):
    ...    if mod.refcnt.counter > 10:
    ...        print(mod.name)
    ...
    (char [56])"snd"
    (char [56])"evdev"
    (char [56])"i915"

Although other debuggers like `GDB <https://www.gnu.org/software/gdb/>`_ have
scripting support, drgn aims to make scripting as natural as possible so that
debugging feels like coding. This makes it well-suited for introspecting the
complex, inter-connected state in large programs.

Additionally, drgn is designed as a library that can be used to build debugging
and introspection tools; see the official `tools
<https://github.com/osandov/drgn/tree/main/tools>`_.

drgn was developed at `Meta <https://opensource.fb.com/>`_ for debugging the
Linux kernel (as an alternative to the `crash
<https://crash-utility.github.io/>`_ utility), but it can also debug userspace
programs written in C. C++ support is in progress.

.. end-introduction

Documentation can be found at `drgn.readthedocs.io
<https://drgn.readthedocs.io>`_.

.. start-installation

Installation
------------

Package Manager
^^^^^^^^^^^^^^^

drgn can be installed using the package manager on some Linux distributions.

.. image:: https://repology.org/badge/vertical-allrepos/drgn.svg?exclude_unsupported=1
    :target: https://repology.org/project/drgn/versions
    :alt: Packaging Status

* Fedora, RHEL/CentOS Stream >= 9

  .. code-block:: console

      $ sudo dnf install drgn

* RHEL/CentOS < 9

  `Enable EPEL <https://docs.fedoraproject.org/en-US/epel/#_quickstart>`_. Then:

  .. code-block:: console

      $ sudo dnf install drgn

* Oracle Linux >= 8

  Enable the ``ol8_addons`` or ``ol9_addons`` repository. Then:

  .. code-block:: console

      $ sudo dnf config-manager --enable ol8_addons  # OR: ol9_addons
      $ sudo dnf install drgn

  drgn is also available for Python versions in application streams. For
  example, use ``dnf install python3.12-drgn`` to install drgn for Python 3.12.
  See the documentation for drgn in `Oracle Linux 9
  <https://docs.oracle.com/en/operating-systems/oracle-linux/9/drgn/how_to_install_drgn.html>`_
  and `Oracle Linux 8
  <https://docs.oracle.com/en/operating-systems/oracle-linux/8/drgn/how_to_install_drgn.html>`_
  for more information.

* Debian >= 12 (Bookworm)/Ubuntu >= 24.04 (Noble Numbat)

  .. code-block:: console

      $ sudo apt install python3-drgn

  To get the latest version on Ubuntu, enable the `michel-slm/kernel-utils PPA
  <https://launchpad.net/~michel-slm/+archive/ubuntu/kernel-utils>`_ first.

* Arch Linux

  .. code-block:: console

      $ sudo pacman -S drgn

* Gentoo

  .. code-block:: console

      $ sudo emerge dev-debug/drgn

* openSUSE

  .. code-block:: console

      $ sudo zypper install python3-drgn

pip
^^^

If your Linux distribution doesn't package the latest release of drgn, you can
install it with `pip <https://pip.pypa.io/>`_.

First, `install pip
<https://packaging.python.org/guides/installing-using-linux-tools/#installing-pip-setuptools-wheel-with-linux-package-managers>`_.
Then, run:

.. code-block:: console

    $ sudo pip3 install drgn

This will install a binary wheel by default. If you get a build error, then pip
wasn't able to use the binary wheel. Install the dependencies listed `below
<#from-source>`_ and try again.

Note that RHEL/CentOS 7, Debian 10 ("buster"), and Ubuntu 18.04 ("Bionic
Beaver") (and older) ship Python versions which are too old. Python 3.8 or
newer must be installed.

.. _installation-from-source:

From Source
^^^^^^^^^^^

To get the development version of drgn, you will need to build it from source.
First, install dependencies:

* Fedora, RHEL/CentOS Stream >= 9

  .. code-block:: console

      $ sudo dnf install autoconf automake check-devel elfutils-debuginfod-client-devel elfutils-devel gcc git libkdumpfile-devel libtool make pkgconf python3 python3-devel python3-pip python3-setuptools xz-devel

* RHEL/CentOS < 9, Oracle Linux

  .. code-block:: console

      $ sudo dnf install autoconf automake check-devel elfutils-devel gcc git libtool make pkgconf python3 python3-devel python3-pip python3-setuptools xz-devel

  Optionally, install ``libkdumpfile-devel`` from EPEL on RHEL/CentOS >= 8 or
  install `libkdumpfile <https://github.com/ptesarik/libkdumpfile>`_ from
  source if you want support for the makedumpfile format. For Oracle Linux >= 7,
  ``libkdumpfile-devel`` can be installed directly from the corresponding addons
  repository (e.g. ``ol9_addons``).

  Replace ``dnf`` with ``yum`` for RHEL/CentOS/Oracle Linux < 8.

  When building on RHEL/CentOS/Oracle Linux < 8, you may need to use a newer
  version of GCC, for example, using the ``devtoolset-12`` developer toolset.
  Check your distribution's documentation for information on installing and
  using these newer toolchains.

* Debian/Ubuntu

  .. code-block:: console

      $ sudo apt install autoconf automake check gcc git libdebuginfod-dev libkdumpfile-dev liblzma-dev libelf-dev libdw-dev libtool make pkgconf python3 python3-dev python3-pip python3-setuptools zlib1g-dev

  On Debian <= 11 (Bullseye) and Ubuntu <= 22.04 (Jammy Jellyfish),
  ``libkdumpfile-dev`` is not available, so you must install libkdumpfile from
  source if you want support for the makedumpfile format.

* Arch Linux

  .. code-block:: console

      $ sudo pacman -S --needed autoconf automake check gcc git libelf libkdumpfile libtool make pkgconf python python-pip python-setuptools xz

* Gentoo

  .. code-block:: console

      $ sudo emerge --noreplace --oneshot dev-build/autoconf dev-build/automake dev-libs/check dev-libs/elfutils sys-devel/gcc dev-vcs/git dev-libs/libkdumpfile dev-build/libtool dev-build/make dev-python/pip virtual/pkgconfig dev-lang/python dev-python/setuptools app-arch/xz-utils

* openSUSE

  .. code-block:: console

      $ sudo zypper install autoconf automake check-devel gcc git libdebuginfod-devel libdw-devel libelf-devel libkdumpfile-devel libtool make pkgconf python3 python3-devel python3-pip python3-setuptools xz-devel

Then, run:

.. code-block:: console

    $ git clone https://github.com/osandov/drgn.git
    $ cd drgn
    $ python3 setup.py build
    $ sudo python3 setup.py install

.. end-installation

See the `installation documentation
<https://drgn.readthedocs.io/en/latest/installation.html>`_ for more options.

Quick Start
-----------

.. start-quick-start

drgn debugs the running kernel by default; simply run ``drgn``. To debug a
running program, run ``drgn -p $PID``. To debug a core dump (either a kernel
vmcore or a userspace core dump), run ``drgn -c $PATH``. Make sure to `install
debugging symbols
<https://drgn.readthedocs.io/en/latest/getting_debugging_symbols.html>`_ for
whatever you are debugging.

Then, you can access variables in the program with ``prog["name"]`` and access
structure members with ``.``:

.. code-block:: pycon

    $ drgn
    >>> prog["init_task"].comm
    (char [16])"swapper/0"

You can use various predefined helpers:

.. code-block:: pycon

    >>> len(list(bpf_prog_for_each()))
    11
    >>> task = find_task(115)
    >>> cmdline(task)
    [b'findmnt', b'-p']

You can get stack traces with ``stack_trace()`` and access parameters or local
variables with ``trace["name"]``:

.. code-block:: pycon

    >>> trace = stack_trace(task)
    >>> trace[5]
    #5 at 0xffffffff8a5a32d0 (do_sys_poll+0x400/0x578) in do_poll at ./fs/select.c:961:8 (inlined)
    >>> poll_list = trace[5]["list"]
    >>> file = fget(task, poll_list.entries[0].fd)
    >>> d_path(file.f_path.address_of_())
    b'/proc/115/mountinfo'

.. end-quick-start

See the `user guide <https://drgn.readthedocs.io/en/latest/user_guide.html>`_
for more details and features.

.. start-for-index

Getting Help
------------

* The `GitHub issue tracker <https://github.com/osandov/drgn/issues>`_ is the
  preferred method to report issues.
* There is also a `Linux Kernel Debuggers Matrix room
  <https://matrix.to/#/#linux-debuggers:matrix.org>`_.

License
-------

Copyright (c) Meta Platforms, Inc. and affiliates.

drgn is licensed under the `LGPLv2.1
<https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html>`_ or later.

.. end-for-index
