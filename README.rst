drgn
====

.. image:: https://img.shields.io/pypi/v/drgn
    :target: https://pypi.org/project/drgn/
    :alt: PyPI

.. image:: https://github.com/osandov/drgn/workflows/CI/badge.svg
    :target: https://github.com/osandov/drgn/actions
    :alt: CI Status

.. image:: https://readthedocs.org/projects/drgn/badge/?version=latest
    :target: https://drgn.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
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
complex, inter-connected state in large programs. It is also designed as a
library that can be used to build debugging and introspection tools; see the
official `tools <https://github.com/osandov/drgn/tree/main/tools>`_.

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

* Fedora >= 32

  .. code-block:: console

      $ sudo dnf install drgn

* RHEL/CentOS >= 8

  `Enable EPEL <https://docs.fedoraproject.org/en-US/epel/#_quickstart>`_. Then:

  .. code-block:: console

      $ sudo dnf install drgn

* Arch Linux

  Install the `drgn <https://aur.archlinux.org/packages/drgn/>`_ package from
  the `AUR <https://wiki.archlinux.org/title/Arch_User_Repository>`_.

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

Note that RHEL/CentOS 6, Debian Stretch, Ubuntu Trusty, and Ubuntu Xenial (and
older) ship Python versions which are too old. Python 3.6 or newer must be
installed.

From Source
^^^^^^^^^^^

To get the development version of drgn, you will need to build it from source.
First, install dependencies:

* Fedora/RHEL/CentOS

  .. code-block:: console

      $ sudo dnf install autoconf automake elfutils-devel gawk gcc git libtool make pkgconf python3 python3-devel python3-pip python3-setuptools

  Replace ``dnf`` with ``yum`` for RHEL/CentOS < 8.

* Debian/Ubuntu

  .. code-block:: console

      $ sudo apt-get install autoconf automake gawk gcc git liblzma-dev libelf-dev libdw-dev libtool make pkgconf python3 python3-dev python3-pip python3-setuptools zlib1g-dev

* Arch Linux

  .. code-block:: console

      $ sudo pacman -S --needed autoconf automake gawk gcc git libelf libtool make pkgconf python python-pip python-setuptools

Optionally, install `libkdumpfile <https://github.com/ptesarik/libkdumpfile>`_
if you want support for the `makedumpfile
<https://github.com/makedumpfile/makedumpfile>`_ compressed kernel core dump
format. ``libkdumpfile`` is currently only packaged on Fedora and EPEL. For
other distributions, you must install it manually.

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

drgn debugs the running kernel by default; run ``sudo drgn``. To debug a
running program, run ``sudo drgn -p $PID``. To debug a core dump (either a
kernel vmcore or a userspace core dump), run ``drgn -c $PATH``. Make sure to
`install debugging symbols
<https://drgn.readthedocs.io/en/latest/getting_debugging_symbols.html>`_ for
whatever you are debugging.

Then, you can access variables in the program with ``prog['name']`` and access
structure members with ``.``:

.. code-block:: pycon

    $ sudo drgn
    >>> prog['init_task'].comm
    (char [16])"swapper/0"

You can use various predefined helpers:

.. code-block:: pycon

    >>> len(list(bpf_prog_for_each(prog)))
    11
    >>> task = find_task(prog, 115)
    >>> cmdline(task)
    [b'findmnt', b'-p']

You can get stack traces with ``prog.stack_trace()`` and access parameters or
local variables with ``stack_trace['name']``:

.. code-block:: pycon

    >>> trace = prog.stack_trace(task)
    >>> trace[5]
    #5 at 0xffffffff8a5a32d0 (do_sys_poll+0x400/0x578) in do_poll at ./fs/select.c:961:8 (inlined)
    >>> poll_list = trace[5]['list']
    >>> file = fget(task, poll_list.entries[0].fd)
    >>> d_path(file.f_path.address_of_())
    b'/proc/115/mountinfo'

.. end-quick-start

See the `user guide <https://drgn.readthedocs.io/en/latest/user_guide.html>`_
for more details and features.

License
-------

.. start-license

Copyright (c) Meta Platforms, Inc. and affiliates.

drgn is licensed under the `GPLv3
<https://www.gnu.org/licenses/gpl-3.0.en.html>`_ or later.

.. end-license
