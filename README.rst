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

drgn was developed for debugging the Linux kernel (as an alternative to the
`crash <http://people.redhat.com/anderson/>`_ utility), but it can also debug
userspace programs written in C. C++ support is in progress.

.. end-introduction

Documentation can be found at `drgn.readthedocs.io
<https://drgn.readthedocs.io>`_.

Installation
------------

.. start-install-dependencies

Install dependencies:

Arch Linux:

.. code-block:: console

    $ sudo pacman -S --needed gcc libelf make pkgconf python python-pip python-setuptools

Debian/Ubuntu:

.. code-block:: console

    $ sudo apt-get install gcc liblzma-dev libelf-dev libdw-dev make pkgconf python3 python3-dev python3-pip python3-setuptools zlib1g-dev

Note that Debian Stretch, Ubuntu Trusty, and Ubuntu Xenial (and older) ship
Python versions which are too old. Python 3.6 or newer must be installed
manually.

Fedora:

.. code-block:: console

    $ sudo dnf install elfutils-devel gcc make pkgconf python3 python3-devel python3-pip python3-setuptools

Optionally, install:

* `libkdumpfile <https://github.com/ptesarik/libkdumpfile>`_ if you want
  support for kdump-compressed kernel core dumps

.. end-install-dependencies

Then, run:

.. code-block:: console

    $ sudo pip3 install drgn

See the `installation documentation
<https://drgn.readthedocs.io/en/latest/installation.html>`_ for more options.

Quick Start
-----------

.. start-quick-start

drgn debugs the running kernel by default; run ``sudo drgn``. To debug a
running program, run ``sudo drgn -p $PID``. To debug a core dump (either a
kernel vmcore or a userspace core dump), run ``drgn -c $PATH``. The program
must have debugging symbols available.

Then, you can access variables in the program with ``prog['name']``, access
structure members with ``.``, use various predefined helpers, and more:

.. code-block:: pycon

    $ sudo drgn
    >>> prog['init_task'].comm
    (char [16])"swapper/0"
    >>> d_path(fget(find_task(prog, 1), 0).f_path.address_of_())
    b'/dev/null'
    >>> max(task.stime for task in for_each_task(prog))
    (u64)4192109975952
    >>> sum(disk.gendisk.part0.nr_sects for disk in for_each_disk(prog))
    (sector_t)999705952

.. end-quick-start

See the `user guide <https://drgn.readthedocs.io/en/latest/user_guide.html>`_
for more information.

License
-------

.. start-license

Copyright (c) Facebook, Inc. and its affiliates.

drgn is licensed under the `GPLv3
<https://www.gnu.org/licenses/gpl-3.0.en.html>`_ or later.

.. end-license
