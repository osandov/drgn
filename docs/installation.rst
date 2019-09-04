Installation
============

.. highlight:: console

drgn depends on:

- `Python <https://www.python.org/>`_ 3.6 or newer
- `zlib <https://www.zlib.net>`_
- `xz <https://tukaani.org/xz/>`_
- `bzip2 <http://www.bzip.org>`_

A version of `elfutils <https://sourceware.org/elfutils/>`_ is bundled with
drgn.

The build requires:

- `GCC <https://gcc.gnu.org/>`_
- `GNU Make <https://www.gnu.org/software/make/>`_
- `pkgconf <http://pkgconf.org/>`_
- `setuptools <https://pypi.org/project/setuptools/>`_
- `autoconf <https://www.gnu.org/software/autoconf/>`_
- `automake <https://www.gnu.org/software/automake/>`_
- `libtool <https://www.gnu.org/software/libtool/>`_
- `flex <https://github.com/westes/flex>`_
- `GNU bison <https://www.gnu.org/software/bison/>`_
- `GNU awk <https://www.gnu.org/software/gawk/>`_

.. include:: ../README.rst
    :start-after: start-install-dependencies
    :end-before: end-install-dependencies

Then, drgn can be built and installed::

    $ python3 setup.py build
    $ sudo python3 setup.py install
    $ drgn --help

Or, it can be be built and run locally::

    $ python3 setup.py build_ext -i
    $ python3 -m drgn --help

libkdumpfile
------------

drgn supports kdump-compressed kernel core dumps when `libkdumpfile
<https://github.com/ptesarik/libkdumpfile>`_ is available. libkdumpfile is not
packaged for most Linux distributions, so it must be built and installed
manually. If it is installed, then drgn is automatically built with support.
