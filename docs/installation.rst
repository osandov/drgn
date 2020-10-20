Installation
============

There are several options for installing drgn.

Dependencies
------------

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

Installation
------------

.. highlight:: console

After installing dependencies, the latest release of drgn can be installed
globally with `pip <https://pip.pypa.io>`_::

    $ sudo pip3 install drgn
    $ drgn --help

The development version can be built and installed manually::

    $ git clone https://github.com/osandov/drgn.git
    $ cd drgn
    $ python3 setup.py build
    $ sudo python3 setup.py install
    $ drgn --help

Both of these options can be done in a `virtual environment
<https://docs.python.org/3/library/venv.html>`_ if you do not wish to install
drgn globally::

    $ python3 -m venv drgnenv
    $ source drgnenv/bin/activate
    (drgenv) $ pip3 install drgn
    (drgenv) $ drgn --help

Development
-----------

For development, drgn can be built and run locally::

    $ CFLAGS="-Wall -Werror -g -O2" python3 setup.py build_ext -i
    $ python3 -m drgn --help

libkdumpfile
------------

drgn supports kdump-compressed kernel core dumps when `libkdumpfile
<https://github.com/ptesarik/libkdumpfile>`_ is available. libkdumpfile is not
packaged for most Linux distributions, so it must be built and installed
manually. If it is installed, then drgn is automatically built with support.
