Installation
============

There are several options for installing drgn.

Dependencies
------------

drgn depends on:

- `Python <https://www.python.org/>`_ 3.6 or newer
- `elfutils <https://sourceware.org/elfutils/>`_ 0.165 or newer

It optionally depends on:

- `libkdumpfile <https://github.com/ptesarik/libkdumpfile>`_ for `makedumpfile
  <https://github.com/makedumpfile/makedumpfile>`_ compressed kernel core dump
  format support

The build requires:

- `GCC <https://gcc.gnu.org/>`_
- `GNU Make <https://www.gnu.org/software/make/>`_
- `pkgconf <http://pkgconf.org/>`_
- `setuptools <https://pypi.org/project/setuptools/>`_

Building from the Git repository (rather than a release tarball) additionally
requires:

- `autoconf <https://www.gnu.org/software/autoconf/>`_
- `automake <https://www.gnu.org/software/automake/>`_
- `libtool <https://www.gnu.org/software/libtool/>`_
- `GNU Awk <https://www.gnu.org/software/gawk/>`_ 4.0 or newer

.. include:: ../README.rst
    :start-after: start-installation
    :end-before: end-installation

.. highlight:: console

Virtual Environment
^^^^^^^^^^^^^^^^^^^

The above options all install drgn globally. You can also install drgn in a
`virtual environment <https://docs.python.org/3/library/venv.html>`_, either
with pip::

    $ python3 -m venv drgnenv
    $ source drgnenv/bin/activate
    (drgnenv) $ pip3 install drgn
    (drgnenv) $ drgn --help

Or from source::

    $ python3 -m venv drgnenv
    $ source drgnenv/bin/activate
    (drgnenv) $ python3 setup.py install
    (drgnenv) $ drgn --help

Running Locally
---------------

If you build drgn from source, you can also run it without installing it::

    $ python3 setup.py build_ext -i
    $ python3 -m drgn --help
