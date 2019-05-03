Installation
============

.. highlight:: console

drgn depends on `Python <https://www.python.org/>`_ 3.6 or newer as well as
`elfutils <https://sourceware.org/elfutils/>`_. The build requires `GCC
<https://gcc.gnu.org/>`_ or `Clang <https://clang.llvm.org/>`_, `GNU Make
<https://www.gnu.org/software/make/>`_, `pkgconf <http://pkgconf.org/>`_, and
`setuptools <https://pypi.org/project/setuptools/>`_. A build from a Git
checkout also requires the GNU Autotools (`autoconf
<https://www.gnu.org/software/autoconf/>`_, `automake
<https://www.gnu.org/software/automake/automake.html>`_, and `libtool
<https://www.gnu.org/software/libtool/libtool.html>`_). Install those
dependencies:

Arch Linux::

    $ sudo pacman -S --needed autoconf automake libtool make gcc pkgconf libelf python python-setuptools

Debian/Ubuntu::

    $ sudo apt-get install autoconf automake libtool make gcc pkgconf libelf-dev libdw-dev python3 python3-dev python3-setuptools

Note that Debian, Ubuntu Trusty, and Ubuntu Xenial ship Python versions which
are too old, so a newer version must be installed manually.

Due to a packaging `bug
<https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=885071>`_, the following may
also be required::

    $ sudo apt-get install liblzma-dev zlib1g-dev

Fedora::

    $ sudo dnf install autoconf automake libtool make gcc pkgconf elfutils-devel python3 python3-devel python3-setuptools

Then, drgn can be built and installed::

    $ python3 setup.py build
    $ sudo python3 setup.py install
    $ drgn --help

Or, it can be be built and run locally::

    $ python3 setup.py build_ext -i
    $ python3 -m drgn --help
