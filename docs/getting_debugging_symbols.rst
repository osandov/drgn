Getting Debugging Symbols
=========================

.. highlight:: console

Most Linux distributions don't install debugging symbols for installed packages
by default. This page documents how to install debugging symbols on common
distributions. If drgn prints an error like::

    $ sudo drgn
    could not get debugging information for:
    kernel (could not find vmlinux for 5.14.14-200.fc34.x86_64)
    ...

Then you need to install debugging symbols.

Fedora
------

Fedora makes it very easy to install debugging symbols with the `DNF
debuginfo-install plugin
<https://dnf-plugins-core.readthedocs.io/en/latest/debuginfo-install.html>`_,
which is installed by default. Simply run ``sudo dnf debuginfo-install
$package``::

    $ sudo dnf debuginfo-install python3

To find out what package owns a binary, use ``rpm -qf``::

    $ rpm -qf $(which python3)
    python3-3.9.7-1.fc34.x86_64

To install symbols for the running kernel::

    $ sudo dnf debuginfo-install kernel-$(uname -r)

Also see the `Fedora documentation
<https://fedoraproject.org/wiki/StackTraces>`_.

Debian
------

Debian requires you to manually add the debugging symbol repositories::

    $ sudo tee /etc/apt/sources.list.d/debug.list << EOF
    deb http://deb.debian.org/debian-debug/ $(lsb_release -cs)-debug main
    deb http://deb.debian.org/debian-debug/ $(lsb_release -cs)-proposed-updates-debug main
    EOF
    $ sudo apt update

Then, debugging symbol packages can be installed with ``sudo apt install``.
Some debugging symbol packages are named with a ``-dbg`` suffix::

    $ sudo apt install python3-dbg

And some are named with a ``-dbgsym`` suffix::

    $ sudo apt install coreutils-dbgsym

You can use the ``find-dbgsym-packages`` command from the ``debian-goodies``
package to find the correct name::

    $ sudo apt install debian-goodies
    $ find-dbgsym-packages $(which python3)
    libc6-dbg libexpat1-dbgsym python3.9-dbg zlib1g-dbgsym
    $ find-dbgsym-packages $(which cat)
    coreutils-dbgsym libc6-dbg

To install symbols for the running kernel::

    $ sudo apt install linux-image-$(uname -r)-dbg

Also see the `Debian documentation
<https://wiki.debian.org/HowToGetABacktrace>`_.

Ubuntu
------

On Ubuntu, you must install the debugging symbol archive signing key and
manually add the debugging symbol repositories::

    $ sudo apt update
    $ sudo apt install ubuntu-dbgsym-keyring
    $ sudo tee /etc/apt/sources.list.d/debug.list << EOF
    deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
    deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
    deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse
    EOF
    $ sudo apt update

Like Debian, some debugging symbol packages are named with a ``-dbg`` suffix
and some are named with a ``-dbgsym`` suffix::

    $ sudo apt install python3-dbg
    $ sudo apt install coreutils-dbgsym

You can use the ``find-dbgsym-packages`` command from the ``debian-goodies``
package to find the correct name::

    $ sudo apt install debian-goodies
    $ find-dbgsym-packages $(which python3)
    libc6-dbg libexpat1-dbgsym python3.9-dbg zlib1g-dbgsym
    $ find-dbgsym-packages $(which cat)
    coreutils-dbgsym libc6-dbg

To install symbols for the running kernel::

    $ sudo apt install linux-image-$(uname -r)-dbgsym

Also see the `Ubuntu documentation
<https://wiki.ubuntu.com/Debug%20Symbol%20Packages>`_.

Arch Linux
----------

Arch Linux unfortunately does not make debugging symbols available. Packages
must be manually rebuilt with debugging symbols enabled. See the `ArchWiki
<https://wiki.archlinux.org/title/Debugging/Getting_traces>`_ and the `feature
request <https://bugs.archlinux.org/task/38755?project=1>`_.
