Getting Debugging Symbols
=========================

.. highlight:: console

drgn needs debugging symbols in order to interpret the target program. If drgn
prints a warning like::

    $ drgn
    warning: missing debugging symbols for kernel 6.13.8-200.fc41.x86_64
    critical: missing some debugging symbols; see https://drgn.readthedocs.io/en/latest/getting_debugging_symbols.html
    ...

then you need to get debugging symbols. The method depends on whether the
binary that is missing debugging symbols was built manually or is provided by
your Linux distribution.

Note that you only need debugging symbols for the binaries you're actually
debugging. If the warnings are for modules, shared libraries, etc. that you
don't care about, feel free to ignore them.

Since drgn 0.0.31, you can run drgn with ``--log-level debug`` to get logs of
where drgn looked for debugging symbols.

Building With Debugging Symbols
-------------------------------

If the binary that drgn warns about is one that you built yourself, then you
need to rebuild it with debugging symbols. Here is a quick overview of how to
do that in different build systems:

.. list-table::
    :header-rows: 1

    * - Build System
      - Instructions
    * - Linux Kernel
      - Since Linux 5.18: In ``menuconfig``, set ``Kernel hacking ->
        Compile-time checks and compiler options -> Debug information`` to
        ``Rely on the toolchain's implicit default DWARF version``. Or, add
        ``CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y`` to :file:`.config`.

        Before Linux 5.18: In ``menuconfig``, enable ``Kernel hacking ->
        Compile-time checks and compiler options -> Compile the kernel with
        debug info``. Or, add ``CONFIG_DEBUG_INFO=y`` to :file:`.config`.
    * - `Meson <https://mesonbuild.com/Builtin-options.html#details-for-buildtype>`_
      - Run ``meson setup --buildtype=debugoptimized $builddir`` or
        ``meson setup --buildtype=debug $builddir``.
    * - `CMake <https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html>`_
      - Run ``cmake --build $builddir -DCMAKE_BUILD_TYPE=RelWithDebInfo`` or
        ``cmake --build $builddir -DCMAKE_BUILD_TYPE=Debug``.

        Or, add ``set(CMAKE_BUILD_TYPE RelWithDebInfo)`` or
        ``set(CMAKE_BUILD_TYPE Debug)`` to :file:`CMakeLists.txt`.
    * - Autotools
      - Depends on the project, but usually ``CFLAGS="-Og -g" ./configure``.
    * - Make
      - Depends on the project, but usually ``CFLAGS="-Og -g" make``.
    * - None (GCC or Clang directly)
      - Pass ``-Og -g`` options.

Consult your build system's documentation for details.

Debugging Symbols for Linux Distribution Packages
-------------------------------------------------

Most Linux distributions don't install debugging symbols for installed packages
by default. If the binary that drgn warns about is part of your Linux
distribution, then you have two options: manual installation through the
package manager or automatic downloads using debuginfod. This section documents
how to do both on common Linux distributions, including flow charts for
recommended practices.

.. contents:: Contents
    :depth: 1
    :local:
    :backlinks: none

Debuginfod
^^^^^^^^^^

`debuginfod <https://sourceware.org/elfutils/Debuginfod.html>`_ is a service
providing debugging symbols via an HTTP API. Many Linux distributions run a
debuginfod server for their packages, and some automatically enable it.

Debugging symbols can be downloaded via debuginfod automatically, so it
typically provides the best user experience. However, there are a few caveats,
especially when debugging the Linux kernel:

1. Before drgn 0.0.31, drgn did not support using debuginfod for the Linux kernel.
2. Except on Fedora's debuginfod server, downloading debugging symbols for the
   Linux kernel is extremely slow due to `technical limitations that have been
   fixed upstream
   <https://blog.osandov.com/2024/07/25/making-debuginfod-viable-for-the-linux-kernel.html>`_
   but not yet deployed on other distributions. As a result, since drgn 0.0.31,
   when debugging the Linux kernel, drgn only uses debuginfod on Fedora.
3. Before drgn 0.0.31, while drgn is downloading from debuginfod, it can't be
   interrupted with :kbd:`Ctrl-C`, and it doesn't print a progress bar.

.. _debuginfod-support:

Since drgn 0.0.31, drgn includes whether it was built with debuginfod support
in its version string (look for "with debuginfod")::

    $ drgn --version
    drgn 0.0.31 (using Python 3.13.2, elfutils 0.192, with debuginfod (dlopen), with libkdumpfile)

If you built drgn from source and the version string includes "without
debuginfod", make sure you installed the :ref:`necessary dependencies
<installation-from-source>` and rebuild drgn. Before drgn 0.0.31, drgn doesn't
need to be built specifically with debuginfod support.

Fedora
^^^^^^

.. graphviz::

    digraph {
        start [
            label = "Need debugging\nsymbols on Fedora"
            style = filled
            fillcolor = lightpink
        ]
        drgn_version [
            label = "What version\nof drgn?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        use_debuginfod [
            label = "Use debuginfod\n(automatic)"
            style = filled
            fillcolor = palegreen
        ]
        use_dnf [
            label = "Manually install with\ndnf debuginfo-install"
            style = filled
            fillcolor = palegreen
        ]

        start -> drgn_version
        drgn_version -> use_debuginfod [ label = ">= 0.0.31" ]
        drgn_version -> use_dnf [ label = "< 0.0.31" ]
    }

Debuginfod
""""""""""

Fedora automatically enables debuginfod by default. Since drgn 0.0.31, drgn can
even use debuginfod for Linux kernel debugging symbols.

If debuginfod is not working, :ref:`make sure <debuginfod-support>` your build
of drgn supports it and try running::

    $ sudo dnf install elfutils-debuginfod-client
    $ source /etc/profile.d/debuginfod.sh

Also see the `Fedora debuginfod documentation
<https://fedoraproject.org/wiki/Debuginfod>`_.

Manual Installation
"""""""""""""""""""

Debugging symbols can also be installed manually on Fedora with ``sudo dnf
debuginfo-install $package``.

To install symbols for the running kernel::

    $ sudo dnf debuginfo-install kernel-$(uname -r)

To find out what package owns a binary, use ``rpm -qf``::

    $ rpm -qf "$(command -v python3)"
    python3-3.13.2-1.fc41.x86_64
    $ sudo dnf debuginfo-install python3

Also see the `Fedora documentation
<https://docs.fedoraproject.org/en-US/quick-docs/bugzilla-providing-a-stacktrace/>`_.

CentOS Stream
^^^^^^^^^^^^^

.. graphviz::

    digraph {
        start [
            label = "Need debugging symbols\non CentOS Stream"
            style = filled
            fillcolor = lightpink
        ]
        drgn_version [
            label = "What version\nof drgn?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        kernel [
            label = "Are you\ndebugging the\nLinux kernel?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        use_debuginfod [
            label = "Use debuginfod\n(automatic)"
            style = filled
            fillcolor = palegreen
        ]
        use_dnf [
            label = "Manually install with\ndnf debuginfo-install"
            style = filled
            fillcolor = palegreen
        ]

        start -> drgn_version
        drgn_version -> kernel [ label = ">= 0.0.31" ]
        drgn_version -> use_dnf [ label = "< 0.0.31" ]
        kernel -> use_dnf [ label = "Yes" ]
        kernel -> use_debuginfod [ label = "No" ]
    }

Debuginfod
""""""""""

CentOS Stream automatically enables debuginfod by default since CentOS Stream
9. drgn will not use it for Linux kernel debugging symbols by default.

If debuginfod is not working, :ref:`make sure <debuginfod-support>` your build
of drgn supports it and try running::

    $ sudo dnf install elfutils-debuginfod-client
    $ source /etc/profile.d/debuginfod.sh

Manual Installation
"""""""""""""""""""

Debugging symbols can be installed manually on CentOS Stream with ``sudo dnf
debuginfo-install $package``.

To install symbols for the running kernel::

    $ sudo dnf debuginfo-install kernel-$(uname -r)

To find out what package owns a binary, use ``rpm -qf``::

    $ rpm -qf "$(command -v python3)"
    python3-3.12.9-1.el10.x86_64
    $ sudo dnf debuginfo-install python3

Debian
^^^^^^

.. graphviz::

    digraph {
        start [
            label = "Need debugging\nsymbols on Debian"
            style = filled
            fillcolor = lightpink
        ]
        drgn_version [
            label = "What version\nof drgn?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        kernel [
            label = "Are you\ndebugging the\nLinux kernel?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        enable_debug_repos [
            label = "Enable debug\nrepositories"
            shape = rectangle
            style = filled
            fillcolor = bisque
        ]
        use_apt [
            label = "Manually install\nwith apt"
            style = filled
            fillcolor = palegreen
        ]
        enable_debuginfod [
            label = "Enable debuginfod"
            shape = rectangle
            style = filled
            fillcolor = bisque
        ]
        use_debuginfod [
            label = "Use debuginfod"
            style = filled
            fillcolor = palegreen
        ]

        start -> drgn_version
        drgn_version -> kernel [ label = ">= 0.0.31" ]
        drgn_version -> enable_debug_repos [ label = "< 0.0.31" ]
        kernel -> enable_debug_repos [ label = "Yes" ]
        enable_debug_repos -> use_apt
        kernel -> enable_debuginfod [ label = "No" ]
        enable_debuginfod -> use_debuginfod
    }

Debuginfod
""""""""""

On Debian, debuginfod must be enabled manually::

    $ sudo apt install libdebuginfod-common
    $ sudo ln -s /usr/share/libdebuginfod-common/debuginfod.sh /usr/share/libdebuginfod-common/debuginfod.csh /etc/profile.d
    $ source /etc/profile.d/debuginfod.sh

drgn will not use it for Linux kernel debugging symbols by default.

Also see the `Debian debuginfod documentation
<https://wiki.debian.org/Debuginfod>`_.

Manual Installation
"""""""""""""""""""

On Debian, the debugging symbol repositories must be added manually::

    $ sudo apt install lsb-release
    $ sudo tee /etc/apt/sources.list.d/debug.list << EOF
    deb http://deb.debian.org/debian-debug/ $(lsb_release -cs)-debug main
    deb http://deb.debian.org/debian-debug/ $(lsb_release -cs)-proposed-updates-debug main
    EOF
    $ sudo apt update

Then, debugging symbol packages can be installed with ``sudo apt install``.

To install symbols for the running kernel::

    $ sudo apt install linux-image-$(uname -r)-dbg

Some debugging symbol packages are named with a ``-dbg`` suffix and some are
named with a ``-dbgsym`` suffix::

    $ sudo apt install python3-dbg
    $ sudo apt install coreutils-dbgsym

You can use the ``find-dbgsym-packages`` command from the ``debian-goodies``
package to find the correct name::

    $ sudo apt install debian-goodies
    $ find-dbgsym-packages $(command -v python3)
    libc6-dbg libexpat1-dbgsym python3.11-dbg zlib1g-dbgsym
    $ find-dbgsym-packages $(command -v cat)
    coreutils-dbgsym libc6-dbg

Also see the `Debian documentation
<https://wiki.debian.org/HowToGetABacktrace>`_.

Ubuntu
^^^^^^

.. graphviz::

    digraph {
        start [
            label = "Need debugging\nsymbols on Ubuntu"
            style = filled
            fillcolor = lightpink
        ]
        drgn_version [
            label = "What version\nof drgn?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        kernel [
            label = "Are you\ndebugging the\nLinux kernel?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        enable_debug_repos [
            label = "Enable debug\nrepositories"
            shape = rectangle
            style = filled
            fillcolor = bisque
        ]
        use_apt [
            label = "Manually install\nwith apt"
            style = filled
            fillcolor = palegreen
        ]
        use_debuginfod [
            label = "Use debuginfod\n(automatic)"
            style = filled
            fillcolor = palegreen
        ]

        start -> drgn_version
        drgn_version -> kernel [ label = ">= 0.0.31" ]
        drgn_version -> enable_debug_repos [ label = "< 0.0.31" ]
        kernel -> enable_debug_repos [ label = "Yes" ]
        enable_debug_repos -> use_apt
        kernel -> use_debuginfod [ label = "No" ]
    }

Debuginfod
""""""""""

Ubuntu automatically enables debuginfod by default since Ubuntu 22.04 (Jammy
Jellyfish). drgn will not use it for Linux kernel debugging symbols by default.

If debuginfod is not working, :ref:`make sure <debuginfod-support>` your build
of drgn supports it and try running::

    $ sudo apt install libdebuginfod-common
    $ source /etc/profile.d/debuginfod.sh

Also see the `Ubuntu debuginfod documentation
<https://documentation.ubuntu.com/server/reference/debugging/about-debuginfod/index.html>`_.

Manual Installation
"""""""""""""""""""

On Ubuntu, the debugging symbol archive signing key must be installed and the
debugging symbol repositories must be added manually::

    $ sudo apt install lsb-release ubuntu-dbgsym-keyring
    $ sudo tee /etc/apt/sources.list.d/debug.list << EOF
    deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
    deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
    deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse
    EOF
    $ sudo apt update

Then, debugging symbol packages can be installed with ``sudo apt install``.

To install symbols for the running kernel::

    $ sudo apt install linux-image-$(uname -r)-dbgsym

Some debugging symbol packages are named with a ``-dbg`` suffix and some are
named with a ``-dbgsym`` suffix::

    $ sudo apt install python3-dbg
    $ sudo apt install coreutils-dbgsym

You can use the ``find-dbgsym-packages`` command from the ``debian-goodies``
package to find the correct name::

    $ sudo apt install debian-goodies
    $ find-dbgsym-packages $(command -v python3)
    libc6-dbg libexpat1-dbgsym python3.12-dbg zlib1g-dbgsym
    $ find-dbgsym-packages $(command -v cat)
    coreutils-dbgsym libc6-dbg

Also see the `Ubuntu documentation
<https://documentation.ubuntu.com/server/reference/debugging/debug-symbol-packages/index.html>`_.

Arch Linux
^^^^^^^^^^

.. graphviz::

    digraph {
        start [
            label = "Need debugging symbols\non Arch Linux"
            style = filled
            fillcolor = lightpink
        ]
        kernel [
            label = "Are you\ndebugging the\nLinux kernel?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        not_available [
            label = "Debugging symbols\nare not available"
            style = filled
            fillcolor = lightpink
        ]
        use_debuginfod [
            label = "Use debuginfod\n(automatic)"
            style = filled
            fillcolor = palegreen
        ]

        start -> kernel
        kernel -> not_available [ label = "Yes" ]
        kernel -> use_debuginfod [ label = "No" ]
    }

Debuginfod
""""""""""

Arch Linux automatically enables debuginfod by default. However, debugging
symbols are not available for the Linux kernel.

If debuginfod is not working, :ref:`make sure <debuginfod-support>` your build
of drgn supports it and try running::

    $ sudo pacman -S --needed libelf
    $ source /etc/profile.d/debuginfod.sh

Also see the `Arch Linux debuginfod documentation
<https://wiki.archlinux.org/title/Debuginfod>`_.

Manual Installation
"""""""""""""""""""

Arch Linux does not provide debugging symbol packages.

openSUSE
^^^^^^^^

.. graphviz::

    digraph {
        start [
            label = "Need debugging symbols\non openSUSE"
            style = filled
            fillcolor = lightpink
        ]
        distribution [
            label = "Which\ndistribution?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        drgn_version [
            label = "What version\nof drgn?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        kernel [
            label = "Are you\ndebugging the\nLinux kernel?"
            shape = diamond
            style = filled
            fillcolor = khaki1
        ]
        use_debuginfod [
            label = "Use debuginfod\n(automatic)"
            style = filled
            fillcolor = palegreen
        ]
        use_zypper [
            label = "Manually install\nwith zypper"
            style = filled
            fillcolor = palegreen
        ]

        start -> distribution
        distribution -> drgn_version [ label = "Tumbleweed" ]
        distribution -> use_zypper [ label = "Leap" ]
        drgn_version -> kernel [ label = ">= 0.0.31" ]
        drgn_version -> use_zypper [ label = "< 0.0.31" ]
        kernel -> use_zypper [ label = "Yes" ]
        kernel -> use_debuginfod [ label = "No" ]
    }

Debuginfod
""""""""""

openSUSE Tumbleweed automatically enables debuginfod by default. drgn will not
use it for Linux kernel debugging symbols by default.

If debuginfod is not working, :ref:`make sure <debuginfod-support>` your build
of drgn supports it and try running::

    $ sudo zypper install debuginfod-client
    $ source /etc/profile.d/debuginfod.sh

openSUSE Leap does not support debuginfod.

Manual Installation
"""""""""""""""""""

Debugging symbols can be installed manually on openSUSE with::

    $ sudo zypper --plus-content debug install "${package}-debuginfo"

To install symbols for the running kernel::

    $ zypper --plus-content debug install "$(rpm --qf '%{NAME}-debuginfo-%{VERSION}-%{RELEASE}.%{ARCH}' -qf /boot/vmlinuz-"$(uname -r)")"

To find out what package owns a binary, use ``rpm -qf``::

    $ rpm -qf "$(command -v python3)"
    python313-base-3.13.2-3.1.x86_64
    $ sudo zypper --plus-content debug install python313-base-debuginfo

Oracle Linux
^^^^^^^^^^^^

Oracle Linux provides documentation on installing debugging symbols for the
Linux kernel. See the documentation for `Oracle Linux 9
<https://docs.oracle.com/en/operating-systems/oracle-linux/9/drgn/installing_debuginfo_packages.html>`_
and `Oracle Linux 8
<https://docs.oracle.com/en/operating-systems/oracle-linux/8/drgn/installing_debuginfo_packages.html>`_.
