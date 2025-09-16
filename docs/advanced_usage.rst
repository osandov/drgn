Advanced Usage
==============

.. highlight:: pycon

The :doc:`user_guide` covers basic usage of drgn, but drgn also supports more
advanced use cases which are covered here.

.. _advanced-modules:

Modules and Debugging Symbols
-----------------------------

drgn tries to determine what executable, libraries, etc. a program uses and
load debugging symbols automatically. As long as :doc:`debugging symbols are
installed <getting_debugging_symbols>`, this should work out of the box on
standard setups.

For non-standard scenarios, drgn allows overriding the defaults with different
levels of control and complexity.

Loading Debugging Symbols From Non-Standard Locations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. program:: drgn

drgn searches standard locations for debugging symbols. If you have debugging
symbols available in a non-standard location, you can provide it to the CLI
with the :option:`-s`/:option:`--symbols` option:

.. code-block:: console

    $ drgn -s ./libfoo.so -s /usr/lib/libbar.so.debug

Or with the :meth:`drgn.Program.load_debug_info()` method::

    >>> prog.load_debug_info(["./libfoo.so", "/usr/lib/libbar.so.debug"])

Loading Debugging Symbols For Specific Modules
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:option:`-s` and :meth:`~drgn.Program.load_debug_info()` try the given files
against all of the modules loaded in the program based on build IDs. You can
also :ref:`look up <api-module-constructors>` a specific module and try a given
file for just that module with :meth:`drgn.Module.try_file()`::

    >>> prog.main_module().try_file("build/vmlinux")

Loading Additional Debugging Symbols
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:option:`-s` and :meth:`~drgn.Program.load_debug_info()` ignore files that
don't correspond to a loaded module. To load debugging symbols from an
arbitrary file, pass :option:`--extra-symbols` to the CLI:

.. code-block:: console

    $ drgn --extra-symbols ./my_extra_symbols.debug

Or create a :class:`drgn.ExtraModule`::

    >>> module = prog.extra_module("my_extra_symbols", create=True)
    >>> module.try_file("./my_extra_symbols.debug")

Listing Modules
^^^^^^^^^^^^^^^

By default, drgn creates a module for everything loaded in the program. You can
disable this in the CLI with :option:`--no-default-symbols`.

You can find or create the loaded modules programmatically with
:meth:`drgn.Program.loaded_modules()`::

    >>> for module, new in prog.loaded_modules():
    ...     print("Created" if new else "Found", module)

You can see all of the created modules with :meth:`drgn.Program.modules()`.

Overriding Modules
^^^^^^^^^^^^^^^^^^

You can create modules with the :ref:`module factory functions
<api-module-constructors>`. You can also modify various attributes of the
:class:`drgn.Module` class.

.. _debugging-information-finders-example:

Debugging Information Finders
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A callback for automatically finding debugging symbols for a set of modules can
be registered with :meth:`drgn.Program.register_debug_info_finder()`. Here is
an example for getting debugging symbols on Fedora Linux using DNF:

.. code-block:: python3

    import subprocess

    import drgn

    # Install debugging symbols using the DNF debuginfo-install plugin. Note that
    # this is mainly for demonstration purposes; debuginfod, which drgn supports
    # out of the box, is more reliable.
    def dnf_debug_info_finder(modules: list[drgn.Module]) -> None:
        # Determine all of the packages for the given modules.
        packages = set()
        for module in modules:
            if not module.wants_debug_file():
                continue

            if not module.name.startswith("/"):
                continue

            proc = subprocess.run(
                ["rpm", "--query", "--file", module.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            if proc.returncode == 0:
                packages.add(proc.stdout.rstrip("\n"))

        # Try installing their debug info.
        subprocess.call(
            ["sudo", "dnf", "debuginfo-install", "--skip-broken", "--"]
            + sorted(packages)
        )

        # Now that it's installed, try the standard locations. Other finders may
        # need to try specific files for specific modules with module.try_file()
        # instead.
        modules[0].prog.find_standard_debug_info(modules)


    prog.register_debug_info_finder("dnf", dnf_debug_info_finder, enable_index=-1)

Custom debugging information finders can even be configured automatically
through the :ref:`plugin system <writing-plugins>`.

.. _writing-plugins:

Writing Plugins
---------------

In order for drgn to load a plugin automatically, it must be registered as an
`entry point <https://packaging.python.org/specifications/entry-points/>`_ for
the ``drgn.plugins`` group. Here is a minimal example. First:

.. code-block:: console

    $ mkdir drgn_plugin_example
    $ cd drgn_plugin_example

Then, create ``pyproject.toml`` with the following contents:

.. code-block:: toml
    :caption: pyproject.toml
    :emphasize-lines: 5-6

    [project]
    name = 'drgn_plugin_example'
    version = '0.0.1'

    [project.entry-points.'drgn.plugins']
    example = 'drgn_plugin_example'

See the `Python Packaging User Guide
<https://packaging.python.org/guides/writing-pyproject-toml/>`_ for a complete
description of ``pyproject.toml``. We are most interested in the last two
lines, which define the entry point. In ``example = 'drgn_plugin_example'``,
``example`` is the plugin name, and ``drgn_plugin_example`` is the plugin
module.

Create ``drgn_plugin_example.py`` with the following contents:

.. code-block:: python3
    :caption: drgn_plugin_example.py

    import drgn

    def example_debug_info_finder(modules: list[drgn.Module]) -> None:
        for module in modules:
            if isinstance(module, drgn.MainModule):
                module.try_file("/my/vmlinux")

    def drgn_prog_set(prog: drgn.Program) -> None:
        if prog.flags & drgn.ProgramFlags.IS_LINUX_KERNEL:
            prog.register_debug_info_finder(
                "example", example_debug_info_finder, enable_index=-1
            )
    # Optional; the default is 50;
    drgn_prog_set.drgn_priority = 100

This is a typical usage of the :func:`drgn_prog_set()` hook to register
finders. See :ref:`plugins` for more details.

After creating the above files, the plugin can be installed with
``pip install .``.

Library
-------

In addition to the CLI, drgn is also available as a library.
:func:`drgn.program_from_core_dump()`, :func:`drgn.program_from_kernel()`, and
:func:`drgn.program_from_pid()` correspond to the :option:`-c`, :option:`-k`,
and :option:`-p` command line options, respectively; they return a
:class:`drgn.Program` that can be used just like the one initialized by the
CLI::

    >>> import drgn
    >>> prog = drgn.program_from_kernel()

C Library
---------

The core functionality of drgn is implemented in C and is available as a C
library, ``libdrgn``. See |drgn.h|_.

.. |drgn.h| replace:: ``drgn.h``
.. _drgn.h: https://github.com/osandov/drgn/blob/main/libdrgn/drgn.h

Full documentation can be generated by running ``doxygen`` in the ``libdrgn``
directory of the source code. Note that the API and ABI are not yet stable.

Custom Programs
---------------

The main components of a :class:`drgn.Program` are the program memory, types,
and objects. The CLI and equivalent library interfaces automatically determine
these. However, it is also possible to create a "blank" ``Program`` and plug in
the main components. The :func:`drgn.cli.run_interactive()` function allows you
to run the same drgn CLI once you've created a :class:`drgn.Program`, so it's
easy to make a custom program which allows interactive debugging.

:meth:`drgn.Program.add_memory_segment()` defines a range of memory and how to
read that memory. The following example uses a Btrfs filesystem image as the
program "memory":

.. code-block:: python3

    import os
    import sys

    import drgn
    from drgn.cli import run_interactive


    def btrfs_debugger(dev):
        file = open(dev, "rb")
        size = file.seek(0, 2)

        def read_file(address, count, offset, physical):
            file.seek(offset)
            return file.read(count)

        platform = drgn.Platform(
            drgn.Architecture.UNKNOWN, drgn.PlatformFlags.IS_LITTLE_ENDIAN
        )
        prog = drgn.Program(platform)
        prog.add_memory_segment(0, size, read_file)
        module = prog.extra_module("btrfs", create=True)
        module.try_file(f"/lib/modules/{os.uname().release}/kernel/fs/btrfs/btrfs.ko")
        return prog


    prog = btrfs_debugger(sys.argv[1] if len(sys.argv) >= 2 else "/dev/sda")
    print(drgn.Object(prog, "struct btrfs_super_block", address=65536))
    run_interactive(prog, banner_func=lambda _: "BTRFS debugger")

:meth:`drgn.Program.register_type_finder()` and
:meth:`drgn.Program.register_object_finder()` are the equivalent methods for
plugging in types and objects.

Environment Variables
---------------------

Some of drgn's behavior can be modified through environment variables:

.. envvar:: DRGN_DISABLE_PLUGINS

    Comma-separated list of plugins to disable. Each item is a glob pattern
    matching plugin entry point names.

.. envvar:: DRGN_PLUGINS

    Comma-separated list of plugins to enable. Each item is either a plugin
    entry point name, a file path, or a module name. Empty items are ignored.

    An item not containing ``=`` is interpreted as a plugin entry point name.
    This takes precedence over :envvar:`DRGN_DISABLE_PLUGINS`.

    An item containing ``=`` is interpreted as an extra plugin to load manually
    instead of via an entry point. The string before ``=`` is the plugin name.
    The string after ``=`` is the value. If the value contains a ``/``, it is
    the file path of a Python module. Otherwise, it is a module name.

    So, ``DRGN_DISABLE_PLUGINS=* DRGN_PLUGINS=foo,bar=/hello/world.py,baz=my.module``
    results in three plugins being loaded: the entry point ``foo``, the file
    ``/hello/world.py`` as ``bar``, and the module ``my.module`` as ``baz``.
    All other plugins are disabled.

.. envvar:: DRGN_MAX_DEBUG_INFO_ERRORS

    The maximum number of warnings about missing debugging information to log
    on CLI startup or from :meth:`drgn.Program.load_debug_info()`. Any
    additional errors are truncated. The default is 5; -1 is unlimited.

.. envvar:: DRGN_PREFER_ORC_UNWINDER

    Whether to prefer using `ORC
    <https://www.kernel.org/doc/html/latest/x86/orc-unwinder.html>`_ over DWARF
    for stack unwinding (0 or 1). The default is 0. Note that drgn will always
    fall back to ORC for functions lacking DWARF call frame information and
    vice versa. This environment variable is mainly intended for testing and
    may be ignored in the future.

.. envvar:: DRGN_USE_LIBKDUMPFILE_FOR_ELF

    Whether drgn should use libkdumpfile for ELF vmcores (0 or 1). The default
    is 0. This functionality will be removed in the future.

.. envvar:: DRGN_USE_SYS_MODULE

    Whether drgn should use ``/sys/module`` to find information about loaded
    kernel modules for the running kernel instead of getting them from the core
    dump (0 or 1). The default is 1. This environment variable is mainly
    intended for testing and may be ignored in the future.

.. envvar:: PYTHON_BASIC_REPL

    If non-empty, don't try to use the `new interactive REPL
    <https://docs.python.org/3/whatsnew/3.13.html#a-better-interactive-interpreter>`_
    added in Python 3.13. drgn makes use of the new REPL through internal
    implementation details since there is `not yet
    <https://github.com/python/cpython/issues/119512>`_ a public API for it. If
    it breaks, this may be used as an escape hatch.

.. _kernel-special-objects:

Linux Kernel Special Objects
----------------------------

When debugging the Linux kernel, there are some special :class:`drgn.Object`\ s
accessible with :meth:`drgn.Program.object()` and :meth:`drgn.Program[]
<drgn.Program.__getitem__>`. Some of these are available even without debugging
information, thanks to metadata called "vmcoreinfo" which is present in kernel
core dumps. These special objects include:

``UTS_RELEASE``
    Object type: ``const char []``

    This corresponds to the ``UTS_RELEASE`` macro in the Linux kernel source
    code. This is the exact kernel release (i.e., the output of ``uname -r``).

    To use this as a Python string, you must convert it::

        >>> release = prog["UTS_RELEASE"].string_().decode("ascii")

    This is available without debugging information.

``PAGE_SIZE``
    Object type: ``unsigned long``

``PAGE_SHIFT``
    Object type: ``unsigned int``

``PAGE_MASK``
    Object type: ``unsigned long``

    These correspond to the macros of the same name in the Linux kernel source
    code. The page size is the smallest contiguous unit of physical memory
    which can be allocated or mapped by the kernel.

    >>> prog['PAGE_SIZE']
    (unsigned long)4096
    >>> prog['PAGE_SHIFT']
    (int)12
    >>> prog['PAGE_MASK']
    (unsigned long)18446744073709547520
    >>> 1 << prog['PAGE_SHIFT'] == prog['PAGE_SIZE']
    True
    >>> ~(prog['PAGE_SIZE'] - 1) == prog['PAGE_MASK']
    True

    These are available without debugging information.

``jiffies``
    Object type: ``volatile unsigned long``

    This is a counter of timer ticks. It is actually an alias of ``jiffies_64``
    on 64-bit architectures, or the least significant 32 bits of ``jiffies_64``
    on 32-bit architectures. Since this alias is defined via the linker, drgn
    handles it specially.

    This is *not* available without debugging information.

``THREAD_SIZE``
    Object type: ``unsigned long``

    This corresponds to the macro of the same name in the Linux kernel source
    code. The thread size is the number of bytes used for kernel stacks. It's
    important to note that for many architectures, there may be additional
    stacks used when handling interrupts, excetpions, or faults. These may have
    a different, architecture-dependent size. ``THREAD_SIZE`` refers only to the
    kernel stacks associated with each task.

    This is *not* available without debugging information.

``vmemmap``
    Object type: ``struct page *``

    This is a pointer to the "virtual memory map", an array of ``struct page``
    for each physical page of memory. While the purpose and implementation
    details of this array are beyond the scope of this documentation, it is
    enough to say that it is represented in the kernel source in an
    architecture-dependent way, frequently as a macro or constant. The
    definition provided by drgn ensures that users can access it without
    resorting to architecture-specific logic.

    This is *not* available without debugging information.

``VMCOREINFO``
    Object type: ``const char []``

    This is the data contained in the vmcoreinfo note, which is present either
    as an ELF note in ``/proc/kcore`` or ELF vmcores, or as a special data
    section in kdump-formatted vmcores. The vmcoreinfo note contains critical
    data necessary for interpreting the kernel image, such as KASLR offsets and
    data structure locations.

    In the Linux kernel, this data is normally stored in a variable called
    ``vmcoreinfo_data``. However, drgn reads this information from ELF note or
    from the diskdump header. It is possible (in rare cases, usually with
    vmcores created by hypervisors) for a vmcore to contain vmcoreinfo which
    differs from the data in ``vmcoreinfo_data``, so it is important to
    distinguish the contents. For that reason, we use the name ``VMCOREINFO`` to
    distinguish it from the kernel variable ``vmcoreinfo_data``.

    This is available without debugging information.
