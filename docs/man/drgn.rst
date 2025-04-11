drgn
====

Synopsis
--------

| **drgn** [*OPTION*...]
| **drgn** [*OPTION*...] *SCRIPT* [*ARGUMENT*...]
| **drgn** [*OPTION*...] **-e** *CODE* [*ARGUMENT*...]

Description
-----------

:command:`drgn` (pronounced "dragon") is a debugger with an emphasis on
programmability. It provides APIs for using the types, variables, and stack
traces in a program or core dump from Python, allowing for easy, expressive
scripting and more complex debugging.

Full documentation is available online at https://drgn.readthedocs.io/.

For in-program documentation, try ``help(drgn)``.

Options
-------

.. program:: drgn

If no positional arguments are given (and :option:`-e` is not given), then drgn
runs in *interactive mode*: commands are read from the terminal. Relevant
helpers are automatically imported. An empty string is prepended to
:py:data:`sys.path`.

If positional arguments are given (and :option:`-e` is not given), then drgn
runs in *script mode*: *SCRIPT* is executed with the given *ARGUMENT*\ s.
Nothing is imported automatically. :py:data:`sys.argv[0] <sys.argv>` is set to
*SCRIPT* and the remaining arguments are added to :py:data:`sys.argv`. The
parent directory of *SCRIPT* is prepended to :py:data:`sys.path`.

.. option:: -e {CODE}

    Evaluate the given code and exit. Relevant helpers are automatically
    imported. :py:data:`sys.argv[0] <sys.argv>` is set to *-e* and the
    remaining arguments are added to :py:data:`sys.argv`. An empty string is
    prepended to :py:data:`sys.path`.

Program Selection
^^^^^^^^^^^^^^^^^

One of these options may be given to specify what program to debug.

.. option:: -k, --kernel

    Debug the running kernel. This is the default.

.. option:: -c, --core {PATH}

    Debug the given core dump.

.. option:: -p, --pid {PID}

    Debug the running process with the given process ID.

Debugging Symbols
^^^^^^^^^^^^^^^^^

.. option:: -s, --symbols {PATH}

    Load debugging symbols from the given file. If the file does not correspond
    to a loaded executable, library, or module, then a warning is printed and
    it is ignored; see :option:`--extra-symbols` for an alternative.

    This option may be given more than once.

.. option:: --main-symbols

    Only load debugging symbols for the main executable and those added with
    :option:`-s` or :option:`--extra-symbols`.

.. option:: --no-default-symbols

    Don't load any debugging symbols that were not explicitly added with
    :option:`-s` or :option:`--extra-symbols`.

.. option:: --extra-symbols {PATH}

    Load additional debugging symbols from the given file, which is assumed not
    to correspond to a loaded executable, library, or module.

    This option may be given more than once.

The following options correspond to :py:attr:`drgn.Program.debug_info_options`
in the Python API.

.. option:: --try-symbols-by {METHOD[,METHOD...]}

    Enable loading debugging symbols using the given methods. *METHOD* may be:

    * The name of a debugging information finder (``standard``, ``debuginfod``,
      or any added by plugins).
    * ``module-name``: if the name of a module looks like a filesystem path, try the
      file at that path.
    * ``build-id``: search by build ID.
    * ``debug-link``: search by debug link (e.g., ``.gnu_debuglink``).
    * ``procfs``: try :file:`/proc/{pid}/exe` or :file:`/proc/{pid}/map_files`.
    * ``embedded-vdso``: try vDSO data saved in a core dump.
    * ``reuse``: try reusing a previously used file.
    * ``supplementary``: try finding supplementary files (e.g.,
      ``.gnu_debugaltlink``).
    * ``kmod=depmod``: search using *depmod* metadata.
    * ``kmod=walk``: search by walking kernel directories.
    * ``kmod=depmod-or-walk``: search using *depmod* metadata if it is
      available or by walking kernel directories if *depmod* metadata does not
      exist.
    * ``kmod=depmod-and-walk``: search using *depmod* metadata if it is
      available, then by walking kernel directories if *depmod* metadata does
      not exist or does not contain the desired module.

    Multiple methods may be enabled by passing a comma-separated list. This
    option may be given more than once, in which case the lists will be
    combined.

.. option:: --no-symbols-by {METHOD[,METHOD...]}

    Disable loading debugging symbols using the given methods. *METHOD* may be
    the name of a debugging information finder, ``module-name``, ``build-id``,
    ``debug-link``, ``procfs``, ``embedded-vdso``, ``reuse``,
    ``supplementary``, or ``kmod``.

    Multiple methods may be disabled by passing a comma-separated list. This
    option may be given more than once, in which case the lists will be
    combined.

.. option:: --debug-directory {PATH}

    Search for debugging symbols by build ID and debug link in the given
    directory.

    This option may be given more than once to search in multiple directories.

.. option:: --no-default-debug-directories

    Don't search for debugging symbols by build ID and debug link in the
    standard directories.

.. option:: --kernel-directory {PATH}

    Search for the kernel image and loadable kernel modules in the given
    directory.

    This option may be given more than once to search in multiple directories.

.. option:: --no-default-kernel-directories

    Don't search for the kernel image and loadable kernel modules in the
    standard directories.

Logging
^^^^^^^

.. option:: --log-level {\{debug,info,warning,error,critical,none\}}

    Log messages of at least the given level to standard error. The default is
    *warning*.

.. option:: -q, --quiet

    Don't print any logs or download progress. This is equivalent to
    :option:`--log-level none <--log-level>`.

Generic Information
^^^^^^^^^^^^^^^^^^^

.. option:: -h, --help

    Show a help message and exit.

.. option:: --version

    Show :command:`drgn`'s version information and exit.
