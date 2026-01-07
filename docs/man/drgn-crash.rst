drgn-crash
==========

.. highlight:: pycon

Synopsis
--------

| **drgn-crash** [*VMLINUX*] [*CORE*]

Description
-----------

:command:`drgn-crash` runs the drgn debugger in :manpage:`crash(8)`
compatibility mode.

In this mode, drgn imitates the UI of the :manpage:`crash(8)` command,
providing implementations of most of its commands. Additionally, the ``--drgn``
option can be given to any command to print example drgn code that does the
equivalent of the command.

The ``drgn`` command can be used to run snippets of drgn code::

    %crash> drgn stack_trace(1)[0]["next"].pid
    (pid_t)0

Or without arguments to enter drgn's usual interactive mode::

    %crash> drgn
    >>>

Documentation of all implemented commands is available online at
https://drgn.readthedocs.io/en/latest/crash_compatibility.html or in-program
with the ``help`` command.

Options
-------

.. program:: drgn-crash

.. option:: VMLINUX

    Path to kernel image (vmlinux). This corresponds to the :manpage:`crash(8)`
    ``NAMELIST`` argument. By default, drgn searches for this automatically.

    For more control over debugging symbols, use :option:`drgn -s` and related
    options of the main :command:`drgn` CLI and then enter crash compatibility
    mode with ``%crash`` instead.

.. option:: CORE

    Path to kernel core dump. This corresponds to the :manpage:`crash(8)`
    ``MEMORY-IMAGE`` argument. By default, this debugs the running kernel.
