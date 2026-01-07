Crash Compatibility
===================

.. highlight:: pycon

drgn provides a compatibility mode emulating the `crash utility
<https://crash-utility.github.io/>`_. Many commands have been ported from
crash. Output is not byte-identical, but it generally closely resembles crash
output.

These commands can be run directly from the drgn CLI as subcommands of the
:drgncommand:`crash` command::

    >>> %crash sys
    KERNEL: ...

Crash commands take an additional ``--drgn`` option instructing them to print
example drgn code that does the equivalent of the command. This is useful for
learning about drgn helpers and APIs. It can also be used to generate a
template for doing something more advanced than the command supports. You can
copy and paste the output or even write it to a file and edit it before running
it:

.. code-block:: pycon
    :force:

    >>> %crash mount --drgn > mount.py
    >>> %sh $EDITOR mount.py
    >>> %source mount.py

Interactive Crash Prompt
------------------------

Calling the :drgncommand:`crash` command with no arguments enters an
interactive prompt where crash commands can be called directly::

    >>> %crash
    %crash> sys
    KERNEL: ...
    %crash>

drgn code can be executed from the interactive crash prompt with the
:drgncommand:`drgn <crash.drgn>` command::

    %crash> drgn stack_trace(1)[0]["next"].pid
    (pid_t)0

Calling the :drgncommand:`drgn <crash.drgn>` command with no arguments returns
to the drgn CLI::

    %crash> drgn
    >>>

The interactive prompt can also be entered directly from a shell with the
:doc:`drgn-crash <man/drgn-crash>` script:

.. code-block:: console

    $ drgn-crash
    KERNEL: ...
    %crash>

Commands
--------

.. drgndoc-command-namespace:: crash
