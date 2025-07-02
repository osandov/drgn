Crash Compatibility
===================

.. highlight:: pycon

drgn provides a compatibility mode emulating the `crash utility
<https://crash-utility.github.io/>`_. Many commands have been ported from
crash. These commands can be run directly from the drgn CLI as subcommands of
the :drgncommand:`crash` command::

    >>> %crash sys
    KERNEL: ...

Calling the :drgncommand:`crash` command with no arguments enters an
interactive prompt where crash commands can be called directly::

    >>> %crash
    %crash> sys
    KERNEL: ...
    %crash>

Most of these commands have an additional ``--drgn`` option instructing them to
print example drgn code that does the equivalent of the command. This is useful
for learning about drgn helpers and APIs. It can also be used to generate a
template for doing something more advanced than the command supports. You can
copy and paste the output or even write it to a file and edit it before running
it:

.. code-block:: pycon
    :force:

    >>> %crash mount --drgn > mount.py
    >>> %sh $EDITOR mount.py
    >>> %source mount.py

Commands
--------

.. drgndoc-command-namespace:: crash
