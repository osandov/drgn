Commands
========

TODO: more background

In the drgn CLI, commands are accessed by starting a line with the ``%``
character.

Many commands provide a ``--drgn`` option instructing them to print example
drgn code that does the equivalent of the command. This can be used as a
template for doing something more advanced than the command supports. It is
also useful for learning about drgn helpers and APIs.

TODO: mention not in script mode, run_command, how to add commands

Syntax
------

.. highlight:: pycon

Most commands use `shell syntax
<https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html>`_
(words split on whitespace unless quoted or escaped, etc.) and command-line
options::

>>> %TODO --example 'foo bar'

Redirecting standard input, standard output, and standard error is supported::

>>> %TODO > file
>>> %TODO >> file
>>> %TODO 2> err
>>> %TODO < file

The output of a command can also be piped to an external command::

>>> %TODO | grep foo | sort -r

Word expansions (including variable expansions, wildcards, etc.) are only
supported in external commands (i.e., after the ``|`` in a pipeline).

A few commands, like :drgncommand:`let`, have their own syntax. These commands
do not support redirection or pipes.

Common
------

The following commands are available when debugging any program.

.. drgndoc-command-namespace::

Linux Kernel
------------

The following commands are available when debugging the Linux kernel.

.. drgndoc-command-namespace::
    :enabled: linux
