Commands
========

.. highlight:: pycon

drgn's programmatic interface excels at complex analysis. For simpler tasks, it
can be more convenient to use pre-defined commands. drgn provides a set of
commands for this purpose.

In interactive mode, commands are accessed by starting a line with the ``%``
character.

In script mode, commands can be run with :func:`drgn.commands.run_command()`.

Plugins and scripts can also register additional commands. See the
:ref:`commands API <api-commands>`.

Syntax
------

Most commands use `shell syntax
<https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html>`_
(words split on whitespace unless quoted or escaped, etc.) and command-line
options::

>>> %example --foo 'hello world'

Redirecting standard input, standard output, and standard error is supported::

>>> %example > file
>>> %example >> file
>>> %example 2> err
>>> %example < file

The output of a command can also be piped to an external command::

>>> %example | grep foo | sort -r

Word expansions (including variable expansions, wildcards, etc.) are only
supported in external commands (i.e., after the ``|`` in a pipeline).

A few commands have their own syntax. These commands do not support redirection
or pipes.

Common
------

The following commands are available when debugging any program.

.. drgndoc-command-namespace::

Linux Kernel
------------

The following commands are available when debugging the Linux kernel.

.. drgndoc-command-namespace::
    :enabled: linux
