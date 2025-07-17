API Reference
=============

.. module:: drgn

Programs
--------

.. drgndoc:: Program
    :exclude: (void|int|bool|float|struct|union|class|enum|typedef|pointer|array|function)_type|(main|shared_library|vdso|relocatable|linux_kernel_loadable|extra)_module
.. drgndoc:: ProgramFlags
.. drgndoc:: FindObjectFlags
.. drgndoc:: ObjectNotFoundError

.. drgndoc:: DebugInfoOptions
.. drgndoc:: KmodSearchMethod

.. drgndoc:: Thread

.. _api-filenames:

Filenames
^^^^^^^^^

The :meth:`Program.type()`, :meth:`Program.object()`,
:meth:`Program.variable()`, :meth:`Program.constant()`, and
:meth:`Program.function()` methods all take a *filename* parameter to
distinguish between multiple definitions with the same name. The filename
refers to the source code file that contains the definition. It is matched with
:func:`filename_matches()`. If multiple definitions match, one is returned
arbitrarily.

.. drgndoc:: filename_matches

.. _api-program-constructors:

Program Constructors
^^^^^^^^^^^^^^^^^^^^

The drgn command line interface automatically creates a :class:`Program` named
``prog``. However, drgn may also be used as a library without the CLI, in which
case a ``Program`` must be created manually.

.. drgndoc:: program_from_core_dump
.. drgndoc:: program_from_kernel
.. drgndoc:: program_from_pid

.. _default-program:

Default Program
^^^^^^^^^^^^^^^

Most functions that take a :class:`Program` can be called without the *prog*
argument. In that case, the *default program argument* is used, which is
determined by the rules below.

.. note::

    In the drgn CLI, you probably don't need to care about these details.
    Simply omit *prog*:

    .. code-block:: python3

        # Equivalent in the CLI.
        find_task(pid)
        find_task(prog, pid)
        find_task(prog["init_pid_ns"].address_of_(), pid)

1. If *prog* is given explicitly, either as a positional or keyword argument,
   then it is used.
2. Otherwise, if the first argument is an :class:`Object`, then
   :attr:`Object.prog_` is used.
3. Otherwise, the *default program* is used.

The default program is set automatically in the CLI. Library users can get and
set it manually. The default program is a per-thread setting. See `Thread
Safety`_.

.. drgndoc:: get_default_prog
.. drgndoc:: set_default_prog
.. drgndoc:: NoDefaultProgramError

For helpers, it is recommended to use the decorators from the
:mod:`drgn.helpers.common.prog` module instead.

Platforms
^^^^^^^^^

.. drgndoc:: Platform
.. drgndoc:: Architecture
.. drgndoc:: PlatformFlags
.. drgndoc:: Register
.. drgndoc:: host_platform

Languages
^^^^^^^^^

.. drgndoc:: Language

Objects
-------

.. drgndoc:: Object
.. drgndoc:: AbsenceReason
.. drgndoc:: NULL
.. drgndoc:: cast
.. drgndoc:: implicit_convert
.. drgndoc:: reinterpret
.. drgndoc:: container_of

Symbols
-------

.. drgndoc:: Symbol
.. drgndoc:: SymbolBinding
.. drgndoc:: SymbolKind
.. drgndoc:: SymbolIndex

Stack Traces
------------

Stack traces are retrieved with :func:`stack_trace()`,
:meth:`Program.stack_trace()`, or :meth:`Thread.stack_trace()`.

.. drgndoc:: stack_trace
.. drgndoc:: StackTrace
.. drgndoc:: StackFrame

.. _api-reference-types:

Types
-----

.. drgndoc:: Type
.. drgndoc:: TypeMember
.. drgndoc:: TypeEnumerator
.. drgndoc:: TypeParameter
.. drgndoc:: TypeTemplateParameter
.. drgndoc:: TypeKind
.. drgndoc:: TypeKindSet
.. drgndoc:: PrimitiveType
.. drgndoc:: Qualifiers
.. drgndoc:: alignof
.. drgndoc:: offsetof

.. _api-type-constructors:

Type Constructors
^^^^^^^^^^^^^^^^^

Custom drgn types can be created with the following factory functions. These
can be used just like types obtained from :meth:`Program.type()`.

.. drgndoc:: Program.void_type
.. drgndoc:: Program.int_type
.. drgndoc:: Program.bool_type
.. drgndoc:: Program.float_type
.. drgndoc:: Program.struct_type
.. drgndoc:: Program.union_type
.. drgndoc:: Program.class_type
.. drgndoc:: Program.enum_type
.. drgndoc:: Program.typedef_type
.. drgndoc:: Program.pointer_type
.. drgndoc:: Program.array_type
.. drgndoc:: Program.function_type

Modules
-------

.. drgndoc:: Module
.. drgndoc:: MainModule
.. drgndoc:: SharedLibraryModule
.. drgndoc:: VdsoModule
.. drgndoc:: RelocatableModule
.. drgndoc:: ExtraModule
.. drgndoc:: ModuleFileStatus
.. drgndoc:: WantedSupplementaryFile
.. drgndoc:: SupplementaryFileKind

.. _api-module-constructors:

Module Lookups/Constructors
^^^^^^^^^^^^^^^^^^^^^^^^^^^

For each module type, there is a corresponding method to create a module of
that type or find one that was previously created::

    >>> prog.extra_module("foo", 1234)
    Traceback (most recent call last):
      ...
    LookupError: module not found
    >>> prog.extra_module("foo", 1234, create=True)
    prog.extra_module(name='foo', id=0x4d2)
    >>> prog.extra_module("foo", 1234)
    prog.extra_module(name='foo', id=0x4d2)

.. drgndoc:: Program.main_module
.. drgndoc:: Program.shared_library_module
.. drgndoc:: Program.vdso_module
.. drgndoc:: Program.relocatable_module
.. drgndoc:: Program.linux_kernel_loadable_module
.. drgndoc:: Program.extra_module

Miscellaneous
-------------

.. drgndoc:: sizeof
.. drgndoc:: execscript
.. drgndoc:: IntegerLike
.. drgndoc:: Path

Exceptions
----------

.. drgndoc:: FaultError
.. drgndoc:: MissingDebugInfoError
.. drgndoc:: ObjectAbsentError
.. drgndoc:: OutOfBoundsError

CLI
---

.. drgndoc:: cli

.. _api-commands:

Commands
--------

.. drgndoc:: commands

.. _plugins:

Plugins
-------

drgn can be extended with plugins. A drgn plugin is a Python module defining
one or more hook functions that are called at specific times. Plugins can also
register :ref:`commands <api-commands>`.

By default, drgn loads installed modules registered as :ref:`entry points
<writing-plugins>` for the ``drgn.plugins`` group. The :envvar:`DRGN_PLUGINS`
and :envvar:`DRGN_DISABLE_PLUGINS` environment variables can be used to
configure this.

The following hooks are currently defined:

.. py:currentmodule:: None

.. function:: drgn_prog_set(prog: drgn.Program) -> None

    Called after the program target has been set (e.g., one of
    :meth:`drgn.Program.set_core_dump()`, :meth:`drgn.Program.set_kernel()`, or
    :meth:`drgn.Program.set_pid()` has been called).

A ``drgn_priority`` integer attribute can be assigned to a hook function to
define when it is called relative to other plugins. Hook functions with lower
``drgn_priority`` values are called earlier. Functions with equal
``drgn_priority`` values are called in an unspecified order. The default if not
defined is 50.

See :ref:`writing-plugins` for an example.

Logging
-------

drgn logs using the standard :mod:`logging` module to a logger named
``"drgn"``.

drgn will also display progress bars on standard error if standard error is a
terminal, the ``"drgn"`` logger has a :class:`~logging.StreamHandler` for
``stderr``, and its log level is less than or equal to ``WARNING``.

Thread Safety
-------------

Only one thread at a time should access the same :class:`Program` (including
:class:`Object`, :class:`Type`, :class:`StackTrace`, etc. from that program).
It is safe to use different :class:`Program`\ s from concurrent threads.
