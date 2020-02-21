API Reference
=============

.. module:: drgn

Programs
--------

.. drgndoc:: Program
    :include: __getitem__
.. drgndoc:: ProgramFlags
.. drgndoc:: FindObjectFlags

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
    :include: __getattribute__|__getitem__|__len__
.. drgndoc:: NULL
.. drgndoc:: cast
.. drgndoc:: reinterpret
.. drgndoc:: container_of

Symbols
-------

.. drgndoc:: Symbol

Stack Traces
------------

Stack traces are retrieved with :meth:`Program.stack_trace()`.

.. drgndoc:: StackTrace
.. drgndoc:: StackFrame

.. _api-reference-types:

Types
-----

.. drgndoc:: Type
.. drgndoc:: TypeMember
.. drgndoc:: TypeEnumerator
.. drgndoc:: TypeParameter
.. drgndoc:: TypeKind
.. drgndoc:: PrimitiveType
.. drgndoc:: Qualifiers

.. _api-type-constructors:

Type Constructors
^^^^^^^^^^^^^^^^^

Custom drgn types can be created with the following factory functions. These
can be used just like types obtained from :meth:`Program.type()`.

.. drgndoc:: void_type
.. drgndoc:: int_type
.. drgndoc:: bool_type
.. drgndoc:: float_type
.. drgndoc:: complex_type
.. drgndoc:: struct_type
.. drgndoc:: union_type
.. drgndoc:: class_type
.. drgndoc:: enum_type
.. drgndoc:: typedef_type
.. drgndoc:: pointer_type
.. drgndoc:: array_type
.. drgndoc:: function_type

Miscellaneous
-------------

.. drgndoc:: sizeof
.. drgndoc:: execscript

Exceptions
----------

.. drgndoc:: FaultError
.. drgndoc:: MissingDebugInfoError
.. drgndoc:: OutOfBoundsError
