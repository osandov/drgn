API Reference
=============

.. module:: drgn

Programs
--------

.. drgndoc:: Program
    :exclude: (void|int|bool|float|struct|union|class|enum|typedef|pointer|array|function)_type
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
.. drgndoc:: NULL
.. drgndoc:: cast
.. drgndoc:: reinterpret
.. drgndoc:: container_of

Symbols
-------

.. drgndoc:: Symbol
.. drgndoc:: SymbolBinding
.. drgndoc:: SymbolKind

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
.. drgndoc:: TypeTemplateParameter
.. drgndoc:: TypeKind
.. drgndoc:: PrimitiveType
.. drgndoc:: Qualifiers
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
