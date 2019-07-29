API Reference
=============

.. module:: drgn

Programs
--------

.. class:: Program(platform=None)

    A ``Program`` represents a crashed or running program. It can be used to
    lookup type definitions, access variables, and read arbitrary memory.

    The main functionality of a ``Program`` is looking up objects (i.e.,
    variables, constants, or functions). This is usually done with the
    :meth:`[] <__getitem__>` operator.

    This class can be constructed directly, but it is usually more convenient
    to use one of the :ref:`api-program-constructors`.

    :param platform: The platform of the program, or ``None`` if it should be
        determined automatically when a core dump or symbol file is added.
    :type platform: Platform or None

    .. attribute:: flags

        Flags which apply to this program.

        :vartype: ProgramFlags

    .. attribute:: platform

        Platform that this program runs on, or ``None`` if it has not been
        determined yet.

        :vartype: Platform or None

    .. method:: __getitem__(name)

        Implement ``self[name]``. Get the object (variable, constant, or
        function) with the given name.

        This is equivalent to ``prog.object(name)`` except that this raises
        :exc:`KeyError` instead of :exc:`LookupError` if no objects with the
        given name are found.

        If there are multiple objects with the same name, one is returned
        arbitrarily. In this case, the :meth:`variable()`, :meth:`constant()`,
        :meth:`function()`, or :meth:`object()` methods can be used instead.

        >>> prog['jiffies']
        Object(prog, 'volatile unsigned long', address=0xffffffff94c05000)

        :param str name: The object name.
        :rtype: Object

    .. method:: variable(name, filename=None)

        Get the variable with the given name.

        >>> prog.variable('jiffies')
        Object(prog, 'volatile unsigned long', address=0xffffffff94c05000)

        This is equivalent to ``prog.object(name, FindObjectFlags.VARIABLE,
        filename)``.

        :param str name: The variable name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :type filename: str or None
        :rtype: Object
        :raises LookupError: if no variables with the given name are found in
            the given file

    .. method:: constant(name, filename=None)

        Get the constant (e.g., enumeration constant) with the given name.

        Note that support for macro constants is not yet implemented for DWARF
        files, and most compilers don't generate macro debugging information
        by default anyways.

        >>> prog.constant('PIDTYPE_MAX')
        Object(prog, 'enum pid_type', value=4)

        This is equivalent to ``prog.object(name, FindObjectFlags.CONSTANT,
        filename)``.

        :param str name: The constant name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :type filename: str or None
        :rtype: Object
        :raises LookupError: if no constants with the given name are found in
            the given file

    .. method:: function(name, filename=None)

        Get the function with the given name.

        >>> prog.function('schedule')
        Object(prog, 'void (void)', address=0xffffffff94392370)

        This is equivalent to ``prog.object(name, FindObjectFlags.FUNCTION,
        filename)``.

        :param str name: The function name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :type filename: str or None
        :rtype: Object
        :raises LookupError: if no functions with the given name are found in
            the given file

    .. method:: object(name, flags=None, filename=None)

        Get the object (variable, constant, or function) with the given name.

        :param str name: The object name.
        :param flags: Flags indicating what kind of object to look for. If this
            is ``None`` or not given, it defaults to
            :attr:`FindObjectFlags.ANY`.
        :type flags: FindObjectFlags or None
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :type filename: str or None
        :rtype: Object
        :raises LookupError: if no objects with the given name are found in
            the given file

    .. method:: symbol(address)

        Get the symbol containing the given address.

        :param int address: The address.
        :rtype: Symbol
        :raises LookupError: if no symbol contains the given address

    .. method:: type(name, filename=None)

        Get the type with the given name.

        >>> prog.type('long')
        int_type(name='long', size=8, is_signed=True)

        :param str name: The type name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :type filename: str or None
        :rtype: Type
        :raises LookupError: if no types with the given name are found in
            the given file

    .. method:: pointer_type(type, qualifiers=None)

        Create a pointer type which points to the given type.

        :param type: The referenced type.
        :type type: str or Type
        :param qualifiers: :attr:`Type.qualifiers`
        :type qualifiers: Qualifiers or None
        :rtype: Type

    .. method:: read(address, size, physical=False)

        Read *size* bytes of memory starting at *address* in the program. The
        address may be virtual (the default) or physical if the program
        supports it.

        >>> prog.read(0xffffffffbe012b40, 16)
        b'swapper/0\x00\x00\x00\x00\x00\x00\x00'

        :param int address: The starting address.
        :param int size: The number of bytes to read.
        :param bool physical: Whether *address* is a physical memory address.
            If ``False``, then it is a virtual memory address. Physical memory
            can usually only be read when the program is an operating system
            kernel.
        :rtype: bytes
        :raises FaultError: if the address range is invalid or the type of
            address (physical or virtual) is not supported by the program
        :raises ValueError: if *size* is negative

    .. method:: add_memory_segment(address, size, read_fn, physical=False)

        Define a region of memory in the program.

        If it overlaps a previously registered segment, the new segment takes
        precedence.

        :param int address: Address of the segment.
        :param int size: Size of the segment in bytes.
        :param bool physical: Whether to add a physical memory segment. If
            ``False``, then this adds a virtual memory segment.
        :param read_fn: Callable to call to read memory from the segment. It is
            passed the address being read from, the number of bytes to read,
            the offset in bytes from the beginning of the segment, and whether
            the address is physical: ``(address, count, offset, physical)``. It
            should return the requested number of bytes as :class:`bytes` or
            another :ref:`buffer <python:binaryseq>` type.

    .. method:: add_type_finder(fn)

        Register a callback for finding types in the program.

        Callbacks are called in reverse order of the order they were added
        until the type is found. So, more recently added callbacks take
        precedence.

        :param fn: Callable taking a :class:`TypeKind`, name (:class:`str`),
            and filename (:class:`str` or ``None``): ``(kind, name,
            filename)``. The filename should be matched with
            :func:`filename_matches()`. This should return a :class:`Type`.

    .. method:: add_object_finder(fn)

        Register a callback for finding objects in the program.

        Callbacks are called in reverse order of the order they were added
        until the object is found. So, more recently added callbacks take
        precedence.

        :param fn: Callable taking a program (:class:`Program`), name
            (:class:`str`), :class:`FindObjectFlags`, and filename
            (:class:`str` or ``None``): ``(prog, name, flags, filename)``. The
            filename should be matched with :func:`filename_matches()`. This
            should return an :class:`Object`.

    .. method:: set_core_dump(path)

        Set the program to a core dump.

        This loads the memory segments from the core dump and determines the
        mapped executable and libraries. It does not load any debugging
        symbols; see :meth:`load_default_debug_info()`.

        :param str path: Core dump file path.

    .. method:: set_kernel()

        Set the program to the running operating system kernel.

        This loads the memory of the running kernel and thus requires root
        privileges. It does not load any debugging symbols; see
        :meth:`load_default_debug_info()`.

    .. method:: set_pid(pid)

        Set the program to a running process.

        This loads the memory of the process and determines the mapped
        executable and libraries. It does not load any debugging symbols; see
        :meth:`load_default_debug_info()`.

        :param int pid: Process ID.

    .. method:: load_debug_info(paths)

        Load debugging information for a list of executable or library files.

        If an error is encountered while loading any file, no new debugging
        information is loaded.

        Note that this is parallelized, so it is usually faster to load
        multiple files at once rather than one by one.

        :param paths: Paths of binary files.
        :type paths: Iterable[str, bytes, or os.PathLike]

    .. method:: load_default_debug_info()

        Load debugging information which can automatically be determined from
        the program.

        For the Linux kernel, this tries to load ``vmlinux`` and any loaded
        kernel modules from a few standard locations.

        For userspace programs, this tries to load the executable and any
        loaded libraries.

        :raises MissingDebugInfoError: if debugging information was not
            available for some files; other files with debugging information
            are still loaded if this is raised

    .. attribute:: cache

        Dictionary for caching program metadata.

        This isn't used by drgn itself. It is intended to be used by helpers to
        cache metadata about the program. For example, if a helper for a
        program depends on the program version or an optional feature, the
        helper can detect it and cache it for subsequent invocations:

        .. code-block:: python3

            def my_helper(prog):
                try:
                    have_foo = prog.cache['have_foo']
                except KeyError:
                    have_foo = detect_foo_feature(prog)
                    prog.cache['have_foo'] = have_foo
                if have_foo:
                    return prog['foo']
                else:
                    return prog['bar']

        :vartype: dict

.. class:: ProgramFlags

    ``ProgramFlags`` is an :class:`enum.Flag` of flags that can apply to a
    :class:`Program` (e.g., about what kind of program it is).

    .. attribute:: IS_LINUX_KERNEL

        The program is the Linux kernel.

    .. attribute:: IS_LIVE

        The program is currently running (e.g., it is the running operating
        system kernel or a running process).

.. class:: FindObjectFlags

    ``FindObjectFlags`` is an :class:`enum.Flag` of flags for
    :meth:`Program.object()`. These can be combined to search for multiple
    kinds of objects at once.

    .. attribute:: CONSTANT

    .. attribute:: FUNCTION

    .. attribute:: VARIABLE

    .. attribute:: ANY

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

.. function:: filename_matches(haystack, needle)

    Return whether a filename containing a definition (*haystack*) matches a
    filename being searched for (*needle*).

    The filename is matched from right to left, so ``'stdio.h'``,
    ``'include/stdio.h'``, ``'usr/include/stdio.h'``, and
    ``'/usr/include/stdio.h'`` would all match a definition in
    ``/usr/include/stdio.h``. If *needle* is ``None`` or empty, it matches any
    definition. If *haystack* is ``None`` or empty, it only matches if *needle*
    is also ``None`` or empty.

    :param haystack: Path of file containing definition.
    :type haystack: str or None
    :param needle: Filename to match.
    :type needle: str or None

.. _api-program-constructors:

Program Constructors
^^^^^^^^^^^^^^^^^^^^

The drgn command line interface automatically creates a :class:`Program` named
``prog``. However, drgn may also be used as a library without the CLI, in which
case a ``Program`` must be created manually.

.. function:: program_from_core_dump(path)

    Create a :class:`Program` from a core dump file. The type of program (e.g.,
    userspace or kernel) is determined automatically.

    :param str path: Core dump file path.
    :rtype: Program

.. function:: program_from_kernel()

    Create a :class:`Program` from the running operating system kernel. This
    requires root privileges.

    :rtype: Program

.. function:: program_from_pid(pid)

    Create a :class:`Program` from a running program with the given PID. This
    requires appropriate permissions (on Linux, :manpage:`ptrace(2)` attach
    permissions).

    :param int pid: Process ID of the program to debug.
    :rtype: Program

Platforms
^^^^^^^^^

.. class:: Platform(arch, flags=None)

    A ``Platform`` represents the environment (i.e., architecture and ABI) that
    a program runs on.

    :param Architecture arch: :attr:`Platform.arch`
    :param flags: :attr:`Platform.flags`; if ``None``, default flags for the
        architecture are used.
    :type flags: PlatformFlags or None

    .. attribute:: arch

        The instruction set architecture of this platform.

        :vartype: Architecture

    .. attribute:: flags

        Flags which apply to this platform.

        :vartype: PlatformFlags

.. class:: Architecture

    ``Architecture`` is an :class:`enum.Enum` of instruction set architectures.

    .. attribute:: X86_64

        The x86-64 architecture, a.k.a. AMD64.

    .. attribute:: UNKNOWN

        An architecture which is not known to drgn. Certain features are not
        available when the architecture is unknown, but most of drgn will still
        work.

.. class:: PlatformFlags

    ``PlatformFlags`` is an :class:`enum.Flag` of flags describing a
    :class:`Platform`.

    .. attribute:: IS_64_BIT

        Platform is 64-bit.

    .. attribute:: IS_LITTLE_ENDIAN

        Platform is little-endian.

.. attribute:: host_platform

    The platform of the host which is running drgn.

    :vartype: Platform

Objects
-------

.. class:: Object(prog, type=None, *, address=None, value=None, byteorder=None, bit_offset=None, bit_field_size=None)

    An ``Object`` represents a symbol or value in a program. An object may
    exist in the memory of the program (a *reference*), or it may be a
    temporary computed value (a *value*).

    All instances of this class have two attributes: :attr:`prog_`, the program
    that the object is from; and :attr:`type_`, the type of the object.
    Reference objects also have an :attr:`address_` attribute. Objects may also
    have a :attr:`byteorder_`, :attr:`bit_offset_`, and
    :attr:`bit_field_size_`.

    :func:`repr()` of an object returns a Python representation of the object:

    >>> print(repr(prog['jiffies']))
    Object(prog, 'volatile long unsigned int', address=0xffffffffbf005000)

    :class:`str() <str>` returns a representation of the object in programming
    language syntax:

    >>> print(prog['jiffies'])
    (volatile long unsigned int)4326237045

    Note that the drgn CLI is set up so that objects are displayed with
    ``str()`` instead of ``repr()`` (the latter is the default behavior of
    Python's interactive mode). This means that in the drgn CLI, the call to
    ``print()`` in the second example above is not necessary.

    Objects support the following operators:

    * Arithmetic operators: ``+``, ``-``, ``*``, ``/``, ``%``
    * Bitwise operators: ``<<``, ``>>``, ``&``, ``|``, ``^``, ``~``
    * Relational operators: ``==``, ``!=``, ``<``, ``>``, ``<=``, ``>=``
    * Subscripting: :meth:`[] <__getitem__>` (Python does not have a unary
      ``*`` operator, so pointers are dereferenced with ``ptr[0]``)
    * Member access: :meth:`. <__getattribute__>` (Python does not have a
      ``->`` operator, so ``.`` is also used to access members of pointers to
      structures)
    * The address-of operator: :meth:`drgn.Object.address_of_()` (this is a
      method because Python does not have a ``&`` operator)
    * Array length: :meth:`len() <__len__>`

    These operators all have the semantics of the program's programming
    language. For example, adding two objects from a program written in C
    results in an object with a type and value according to the rules of C:

    >>> Object(prog, 'unsigned long', value=2**64 - 1) + Object(prog, 'int', value=1)
    Object(prog, 'unsigned long', value=0)

    If only one operand to a binary operator is an object, the other operand
    will be converted to an object according to the language's rules for
    literals:

    >>> Object(prog, 'char', value=0) - 1
    Object(prog, 'int', value=-1)

    The standard :class:`int() <int>`, :class:`float() <float>`, and
    :class:`bool() <bool>` functions convert an object to that Python type.
    Conversion to ``bool`` uses the programming language's notion of
    "truthiness". Additionally, certain Python functions will automatically
    coerce an object to the appropriate Python type (e.g., :func:`hex()`,
    :func:`round()`, and :meth:`list subscripting <object.__getitem__>`).

    Object attributes and methods are named with a trailing underscore to avoid
    conflicting with structure or union members. The attributes and methods
    always take precedence; use :meth:`member_()` if there is a conflict.

    Objects are usually obtained directly from a :class:`Program`, but they can
    be constructed manually, as well (for example, if you got a variable
    address from a log file).

    :param Program prog: The program to create this object in.
    :param type: The type of the object. If omitted, this is deduced from
        *value* according to the language's rules for literals.
    :type type: str or Type
    :param int address: The address of this object in the program. Either this
        or *value* must be given, but not both.
    :param value: The value of this object. See :meth:`value_()`.
    :param byteorder: Byte order of the object. This should be ``'little'`` or
        ``'big'``. The default is ``None``, which indicates the program byte
        order. This must be ``None`` for primitive values.
    :type byteorder: str or None
    :param bit_offset: Offset in bits from the object's address to the
        beginning of the object. The default is ``None``, which means no
        offset. This must be ``None`` for primitive values.
    :type bit_offset: int or None
    :param bit_field_size: Size in bits of this object if it is a bit field.
        The default is ``None``, which means the object is not a bit field.
    :type bit_field_size: int or None

    .. attribute:: prog_

        Program that this object is from.

        :vartype: Program

    .. attribute:: type_

        Type of this object.

        :vartype: Type

    .. attribute:: address_

        Address of this object if it is a reference, ``None`` if it is a value.

        :vartype: int or None

    .. attribute:: byteorder_

        Byte order of this object (either ``'little'`` or ``'big'``) if it is a
        reference or a non-primitive value, ``None`` otherwise.

        :vartype: str or None

    .. attribute:: bit_offset_

        Offset in bits from this object's address to the beginning of the
        object if it is a reference or a non-primitive value, ``None``
        otherwise.

        :vartype: int or None

    .. attribute:: bit_field_size_

        Size in bits of this object if it is a bit field, ``None`` if it is
        not.

        :vartype: int or None

    .. method:: __getattribute__(name)

        Implement ``self.name``.

        If *name* is an attribute of the :class:`Object` class, then this
        returns that attribute. Otherwise, it is equivalent to
        :meth:`member_()`.

        >>> print(prog['init_task'].pid)
        (pid_t)0

        :param str name: Attribute name.

    .. method:: __getitem__(idx)

        Implement ``self[idx]``. Get the array element at the given index.

        >>> print(prog['init_task'].comm[0])
        (char)115

        This is only valid for pointers and arrays.

        :param int idx: The array index.
        :rtype: Object
        :raises TypeError: if this object is not a pointer or array

    .. method:: __len__()

        Implement ``len(self)``. Get the number of elements in this object.

        >>> len(prog['init_task'].comm)
        16

        This is only valid for arrays.

        :rtype: int
        :raises TypeError: if this object is not an array with complete type

    .. method:: value_()

        Get the value of this object as a Python object.

        For basic types (integer, floating-point, boolean), this returns an
        object of the directly corresponding Python type (``int``, ``float``,
        ``bool``). For pointers, this returns the address value of the pointer.
        For enums, this returns an ``int``. For structures and unions, this
        returns a ``dict`` of members. For arrays, this returns a ``list`` of
        values.

        :raises FaultError: if reading the object causes a bad memory access
        :raises TypeError: if this object has an unreadable type (e.g.,
            ``void``)

    .. method:: string_()

        Read a null-terminated string pointed to by this object.

        This is only valid for pointers and arrays. The element type is
        ignored; this operates byte-by-byte.

        For pointers and flexible arrays, this stops at the first null byte.

        For complete arrays, this stops at the first null byte or at the end of
        the array.

        :rtype: bytes
        :raises FaultError: if reading the string causes a bad memory access
        :raises TypeError: if this object is not a pointer or array

    .. method:: member_(name)

        Get a member of this object.

        This is valid for structures, unions, and pointers to either.

        Normally the dot operator (``.``) can be used to accomplish the same
        thing, but this method can be used if there is a name conflict with an
        Object member or method.

        :param str name: Name of the member.
        :rtype: Object
        :raises TypeError: if this object is not a structure, union, or a
            pointer to either
        :raises LookupError: if this object does not have a member with the
            given name

    .. method:: address_of_()

        Get a pointer to this object.

        This corresponds to the address-of (``&``) operator in C. It is only
        possible for reference objects, as value objects don't have an address
        in the program.

        As opposed to :attr:`address_`, this returns an ``Object``, not an
        ``int``.

        :rtype: Object
        :raises ValueError: if this object is a value

    .. method:: read_()

        Read this object (which may be a reference or a value) and return it as
        a value object.

        This is useful if the object can change in the running program (but of
        course nothing stops the program from modifying the object while it is
        being read).

        As opposed to :meth:`value_()`, this returns an ``Object``, not a
        standard Python type.

        :rtype: Object
        :raises FaultError: if reading this object causes a bad memory access
        :raises TypeError: if this object has an unreadable type (e.g.,
            ``void``)

.. function:: NULL(prog, type)

    Get an object representing ``NULL`` casted to the given type.

    This is equivalent to ``Object(prog, type, value=0)``.

    :param Program prog: The program.
    :param type: The type.
    :type type: str or Type
    :rtype: Object

.. function:: cast(type, obj)

    Get the value of the given object casted to another type.

    Objects with a scalar type (integer, boolean, enumerated, floating-point,
    or pointer) can be casted to a different scalar type. Other objects can
    only be casted to the same type. This always results in a value object. See
    also :func:`drgn.reinterpret()`.

    :param type: The type to cast to.
    :type type: str or Type
    :param Object obj: The object to cast.
    :rtype: Object

.. function:: reinterpret(type, obj, byteorder=None)

    Get a copy of the given object reinterpreted as another type and/or byte
    order.

    This reinterprets the raw memory of the object, so an object can be
    reinterpreted as any other type. However, value objects with a scalar type
    cannot be reinterpreted, as their memory layout in the program is not
    known. Reinterpreting a reference results in a reference, and
    reinterpreting a value results in a value. See also :func:`drgn.cast()`.

    :param type: The type to reinterpret as.
    :type type: str or Type
    :param Object obj: The object to reinterpret.
    :param byteorder: The byte order to reinterpret as. This should be
        ``'little'`` or ``'big'``. The default is ``None``, which indicates the
        program byte order.
    :type byteorder: str or None
    :rtype: Object

.. function:: container_of(ptr, type, member)

    Get the containing object of a pointer object.

    This corresponds to the ``container_of()`` macro in C.

    :param Object ptr: The pointer.
    :param type: The type of the containing object.
    :type type: str or Type
    :param str member: The name of the member in ``type``.
    :raises TypeError: if the object is not a pointer or the type is not a
        structure or union type
    :raises LookupError: If the type does not have a member with the given name

Symbols
-------

.. class:: Symbol

    A ``Symbol`` represents an entry in the symbol table of a program, i.e., an
    identifier along with its corresponding address range in the program.

    .. attribute:: name

        Name of this symbol.

        :vartype: str

    .. attribute:: address

        Start address of this symbol.

        :vartype: int

    .. attribute:: size

        Size of this symbol in bytes.

        :vartype: int

.. _api-reference-types:

Types
-----

.. class:: Type

    A ``Type`` object describes a type in a program. Each kind of type (e.g.,
    integer, structure) has different attributes (e.g., name, size). Types can
    also have qualifiers (e.g., constant, atomic). Accessing an attribute which
    does not apply to a type raises an :exc:`AttributeError`.

    :func:`repr()` of a Type returns a Python representation of the type:

    >>> print(repr(prog.type('sector_t')))
    typedef_type(name='sector_t', type=int_type(name='unsigned long', size=8, is_signed=False))

    :class:`str() <str>` returns a representation of the type in programming
    language syntax:

    >>> print(prog.type('sector_t'))
    typedef unsigned long sector_t

    The drgn CLI is set up so that types are displayed with ``str()`` instead
    of ``repr()`` by default.

    This class cannot be constructed directly. Instead, use one of the
    :ref:`api-type-constructors`.

    .. attribute:: kind

        Kind of this type.

        :vartype: TypeKind

    .. attribute:: primitive

        If this is a primitive type (e.g., ``int`` or ``double``), the kind of
        primitive type. Otherwise, ``None``.

        :vartype: PrimitiveType or None

    .. attribute:: qualifiers

        Bitmask of this type's qualifier.

        :vartype: Qualifiers

    .. attribute:: name

        Name of this type. This is present for integer, boolean,
        floating-point, complex, and typedef types.

        :vartype: str

    .. attribute:: tag

        Tag of this type, or ``None`` if this is an anonymous type. This is
        present for structure, union, and enumerated types.

        :vartype: str or None

    .. attribute:: size

        Size of this type in bytes, or ``None`` if this is an incomplete type.
        This is present for integer, boolean, floating-point, complex,
        structure, union, and pointer types.

        :vartype: int or None

    .. attribute:: length

        Number of elements in this type, or ``None`` if this is an incomplete
        type. This is only present for array types.

        :vartype: int or None

    .. attribute:: is_signed

        Whether this type is signed. This is only present for integer types.

        :vartype: bool

    .. attribute:: type

        Type underlying this type, defined as follows:

        * For complex types, the corresponding the real type.
        * For typedef types, the aliased type.
        * For enumerated types, the compatible integer type, which is ``None``
          if this is an incomplete type.
        * For pointer types, the referenced type.
        * For array types, the element type.
        * For function types, the return type.

        For other types, this attribute is not present.

        :vartype: Type

    .. attribute:: members

        List of members of this type, or ``None`` if this is an incomplete
        type. This is present for structure and union types.

        Each member is a (type, name, bit offset, bit field size) tuple. The
        name is ``None`` if the member is unnamed; the bit field size is zero
        if the member is not a bit field.

        :vartype: list[tuple(Type, str or None, int, int)]

    .. attribute:: enumerators

        List of enumeration constants of this type, or ``None`` if this is an
        incomplete type. This is only present for enumerated types.

        Each enumeration constant is a (name, value) tuple.

        :vartype: list[tuple(str, int)] or None

    .. attribute:: parameters

        List of parameters of this type. This is only present for function
        types.

        Each parameter is a (type, name) tuple. The name is ``None`` if the
        parameter is unnamed.

        :vartype: list[tuple(Type, str or None)]

    .. attribute:: is_variadic

        Whether this type takes a variable number of arguments. This is only
        present for function types.

        :vartype: bool

    .. method:: type_name()

        Get a descriptive full name of this type.

        :rtype: str

    .. method:: is_complete()

        Get whether this type is complete (i.e., the type definition is known).
        This is always ``False`` for void types. It may be ``False`` for
        structure, union, enumerated, and array types, as well as typedef types
        where the underlying type is one of those. Otherwise, it is always
        ``True``.

        :rtype: bool

    .. method:: qualified(qualifiers)

        Get a copy of this type with different qualifiers.

        Note that the original qualifiers are replaced, not added to.

        :param qualifiers: New type qualifiers.
        :type qualifiers: Qualifiers or None
        :rtype: Type

    .. method:: unqualified()

        Get a copy of this type with no qualifiers.

        :rtype: Type

.. class:: TypeKind

    ``TypeKind`` is an :class:`enum.Enum` of the different kinds of types.

    .. attribute:: VOID

        Void type.

    .. attribute:: INT

        Integer type.

    .. attribute:: BOOL

        Boolean type.

    .. attribute:: FLOAT

        Floating-point type.

    .. attribute:: COMPLEX

        Complex type.

    .. attribute:: STRUCT

        Structure type.

    .. attribute:: UNION

        Union type.

    .. attribute:: ENUM

        Enumerated type.

    .. attribute:: TYPEDEF

        Type definition (a.k.a. alias) type.

    .. attribute:: POINTER

        Pointer type.

    .. attribute:: ARRAY

        Array type.

    .. attribute:: FUNCTION

        Function type.

.. class:: PrimitiveType

    ``PrimitiveType`` is a :class:`enum.Enum` of the primitive types known to
    drgn.

    .. attribute:: C_VOID

    .. attribute:: C_CHAR

    .. attribute:: C_SIGNED_CHAR

    .. attribute:: C_UNSIGNED_CHAR

    .. attribute:: C_SHORT

    .. attribute:: C_UNSIGNED_SHORT

    .. attribute:: C_INT

    .. attribute:: C_UNSIGNED_INT

    .. attribute:: C_LONG

    .. attribute:: C_UNSIGNED_LONG

    .. attribute:: C_LONG_LONG

    .. attribute:: C_UNSIGNED_LONG_LONG

    .. attribute:: C_BOOL

    .. attribute:: C_FLOAT

    .. attribute:: C_DOUBLE

    .. attribute:: C_LONG_DOUBLE

    .. attribute:: C_SIZE_T

    .. attribute:: C_PTRDIFF_T

.. class:: Qualifiers

    ``Qualifiers`` is an :class:`enum.Flag` of type qualifiers.

    .. attribute:: CONST

        Constant type.

    .. attribute:: VOLATILE

        Volatile type.

    .. attribute:: RESTRICT

        `Restrict <https://en.cppreference.com/w/c/language/restrict>`_ type.

    .. attribute:: ATOMIC

        Atomic type.

.. _api-type-constructors:

Type Constructors
^^^^^^^^^^^^^^^^^

Custom drgn types can be created with the following factory functions. These
can be used just like types obtained from :meth:`Program.type()`.

.. function:: void_type(qualifiers=None)

    Create a new void type. It has kind :attr:`TypeKind.VOID`.

    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: int_type(name, size, is_signed, qualifiers=None)

    Create a new integer type. It has kind :attr:`TypeKind.INT`.

    :param str name: :attr:`Type.name`
    :param int size: :attr:`Type.size`
    :param bool is_signed: :attr:`Type.is_signed`
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: bool_type(name, size, qualifiers=None)

    Create a new boolean type. It has kind :attr:`TypeKind.BOOL`.

    :param str name: :attr:`Type.name`
    :param int size: :attr:`Type.size`
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: float_type(name, size, qualifiers=None)

    Create a new floating-point type. It has kind :attr:`TypeKind.FLOAT`.

    :param str name: :attr:`Type.name`
    :param int size: :attr:`Type.size`
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: complex_type(name, size, type, qualifiers=None)

    Create a new complex type. It has kind :attr:`TypeKind.COMPLEX`.

    :param str name: :attr:`Type.name`
    :param int size: :attr:`Type.size`
    :param Type type: The corresponding real type (:attr:`Type.type`)
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: struct_type(tag, size, members, qualifiers=None)

    Create a new structure type. It has kind :attr:`TypeKind.STRUCT`.

    :param tag: :attr:`Type.tag`
    :type tag: str or None
    :param size: :attr:`Type.size`; ``None`` if this is an incomplete type.
    :type size: int or None
    :param members: :attr:`Type.members`; ``None`` if this is an incomplete
        type. The type of a member may be given as a callable returning a
        ``Type``; it will be called the first time that the member is accessed.
        The name, bit offset, and bit field size may be omitted; they default
        to ``None``, 0, and 0, respectively.
    :type members: list[tuple] or None
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: union_type(tag, size, members, qualifiers=None)

    Create a new union type. It has kind :attr:`TypeKind.UNION`. Otherwise,
    this is the same as :func:`struct_type()`.

.. function:: enum_type(tag, type, enumerators, qualifiers=None)

    Create a new enumerated type. It has kind :attr:`TypeKind.ENUM`.

    :param tag: :attr:`Type.tag`
    :type tag: str or None
    :param type: The compatible integer type (:attr:`Type.type`)
    :type param Type or None:
    :param enumerators: :attr:`Type.enumerators`
    :type enumerators: list[tuple] or None
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: typedef_type(name, type, qualifiers=None)

    Create a new typedef type. It has kind :attr:`TypeKind.TYPEDEF`.

    :param str name: :attr:`Type.name`
    :param Type type: The aliased type (:attr:`Type.type`)
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: pointer_type(size, type, qualifiers=None)

    Create a new pointer type. It has kind :attr:`TypeKind.POINTER`,

    You can usually use :meth:`Program:pointer_type()` instead.

    :param int size: :attr:`Type.size`
    :param type: The referenced type (:attr:`Type.type`)
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: array_type(length, type, qualifiers=None)

    Create a new array type. It has kind :attr:`TypeKind.ARRAY`.

    :param length: :attr:`Type.length`
    :type length: int or None
    :param Type type: The element type (:attr:`Type.type`)
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

.. function:: function_type(type, parameters, is_variadic=False, qualifiers=None)

    Create a new function type. It has kind :attr:`TypeKind.FUNCTION`.

    :param Type type: The return type (:attr:`Type.type`)
    :param list[tuple] parameters: :attr:`Type.parameters`. The type of a
        parameter may be given as a callable returning a ``Type``; it will be
        called the first time that the parameter is accessed. The name may be
        omitted and defaults to ``None``.
    :param bool is_variadic: :attr:`Type.is_variadic`
    :param qualifiers: :attr:`Type.qualifiers`
    :type qualifiers: Qualifiers or None
    :rtype: Type

Miscellaneous
-------------

.. autofunction:: execscript

Exceptions
----------

.. exception:: FaultError

    This error is raised when a bad memory access is attempted (i.e., when
    accessing a memory address which is not valid in a program, or when
    accessing out of bounds of a value object).

.. exception:: FileFormatError

    This error is raised when a file cannot be parsed according to its expected
    format (e.g., ELF or DWARF).

.. exception:: MissingDebugInfoError

    This error is raised when one or more files in a program do not have debug
    information.
