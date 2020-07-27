# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

"""
libdrgn bindings

Don't use this module directly. Instead, use the drgn package.
"""

import enum
import os
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    Optional,
    Sequence,
    Union,
    overload,
)

class Program:
    """
    A ``Program`` represents a crashed or running program. It can be used to
    lookup type definitions, access variables, and read arbitrary memory.

    The main functionality of a ``Program`` is looking up objects (i.e.,
    variables, constants, or functions). This is usually done with the
    :meth:`[] <.__getitem__>` operator.

    This class can be constructed directly, but it is usually more convenient
    to use one of the :ref:`api-program-constructors`.

    :param platform: The platform of the program, or ``None`` if it should be
        determined automatically when a core dump or symbol file is added.
    """

    def __init__(self, platform: Optional[Platform] = None) -> None: ...
    flags: ProgramFlags
    """Flags which apply to this program."""

    platform: Optional[Platform]
    """
    Platform that this program runs on, or ``None`` if it has not been
    determined yet.
    """

    language: Language
    """
    Default programming language of the program.

    This is used for interpreting the type name given to :meth:`type()` and
    when creating an :class:`Object` without an explicit type.

    For the Linux kernel, this is :attr:`Language.C`. For userspace programs,
    this is determined from the language of ``main`` in the program, falling
    back to :attr:`Language.C`. This heuristic may change in the future.
    """
    def __getitem__(self, name: str) -> Object:
        """
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

        :param name: The object name.
        """
        ...
    def variable(self, name: str, filename: Optional[str] = None) -> Object:
        """
        Get the variable with the given name.

        >>> prog.variable('jiffies')
        Object(prog, 'volatile unsigned long', address=0xffffffff94c05000)

        This is equivalent to ``prog.object(name, FindObjectFlags.VARIABLE,
        filename)``.

        :param name: The variable name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :raises LookupError: if no variables with the given name are found in
            the given file
        """
        ...
    def constant(self, name: str, filename: Optional[str] = None) -> Object:
        """
        Get the constant (e.g., enumeration constant) with the given name.

        Note that support for macro constants is not yet implemented for DWARF
        files, and most compilers don't generate macro debugging information by
        default anyways.

        >>> prog.constant('PIDTYPE_MAX')
        Object(prog, 'enum pid_type', value=4)

        This is equivalent to ``prog.object(name, FindObjectFlags.CONSTANT,
        filename)``.

        :param name: The constant name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :raises LookupError: if no constants with the given name are found in
            the given file
        """
        ...
    def function(self, name: str, filename: Optional[str] = None) -> Object:
        """
        Get the function with the given name.

        >>> prog.function('schedule')
        Object(prog, 'void (void)', address=0xffffffff94392370)

        This is equivalent to ``prog.object(name, FindObjectFlags.FUNCTION,
        filename)``.

        :param name: The function name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :raises LookupError: if no functions with the given name are found in
            the given file
        """
        ...
    def object(
        self,
        name: str,
        flags: Optional[FindObjectFlags] = None,
        filename: Optional[str] = None,
    ) -> Object:
        """
        Get the object (variable, constant, or function) with the given name.

        :param name: The object name.
        :param flags: Flags indicating what kind of object to look for. If this
            is ``None`` or not given, it defaults to
            :attr:`FindObjectFlags.ANY`.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :raises LookupError: if no objects with the given name are found in
            the given file
        """
        ...
    # address_or_name is positional-only.
    def symbol(self, address_or_name: Union[int, str]) -> Symbol:
        """
        Get the symbol containing the given address, or the global symbol with
        the given name.

        :param address_or_name: The address or name.
        :raises LookupError: if no symbol contains the given address or matches
            the given name
        """
        ...
    def stack_trace(self, thread: Union[Object, int]) -> StackTrace:
        """
        Get the stack trace for the given thread in the program.

        ``thread`` may be a thread ID (as defined by `gettid(2)
        <http://man7.org/linux/man-pages/man2/gettid.2.html>`_), in which case
        this will unwind the stack for the thread with that ID. The ID may be a
        Python ``int`` or an integer :class:`Object`

        ``thread`` may also be a ``struct pt_regs`` or ``struct pt_regs *``
        object, in which case the initial register values will be fetched from
        that object.

        Finally, if debugging the Linux kernel, ``thread`` may be a ``struct
        task_struct *`` object, in which case this will unwind the stack for
        that task. See :func:`drgn.helpers.linux.pid.find_task()`.

        This is implemented for the Linux kernel (both live and core dumps) as
        well as userspace core dumps; it is not yet implemented for live
        userspace processes.

        :param thread: Thread ID, ``struct pt_regs`` object, or
            ``struct task_struct *`` object.
        """
        ...
    def type(self, name: str, filename: Optional[str] = None) -> Type:
        """
        Get the type with the given name.

        >>> prog.type('long')
        int_type(name='long', size=8, is_signed=True)

        :param name: The type name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :raises LookupError: if no types with the given name are found in
            the given file
        """
        ...
    def pointer_type(
        self,
        type: Union[str, Type],
        qualifiers: Optional[Qualifiers] = None,
        *,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a pointer type which points to the given type.

        :param type: The referenced type.
        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...
    def read(self, address: int, size: int, physical: bool = False) -> bytes:
        """
        Read *size* bytes of memory starting at *address* in the program. The
        address may be virtual (the default) or physical if the program
        supports it.

        >>> prog.read(0xffffffffbe012b40, 16)
        b'swapper/0\x00\x00\x00\x00\x00\x00\x00'

        :param address: The starting address.
        :param size: The number of bytes to read.
        :param physical: Whether *address* is a physical memory address. If
            ``False``, then it is a virtual memory address. Physical memory can
            usually only be read when the program is an operating system
            kernel.
        :raises FaultError: if the address range is invalid or the type of
            address (physical or virtual) is not supported by the program
        :raises ValueError: if *size* is negative
        """
        ...
    def read_u8(self, address: int, physical: bool = False) -> int: ...
    def read_u16(self, address: int, physical: bool = False) -> int: ...
    def read_u32(self, address: int, physical: bool = False) -> int: ...
    def read_u64(self, address: int, physical: bool = False) -> int: ...
    def read_word(self, address: int, physical: bool = False) -> int:
        """
        Read an unsigned integer from the program's memory in the program's
        byte order.

        :meth:`read_u8()`, :meth:`read_u16()`, :meth:`read_u32()`, and
        :meth:`read_u64()` read an 8-, 16-, 32-, or 64-bit unsigned integer,
        respectively. :meth:`read_word()` reads a program word-sized unsigned
        integer.

        For signed integers, alternate byte order, or other formats, you can
        use :meth:`read()` and :meth:`int.from_bytes()` or the :mod:`struct`
        module.

        :param address: Address of the integer.
        :param physical: Whether *address* is a physical memory address; see
            :meth:`read()`.
        :raises FaultError: if the address is invalid; see :meth:`read()`
        """
        ...
    def add_memory_segment(
        self,
        address: int,
        size: int,
        read_fn: Callable[[int, int, int, bool], bytes],
        physical: bool = False,
    ) -> None:
        """
        Define a region of memory in the program.

        If it overlaps a previously registered segment, the new segment takes
        precedence.

        :param address: Address of the segment.
        :param size: Size of the segment in bytes.
        :param physical: Whether to add a physical memory segment. If
            ``False``, then this adds a virtual memory segment.
        :param read_fn: Callable to call to read memory from the segment. It is
            passed the address being read from, the number of bytes to read,
            the offset in bytes from the beginning of the segment, and whether
            the address is physical: ``(address, count, offset, physical)``. It
            should return the requested number of bytes as :class:`bytes` or
            another :ref:`buffer <python:binaryseq>` type.
        """
        ...
    def add_type_finder(
        self, fn: Callable[[TypeKind, str, Optional[str]], Type]
    ) -> None:
        """
        Register a callback for finding types in the program.

        Callbacks are called in reverse order of the order they were added
        until the type is found. So, more recently added callbacks take
        precedence.

        :param fn: Callable taking a :class:`TypeKind`, name, and filename:
            ``(kind, name, filename)``. The filename should be matched with
            :func:`filename_matches()`. This should return a :class:`Type`.
        """
        ...
    def add_object_finder(
        self, fn: Callable[[Program, str, FindObjectFlags, Optional[str]], Object]
    ) -> None:
        """
        Register a callback for finding objects in the program.

        Callbacks are called in reverse order of the order they were added
        until the object is found. So, more recently added callbacks take
        precedence.

        :param fn: Callable taking a program, name, :class:`FindObjectFlags`,
            and filename: ``(prog, name, flags, filename)``. The filename
            should be matched with :func:`filename_matches()`. This should
            return an :class:`Object`.
        """
        ...
    def set_core_dump(self, path: Union[str, bytes, os.PathLike]) -> None:
        """
        Set the program to a core dump.

        This loads the memory segments from the core dump and determines the
        mapped executable and libraries. It does not load any debugging
        symbols; see :meth:`load_default_debug_info()`.

        :param path: Core dump file path.
        """
        ...
    def set_kernel(self) -> None:
        """
        Set the program to the running operating system kernel.

        This loads the memory of the running kernel and thus requires root
        privileges. It does not load any debugging symbols; see
        :meth:`load_default_debug_info()`.
        """
        ...
    def set_pid(self, pid: int) -> None:
        """
        Set the program to a running process.

        This loads the memory of the process and determines the mapped
        executable and libraries. It does not load any debugging symbols; see
        :meth:`load_default_debug_info()`.

        :param pid: Process ID.
        """
        ...
    def load_debug_info(
        self,
        paths: Optional[Iterable[Union[str, bytes, os.PathLike]]] = None,
        default: bool = False,
        main: bool = False,
    ) -> None:
        """
        Load debugging information for a list of executable or library files.

        Note that this is parallelized, so it is usually faster to load
        multiple files at once rather than one by one.

        :param paths: Paths of binary files.
        :param default: Also load debugging information which can automatically
            be determined from the program.

            For the Linux kernel, this tries to load ``vmlinux`` and any loaded
            kernel modules from a few standard locations.

            For userspace programs, this tries to load the executable and any
            loaded libraries.

            This implies ``main=True``.
        :param main: Also load debugging information for the main executable.

            For the Linux kernel, this tries to load ``vmlinux``.

            This is currently ignored for userspace programs.
        :raises MissingDebugInfoError: if debugging information was not
            available for some files; other files with debugging information
            are still loaded
        """
        ...
    def load_default_debug_info(self) -> None:
        """
        Load debugging information which can automatically be determined from
        the program.

        This is equivalent to ``load_debug_info(None, True)``.
        """
        ...
    cache: dict
    """
    Dictionary for caching program metadata.

    This isn't used by drgn itself. It is intended to be used by helpers to
    cache metadata about the program. For example, if a helper for a program
    depends on the program version or an optional feature, the helper can
    detect it and cache it for subsequent invocations:

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
    """

class ProgramFlags(enum.Flag):
    """
    ``ProgramFlags`` are flags that can apply to a :class:`Program` (e.g.,
    about what kind of program it is).
    """

    IS_LINUX_KERNEL = ...
    """The program is the Linux kernel."""

    IS_LIVE = ...
    """
    The program is currently running (e.g., it is the running operating system
    kernel or a running process).
    """

class FindObjectFlags(enum.Flag):
    """
    ``FindObjectFlags`` are flags for :meth:`Program.object()`. These can be
    combined to search for multiple kinds of objects at once.
    """

    CONSTANT = ...
    FUNCTION = ...
    VARIABLE = ...
    ANY = ...

def filename_matches(haystack: Optional[str], needle: Optional[str]) -> bool:
    """
    Return whether a filename containing a definition (*haystack*) matches a
    filename being searched for (*needle*).

    The filename is matched from right to left, so ``'stdio.h'``,
    ``'include/stdio.h'``, ``'usr/include/stdio.h'``, and
    ``'/usr/include/stdio.h'`` would all match a definition in
    ``/usr/include/stdio.h``. If *needle* is ``None`` or empty, it matches any
    definition. If *haystack* is ``None`` or empty, it only matches if *needle*
    is also ``None`` or empty.

    :param haystack: Path of file containing definition.
    :param needle: Filename to match.
    """
    ...

def program_from_core_dump(path: Union[str, bytes, os.PathLike]) -> Program:
    """
    Create a :class:`Program` from a core dump file. The type of program (e.g.,
    userspace or kernel) is determined automatically.

    :param path: Core dump file path.
    """
    ...

def program_from_kernel() -> Program:
    """
    Create a :class:`Program` from the running operating system kernel. This
    requires root privileges.
    """
    ...

def program_from_pid(pid: int) -> Program:
    """
    Create a :class:`Program` from a running program with the given PID. This
    requires appropriate permissions (on Linux, :manpage:`ptrace(2)` attach
    permissions).

    :param pid: Process ID of the program to debug.
    """
    ...

class Platform:
    """
    A ``Platform`` represents the environment (i.e., architecture and ABI) that
    a program runs on.

    :param arch: :attr:`Platform.arch`
    :param flags: :attr:`Platform.flags`; if ``None``, default flags for the
        architecture are used.
    """

    def __init__(
        self, arch: Architecture, flags: Optional[PlatformFlags] = None
    ) -> None: ...
    arch: Architecture
    """Instruction set architecture of this platform."""

    flags: PlatformFlags
    """Flags which apply to this platform."""

    registers: Sequence[Register]
    """Processor registers on this platform."""

class Architecture(enum.Enum):
    """``Architecture`` represents an instruction set architecture."""

    X86_64 = ...
    """The x86-64 architecture, a.k.a. AMD64."""

    UNKNOWN = ...
    """
    An architecture which is not known to drgn. Certain features are not
    available when the architecture is unknown, but most of drgn will still
    work.
    """

class PlatformFlags(enum.Flag):
    """``PlatformFlags`` are flags describing a :class:`Platform`."""

    IS_64_BIT = ...
    """Platform is 64-bit."""

    IS_LITTLE_ENDIAN = ...
    """Platform is little-endian."""

class Register:
    """A ``Register`` represents information about a processor register."""

    name: str
    """Name of this register."""

    number: int
    """
    Arbitrary number which uniquely identifies this register on its platform.
    """

host_platform: Platform
"""The platform of the host which is running drgn."""

class Language:
    """
    A ``Language`` represents a programming language supported by drgn.

    This class cannot be constructed; there are singletons for the supported
    languages.
    """

    name: str
    """Name of the programming language."""

    C: Language
    """The C programming language."""

class Object:
    """
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
    Object(prog, 'volatile unsigned long', address=0xffffffffbf005000)

    :class:`str() <str>` returns a "pretty" representation of the object in
    programming language syntax:

    >>> print(prog['jiffies'])
    (volatile unsigned long)4326237045

    The output format of ``str()`` can be modified by using the
    :meth:`format_()` method instead:

    >>> sysname = prog['init_uts_ns'].name.sysname
    >>> print(sysname)
    (char [65])"Linux"
    >>> print(sysname.format_(type_name=False))
    "Linux"
    >>> print(sysname.format_(string=False))
    (char [65]){ 76, 105, 110, 117, 120 }

    .. note::

        The drgn CLI is set up so that objects are displayed in the "pretty"
        format instead of with ``repr()`` (which is the default behavior of
        Python's interactive mode). Therefore, it's usually not necessary to
        call ``print()`` in the drgn CLI.

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

    >>> Object(prog, 'unsigned long', 2**64 - 1) + Object(prog, 'int', 1)
    Object(prog, 'unsigned long', value=0)

    If only one operand to a binary operator is an object, the other operand
    will be converted to an object according to the language's rules for
    literals:

    >>> Object(prog, 'char', 0) - 1
    Object(prog, 'int', value=-1)

    The standard :class:`int() <int>`, :class:`float() <float>`, and
    :class:`bool() <bool>` functions convert an object to that Python type.
    Conversion to ``bool`` uses the programming language's notion of
    "truthiness". Additionally, certain Python functions will automatically
    coerce an object to the appropriate Python type (e.g., :func:`hex()`,
    :func:`round()`, and :meth:`list subscripting <object.__getitem__>`).

    Object attributes and methods are named with a trailing underscore to avoid
    conflicting with structure, union, or class members. The attributes and
    methods always take precedence; use :meth:`member_()` if there is a
    conflict.

    Objects are usually obtained directly from a :class:`Program`, but they can
    be constructed manually, as well (for example, if you got a variable
    address from a log file).

    :param prog: The program to create this object in.
    :param type: The type of the object. If omitted, this is deduced from
        *value* according to the language's rules for literals.
    :param value: The value of this object. See :meth:`value_()`.
    :param address: The address of this object in the program. Either this or
        *value* must be given, but not both.
    :param byteorder: Byte order of the object. This should be ``'little'`` or
        ``'big'``. The default is ``None``, which indicates the program byte
        order. This must be ``None`` for primitive values.
    :param bit_offset: Offset in bits from the object's address to the
        beginning of the object. The default is ``None``, which means no
        offset. This must be ``None`` for primitive values.
    :param bit_field_size: Size in bits of this object if it is a bit field.
        The default is ``None``, which means the object is not a bit field.
    """

    def __init__(
        self,
        prog: Program,
        type: Union[str, Type, None] = None,
        value: Any = None,
        *,
        address: Optional[int] = None,
        byteorder: Optional[str] = None,
        bit_offset: Optional[int] = None,
        bit_field_size: Optional[int] = None,
    ) -> None: ...
    prog_: Program
    """Program that this object is from."""

    type_: Type
    """Type of this object."""

    address_: Optional[int]
    """Address of this object if it is a reference, ``None`` if it is a value."""

    byteorder_: Optional[str]
    """
    Byte order of this object (either ``'little'`` or ``'big'``) if it is a
    reference or a non-primitive value, ``None`` otherwise.
    """

    bit_offset_: Optional[int]
    """
    Offset in bits from this object's address to the beginning of the object if
    it is a reference or a non-primitive value, ``None`` otherwise.
    """

    bit_field_size_: Optional[int]
    """
    Size in bits of this object if it is a bit field, ``None`` if it is not.
    """
    def __getattribute__(self, name: str) -> Object:
        """
        Implement ``self.name``.

        If *name* is an attribute of the :class:`Object` class, then this
        returns that attribute. Otherwise, it is equivalent to
        :meth:`member_()`.

        >>> print(prog['init_task'].pid)
        (pid_t)0

        :param name: Attribute name.
        """
        ...
    def __getitem__(self, idx: Union[int, Object]) -> Object:
        """
        Implement ``self[idx]``. Get the array element at the given index.

        >>> print(prog['init_task'].comm[0])
        (char)115

        This is only valid for pointers and arrays.

        .. note::

            Negative indices behave as they would in the object's language (as
            opposed to the Python semantics of indexing from the end of the
            array).

        :param idx: The array index.
        :raises TypeError: if this object is not a pointer or array
        """
        ...
    def __len__(self) -> int:
        """
        Implement ``len(self)``. Get the number of elements in this object.

        >>> len(prog['init_task'].comm)
        16

        This is only valid for arrays.

        :raises TypeError: if this object is not an array with complete type
        """
        ...
    def value_(self) -> Any:
        """
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
        """
        ...
    def string_(self) -> bytes:
        """
        Read a null-terminated string pointed to by this object.

        This is only valid for pointers and arrays. The element type is
        ignored; this operates byte-by-byte.

        For pointers and flexible arrays, this stops at the first null byte.

        For complete arrays, this stops at the first null byte or at the end of
        the array.

        :raises FaultError: if reading the string causes a bad memory access
        :raises TypeError: if this object is not a pointer or array
        """
        ...
    def member_(self, name: str) -> Object:
        """
        Get a member of this object.

        This is valid for structures, unions, and pointers to either.

        Normally the dot operator (``.``) can be used to accomplish the same
        thing, but this method can be used if there is a name conflict with an
        Object member or method.

        :param name: Name of the member.
        :raises TypeError: if this object is not a structure, union, class, or
            a pointer to one of those
        :raises LookupError: if this object does not have a member with the
            given name
        """
        ...
    def address_of_(self) -> Object:
        """
        Get a pointer to this object.

        This corresponds to the address-of (``&``) operator in C. It is only
        possible for reference objects, as value objects don't have an address
        in the program.

        As opposed to :attr:`address_`, this returns an ``Object``, not an
        ``int``.

        :raises ValueError: if this object is a value
        """
        ...
    def read_(self) -> Object:
        """
        Read this object (which may be a reference or a value) and return it as
        a value object.

        This is useful if the object can change in the running program (but of
        course nothing stops the program from modifying the object while it is
        being read).

        As opposed to :meth:`value_()`, this returns an ``Object``, not a
        standard Python type.

        :raises FaultError: if reading this object causes a bad memory access
        :raises TypeError: if this object has an unreadable type (e.g.,
            ``void``)
        """
        ...
    def format_(
        self,
        *,
        columns: Optional[int] = None,
        dereference: Optional[bool] = None,
        symbolize: Optional[bool] = None,
        string: Optional[bool] = None,
        char: Optional[bool] = None,
        type_name: Optional[bool] = None,
        member_type_names: Optional[bool] = None,
        element_type_names: Optional[bool] = None,
        members_same_line: Optional[bool] = None,
        elements_same_line: Optional[bool] = None,
        member_names: Optional[bool] = None,
        element_indices: Optional[bool] = None,
        implicit_members: Optional[bool] = None,
        implicit_elements: Optional[bool] = None,
    ) -> str:
        """
        Format this object in programming language syntax.

        Various format options can be passed (as keyword arguments) to control
        the output. Options that aren't passed or are passed as ``None`` fall
        back to a default. Specifically, ``obj.format_()`` (i.e., with no
        passed options) is equivalent to ``str(obj)``.

        >>> workqueues = prog['workqueues']
        >>> print(workqueues)
        (struct list_head){
                .next = (struct list_head *)0xffff932ecfc0ae10,
                .prev = (struct list_head *)0xffff932e3818fc10,
        }
        >>> print(workqueues.format_(type_name=False,
        ...                          member_type_names=False,
        ...                          member_names=False,
        ...                          members_same_line=True))
        { 0xffff932ecfc0ae10, 0xffff932e3818fc10 }

        :param columns: Number of columns to limit output to when the
            expression can be reasonably wrapped. Defaults to no limit.
        :param dereference: If this object is a pointer, include the
            dereferenced value. This does not apply to structure, union, or
            class members, or array elements, as dereferencing those could lead
            to an infinite loop. Defaults to ``True``.
        :param symbolize: Include a symbol name and offset for pointer objects.
            Defaults to ``True``.
        :param string: Format the values of objects with string type as strings.
            For C, this applies to pointers to and arrays of ``char``, ``signed
            char``, and ``unsigned char``. Defaults to ``True``.
        :param char: Format objects with character type as character literals.
            For C, this applies to ``char``, ``signed char``, and ``unsigned
            char``. Defaults to ``False``.
        :param type_name: Include the type name of this object. Defaults to
            ``True``.
        :param member_type_names: Include the type names of structure, union,
            and class members. Defaults to ``True``.
        :param element_type_names: Include the type names of array elements.
            Defaults to ``False``.
        :param members_same_line: Place multiple structure, union, and class
            members on the same line if they fit within the specified
            number of ``columns``. Defaults to ``False``.
        :param elements_same_line: Place multiple array elements on the same
            line if they fit within the specified number of ``columns``.
            Defaults to ``True``.
        :param member_names: Include the names of structure, union, and class
            members. Defaults to ``True``.
        :param element_indices: Include the indices of array elements. Defaults
            to ``False``.
        :param implicit_members: Include structure, union, and class members
            which have an implicit value (i.e., for C, zero-initialized).
            Defaults to ``True``.
        :param implicit_elements: Include array elements which have an implicit
            value (i.e., for C, zero-initialized). Defaults to ``False``.
        """
        ...
    def __iter__(self) -> Iterator[Object]: ...
    def __bool__(self) -> bool: ...
    def __lt__(self, other: Any) -> bool: ...
    def __le__(self, other: Any) -> bool: ...
    def __eq__(self, other: Any) -> bool: ...
    def __ne__(self, other: Any) -> bool: ...
    def __gt__(self, other: Any) -> bool: ...
    def __ge__(self, other: Any) -> bool: ...
    def __add__(self, other: Any) -> Object: ...
    def __sub__(self, other: Any) -> Object: ...
    def __mul__(self, other: Any) -> Object: ...
    def __truediv__(self, other: Any) -> Object: ...
    def __mod__(self, other: Any) -> Object: ...
    def __lshift__(self, other: Any) -> Object: ...
    def __rshift__(self, other: Any) -> Object: ...
    def __and__(self, other: Any) -> Object: ...
    def __xor__(self, other: Any) -> Object: ...
    def __or__(self, other: Any) -> Object: ...
    def __radd__(self, other: Any) -> Object: ...
    def __rsub__(self, other: Any) -> Object: ...
    def __rmul__(self, other: Any) -> Object: ...
    def __rtruediv__(self, other: Any) -> Object: ...
    def __rmod__(self, other: Any) -> Object: ...
    def __rlshift__(self, other: Any) -> Object: ...
    def __rrshift__(self, other: Any) -> Object: ...
    def __rand__(self, other: Any) -> Object: ...
    def __rxor__(self, other: Any) -> Object: ...
    def __ror__(self, other: Any) -> Object: ...
    def __neg__(self) -> Object: ...
    def __pos__(self) -> Object: ...
    def __invert__(self) -> Object: ...
    def __int__(self) -> int: ...
    def __float__(self) -> float: ...
    def __index__(self) -> int: ...
    @overload
    def __round__(self, ndigits: None = None) -> int: ...
    @overload
    def __round__(self, ndigits: int) -> Any: ...
    def __trunc__(self) -> int: ...
    def __floor__(self) -> int: ...
    def __ceil__(self) -> int: ...

def NULL(prog: Program, type: Union[str, Type]) -> Object:
    """
    Get an object representing ``NULL`` casted to the given type.

    This is equivalent to ``Object(prog, type, 0)``.

    :param prog: The program.
    :param type: The type.
    """
    ...

def cast(type: Union[str, Type], obj: Object) -> Object:
    """
    Get the value of the given object casted to another type.

    Objects with a scalar type (integer, boolean, enumerated, floating-point,
    or pointer) can be casted to a different scalar type. Other objects can
    only be casted to the same type. This always results in a value object. See
    also :func:`drgn.reinterpret()`.

    :param type: The type to cast to.
    :param obj: The object to cast.
    """
    ...

def reinterpret(
    type: Union[str, Type], obj: Object, byteorder: Optional[str] = None
) -> Object:
    """
    Get a copy of the given object reinterpreted as another type and/or byte
    order.

    This reinterprets the raw memory of the object, so an object can be
    reinterpreted as any other type. However, value objects with a scalar type
    cannot be reinterpreted, as their memory layout in the program is not
    known. Reinterpreting a reference results in a reference, and
    reinterpreting a value results in a value. See also :func:`drgn.cast()`.

    :param type: The type to reinterpret as.
    :param obj: The object to reinterpret.
    :param byteorder: The byte order to reinterpret as. This should be
        ``'little'`` or ``'big'``. The default is ``None``, which indicates the
        program byte order.
    """
    ...

def container_of(ptr: Object, type: Union[str, Type], member: str) -> Object:
    """
    Get the containing object of a pointer object.

    This corresponds to the ``container_of()`` macro in C.

    :param ptr: The pointer.
    :param type: The type of the containing object.
    :param member: The name of the member in ``type``.
    :raises TypeError: if the object is not a pointer or the type is not a
        structure, union, or class type
    :raises LookupError: If the type does not have a member with the given name
    """
    ...

class Symbol:
    """
    A ``Symbol`` represents an entry in the symbol table of a program, i.e., an
    identifier along with its corresponding address range in the program.
    """

    name: str
    """Name of this symbol."""

    address: int
    """Start address of this symbol."""

    size: int
    """Size of this symbol in bytes."""

class StackTrace:
    """
    A ``StackTrace`` is a :ref:`sequence <python:typesseq-common>` of
    :class:`StackFrame`.

    ``len(trace)`` is the number of stack frames in the trace. ``trace[0]`` is
    the innermost stack frame, ``trace[1]`` is its caller, and
    ``trace[len(trace) - 1]`` is the outermost frame. Negative indexing also
    works: ``trace[-1]`` is the outermost frame and ``trace[-len(trace)]`` is
    the innermost frame. It is also iterable:

    .. code-block:: python3

        for frame in trace:
            if frame.symbol().name == 'io_schedule':
                print('Thread is doing I/O')

    :class:`str() <str>` returns a pretty-printed stack trace:

    >>> print(prog.stack_trace(1))
    #0  __schedule+0x25c/0x8ba
    #1  schedule+0x3c/0x7e
    #2  schedule_hrtimeout_range_clock+0x10c/0x118
    #3  ep_poll+0x3ca/0x40a
    #4  do_epoll_wait+0xb0/0xc6
    #5  __x64_sys_epoll_wait+0x1a/0x1d
    #6  do_syscall_64+0x55/0x17c
    #7  entry_SYSCALL_64+0x7c/0x156

    The drgn CLI is set up so that stack traces are displayed with ``str()`` by
    default.
    """

    def __getitem__(self, idx: int) -> StackFrame: ...

class StackFrame:
    """
    A ``StackFrame`` represents a single *frame* (i.e., function call) in a
    thread's call stack.
    """

    pc: int
    """
    The program counter at this stack frame.

    For the innermost frame, this is typically the instruction that was being
    executed when the stack trace was captured. For function calls, this is
    generally the return address, i.e., the value of the program counter when
    control returns to this frame.
    """
    def symbol(self) -> Symbol:
        """
        Get the function symbol at this stack frame.

        This may differ from :meth:`prog.symbol(frame.pc) <Program.symbol>`, as
        for function calls, the program counter may be adjusted to the call
        instruction instead of the return address.
        """
        ...
    def register(self, reg: Union[str, int, Register]) -> int:
        """
        Get the value of the given register at this stack frame. The register
        can be specified by name (e.g., ``'rax'``), number (see
        :attr:`Register.number`), or as a :class:`Register`.

        :param reg: Register to get.
        """
        ...
    def registers(self) -> Dict[str, int]:
        """
        Get the values of all available registers at this stack frame as a
        dictionary with the register names as keys.
        """
        ...

class Type:
    """
    A ``Type`` object describes a type in a program. Each kind of type (e.g.,
    integer, structure) has different attributes (e.g., name, size). Types can
    also have qualifiers (e.g., constant, atomic). Accessing an attribute which
    does not apply to a type raises an :exc:`AttributeError`.

    :func:`repr()` of a ``Type`` returns a Python representation of the type:

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

    .. note::

        ``Type`` objects can be compared with ``==``. However, this is mostly
        intended for testing and should not be used for type checking, as it
        does a deep comparison that checks that the type definitions are
        exactly the same, which is potentially time-consuming and
        memory-intensive.
    """

    kind: TypeKind
    """Kind of this type."""

    primitive: Optional[PrimitiveType]
    """
    If this is a primitive type (e.g., ``int`` or ``double``), the kind of
    primitive type. Otherwise, ``None``.
    """

    qualifiers: Qualifiers
    """Bitmask of this type's qualifier."""

    language: Language
    """Programming language of this type."""

    name: str
    """
    Name of this type. This is present for integer, boolean, floating-point,
    complex, and typedef types.
    """

    tag: Optional[str]
    """
    Tag of this type, or ``None`` if this is an anonymous type. This is present
    for structure, union, class, and enumerated types.
    """

    size: Optional[int]
    """
    Size of this type in bytes, or ``None`` if this is an incomplete type. This
    is present for integer, boolean, floating-point, complex, structure, union,
    class, and pointer types.
    """

    length: Optional[int]
    """
    Number of elements in this type, or ``None`` if this is an incomplete type.
    This is only present for array types.
    """

    is_signed: bool
    """Whether this type is signed. This is only present for integer types."""

    type: Type
    """
    Type underlying this type, defined as follows:

    * For complex types, the corresponding the real type.
    * For typedef types, the aliased type.
    * For enumerated types, the compatible integer type, which is ``None`` if
      this is an incomplete type.
    * For pointer types, the referenced type.
    * For array types, the element type.
    * For function types, the return type.

    For other types, this attribute is not present.
    """

    members: Optional[Sequence[TypeMember]]
    """
    List of members of this type, or ``None`` if this is an incomplete type.
    This is present for structure, union, and class types.
    """

    enumerators: Optional[Sequence[TypeEnumerator]]
    """
    List of enumeration constants of this type, or ``None`` if this is an
    incomplete type. This is only present for enumerated types.
    """

    parameters: Sequence[TypeParameter]
    """
    List of parameters of this type. This is only present for function types.
    """

    is_variadic: bool
    """
    Whether this type takes a variable number of arguments. This is only
    present for function types.
    """
    def type_name(self) -> str:
        """Get a descriptive full name of this type."""
        ...
    def is_complete(self) -> bool:
        """
        Get whether this type is complete (i.e., the type definition is known).
        This is always ``False`` for void types. It may be ``False`` for
        structure, union, class, enumerated, and array types, as well as
        typedef types where the underlying type is one of those. Otherwise, it
        is always ``True``.
        """
        ...
    def qualified(self, qualifiers: Optional[Qualifiers]) -> Type:
        """
        Get a copy of this type with different qualifiers.

        Note that the original qualifiers are replaced, not added to.

        :param qualifiers: New type qualifiers.
        """
        ...
    def unqualified(self) -> Type:
        """Get a copy of this type with no qualifiers."""
        ...

class TypeMember:
    """
    A ``TypeMember`` represents a member of a structure, union, or class type.

    :param type: Type of the member. This may be a :class:`Type` or a callable
        that takes no arguments and returns a :class:`Type`.
    :param name: Name of the member. This may be ``None`` if the member is
        unnamed.
    :param bit_offset: Offset of the member from the beginning of the type
        in bits.
    :param bit_field_size: Size in bits of this member if it is a bit field,
        zero otherwise.
    """

    def __init__(
        self,
        type: Union[Type, Callable[[], Type]],
        name: Optional[str] = None,
        bit_offset: int = 0,
        bit_field_size: int = 0,
    ) -> None: ...
    type: Type

    name: Optional[str]

    bit_offset: int

    offset: int
    """
    Offset of the member from the beginning of the type in bytes. If the offset
    is not byte-aligned, accessing this attribute raises :exc:`ValueError`.
    """

    bit_field_size: int

class TypeEnumerator:
    """
    A ``TypeEnumerator`` represents a constant in an enumerated type.

    Its name and value may be accessed as attributes or unpacked:

    >>> prog.type('enum pid_type').enumerators[0].name
    'PIDTYPE_PID'
    >>> name, value = prog.type('enum pid_type').enumerators[0]
    >>> value
    0

    :param name: Enumerator name.
    :param value: Enumerator value.
    """

    def __init__(self, name: str, value: int) -> None: ...
    name: str

    value: int
    def __len__(self) -> int: ...
    def __getitem__(self, idx: int) -> Any: ...
    def __iter__(self) -> Iterator[Any]: ...

class TypeParameter:
    """
    A ``TypeParameter`` represents a parameter of a function type.

    :param type: Type of the parameter. This may be a :class:`Type` or a callable
        that takes no arguments and returns a :class:`Type`.
    :param name: Name of the parameter. This may be ``None`` if the parameter is
        unnamed.
    """

    def __init__(
        self, type: Union[Type, Callable[[], Type]], name: Optional[str] = None
    ) -> None: ...
    type: Type

    name: Optional[str]

class TypeKind(enum.Enum):
    """A ``TypeKind`` represents a kind of type."""

    VOID = ...
    """Void type."""

    INT = ...
    """Integer type."""

    BOOL = ...
    """Boolean type."""

    FLOAT = ...
    """Floating-point type."""

    COMPLEX = ...
    """Complex type."""

    STRUCT = ...
    """Structure type."""

    UNION = ...
    """Union type."""

    CLASS = ...
    """Class type."""

    ENUM = ...
    """Enumerated type."""

    TYPEDEF = ...
    """Type definition (a.k.a. alias) type."""

    POINTER = ...
    """Pointer type."""

    ARRAY = ...
    """Array type."""

    FUNCTION = ...
    """Function type."""

class PrimitiveType(enum.Enum):
    """A ``PrimitiveType`` represents a primitive type known to drgn."""

    C_VOID = ...
    C_CHAR = ...
    C_SIGNED_CHAR = ...
    C_UNSIGNED_CHAR = ...
    C_SHORT = ...
    C_UNSIGNED_SHORT = ...
    C_INT = ...
    C_UNSIGNED_INT = ...
    C_LONG = ...
    C_UNSIGNED_LONG = ...
    C_LONG_LONG = ...
    C_UNSIGNED_LONG_LONG = ...
    C_BOOL = ...
    C_FLOAT = ...
    C_DOUBLE = ...
    C_LONG_DOUBLE = ...
    C_SIZE_T = ...
    C_PTRDIFF_T = ...

class Qualifiers(enum.Flag):
    """``Qualifiers`` are modifiers on types."""

    CONST = ...
    """Constant type."""

    VOLATILE = ...
    """Volatile type."""

    RESTRICT = ...
    """`Restrict <https://en.cppreference.com/w/c/language/restrict>`_ type."""

    ATOMIC = ...
    """Atomic type."""

def void_type(
    qualifiers: Optional[Qualifiers] = None, *, language: Optional[Language] = None
) -> Type:
    """
    Create a new void type. It has kind :attr:`TypeKind.VOID`.

    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def int_type(
    name: str,
    size: int,
    is_signed: bool,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new integer type. It has kind :attr:`TypeKind.INT`.

    :param name: :attr:`Type.name`
    :param size: :attr:`Type.size`
    :param is_signed: :attr:`Type.is_signed`
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def bool_type(
    name: str,
    size: int,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new boolean type. It has kind :attr:`TypeKind.BOOL`.

    :param name: :attr:`Type.name`
    :param size: :attr:`Type.size`
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def float_type(
    name: str,
    size: int,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new floating-point type. It has kind :attr:`TypeKind.FLOAT`.

    :param name: :attr:`Type.name`
    :param size: :attr:`Type.size`
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def complex_type(
    name: str,
    size: int,
    type: Type,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new complex type. It has kind :attr:`TypeKind.COMPLEX`.

    :param name: :attr:`Type.name`
    :param size: :attr:`Type.size`
    :param type: The corresponding real type (:attr:`Type.type`)
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def struct_type(
    tag: Optional[str],
    size: Optional[int] = None,
    members: Optional[Sequence[TypeMember]] = None,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new structure type. It has kind :attr:`TypeKind.STRUCT`.

    :param tag: :attr:`Type.tag`
    :param size: :attr:`Type.size`; ``None`` if this is an incomplete type.
    :param members: :attr:`Type.members`
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def union_type(
    tag: Optional[str],
    size: Optional[int] = None,
    members: Optional[Sequence[TypeMember]] = None,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new union type. It has kind :attr:`TypeKind.UNION`. Otherwise,
    this is the same as :func:`struct_type()`.
    """
    ...

def class_type(
    tag: Optional[str],
    size: Optional[int] = None,
    members: Optional[Sequence[TypeMember]] = None,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new class type. It has kind :attr:`TypeKind.CLASS`. Otherwise,
    this is the same as :func:`struct_type()`.
    """
    ...

def enum_type(
    tag: Optional[str],
    type: Optional[Type] = None,
    enumerators: Optional[Sequence[TypeEnumerator]] = None,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new enumerated type. It has kind :attr:`TypeKind.ENUM`.

    :param tag: :attr:`Type.tag`
    :param type: The compatible integer type (:attr:`Type.type`)
    :param enumerators: :attr:`Type.enumerators`
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def typedef_type(
    name: str,
    type: Type,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new typedef type. It has kind :attr:`TypeKind.TYPEDEF`.

    :param name: :attr:`Type.name`
    :param type: The aliased type (:attr:`Type.type`)
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def pointer_type(
    size: int,
    type: Type,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new pointer type. It has kind :attr:`TypeKind.POINTER`,

    You can usually use :meth:`Program:pointer_type()` instead.

    :param size: :attr:`Type.size`
    :param type: The referenced type (:attr:`Type.type`)
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def array_type(
    length: Optional[int],
    type: Type,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new array type. It has kind :attr:`TypeKind.ARRAY`.

    :param length: :attr:`Type.length`
    :param type: The element type (:attr:`Type.type`)
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

def function_type(
    type: Type,
    parameters: Sequence[TypeParameter],
    is_variadic: bool = False,
    qualifiers: Optional[Qualifiers] = None,
    *,
    language: Optional[Language] = None,
) -> Type:
    """
    Create a new function type. It has kind :attr:`TypeKind.FUNCTION`.

    :param type: The return type (:attr:`Type.type`)
    :param parameters: :attr:`Type.parameters`
    :param is_variadic: :attr:`Type.is_variadic`
    :param qualifiers: :attr:`Type.qualifiers`
    :param lang: :attr:`Type.language`
    """
    ...

# type_or_obj is positional-only.
def sizeof(type_or_obj: Union[Type, Object]) -> int:
    """
    Get the size of a :class:`Type` or :class:`Object` in bytes.

    :param type_or_obj: Entity to get the size of.
    :raises TypeError: if the type does not have a size (e.g., because it is
        incomplete or void)
    """
    ...

class FaultError(Exception):
    """
    This error is raised when a bad memory access is attempted (i.e., when
    accessing a memory address which is not valid in a program).

    :param address: Address that couldn't be accessed.
    """

    def __init__(self, address: int) -> None: ...
    address: int

class MissingDebugInfoError(Exception):
    """
    This error is raised when one or more files in a program do not have debug
    information.
    """

    ...

class OutOfBoundsError(Exception):
    """
    This error is raised when attempting to access beyond the bounds of a value
    object.
    """

    ...

_with_libkdumpfile: bool

def _linux_helper_read_vm(prog, pgtable, address, size): ...
def _linux_helper_radix_tree_lookup(root, index): ...
def _linux_helper_idr_find(idr, id): ...
def _linux_helper_find_pid(ns, pid): ...
def _linux_helper_pid_task(pid, pid_type): ...
def _linux_helper_find_task(ns, pid): ...
def _linux_helper_task_state_to_char(task): ...
def _linux_helper_kaslr_offset(prog): ...
def _linux_helper_pgtable_l5_enabled(prog): ...
