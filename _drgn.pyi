# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""
libdrgn bindings

Don't use this module directly. Instead, use the drgn package.
"""

import collections.abc
import enum
import os
import sys
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    Final,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    NamedTuple,
    Optional,
    Protocol,
    Sequence,
    Set,
    SupportsIndex,
    Tuple,
    Union,
    overload,
)

if sys.version_info < (3, 10):
    from typing_extensions import TypeAlias
else:
    from typing import TypeAlias

if sys.version_info < (3, 12):
    from typing_extensions import Buffer
else:
    from collections.abc import Buffer

IntegerLike: TypeAlias = SupportsIndex
"""
An :class:`int` or integer-like object.

Parameters annotated with this type expect an integer which may be given as a
Python :class:`int` or an :class:`Object` with integer type.

This is equivalent to :class:`typing.SupportsIndex`.
"""

Path: TypeAlias = Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]
"""
Filesystem path.

Parameters annotated with this type accept a filesystem path as :class:`str`,
:class:`bytes`, or :class:`os.PathLike`.
"""

class Program:
    """
    A ``Program`` represents a crashed or running program. It can be used to
    lookup type definitions, access variables, and read arbitrary memory.

    The main functionality of a ``Program`` is looking up objects (i.e.,
    variables, constants, or functions). This is usually done with the
    :meth:`[] <.__getitem__>` operator.
    """

    def __init__(
        self,
        platform: Optional[Platform] = None,
        *,
        vmcoreinfo: Union[bytes, str, None] = None,
    ) -> None:
        """
        Create a ``Program`` with no target program. It is usually more
        convenient to use one of the :ref:`api-program-constructors`.

        :param platform: The platform of the program, or ``None`` if it should
            be determined automatically when a core dump or symbol file is
            added.
        :param vmcoreinfo: Optionally provide the ``VMCOREINFO`` note data for
            Linux kernel core dumps, which will override any detected data. When
            not provided or ``None``, automatically detect the info.
        """
        ...
    flags: ProgramFlags
    """Flags which apply to this program."""

    platform: Optional[Platform]
    """
    Platform that this program runs on, or ``None`` if it has not been
    determined yet.
    """

    core_dump_path: Optional[str]
    """
    Path of the core dump that this program was created from, or ``None`` if it
    was not created from a core dump.
    """

    language: Language
    """
    Default programming language of the program.

    This is used for interpreting the type name given to :meth:`type()` and
    when creating an :class:`Object` without an explicit type.

    For the Linux kernel, this defaults to :attr:`Language.C`. For userspace
    programs, this defaults to the language of ``main`` in the program, falling
    back to :attr:`Language.C`. This heuristic may change in the future.

    This can be explicitly set to a different language (e.g., if the heuristic
    was incorrect).
    """
    def __getitem__(self, name: str) -> Object:
        """
        Implement ``self[name]``. Get the object (variable, constant, or
        function) with the given name.

        This is equivalent to ``prog.object(name)``.

        If there are multiple objects with the same name, one is returned
        arbitrarily. In this case, the :meth:`variable()`, :meth:`constant()`,
        :meth:`function()`, or :meth:`object()` methods can be used instead.

        >>> prog['jiffies']
        Object(prog, 'volatile unsigned long', address=0xffffffff94c05000)

        :param name: Object name.
        """
        ...

    def __contains__(self, name: str) -> bool:
        """
        Implement ``name in self``. Return whether an object (variable,
        constant, or function) with the given name exists in the program.

        :param name: Object name.
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
        :raises ObjectNotFoundError: if no variables with the given name are
            found in the given file
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
        :raises ObjectNotFoundError: if no constants with the given name are
            found in the given file
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
        :raises ObjectNotFoundError: if no functions with the given name are
            found in the given file
        """
        ...

    def object(
        self,
        name: str,
        flags: FindObjectFlags = FindObjectFlags.ANY,
        filename: Optional[str] = None,
    ) -> Object:
        """
        Get the object (variable, constant, or function) with the given name.

        When debugging the Linux kernel, this can look up certain special
        objects documented in :ref:`kernel-special-objects`, sometimes without
        any debugging information loaded.

        :param name: The object name.
        :param flags: Flags indicating what kind of object to look for.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :raises ObjectNotFoundError: if no objects with the given name are
            found in the given file
        """
        ...

    def symbol(self, __address_or_name: Union[IntegerLike, str]) -> Symbol:
        """
        Get a symbol containing the given address, or a symbol with the given
        name.

        If there are multiple symbols containing a given address, then this
        will attempt to find the closest match.

        If searching by name or if there is a tie, global symbols are preferred
        over weak symbols, and weak symbols are preferred over other symbols.
        In other words: if a matching :attr:`SymbolBinding.GLOBAL` or
        :attr:`SymbolBinding.UNIQUE` symbol is found, it is returned.
        Otherwise, if a matching :attr:`SymbolBinding.WEAK` symbol is found, it
        is returned. Otherwise, any matching symbol (e.g.,
        :attr:`SymbolBinding.LOCAL`) is returned. If there is still a tie, one
        is returned arbitrarily. To retrieve all matching symbols, use
        :meth:`symbols()`.

        :param address_or_name: Address or name to search for.
        :raises LookupError: if no symbol contains the given address or matches
            the given name
        """
        ...

    def symbols(
        self,
        __address_or_name: Union[None, IntegerLike, str] = None,
    ) -> List[Symbol]:
        """
        Get a list of global and local symbols, optionally matching a name or
        address.

        If a string argument is given, this returns all symbols matching that
        name. If an integer-like argument given, this returns a list of all
        symbols containing that address. If no argument is given, all symbols
        in the program are returned. In all cases, the symbols are returned in
        an unspecified order.

        :param address_or_name: Address or name to search for.
        """
        ...

    def stack_trace(
        self,
        # Object is already IntegerLike, but this explicitly documents that it
        # can take non-integer Objects.
        thread: Union[Object, IntegerLike],
    ) -> StackTrace:
        """
        Get the stack trace for the given thread in the program.

        ``thread`` may be a thread ID (as defined by :manpage:`gettid(2)`), in
        which case this will unwind the stack for the thread with that ID. The
        ID may be a Python ``int`` or an integer :class:`Object`

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

    def stack_trace_from_pcs(self, pcs: Sequence[IntegerLike]) -> StackTrace:
        """
        Get a stack trace with the supplied list of program counters.

        :param pcs: List of program counters.
        """
        ...

    @overload
    def type(self, name: str, filename: Optional[str] = None) -> Type:
        """
        Get the type with the given name.

        >>> prog.type('long')
        prog.int_type(name='long', size=8, is_signed=True)

        :param name: The type name.
        :param filename: The source code file that contains the definition. See
            :ref:`api-filenames`.
        :raises LookupError: if no types with the given name are found in
            the given file
        """
        ...

    @overload
    def type(self, __type: Type) -> Type:
        """
        Return the given type.

        This is mainly useful so that helpers can use ``prog.type()`` to get a
        :class:`Type` regardless of whether they were given a :class:`str` or a
        :class:`Type`. For example:

        .. code-block:: python3

            def my_helper(obj: Object, type: Union[str, Type]) -> bool:
                # type may be str or Type.
                type = obj.prog_.type(type)
                # type is now always Type.
                return sizeof(obj) > sizeof(type)

        :param type: Type.
        :return: The exact same type.
        """
        ...

    def threads(self) -> Iterator[Thread]:
        """Get an iterator over all of the threads in the program."""
        ...

    def thread(self, tid: IntegerLike) -> Thread:
        """
        Get the thread with the given thread ID.

        :param tid: Thread ID (as defined by :manpage:`gettid(2)`).
        :raises LookupError: if no thread has the given thread ID
        """
        ...

    def main_thread(self) -> Thread:
        """
        Get the main thread of the program.

        This is only defined for userspace programs.

        :raises ValueError: if the program is the Linux kernel
        """
        ...

    def crashed_thread(self) -> Thread:
        """
        Get the thread that caused the program to crash.

        For userspace programs, this is the thread that received the fatal
        signal (e.g., ``SIGSEGV`` or ``SIGQUIT``).

        For the kernel, this is the thread that panicked (either directly or as
        a result of an oops, ``BUG_ON()``, etc.).

        :raises ValueError: if the program is live (i.e., not a core dump)
        """
        ...

    def read(
        self, address: IntegerLike, size: IntegerLike, physical: bool = False
    ) -> bytes:
        r"""
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

    def read_u8(self, address: IntegerLike, physical: bool = False) -> int:
        """ """
        ...

    def read_u16(self, address: IntegerLike, physical: bool = False) -> int:
        """ """
        ...

    def read_u32(self, address: IntegerLike, physical: bool = False) -> int:
        """ """
        ...

    def read_u64(self, address: IntegerLike, physical: bool = False) -> int:
        """ """
        ...

    def read_word(self, address: IntegerLike, physical: bool = False) -> int:
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
        address: IntegerLike,
        size: IntegerLike,
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

    def register_type_finder(
        self,
        name: str,
        fn: Callable[[Program, TypeKindSet, str, Optional[str]], Optional[Type]],
        *,
        enable_index: Optional[int] = None,
    ) -> None:
        """
        Register a callback for finding types in the program.

        This does not enable the finder unless *enable_index* is given.

        :param name: Finder name.
        :param fn: Callable taking the program, a :class:`TypeKindSet`, name,
            and filename: ``(prog, kinds, name, filename)``. The filename
            should be matched with :func:`filename_matches()`. This should
            return a :class:`Type` or ``None`` if not found.
        :param enable_index: Insert the finder into the list of enabled type
            finders at the given index. If -1 or greater than the number of
            enabled finders, insert it at the end. If ``None`` or not given,
            don't enable the finder.
        :raises ValueError: if there is already a finder with the given name
        """
        ...

    def registered_type_finders(self) -> Set[str]:
        """Return the names of all registered type finders."""
        ...

    def set_enabled_type_finders(self, names: Sequence[str]) -> None:
        """
        Set the list of enabled type finders.

        Finders are called in the same order as the list until a type is found.

        Finders that are not in the list are not called.

        :param names: Names of finders to enable, in order.
        :raises ValueError: if no finder has a given name or the same name is
            given more than once
        """
        ...

    def enabled_type_finders(self) -> List[str]:
        """Return the names of enabled type finders, in order."""
        ...

    def register_object_finder(
        self,
        name: str,
        fn: Callable[[Program, str, FindObjectFlags, Optional[str]], Optional[Object]],
        *,
        enable_index: Optional[int] = None,
    ) -> None:
        """
        Register a callback for finding objects in the program.

        This does not enable the finder unless *enable_index* is given.

        :param name: Finder name.
        :param fn: Callable taking the program, name, :class:`FindObjectFlags`,
            and filename: ``(prog, name, flags, filename)``. The filename
            should be matched with :func:`filename_matches()`. This should
            return an :class:`Object` or ``None`` if not found.
        :param enable_index: Insert the finder into the list of enabled object
            finders at the given index. If -1 or greater than the number of
            enabled finders, insert it at the end. If ``None`` or not given,
            don't enable the finder.
        :raises ValueError: if there is already a finder with the given name
        """
        ...

    def registered_object_finders(self) -> Set[str]:
        """Return the names of all registered object finders."""
        ...

    def set_enabled_object_finders(self, names: Sequence[str]) -> None:
        """
        Set the list of enabled object finders.

        Finders are called in the same order as the list until an object is found.

        Finders that are not in the list are not called.

        :param names: Names of finders to enable, in order.
        :raises ValueError: if no finder has a given name or the same name is
            given more than once
        """
        ...

    def enabled_object_finders(self) -> List[str]:
        """Return the names of enabled object finders, in order."""
        ...

    def register_symbol_finder(
        self,
        name: str,
        fn: Callable[[Program, Optional[str], Optional[int], bool], Sequence[Symbol]],
        *,
        enable_index: Optional[int] = None,
    ) -> None:
        """
        Register a callback for finding symbols in the program.

        This does not enable the finder unless *enable_index* is given.

        The callback should take four arguments: the program, a *name*, an
        *address*, and a boolean flag *one*. It should return a list of symbols
        or an empty list if no matches are found.

        If *name* is not ``None``, then only symbols with that name should be
        returned. If *address* is not ``None``, then only symbols containing
        that address should be returned. If neither is ``None``, then the
        returned symbols must match both. If both are ``None``, then all
        symbols should be considered matching.

        When the *one* flag is ``False``, the callback should return a list of
        all matching symbols. When it is ``True``, it should return a list with
        at most one symbol which is the best match.

        :param name: Finder name.
        :param fn: Callable taking ``(prog, name, address, one)`` and returning
            a sequence of :class:`Symbol`\\ s.
        :param enable_index: Insert the finder into the list of enabled finders
            at the given index. If -1 or greater than the number of enabled
            finders, insert it at the end. If ``None`` or not given, don't
            enable the finder.
        :raises ValueError: if there is already a finder with the given name
        """
        ...

    def registered_symbol_finders(self) -> Set[str]:
        """Return the names of all registered symbol finders."""
        ...

    def set_enabled_symbol_finders(self, names: Sequence[str]) -> None:
        """
        Set the list of enabled symbol finders.

        Finders are called in the same order as the list. When the *one* flag
        is set, the search will short-circuit after the first finder which
        returns a result, and subsequent finders will not be called. Otherwise,
        all callbacks will be called, and all results will be returned.

        Finders that are not in the list are not called.

        :param names: Names of finders to enable, in order.
        :raises ValueError: if no finder has a given name or the same name is
            given more than once
        """
        ...

    def enabled_symbol_finders(self) -> List[str]:
        """Return the names of enabled symbol finders, in order."""
        ...

    def add_type_finder(
        self, fn: Callable[[TypeKind, str, Optional[str]], Optional[Type]]
    ) -> None:
        """
        Deprecated method to register and enable a callback for finding types
        in the program.

        .. deprecated:: 0.0.27
            Use :meth:`register_type_finder()` instead.

        The differences from :meth:`register_type_finder()` are:

        1. *fn* is not passed *prog*.
        2. *fn* is passed a :class:`TypeKind` instead of a
           :class:`TypeKindSet`. If multiple kinds are being searched for, *fn*
           will be called multiple times.
        3. A name for the finder is generated from *fn*.
        4. The finder is always enabled before any existing finders.
        """
        ...

    def add_object_finder(
        self,
        fn: Callable[[Program, str, FindObjectFlags, Optional[str]], Optional[Object]],
    ) -> None:
        """
        Deprecated method to register and enable a callback for finding objects
        in the program.

        .. deprecated:: 0.0.27
            Use :meth:`register_object_finder()` instead.

        The differences from :meth:`register_object_finder()` are:

        1. A name for the finder is generated from *fn*.
        2. The finder is always enabled before any existing finders.
        """
        ...

    def set_core_dump(self, path: Union[Path, int]) -> None:
        """
        Set the program to a core dump.

        This loads the memory segments from the core dump and determines the
        mapped executable and libraries. It does not load any debugging
        symbols; see :meth:`load_default_debug_info()`.

        :param path: Core dump file path or open file descriptor.
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

    def modules(self) -> Iterator[Module]:
        """Get an iterator over all of the created modules in the program."""

    def loaded_modules(self) -> Iterator[Tuple[Module, bool]]:
        """
        Get an iterator over executables, libraries, etc. that are loaded in
        the program, creating modules to represent them.

        Modules are created lazily as items are consumed.

        This may automatically load some debugging information necessary to
        enumerate the modules. Other than that, it does not load debugging
        information.

        See :meth:`load_debug_info()` for a higher-level interface that does
        load debugging information.

        :return: Iterator of module and ``True`` if it was newly created
            or ``False`` if it was previously found.
        """
        ...

    def create_loaded_modules(self) -> None:
        """
        Determine what executables, libraries, etc. are loaded in the program
        and create modules to represent them.

        This is a shortcut for exhausting a :meth:`loaded_modules()` iterator.
        It is equivalent to:

        .. code-block:: python3

            for _ in prog.loaded_modules():
                pass
        """

    @overload
    def main_module(self) -> MainModule:
        """
        Find the main module.

        :raises LookupError: if the main module has not been created
        """
        ...

    @overload
    def main_module(self, name: Path, *, create: bool = False) -> MainModule:
        """
        Find the main module.

        :param name: :attr:`Module.name`
        :param create: Create the module if it doesn't exist.
        :raises LookupError: if the main module has not been created and
            *create* is ``False``, or if the main module has already been
            created with a different name
        """
        ...

    def shared_library_module(
        self,
        name: Path,
        dynamic_address: IntegerLike,
        *,
        create: bool = False,
    ) -> SharedLibraryModule:
        """
        Find a shared library module.

        :param name: :attr:`Module.name`
        :param dynamic_address: :attr:`SharedLibraryModule.dynamic_address`
        :param create: Create the module if it doesn't exist.
        :return: Shared library module with the given name and dynamic address.
        :raises LookupError: if no matching module has been created and
            *create* is ``False``
        """
        ...

    def vdso_module(
        self,
        name: Path,
        dynamic_address: IntegerLike,
        *,
        create: bool = False,
    ) -> VdsoModule:
        """
        Find a vDSO module.

        :param name: :attr:`Module.name`
        :param dynamic_address: :attr:`VdsoModule.dynamic_address`
        :param create: Create the module if it doesn't exist.
        :return: vDSO module with the given name and dynamic address.
        :raises LookupError: if no matching module has been created and
            *create* is ``False``
        """
        ...

    def relocatable_module(
        self, name: Path, address: IntegerLike, *, create: bool = False
    ) -> RelocatableModule:
        """
        Find a relocatable module.

        :param name: :attr:`Module.name`
        :param address: :attr:`RelocatableModule.address`
        :param create: Create the module if it doesn't exist.
        :return: Relocatable module with the given name and address.
        :raises LookupError: if no matching module has been created and
            *create* is ``False``
        """
        ...

    def linux_kernel_loadable_module(
        self, module_obj: Object, *, create: bool = False
    ) -> RelocatableModule:
        """
        Find a Linux kernel loadable module from a ``struct module *`` object.

        Note that kernel modules are represented as relocatable modules.

        :param module_obj: ``struct module *`` object for the kernel module.
        :param create: Create the module if it doesn't exist.
        :return: Relocatable module with a name and address matching
            *module_obj*.
        :raises LookupError: if no matching module has been created and
            *create* is ``False``
        """
        ...

    def extra_module(
        self, name: Path, id: IntegerLike = 0, *, create: bool = False
    ) -> ExtraModule:
        """
        Find an extra module.

        :param name: :attr:`Module.name`
        :param id: :attr:`ExtraModule.id`
        :param create: Create the module if it doesn't exist.
        :return: Extra module with the given name and ID number.
        :raises LookupError: if no matching module has been created and
            *create* is ``False``
        """
        ...

    def module(self, __address_or_name: Union[IntegerLike, str]) -> Module:
        """
        Find the module containing the given address, or the module with the
        given name.

        Addresses are matched based on :attr:`Module.address_ranges`.

        If there are multiple modules with the given name, one is returned
        arbitrarily.

        :param address_or_name: Address or name to search for.
        :raises LookupError: if no module contains the given address or has the
            given name
        """
        ...

    def register_debug_info_finder(
        self,
        name: str,
        fn: Callable[[Sequence[Module]], None],
        *,
        enable_index: Optional[int] = None,
    ) -> None:
        """
        Register a callback for finding debugging information.

        This does not enable the finder unless *enable_index* is given.

        :param name: Finder name.
        :param fn: Callable taking a list of :class:`Module`\\ s that want
            debugging information.

            This should check :meth:`Module.wants_loaded_file()` and
            :meth:`Module.wants_debug_file()` and do one of the following for
            each module:

            * Obtain and/or locate a file wanted by the module and call
              :meth:`Module.try_file()`.
            * Install files for a later finder to use.
            * Set :attr:`Module.loaded_file_status` or
              :attr:`Module.debug_file_status` to
              :attr:`ModuleFileStatus.DONT_NEED` if the finder believes that
              the file is not needed.
            * Ignore it, for example if the finder doesn't know how to find the
              wanted files for the module.
        :param enable_index: Insert the finder into the list of enabled object
            finders at the given index. If -1 or greater than the number of
            enabled finders, insert it at the end. If ``None`` or not given,
            don't enable the finder.
        :raises ValueError: if there is already a finder with the given name
        """
        ...

    def registered_debug_info_finders(self) -> Set[str]:
        """Return the names of all registered debugging information finders."""
        ...

    def set_enabled_debug_info_finders(self, names: Sequence[str]) -> None:
        """
        Set the list of enabled debugging information finders.

        Finders are called in the same order as the list until all wanted files
        have been found.

        Finders that are not in the list are not called.

        :param names: Names of finders to enable, in order.
        :raises ValueError: if no finder has a given name or the same name is
            given more than once
        """
        ...

    def enabled_debug_info_finders(self) -> List[str]:
        """
        Return the names of enabled debugging information finders, in order.
        """
        ...
    debug_info_options: DebugInfoOptions
    """Default options for debugging information searches."""

    def load_debug_info(
        self,
        paths: Optional[Iterable[Path]] = (),
        default: bool = False,
        main: bool = False,
    ) -> None:
        """
        Load debugging information for the given set of files and/or modules.

        This determines what executables, libraries, etc. are loaded in the
        program (see :meth:`loaded_modules()`) and tries to load their
        debugging information from the given *paths*.

        .. note::
            It is much more efficient to load multiple files at once rather
            than one by one when possible.

        :param paths: Paths of binary files to try.

            Files that don't correspond to any loaded modules are ignored. See
            :class:`ExtraModule` for a way to provide arbitrary debugging
            information.
        :param default: Try to load all debugging information for all loaded
            modules.

            The files in *paths* are tried first before falling back to the
            enabled debugging information finders.

            This implies ``main=True``.
        :param main: Try to load all debugging information for the main module.

            The files in *paths* are tried first before falling back to the
            enabled debugging information finders.
        :raises MissingDebugInfoError: if debugging information was not
            available for some files; other files with debugging information
            are still loaded
        """
        ...

    def load_default_debug_info(self) -> None:
        """
        Load all debugging information that can automatically be determined
        from the program.

        This is equivalent to ``load_debug_info(default=True)``.
        """
        ...

    def load_module_debug_info(self, *modules: Module) -> None:
        """
        Load debugging information for the given modules using the enabled
        debugging information finders.

        The files to search for are controlled by
        :attr:`Module.loaded_file_status` and :attr:`Module.debug_file_status`.
        """
        ...

    def find_standard_debug_info(
        self, modules: Iterable[Module], options: Optional[DebugInfoOptions] = None
    ) -> None:
        """
        Load debugging information for the given modules from the standard
        locations.

        This is equivalent to the ``standard`` debugging information finder
        that is registered by default. It is intended for use by other
        debugging information finders that need a variation of the standard
        finder (e.g., after installing something or setting specific options).

        :param modules: Modules to load debugging information for.
        :param options: Options to use when searching for debugging
            information. If ``None`` or not given, this uses
            :attr:`self.debug_info_options <debug_info_options>`.
        """
    cache: Dict[Any, Any]
    """
    Dictionary for caching program metadata.

    This isn't used by the :class:`Program` itself. It is intended to be used
    by helpers to cache metadata about the program. For example, if a helper
    for a program depends on the program version or an optional feature, the
    helper can detect it and cache it for subsequent invocations:

    .. code-block:: python3

        def my_helper(prog):
            try:
                have_foo = prog.cache["have_foo"]
            except KeyError:
                have_foo = detect_foo_feature(prog)
                prog.cache["have_foo"] = have_foo
            if have_foo:
                return prog["foo"]
            else:
                return prog["bar"]
    """
    config: Dict[str, Any]
    """
    Dictionary for configuration options.

    This isn't used by the :class:`Program` itself. It can be used to store
    configuration options for commands and helpers.
    """
    def void_type(
        self,
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new void type. It has kind :attr:`TypeKind.VOID`.

        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...

    def int_type(
        self,
        name: str,
        size: IntegerLike,
        is_signed: bool,
        byteorder: Optional[str] = None,
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new integer type. It has kind :attr:`TypeKind.INT`.

        :param name: :attr:`Type.name`
        :param size: :attr:`Type.size`
        :param is_signed: :attr:`Type.is_signed`
        :param byteorder: :attr:`Type.byteorder`, or ``None`` to use the
            program's default byte order.
        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...

    def bool_type(
        self,
        name: str,
        size: IntegerLike,
        byteorder: Optional[str] = None,
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new boolean type. It has kind :attr:`TypeKind.BOOL`.

        :param name: :attr:`Type.name`
        :param size: :attr:`Type.size`
        :param byteorder: :attr:`Type.byteorder`, or ``None`` to use the
            program's default byte order.
        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...

    def float_type(
        self,
        name: str,
        size: IntegerLike,
        byteorder: Optional[str] = None,
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new floating-point type. It has kind :attr:`TypeKind.FLOAT`.

        :param name: :attr:`Type.name`
        :param size: :attr:`Type.size`
        :param byteorder: :attr:`Type.byteorder`, or ``None`` to use the
            program's default byte order.
        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...

    @overload
    def struct_type(
        self,
        tag: Optional[str],
        size: IntegerLike,
        members: Sequence[TypeMember],
        *,
        template_parameters: Sequence[TypeTemplateParameter] = (),
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new structure type. It has kind :attr:`TypeKind.STRUCT`.

        :param tag: :attr:`Type.tag`
        :param size: :attr:`Type.size`
        :param members: :attr:`Type.members`
        :param template_parameters: :attr:`Type.template_parameters`
        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...

    @overload
    def struct_type(
        self,
        tag: Optional[str],
        size: None = None,
        members: None = None,
        *,
        template_parameters: Sequence[TypeTemplateParameter] = (),
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """Create a new incomplete structure type."""
        ...

    @overload
    def union_type(
        self,
        tag: Optional[str],
        size: IntegerLike,
        members: Sequence[TypeMember],
        *,
        template_parameters: Sequence[TypeTemplateParameter] = (),
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new union type. It has kind :attr:`TypeKind.UNION`. Otherwise,
        this is the same as as :meth:`struct_type()`.
        """
        ...

    @overload
    def union_type(
        self,
        tag: Optional[str],
        size: None = None,
        members: None = None,
        *,
        template_parameters: Sequence[TypeTemplateParameter] = (),
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """Create a new incomplete union type."""
        ...

    @overload
    def class_type(
        self,
        tag: Optional[str],
        size: IntegerLike,
        members: Sequence[TypeMember],
        *,
        template_parameters: Sequence[TypeTemplateParameter] = (),
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new class type. It has kind :attr:`TypeKind.CLASS`. Otherwise,
        this is the same as as :meth:`struct_type()`.
        """
        ...

    @overload
    def class_type(
        self,
        tag: Optional[str],
        size: None = None,
        members: None = None,
        *,
        template_parameters: Sequence[TypeTemplateParameter] = (),
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """Create a new incomplete class type."""
        ...

    @overload
    def enum_type(
        self,
        tag: Optional[str],
        type: Type,
        enumerators: Sequence[TypeEnumerator],
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
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

    @overload
    def enum_type(
        self,
        tag: Optional[str],
        type: None = None,
        enumerators: None = None,
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """Create a new incomplete enumerated type."""
        ...

    def typedef_type(
        self,
        name: str,
        type: Type,
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
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
        self,
        type: Type,
        size: Optional[int] = None,
        byteorder: Optional[str] = None,
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new pointer type. It has kind :attr:`TypeKind.POINTER`,

        :param type: The referenced type (:attr:`Type.type`)
        :param size: :attr:`Type.size`, or ``None`` to use the program's
            default pointer size.
        :param byteorder: :attr:`Type.byteorder`, or ``None`` to use the
            program's default byte order.
        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...

    def array_type(
        self,
        type: Type,
        length: Optional[int] = None,
        *,
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new array type. It has kind :attr:`TypeKind.ARRAY`.

        :param type: The element type (:attr:`Type.type`)
        :param length: :attr:`Type.length`
        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...

    def function_type(
        self,
        type: Type,
        parameters: Sequence[TypeParameter],
        is_variadic: bool = False,
        *,
        template_parameters: Sequence[TypeTemplateParameter] = (),
        qualifiers: Qualifiers = Qualifiers.NONE,
        language: Optional[Language] = None,
    ) -> Type:
        """
        Create a new function type. It has kind :attr:`TypeKind.FUNCTION`.

        :param type: The return type (:attr:`Type.type`)
        :param parameters: :attr:`Type.parameters`
        :param is_variadic: :attr:`Type.is_variadic`
        :param template_parameters: :attr:`Type.template_parameters`
        :param qualifiers: :attr:`Type.qualifiers`
        :param lang: :attr:`Type.language`
        """
        ...

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

    IS_LOCAL = ...
    """
    The program is running on the local machine.
    """

class FindObjectFlags(enum.Flag):
    """
    ``FindObjectFlags`` are flags for :meth:`Program.object()`. These can be
    combined to search for multiple kinds of objects at once.
    """

    CONSTANT = ...
    ""
    FUNCTION = ...
    ""
    VARIABLE = ...
    ""
    ANY = ...
    ""

class ObjectNotFoundError(KeyError):
    def __init__(self, *args: object, name: str) -> None:
        """Error raised when an object is not found in a program."""
        ...
    name: str
    """Object name that was not found."""

class DebugInfoOptions:
    """
    Options for debugging information searches.

    All of these options can be reassigned.
    """

    def __init__(
        self,
        __options: Optional[DebugInfoOptions] = None,
        *,
        directories: Iterable[Path] = ...,
        try_module_name: bool = ...,
        try_build_id: bool = ...,
        try_debug_link: bool = ...,
        try_procfs: bool = ...,
        try_embedded_vdso: bool = ...,
        try_reuse: bool = ...,
        try_supplementary: bool = ...,
        kernel_directories: Iterable[Path] = ...,
        try_kmod: KmodSearchMethod = ...,
    ) -> None:
        """
        Create a ``DebugInfoOptions``.

        :param options: If given, create a copy of the given options.
            Otherwise, use the default options.

        Any remaining arguments override the copied/default options.
        """
        ...
    directories: Tuple[str, ...]
    """
    Directories to search for debugging information files.

    Defaults to ``("/usr/lib/debug",)``, which should work out of the box on
    most Linux distributions. Empty strings are not allowed.

    By default, this is used for searches by build ID (see
    :attr:`try_build_id`), debug link (see :attr:`debug_link_directories`), for
    supplementary files (see :attr:`try_supplementary`), and for kernel files
    (see :attr:`kernel_directories`).
    """
    try_module_name: bool
    """
    If the name of a module resembles a filesystem path, try the file at that
    path.

    Defaults to ``True``.
    """
    try_build_id: bool
    """
    Try finding files using build IDs.

    Defaults to ``True``.

    A *build ID* is a unique byte string present in a module's :ref:`loaded
    file <module-loaded-file>` and :ref:`debug file <module-debug-file>`. If
    configured correctly, it is also present in core dumps and provides a
    reliable way to identify the correct files for a module.

    Searches by build ID check under each path in :attr:`directories` for a
    file named ``.build-id/xx/yyyy`` (for loaded files) or
    ``.build-id/xx/yyyy.debug`` (for debug files), where ``xxyyyy`` is the
    lowercase hexadecimal representation of the build ID.
    """
    debug_link_directories: Tuple[str, ...]
    """
    Directories to search for debug links.

    Defaults to ``("$ORIGIN", "$ORIGIN/.debug", "")``, which should work out of
    the box on most Linux distributions.

    ``$ORIGIN`` (or ``${ORIGIN}``) is replaced with the absolute path of the
    directory containing the loaded file. An empty string means to check under
    each path in :attr:`directories` (i.e., ``path$ORIGIN`` for each path in
    :attr:`directories`).

    See :attr:`try_debug_link`.
    """
    try_debug_link: bool
    """
    Try finding files using debug links.

    Defaults to ``True``.

    A *debug link* is a pointer in a module's :ref:`loaded file
    <module-loaded-file>` to its :ref:`debug file <module-debug-file>`. It
    consists of a name and a checksum.

    Searches by debug link check every path in :attr:`debug_link_directories`
    for a file with a matching name and checksum.
    """
    try_procfs: bool
    """
    For local processes, try getting files via the ``proc`` filesystem (e.g.,
    :manpage:`proc_pid_exe(5)`, :manpage:`proc_pid_map_files(5)`).

    Defaults to ``True``.
    """
    try_embedded_vdso: bool
    """
    Try reading the vDSO embedded in a process's memory/core dump.

    Defaults to ``True``.

    The entire (stripped) vDSO is included in core dumps, so this is a reliable
    way to get it.
    """
    try_reuse: bool
    """
    Try reusing a module's loaded file as its debug file and vice versa.

    Defaults to ``True``.
    """
    try_supplementary: bool
    """
    Try finding :ref:`supplementary files <module-supplementary-debug-file>`.

    Defaults to ``True``.
    """
    kernel_directories: Tuple[str, ...]
    """
    Directories to search for the kernel image and loadable kernel modules.

    Defaults to ``("",)``.

    An empty string means to check standard paths (e.g.,
    :file:`/boot/vmlinux-{release}`, :file:`/lib/modules/{release}`) absolutely
    and under each path in :attr:`directories`.
    """
    try_kmod: KmodSearchMethod
    """
    How to search for loadable kernel modules.

    Defaults to :attr:`KmodSearchMethod.DEPMOD_OR_WALK`.
    """

class KmodSearchMethod(enum.Enum):
    """
    Methods of searching for loadable kernel module debugging information.

    In addition to searching by build ID, there are currently two methods of
    searching for debugging information specific to loadable kernel modules:

    1. Using :manpage:`depmod(8)` metadata. This looks for :command:`depmod`
       metadata (specifically, :file:`modules.dep.bin`) at the top level of
       each directory in :attr:`DebugInfoOptions.kernel_directories` (an empty
       path means :file:`/lib/modules/{release}`). The metadata is used to
       quickly find the path of each module, which is then checked relative to
       each directory specified by :attr:`DebugInfoOptions.kernel_directories`.

       This method is faster but typically only applicable to installed
       kernels.
    2. Walking kernel directories. This traverses each directory specified by
       :attr:`DebugInfoOptions.kernel_directories` looking for ``.ko`` files.
       Module names are matched to filenames before the ``.ko`` extension and
       with dashes (``-``) replaced with underscores (``_``).

       This method is slower but not limited to installed kernels.

    Debugging information searches can be configured to use one, both, or
    neither method.
    """

    NONE = ...
    """Don't search using kernel module-specific methods."""
    DEPMOD = ...
    """Search using :command:`depmod` metadata."""
    WALK = ...
    """Search by walking kernel directories."""
    DEPMOD_OR_WALK = ...
    """
    Search using :command:`depmod` metadata, falling back to walking kernel
    directories only if no :command:`depmod` metadata is found.

    Since :command:`depmod` metadata is expected to be reliable if present,
    this is the default.
    """
    DEPMOD_AND_WALK = ...
    """
    Search using :command:`depmod` metadata and by walking kernel directories.

    Unlike :attr:`DEPMOD_OR_WALK`, if :command:`depmod` metadata is found but
    doesn't result in the desired debugging information, this will still walk
    kernel directories.
    """

def get_default_prog() -> Program:
    """
    Get the default program for the current thread.

    :raises NoDefaultProgramError: if the default program is not set
    """
    ...

def set_default_prog(__prog: Optional[Program]) -> None:
    """
    Set the default program for the current thread.

    :param prog: Program to set as the default, or ``None`` to unset it.
    """
    ...

class NoDefaultProgramError(Exception):
    """
    Error raised when trying to use the default program when it is not set.
    """

    ...

class Module:
    """
    A ``Module`` represents an executable, library, or other binary file used
    by a program. It has several subclasses representing specific types of
    modules.

    Modules are uniquely identified by their type, name, and a type-specific
    value.

    Modules have several attributes that are determined automatically whenever
    possible but may be overridden manually if needed.

    Modules can be assigned files that provide debugging and runtime
    information:

    * .. _module-loaded-file:

      The "loaded file" is the file containing the executable code, data, etc.
      used by the program at runtime.


    * .. _module-debug-file:

      The "debug file" is the file containing debugging information (e.g.,
      `DWARF <https://dwarfstd.org/>`_).

      The loaded file and debug file may be the same file, for example, an
      unstripped binary. They may be different files if the binary was stripped
      and its debugging information was split into a separate file.


    * .. _module-supplementary-debug-file:

      The debug file may depend on a "supplementary debug file" such as one
      generated by `dwz(1) <https://manpages.debian.org/dwz.1.html>`_. If so,
      then the supplementary debug file must be found before the debug file can
      be used.
    """

    prog: Final[Program]
    """Program that this module is from."""
    name: Final[str]
    """
    Name of this module.

    Its exact meaning varies by module type.
    """
    address_ranges: Optional[Sequence[Tuple[int, int]]]
    """
    Address ranges where this module is loaded.

    This is a sequence of tuples of the start (inclusive) and end (exclusive)
    addresses. For each range, the start address is strictly less than the end
    address. If the module is not loaded in memory, then the sequence is empty.
    If not known yet, then this is ``None``.

    :meth:`Program.loaded_modules()` sets this automatically from the program
    state/core dump when possible. Otherwise, for :class:`MainModule`,
    :class:`SharedLibraryModule`, and :class:`VdsoModule`, it may be set
    automatically when a file is assigned to the module. It is never set
    automatically for :class:`ExtraModule`. It can also be set manually.

    Other than Linux kernel loadable modules, most modules have only one
    address range. See :attr:`address_range`.
    """
    address_range: Optional[Tuple[int, int]]
    """
    Address range where this module is loaded.

    This is an alias of :attr:`address_ranges[0] <address_ranges>` with a
    couple of small differences:

    * If the module has more than one address range, then reading this raises a
      :class:`ValueError`.
    * If the module is not loaded in memory, then this is ``(0, 0)``.
    """
    build_id: Optional[bytes]
    """
    Unique byte string (e.g., GNU build ID) identifying files used by this
    module.

    If not known, then this is ``None``.

    :meth:`Program.loaded_modules()` sets this automatically from the program
    state/core dump when possible. Otherwise, when a file is assigned to the
    module, it is set to the file's build ID if it is not already set. It can
    also be set manually.
    """
    object: Object
    """
    The object associated with this module.

    For Linux kernel loadable modules, this is the ``struct module *``
    associated with the kernel module. For other kinds, this is currently an
    absent object. The object may be set manually.
    """
    loaded_file_status: ModuleFileStatus
    """Status of the module's :ref:`loaded file <module-loaded-file>`."""
    loaded_file_path: Optional[str]
    """
    Absolute path of the module's :ref:`loaded file <module-loaded-file>`, or
    ``None`` if not known.
    """
    loaded_file_bias: Optional[int]
    """
    Difference between the load address in the program and addresses in the
    :ref:`loaded file <module-loaded-file>` itself.

    This is often non-zero due to address space layout randomization (ASLR).

    It is set automatically based on the module type when the loaded file is
    added:

    * For :class:`MainModule`, it is set based on metadata from the process or
      core dump (the `auxiliary vector
      <https://man7.org/linux/man-pages/man3/getauxval.3.html>`_ for userspace
      programs, the ``VMCOREINFO`` note for the Linux kernel).
    * For :class:`SharedLibraryModule` and :class:`VdsoModule`, it is set to
      :attr:`~SharedLibraryModule.dynamic_address` minus the address of the
      dynamic section in the file.
    * For :class:`RelocatableModule`, it is set to zero. Addresses are adjusted
      according to :attr:`~RelocatableModule.section_addresses` instead.
    * For :class:`ExtraModule`, if :attr:`~Module.address_ranges` is set to a
      single range before the file is added, then the bias is set to
      :attr:`address_ranges[0][0] <Module.address_ranges>` (i.e., the module's
      start address) minus the file's start address. If
      :attr:`~Module.address_ranges` is not set when the file is added, is
      empty, or comprises more than one range, then the bias is set to zero.

    This cannot be set manually.
    """
    debug_file_status: ModuleFileStatus
    """Status of the module's :ref:`debug file <module-debug-file>`."""
    debug_file_path: Optional[str]
    """
    Absolute path of the module's :ref:`debug file <module-debug-file>`, or
    ``None`` if not known.
    """
    debug_file_bias: Optional[int]
    """
    Difference between the load address in the program and addresses in the
    :ref:`debug file <module-debug-file>`.

    See :attr:`loaded_file_bias`.
    """
    supplementary_debug_file_kind: Optional[SupplementaryFileKind]
    """
    Kind of the module's :ref:`supplementary debug file
    <module-supplementary-debug-file>`, or ``None`` if not known or not needed.
    """
    supplementary_debug_file_path: Optional[str]
    """
    Absolute path of the module's :ref:`supplementary debug file
    <module-supplementary-debug-file>`, or ``None`` if not known or not needed.
    """

    def wants_loaded_file(self) -> bool:
        """
        Return whether this module wants a :ref:`loaded file
        <module-loaded-file>`.

        This should be preferred over checking :attr:`loaded_file_status`
        directly since this is future-proof against new status types being
        added. It is currently equivalent to ``module.loaded_file_status ==
        ModuleFileStatus.WANT``.
        """
        ...

    def wants_debug_file(self) -> bool:
        """
        Return whether this module wants a :ref:`debug file
        <module-debug-file>`.

        This should be preferred over checking :attr:`debug_file_status`
        directly since this is future-proof against new status types being
        added. It is currently equivalent to ``module.debug_file_status ==
        ModuleFileStatus.WANT or module.debug_file_status ==
        ModuleFileStatus.WANT_SUPPLEMENTARY``.
        """
        ...

    def wanted_supplementary_debug_file(self) -> WantedSupplementaryFile:
        """
        Return information about the :ref:`supplementary debug file
        <module-supplementary-debug-file>` that this module currently wants.

        :raises ValueError: if the module doesn't currently want a
            supplementary debug file (i.e., ``module.debug_file_status !=
            ModuleFileStatus.WANT_SUPPLEMENTARY``)
        """
        ...

    def try_file(
        self,
        path: Path,
        *,
        fd: int = -1,
        force: bool = False,
    ) -> None:
        """
        Try to use the given file for this module.

        If the file does not appear to belong to this module, then it is
        ignored. This currently checks that the file and the module have the
        same build ID.

        If :attr:`loaded_file_status` is :attr:`~ModuleFileStatus.WANT` and the
        file is loadable, then it is used as the :ref:`loaded file
        <module-loaded-file>` and :attr:`loaded_file_status` is set to
        :attr:`~ModuleFileStatus.HAVE`.

        If :attr:`debug_file_status` is :attr:`~ModuleFileStatus.WANT` or
        :attr:`~ModuleFileStatus.WANT_SUPPLEMENTARY` and the file provides
        debugging information, then it is used as the :ref:`debug file
        <module-debug-file>` and :attr:`debug_file_status` is set to
        :attr:`~ModuleFileStatus.HAVE`. However, if the file requires a
        supplementary debug file, then it is not used as the debug file yet and
        :attr:`debug_file_status` is set to
        :attr:`~ModuleFileStatus.WANT_SUPPLEMENTARY` instead.

        If :attr:`debug_file_status` is
        :attr:`~ModuleFileStatus.WANT_SUPPLEMENTARY` and the file matches
        :meth:`wanted_supplementary_debug_file()`, then the previously found
        file is used as the debug file, the given file is used as the
        :ref:`supplementary debug file <module-supplementary-debug-file>`, and
        :attr:`debug_file_status` is set to :attr:`~ModuleFileStatus.HAVE`.

        The file may be used as both the loaded file and debug file if
        applicable.

        :param path: Path to file.
        :param fd: If nonnegative, an open file descriptor referring to the
            file. This always takes ownership of the file descriptor even if
            the file is not used or on error, so the caller must not close it.
        :param force: If ``True``, then don't check whether the file matches
            the module.
        """
        ...

class MainModule(Module):
    """
    Main module.

    There is only one main module in a program. For userspace programs, it is
    the executable, and its name is usually the absolute path of the
    executable. For the Linux kernel, it is the kernel image, a.k.a.
    ``vmlinux``, and its name is "kernel".
    """

class SharedLibraryModule(Module):
    """
    Shared library (a.k.a. dynamic library, dynamic shared object, or ``.so``)
    module.

    Shared libraries are uniquely identified by their name (usually the
    absolute path of the shared object file) and dynamic address.
    """

    dynamic_address: Final[int]
    """Address of the shared object's dynamic section."""

class VdsoModule(Module):
    """
    Virtual dynamic shared object (vDSO) module.

    The vDSO is a special shared library automatically loaded into a process by
    the kernel; see :manpage:`vdso(7)`. It is uniquely identified by its name
    (the ``SONAME`` field of the shared object file) and dynamic address.
    """

    dynamic_address: Final[int]
    """Address of the shared object's dynamic section."""

class RelocatableModule(Module):
    """
    Relocatable object module.

    A relocatable object is an object file requiring a linking step to assign
    section addresses and adjust the file to reference those addresses.

    Linux kernel loadable modules (``.ko`` files) are a special kind of
    relocatable object.

    For userspace programs, relocatable objects are usually intermediate
    products of the compilation process (``.o`` files). They are not typically
    loaded at runtime. However, drgn allows manually defining a relocatable
    module and assigning its section addresses if needed.

    Relocatable modules are uniquely identified by a name and address.
    """

    address: Final[int]
    """
    Address identifying the module.

    For Linux kernel loadable modules, this is the module base address.
    """

    section_addresses: MutableMapping[str, int]
    """
    Mapping from section names to assigned addresses.

    Once a file has been assigned to the module, this can no longer be
    modified.

    :meth:`Program.linux_kernel_loadable_module()` and
    :meth:`Program.loaded_modules()` prepopulate this for Linux kernel loadable
    modules.
    """

class ExtraModule(Module):
    """
    Module with extra debugging information.

    For advanced use cases, it may be necessary to manually add debugging
    information that does not fit into any of the categories above.
    ``ExtraModule`` is intended for these use cases. For example, it can be
    used to add debugging information from a standalone file that is not in use
    by a particular program.

    Extra modules are uniquely identified by a name and ID number. Both the
    name and ID number are arbitrary.
    """

    id: Final[int]
    """Arbitrary identification number."""

class ModuleFileStatus(enum.Enum):
    """
    Status of a file in a :class:`Module`.

    This is usually used to communicate with debugging information finders; see
    :meth:`Program.register_debug_info_finder()`.
    """

    WANT = ...
    """File has not been found and should be searched for."""

    HAVE = ...
    """File has already been found and assigned."""

    DONT_WANT = ...
    """
    File has not been found, but it should not be searched for.

    :meth:`Module.try_file()` and debugging information finders are required to
    honor this and will never change it. However, other operations may reset
    this to :attr:`WANT` when they load debugging information automatically.
    """

    DONT_NEED = ...
    """
    File has not been found and is not needed (e.g., because its debugging
    information is not applicable or is provided through another mechanism).

    In contrast to :attr:`DONT_WANT`, drgn itself will never change this to
    :attr:`WANT`.
    """

    WANT_SUPPLEMENTARY = ...
    """
    File has been found, but it requires a supplementary file before it can be
    used. See :meth:`Module.wanted_supplementary_debug_file()`.
    """

class WantedSupplementaryFile(NamedTuple):
    """Information about a wanted supplementary file."""

    kind: SupplementaryFileKind
    """Kind of supplementary file."""
    path: str
    """Path of main file that wants the supplementary file."""
    supplementary_path: str
    """
    Path to the supplementary file.

    This may be absolute or relative to :attr:`path`.
    """
    checksum: bytes
    """
    Unique identifier of the supplementary file.

    The interpretation depends on :attr:`kind`.
    """

class SupplementaryFileKind(enum.Enum):
    """
    Kind of supplementary file.

    .. note::
        DWARF 5 supplementary files are not currently supported but may be in
        the future.

        DWARF package files are not considered supplementary files. They are
        considered part of the debug file and must have the same path as the
        debug file plus a ".dwp" extension.
    """

    GNU_DEBUGALTLINK = ...
    """
    GNU-style supplementary debug file referred to by a ``.gnu_debugaltlink``
    section.

    Its :attr:`~WantedSupplementaryFile.checksum` is the file's GNU build ID.
    """

class Thread:
    """A thread in a program."""

    tid: Final[int]
    """Thread ID (as defined by :manpage:`gettid(2)`)."""
    name: Optional[str]
    """
    Thread name, or ``None`` if unknown.

    See `PR_SET_NAME
    <https://man7.org/linux/man-pages/man2/PR_SET_NAME.2const.html>`_ and
    `/proc/pid/comm
    <https://man7.org/linux/man-pages/man5/proc_pid_comm.5.html>`_.

    .. note::
        Linux userspace core dumps only save the name of the main thread, so
        :attr:`name` will be ``None`` for other threads.
    """
    object: Final[Object]
    """
    If the program is the Linux kernel, the ``struct task_struct *`` object for
    this thread. Otherwise, not defined.
    """
    def stack_trace(self) -> StackTrace:
        """
        Get the stack trace for this thread.

        This is equivalent to ``prog.stack_trace(thread.tid)``. See
        :meth:`Program.stack_trace()`.
        """
        ...

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

def program_from_core_dump(path: Union[Path, int]) -> Program:
    """
    Create a :class:`Program` from a core dump file. The type of program (e.g.,
    userspace or kernel) is determined automatically.

    :param path: Core dump file path or open file descriptor.
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
    """

    def __init__(
        self, arch: Architecture, flags: Optional[PlatformFlags] = None
    ) -> None:
        """
        Create a ``Platform``.

        :param arch: :attr:`Platform.arch`
        :param flags: :attr:`Platform.flags`; if ``None``, default flags for
            the architecture are used.
        """
        ...
    arch: Final[Architecture]
    """Instruction set architecture of this platform."""

    flags: Final[PlatformFlags]
    """Flags which apply to this platform."""

    registers: Final[Sequence[Register]]
    """Processor registers on this platform."""

class Architecture(enum.Enum):
    """An ``Architecture`` represents an instruction set architecture."""

    X86_64 = ...
    """The x86-64 architecture, a.k.a. AMD64 or Intel 64."""

    I386 = ...
    """The 32-bit x86 architecture, a.k.a. i386 or IA-32."""

    AARCH64 = ...
    """The AArch64 architecture, a.k.a. ARM64."""

    ARM = ...
    """The 32-bit Arm architecture."""

    PPC64 = ...
    """The 64-bit PowerPC architecture."""

    RISCV64 = ...
    """The 64-bit RISC-V architecture."""

    RISCV32 = ...
    """The 32-bit RISC-V architecture."""

    S390X = ...
    """The s390x architecture, a.k.a. IBM Z or z/Architecture."""

    S390 = ...
    """The 32-bit s390 architecture, a.k.a. System/390."""

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

    names: Final[Sequence[str]]
    """Names of this register."""

host_platform: Platform
"""The platform of the host which is running drgn."""

class Language:
    """
    A ``Language`` represents a programming language supported by drgn.

    This class cannot be constructed; there are singletons for the supported
    languages.
    """

    name: Final[str]
    """Name of the programming language."""

    C: ClassVar[Language]
    """The C programming language."""

    CPP: ClassVar[Language]
    """The C++ programming language."""

class Object:
    """
    An ``Object`` represents a symbol or value in a program. An object may
    exist in the memory of the program (a *reference*), it may be a constant or
    temporary computed value (a *value*), or it may be absent entirely (an
    *absent* object).

    All instances of this class have two attributes: :attr:`prog_`, the program
    that the object is from; and :attr:`type_`, the type of the object.
    Reference objects also have an :attr:`address_` and a :attr:`bit_offset_`.
    Objects may also have a :attr:`bit_field_size_`.

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
        format instead of with ``repr()`` (the latter is the default behavior
        of Python's interactive mode). Therefore, it's usually not necessary to
        call ``print()`` in the drgn CLI.

    Objects support the following operators:

    * Arithmetic operators: ``+``, ``-``, ``*``, ``/``, ``%``
    * Bitwise operators: ``<<``, ``>>``, ``&``, ``|``, ``^``, ``~``
    * Relational operators: ``==``, ``!=``, ``<``, ``>``, ``<=``, ``>=``
    * Subscripting: :meth:`[] <__getitem__>` (Python does not have a unary
      ``*`` operator, so pointers are dereferenced with ``ptr[0]``)
    * Member access: :meth:`. <__getattr__>` (Python does not have a ``->``
      operator, so ``.`` is also used to access members of pointers to
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
    """

    @overload
    def __init__(
        self,
        prog: Program,
        type: Union[str, Type],
        # This should use numbers.Number, but mypy doesn't support it yet; see
        # python/mypy#3186. Additionally, once mypy supports recursive types,
        # we can make the Mapping and Sequence item types stricter; see
        # python/mypy#731.
        value: Union[IntegerLike, float, bool, Mapping[str, Any], Sequence[Any]],
        *,
        bit_field_size: Optional[IntegerLike] = None,
    ) -> None:
        """
        Create a value object given its type and value.

        :param prog: Program to create the object in.
        :param type: Type of the object.
        :param value: Value of the object. See :meth:`value_()`.
        :param bit_field_size: Size in bits of the object if it is a bit field.
            The default is ``None``, which means the object is not a bit field.
        """
        ...

    @overload
    def __init__(self, prog: Program, *, value: Union[int, float, bool]) -> None:
        """
        Create a value object from a "literal".

        This is used to emulate a literal number in the source code of the
        program. The type is deduced from *value* according to the language's
        rules for literals.

        :param value: Value of the literal.
        """
        ...

    @overload
    def __init__(
        self,
        prog: Program,
        type: Union[str, Type],
        *,
        address: IntegerLike,
        bit_offset: IntegerLike = 0,
        bit_field_size: Optional[IntegerLike] = None,
    ) -> None:
        """
        Create a reference object.

        :param address: Address of the object in the program.
        :param bit_offset: Offset in bits from *address* to the beginning of
            the object.
        """
        ...

    @overload
    def __init__(
        self,
        prog: Program,
        type: Union[str, Type],
        *,
        absence_reason: AbsenceReason = AbsenceReason.OTHER,
        bit_field_size: Optional[IntegerLike] = None,
    ) -> None:
        """Create an absent object."""
        ...
    prog_: Final[Program]
    """Program that this object is from."""

    type_: Final[Type]
    """Type of this object."""

    address_: Final[Optional[int]]
    """
    Address of this object if it is a reference, ``None`` if it is a value or
    absent.
    """

    absent_: Final[bool]
    """
    Whether this object is absent.

    This is ``False`` for all values and references (even if the reference has
    an invalid address).
    """

    absence_reason_: Final[Optional[AbsenceReason]]
    """
    Reason that this object is absent.

    This is ``None`` for all values and references.
    """

    bit_offset_: Final[Optional[int]]
    """
    Offset in bits from this object's address to the beginning of the object if
    it is a reference, ``None`` otherwise. This can only be non-zero for
    scalars.
    """

    bit_field_size_: Final[Optional[int]]
    """
    Size in bits of this object if it is a bit field, ``None`` if it is not.
    """
    def __getattr__(self, name: str) -> Object:
        """
        Implement ``self.name``.

        This corresponds to both the member access (``.``) and member access
        through pointer (``->``) operators in C.

        Note that if *name* is an attribute or method of the :class:`Object`
        class, then that takes precedence. Otherwise, this is equivalent to
        :meth:`member_()`.

        >>> print(prog['init_task'].pid)
        (pid_t)0

        :param name: Attribute name.
        """
        ...

    @overload
    def __getitem__(self, /, i: IntegerLike) -> Object:
        """
        Implement ``self[i]``. Get the array element at the given index.

        This is only valid for pointers and arrays.

        >>> print(prog["init_task"].comm[1])
        (char)119

        ``[0]`` is also the equivalent of the pointer dereference (``*``)
        operator in C:

        >>> ptr_to_ptr
        *(void **)0xffff9b86801e2968 = 0xffff9b86801e2460
        >>> print(ptr_to_ptr[0])
        (void *)0xffff9b86801e2460

        .. note::

            Negative indices are relative to the start of the pointer/array
            (like in C), not relative to the end (like for Python lists).

            >>> ptr[-2].address_of_() == ptr - 2
            True

        :param i: Index.
        :raises TypeError: if this object is not a pointer or array
        """
        ...

    @overload
    def __getitem__(self, /, s: slice) -> Object:
        """
        Implement ``self[start:stop]``. Get an array :term:`slice`.

        This is only valid for pointers and arrays. It creates a new array for
        the range of elements from the (inclusive) start index to the
        (exclusive) stop index. The length of the resulting array is therefore
        the stop index minus the start index, or zero if the stop index is less
        than the start index.

        If the start index is omitted, it defaults to 0. If the stop index is
        omitted, it defaults to the length of the array (in which case the
        object must be a complete array).

        For example, this can be used to get a subset of an array:

        >>> prog["init_task"].comm[1:3]
        (char [2])"wa"

        Or to get a complete array from a pointer/incomplete array with a
        separate length:

        >>> poll_list
        *(struct poll_list *)0xffffa3d3c126fa70 = {
                .next = (struct poll_list *)0x0,
                .len = (unsigned int)2,
                .entries = (struct pollfd []){},
        }
        >>> poll_list.entries[:poll_list.len]
        (struct pollfd [2]){
                {
                        .fd = (int)6,
                        .events = (short)1,
                        .revents = (short)0,
                },
                {
                        .fd = (int)14,
                        .events = (short)1,
                        .revents = (short)0,
                },
        }

        .. note::

            Negative indices are relative to the start of the pointer/array
            (like in C), not relative to the end (like for Python lists).

            >>> prog['init_task'].comm[-2:]
            (char [18])""
            >>> prog['init_task'].comm[:-2]
            (char [0]){}

        :param s: Slice.
        :raises TypeError: if this object is not a pointer or array
        :raises TypeError: if the stop index is omitted and this object is not
            an array with complete type
        """

    def __len__(self) -> int:
        """
        Implement ``len(self)``. Get the number of elements in this object.

        >>> len(prog["init_task"].comm)
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

        .. note::
            Helpers that wish to accept an argument that may be an
            :class:`Object` or an :class:`int` should use
            :func:`operator.index()` and :class:`IntegerLike` instead:

            .. code-block:: python3

                import operator
                from drgn import IntegerLike

                def my_helper(i: IntegerLike) -> ...:
                    value = operator.index(i)  # Returns an int
                    ...

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

        This is valid for structures, unions, classes, and pointers to any of
        those. If the object is a pointer, it is automatically dereferenced
        first.

        Normally the dot operator (:meth:`. <__getattr__>`) can be used to
        accomplish the same thing, but this method can be used if there is a
        name conflict with an ``Object`` attribute or method.

        :param name: Name of the member.
        :raises TypeError: if this object is not a structure, union, class, or
            a pointer to one of those
        :raises LookupError: if this object does not have a member with the
            given name
        """
        ...

    def subobject_(self, designator: str) -> Object:
        """
        Get a subobject (member or element) of this object.

        Usually, a combination of the :meth:`. <__getattr__>` and :meth:`[]
        <.__getitem__>` operators can be used instead, but this can be used as:

        1. A variant of :meth:`member_()` that doesn't automatically
           dereference pointers.
        2. A generalization of :func:`offsetof()`.

        >>> prog["init_task"].subobject_("comm[0]") == prog["init_task"].comm[0]
        True

        :param designator: One or more member references or array subscripts.
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

    def to_bytes_(self) -> bytes:
        """Return the binary representation of this object's value."""
        ...

    @classmethod
    def from_bytes_(
        cls,
        prog: Program,
        type: Union[str, Type],
        bytes: Buffer,
        *,
        bit_offset: IntegerLike = 0,
        bit_field_size: Optional[IntegerLike] = None,
    ) -> Object:
        r"""
        Return a value object from its binary representation.

        >>> print(Object.from_bytes_(prog, "int", b"\x10\x00\x00\x00"))
        (int)16

        :param prog: Program to create the object in.
        :param type: Type of the object.
        :param bytes: Buffer containing value of the object.
        :param bit_offset: Offset in bits from the beginning of *bytes* to the
            beginning of the object.
        :param bit_field_size: Size in bits of the object if it is a bit field.
            The default is ``None``, which means the object is not a bit field.
        """
        ...

    def format_(
        self,
        *,
        columns: Optional[IntegerLike] = None,
        integer_base: Optional[IntegerLike] = None,
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
        :param integer_base: Base to format integers in (8, 10, or 16).
            Defaults to 10.
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
    def _repr_pretty_(self, p: Any, cycle: bool) -> None: ...

class AbsenceReason(enum.Enum):
    """Reason an object is :ref:absent <absent-objects>`."""

    OTHER = ...
    """Another reason not listed below."""
    OPTIMIZED_OUT = ...
    """Object was optimized out by the compiler."""
    NOT_IMPLEMENTED = ...
    """Encountered unknown debugging information."""

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
    Get the value of an object explicitly casted to another type.

    This uses the programming language's rules for explicit conversions, like
    the cast operator.

    >>> cast("unsigned int", Object(prog, "float", 2.0))
    (unsigned int)2
    >>> cast("void *", Object(prog, "int", 0))
    (void *)0x0

    See also :func:`implicit_convert()` for implicit conversions (which usually
    do stricter type checking) and :func:`reinterpret()` for reinterpreting the
    raw memory of an object.

    :param type: Type to cast to.
    :param obj: Object to cast.
    :return: Casted object. This is always a value object.
    :raises TypeError: if casting *obj* to *type* is not allowed
    """
    ...

def implicit_convert(type: Union[str, Type], obj: Object) -> Object:
    """
    Get the value of an object implicitly converted to another type.

    This uses the programming language's rules for implicit conversions, like
    when assigning to a variable or passing arguments to a function call.

    >>> implicit_convert("unsigned int", Object(prog, "float", 2.0))
    (unsigned int)2
    >>> implicit_convert("void *", Object(prog, "int", 0))
    Traceback (most recent call last):
      ...
    TypeError: cannot convert 'int' to incompatible type 'void *'

    See also :func:`cast()` for explicit conversions and :func:`reinterpret()`
    for reinterpreting the raw memory of an object.

    :param type: Type to convert to.
    :param obj: Object to convert.
    :return: Converted object. This is always a value object.
    :raises TypeError: if converting *obj* to *type* is not allowed
    """
    ...

def reinterpret(type: Union[str, Type], obj: Object) -> Object:
    """
    Get the representation of an object reinterpreted as another type.

    This reinterprets the raw memory of the object, so an object can be
    reinterpreted as any other type.

    >>> reinterpret("unsigned int", Object(prog, "float", 2.0))
    (unsigned int)1073741824

    .. note::

        You usually want :func:`cast()` or :func:`implicit_convert()` instead,
        which convert the *value* of an object instead of its in-memory
        representation.

    :param type: Type to reinterpret as.
    :param obj: Object to reinterpret.
    :return: Reinterpreted object. If *obj* is a reference object, then this is
        a reference object. If *obj* is a value object, then this is a value
        object.
    :raises OutOfBoundsError: if *obj* is a value object and *type* is larger
        than *obj*
    """
    ...

def container_of(ptr: Object, type: Union[str, Type], member: str) -> Object:
    """
    Get the containing object of a pointer object.

    This corresponds to the ``container_of()`` macro in C.

    :param ptr: Pointer to member in containing object.
    :param type: Type of containing object.
    :param member: Name of member in containing object. May include one or more
        member references and zero or more array subscripts.
    :return: Pointer to containing object.
    :raises TypeError: if *ptr* is not a pointer or *type* is not a structure,
        union, or class type
    :raises ValueError: if the member is not byte-aligned (e.g., because it is
        a bit field)
    :raises LookupError: if *type* does not have a member with the given name
    """
    ...

class Symbol:
    """
    A ``Symbol`` represents an entry in the symbol table of a program, i.e., an
    identifier along with its corresponding address range in the program.
    """

    def __init__(
        self,
        name: str,
        address: int,
        size: int,
        binding: SymbolBinding,
        kind: SymbolKind,
    ) -> None:
        """
        Create a ``Symbol``.

        :param name: :attr:`Symbol.name`
        :param address: :attr:`Symbol.address`
        :param size: :attr:`Symbol.size`
        :param binding: :attr:`Symbol.binding`
        :param kind: :attr:`Symbol.kind`
        """
        ...
    name: Final[str]
    """Name of this symbol."""

    address: Final[int]
    """Start address of this symbol."""

    size: Final[int]
    """Size of this symbol in bytes."""

    binding: Final[SymbolBinding]
    """Linkage behavior and visibility of this symbol."""

    kind: Final[SymbolKind]
    """Kind of entity represented by this symbol."""

class SymbolIndex:
    """
    A ``SymbolIndex`` contains a static set of symbols and allows efficient
    lookup by name and address.

    With :meth:`Program.register_symbol_finder()`, you can add a callback to
    provide custom symbol finding logic. However, in many cases, all that is
    necessary is to provide drgn with a list of symbols that you know to be part
    of the program. This object allows you to do that. It efficiently implements
    the Symbol Finder API given a static set of symbols. For example::

        >>> prog = drgn.Program()
        >>> symbol = drgn.Symbol("foo", 0x123, 1, drgn.SymbolBinding.GLOBAL, drgn.SymbolKind.OBJECT)
        >>> finder = drgn.SymbolIndex([symbol])
        >>> prog.register_symbol_finder("SymbolIndex", finder, enable_index=0)
        >>> prog.symbols()
        [Symbol(name='foo', address=0x123, size=0x1, binding=<SymbolBinding.GLOBAL: 2>, kind=<SymbolKind.OBJECT: 1>)]
        >>> prog.symbol("bar")
        Traceback (most recent call last):
          File "<console>", line 1, in <module>
        LookupError: not found
        >>> prog.symbol("foo")
        Symbol(name='foo', address=0x123, size=0x1, binding=<SymbolBinding.GLOBAL: 2>, kind=<SymbolKind.OBJECT: 1>)
        >>> prog.symbol(0x100)
        Traceback (most recent call last):
          File "<console>", line 1, in <module>
        LookupError: not found
        >>> prog.symbol(0x123)
        Symbol(name='foo', address=0x123, size=0x1, binding=<SymbolBinding.GLOBAL: 2>, kind=<SymbolKind.OBJECT: 1>)
    """

    def __init__(self, symbols: Iterable[Symbol]) -> None:
        """
        Create a ``SymbolIndex`` from a sequence of symbols

        The returned symbol index satisfies the Symbol Finder API. It supports
        overlapping symbol address ranges and duplicate symbol names. However,
        in the case of these sorts of conflicts, it doesn't provide any
        guarantee on the order of the results, or which result is returned when
        a single symbol is requested.

        :param symbols: An iterable of symbols
        :returns: A callable object suitable to provide to
          :meth:`Program.register_symbol_finder()`.
        """

    def __call__(
        self,
        prog: Program,
        name: Optional[str],
        address: Optional[int],
        one: bool,
    ) -> List[Symbol]:
        """
        Lookup symbol by name, address, or both.

        :param prog: (unused) the program looking up this symbol
        :param name: if given, only return symbols with this name
        :param address: if given, only return symbols spanning this address
        :param one: if given, limit the result to a single symbol
        :returns: a list of matching symbols (empty if none are found)
        """

class SymbolBinding(enum.Enum):
    """
    A ``SymbolBinding`` describes the linkage behavior and visibility of a
    symbol.
    """

    UNKNOWN = ...
    """Unknown."""

    LOCAL = ...
    """Not visible outside of the object file containing its definition."""

    GLOBAL = ...
    """Globally visible."""

    WEAK = ...
    """Globally visible but may be overridden by a non-weak global symbol."""

    UNIQUE = ...
    """
    Globally visible even if dynamic shared object is loaded locally. See GCC's
    ``-fno-gnu-unique`` `option
    <https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html>`_.
    """

class SymbolKind(enum.Enum):
    """
    A ``SymbolKind`` describes the kind of entity that a symbol represents.
    """

    UNKNOWN = ...
    """Unknown or not defined."""

    OBJECT = ...
    """Data object (e.g., variable or array)."""

    FUNC = ...
    """Function or other executable code."""

    SECTION = ...
    """Object file section."""

    FILE = ...
    """Source file."""

    COMMON = ...
    """Data object in common block."""

    TLS = ...
    """Thread-local storage entity."""

    IFUNC = ...
    """`Indirect function <https://sourceware.org/glibc/wiki/GNU_IFUNC>`_."""

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
            if frame.name == 'io_schedule':
                print('Thread is doing I/O')

    :class:`str() <str>` returns a pretty-printed stack trace:

    >>> prog.stack_trace(1)
    #0  context_switch (kernel/sched/core.c:4339:2)
    #1  __schedule (kernel/sched/core.c:5147:8)
    #2  schedule (kernel/sched/core.c:5226:3)
    #3  do_wait (kernel/exit.c:1534:4)
    #4  kernel_wait4 (kernel/exit.c:1678:8)
    #5  __do_sys_wait4 (kernel/exit.c:1706:13)
    #6  do_syscall_64 (arch/x86/entry/common.c:47:14)
    #7  entry_SYSCALL_64+0x7c/0x15b (arch/x86/entry/entry_64.S:112)
    #8  0x4d49dd

    The format is subject to change. The drgn CLI is set up so that stack
    traces are displayed with ``str()`` by default.
    """

    prog: Final[Program]
    """Program that this stack trace is from."""

    def __getitem__(self, idx: IntegerLike) -> StackFrame: ...
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[StackFrame]: ...
    def _repr_pretty_(self, p: Any, cycle: bool) -> None: ...

class StackFrame:
    """
    A ``StackFrame`` represents a single *frame* in a thread's call stack.

    :class:`str() <str>` returns a pretty-printed stack frame:

    >>> prog.stack_trace(1)[0]
    #0 at 0xffffffffb64ac287 (__schedule+0x227/0x606) in context_switch at kernel/sched/core.c:4339:2 (inlined)

    This includes more information than when printing the full stack trace. The
    format is subject to change. The drgn CLI is set up so that stack frames
    are displayed with ``str()`` by default.

    The :meth:`[] <.__getitem__>` operator can look up function parameters,
    local variables, and global variables in the scope of the stack frame:

    >>> prog.stack_trace(1)[0]['prev'].pid
    (pid_t)1
    >>> prog.stack_trace(1)[0]['scheduler_running']
    (int)1
    """

    name: Final[str]
    """
    Name of the function or symbol at this frame.

    This tries to get the best available name for this frame in the following
    order:

    1. The name of the function in the source code based on debugging
       information (:attr:`frame.function_name <function_name>`).
    2. The name of the symbol in the binary (:meth:`frame.symbol().name
       <symbol>`).
    3. The program counter in hexadecimal (:attr:`hex(frame.pc) <pc>`).
    4. The string "???".
    """

    function_name: Final[Optional[str]]
    """
    Name of the function at this frame, or ``None`` if it could not be
    determined.

    The name cannot be determined if debugging information is not available for
    the function, e.g., because it is implemented in assembly.
    """

    is_inline: Final[bool]
    """
    Whether this frame is for an inlined call.

    An inline frame shares the same stack frame in memory as its caller.
    Therefore, it has the same registers (including program counter and thus
    symbol).
    """

    interrupted: Final[bool]
    """
    Whether this stack frame was interrupted (for example, by a hardware
    interrupt, signal, trap, etc.).

    If this is ``True``, then the register values in this frame are the values
    at the time that the frame was interrupted.

    This is ``False`` if the frame is for a function call, in which case the
    register values are the values when control returns to this frame. In
    particular, the program counter is the return address, which is typically
    the instruction after the call instruction.
    """

    pc: Final[int]
    """Program counter at this stack frame."""

    sp: Final[int]
    """Stack pointer at this stack frame."""

    def __getitem__(self, name: str) -> Object:
        """
        Implement ``self[name]``. Get the object (variable, function parameter,
        constant, or function) with the given name in the scope of this frame.

        If the object exists but has been optimized out, this returns an
        :ref:`absent object <absent-objects>`.

        :param name: Object name.
        """
        ...

    def __contains__(self, name: str) -> bool:
        """
        Implement ``name in self``. Return whether an object with the given
        name exists in the scope of this frame.

        :param name: Object name.
        """
        ...

    def locals(self) -> List[str]:
        """
        Get a list of the names of all local objects (local variables, function
        parameters, local constants, and nested functions) in the scope of this
        frame.

        Not all names may have present values, but they can be used with the
        :meth:`[] <.__getitem__>` operator to check.
        """
        ...

    def source(self) -> Tuple[str, int, int]:
        """
        Get the source code location of this frame.

        :return: Location as a ``(filename, line, column)`` triple.
        :raises LookupError: if the source code location is not available
        """
        ...

    def symbol(self) -> Symbol:
        """
        Get the function symbol at this stack frame.

        This is equivalent to:

        .. code-block:: python3

            prog.symbol(frame.pc - (0 if frame.interrupted else 1))
        """
        ...

    def register(self, reg: str) -> int:
        """
        Get the value of the given register at this stack frame.

        :param reg: Register name.
        :raises ValueError: if the register name is not recognized
        :raises LookupError: if the register value is not known
        """
        ...

    def registers(self) -> Dict[str, int]:
        """
        Get the values of all available registers at this stack frame as a
        dictionary with the register names as keys.
        """
        ...

    def _repr_pretty_(self, p: Any, cycle: bool) -> None: ...

class Type:
    """
    A ``Type`` object describes a type in a program. Each kind of type (e.g.,
    integer, structure) has different attributes (e.g., name, size). Types can
    also have qualifiers (e.g., constant, atomic). Accessing an attribute which
    does not apply to a type raises an :exc:`AttributeError`.

    :func:`repr()` of a ``Type`` returns a Python representation of the type:

    >>> print(repr(prog.type('sector_t')))
    prog.typedef_type(name='sector_t', type=prog.int_type(name='unsigned long', size=8, is_signed=False))

    :class:`str() <str>` returns a representation of the type in programming
    language syntax:

    >>> print(prog.type('sector_t'))
    typedef unsigned long sector_t

    The drgn CLI is set up so that types are displayed with ``str()`` instead
    of ``repr()`` by default.

    This class cannot be constructed directly. Instead, use one of the
    :ref:`api-type-constructors`.
    """

    prog: Final[Program]
    """Program that this type is from."""

    kind: Final[TypeKind]
    """Kind of this type."""

    primitive: Final[Optional[PrimitiveType]]
    """
    If this is a primitive type (e.g., ``int`` or ``double``), the kind of
    primitive type. Otherwise, ``None``.
    """

    qualifiers: Final[Qualifiers]
    """Bitmask of this type's qualifier."""

    language: Final[Language]
    """Programming language of this type."""

    name: Final[str]
    """
    Name of this type. This is present for integer, boolean, floating-point,
    and typedef types.
    """

    tag: Final[Optional[str]]
    """
    Tag of this type, or ``None`` if this is an anonymous type. This is present
    for structure, union, class, and enumerated types.
    """

    size: Final[Optional[int]]
    """
    Size of this type in bytes, or ``None`` if this is an incomplete type. This
    is present for integer, boolean, floating-point, structure, union, class,
    and pointer types.
    """

    length: Final[Optional[int]]
    """
    Number of elements in this type, or ``None`` if this is an incomplete type.
    This is only present for array types.
    """

    is_signed: Final[bool]
    """Whether this type is signed. This is only present for integer types."""

    byteorder: Final[str]
    """
    Byte order of this type: ``'little'`` if it is little-endian, or ``'big'``
    if it is big-endian. This is present for integer, boolean, floating-point,
    and pointer types.
    """

    type: Final[Type]
    """
    Type underlying this type, defined as follows:

    * For typedef types, the aliased type.
    * For enumerated types, the compatible integer type, which is ``None`` if
      this is an incomplete type.
    * For pointer types, the referenced type.
    * For array types, the element type.
    * For function types, the return type.

    For other types, this attribute is not present.
    """

    members: Final[Optional[Sequence[TypeMember]]]
    """
    List of members of this type, or ``None`` if this is an incomplete type.
    This is present for structure, union, and class types.
    """

    enumerators: Final[Optional[Sequence[TypeEnumerator]]]
    """
    List of enumeration constants of this type, or ``None`` if this is an
    incomplete type. This is only present for enumerated types.
    """

    parameters: Final[Sequence[TypeParameter]]
    """
    List of parameters of this type. This is only present for function types.
    """

    is_variadic: Final[bool]
    """
    Whether this type takes a variable number of arguments. This is only
    present for function types.
    """

    template_parameters: Final[Sequence[TypeTemplateParameter]]
    """
    List of template parameters of this type. This is present for structure,
    union, class, and function types.
    """
    def type_name(self) -> str:
        """Get a descriptive full name of this type."""
        ...

    def variable_declaration(self, name: str) -> str:
        """
        Format a variable declaration with this type.

        >>> prog.type("int [4]").variable_declaration("my_array")
        'int my_array[4]'

        :param name: Name of the variable.
        :return: Variable declaration in programming language syntax.
        """

    def is_complete(self) -> bool:
        """
        Get whether this type is complete (i.e., the type definition is known).
        This is always ``False`` for void types. It may be ``False`` for
        structure, union, class, enumerated, and array types, as well as
        typedef types where the underlying type is one of those. Otherwise, it
        is always ``True``.
        """
        ...

    def qualified(self, qualifiers: Qualifiers) -> Type:
        """
        Get a copy of this type with different qualifiers.

        Note that the original qualifiers are replaced, not added to.

        :param qualifiers: New type qualifiers.
        """
        ...

    def unqualified(self) -> Type:
        """Get a copy of this type with no qualifiers."""
        ...

    def member(self, name: str) -> TypeMember:
        """
        Look up a member in this type by name.

        If this type has any unnamed members, this also matches members of
        those unnamed members, recursively. If the member is found in an
        unnamed member, :attr:`TypeMember.bit_offset` and
        :attr:`TypeMember.offset` are adjusted accordingly.

        :param name: Name of the member.
        :raises TypeError: if this type is not a structure, union, or class
            type
        :raises LookupError: if this type does not have a member with the given
            name
        """
        ...

    def has_member(self, name: str) -> bool:
        """
        Return whether this type has a member with the given name.

        If this type has any unnamed members, this also matches members of
        those unnamed members, recursively.

        :param name: Name of the member.
        :raises TypeError: if this type is not a structure, union, or class
            type
        """

    def _repr_pretty_(self, p: Any, cycle: bool) -> None: ...

class TypeMember:
    """
    A ``TypeMember`` represents a member of a structure, union, or class type.
    """

    def __init__(
        self,
        object_or_type: Union[Object, Type, Callable[[], Union[Object, Type]]],
        name: Optional[str] = None,
        bit_offset: int = 0,
    ) -> None:
        """
        Create a ``TypeMember``.

        :param object_or_type: One of:

            1. :attr:`TypeMember.object` as an :class:`Object`.
            2. :attr:`TypeMember.type` as a :class:`Type`. In this case,
               ``object`` is set to an absent object with that type.
            3. A callable that takes no arguments and returns one of the above.
               It is called when ``object`` or ``type`` is first accessed, and
               the result is cached.
        :param name: :attr:`TypeMember.name`
        :param bit_offset: :attr:`TypeMember.bit_offset`
        """
        ...
    object: Final[Object]
    """
    Member as an :class:`Object`.

    This is the default initializer for the member, or an absent object if the
    member has no default initializer. (However, the DWARF specification as of
    version 5 does not actually support default member initializers, so this is
    usually absent.)
    """

    type: Final[Type]
    """
    Member type.

    This is a shortcut for ``TypeMember.object.type``.
    """

    name: Final[Optional[str]]
    """Member name, or ``None`` if the member is unnamed."""

    bit_offset: Final[int]
    """Offset of the member from the beginning of the type in bits."""

    offset: Final[int]
    """
    Offset of the member from the beginning of the type in bytes. If the offset
    is not byte-aligned, accessing this attribute raises :exc:`ValueError`.
    """

    bit_field_size: Final[Optional[int]]
    """
    Size in bits of this member if it is a bit field, ``None`` if it is not.

    This is a shortcut for ``TypeMember.object.bit_field_size_``.
    """

class TypeEnumerator:
    """
    A ``TypeEnumerator`` represents a constant in an enumerated type.

    Its name and value may be accessed as attributes or unpacked:

    >>> prog.type('enum pid_type').enumerators[0].name
    'PIDTYPE_PID'
    >>> name, value = prog.type('enum pid_type').enumerators[0]
    >>> value
    0
    """

    def __init__(self, name: str, value: int) -> None:
        """
        Create a ``TypeEnumerator``.

        :param name: :attr:`TypeEnumerator.name`
        :param value: :attr:`TypeEnumerator.value`
        """
        ...
    name: Final[str]
    "Enumerator name."

    value: Final[int]
    "Enumerator value."
    def __len__(self) -> int: ...
    def __getitem__(self, idx: int) -> Any: ...
    def __iter__(self) -> Iterator[Any]: ...

class TypeParameter:
    """
    A ``TypeParameter`` represents a parameter of a function type.
    """

    def __init__(
        self,
        default_argument_or_type: Union[
            Object, Type, Callable[[], Union[Object, Type]]
        ],
        name: Optional[str] = None,
    ) -> None:
        """
        Create a ``TypeParameter``.

        :param default_argument_or_type: One of:

            1. :attr:`TypeParameter.default_argument` as an :class:`Object`.
            2. :attr:`TypeParameter.type` as a :class:`Type`. In this case,
               ``default_argument`` is set to an absent object with that type.
            3. A callable that takes no arguments and returns one of the above.
               It is called when ``default_argument`` or ``type`` is first
               accessed, and the result is cached.
        :param name: :attr:`TypeParameter.name`
        """
        ...
    default_argument: Final[Object]
    """
    Default argument for parameter.

    If the parameter does not have a default argument, then this is an absent
    object.

    .. note::

        Neither GCC nor Clang emits debugging information for default arguments
        (as of GCC 10 and Clang 11), and drgn does not yet parse it, so this is
        usually absent.
    """

    type: Final[Type]
    """
    Parameter type.

    This is the same as ``TypeParameter.default_argument.type_``.
    """

    name: Final[Optional[str]]
    """Parameter name, or ``None`` if the parameter is unnamed."""

class TypeTemplateParameter:
    """
    A ``TypeTemplateParameter`` represents a template parameter of a structure,
    union, class, or function type.
    """

    def __init__(
        self,
        argument: Union[Type, Object, Callable[[], Union[Type, Object]]],
        name: Optional[str] = None,
        is_default: bool = False,
    ) -> None:
        """
        Create a ``TypeTemplateParameter``.

        :param argument: One of:

            1. :attr:`TypeTemplateParameter.argument` as a :class:`Type` if the
               parameter is a type template parameter.
            2. :attr:`TypeTemplateParameter.argument` as a non-absent
               :class:`Object` if the parameter is a non-type template
               parameter.
            3. A callable that takes no arguments and returns one of the above.
               It is called when ``argument`` is first accessed, and the result
               is cached.
        :param name: :attr:`TypeTemplateParameter.name`
        :param is_default: :attr:`TypeTemplateParameter.is_default`
        """
        ...
    argument: Final[Union[Type, Object]]
    """
    Template argument.

    If this is a type template parameter, then this is a :class:`Type`. If this
    is a non-type template parameter, then this is an :class:`Object`.
    """

    name: Final[Optional[str]]
    """Template parameter name, or ``None`` if the parameter is unnamed."""

    is_default: Final[bool]
    """
    Whether :attr:`argument` is the default for the template parameter.

    .. note::

        There are two ways to interpret this:

            1. The argument was omitted entirely and thus defaulted to the
               default argument.
            2. The (specified or defaulted) argument is the same as the default
               argument.

        Compilers are inconsistent about which interpretation they use.

        GCC added this information in version 4.9. Clang added it in version 11
        (and only when emitting DWARF version 5). If the program was compiled
        by an older version, this is always false.
    """

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

class TypeKindSet(collections.abc.Set[TypeKind]):
    """
    Immutable set of :class:`TypeKind`\\ s.

    >>> kinds = TypeKindSet({TypeKind.STRUCT, TypeKind.CLASS})
    >>> TypeKind.STRUCT in kinds
    True
    >>> TypeKind.INT in kinds
    False
    >>> for kind in kinds:
    ...     print(kind)
    ...
    TypeKind.STRUCT
    TypeKind.CLASS
    """

    def __contains__(self, __x: object) -> bool: ...
    def __iter__(self) -> Iterator[TypeKind]: ...
    def __len__(self) -> int: ...

class PrimitiveType(enum.Enum):
    """A ``PrimitiveType`` represents a primitive type known to drgn."""

    C_VOID = ...
    ""
    C_CHAR = ...
    ""
    C_SIGNED_CHAR = ...
    ""
    C_UNSIGNED_CHAR = ...
    ""
    C_SHORT = ...
    ""
    C_UNSIGNED_SHORT = ...
    ""
    C_INT = ...
    ""
    C_UNSIGNED_INT = ...
    ""
    C_LONG = ...
    ""
    C_UNSIGNED_LONG = ...
    ""
    C_LONG_LONG = ...
    ""
    C_UNSIGNED_LONG_LONG = ...
    ""
    C_BOOL = ...
    ""
    C_FLOAT = ...
    ""
    C_DOUBLE = ...
    ""
    C_LONG_DOUBLE = ...
    ""
    C_SIZE_T = ...
    ""
    C_PTRDIFF_T = ...
    ""

class Qualifiers(enum.Flag):
    """``Qualifiers`` are modifiers on types."""

    NONE = ...
    """No qualifiers."""

    CONST = ...
    """Constant type."""

    VOLATILE = ...
    """Volatile type."""

    RESTRICT = ...
    """`Restrict <https://en.cppreference.com/w/c/language/restrict>`_ type."""

    ATOMIC = ...
    """Atomic type."""

def sizeof(__type_or_obj: Union[Type, Object]) -> int:
    """
    Get the size of a :class:`Type` or :class:`Object` in bytes.

    :param type_or_obj: Entity to get the size of.
    :raises TypeError: if the type does not have a size (e.g., because it is
        incomplete or void)
    """
    ...

def alignof(__type: Type) -> int:
    """
    Get the alignment requirement (in bytes) of a :class:`Type`.

    This corresponds to |alignof()|_ in C.

    .. |alignof()| replace:: ``_Alignof()``
    .. _alignof(): https://en.cppreference.com/w/c/language/_Alignof

    :raises TypeError: if *type* is a function type or an incomplete type
    """
    ...

def offsetof(type: Type, member: str) -> int:
    """
    Get the offset (in bytes) of a member in a :class:`Type`.

    This corresponds to |offsetof()|_ in C.

    .. |offsetof()| replace:: ``offsetof()``
    .. _offsetof(): https://en.cppreference.com/w/c/types/offsetof

    :param type: Structure, union, or class type.
    :param member: Name of member. May include one or more member references
        and zero or more array subscripts.
    :raises TypeError: if *type* is not a structure, union, or class type
    :raises ValueError: if the member is not byte-aligned (e.g., because it is
        a bit field)
    :raises LookupError: if *type* does not have a member with the given name
    """
    ...

class FaultError(Exception):
    """
    This error is raised when a bad memory access is attempted (i.e., when
    accessing a memory address which is not valid in a program).
    """

    def __init__(self, message: str, address: int) -> None:
        """
        :param message: :attr:`FaultError.message`
        :param address: :attr:`FaultError.address`
        """
        ...
    message: str
    """Error message."""
    address: int
    """Address that couldn't be accessed."""

class MissingDebugInfoError(Exception):
    """
    This error is raised when one or more files in a program do not have debug
    information.
    """

    ...

class ObjectAbsentError(Exception):
    """This error is raised when attempting to use an absent object."""

    ...

class OutOfBoundsError(Exception):
    """
    This error is raised when attempting to access beyond the bounds of a value
    object.
    """

    ...

_elfutils_version: str
_have_debuginfod: bool
_enable_dlopen_debuginfod: bool
_with_libkdumpfile: bool
_with_lzma: bool

def _linux_helper_direct_mapping_offset(__prog: Program) -> int: ...
def _linux_helper_read_vm(
    prog: Program, pgtable: Object, address: IntegerLike, size: IntegerLike
) -> bytes: ...
def _linux_helper_follow_phys(
    prog: Program, pgtable: Object, address: IntegerLike
) -> int: ...
def _linux_helper_xa_load(xa: Object, index: IntegerLike) -> Object: ...
def _linux_helper_per_cpu_ptr(ptr: Object, cpu: IntegerLike) -> Object:
    """
    Return the per-CPU pointer for a given CPU.

    >>> prog["init_net"].loopback_dev.pcpu_refcnt
    (int *)0x2c980
    >>> per_cpu_ptr(prog["init_net"].loopback_dev.pcpu_refcnt, 7)
    *(int *)0xffff925e3ddec980 = 4

    :param ptr: Per-CPU pointer, i.e., ``type __percpu *``. For global
        variables, it's usually easier to use :func:`per_cpu()`.
    :param cpu: CPU number.
    :return: ``type *`` object.
    """
    ...

def _linux_helper_cpu_curr(__prog: Program, __cpu: IntegerLike) -> Object: ...
def _linux_helper_idle_task(__prog: Program, __cpu: IntegerLike) -> Object: ...
def _linux_helper_task_thread_info(task: Object) -> Object:
    """
    Return the thread information structure for a task.

    :param task: ``struct task_struct *``
    :return: ``struct thread_info *``
    """
    ...

def _linux_helper_task_cpu(task: Object) -> int:
    """
    Return the CPU number that the given task last ran on.

    :param task: ``struct task_struct *``
    """
    ...

def _linux_helper_task_on_cpu(task: Object) -> bool:
    """
    Return whether the given task is currently running on a CPU.

    :param task: ``struct task_struct *``
    """
    ...

def _linux_helper_idr_find(idr: Object, id: IntegerLike) -> Object: ...
def _linux_helper_find_pid(__ns: Object, __pid: IntegerLike) -> Object: ...
def _linux_helper_pid_task(pid: Object, pid_type: IntegerLike) -> Object:
    """
    Return the ``struct task_struct *`` containing the given ``struct pid *``
    of the given type.

    :param pid: ``struct pid *``
    :param pid_type: ``enum pid_type``
    :return: ``struct task_struct *``
    """
    ...

def _linux_helper_find_task(__ns: Object, __pid: IntegerLike) -> Object: ...
def _linux_helper_kaslr_offset(__prog: Program) -> int: ...
def _linux_helper_pgtable_l5_enabled(__prog: Program) -> bool: ...
def _linux_helper_load_proc_kallsyms(
    filename: Optional[str] = None,
    modules: bool = False,
) -> SymbolIndex: ...
def _linux_helper_load_builtin_kallsyms(prog: Program) -> SymbolIndex: ...
