Support Matrix
==============

Architectures
-------------

Some features in drgn require architecture-specific support. The current status
of this support is:

.. _architecture support matrix:

.. list-table::
    :header-rows: 1

    * - Architecture
      - Linux Kernel Modules [1]_
      - Stack Traces [2]_
      - Virtual Address Translation [3]_
    * - x86-64
      - ✓
      - ✓
      - ✓
    * - AArch64
      - ✓
      - ✓
      - ✓
    * - s390x
      - ✓
      - ✓
      - ✓
    * - ppc64
      - ✓
      - ✓
      - ✓
    * - i386
      - ✓
      -
      -
    * - Arm
      - ✓
      - ✓
      - ✓
    * - RISC-V
      - ✓
      -
      -

.. rubric:: Key

.. [1] Support for loading debugging symbols for Linux kernel modules.
.. [2] Support for capturing stack traces (:meth:`drgn.Program.stack_trace()`, :meth:`drgn.Thread.stack_trace()`).
.. [3] Support for translating virtual addresses, which is required for reading from vmalloc/vmap and module memory in Linux kernel vmcores and for various helpers in :mod:`drgn.helpers.linux.mm`.

The listed architectures are recognized in :class:`drgn.Architecture`. Other
architectures are represented by :attr:`drgn.Architecture.UNKNOWN`. Features
not mentioned above should work on any architecture, listed or not.

Cross-Debugging
^^^^^^^^^^^^^^^

drgn can debug architectures different from the host. For example, you can
debug an AArch64 (kernel or userspace) core dump from an x86-64 machine.

Linux Kernel Versions
---------------------

drgn officially supports the current mainline, stable, and longterm kernel
releases from `kernel.org <https://www.kernel.org/>`_. (There may be some delay
before a new mainline version is fully supported.) End-of-life versions are
supported until it becomes too difficult to do so. The kernel versions
currently fully supported are:

.. Keep this in sync with vmtest/config.py.

- 6.0-6.19
- 5.10-5.19
- 5.4
- 4.19
- 4.14
- 4.9

Other versions are not tested. They'll probably mostly work, but support is
best-effort.

Kernel Configuration
^^^^^^^^^^^^^^^^^^^^

drgn supports debugging kernels with various configurations:

- SMP and !SMP.
- Preemptible and non-preemptible.
- SLUB, SLAB, and SLOB allocators.

drgn requires a kernel configured with ``CONFIG_PROC_KCORE=y`` for live kernel
debugging.
