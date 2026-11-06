Rust namespace scope test
============================

``tests/test_stack_trace.py`` uses this test program to check local lookup in a
Rust function nested beneath a DWARF namespace without an address range.
The resources were generated on x86-64 Fedora with rustc 1.99.1
(Fedora 1.99.1-2.fc44) and GDB 17.2-4.fc44.

From the repository root, build and capture the test program::

    rustc -g -C opt-level=0 -C prefer-dynamic scripts/rust/rust_namespace.rs -o /tmp/rust-namespace
    printf '%s\n' '#!/bin/sh' 'echo 0x23 > /proc/self/coredump_filter' 'exec "$@"' > /tmp/rust-core-wrapper
    chmod u+x /tmp/rust-core-wrapper
    gdb -nx -nh -batch \
        -iex 'set debuginfod enabled off' \
        -ex "set environment LD_LIBRARY_PATH $(rustc --print target-libdir)" \
        -ex 'set exec-wrapper /tmp/rust-core-wrapper' \
        -ex 'break rust_namespace.rs:8' \
        -ex run \
        -ex 'generate-core-file /tmp/rust-namespace.core' \
        -ex kill /tmp/rust-namespace

Dynamic linking keeps the executable small. The breakpoint stops after ``point``
is initialized, before the sleep call. Adjust it if the source changes. Stopping
in the test program avoids needing Rust standard-library unwind information in the
test. Filter ``0x23`` disables file-backed mapping and ELF-header dumping, the
test explicitly associates the executable with the headerless main module.

Compress the matching executable and core::

    zstd -f -19 /tmp/rust-namespace -o tests/resources/rust_namespace.zst
    zstd -f -19 /tmp/rust-namespace.core -o tests/resources/rust_namespace.core.zst
    chmod a-x tests/resources/rust_namespace*.zst

Regenerate both resources together. Rust and its shared standard library are
needed for generation, but the test uses drgn to inspect the saved executable
and core with automatic debug-info discovery disabled. After rebuilding drgn,
run the regression test from the repository root::

    python3 -m unittest -v tests.test_stack_trace.TestRustNamespaceCoreDump

This command assumes an in-tree build. For build and test guidance, see the
`contribution guide <../../CONTRIBUTING.rst>`_.
