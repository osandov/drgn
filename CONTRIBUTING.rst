Contributing
============

Thanks for your interest in drgn! See below for how to build, test, code, and
submit changes for drgn.

Building
--------

The easiest way to develop drgn is by building and running it locally. See the
`installation documentation
<https://drgn.readthedocs.io/en/latest/installation.html#development>`_.

Testing
-------

.. highlight:: console

Tests should be added for all features and bug fixes.

drgn's test suite can be run with::

    $ python3 setup.py test

To run Linux kernel helper tests in a virtual machine on all supported kernels,
add ``-K``. See `vmtest <vmtest/README.rst>`_ for more details.

Tests can also be run manually with `unittest
<https://docs.python.org/3/library/unittest.html#command-line-interface>`_
after building locally::

    $ python3 -m unittest discover -v

To run Linux kernel helper tests on the running kernel, this must be run as
root, and debug information for the running kernel must be available.

Coding Guidelines
-----------------

* Core functionality should be implemented in ``libdrgn`` and exposed to Python
  via the `C extension <libdrgn/python>`_. Only the CLI and helpers should be
  in pure Python.
* Linux kernel helpers should work on all supported kernels if possible.

C
^

C code in drgn mostly follows the `Linux kernel coding style
<https://www.kernel.org/doc/html/latest/process/coding-style.html>`_ except
that drgn requires C11 or newer, so declarations may be mixed with code.

A few other guidelines:

* Functions that can fail should return a ``struct drgn_error *`` (and return
  their result via an out parameter if necessary).
* Out parameters should be named ``ret`` (or suffixed with ``_ret`` if there
  are multiple).
* Constants should be defined as enums or ``static const`` variables rather
  than macros.

drgn assumes some `implementation-defined behavior
<https://gcc.gnu.org/onlinedocs/gcc/C-Implementation.html>`_ for sanity:

* Signed integers are represented with two's complement.
* Bitwise operators on signed integers operate on the two's complement
  representation.
* Right shift of a signed integer type is arithmetic.
* Conversion to a signed integer type is modular.
* Casting between pointers and integers does not change the bit representation.

Python
^^^^^^

Python code in drgn should be compatible with Python 3.6 and newer.

Python code should be formatted with `black <https://github.com/psf/black>`_
and `isort <https://github.com/timothycrosley/isort>`_::

    $ isort . && black .

Type hints should be provided for all interfaces (including helpers and the C
extension).

Submitting PRs
--------------

Pull requests and issues are always welcome. Feel free to start a discussion
with a prototype.

Signing Off
^^^^^^^^^^^

All commits must be signed off (i.e., ``Signed-off-by: Jane Doe
<janedoe@example.org>``) as per the `Developer Certificate of Origin
<https://developercertificate.org/>`_. ``git commit -s`` can do this for you.

Separating Changes
^^^^^^^^^^^^^^^^^^

Each logical change should be a separate commit. For example, if a PR adds new
functionality to the core library and a new helper that uses the new
functionality, the core change and the helper should be separate commits. This
makes code review much easier.

Each commit should build, pass tests, follow coding guidelines, and run
correctly. (In other words, within a PR, later commits often build on top of
earlier commits, but later commits shouldn't need to "fix" earlier commits.)
This makes it easier to track down problems with tools like ``git bisect``
which may check out any commit in the middle of a PR.

Commit Messages
^^^^^^^^^^^^^^^

The template for a good commit message is:

.. code-block:: none

    One line summary

    Longer explanation including more details, background, and/or
    motivation.

    Signed-off-by: Jane Doe <janedoe@example.org>

See `this post <https://chris.beams.io/posts/git-commit/>`_ for more
information about writing good commit messages.
