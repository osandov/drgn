drgn
====

`drgn` is a debugger-as-a-library. In contrast to existing debuggers like
[GDB](https://www.gnu.org/software/gdb/) which excel in breakpoint-based
debugging, drgn focuses on live introspection. drgn exposes the types and data
in a program for easy, expressive scripting.

drgn was developed for debugging the Linux kernel (as an alternative to the
[crash](http://people.redhat.com/anderson/) utility), but it can also debug
userspace programs written in C. C++ support is planned.

Python is the main interface for drgn, although an experimental C library,
`libdrgn`, is also provided.

Installation
------------

drgn is built with setuptools. Build it like so:

```
$ python3 setup.py build_ext -i
```

Then, you can either run it locally:

```
$ python3 -m drgn --help
```

Or install it and run it:

```
$ sudo python3 setup.py install
$ drgn --help
```

Or, pick your favorite Python package installation method.

Getting Started
---------------

drgn can be used as a command line tool or as a library. The rest of this
section describes using the CLI; the CLI is basically a wrapper around the
library which provides a nice interface, including history and tab completion.

To debug the running kernel, run `sudo drgn -k`. To debug a running program,
run `sudo drgn -p $PID`. To debug a core dump (either a kernel vmcore or a
userspace core dump), run `drgn -c $PATH`.

The drgn CLI has an interactive mode and a script mode. If no arguments are
passed, drgn runs in interactive mode; otherwise, the given script is run with
the given arguments. The drgn CLI is actually just the Python interpreter
initialized with a `prog` object representing the debugged program:

```
$ sudo drgn -k
>>> prog.type('struct list_head')
struct list_head {
        struct list_head *next;
        struct list_head *prev;
}
>>> prog['modules']
(struct list_head){
        .next = (struct list_head *)0xffffffffc0b91048,
        .prev = (struct list_head *)0xffffffffc0066148,
}
>>> prog['init_task'].pid
(pid_t)0
>>> from drgn.helpers.linux import list_for_each_entry
>>> for mod in list_for_each_entry('struct module', prog['modules'].address_of_(), 'list'):
...    if mod.refcnt.counter > 10:
...        print(mod.name)
...
(char [56])"snd"
(char [56])"evdev"
(char [56])"i915"
```

See the in-program documentation in interactive mode with `help(drgn)` for more
information. See `examples` and `drgn/helpers` for some examples.

License
-------

Copyright 2018-2019 - Omar Sandoval

Licensed under the GPLv3 or later

Acknowledgements
----------------

drgn is named after
[this](https://giraffesgiraffes.bandcamp.com/track/drgnfkr-2) because dragons
eat [dwarves](http://dwarfstd.org/).
