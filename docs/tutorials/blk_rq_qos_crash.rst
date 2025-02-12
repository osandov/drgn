Stack Traces and Mystery Addresses (blk-rq-qos Crash)
=====================================================

| Author: Omar Sandoval
| Date: February 12, 2025

.. linuxversion:: v6.11

This is a hands-on tutorial walking through a real Linux kernel bug that caused
kernel crashes in production. We'll read kernel code and use a few important
drgn techniques for reading stack traces and interpreting memory in order to
identify the root cause of the bug.

We saw this crash on storage workloads on multiple kernel versions, up to and
including the latest at the time, Linux 6.11. The kernel logs all implicated
something in the block layer.

A core dump and debugging symbols are provided for you to follow along with.

This tutorial is also available as a video:

.. raw:: html

    <iframe width="560" height="315" src="https://www.youtube.com/embed/s5TvkvMiV_M?si=_EjaR7gpyGcACeS7" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

Setup
-----

.. highlight:: console

Follow the :doc:`../installation` instructions to get drgn.

Download and extract the tutorial files:

.. code-block::
    :class: tutorial

    $ curl -L https://github.com/osandov/drgn/releases/download/tutorial-assets/blk_rq_qos_crash_tutorial.tar.zst \
      | zstd -d | tar -x

This will create a directory named ``blk_rq_qos_crash_tutorial``. Enter it:

.. code-block::
    :class: tutorial

    $ cd blk_rq_qos_crash_tutorial

Then, run drgn as follows. It will print a version banner and automatically
import the relevant :doc:`../helpers`:

.. code-block::
    :class: tutorial

    $ drgn -c vmcore -s vmlinux --main-symbols
    drgn 0.0.30 (using Python 3.13.1, elfutils 0.192, with libkdumpfile)
    For help, type help(drgn).
    >>> import drgn
    >>> from drgn import FaultError, NULL, Object, alignof, cast, container_of, execscript, implicit_convert, offsetof, reinterpret, sizeof, stack_trace
    >>> from drgn.helpers.common import *
    >>> from drgn.helpers.linux import *

In another window, check out the source code for Linux 6.11. For example, run
``git checkout v6.11`` in an existing Linux repo, or run:

.. code-block::
    :class: tutorial

    $ git clone -b v6.11 --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
    ...
    $ cd linux

Now we can dive into the core dump.

Starting With Dmesg
-------------------

.. highlight:: pycon

The kernel log buffer is usually the first place to look when debugging a
crash. In drgn, call :func:`~drgn.helpers.linux.printk.print_dmesg()` and
scroll up until you find the line starting with ``BUG:``. You should see the
following trace:

.. code-block::
    :class: scroll-y tutorial
    :emphasize-lines: 3,11

    >>> print_dmesg()
    ...
    [   18.051123] BUG: kernel NULL pointer dereference, address: 00000000000006fc
    [   18.051597] #PF: supervisor write access in kernel mode
    [   18.051936] #PF: error_code(0x0002) - not-present page
    [   18.052241] PGD 0 P4D 0
    [   18.052336] Oops: Oops: 0002 [#1] PREEMPT SMP NOPTI
    [   18.052629] CPU: 0 UID: 0 PID: 906 Comm: fio Kdump: loaded Not tainted 6.11.0 #1
    [   18.053123] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-3.fc41 04/01/2014
    [   18.053739] RIP: 0010:_raw_spin_lock_irqsave+0x36/0x70
    [   18.054059] Code: 04 25 28 00 00 00 48 89 44 24 08 48 c7 04 24 00 00 00 00 9c 8f 04 24 48 8b 1c 24 fa 65 ff 05 89 2a b7 7e b9 01 00 00 00 31 c0 <f0> 0f b1 0f 75 1e 65 48 8b 04 25 28 00 00 00 48 3b 44 24 08 75 17
    [   18.055467] RSP: 0000:ffffc900011abcd0 EFLAGS: 00010046
    [   18.055788] RAX: 0000000000000000 RBX: 0000000000000082 RCX: 0000000000000001
    [   18.056260] RDX: 0000000000000000 RSI: 0000000000000003 RDI: 00000000000006fc
    [   18.056725] RBP: 0000000000000000 R08: 0000000000000000 R09: 000000000015000e
    [   18.057202] R10: ffff888002fa5900 R11: ffffffff81312090 R12: 0000000000000003
    [   18.057669] R13: ffff888002d4b678 R14: 00000000000006fc R15: 0000000000000003
    [   18.058138] FS:  00007f1ee66c06c0(0000) GS:ffff888005a00000(0000) knlGS:0000000000000000
    [   18.058677] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
    [   18.059039] CR2: 00000000000006fc CR3: 0000000002f4a005 CR4: 0000000000770ef0
    [   18.059508] PKRU: 55555554
    [   18.059614] Call Trace:
    [   18.059700]  <TASK>
    [   18.059782]  ? __die_body+0x16/0x60
    [   18.059982]  ? page_fault_oops+0x31e/0x3a0
    [   18.060205]  ? exc_page_fault+0x55/0xa0
    [   18.060409]  ? asm_exc_page_fault+0x26/0x30
    [   18.060640]  ? __pfx_wbt_inflight_cb+0x10/0x10
    [   18.060892]  ? _raw_spin_lock_irqsave+0x36/0x70
    [   18.061150]  try_to_wake_up+0x3e/0x400
    [   18.061342]  rq_qos_wake_function+0x4d/0x60
    [   18.061572]  __wake_up_common+0x42/0x80
    [   18.061770]  __wake_up_common_lock+0x33/0x60
    [   18.062007]  wbt_done+0x60/0x80
    [   18.062152]  __rq_qos_done+0x22/0x40
    [   18.062330]  blk_mq_free_request+0x62/0xb0
    [   18.062551]  virtblk_done+0x99/0x120
    [   18.062731]  vring_interrupt+0x71/0x80
    [   18.062928]  vp_interrupt+0xa8/0xe0
    [   18.063100]  __handle_irq_event_percpu+0x89/0x1b0
    [   18.063373]  handle_irq_event_percpu+0xf/0x40
    [   18.063614]  handle_irq_event+0x30/0x50
    [   18.063831]  handle_fasteoi_irq+0xaa/0x1b0
    [   18.064051]  __common_interrupt+0x3a/0xb0
    [   18.064266]  common_interrupt+0x3d/0x90
    [   18.064462]  asm_common_interrupt+0x26/0x40
    [   18.064691] RIP: 0033:0x7f1ef33679b9
    [   18.064886] Code: ff 48 85 c0 0f 84 32 35 00 00 48 8b bd b8 f9 ff ff 4c 89 b5 80 f9 ff ff 48 89 07 4c 01 f8 48 89 85 78 f9 ff ff e9 8d ca ff ff <48> 8b 85 60 fa ff ff 48 8d 50 08 48 89 95 60 fa ff ff e9 c7 d5 ff
    [   18.066333] RSP: 002b:00007f1ee66baad0 EFLAGS: 00000212
    [   18.066624] RAX: 00007f1ee66bad56 RBX: 00007f1ee66bb1d0 RCX: 00007f1ee66bad56
    [   18.066999] RDX: 0000000000000030 RSI: 00000000000f12b3 RDI: 000000000000000a
    [   18.067476] RBP: 00007f1ee66bb1a0 R08: 000000000000002c R09: 0000000000000000
    [   18.068003] R10: 00007f1ef348dfe0 R11: 0000000000000020 R12: 0000000000000020
    [   18.068482] R13: 0000000000000000 R14: 00000000ffffffff R15: 0000000000000001
    [   18.069005]  </TASK>
    [   18.069097] CR2: 00000000000006fc

``BUG: kernel NULL pointer dereference, address: 00000000000006fc`` tells us
that the kernel crashed because it dereferenced a null pointer and tried to
access the address 0x6fc.

``RIP: 0010:_raw_spin_lock_irqsave+0x36/0x70`` tells us that the bad access
happened in the function :linux:`_raw_spin_lock_irqsave()
<kernel/locking/spinlock.c:160>`. Below that, the stack trace tells us how we
got there.

.. tip::

    Ignore call trace lines starting with ``?``. These are stale function
    addresses on the stack that are not part of the actual call trace. They are
    printed as a :linuxt:`hint/fail-safe <arch/x86/kernel/dumpstack.c:246>`,
    but they are misleading as often as not.

We'll look at the trace in more detail with drgn soon, but we can see that we
got an interrupt for a disk I/O completion, which then tried to wake up a task
and acquire a spinlock.

Stack Trace in drgn
-------------------

Now let's look at drgn's view of the stack trace. Save the stack trace of the
crashed thread:

.. code-block::
    :class: tutorial

    >>> trace = prog.crashed_thread().stack_trace()

And print it:

.. code-block::
    :class: scroll-y tutorial

    >>> trace
    #0  arch_atomic_try_cmpxchg (./arch/x86/include/asm/atomic.h:107:9)
    #1  raw_atomic_try_cmpxchg_acquire (./include/linux/atomic/atomic-arch-fallback.h:2170:9)
    #2  atomic_try_cmpxchg_acquire (./include/linux/atomic/atomic-instrumented.h:1302:9)
    #3  queued_spin_lock (./include/asm-generic/qspinlock.h:111:6)
    #4  do_raw_spin_lock (./include/linux/spinlock.h:187:2)
    #5  __raw_spin_lock_irqsave (./include/linux/spinlock_api_smp.h:111:2)
    #6  _raw_spin_lock_irqsave (kernel/locking/spinlock.c:162:9)
    #7  class_raw_spinlock_irqsave_constructor (./include/linux/spinlock.h:551:1)
    #8  try_to_wake_up (kernel/sched/core.c:4051:2)
    #9  rq_qos_wake_function (block/blk-rq-qos.c:223:2)
    #10 __wake_up_common (kernel/sched/wait.c:89:9)
    #11 __wake_up_common_lock (kernel/sched/wait.c:106:14)
    #12 wbt_done (block/blk-wbt.c:259:3)
    #13 __rq_qos_done (block/blk-rq-qos.c:39:4)
    #14 rq_qos_done (block/blk-rq-qos.h:122:3)
    #15 blk_mq_free_request (block/blk-mq.c:737:2)
    #16 virtblk_done (drivers/block/virtio_blk.c:367:5)
    #17 vring_interrupt (drivers/virtio/virtio_ring.c:2595:3)
    #18 vp_vring_interrupt (drivers/virtio/virtio_pci_common.c:82:7)
    #19 vp_interrupt (drivers/virtio/virtio_pci_common.c:113:9)
    #20 __handle_irq_event_percpu (kernel/irq/handle.c:158:9)
    #21 handle_irq_event_percpu (kernel/irq/handle.c:193:11)
    #22 handle_irq_event (kernel/irq/handle.c:210:8)
    #23 handle_fasteoi_irq (kernel/irq/chip.c:720:2)
    #24 generic_handle_irq_desc (./include/linux/irqdesc.h:173:2)
    #25 handle_irq (arch/x86/kernel/irq.c:247:3)
    #26 call_irq_handler (arch/x86/kernel/irq.c:259:3)
    #27 __common_interrupt (arch/x86/kernel/irq.c:285:6)
    #28 common_interrupt (arch/x86/kernel/irq.c:278:1)
    #29 asm_common_interrupt+0x26/0x2b (./arch/x86/include/asm/idtentry.h:693)
    #30 0x7f1ef33679b9

Notice that drgn's stack trace includes information not in the kernel trace,
namely:

1. File names and line and column numbers. These are very useful for navigating
   the code that you're debugging.
2. Inlined function calls. For example, frames 0-5 are all inlined calls, and
   frame 6 was the last actual call. You can verify this by printing each frame
   individually:

   .. code-block::
       :class: tutorial


       >>> trace[0]
       #0 at 0xffffffff814b6446 (_raw_spin_lock_irqsave+0x36/0x68) in arch_atomic_try_cmpxchg at ./arch/x86/include/asm/atomic.h:107:9 (inlined)
       >>> trace[1]
       #1 at 0xffffffff814b6446 (_raw_spin_lock_irqsave+0x36/0x68) in raw_atomic_try_cmpxchg_acquire at ./include/linux/atomic/atomic-arch-fallback.h:2170:9 (inlined)
       >>> trace[2]
       #2 at 0xffffffff814b6446 (_raw_spin_lock_irqsave+0x36/0x68) in atomic_try_cmpxchg_acquire at ./include/linux/atomic/atomic-instrumented.h:1302:9 (inlined)
       >>> trace[3]
       #3 at 0xffffffff814b6446 (_raw_spin_lock_irqsave+0x36/0x68) in queued_spin_lock at ./include/asm-generic/qspinlock.h:111:6 (inlined)
       >>> trace[4]
       #4 at 0xffffffff814b6446 (_raw_spin_lock_irqsave+0x36/0x68) in do_raw_spin_lock at ./include/linux/spinlock.h:187:2 (inlined)
       >>> trace[5]
       #5 at 0xffffffff814b6446 (_raw_spin_lock_irqsave+0x36/0x68) in __raw_spin_lock_irqsave at ./include/linux/spinlock_api_smp.h:111:2 (inlined)
       >>> trace[6]
       #6 at 0xffffffff814b6446 (_raw_spin_lock_irqsave+0x36/0x68) in _raw_spin_lock_irqsave at kernel/locking/spinlock.c:162:9

   Notice that frames 0-5 end with ``(inlined)``, and all of the frames have
   the same instruction pointer, ``0xffffffff814b6446``.

Tracing Local Variables
-----------------------

Next, let's walk through the stack trace to figure out where the null pointer
came from.

Frames 0-2 are low-level atomic operations::

    #0  arch_atomic_try_cmpxchg (./arch/x86/include/asm/atomic.h:107:9)
    #1  raw_atomic_try_cmpxchg_acquire (./include/linux/atomic/atomic-arch-fallback.h:2170:9)
    #2  atomic_try_cmpxchg_acquire (./include/linux/atomic/atomic-instrumented.h:1302:9)

That's essentially a fancy memory access, so let's skip those frames. Frame 3
is in :linux:`queued_spin_lock() <include/asm-generic/qspinlock.h:107>`, the
kernel's spinlock implementation::

    #3  queued_spin_lock (./include/asm-generic/qspinlock.h:111:6)

In your window with the Linux source code, open
:file:`include/asm-generic/qspinlock.h` and jump to line 111:

.. code-block:: c
    :caption: include/asm-generic/qspinlock.h
    :lineno-start: 107
    :emphasize-lines: 5

    static __always_inline void queued_spin_lock(struct qspinlock *lock)
    {
            int val = 0;

            if (likely(atomic_try_cmpxchg_acquire(&lock->val, &val, _Q_LOCKED_VAL)))
                    return;

            queued_spin_lock_slowpath(lock, val);
    }

Notice that it accesses the ``lock`` parameter. Print it in drgn:

.. code-block::
    :class: tutorial

    >>> trace[3]["lock"]
    (struct qspinlock *)0x6fc

This matches the address from the ``BUG`` message in dmesg!

Now let's find out where ``lock`` came from. Frames 4-7 wrap the low-level
spinlock implementation::

    #4  do_raw_spin_lock (./include/linux/spinlock.h:187:2)
    #5  __raw_spin_lock_irqsave (./include/linux/spinlock_api_smp.h:111:2)
    #6  _raw_spin_lock_irqsave (kernel/locking/spinlock.c:162:9)
    #7  class_raw_spinlock_irqsave_constructor (./include/linux/spinlock.h:551:1)

Feel free to open the source code for these, but we can quickly check that the
lock simply gets passed through:

.. code-block::
    :class: tutorial

    >>> trace[4]["lock"]
    (raw_spinlock_t *)0x6fc
    >>> trace[5]["lock"]
    (raw_spinlock_t *)0x6fc
    >>> trace[6]["lock"]
    (raw_spinlock_t *)0x6fc

:linux:`class_raw_spinlock_irqsave_constructor()
<include/linux/spinlock.h:551>` is slightly different. It is generated by a
macro and doesn't use the name ``lock``:

.. code-block::
    :class: tutorial

    >>> trace[7]["lock"]
    Traceback (most recent call last):
      ...
    KeyError: 'lock'

Let's list all of its local variables and make a guess:

.. code-block::
    :class: tutorial

    >>> trace[7].locals()
    ['l', '_t']
    >>> trace[7]["l"]
    (raw_spinlock_t *)0x6fc

.. tip::

    Use :meth:`drgn.StackFrame.locals()` to get the list of parameters and
    local variables in a stack frame when finding the implementation of the
    function is inconvenient.

The caller must have passed 0x6fc. Let's look at it. The next frame is in
:linux:`try_to_wake_up() <kernel/sched/core.c:4020>`::

    #8  try_to_wake_up (kernel/sched/core.c:4051:2)

Open :file:`kernel/sched/core.c` at line 4051:

.. code-block:: c
    :caption: kernel/sched/core.c
    :emphasize-lines: 4

    int try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
    {
    ...
            scoped_guard (raw_spinlock_irqsave, &p->pi_lock) {

It is acquiring :linux:`pi_lock <include/linux/sched.h:1160>` in a
:linux:`task_struct <include/linux/sched.h:756>` (using a `scoped guard
<https://lwn.net/Articles/934679/>`_). Print the ``task_struct``:

.. code-block::
    :class: tutorial

    >>> trace[8]["p"]
    (struct task_struct *)0x0

There's our null pointer! But where did 0x6fc come from? Look at the offset of
``pi_lock`` in ``struct task_struct``:

.. code-block::
    :class: tutorial

    >>> hex(offsetof(prog.type("struct task_struct"), "pi_lock"))
    '0x6fc'

Or do the inverse and see what's at offset 0x6fc in ``struct task_struct``:

.. code-block::
    :class: tutorial

    >>> member_at_offset(prog.type("struct task_struct"), 0x6fc)
    'pi_lock.raw_lock.val.counter or pi_lock.raw_lock.locked or pi_lock.raw_lock.locked_pending'

.. tip::

    Use :func:`~drgn.offsetof()` and
    :func:`~drgn.helpers.common.type.member_at_offset()` to decipher pointers
    to struct members.

So where did ``p`` come from? Let's look at the caller,
:linux:`rq_qos_wake_function() <block/blk-rq-qos.c:206>`, in frame 9::

    #9  rq_qos_wake_function (block/blk-rq-qos.c:223:2)

Open :file:`block/blk-rq-qos.c` at line 223:

.. code-block:: c
    :caption: block/blk-rq-qos.c
    :lineno-start: 206
    :emphasize-lines: 18

    static int rq_qos_wake_function(struct wait_queue_entry *curr,
                                    unsigned int mode, int wake_flags, void *key)
    {
            struct rq_qos_wait_data *data = container_of(curr,
                                                         struct rq_qos_wait_data,
                                                         wq);

            /*
             * If we fail to get a budget, return -1 to interrupt the wake up loop
             * in __wake_up_common.
             */
            if (!data->cb(data->rqw, data->private_data))
                    return -1;

            data->got_token = true;
            smp_wmb();
            list_del_init(&curr->entry);
            wake_up_process(data->task);
            return 1;
    }

(Note: :linux:`wake_up_process() <kernel/sched/core.c:4297>` doesn't show up in
the stack trace because of `tail call elimination
<https://en.wikipedia.org/wiki/Tail_call>`_. This `may be fixed
<https://github.com/osandov/drgn/issues/345>`_ in a future release of drgn.)

``p`` came from ``data->task``. Print ``data``:

.. code-block::
    :class: tutorial

    >>> trace[9]["data"]
    *(struct rq_qos_wait_data *)0xffffc900011b3558 = {
            .wq = (struct wait_queue_entry){
                    .flags = (unsigned int)2168637095,
                    .private = (void *)0xffff888002d6c000,
                    .func = (wait_queue_func_t)0x0,
                    .entry = (struct list_head){
                            .next = (struct list_head *)0xffff888002d6c000,
                            .prev = (struct list_head *)0xffff888002da2100,
                    },
            },
            .task = (struct task_struct *)0xffff888000fd6001,
            .rqw = (struct rq_wait *)0xffffc900011b3a30,
            .cb = (acquire_inflight_cb_t *)0xffff888002763030,
            .private_data = (void *)0x1,
            .got_token = (bool)201,
    }

Notice that ``data->task`` is NOT null. Print the ``comm`` member, which should
be the thread name:

.. code-block::
    :class: tutorial

    >>> trace[9]["data"].task.comm
    (char [16])""

Instead, it's empty. This doesn't appear to be a valid ``task_struct``.

Identifying Mystery Addresses
-----------------------------

If ``data->task`` isn't a valid ``task_struct``, then what is it? Pass it to
:func:`~drgn.helpers.common.memory.identify_address()` to answer that:

.. code-block::
    :class: tutorial

    >>> identify_address(trace[9]["data"].task)
    'slab object: buffer_head+0x1'

It's a pointer to a completely unrelated type.

Since our problem seems to stem from ``data``, pass it to
``identify_address()`` to see where it comes from:

.. code-block::
    :class: tutorial

    >>> identify_address(trace[9]["data"])
    'vmap stack: 909 (fio) +0x3558'

This means that ``data`` is on the stack of the task with PID 909.

.. tip::

    Use :func:`~drgn.helpers.common.memory.identify_address()` to figure out
    what an unknown address refers to.

Other Stacks
------------

Notice that we've seen three possibilities for ``data->task``:

1. When it was passed to ``wake_up_process()``, it was ``NULL``.
2. By the time of the crash, it was an unrelated pointer.
3. It's supposed to point to a ``task_struct``.

This suggests that there's a data race on ``data->task``.

We know that ``data`` is on the stack of another task. Let's find where it's
created. In :file:`block/blk-rq-qos.c`, search for ``struct rq_qos_wait_data``.
You should find it being used in :linux:`rq_qos_wait()
<block/blk-rq-qos.c:243>`:

.. code-block:: c
    :caption: block/blk-rq-qos.c
    :lineno-start: 243
    :emphasize-lines: 5

    void rq_qos_wait(struct rq_wait *rqw, void *private_data,
                     acquire_inflight_cb_t *acquire_inflight_cb,
                     cleanup_cb_t *cleanup_cb)
    {
            struct rq_qos_wait_data data = {
                    .wq = {
                            .func	= rq_qos_wake_function,
                            .entry	= LIST_HEAD_INIT(data.wq.entry),
                    },
                    .task = current,
                    .rqw = rqw,
                    .cb = acquire_inflight_cb,
                    .private_data = private_data,
            };
            bool has_sleeper;

            has_sleeper = wq_has_sleeper(&rqw->wait);
            if (!has_sleeper && acquire_inflight_cb(rqw, private_data))
                    return;

            has_sleeper = !prepare_to_wait_exclusive(&rqw->wait, &data.wq,
                                                     TASK_UNINTERRUPTIBLE);
            do {
                    /* The memory barrier in set_task_state saves us here. */
                    if (data.got_token)
                            break;
                    if (!has_sleeper && acquire_inflight_cb(rqw, private_data)) {
                            finish_wait(&rqw->wait, &data.wq);

                            /*
                             * We raced with rq_qos_wake_function() getting a token,
                             * which means we now have two. Put our local token
                             * and wake anyone else potentially waiting for one.
                             */
                            smp_rmb();
                            if (data.got_token)
                                    cleanup_cb(rqw, private_data);
                            break;
                    }
                    io_schedule();
                    has_sleeper = true;
                    set_current_state(TASK_UNINTERRUPTIBLE);
            } while (1);
            finish_wait(&rqw->wait, &data.wq);
    }

This function creates ``data`` on the stack, with ``data->task`` set to the
current task, and then tries to acquire an "inflight counter". If one is not
available, it puts itself on a wait queue and blocks until it can get one.

So, ``rq_qos_wait()`` waits for an inflight counter, and
``rq_qos_wake_function()`` wakes it up when one becomes available. We would
expect that the PID we found earlier, 909, is currently blocked in
``rq_qos_wait()``. Pass the PID to :func:`~drgn.stack_trace()` to check:

.. code-block::
    :class: scroll-y tutorial

    >>> stack_trace(909)
    #0  rep_nop (./arch/x86/include/asm/vdso/processor.h:0:2)
    #1  cpu_relax (./arch/x86/include/asm/vdso/processor.h:18:2)
    #2  queued_spin_lock_slowpath (kernel/locking/qspinlock.c:380:3)
    #3  queued_spin_lock (./include/asm-generic/qspinlock.h:114:2)
    #4  do_raw_spin_lock (./include/linux/spinlock.h:187:2)
    #5  __raw_spin_lock_irqsave (./include/linux/spinlock_api_smp.h:111:2)
    #6  _raw_spin_lock_irqsave (kernel/locking/spinlock.c:162:9)
    #7  virtblk_add_req_batch (drivers/block/virtio_blk.c:481:2)
    #8  virtio_queue_rqs (drivers/block/virtio_blk.c:519:11)
    #9  __blk_mq_flush_plug_list (block/blk-mq.c:2704:2)
    #10 blk_mq_flush_plug_list (block/blk-mq.c:2781:4)
    #11 blk_add_rq_to_plug (block/blk-mq.c:1292:3)
    #12 blk_mq_submit_bio (block/blk-mq.c:3028:3)
    #13 __submit_bio (block/blk-core.c:615:3)
    #14 __submit_bio_noacct_mq (block/blk-core.c:696:3)
    #15 submit_bio_noacct_nocheck (block/blk-core.c:725:3)
    #16 ext4_io_submit (fs/ext4/page-io.c:377:3)
    #17 io_submit_add_bh (fs/ext4/page-io.c:418:3)
    #18 ext4_bio_write_folio (fs/ext4/page-io.c:560:3)
    #19 mpage_submit_folio (fs/ext4/inode.c:1943:8)
    #20 mpage_process_page_bufs (fs/ext4/inode.c:2056:9)
    #21 mpage_prepare_extent_to_map (fs/ext4/inode.c:2564:11)
    #22 ext4_do_writepages (fs/ext4/inode.c:2706:8)
    #23 ext4_writepages (fs/ext4/inode.c:2842:8)
    #24 do_writepages (mm/page-writeback.c:2683:10)
    #25 __filemap_fdatawrite_range (mm/filemap.c:430:9)
    #26 generic_fadvise (mm/fadvise.c:114:3)
    #27 vfs_fadvise (mm/fadvise.c:185:9)
    #28 ksys_fadvise64_64 (mm/fadvise.c:199:8)
    #29 __do_sys_fadvise64 (mm/fadvise.c:214:9)
    #30 __se_sys_fadvise64 (mm/fadvise.c:212:1)
    #31 __x64_sys_fadvise64 (mm/fadvise.c:212:1)
    #32 do_syscall_x64 (arch/x86/entry/common.c:52:14)
    #33 do_syscall_64 (arch/x86/entry/common.c:83:7)
    #34 entry_SYSCALL_64+0xaf/0x14c (arch/x86/entry/entry_64.S:121)
    #35 0x7f1ef340203a

It's not in ``rq_qos_wait()``! It seems to have moved on to something else.

Analysis
--------

At this point, we've gotten everything that we need from drgn. Now we need to
interpret what we've gathered and analyze the kernel code.

Based on the stack trace for PID 909, we can conclude that the *waiter* got a
counter, returned, and moved on to something else. It reused the stack for
unrelated data, which explains the mystery pointer that we saw in
``data->task``. The series of events is something like this:

1. ``acquire_inflight_cb()`` on line 260 fails.
2. ``prepare_to_wait_exclusive()`` puts ``data`` on the waitqueue.
3. ``acquire_inflight_cb()`` on line 269 succeeds.
4. ``finish_wait()`` removes ``data`` from the waitqueue.
5. ``rq_qos_wait()`` returns and the task moves on to something else, reusing
   the stack memory.

This means that the *waker* found the waiter's ``data`` in between steps 2 and
4, but by the time the waker called ``wake_up_process(data->task)``, the waiter
was past step 5.

Wakers and waiters are supposed to be synchronized. Going back to the crashing
stack trace, we see that ``rq_qos_wake_function()`` is called via
:linux:`__wake_up_common_lock() <kernel/sched/wait.c:99>`::

    #10 __wake_up_common (kernel/sched/wait.c:89:9)
    #11 __wake_up_common_lock (kernel/sched/wait.c:106:14)

Open :file:`kernel/sched/wait.c` at line 106 and see that it's holding
``wq_head->lock``:

.. code-block:: c
    :caption: kernel/sched/wait.c
    :lineno-start: 99
    :emphasize-lines: 8

    static int __wake_up_common_lock(struct wait_queue_head *wq_head, unsigned int mode,
                            int nr_exclusive, int wake_flags, void *key)
    {
            unsigned long flags;
            int remaining;

            spin_lock_irqsave(&wq_head->lock, flags);
            remaining = __wake_up_common(wq_head, mode, nr_exclusive, wake_flags,
                            key);
            spin_unlock_irqrestore(&wq_head->lock, flags);

            return nr_exclusive - remaining;
    }

On the waiter side, :linux:`finish_wait() <kernel/sched/wait.c:446>` also grabs
``wq_head->lock``:

.. code-block:: c
    :caption: kernel/sched/wait.c
    :lineno-start: 446

    void finish_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
    {
            unsigned long flags;

            __set_current_state(TASK_RUNNING);
            /*
             * We can check for list emptiness outside the lock
             * IFF:
             *  - we use the "careful" check that verifies both
             *    the next and prev pointers, so that there cannot
             *    be any half-pending updates in progress on other
             *    CPU's that we haven't seen yet (and that might
             *    still change the stack area.
             * and
             *  - all other users take the lock (ie we can only
             *    have _one_ other CPU that looks at or modifies
             *    the list).
             */
            if (!list_empty_careful(&wq_entry->entry)) {
                    spin_lock_irqsave(&wq_head->lock, flags);
                    list_del_init(&wq_entry->entry);
                    spin_unlock_irqrestore(&wq_head->lock, flags);
            }
    }

But there's an important detail here: ``finish_wait()`` doesn't take the lock
if the wait queue list entry is empty, i.e., if it has already been removed
from the wait queue.

Go back to ``rq_qos_wake_function()``:

.. code-block:: c
    :caption: block/blk-rq-qos.c
    :lineno-start: 206

    static int rq_qos_wake_function(struct wait_queue_entry *curr,
                                    unsigned int mode, int wake_flags, void *key)
    {
            struct rq_qos_wait_data *data = container_of(curr,
                                                         struct rq_qos_wait_data,
                                                         wq);

            /*
             * If we fail to get a budget, return -1 to interrupt the wake up loop
             * in __wake_up_common.
             */
            if (!data->cb(data->rqw, data->private_data))
                    return -1;

            data->got_token = true;
            smp_wmb();
            list_del_init(&curr->entry);
            wake_up_process(data->task);
            return 1;
    }

It removes the entry from the wait queue on line 222, then accesses the entry
on line 223.

That's the race condition: as soon as the entry has been removed from the wait
queue, ``finish_wait()`` in the waiter can return instantly, and the waiter is
free to move on. Therefore, after the entry has been removed, the waker must
not access it.

The Fix
-------

The fix is trivial: don't delete the wait queue entry until *after* using it.

.. code-block:: diff

    diff --git a/block/blk-rq-qos.c b/block/blk-rq-qos.c
    index 2cfb297d9a62..058f92c4f9d5 100644
    --- a/block/blk-rq-qos.c
    +++ b/block/blk-rq-qos.c
    @@ -219,8 +219,8 @@ static int rq_qos_wake_function(struct wait_queue_entry *curr,

            data->got_token = true;
            smp_wmb();
    -       list_del_init(&curr->entry);
            wake_up_process(data->task);
    +       list_del_init_careful(&curr->entry);
            return 1;
     }

The deletion also needs careful memory ordering to pair with the
:linux:`list_empty_careful() <include/linux/list.h:407>` in ``finish_wait()``,
hence the replacement of :linux:`list_del_init() <include/linux/list.h:285>`
with :linux:`list_del_init_careful() <include/linux/list.h:387>`.

This fix was merged in Linux 6.12 in `commit e972b08b91ef ("blk-rq-qos: fix
crash on rq_qos_wait vs. rq_qos_wake_function race")
<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e972b08b91ef48488bae9789f03cfedb148667fb>`_.

Conclusion
----------

Debugging a core dump involves a lot of cross-referencing code and core dump
state. drgn gives you some powerful capabilities for understanding kernel
state, which you can use to discern subtle bugs like this one. In particular,
:func:`~drgn.helpers.common.memory.identify_address()`,
:func:`~drgn.helpers.common.type.member_at_offset()`, and
:meth:`drgn.StackFrame.locals()` are often crucial to an investigation.

Feel free to reference the :doc:`../helpers` and explore this core dump further.

Bonus Challenge: Reading File Pages
-----------------------------------

As a bonus, try dumping the contents of the file ``/init`` in the core dump
(this is the script that I used to reproduce the bug).

First, find the inode for ``/init`` and its file size.

.. details:: Hint

    See :func:`~drgn.helpers.linux.fs.path_lookup()`.

.. details:: Answer

    .. code-block::
        :class: tutorial

        >>> inode = path_lookup("/init").dentry.d_inode
        >>> inode
        *(struct inode *)0xffff88800289c568 = {
                ...
        }
        >>> inode.i_size
        (loff_t)578

The page cache for an inode is in an XArray, ``inode->i_mapping->i_pages``. Get
the cached page at offset 0.

.. details:: Hint

    See :func:`~drgn.helpers.linux.xarray.xa_load()` and :func:`~drgn.cast()`.

.. details:: Answer

    .. code-block::
        :class: tutorial

        >>> entry = xa_load(inode.i_mapping.i_pages.address_of_(), 0)
        >>> page = cast("struct page *", entry)
        >>> page
        *(struct page *)0xffffea000015f840 = {
                ...
        }

Get the page's virtual address.

.. details:: Hint

    See :func:`~drgn.helpers.linux.mm.page_to_virt()`.

.. details:: Answer

    .. code-block::
        :class: tutorial

        >>> addr = page_to_virt(page)
        >>> addr
        (void *)0xffff8880057e1000

Finally, read from the virtual address.

.. details:: Hint

    See :meth:`drgn.Program.read()`.

.. details:: Answer

    .. code-block::
        :class: tutorial

        >>> print(prog.read(addr, inode.i_size).decode())
        #!/bin/sh -e

        mount -t proc -o nosuid,nodev,noexec proc /proc
        mount -t devtmpfs -o nosuid dev /dev
        mkdir /dev/shm
        mount -t tmpfs -o nosuid,nodev tmpfs /dev/shm
        mount -t sysfs -o nosuid,nodev,noexec sys /sys
        mount -t tmpfs -o nosuid,nodev tmpfs /tmp
        kexec --load-panic --kexec-syscall-auto --command-line="root=/dev/vda rw console=ttyS0,115200 init=/kdump-init" vmlinuz
        echo 1 > /sys/block/vda/queue/wbt_lat_usec
        while true; do
                cat /init > /dev/null
        done &
        fio --name=writer --rw=randwrite --ioengine=sync --buffered=1 --bs=4K --time_based --runtime=3600 --size=16M
        poweroff -f
