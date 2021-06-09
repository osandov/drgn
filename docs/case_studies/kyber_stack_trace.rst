Using Stack Trace Variables to Find a Kyber Bug
===============================================

| Author: Omar Sandoval
| Date: June 9th, 2021

.. highlight:: pycon

Jakub Kicinski reported a crash in the `Kyber I/O scheduler
<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/block/kyber-iosched.c>`_
when he was testing Linux 5.12. He captured a core dump and asked me to debug
it. This is a quick writeup of that investigation.

First, we can get the task that crashed::

    >>> task = per_cpu(prog["runqueues"], prog["crashing_cpu"]).curr

Then, we can get its stack trace::

    >>> trace = prog.stack_trace(task)
    >>> trace
    #0  queued_spin_lock_slowpath (../kernel/locking/qspinlock.c:471:3)
    #1  queued_spin_lock (../include/asm-generic/qspinlock.h:85:2)
    #2  do_raw_spin_lock (../kernel/locking/spinlock_debug.c:113:2)
    #3  spin_lock (../include/linux/spinlock.h:354:2)
    #4  kyber_bio_merge (../block/kyber-iosched.c:573:2)
    #5  blk_mq_sched_bio_merge (../block/blk-mq-sched.h:37:9)
    #6  blk_mq_submit_bio (../block/blk-mq.c:2182:6)
    #7  __submit_bio_noacct_mq (../block/blk-core.c:1015:9)
    #8  submit_bio_noacct (../block/blk-core.c:1048:10)
    #9  submit_bio (../block/blk-core.c:1125:9)
    #10 submit_stripe_bio (../fs/btrfs/volumes.c:6553:2)
    #11 btrfs_map_bio (../fs/btrfs/volumes.c:6642:3)
    #12 btrfs_submit_data_bio (../fs/btrfs/inode.c:2440:8)
    #13 submit_one_bio (../fs/btrfs/extent_io.c:175:9)
    #14 submit_extent_page (../fs/btrfs/extent_io.c:3229:10)
    #15 __extent_writepage_io (../fs/btrfs/extent_io.c:3793:9)
    #16 __extent_writepage (../fs/btrfs/extent_io.c:3872:8)
    #17 extent_write_cache_pages (../fs/btrfs/extent_io.c:4514:10)
    #18 extent_writepages (../fs/btrfs/extent_io.c:4635:8)
    #19 do_writepages (../mm/page-writeback.c:2352:10)
    #20 __writeback_single_inode (../fs/fs-writeback.c:1467:8)
    #21 writeback_sb_inodes (../fs/fs-writeback.c:1732:3)
    #22 __writeback_inodes_wb (../fs/fs-writeback.c:1801:12)
    #23 wb_writeback (../fs/fs-writeback.c:1907:15)
    #24 wb_check_background_flush (../fs/fs-writeback.c:1975:10)
    #25 wb_do_writeback (../fs/fs-writeback.c:2063:11)
    #26 wb_workfn (../fs/fs-writeback.c:2091:20)
    #27 process_one_work (../kernel/workqueue.c:2275:2)
    #28 worker_thread (../kernel/workqueue.c:2421:4)
    #29 kthread (../kernel/kthread.c:292:9)
    #30 ret_from_fork+0x1f/0x2a (../arch/x86/entry/entry_64.S:294)

It looks like ``kyber_bio_merge()`` tried to lock an invalid spinlock. For
reference, this is the source code of ``kyber_bio_merge()``:

.. code-block:: c
   :lineno-start: 563

   static bool kyber_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio,
   			       unsigned int nr_segs)
   {
           struct kyber_hctx_data *khd = hctx->sched_data;
           struct blk_mq_ctx *ctx = blk_mq_get_ctx(hctx->queue);
           struct kyber_ctx_queue *kcq = &khd->kcqs[ctx->index_hw[hctx->type]];
           unsigned int sched_domain = kyber_sched_domain(bio->bi_opf);
           struct list_head *rq_list = &kcq->rq_list[sched_domain];
           bool merged;

           spin_lock(&kcq->lock);
           merged = blk_bio_list_merge(hctx->queue, rq_list, bio, nr_segs);
           spin_unlock(&kcq->lock);

           return merged;
   }

When printed, the ``kcq`` structure containing the spinlock indeed looks like
garbage (omitted for brevity).

A crash course on the Linux kernel block layer: for each block device, there is
a "software queue" (``struct blk_mq_ctx *ctx``) for each CPU and a "hardware
queue" (``struct blk_mq_hw_ctx *hctx``) for each I/O queue provided by the
device. Each hardware queue has one or more software queues assigned to it.
Kyber keeps additional data per hardware queue (``struct kyber_hctx_data
*khd``) and per software queue (``struct kyber_ctx_queue *kcq``).

Let's try to figure out where the bad ``kcq`` came from. It should be an
element of the ``khd->kcqs`` array (``khd`` is optimized out, but we can
recover it from ``hctx->sched_data``)::

    >>> trace[4]["khd"]
    (struct kyber_hctx_data *)<absent>
    >>> hctx = trace[4]["hctx"]
    >>> khd = cast("struct kyber_hctx_data *", hctx.sched_data)
    >>> trace[4]["kcq"] - khd.kcqs
    (ptrdiff_t)1
    >>> hctx.nr_ctx
    (unsigned short)1

So the ``kcq`` is for the second software queue, but the hardware queue is only
supposed to have one software queue. Let's see which CPU was assigned to the
hardware queue::

    >>> hctx.ctxs[0].cpu
    (unsigned int)6

Here's the problem: we're not running on CPU 6, we're running on CPU 19::

    >>> prog["crashing_cpu"]
    (int)19

And CPU 19 is assigned to a different hardware queue that actually does have
two software queues::

    >>> ctx = per_cpu_ptr(hctx.queue.queue_ctx, 19)
    >>> other_hctx = ctx.hctxs[hctx.type]
    >>> other_hctx == hctx
    False
    >>> other_hctx.nr_ctx
    (unsigned short)2

The bug is that the caller gets the ``hctx`` for the current CPU, then
``kyber_bio_merge()`` gets the ``ctx`` for the current CPU, and if the thread
is migrated to another CPU in between, they won't match. The fix is to get a
consistent view of the ``hctx`` and ``ctx``. The commit that fixes this is
`here
<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=efed9a3337e341bd0989161b97453b52567bc59d>`_.
