// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-or-later

// Linux kernel module for breakpoints on the running kernel for drgn.
//
// A breakpoint is a kprobe. A kprobe handler can't sleep, so it can't wait for
// a debugger. Instead, the handler makes the thread return to a trampoline in
// this module instead of to the breakpoint. The trampoline runs in the same
// context as the code that hit the breakpoint, so if that code could sleep,
// then the trampoline can, too. It sleeps until drgn, which finds out about it
// by reading from the device, tells it to continue. Then, it returns to the
// breakpoint. The thread hits the kprobe again, but this time, the handler
// recognizes it and lets it past.
//
// As a result:
//
// - Only the thread that hit a breakpoint stops. Everything else keeps
//   running.
// - A thread only stops if it has interrupts enabled and it can sleep. This
//   can only be detected if CONFIG_PREEMPT_COUNT is enabled. If it isn't, then
//   breakpoints must only be set where it is safe to sleep.
// - The exception is a breakpoint with DRGN_BREAKPOINT_ATOMIC, which is for
//   holding a thread in the middle of a race. If the thread can't sleep, then
//   it spins instead, with whatever it has disabled still disabled, so its
//   CPU does nothing else until it is resumed. Anything that needs that CPU
//   to respond waits, too. That includes adding and removing breakpoints, so
//   those fail while any thread is spinning.
// - This has only been used with kprobes that use a breakpoint instruction,
//   not ones that use ftrace.

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "drgn_breakpoint.h"

#ifndef CONFIG_X86_64
#error "only x86-64 is supported"
#endif

void drgn_breakpoint_trampoline(void);

// State of one open file.
struct drgn_breakpoint_session {
	// In drgn_breakpoint_sessions.
	struct list_head node;
	struct rcu_head rcu;
	// Process that opened the file.
	pid_t owner;
	// For readers.
	wait_queue_head_t event_wq;
};

struct drgn_breakpoint {
	struct kprobe kp;
	struct list_head node;
	struct drgn_breakpoint_session *session;
	u64 address;
	// DRGN_BREAKPOINT_*
	u32 flags;
	// If not 0, the only thread that stops.
	u32 tid;
	// Unique, so that a breakpoint can be told apart from an earlier one
	// at the same address.
	u64 id;
	atomic64_t hits;
	atomic64_t skipped;
	// Number of threads that the kprobe handler diverted that
	// drgn_breakpoint_hit() hasn't gotten what it needs from this for yet.
	atomic_t arriving;
};

enum drgn_breakpoint_thread_state {
	// The kprobe handler diverted the thread. It shouldn't stop again
	// before it is done, which would happen if there is a breakpoint on
	// something that drgn_breakpoint_hit() calls.
	DRGN_BREAKPOINT_THREAD_STOPPING,
	// The thread is waiting to be resumed.
	DRGN_BREAKPOINT_THREAD_STOPPED,
	// The thread is returning to the breakpoint with this ID and stack
	// pointer, where it shouldn't stop again.
	DRGN_BREAKPOINT_THREAD_RESUMING,
	// The thread was killed while it was stopped and drgn hasn't been told
	// yet. The thread itself is done with this.
	DRGN_BREAKPOINT_THREAD_KILLED,
};

// Thread that is stopped at a breakpoint or on its way to or from that.
struct drgn_breakpoint_thread {
	// NULL if unused. This is claimed with cmpxchg() by the kprobe handler
	// and otherwise only changed by the thread itself or with
	// drgn_breakpoint_mutex.
	struct task_struct *task;
	int state;
	unsigned long sp;
	u64 id;
	// The rest is protected by drgn_breakpoint_mutex and only valid if
	// stopped or killed.
	//
	// NULL if the session ended or let go of the thread.
	struct drgn_breakpoint_session *session;
	u32 tid;
	u32 cpu;
	u64 address;
	// On the thread's stack.
	struct pt_regs *regs;
	// Whether drgn was told that the thread stopped.
	bool reported;
	bool resume;
};

// The trampoline knows the layout of this.
struct drgn_breakpoint_saved {
	struct pt_regs regs;
	struct drgn_breakpoint *bp;
	struct drgn_breakpoint_thread *thread;
};

// Protects everything below except as noted.
static DEFINE_MUTEX(drgn_breakpoint_mutex);
// Breakpoints of all sessions. No two are at the same address.
static LIST_HEAD(drgn_breakpoints);
static u64 drgn_breakpoint_next_id = 1;
// Read with RCU by the kprobe handler.
static LIST_HEAD(drgn_breakpoint_sessions);

// Maximum number of threads that can be stopped at once.
#define DRGN_BREAKPOINT_MAX_THREADS 1024
static struct drgn_breakpoint_thread *drgn_breakpoint_threads;

#define for_each_drgn_breakpoint_thread(thread)				\
	for (thread = drgn_breakpoint_threads;				\
	     thread < &drgn_breakpoint_threads[DRGN_BREAKPOINT_MAX_THREADS];\
	     thread++)

// Number of threads that are between the kprobe handler diverting them and
// drgn_breakpoint_hit() returning.
static atomic_t drgn_breakpoint_num_stopped;
// Number of threads that are spinning until they are resumed.
static atomic_t drgn_breakpoint_num_spinning;
// For threads waiting to be resumed and anything waiting for them.
static DECLARE_WAIT_QUEUE_HEAD(drgn_breakpoint_wq);

static DEFINE_PER_CPU(struct drgn_breakpoint_saved, drgn_breakpoint_saved);

static struct drgn_breakpoint *drgn_breakpoint_find(u64 address)
{
	struct drgn_breakpoint *bp;

	list_for_each_entry(bp, &drgn_breakpoints, node) {
		if (bp->address == address)
			return bp;
	}
	return NULL;
}

static struct drgn_breakpoint *drgn_breakpoint_find_id(u64 id)
{
	struct drgn_breakpoint *bp;

	list_for_each_entry(bp, &drgn_breakpoints, node) {
		if (bp->id == id)
			return bp;
	}
	return NULL;
}

// Called by drgn_breakpoint_trampoline() with interrupts enabled. Must return
// with interrupts disabled.
__visible noinline void drgn_breakpoint_hit(struct pt_regs *regs,
					    struct drgn_breakpoint *bp,
					    struct drgn_breakpoint_thread *thread);
__visible noinline void drgn_breakpoint_hit(struct pt_regs *regs,
					    struct drgn_breakpoint *bp,
					    struct drgn_breakpoint_thread *thread)
{
	u64 id = bp->id;
	u64 address = bp->address;
	// The kprobe handler already checked that interrupts were enabled.
	bool can_sleep = !in_atomic() && !irqs_disabled()
			 && !rcu_preempt_depth();
	bool killed = false;

	if (!can_sleep && (bp->flags & DRGN_BREAKPOINT_ATOMIC) && in_task()) {
		// The breakpoint and its session can't go away until we're
		// done with them below.
		atomic64_inc(&bp->hits);
		thread->tid = current->pid;
		thread->cpu = raw_smp_processor_id();
		thread->address = address;
		thread->regs = regs;
		thread->reported = false;
		thread->resume = false;
		thread->session = bp->session;
		atomic_inc(&drgn_breakpoint_num_spinning);
		// Nothing looks at the above before this.
		smp_store_release(&thread->state,
				  DRGN_BREAKPOINT_THREAD_STOPPED);
		wake_up_interruptible(&bp->session->event_wq);
		if (atomic_dec_and_test(&bp->arriving))
			wake_up_all(&drgn_breakpoint_wq);

		while (!READ_ONCE(thread->resume)) {
			touch_nmi_watchdog();
			cpu_relax();
		}

		// Breakpoints can't be removed while we're spinning.
		WRITE_ONCE(thread->state, DRGN_BREAKPOINT_THREAD_RESUMING);
		atomic_dec(&drgn_breakpoint_num_spinning);
		wake_up_all(&drgn_breakpoint_wq);
		goto out;
	}

	if (!can_sleep) {
		atomic64_inc(&bp->skipped);
		WRITE_ONCE(thread->state, DRGN_BREAKPOINT_THREAD_RESUMING);
	}
	// The breakpoint can't be freed until we do this. We haven't slept
	// yet.
	if (atomic_dec_and_test(&bp->arriving))
		wake_up_all(&drgn_breakpoint_wq);

	if (can_sleep) {
		mutex_lock(&drgn_breakpoint_mutex);
		// The breakpoint may have been removed in the meantime.
		bp = drgn_breakpoint_find_id(id);
		if (bp) {
			atomic64_inc(&bp->hits);
			thread->session = bp->session;
			thread->tid = current->pid;
			thread->cpu = raw_smp_processor_id();
			thread->address = address;
			thread->regs = regs;
			thread->reported = false;
			thread->resume = false;
			WRITE_ONCE(thread->state,
				   DRGN_BREAKPOINT_THREAD_STOPPED);
			wake_up_interruptible(&bp->session->event_wq);
			mutex_unlock(&drgn_breakpoint_mutex);

			killed = wait_event_killable(drgn_breakpoint_wq,
						     READ_ONCE(thread->resume));

			mutex_lock(&drgn_breakpoint_mutex);
			// If nobody is waiting to resume it, then nobody
			// needs to know.
			killed = killed && thread->session;
		}
		// If the breakpoint is gone, then there is nothing to get
		// past.
		if (killed) {
			WRITE_ONCE(thread->state,
				   DRGN_BREAKPOINT_THREAD_KILLED);
			wake_up_interruptible(&thread->session->event_wq);
		} else if (drgn_breakpoint_find_id(id))
			WRITE_ONCE(thread->state,
				   DRGN_BREAKPOINT_THREAD_RESUMING);
		else
			WRITE_ONCE(thread->task, NULL);
		mutex_unlock(&drgn_breakpoint_mutex);
	}

out:
	local_irq_disable();
	if (atomic_dec_and_test(&drgn_breakpoint_num_stopped))
		wake_up_all(&drgn_breakpoint_wq);
}

static int drgn_breakpoint_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct drgn_breakpoint *bp =
		container_of(p, struct drgn_breakpoint, kp);
	struct drgn_breakpoint_session *session;
	struct drgn_breakpoint_thread *thread;
	struct drgn_breakpoint_saved *saved;

	if (bp->tid && current->pid != bp->tid)
		goto skip;
	// The thread can't sleep with interrupts disabled. Don't stop a
	// thread that wouldn't wait, either.
	if ((!(regs->flags & X86_EFLAGS_IF)
	     && !(bp->flags & DRGN_BREAKPOINT_ATOMIC))
	    || fatal_signal_pending(current))
		goto skip;
	// Don't stop a debugger: it would never be able to resume itself, and
	// two of them could stop each other.
	list_for_each_entry_rcu(session, &drgn_breakpoint_sessions, node) {
		if (current->tgid == session->owner)
			goto skip;
	}

	for_each_drgn_breakpoint_thread(thread) {
		int state;

		if (READ_ONCE(thread->task) != current)
			continue;
		state = READ_ONCE(thread->state);
		// This is from a thread that is gone.
		if (state == DRGN_BREAKPOINT_THREAD_KILLED)
			continue;
		if (state != DRGN_BREAKPOINT_THREAD_RESUMING)
			goto skip;
		if (thread->id == bp->id && thread->sp == regs->sp) {
			// The thread is returning from stopping here.
			WRITE_ONCE(thread->task, NULL);
			return 0;
		}
	}

	for_each_drgn_breakpoint_thread(thread) {
		if (!READ_ONCE(thread->task)
		    && !cmpxchg(&thread->task, NULL, current))
			goto found;
	}
	goto skip;

found:
	thread->state = DRGN_BREAKPOINT_THREAD_STOPPING;
	thread->sp = regs->sp;
	thread->id = bp->id;

	atomic_inc(&drgn_breakpoint_num_stopped);
	atomic_inc(&bp->arriving);
	// Interrupts stay disabled until the trampoline has copied this.
	saved = this_cpu_ptr(&drgn_breakpoint_saved);
	saved->regs = *regs;
	saved->regs.ip = (unsigned long)p->addr;
	saved->bp = bp;
	saved->thread = thread;
	regs->di = (unsigned long)saved;
	regs->ip = (unsigned long)drgn_breakpoint_trampoline;
	regs->flags &= ~X86_EFLAGS_IF;
	// We changed where the thread is returning to.
	return 1;

skip:
	atomic64_inc(&bp->skipped);
	return 0;
}

static void drgn_breakpoint_post_handler(struct kprobe *p,
					 struct pt_regs *regs,
					 unsigned long flags)
{
	// A kprobe with a post-handler is never optimized. An optimized
	// kprobe can't change where the thread is returning to.
}

// Adding or removing a kprobe needs every CPU to respond.
static bool drgn_breakpoint_can_change(void)
{
	return atomic_read(&drgn_breakpoint_num_spinning) == 0;
}

static int drgn_breakpoint_add(struct drgn_breakpoint_session *session,
			       const struct drgn_breakpoint_add *add)
{
	struct drgn_breakpoint *bp;
	int r;

	if (add->flags & ~DRGN_BREAKPOINT_ATOMIC)
		return -EINVAL;
	bp = drgn_breakpoint_find(add->address);
	if (bp)
		return bp->session == session ? -EEXIST : -EBUSY;
	if (!drgn_breakpoint_can_change())
		return -EBUSY;

	bp = kzalloc(sizeof(*bp), GFP_KERNEL);
	if (!bp)
		return -ENOMEM;
	bp->session = session;
	bp->address = add->address;
	bp->flags = add->flags;
	bp->tid = add->tid;
	bp->id = drgn_breakpoint_next_id++;
	bp->kp.addr = (kprobe_opcode_t *)(unsigned long)add->address;
	bp->kp.pre_handler = drgn_breakpoint_pre_handler;
	bp->kp.post_handler = drgn_breakpoint_post_handler;
	r = register_kprobe(&bp->kp);
	if (r < 0) {
		kfree(bp);
		return r;
	}
	list_add_tail(&bp->node, &drgn_breakpoints);
	return 0;
}

static void drgn_breakpoint_remove(struct drgn_breakpoint *bp)
{
	struct drgn_breakpoint_thread *thread;

	list_del(&bp->node);
	// After this, the handler isn't running and won't run again.
	unregister_kprobe(&bp->kp);
	// This doesn't take long because they don't sleep or take
	// drgn_breakpoint_mutex before they're done with it.
	wait_event(drgn_breakpoint_wq, atomic_read(&bp->arriving) == 0);

	// Any threads that were returning to it don't have anything to get
	// past anymore. Nothing else changes these without the handler, and
	// nothing can start returning to it without the mutex.
	for_each_drgn_breakpoint_thread(thread) {
		if (READ_ONCE(thread->task)
		    && READ_ONCE(thread->state)
		       == DRGN_BREAKPOINT_THREAD_RESUMING
		    && thread->id == bp->id)
			WRITE_ONCE(thread->task, NULL);
	}
	kfree(bp);
}

// Remove all breakpoints and resume all threads.
static void drgn_breakpoint_detach(struct drgn_breakpoint_session *session)
{
	struct drgn_breakpoint *bp, *tmp;
	struct drgn_breakpoint_thread *thread;

	// Atomic breakpoints can still be hit, but not by threads that stay:
	// nobody is listening.
	list_for_each_entry(bp, &drgn_breakpoints, node) {
		if (bp->session == session)
			WRITE_ONCE(bp->flags, 0);
	}
	for_each_drgn_breakpoint_thread(thread) {
		if (!READ_ONCE(thread->task)
		    || READ_ONCE(thread->session) != session)
			continue;
		if (READ_ONCE(thread->state)
		    == DRGN_BREAKPOINT_THREAD_STOPPED) {
			thread->session = NULL;
			WRITE_ONCE(thread->resume, true);
		} else if (thread->state == DRGN_BREAKPOINT_THREAD_KILLED) {
			WRITE_ONCE(thread->task, NULL);
		}
	}
	wake_up_all(&drgn_breakpoint_wq);
	// Any that were spinning need to be done before breakpoints can be
	// removed. If another session has one spinning, then this waits for
	// that session to resume it.
	wait_event(drgn_breakpoint_wq, drgn_breakpoint_can_change());

	list_for_each_entry_safe(bp, tmp, &drgn_breakpoints, node) {
		if (bp->session == session)
			drgn_breakpoint_remove(bp);
	}
}

static int drgn_breakpoint_resume(struct drgn_breakpoint_session *session,
				  u32 tid)
{
	struct drgn_breakpoint_thread *thread;

	for_each_drgn_breakpoint_thread(thread) {
		if (READ_ONCE(thread->task) && thread->session == session
		    && thread->state == DRGN_BREAKPOINT_THREAD_STOPPED
		    && thread->tid == tid) {
			thread->session = NULL;
			WRITE_ONCE(thread->resume, true);
			wake_up_all(&drgn_breakpoint_wq);
			return 0;
		}
	}
	return -ESRCH;
}

static bool drgn_breakpoint_thread_has_event(struct drgn_breakpoint_session *session,
					     struct drgn_breakpoint_thread *thread)
{
	int state;

	if (!READ_ONCE(thread->task) || READ_ONCE(thread->session) != session)
		return false;
	state = READ_ONCE(thread->state);
	return (state == DRGN_BREAKPOINT_THREAD_STOPPED
		&& !READ_ONCE(thread->reported))
	       || state == DRGN_BREAKPOINT_THREAD_KILLED;
}

static bool drgn_breakpoint_has_event(struct drgn_breakpoint_session *session)
{
	struct drgn_breakpoint_thread *thread;

	for_each_drgn_breakpoint_thread(thread) {
		if (drgn_breakpoint_thread_has_event(session, thread))
			return true;
	}
	return false;
}

static bool drgn_breakpoint_next_event(struct drgn_breakpoint_session *session,
				       struct drgn_breakpoint_event *event)
{
	struct drgn_breakpoint_thread *thread;

	for_each_drgn_breakpoint_thread(thread) {
		if (!drgn_breakpoint_thread_has_event(session, thread))
			continue;
		memset(event, 0, sizeof(*event));
		event->tid = thread->tid;
		event->cpu = thread->cpu;
		event->address = thread->address;
		if (thread->state == DRGN_BREAKPOINT_THREAD_KILLED) {
			event->type = DRGN_BREAKPOINT_EVENT_KILLED;
			WRITE_ONCE(thread->task, NULL);
		} else {
			event->type = DRGN_BREAKPOINT_EVENT_STOPPED;
			memcpy(event->regs, thread->regs,
			       sizeof(event->regs));
			WRITE_ONCE(thread->reported, true);
		}
		return true;
	}
	return false;
}

static ssize_t drgn_breakpoint_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct drgn_breakpoint_session *session = file->private_data;
	struct drgn_breakpoint_event event;
	bool found;
	int r;

	if (count < sizeof(event))
		return -EINVAL;
	for (;;) {
		mutex_lock(&drgn_breakpoint_mutex);
		found = drgn_breakpoint_next_event(session, &event);
		mutex_unlock(&drgn_breakpoint_mutex);
		if (found)
			break;
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		r = wait_event_interruptible(session->event_wq,
					     drgn_breakpoint_has_event(session));
		if (r)
			return r;
	}
	if (copy_to_user(buf, &event, sizeof(event)))
		return -EFAULT;
	return sizeof(event);
}

static __poll_t drgn_breakpoint_poll(struct file *file, poll_table *wait)
{
	struct drgn_breakpoint_session *session = file->private_data;

	poll_wait(file, &session->event_wq, wait);
	return drgn_breakpoint_has_event(session) ? EPOLLIN | EPOLLRDNORM : 0;
}

static int drgn_breakpoint_open(struct inode *inode, struct file *file)
{
	struct drgn_breakpoint_session *session;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;
	session->owner = current->tgid;
	init_waitqueue_head(&session->event_wq);
	file->private_data = session;
	mutex_lock(&drgn_breakpoint_mutex);
	list_add_rcu(&session->node, &drgn_breakpoint_sessions);
	mutex_unlock(&drgn_breakpoint_mutex);
	return 0;
}

static int drgn_breakpoint_release(struct inode *inode, struct file *file)
{
	struct drgn_breakpoint_session *session = file->private_data;

	mutex_lock(&drgn_breakpoint_mutex);
	drgn_breakpoint_detach(session);
	list_del_rcu(&session->node);
	mutex_unlock(&drgn_breakpoint_mutex);
	kfree_rcu(session, rcu);
	return 0;
}

static long drgn_breakpoint_ioctl_locked(struct drgn_breakpoint_session *session,
					 unsigned int cmd, void __user *uarg)
{
	struct drgn_breakpoint_stats stats;
	struct drgn_breakpoint_add add;
	struct drgn_breakpoint *bp;
	u64 address;
	u32 tid;

	switch (cmd) {
	case DRGN_BREAKPOINT_DETACH:
		drgn_breakpoint_detach(session);
		return 0;
	case DRGN_BREAKPOINT_ADD:
		if (copy_from_user(&add, uarg, sizeof(add)))
			return -EFAULT;
		return drgn_breakpoint_add(session, &add);
	case DRGN_BREAKPOINT_REMOVE:
		if (copy_from_user(&address, uarg, sizeof(address)))
			return -EFAULT;
		bp = drgn_breakpoint_find(address);
		if (!bp || bp->session != session)
			return -ENOENT;
		if (!drgn_breakpoint_can_change())
			return -EBUSY;
		drgn_breakpoint_remove(bp);
		return 0;
	case DRGN_BREAKPOINT_GET_STATS:
		if (copy_from_user(&stats, uarg, sizeof(stats)))
			return -EFAULT;
		bp = drgn_breakpoint_find(stats.address);
		if (!bp || bp->session != session)
			return -ENOENT;
		stats.hits = atomic64_read(&bp->hits);
		stats.skipped = atomic64_read(&bp->skipped);
		if (copy_to_user(uarg, &stats, sizeof(stats)))
			return -EFAULT;
		return 0;
	case DRGN_BREAKPOINT_RESUME:
		if (copy_from_user(&tid, uarg, sizeof(tid)))
			return -EFAULT;
		return drgn_breakpoint_resume(session, tid);
	default:
		return -ENOTTY;
	}
}

static long drgn_breakpoint_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long r;

	mutex_lock(&drgn_breakpoint_mutex);
	r = drgn_breakpoint_ioctl_locked(file->private_data, cmd,
					 (void __user *)arg);
	mutex_unlock(&drgn_breakpoint_mutex);
	return r;
}

static const struct file_operations drgn_breakpoint_fops = {
	.owner = THIS_MODULE,
	.open = drgn_breakpoint_open,
	.read = drgn_breakpoint_read,
	.poll = drgn_breakpoint_poll,
	.release = drgn_breakpoint_release,
	.unlocked_ioctl = drgn_breakpoint_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice drgn_breakpoint_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "drgn_breakpoint",
	.fops = &drgn_breakpoint_fops,
	.mode = 0600,
};

static int __init drgn_breakpoint_init(void)
{
	int r;

	BUILD_BUG_ON(sizeof(struct pt_regs) != 168);
	BUILD_BUG_ON(sizeof(struct pt_regs)
		     != sizeof_field(struct drgn_breakpoint_event, regs));
	BUILD_BUG_ON(offsetof(struct drgn_breakpoint_saved, bp) != 168);
	BUILD_BUG_ON(offsetof(struct drgn_breakpoint_saved, thread) != 176);

	drgn_breakpoint_threads = kvcalloc(DRGN_BREAKPOINT_MAX_THREADS,
					   sizeof(drgn_breakpoint_threads[0]),
					   GFP_KERNEL);
	if (!drgn_breakpoint_threads)
		return -ENOMEM;
	r = misc_register(&drgn_breakpoint_device);
	if (r)
		kvfree(drgn_breakpoint_threads);
	return r;
}

static void __exit drgn_breakpoint_exit(void)
{
	// The device can't be open, so there aren't any breakpoints.
	misc_deregister(&drgn_breakpoint_device);
	// There may still be threads that are on their way back to their
	// breakpoint. They have interrupts disabled from when they're counted
	// until they are out of this module.
	wait_event(drgn_breakpoint_wq,
		   atomic_read(&drgn_breakpoint_num_stopped) == 0);
	synchronize_rcu();
	kvfree(drgn_breakpoint_threads);
}

module_init(drgn_breakpoint_init);
module_exit(drgn_breakpoint_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Breakpoints on the running kernel for drgn");
