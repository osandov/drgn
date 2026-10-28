/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

/*
 * Interface between the drgn_breakpoint kernel module and drgn.
 *
 * drgn opens /dev/drgn_breakpoint and adds breakpoints. When a thread hits a
 * breakpoint, it sleeps until it is resumed. Reading from the device returns
 * one struct drgn_breakpoint_event at a time; if there aren't any, it blocks
 * unless the file is non-blocking. The device can be polled for events.
 *
 * Each open file has its own breakpoints and stopped threads, but no two can
 * have a breakpoint at the same address. Threads in a process that opened the
 * device and still has it open never stop at breakpoints.
 *
 * Closing the file removes its breakpoints and resumes its threads. Note that
 * a file is not closed until every process that has it is done with it,
 * including any that inherited it.
 */

#ifndef DRGN_BREAKPOINT_H
#define DRGN_BREAKPOINT_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct drgn_breakpoint_stats {
	/* Address passed to DRGN_BREAKPOINT_ADD. */
	__u64 address;
	/* Number of times that a thread stopped at the breakpoint. */
	__u64 hits;
	/*
	 * Number of times that a thread got to the breakpoint but couldn't
	 * stop because of what it was in the middle of.
	 */
	__u64 skipped;
};

enum {
	/*
	 * Stop even if the thread can't sleep, as long as it isn't handling
	 * an interrupt. In that case, it spins, so its CPU does nothing else
	 * until it is resumed. While any thread is doing that, breakpoints
	 * can't be added or removed.
	 */
	DRGN_BREAKPOINT_ATOMIC = 1 << 0,
};

struct drgn_breakpoint_add {
	__u64 address;
	/* DRGN_BREAKPOINT_* */
	__u32 flags;
	/* If not 0, the only thread that stops, by thread ID. */
	__u32 tid;
};

#define DRGN_BREAKPOINT_IOC_MAGIC 0xdb

/*
 * Add or remove a breakpoint at an address. Adding fails with EBUSY if
 * another file has one there.
 */
#define DRGN_BREAKPOINT_ADD \
	_IOW(DRGN_BREAKPOINT_IOC_MAGIC, 0, struct drgn_breakpoint_add)
#define DRGN_BREAKPOINT_REMOVE _IOW(DRGN_BREAKPOINT_IOC_MAGIC, 1, __u64)
#define DRGN_BREAKPOINT_GET_STATS \
	_IOWR(DRGN_BREAKPOINT_IOC_MAGIC, 2, struct drgn_breakpoint_stats)
/* Resume a stopped thread by thread ID. */
#define DRGN_BREAKPOINT_RESUME _IOW(DRGN_BREAKPOINT_IOC_MAGIC, 3, __u32)
/* Remove all breakpoints and resume all threads. */
#define DRGN_BREAKPOINT_DETACH _IO(DRGN_BREAKPOINT_IOC_MAGIC, 4)

enum {
	/* A thread stopped at a breakpoint. */
	DRGN_BREAKPOINT_EVENT_STOPPED = 0,
	/* A stopped thread was killed, so it isn't stopped anymore. */
	DRGN_BREAKPOINT_EVENT_KILLED = 1,
};

struct drgn_breakpoint_event {
	/* DRGN_BREAKPOINT_EVENT_* */
	__u32 type;
	/* Thread ID in the initial PID namespace. */
	__u32 tid;
	__u32 cpu;
	__u32 reserved;
	/* Address passed to DRGN_BREAKPOINT_ADD. */
	__u64 address;
	/*
	 * struct pt_regs at the breakpoint for DRGN_BREAKPOINT_EVENT_STOPPED,
	 * unused otherwise.
	 */
	__u64 regs[21];
};

#endif /* DRGN_BREAKPOINT_H */
