// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "breakpoint.h"
#include "cleanup.h"
#include "error.h"
#include "event.h"
#include "execution_control.h"
#include "hash_table.h"
#include "list.h"
#include "program.h"
#include "thread.h"
#include "util.h"

DEFINE_DEQUE_FUNCTIONS(drgn_event_deque);

static inline uint64_t
drgn_breakpoint_site_to_key(struct drgn_breakpoint_site * const *entry)
{
	return (*entry)->address;
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_breakpoint_site_table,
			    drgn_breakpoint_site_to_key, int_key_hash_pair,
			    scalar_key_eq);

struct drgn_breakpoint_iterator {
	struct drgn_program *prog;
	struct drgn_breakpoint_site *site;
	uint64_t generation;
	const struct list_head *head;
	struct list_head *next;
};

struct drgn_breakpoint_site_iterator {
	struct drgn_program *prog;
	uint64_t generation;
	struct drgn_breakpoint_site_table_iterator it;
};

static struct drgn_execution_controller *
get_enabled_controller(struct drgn_program *prog)
{
	return drgn_handler_list_first_enabled(&prog->execution_controllers);
}

static struct drgn_error exited_error =
	DRGN_ERROR_INIT(DRGN_ERROR_PROGRAM_EXITED, "program exited");

static struct drgn_error not_attached_error =
	DRGN_ERROR_INIT(DRGN_ERROR_NOT_ATTACHED, "not attached to program");

static struct drgn_error no_events_error =
	DRGN_ERROR_INIT(DRGN_ERROR_NO_EVENTS, "no events available");

struct drgn_error *
drgn_execution_controller_init(struct drgn_program *prog,
			       struct drgn_execution_controller *controller)
{
	if (!controller->ops.attach) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "drgn_execution_controller_ops::attach is required");
	}
	if (!controller->ops.detach) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "drgn_execution_controller_ops::detach is required");
	}
	if (!controller->ops.queue_events) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "drgn_execution_controller_ops::queue_events is required");
	}
	if (!controller->ops.enable_breakpoint_sites
	    != !controller->ops.disable_breakpoint_sites) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "drgn_execution_controller_ops::enable_breakpoint_sites and disable_breakpoint_sites must both be set or both be unset");
	}
	return NULL;
}

struct drgn_error *
drgn_execution_controller_check_change_enabled(struct drgn_program *prog,
					       bool multiple)
{
	if (prog->attach_state != DRGN_ATTACH_STATE_DETACHED) {
		return drgn_error_create(DRGN_ERROR_ALREADY_ATTACHED,
					 "cannot change execution controller while attached");
	}
	if (multiple) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "only one execution controller may be enabled");
	}
	return NULL;
}

static struct drgn_error *check_attached(struct drgn_program *prog)
{
	if (prog->attach_state == DRGN_ATTACH_STATE_DETACHED)
		return &not_attached_error;
	else if (prog->attach_state == DRGN_ATTACH_STATE_EXITED)
		return &exited_error;
	return NULL;
}

static inline struct drgn_error *
sync_events_and_check_attached(struct drgn_program *prog, bool sync_events)
{
	if (sync_events) {
		struct drgn_error *err = drgn_program_sync_events(prog, false);
		if (err)
			return err;
		// drgn_program_sync_events() calls check_attached() before
		// syncing, but we have to check again since a process exit
		// event may have been queued.
	}
	return check_attached(prog);
}

void drgn_program_init_execution_control(struct drgn_program *prog)
{
	drgn_event_deque_init(&prog->event_queue);
	drgn_breakpoint_site_table_init(&prog->breakpoint_sites);
	INIT_LIST_HEAD(&prog->breakpoints);
	INIT_LIST_HEAD(&prog->stopped_threads);
	INIT_LIST_HEAD(&prog->resumed_threads);
	INIT_LIST_HEAD(&prog->running_threads);
}

static void clear_events(struct drgn_program *prog)
{
	while (!drgn_event_deque_empty(&prog->event_queue))
		drgn_event_decref(*drgn_event_deque_pop_first(&prog->event_queue));
}

static void clear_running_threads(struct drgn_program *prog)
{
	struct drgn_thread *thread, *tmp;
	list_for_each_entry_safe(thread, tmp, &prog->running_threads, node) {
		list_del_init(&thread->node);
		drgn_thread_decref(thread);
	}
}

static void clear_controlled_threads(struct drgn_program *prog)
{
	struct drgn_thread *thread, *tmp;
	// Detach implicitly resumes all threads. At deinit, we don't care
	// anymore.
	list_for_each_entry_safe(thread, tmp, &prog->stopped_threads, node) {
		thread->last_signal = 0;
		list_del_init(&thread->node);
		drgn_thread_decref(thread);
	}
	list_for_each_entry_safe(thread, tmp, &prog->resumed_threads, node) {
		thread->last_signal = 0;
		thread->resume_signal = -1;
		list_del_init(&thread->node);
		drgn_thread_decref(thread);
	}
	clear_running_threads(prog);
}

static void drgn_breakpoint_remove_impl(struct drgn_breakpoint *bp)
{
	assert(!bp->enabled);
	struct drgn_program *prog = drgn_breakpoint_program(bp);

	for (size_t i = 0; i < bp->num_sites; i++) {
		struct drgn_breakpoint_site_node *site_node =
			&bp->site_nodes[i];
		list_del_init(&site_node->node);
		site_node->site->lists_generation++;
		if (list_empty(&site_node->site->enabled_breakpoints)
		    && list_empty(&site_node->site->disabled_breakpoints)) {
			drgn_breakpoint_site_table_delete_entry(&prog->breakpoint_sites,
								&site_node->site);
			prog->breakpoint_sites_generation++;
		}
	}

	if (!list_empty(&bp->prog_node)) {
		list_del_init(&bp->prog_node);
		prog->breakpoints_generation++;
		// Drop the reference held by prog->breakpoints. Note that this
		// could be the last reference.
		drgn_breakpoint_decref(bp);
	}
}

static void clear_breakpoints(struct drgn_program *prog)
{
	struct drgn_breakpoint *bp, *tmp;
	list_for_each_entry_safe(bp, tmp, &prog->breakpoints, prog_node) {
		// Detach implicitly disables all remaining breakpoints. At
		// deinit, we don't care anymore.
		bp->enabled = false;
		drgn_breakpoint_remove_impl(bp);
	}
}

void drgn_program_clear_execution_control(struct drgn_program *prog)
{
	clear_events(prog);
	clear_controlled_threads(prog);
	clear_breakpoints(prog);
}

int drgn_program_traverse_execution_control(struct drgn_program *prog,
	    int (*visit_event)(struct drgn_event *, void *),
	    int (*visit_thread)(struct drgn_thread *, void *),
	    int (*visit_breakpoint)(struct drgn_breakpoint *, void *),
	    int (*visit_breakpoint_site)(struct drgn_breakpoint_site *, void *),
	    void *arg)
{
	int ret;
	for (size_t i = 0, n = drgn_event_deque_size(&prog->event_queue);
	     i < n; i++) {
		ret = visit_event(*drgn_event_deque_at(&prog->event_queue, i),
				  arg);
		if (ret)
			return ret;
	}
	struct drgn_thread *thread;
	list_for_each_entry(thread, &prog->stopped_threads, node) {
		ret = visit_thread(thread, arg);
		if (ret)
			return ret;
	}
	list_for_each_entry(thread, &prog->resumed_threads, node) {
		ret = visit_thread(thread, arg);
		if (ret)
			return ret;
	}
	list_for_each_entry(thread, &prog->running_threads, node) {
		ret = visit_thread(thread, arg);
		if (ret)
			return ret;
	}
	struct drgn_breakpoint *bp;
	list_for_each_entry(bp, &prog->breakpoints, prog_node) {
		ret = visit_breakpoint(bp, arg);
		if (ret)
			return ret;
	}
	hash_table_for_each(drgn_breakpoint_site_table, it,
			    &prog->breakpoint_sites) {
		ret = visit_breakpoint_site(*it.entry, arg);
		if (ret)
			return ret;
	}
	return 0;
}

void drgn_program_deinit_execution_control(struct drgn_program *prog)
{
	drgn_program_clear_execution_control(prog);
	drgn_event_deque_deinit(&prog->event_queue);
	drgn_breakpoint_site_table_deinit(&prog->breakpoint_sites);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_attach(struct drgn_program *prog, enum drgn_attach_flags flags)
{
	if (prog->attach_state != DRGN_ATTACH_STATE_DETACHED) {
		return drgn_error_create(DRGN_ERROR_ALREADY_ATTACHED,
					 "already attached to program");
	}
	if (flags & ~(DRGN_ATTACH_NON_STOP | DRGN_ATTACH_ALL_STOP
		      | DRGN_ATTACH_INTERRUPT)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "unknown attach flag");
	}
	if ((flags & DRGN_ATTACH_NON_STOP) && (flags & DRGN_ATTACH_ALL_STOP)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "NON_STOP and ALL_STOP are mutually exclusive");
	}
	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (!ctrl) {
		return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
					 "no execution controller is enabled");
	}
	bool all_stop;
	struct drgn_error *err = ctrl->ops.attach(ctrl->arg, prog, flags,
						  &all_stop);
	if (err)
		return err;
	prog->attach_state = DRGN_ATTACH_STATE_ATTACHED;
	prog->all_stop = all_stop;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_detach(struct drgn_program *prog)
{
	struct drgn_error *err;

	if (prog->attach_state == DRGN_ATTACH_STATE_DETACHED)
		return NULL;

	if (prog->resuming_threads) {
		return drgn_error_create(DRGN_ERROR_RUNTIME,
					 "detaching while resuming threads is not allowed");
	}
	if (prog->modifying_breakpoints) {
		return drgn_error_format(DRGN_ERROR_RUNTIME,
					 "detaching while %s a breakpoint is not allowed",
					 prog->modifying_breakpoints);
	}

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	err = ctrl->ops.detach(ctrl->arg, prog);
	if (err)
		return err;

	drgn_program_clear_execution_control(prog);
	prog->attach_state = DRGN_ATTACH_STATE_DETACHED;
	prog->in_all_stop = false;
	return NULL;
}

LIBDRGN_PUBLIC enum drgn_attach_state
drgn_program_attach_state(const struct drgn_program *prog)
{
	return prog->attach_state;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_get_all_stop(struct drgn_program *prog, bool *ret)
{
	// Not check_attached() because it's fine to query this on an exited
	// program.
	if (prog->attach_state == DRGN_ATTACH_STATE_DETACHED)
		return &not_attached_error;
	*ret = prog->all_stop;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_all_stop(struct drgn_program *prog, bool all_stop,
			  bool sync_events)
{
	struct drgn_error *err;

	err = sync_events_and_check_attached(prog, sync_events);
	if (err)
		return err;

	if (prog->all_stop == all_stop)
		return NULL;

	// Changing all_stop in the middle of a resume makes it difficult to
	// update in_all_stop correctly. There's no good reason for a controller
	// to be doing that, anyways, so disallow it.
	if (prog->resuming_threads) {
		return drgn_error_create(DRGN_ERROR_RUNTIME,
					 "changing stop mode while resuming threads is not allowed");
	}

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (!ctrl->ops.set_all_stop) {
		return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
					 "changing stop mode is not supported");
	}
	err = ctrl->ops.set_all_stop(ctrl->arg, prog, all_stop);
	if (err)
		return err;
	prog->all_stop = all_stop;
	// This only affects future events, so we don't touch in_all_stop.
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_interrupt_any_thread(struct drgn_program *prog)
{
	struct drgn_error *err = check_attached(prog);
	if (err)
		return err;
	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (!ctrl->ops.interrupt_any_thread) {
		return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
					 "interrupting any thread is not supported");
	}
	return ctrl->ops.interrupt_any_thread(ctrl->arg, prog);
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_thread_stopped(struct drgn_thread *thread,
				       bool sync_events, int *ret)
{
	struct drgn_program *prog = drgn_thread_program(thread);

	// We allow calling this when not attached (it should always return 0),
	// so only sync if attached.
	if (sync_events
	    && prog->attach_state == DRGN_ATTACH_STATE_ATTACHED) {
		struct drgn_error *err = drgn_program_sync_events(prog, false);
		if (err)
			return err;
	}

	if (list_empty(&thread->node))
		*ret = prog->in_all_stop ? -1 : 0;
	else if (thread->last_signal > 0)
		*ret = thread->last_signal;
	else if (thread->resume_signal >= 0)
		*ret = -1;
	else
		*ret = 0;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_interrupt(struct drgn_thread *thread)
{
	struct drgn_program *prog = drgn_thread_program(thread);
	struct drgn_error *err = check_attached(prog);
	if (err)
		return err;
	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (!ctrl->ops.interrupt_thread) {
		return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
					 "interrupting specific thread is not supported");
	}
	return ctrl->ops.interrupt_thread(ctrl->arg, thread);
}

#define resuming_threads_guard(prog)					\
	if (prog->resuming_threads) {					\
		return drgn_error_create(DRGN_ERROR_RUNTIME,		\
					 "resuming threads while resuming other threads is not allowed");\
	}								\
	(prog)->resuming_threads = true;				\
	__attribute__((__cleanup__(resuming_threads_guard_cleanup),	\
		       __unused__))					\
	struct drgn_program *resuming_threads_prog = (prog)

static inline void
resuming_threads_guard_cleanup(struct drgn_program **progp)
{
	(*progp)->resuming_threads = false;
}

static inline void move_thread(struct drgn_thread *thread,
			       struct list_head *list)
{
	if (list_empty(&thread->node)) {
		drgn_thread_incref(thread);
		list_add_tail(&thread->node, list);
	} else {
		list_move_tail(&thread->node, list);
	}
}

static void set_resume_signal(struct drgn_thread *thread, int sig)
{
	if (sig == DRGN_RESUME_DEFAULT_SIGNAL) {
		if (thread->resume_signal >= 0)
			return;
		sig = thread->last_signal;
		if (sig == SIGINT || sig == SIGTRAP)
			sig = 0;
	}
	thread->resume_signal = sig;
}

static void clear_resumed_threads(struct drgn_program *prog,
				  struct drgn_thread * const *threads, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		struct drgn_thread *thread = threads[i];
		if (thread->resume_signal < 0) {
			// The thread stopped again while resuming.
			continue;
		}
		thread->last_signal = 0;
		thread->resume_signal = -1;
		if (!list_empty(&thread->node)) {
			list_del_init(&thread->node);
			drgn_thread_decref(thread);
		}
	}
}

static void add_running_threads(struct drgn_program *prog,
				struct drgn_thread * const *threads, size_t n)
{
	if (!prog->in_all_stop) {
		clear_resumed_threads(prog, threads, n);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		struct drgn_thread *thread = threads[i];
		if (thread->resume_signal < 0) {
			// The thread stopped again while resuming.
			continue;
		}
		thread->last_signal = 0;
		thread->resume_signal = -1;
		move_thread(thread, &prog->running_threads);
	}
}

// Common case is resuming one thread, so pass inline_size as 1.
DEFINE_VECTOR(drgn_thread_vector, struct drgn_thread *, 1);
DEFINE_VECTOR(signal_vector, int, 1);

static struct drgn_error *
resume_all_threads(struct drgn_program *prog,
		   struct drgn_execution_controller *ctrl)
{
	struct drgn_error *err;
	VECTOR(drgn_thread_vector, threads);
	VECTOR(signal_vector, sigs);
	struct drgn_thread *thread;
	list_for_each_entry(thread, &prog->resumed_threads, node) {
		if (!drgn_thread_vector_append(&threads, &thread)
		    || !signal_vector_append(&sigs, &thread->resume_signal))
			return &drgn_enomem;
	}

	err = (prog->in_all_stop
	       ? ctrl->ops.resume_all_threads
	       : ctrl->ops.resume_only_threads)(ctrl->arg, prog,
						drgn_thread_vector_begin(&threads),
						signal_vector_begin(&sigs),
						drgn_thread_vector_size(&threads));
	if (err)
		return err;

	clear_resumed_threads(prog, drgn_thread_vector_begin(&threads),
			      drgn_thread_vector_size(&threads));
	if (prog->in_all_stop) {
		clear_running_threads(prog);
		// If any threads stopped while resuming, we're still in
		// all-stop.
		if (list_empty(&prog->stopped_threads))
			prog->in_all_stop = false;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_resume(struct drgn_thread *thread, int sig, bool only,
		   bool sync_events)
{
	struct drgn_error *err;

	if (sig < 0 && sig != DRGN_RESUME_DEFAULT_SIGNAL) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "resume signal must be non-negative");
	}

	struct drgn_program *prog = drgn_thread_program(thread);
	err = sync_events_and_check_attached(prog, sync_events);
	if (err)
		return err;

	int stopped;
	err = drgn_thread_stopped(thread, false, &stopped);
	if (err)
		return err;
	if (!stopped) {
		return drgn_error_create(DRGN_ERROR_NOT_STOPPED,
					 "thread is not stopped");
	}

	resuming_threads_guard(prog);

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (prog->in_all_stop && !only) {
		if (!ctrl->ops.resume_all_threads) {
			return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
						 "resuming all threads is not supported");
		}
	} else {
		if (!ctrl->ops.resume_only_threads) {
			return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
						 "resuming specific threads is not supported");
		}
	}

	set_resume_signal(thread, sig);

	move_thread(thread, &prog->resumed_threads);

	if (prog->in_all_stop && !only) {
		if (!list_empty(&prog->stopped_threads))
			return NULL;
		return resume_all_threads(prog, ctrl);
	}

	err = ctrl->ops.resume_only_threads(ctrl->arg, prog, &thread,
					    &thread->resume_signal, 1);
	if (err)
		return err;
	add_running_threads(prog, &thread, 1);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_resume_all_threads(struct drgn_program *prog,
				struct drgn_thread * const *threads,
				const int *sigs, size_t num_threads,
				bool sync_events)
{
	struct drgn_error *err;

	err = sync_events_and_check_attached(prog, sync_events);
	if (err)
		return err;

	for (size_t i = 0; i < num_threads; i++) {
		struct drgn_thread *thread = threads[i];

		if (sigs && sigs[i] < 0
		    && sigs[i] != DRGN_RESUME_DEFAULT_SIGNAL) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "resume signal must be non-negative");
		}

		if (drgn_thread_program(thread) != prog) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "thread from wrong program");
		}
		int stopped;
		err = drgn_thread_stopped(thread, false, &stopped);
		if (err)
			return err;
		if (!stopped) {
			return drgn_error_create(DRGN_ERROR_NOT_STOPPED,
						 "thread is not stopped");
		}
	}

	resuming_threads_guard(prog);

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (prog->in_all_stop) {
		if (!ctrl->ops.resume_all_threads) {
			return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
						 "resuming all threads is not supported");
		}
	} else {
		if (!ctrl->ops.resume_only_threads) {
			return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
						 "resuming specific threads is not supported");
		}
	}

	for (size_t i = 0; i < num_threads; i++) {
		struct drgn_thread *thread = threads[i];
		set_resume_signal(thread,
				  sigs ? sigs[i] : DRGN_RESUME_DEFAULT_SIGNAL);
		move_thread(thread, &prog->resumed_threads);
	}

	struct drgn_thread *thread;
	list_for_each_entry(thread, &prog->stopped_threads, node)
		set_resume_signal(thread, DRGN_RESUME_DEFAULT_SIGNAL);
	list_splice_tail_init(&prog->stopped_threads, &prog->resumed_threads);

	if (list_empty(&prog->resumed_threads) && !prog->in_all_stop)
		return NULL;

	return resume_all_threads(prog, ctrl);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_resume_only_threads(struct drgn_program *prog,
				 struct drgn_thread * const *threads,
				 const int *sigs, size_t num_threads,
				 bool sync_events)
{
	struct drgn_error *err;
	if (!num_threads)
		return NULL;

	err = sync_events_and_check_attached(prog, sync_events);
	if (err)
		return err;

	for (size_t i = 0; i < num_threads; i++) {
		struct drgn_thread *thread = threads[i];

		if (sigs && sigs[i] < 0
		    && sigs[i] != DRGN_RESUME_DEFAULT_SIGNAL) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "resume signal must be non-negative");
		}

		if (drgn_thread_program(thread) != prog) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "thread from wrong program");
		}
		int stopped;
		err = drgn_thread_stopped(thread, false, &stopped);
		if (err)
			return err;
		if (!stopped) {
			return drgn_error_create(DRGN_ERROR_NOT_STOPPED,
						 "thread is not stopped");
		}

		thread->resume_index = SIZE_MAX;
	}

	resuming_threads_guard(prog);

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (!ctrl->ops.resume_only_threads) {
		return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
					 "resuming specific threads is not supported");
	}

	VECTOR(drgn_thread_vector, unique_threads);
	VECTOR(signal_vector, unique_sigs);
	if (!drgn_thread_vector_reserve(&unique_threads, num_threads)
	    || !signal_vector_reserve(&unique_sigs, num_threads))
		return &drgn_enomem;
	for (size_t i = 0; i < num_threads; i++) {
		struct drgn_thread *thread = threads[i];
		set_resume_signal(thread,
				  sigs ? sigs[i] : DRGN_RESUME_DEFAULT_SIGNAL);
		if (thread->resume_index == SIZE_MAX) {
			thread->resume_index =
				drgn_thread_vector_size(&unique_threads);
			// Reserved above, so these can't fail.
			drgn_thread_vector_append(&unique_threads, &thread);
			signal_vector_append(&unique_sigs,
					     &thread->resume_signal);
			move_thread(thread, &prog->resumed_threads);
		} else {
			// Duplicate thread. Overwrite its corresponding signal.
			*signal_vector_at(&unique_sigs, thread->resume_index) =
				thread->resume_signal;
		}
	}

	err = ctrl->ops.resume_only_threads(ctrl->arg, prog,
					    drgn_thread_vector_begin(&unique_threads),
					    signal_vector_begin(&unique_sigs),
					    drgn_thread_vector_size(&unique_threads));
	if (err)
		return err;
	add_running_threads(prog, drgn_thread_vector_begin(&unique_threads),
			    drgn_thread_vector_size(&unique_threads));
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_get_event(struct drgn_program *prog, bool block,
		       struct drgn_event **ret)
{
	// Do this before check_attached() so that we can return queued events
	// from an exited program.
	if (!drgn_event_deque_empty(&prog->event_queue)) {
		*ret = *drgn_event_deque_pop_first(&prog->event_queue);
		return NULL;
	}

	struct drgn_error *err = check_attached(prog);
	if (err)
		return err;

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	err = ctrl->ops.queue_events(ctrl->arg, prog, block);
	if (err)
		return err;

	if (drgn_event_deque_empty(&prog->event_queue))
		return &no_events_error;
	*ret = *drgn_event_deque_pop_first(&prog->event_queue);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_sync_events(struct drgn_program *prog, bool block)
{
	struct drgn_error *err = check_attached(prog);
	if (err)
		return err;
	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (block) {
		err = ctrl->ops.queue_events(ctrl->arg, prog, true);
		if (err)
			return err;
	}
	size_t prev_size;
	do {
		prev_size = drgn_event_deque_size(&prog->event_queue);
		err = ctrl->ops.queue_events(ctrl->arg, prog, false);
		if (err)
			return err;
	} while (drgn_event_deque_size(&prog->event_queue) > prev_size);
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_program_queue_event(struct drgn_program *prog,
					    struct drgn_event *event)
{
	struct drgn_error *err = check_attached(prog);
	if (err)
		return err;
	if (!drgn_event_deque_reserve_for_append(&prog->event_queue))
		return &drgn_enomem;

	SWITCH_ENUM(event->type) {
	case DRGN_EVENT_THREAD_SIGNAL:
	case DRGN_EVENT_BREAKPOINT: {
		struct drgn_thread_signal_event *se =
			(struct drgn_thread_signal_event *)event;
		struct drgn_thread *thread = se->thread_event.thread;
		thread->last_signal = se->signal;
		thread->resume_signal = -1;
		if (list_empty(&thread->node)) {
			drgn_thread_incref(thread);
			list_add_tail(&thread->node, &prog->stopped_threads);
		} else {
			list_move_tail(&thread->node, &prog->stopped_threads);
		}
		if (prog->all_stop) {
			prog->in_all_stop = true;
			clear_running_threads(prog);
		}
		break;
	}
	case DRGN_EVENT_PROGRAM_EXIT:
		prog->attach_state = DRGN_ATTACH_STATE_EXITED;
		break;
	case DRGN_EVENT_THREAD_EXIT:
		break;
	default:
		UNREACHABLE();
	}

	// Reserved above.
	drgn_event_deque_append(&prog->event_queue, &event);
	drgn_event_incref(event);
	return NULL;
}

void drgn_breakpoint_deinit(struct drgn_breakpoint *bp)
{
	if (bp->destroy_data)
		bp->destroy_data(bp->data);
	for (size_t i = 0; i < bp->num_sites; i++)
		drgn_breakpoint_site_decref(bp->site_nodes[i].site);
	free(bp->site_nodes);
	drgn_program_decref(bp->prog);
}

LIBDRGN_PUBLIC struct drgn_program *
drgn_breakpoint_program(const struct drgn_breakpoint *bp)
{
	return bp->prog;
}

// enable_breakpoint_sites() and disable_breakpoint_sites() can run arbitrary
// code, so we have to be very careful when modifying breakpoints.
//
// Firstly, re-entrant calls into breakpoint modification functions from
// enable_breakpoint_sites() or disable_breakpoint_sites() would complicate
// things significantly. There's no good reason to allow re-entrant calls, so we
// block them.
//
// Secondly, all drgn_breakpoint and drgn_breakpoint_site objects must be valid
// when enable_breakpoint_sites() or disable_breakpoint_sites() is called. In
// particular, we call the callback before updating object state, but all of the
// data structures must be consistent.
//
// Thirdly, active drgn_breakpoint_iterators and drgn_breakpoint_site_iterators
// must be invalidated when the data structures they use are modified.

#define modifying_breakpoints_guard(prog, reason)				\
	if (prog->modifying_breakpoints) {					\
		return drgn_error_format(DRGN_ERROR_RUNTIME,			\
					 "%s breakpoint while %s another breakpoint is not allowed",\
					 (reason),				\
					 (prog)->modifying_breakpoints);	\
	}									\
	(prog)->modifying_breakpoints = (reason);				\
	__attribute__((__cleanup__(modifying_breakpoints_guard_cleanup),	\
		       __unused__))						\
	struct drgn_program *modifying_breakpoints_prog = (prog)

static inline void
modifying_breakpoints_guard_cleanup(struct drgn_program **progp)
{
	(*progp)->modifying_breakpoints = NULL;
}

static void rollback_set_breakpoint(struct drgn_breakpoint **bpp)
{
	if (*bpp) {
		drgn_breakpoint_remove_impl(*bpp);
		drgn_breakpoint_decref(*bpp);
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_breakpoint(struct drgn_program *prog,
			    const uint64_t *addresses, size_t n, bool hardware,
			    bool enable, bool sync_events,
			    struct drgn_breakpoint **ret)
{
	struct drgn_error *err;
	if (n == 0) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "breakpoint must have at least one address");
	}

	err = sync_events_and_check_attached(prog, sync_events);
	if (err)
		return err;
	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (!ctrl->ops.enable_breakpoint_sites) {
		return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
					 "breakpoints are not supported");
	}

	modifying_breakpoints_guard(prog, "setting");

	_cleanup_(rollback_set_breakpoint) struct drgn_breakpoint *bp =
		drgn_breakpoint_alloc();
	if (!bp)
		return &drgn_enomem;
	drgn_program_incref(prog);
	bp->prog = prog;
	INIT_LIST_HEAD(&bp->prog_node);

	bp->site_nodes = malloc_array(n, sizeof(bp->site_nodes[0]));
	if (!bp->site_nodes)
		return &drgn_enomem;

	_cleanup_free_ struct drgn_breakpoint_site **sites_to_enable = NULL;
	if (enable) {
		sites_to_enable = malloc_array(n, sizeof(sites_to_enable[0]));
		if (!sites_to_enable)
			return &drgn_enomem;
	}
	size_t num_sites_to_enable = 0;

	for (size_t i = 0; i < n; i++) {
		struct hash_pair hp =
			drgn_breakpoint_site_table_hash(&addresses[i]);
		auto it = drgn_breakpoint_site_table_search_hashed(&prog->breakpoint_sites,
								   &addresses[i],
								   hp);
		struct drgn_breakpoint_site *site;
		if (it.entry) {
			site = *it.entry;
			struct drgn_breakpoint_site_node *site_node =
				list_last_entry_or_null(&site->disabled_breakpoints,
							struct drgn_breakpoint_site_node,
							node);
			if (site_node && site_node->bp == bp) {
				// Must be a duplicate address. Skip it.
				continue;
			}
			drgn_breakpoint_site_incref(site);
		} else {
			site = drgn_breakpoint_site_alloc();
			if (!site)
				return &drgn_enomem;
			_cleanup_breakpoint_site_ struct drgn_breakpoint_site
				*site_to_cleanup = site;
			drgn_program_incref(prog);
			site->prog = prog;
			site->address = addresses[i];
			site->hardware = hardware;
			INIT_LIST_HEAD(&site->enabled_breakpoints);
			INIT_LIST_HEAD(&site->disabled_breakpoints);

			if (drgn_breakpoint_site_table_insert_searched(&prog->breakpoint_sites,
								       &site,
								       hp,
								       NULL) < 0)
				return &drgn_enomem;
			prog->breakpoint_sites_generation++;

			site_to_cleanup = NULL;
		}

		struct drgn_breakpoint_site_node *site_node =
			&bp->site_nodes[bp->num_sites++];
		site_node->site = site;
		site_node->bp = bp;
		list_add_tail(&site_node->node, &site->disabled_breakpoints);
		site->lists_generation++;
		if (enable && list_empty(&site->enabled_breakpoints))
			sites_to_enable[num_sites_to_enable++] = site;
	}

	// prog->breakpoints holds a reference.
	drgn_breakpoint_incref(bp);
	list_add_tail(&bp->prog_node, &prog->breakpoints);
	prog->breakpoints_generation++;

	if (enable) {
		if (num_sites_to_enable) {
			err = ctrl->ops.enable_breakpoint_sites(ctrl->arg,
								sites_to_enable,
								num_sites_to_enable);
			if (err)
				return err;
		}
		for (size_t i = 0; i < bp->num_sites; i++) {
			list_move_tail(&bp->site_nodes[i].node,
				       &bp->site_nodes[i].site->enabled_breakpoints);
			bp->site_nodes[i].site->lists_generation++;
		}
		bp->enabled = true;
	}

	*ret = no_cleanup_ptr(bp);
	return NULL;
}

static struct drgn_error *
drgn_breakpoint_disable_impl(struct drgn_breakpoint *bp)
{
	struct drgn_error *err;

	if (!bp->enabled)
		return NULL;

	_cleanup_free_ struct drgn_breakpoint_site **sites_to_disable =
		malloc_array(bp->num_sites, sizeof(sites_to_disable[0]));
	if (!sites_to_disable)
		return &drgn_enomem;
	size_t num_sites_to_disable = 0;

	for (size_t i = 0; i < bp->num_sites; i++) {
		struct drgn_breakpoint_site_node *site_node =
			&bp->site_nodes[i];
		struct drgn_breakpoint_site *site = site_node->site;
		if (list_is_singular(&site->enabled_breakpoints)
		    && site->enabled_breakpoints.next == &site_node->node)
			sites_to_disable[num_sites_to_disable++] = site;
	}

	if (num_sites_to_disable) {
		struct drgn_execution_controller *ctrl =
			get_enabled_controller(drgn_breakpoint_program(bp));
		err = ctrl->ops.disable_breakpoint_sites(ctrl->arg,
							 sites_to_disable,
							 num_sites_to_disable);
		if (err)
			return err;
	}

	for (size_t i = 0; i < bp->num_sites; i++) {
		list_move_tail(&bp->site_nodes[i].node,
			       &bp->site_nodes[i].site->disabled_breakpoints);
		bp->site_nodes[i].site->lists_generation++;
	}
	bp->enabled = false;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_breakpoint_remove(struct drgn_breakpoint *bp, bool sync_events)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_breakpoint_program(bp);

	for (;;) {
		if (list_empty(&bp->prog_node))
			return NULL;

		if (!sync_events)
			break;
		// Breakpoints can only be set while attached to the program, so
		// we don't need to check.
		err = drgn_program_sync_events(prog, false);
		if (err)
			return err;
		// queue_events could have removed this breakpoint. Check again.
		sync_events = false;
	}

	modifying_breakpoints_guard(prog, "removing");

	err = drgn_breakpoint_disable_impl(bp);
	if (err)
		return err;
	drgn_breakpoint_remove_impl(bp);
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_breakpoint_enable(struct drgn_breakpoint *bp,
					  bool sync_events)
{
	struct drgn_error *err;
	struct drgn_program *prog = bp->prog;

	for (;;) {
		if (bp->enabled)
			return NULL;
		if (list_empty(&bp->prog_node)) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "can't enable removed breakpoint");
		}

		if (!sync_events)
			break;
		// Breakpoints can only be set while attached to the program, so
		// we don't need to check.
		err = drgn_program_sync_events(prog, false);
		if (err)
			return err;
		// queue_events could have enabled or removed this breakpoint.
		// Check again.
		sync_events = false;
	}

	modifying_breakpoints_guard(prog, "enabling");

	_cleanup_free_ struct drgn_breakpoint_site **sites_to_enable =
		malloc_array(bp->num_sites, sizeof(sites_to_enable[0]));
	if (!sites_to_enable)
		return &drgn_enomem;
	size_t num_sites_to_enable = 0;

	for (size_t i = 0; i < bp->num_sites; i++) {
		struct drgn_breakpoint_site_node *site_node =
			&bp->site_nodes[i];
		struct drgn_breakpoint_site *site = site_node->site;
		if (list_empty(&site->enabled_breakpoints))
			sites_to_enable[num_sites_to_enable++] = site;
	}

	if (num_sites_to_enable) {
		struct drgn_execution_controller *ctrl =
			get_enabled_controller(prog);
		err = ctrl->ops.enable_breakpoint_sites(ctrl->arg,
							sites_to_enable,
							num_sites_to_enable);
		if (err)
			return err;
	}

	for (size_t i = 0; i < bp->num_sites; i++) {
		list_move_tail(&bp->site_nodes[i].node,
			       &bp->site_nodes[i].site->enabled_breakpoints);
		bp->site_nodes[i].site->lists_generation++;
	}
	bp->enabled = true;
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_breakpoint_disable(struct drgn_breakpoint *bp,
					   bool sync_events)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_breakpoint_program(bp);

	for (;;) {
		if (!bp->enabled)
			return NULL;

		if (!sync_events)
			break;
		// Breakpoints can only be enabled while attached to the
		// program, so we don't need to check.
		err = drgn_program_sync_events(prog, false);
		if (err)
			return err;
		// queue_events could have disabled this breakpoint. Check
		// again.
		sync_events = false;
	}

	modifying_breakpoints_guard(prog, "disabling");

	return drgn_breakpoint_disable_impl(bp);
}

LIBDRGN_PUBLIC bool drgn_breakpoint_enabled(const struct drgn_breakpoint *bp)
{
	return bp->enabled;
}

LIBDRGN_PUBLIC bool drgn_breakpoint_removed(const struct drgn_breakpoint *bp)
{
	return list_empty(&bp->prog_node);
}

static struct drgn_error *
drgn_program_disable_all_breakpoints_impl(struct drgn_program *prog)
{
	struct drgn_error *err;

	_cleanup_free_ struct drgn_breakpoint_site **sites_to_disable =
		malloc_array(drgn_breakpoint_site_table_size(&prog->breakpoint_sites),
			     sizeof(sites_to_disable[0]));
	if (!sites_to_disable)
		return &drgn_enomem;
	size_t num_sites_to_disable = 0;

	hash_table_for_each(drgn_breakpoint_site_table, it,
			    &prog->breakpoint_sites) {
		struct drgn_breakpoint_site *site = *it.entry;
		if (!list_empty(&site->enabled_breakpoints))
			sites_to_disable[num_sites_to_disable++] = site;
	}

	if (num_sites_to_disable) {
		struct drgn_execution_controller *ctrl =
			get_enabled_controller(prog);
		err = ctrl->ops.disable_breakpoint_sites(ctrl->arg,
							 sites_to_disable,
							 num_sites_to_disable);
		if (err)
			return err;

		// sites_to_disable already contains every site with any enabled
		// breakpoints, so we don't have to iterate the entire sites
		// table.
		for (size_t i = 0; i < num_sites_to_disable; i++) {
			struct drgn_breakpoint_site *site = sites_to_disable[i];
			struct drgn_breakpoint_site_node *site_node;
			list_for_each_entry(site_node,
					    &site->enabled_breakpoints, node)
				site_node->bp->enabled = false;

			list_splice_tail_init(&site->enabled_breakpoints,
					      &site->disabled_breakpoints);
			site->lists_generation++;
		}
	}

	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_remove_all_breakpoints(struct drgn_program *prog, bool sync_events)
{
	struct drgn_error *err;

	for (;;) {
		if (list_empty(&prog->breakpoints))
			return NULL;

		if (!sync_events)
			break;
		// Breakpoints can only be set while attached to the program, so
		// we don't need to check.
		err = drgn_program_sync_events(prog, false);
		if (err)
			return err;
		// queue_events could have removed all breakpoints. Check again.
		sync_events = false;
	}

	modifying_breakpoints_guard(prog, "removing");

	err = drgn_program_disable_all_breakpoints_impl(prog);
	if (err)
		return err;

	struct drgn_breakpoint *bp, *tmp;
	list_for_each_entry_safe(bp, tmp, &prog->breakpoints, prog_node)
		drgn_breakpoint_remove_impl(bp);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_enable_all_breakpoints(struct drgn_program *prog,
				    bool sync_events)
{
	struct drgn_error *err;

	for (;;) {
		if (list_empty(&prog->breakpoints))
			return NULL;

		if (!sync_events)
			break;
		// Breakpoints can only be set while attached to the program, so
		// we don't need to check.
		err = drgn_program_sync_events(prog, false);
		if (err)
			return err;
		// queue_events could have removed all breakpoints. Check again.
		sync_events = false;
	}

	modifying_breakpoints_guard(prog, "enabling");

	_cleanup_free_ struct drgn_breakpoint_site **sites_to_enable =
		malloc_array(drgn_breakpoint_site_table_size(&prog->breakpoint_sites),
			     sizeof(sites_to_enable[0]));
	if (!sites_to_enable)
		return &drgn_enomem;
	size_t num_sites_to_enable = 0;

	hash_table_for_each(drgn_breakpoint_site_table, it,
			    &prog->breakpoint_sites) {
		struct drgn_breakpoint_site *site = *it.entry;
		if (list_empty(&site->enabled_breakpoints))
			sites_to_enable[num_sites_to_enable++] = site;
	}

	if (num_sites_to_enable) {
		struct drgn_execution_controller *ctrl =
			get_enabled_controller(prog);
		err = ctrl->ops.enable_breakpoint_sites(ctrl->arg,
							sites_to_enable,
							num_sites_to_enable);
		if (err)
			return err;
	}

	// sites_to_enable doesn't contain sites with a mix of enabled and
	// disabled breakpoints, so we have to iterate the entire sites table.
	hash_table_for_each(drgn_breakpoint_site_table, it,
			    &prog->breakpoint_sites) {
		struct drgn_breakpoint_site *site = *it.entry;
		struct drgn_breakpoint_site_node *site_node;
		list_for_each_entry(site_node, &site->disabled_breakpoints,
				    node)
			site_node->bp->enabled = true;

		list_splice_tail_init(&site->disabled_breakpoints,
				      &site->enabled_breakpoints);
		site->lists_generation++;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_disable_all_breakpoints(struct drgn_program *prog, bool sync_events)
{
	struct drgn_error *err;

	for (;;) {
		if (list_empty(&prog->breakpoints))
			return NULL;

		if (!sync_events)
			break;
		// Breakpoints can only be set while attached to the program, so
		// we don't need to check.
		err = drgn_program_sync_events(prog, false);
		if (err)
			return err;
		// queue_events could have removed all breakpoints. Check again.
		sync_events = false;
	}

	modifying_breakpoints_guard(prog, "disabling");

	return drgn_program_disable_all_breakpoints_impl(prog);
}

LIBDRGN_PUBLIC size_t
drgn_breakpoint_num_sites(const struct drgn_breakpoint *bp)
{
	return bp->num_sites;
}

LIBDRGN_PUBLIC struct drgn_breakpoint_site *
drgn_breakpoint_get_site(const struct drgn_breakpoint *bp, size_t i)
{
	return bp->site_nodes[i].site;
}

LIBDRGN_PUBLIC void *
drgn_breakpoint_get_data(const struct drgn_breakpoint *bp)
{
	return bp->data;
}

LIBDRGN_PUBLIC void
drgn_breakpoint_set_data(struct drgn_breakpoint *bp, void *data,
			 void (*destroy_data)(void *))
{
	if (bp->destroy_data)
		bp->destroy_data(bp->data);
	bp->data = data;
	bp->destroy_data = destroy_data;
}

LIBDRGN_PUBLIC struct drgn_breakpoint_site *
drgn_program_find_breakpoint_site(struct drgn_program *prog, uint64_t address)
{
	auto it = drgn_breakpoint_site_table_search(&prog->breakpoint_sites,
						    &address);
	if (!it.entry)
		return NULL;
	struct drgn_breakpoint_site *site = *it.entry;
	drgn_breakpoint_site_incref(site);
	return site;
}

void drgn_breakpoint_site_deinit(struct drgn_breakpoint_site *site)
{
	if (site->destroy_controller_data)
		site->destroy_controller_data(site->controller_data);
	drgn_program_decref(site->prog);
}

LIBDRGN_PUBLIC struct drgn_program *
drgn_breakpoint_site_program(const struct drgn_breakpoint_site *site)
{
	return site->prog;
}

LIBDRGN_PUBLIC
uint64_t drgn_breakpoint_site_address(const struct drgn_breakpoint_site *site)
{
	return site->address;
}

LIBDRGN_PUBLIC
bool drgn_breakpoint_site_hardware(const struct drgn_breakpoint_site *site)
{
	return site->hardware;
}

LIBDRGN_PUBLIC
bool drgn_breakpoint_site_enabled(const struct drgn_breakpoint_site *site)
{
	return !list_empty(&site->enabled_breakpoints);
}

LIBDRGN_PUBLIC
bool drgn_breakpoint_site_removed(const struct drgn_breakpoint_site *site)
{
	return list_empty(&site->enabled_breakpoints)
	       && list_empty(&site->disabled_breakpoints);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_breakpoint_site_enabled_breakpoints(struct drgn_breakpoint_site *site,
					 struct drgn_breakpoint_iterator **ret)
{

	struct drgn_breakpoint_iterator *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;
	it->prog = drgn_breakpoint_site_program(site);
	drgn_breakpoint_site_incref(site);
	it->site = site;
	it->generation = site->lists_generation;
	it->head = &site->enabled_breakpoints;
	it->next = site->enabled_breakpoints.next;
	*ret = it;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_breakpoint_site_disabled_breakpoints(struct drgn_breakpoint_site *site,
					  struct drgn_breakpoint_iterator **ret)
{
	struct drgn_breakpoint_iterator *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;
	it->prog = drgn_breakpoint_site_program(site);
	drgn_breakpoint_site_incref(site);
	it->site = site;
	it->generation = site->lists_generation;
	it->head = &site->disabled_breakpoints;
	it->next = site->disabled_breakpoints.next;
	*ret = it;
	return NULL;
}

LIBDRGN_PUBLIC void *
drgn_breakpoint_site_get_controller_data(const struct drgn_breakpoint_site *site)
{
	return site->controller_data;
}

LIBDRGN_PUBLIC void
drgn_breakpoint_site_set_controller_data(struct drgn_breakpoint_site *site,
					 void *data,
					 void (*destroy_data)(void *))
{
	if (site->destroy_controller_data)
		site->destroy_controller_data(site->controller_data);
	site->controller_data = data;
	site->destroy_controller_data = destroy_data;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_breakpoints(struct drgn_program *prog,
			 struct drgn_breakpoint_iterator **ret)
{
	struct drgn_breakpoint_iterator *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;
	it->prog = prog;
	it->site = NULL;
	it->generation = prog->breakpoints_generation;
	it->head = &prog->breakpoints;
	it->next = prog->breakpoints.next;
	*ret = it;
	return NULL;
}

LIBDRGN_PUBLIC void
drgn_breakpoint_iterator_destroy(struct drgn_breakpoint_iterator *it)
{
	drgn_breakpoint_site_decref(it->site);
	free(it);
}

LIBDRGN_PUBLIC struct drgn_program *
drgn_breakpoint_iterator_program(struct drgn_breakpoint_iterator *it)
{
	return it->prog;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_breakpoint_iterator_next(struct drgn_breakpoint_iterator *it,
			      struct drgn_breakpoint **ret)
{
	uint64_t current_generation =
		it->site ? it->site->lists_generation
			 : it->prog->breakpoints_generation;
	if (it->generation != current_generation) {
		return drgn_error_create(DRGN_ERROR_RUNTIME,
					 "breakpoints changed during iteration");
	}

	if (it->next == it->head) {
		*ret = NULL;
		return NULL;
	}
	if (it->site) {
		*ret = list_entry(it->next, struct drgn_breakpoint_site_node,
				  node)->bp;
	} else {
		*ret = list_entry(it->next, struct drgn_breakpoint, prog_node);
	}
	drgn_breakpoint_incref(*ret);
	it->next = it->next->next;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_breakpoint_sites(struct drgn_program *prog,
			      struct drgn_breakpoint_site_iterator **ret)
{
	struct drgn_breakpoint_site_iterator *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;
	it->prog = prog;
	it->generation = prog->breakpoint_sites_generation;
	it->it = drgn_breakpoint_site_table_first(&prog->breakpoint_sites);
	*ret = it;
	return NULL;
}

LIBDRGN_PUBLIC void
drgn_breakpoint_site_iterator_destroy(struct drgn_breakpoint_site_iterator *it)
{
	free(it);
}

LIBDRGN_PUBLIC struct drgn_program *
drgn_breakpoint_site_iterator_program(struct drgn_breakpoint_site_iterator *it)
{
	return it->prog;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_breakpoint_site_iterator_next(struct drgn_breakpoint_site_iterator *it,
				   struct drgn_breakpoint_site **ret)
{
	if (it->generation != it->prog->breakpoint_sites_generation) {
		return drgn_error_create(DRGN_ERROR_RUNTIME,
					 "breakpoint sites changed during iteration");
	}
	if (!it->it.entry) {
		*ret = NULL;
		return NULL;
	}
	struct drgn_breakpoint_site *site = *it->it.entry;
	drgn_breakpoint_site_incref(site);
	*ret = site;
	it->it = drgn_breakpoint_site_table_next(it->it);
	return NULL;
}
