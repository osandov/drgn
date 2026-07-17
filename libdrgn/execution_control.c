// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include "array.h"
#include "breakpoint.h"
#include "cleanup.h"
#include "error.h"
#include "event.h"
#include "execution_control.h"
#include "hash_table.h"
#include "list.h"
#include "log.h"
#include "program.h"
#include "thread.h"
#include "util.h"

// TODO: remove these
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"

struct drgn_event_listener {
	struct drgn_program *prog;
	struct list_head node;
	drgn_event_listener_fn *callback;
	void *arg;
	struct drgn_event_listener *next_to_free;
};

static inline uint64_t
drgn_breakpoint_site_to_key(struct drgn_breakpoint_site * const *entry)
{
	return (*entry)->address;
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_breakpoint_site_table,
			    drgn_breakpoint_site_to_key, int_key_hash_pair,
			    scalar_key_eq);

struct fd_handler {
	int fd;
	enum drgn_fd_events events;
	drgn_fd_handler_fn *callback;
	void *arg;
	struct fd_handler *next_to_free;
};

static inline int fd_handler_key(struct fd_handler * const *entry)
{
	return (*entry)->fd;
}

DEFINE_HASH_TABLE_FUNCTIONS(fd_handler_table, fd_handler_key, int_key_hash_pair,
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
	if (!controller->ops.resume_threads) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "drgn_execution_controller_ops::resume_threads is required");
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
	SWITCH_ENUM(prog->attach_state) {
	case DRGN_ATTACH_STATE_DETACHED:
	case DRGN_ATTACH_STATE_ATTACHING:
	// TODO: maybe we should allow DETACHING?
	case DRGN_ATTACH_STATE_DETACHING:
		return drgn_error_create(DRGN_ERROR_NOT_ATTACHED,
					 "not attached to program");
	case DRGN_ATTACH_STATE_ATTACHED:
		return NULL;
	case DRGN_ATTACH_STATE_EXITED:
		return drgn_error_create(DRGN_ERROR_PROGRAM_EXITED,
					 "program exited");
	default:
		UNREACHABLE();
	}
}

void drgn_program_init_execution_control(struct drgn_program *prog)
{
	drgn_breakpoint_site_table_init(&prog->breakpoint_sites);
	INIT_LIST_HEAD(&prog->breakpoints);
	INIT_LIST_HEAD(&prog->stopped_threads);
	INIT_LIST_HEAD(&prog->resumed_threads);
	INIT_LIST_HEAD(&prog->running_threads);
	INIT_LIST_HEAD(&prog->event_listeners);
	fd_handler_table_init(&prog->fd_handlers);
	prog->epoll_fd = -1;
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
		thread->last_signal = -1;
		list_del_init(&thread->node);
		drgn_thread_decref(thread);
	}
	list_for_each_entry_safe(thread, tmp, &prog->resumed_threads, node) {
		thread->last_signal = -1;
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
	clear_controlled_threads(prog);
	clear_breakpoints(prog);
}

int drgn_program_traverse_execution_control(struct drgn_program *prog,
	    int (*visit_thread)(struct drgn_thread *, void *),
	    int (*visit_breakpoint)(struct drgn_breakpoint *, void *),
	    int (*visit_breakpoint_site)(struct drgn_breakpoint_site *, void *),
	    void *arg)
{
	int ret;
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
	if (prog->epoll_fd >= 0)
		close(prog->epoll_fd);
	hash_table_for_each(fd_handler_table, it, &prog->fd_handlers) {
		struct fd_handler *handler = *it.entry;
		handler->callback(prog, handler->fd, 0, handler->arg);
		free(handler);
	}
	fd_handler_table_deinit(&prog->fd_handlers);

	struct drgn_event_listener *listener, *tmp;
	list_for_each_entry_safe(listener, tmp, &prog->event_listeners, node)
		drgn_event_listener_remove(listener);

	drgn_program_clear_execution_control(prog);
	drgn_breakpoint_site_table_deinit(&prog->breakpoint_sites);
}

static struct fd_handler sentinel_fd_handler;

struct drgn_error *drgn_program_ensure_epoll_fd(struct drgn_program *prog)
{
	if (prog->epoll_fd < 0) {
		prog->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
		if (prog->epoll_fd < 0)
			return drgn_error_create_os("epoll_create1", errno, NULL);
	}
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_program_poll(struct drgn_program *prog, int timeout_ms,
				     bool *ret)
{
	struct drgn_error *err;

	// Ensure that epoll_wait() works even if no fds have been registered.
	err = drgn_program_ensure_epoll_fd(prog);
	if (err)
		return err;

	struct timespec start, now;
	if (timeout_ms > 0 && clock_gettime(CLOCK_MONOTONIC, &start) < 0)
		return drgn_error_create_os("clock_gettime", errno, NULL);

	struct epoll_event events[64];
	int num_events;
	int remaining_ms = timeout_ms;
	for (;;) {
		drgn_blocking_state blocking_state = drgn_begin_blocking();
		num_events = epoll_wait(prog->epoll_fd, events,
					array_size(events), remaining_ms);
		int saved_errno = errno;
		err = drgn_end_blocking_and_check_signals(blocking_state);
		if (err)
			return err;
		if (num_events > 0)
			break;
		if (num_events == 0) {
			if (ret)
				*ret = false;
			return NULL;
		}
		if (saved_errno != EINTR) {
			return drgn_error_create_os("epoll_wait", saved_errno,
						    NULL);
		}
		if (timeout_ms > 0) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
				return drgn_error_create_os("clock_gettime",
							    errno, NULL);
			}
			long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000
					  + (now.tv_nsec - start.tv_nsec) / 1000000;
			if (elapsed_ms > timeout_ms) {
				if (ret)
					*ret = false;
				return NULL;
			}
			remaining_ms = timeout_ms - elapsed_ms;
		}
	}

	// NB: we guarantee that an abort callback won't be called after its
	// corresponding success or error callback is called, so we can't return
	// an error after calling any handlers.

	bool free_handlers = !prog->fd_handlers_to_free;
	if (free_handlers)
		prog->fd_handlers_to_free = &sentinel_fd_handler;

	for (int i = 0; i < num_events; i++) {
		struct fd_handler *handler = events[i].data.ptr;
		if (!handler->callback) {
			// fd was unregistered from another callback.
			continue;
		}

		enum drgn_fd_events fd_events = 0;
		// Invert masks to catch error conditions, too.
		if (events[i].events & ~EPOLLOUT)
			fd_events |= DRGN_FD_EVENT_READ;
		if (events[i].events & ~EPOLLIN)
			fd_events |= DRGN_FD_EVENT_WRITE;
		handler->callback(prog, handler->fd, fd_events, handler->arg);
	}

	if (free_handlers) {
		struct fd_handler *handler = prog->fd_handlers_to_free;
		while (handler != &sentinel_fd_handler) {
			struct fd_handler *next = handler->next_to_free;
			free(handler);
			handler = next;
		}
		prog->fd_handlers_to_free = NULL;
	}
	if (ret)
		*ret = true;
	return NULL;
}

struct result_arg {
	struct drgn_program *prog;
	struct drgn_error *err;
};

static struct drgn_error result_pending =
	DRGN_ERROR_INIT(DRGN_ERROR_RUNTIME, "result pending");

static struct drgn_error result_aborted =
	DRGN_ERROR_INIT(DRGN_ERROR_RUNTIME, "result aborted");

static void result_arg_init(struct result_arg *result, struct drgn_program *prog)
{
	result->prog = prog;
	result->err = &result_pending;
}

static struct result_arg *result_arg_alloc(struct drgn_program *prog)
{
	struct result_arg *result = malloc(sizeof(*result));
	if (result)
		result_arg_init(result, prog);
	return result;
}

// Returns false if result was previously aborted and is now freed, false
// otherwise.
static bool set_result(struct result_arg *result, struct drgn_error *err)
{
	// pending -NULL------------> completed
	//         -!NULL-----------> errored
	//         -&result_aborted-> aborted -any-> freed
	// TODO: document state transitions better
	if (result->err != &result_pending) {
		// Result must only be set once.
		assert(result->err == &result_aborted);
		// Result can only be aborted while it is pending.
		assert(err != &result_aborted);
		drgn_error_destroy(err);
		free(result);
		return false;
	}
	result->err = err;
	return true;
}

static void noop_success(void *arg)
{
	set_result(arg, NULL);
}

static void noop_error(void *arg, struct drgn_error *err)
{
	set_result(arg, err);
}

static struct drgn_error *wait_for_result(struct result_arg *result,
					  drgn_error_fn *on_abort)
{
	struct drgn_error *err;
	struct drgn_program *prog = result->prog;
	while (result->err == &result_pending) {
		err = drgn_program_poll(prog, -1, NULL);
		if (err) {
			on_abort(result, &result_aborted);
			return err;
		}
	}
	err = result->err;
	free(result);
	return err;
}

static void attach_success(void *arg, bool all_stop)
{
	struct result_arg *result = arg;
	if (!set_result(result, NULL))
		return;

	struct drgn_program *prog = result->prog;
	prog->attach_state = DRGN_ATTACH_STATE_ATTACHED;
	prog->all_stop = all_stop;
}

static void attach_error(void *arg, struct drgn_error *err)
{
	struct result_arg *result = arg;
	result->prog->attach_state = DRGN_ATTACH_STATE_DETACHED;
	set_result(result, err);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_attach(struct drgn_program *prog, enum drgn_attach_flags flags)
{
	if (flags & ~(DRGN_ATTACH_NON_STOP | DRGN_ATTACH_ALL_STOP
		      | DRGN_ATTACH_INTERRUPT)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "unknown attach flag");
	}
	if ((flags & DRGN_ATTACH_NON_STOP) && (flags & DRGN_ATTACH_ALL_STOP)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "NON_STOP and ALL_STOP are mutually exclusive");
	}

	if (prog->attach_state != DRGN_ATTACH_STATE_DETACHED) {
		return drgn_error_create(DRGN_ERROR_ALREADY_ATTACHED,
					 "already attached to program");
	}

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (!ctrl) {
		return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
					 "no execution controller is enabled");
	}

	struct result_arg *result = result_arg_alloc(prog);
	if (!result)
		return &drgn_enomem;

	prog->attach_state = DRGN_ATTACH_STATE_ATTACHING;

	ctrl->ops.attach(ctrl->arg, prog, flags, attach_success, attach_error,
			 result);
	return wait_for_result(result, attach_error);
}

struct detach_result {
	struct result_arg result;
	enum drgn_attach_state orig_attach_state;
};

static void detach_success(void *arg)
{
	struct detach_result *result = arg;
	if (!set_result(&result->result, NULL))
		return;

	struct drgn_program *prog = result->result.prog;
	drgn_program_clear_execution_control(prog);
	prog->attach_state = DRGN_ATTACH_STATE_DETACHED;
	prog->in_all_stop = false;
}

static void detach_error(void *arg, struct drgn_error *err)
{
	struct detach_result *result = arg;
	result->result.prog->attach_state = result->orig_attach_state;
	set_result(&result->result, err);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_detach(struct drgn_program *prog)
{
	// TODO: what about ATTACHING or DETACHING?
	if (prog->attach_state == DRGN_ATTACH_STATE_DETACHED)
		return NULL;

#if 0
	// TODO: still need some of these protections?
	if (prog->resuming_threads) {
		return drgn_error_create(DRGN_ERROR_RUNTIME,
					 "detaching while resuming threads is not allowed");
	}
	if (prog->modifying_breakpoints) {
		return drgn_error_format(DRGN_ERROR_RUNTIME,
					 "detaching while %s a breakpoint is not allowed",
					 prog->modifying_breakpoints);
	}
#endif

	struct detach_result *result = malloc(sizeof(*result));
	if (!result)
		return &drgn_enomem;
	result_arg_init(&result->result, prog);
	result->orig_attach_state = prog->attach_state;

	prog->attach_state = DRGN_ATTACH_STATE_DETACHING;

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	ctrl->ops.detach(ctrl->arg, prog, detach_success, detach_error, result);
	return wait_for_result(&result->result, detach_error);
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

#if 0
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
#endif

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

	struct result_arg *result = result_arg_alloc(prog);
	if (!result)
		return &drgn_enomem;
	ctrl->ops.interrupt_any_thread(ctrl->arg, prog, noop_success,
				       noop_error, result);
	return wait_for_result(result, noop_error);
}

LIBDRGN_PUBLIC
enum drgn_stop_reason drgn_thread_stop_reason(struct drgn_thread *thread)
{
	if (thread->stop_reason == DRGN_STOP_REASON_NONE) {
		if (drgn_thread_program(thread)->in_all_stop)
			return DRGN_STOP_REASON_SYNTHETIC;
	} else if (thread->resume_signal >= 0) {
		return DRGN_STOP_REASON_SYNTHETIC;
	}
	return thread->stop_reason;
}

LIBDRGN_PUBLIC int drgn_thread_stop_signal(struct drgn_thread *thread)
{
	if (drgn_thread_stop_reason(thread) == DRGN_STOP_REASON_SYNTHETIC)
		return 0;
	return thread->stop_signal;
}

LIBDRGN_PUBLIC struct drgn_breakpoint_site *
drgn_thread_stop_breakpoint_site(struct drgn_thread *thread)
{
	return thread->stop_site;
}

#if 0
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
#endif

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

// TODO: name
static inline void unleash_thread(struct drgn_thread *thread)
{
	if (!list_empty(&thread->node)) {
		list_del_init(&thread->node);
		drgn_thread_decref(thread);
	}
}

static void set_resume_signal(struct drgn_thread *thread, int sig)
{
	if (sig == DRGN_RESUME_DEFAULT_SIGNAL) {
		if (thread->resume_signal >= 0)
			return;
		sig = drgn_thread_stop_signal(thread);
		if (sig == SIGINT || sig == SIGTRAP)
			sig = 0;
	}
	thread->resume_signal = sig;
}

#if 0
static void clear_resumed_threads(struct drgn_program *prog,
				  struct drgn_thread * const *threads, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		struct drgn_thread *thread = threads[i];
		if (thread->resume_signal < 0) {
			// The thread stopped again while resuming.
			continue;
		}
		thread->last_signal = -1;
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
		thread->last_signal = -1;
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
#endif

static struct drgn_event_listener sentinel_event_listener;

static struct drgn_event_listener *
start_for_each_event_listener(struct drgn_event_listener *listener)
{
	if (!listener || listener->prog->event_listeners_to_free)
		return NULL;
	listener->prog->event_listeners_to_free = &sentinel_event_listener;
	return listener;
}

static void end_for_each_event_listener(struct drgn_event_listener **listenerp)
{
	if (!*listenerp)
		return;
	struct drgn_program *prog = (*listenerp)->prog;
	struct drgn_event_listener *listener = prog->event_listeners_to_free;
	while (listener != &sentinel_event_listener) {
		struct drgn_event_listener *next = listener->next_to_free;
		list_del(&listener->node);
		free(listener);
		listener = next;
	}
	prog->event_listeners_to_free = NULL;
}

static inline struct drgn_event_listener *
next_event_listener(struct drgn_event_listener *listener,
		    struct drgn_event_listener *last_listener)
{
	while (listener != last_listener) {
		listener = list_next_entry(listener, node);
		if (listener->callback)
			return listener;
		// Listener was removed.
	}
	return NULL;
}

#define for_each_event_listener(listener, prog)					\
	for (struct drgn_event_listener *listener =				\
	     list_first_entry_or_null(&(prog)->event_listeners,			\
				      struct drgn_event_listener, node),	\
	     *last_##listener =							\
	     list_last_entry_or_null(&(prog)->event_listeners,			\
				     struct drgn_event_listener, node),		\
	     *cleanup_##listener _cleanup_(end_for_each_event_listener) =	\
	     start_for_each_event_listener(listener);				\
	     listener;								\
	     listener = next_event_listener(listener, last_##listener))

static void emit_event(struct drgn_program *prog, struct drgn_event *event)
{
	// TODO: probably don't need this macro craziness.
	for_each_event_listener(listener, prog)
		listener->callback(prog, event, listener->arg);
}

static void emit_thread_stop_event(struct drgn_thread *thread)
{
	struct drgn_program *prog = drgn_thread_program(thread);
	struct drgn_event event = {
		.type = DRGN_EVENT_THREAD_STOP,
		.thread = thread,
	};
	emit_event(prog, &event);
}

struct resume_threads_result {
	struct result_arg result;
	struct drgn_resume_action *actions;
	size_t num_actions;
};

static void resume_threads_success(void *arg)
{
	struct resume_threads_result *result = arg;
	struct drgn_program *prog = result->result.prog;
	_cleanup_free_ struct drgn_resume_action *actions = result->actions;
	size_t num_actions = result->num_actions;
	if (!set_result(&result->result, NULL))
		return;

	assert(!actions[num_actions - 1].thread
	       && actions[num_actions - 1].mode == DRGN_RESUME_MODE_CONTINUE
	       && actions[num_actions - 1].sig == 0);

	num_actions--;

	for (size_t i = 0; i < num_actions; i++) {
		struct drgn_thread *thread = actions[i].thread;

		thread->stop_reason = DRGN_STOP_REASON_NONE;
		thread->stop_signal = -1;
		thread->resume_signal = -1;
		drgn_clear_ref(thread->stop_site);
		unleash_thread(thread);
	}

	/* clear_running_threads(prog); */
	prog->in_all_stop = false;
}

static void resume_threads_error(void *arg, struct drgn_error *err)
{
	struct resume_threads_result *result = arg;
	free(result->actions);
	set_result(&result->result, err);
}

// TODO: pass inline_size?
DEFINE_VECTOR(drgn_resume_action_vector, struct drgn_resume_action);

static struct drgn_error *resume_all_threads(struct drgn_program *prog)
{
	struct drgn_error *err;

	VECTOR(drgn_resume_action_vector, actions);
	struct drgn_thread *thread;
	list_for_each_entry(thread, &prog->resumed_threads, node) {
		// TODO: skip redundant actions?
		struct drgn_resume_action action = {
			.thread = thread,
			.mode = thread->resume_mode,
			.sig = thread->resume_signal,
		};
		if (!drgn_resume_action_vector_append(&actions, &action))
			return &drgn_enomem;
	}

	struct drgn_resume_action action = {
		.mode = DRGN_RESUME_MODE_CONTINUE,
	};
	if (!drgn_resume_action_vector_append(&actions, &action))
		return &drgn_enomem;

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);

	struct resume_threads_result *result = malloc(sizeof(*result));
	if (!result)
		return &drgn_enomem;
	result_arg_init(&result->result, prog);
	drgn_resume_action_vector_steal(&actions, &result->actions,
					&result->num_actions);
	ctrl->ops.resume_threads(ctrl->arg, prog, result->actions,
				 result->num_actions, resume_threads_success,
				 resume_threads_error, result);
	return wait_for_result(&result->result, resume_threads_error);
}

#if 0
static void resume_only_thread_success(void *arg)
{
	if (!set_result(result, NULL))
		return;

	if (thread->resume_signal < 0) {
		// The thread stopped again while resuming.
		continue;
	}
	thread->stop_reason = DRGN_STOP_REASON_NONE;
	thread->resume_signal = -1;
	unleash_thread(thread);
}

static struct drgn_error *resume_only_thread(struct drgn_thread *thread)
{
	struct drgn_program *prog = drgn_thread_program(thread);
	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);

	struct drgn_thread_resume_action action = {
		.thread = thread,
		.mode = thread->resume_mode,
		.sig = thread->resume_signal,
	};

	struct result_arg *result = result_arg_alloc(prog);
	if (!result)
		return &drgn_enomem;
	ctrl->ops.resume_threads(ctrl->arg, prog, &action, 1, false,
				 resume_only_thread_success, noop_error,
				 result);
	return wait_for_result(result);
}
#endif

LIBDRGN_PUBLIC
struct drgn_error *drgn_thread_continue(struct drgn_thread *thread, int sig,
					bool only)
{
	struct drgn_error *err;

	if (sig < 0 && sig != DRGN_RESUME_DEFAULT_SIGNAL) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "resume signal must be non-negative");
	}

	if (drgn_thread_stop_reason(thread) == DRGN_STOP_REASON_NONE) {
		return drgn_error_create(DRGN_ERROR_NOT_STOPPED,
					 "thread is not stopped");
	}

	struct drgn_program *prog = drgn_thread_program(thread);

	err = check_attached(prog);
	if (err)
		return err;

	set_resume_signal(thread, sig);
	thread->resume_mode = DRGN_RESUME_MODE_CONTINUE;

	if (prog->in_all_stop && !only) {
		bool was_first_stopped =
			list_is_first(&thread->node, &prog->stopped_threads);

		move_thread(thread, &prog->resumed_threads);

		if (!list_empty(&prog->stopped_threads)) {
			if (was_first_stopped) {
				struct drgn_thread *next_stopped =
					list_first_entry(&prog->stopped_threads,
							 struct drgn_thread,
							 node);
				emit_thread_stop_event(next_stopped);
			}
			return NULL;
		}

		return resume_all_threads(prog);
	} else {
		return drgn_error_format(DRGN_ERROR_OTHER, "TODO %d %d",
					 prog->in_all_stop, only);
#if 0
		move_thread(thread, &prog->resumed_threads);
		return resume_only_thread(thread);
#endif
	}
}

#if 0
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

DEFINE_VECTOR(drgn_thread_resume_action_vector,
	      struct drgn_thread_resume_action);

DEFINE_HASH_MAP(breakpoint_step_map, struct drgn_breakpoint_site *,
		struct drgn_thread_vector threads, ptr_key_hash_pair,
		scalar_key_eq);

// TODO: name
static bool add_action(struct drgn_thread_resume_action_vector *controller_actions,
		       struct breakpoint_step_map *breakpoints,
		       const struct drgn_thread_resume_action *action)
{
	struct drgn_thread *thread = action->thread;

	if (thread->resume_generation == prog->resume_generation)
		return true; // Duplicate thread. Skip it.
	thread->resume_generation = prog->resume_generation;

	// TODO: should we resolve DRGN_RESUME_DEFAULT_SIGNAL here?
	thread->resuming = action->mode;
	if (thread->breakpoint_site
	    && !thread->breakpoint_site->hardware
	    && drgn_breakpoint_site_enabled(thread->breakpoint_site)) {
		struct drgn_thread_resume_action tmp_action = {
			.thread = thread,
			.mode = DRGN_RESUME_MODE_STEP,
			.sig = action->sig,
		};
		// TODO: add to breakpoints
	} else {
		return drgn_thread_resume_action_vector_append(controller_actions,
							       action);
	}
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_resume_threads(struct drgn_program *prog,
			    const struct drgn_thread_resume_action *actions,
			    size_t num_actions, bool sync_events)
{
	struct drgn_error *err;
	if (!num_actions) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "at least one thread must be given to resume");
	}

	err = sync_events_and_check_attached(prog, sync_events);
	if (err)
		return err;

	resuming_threads_guard(prog);

	prog->resume_generation++;

	VECTOR(drgn_thread_resume_action_vector, controller_actions);
	HASH_TABLE(breakpoint_step_map, breakpoints);
	size_t new_num_actions = num_actions;
	for (size_t i = 0; i < num_actions; i++) {
		const struct drgn_thread_resume_action *action = &actions[i];
		struct drgn_thread *thread = action->thread;

		SWITCH_ENUM(action->mode) {
		case DRGN_RESUME_MODE_CONTINUE:
		case DRGN_RESUME_MODE_STEP:
			if (action->sig < 0
			    && action->sig != DRGN_RESUME_DEFAULT_SIGNAL) {
				return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
							 "resume signal must be non-negative");
			}
			break;
		default:
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "invalid thread resume mode");
		}

		if (action->_reserved[0] || action->_reserved[1]) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "reserved fields must be 0");
		}

		if (thread) {
			if (drgn_thread_program(thread) != prog) {
				return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
							 "thread from wrong program");
			}
			if (new_num_actions < num_actions)
				continue; // TODO: explain

			if (!add_action(&controller_actions, &breakpoints, action))
				return &drgn_enomem;
		} else {
			if (new_num_actions < num_actions)
				continue;
			new_num_actions = i + 1;

			prog->resuming = action->mode;
			struct drgn_thread_resume_action tmp_action = *action;
			list_for_each_entry(thread, &prog->stopped_threads,
					    node) {
				tmp_action.thread = thread;
				if (!add_action(&controller_actions,
						&breakpoints, &tmp_action))
					return &drgn_enomem;
			}
			list_for_each_entry(thread, &prog->resumed_threads,
					    node) {
				tmp_action.thread = thread;
				if (!add_action(&controller_actions,
						&breakpoints, &tmp_action))
					return &drgn_enomem;
			}
		}
	}

	num_actions = new_num_actions;

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	// TODO: check that resume_threads/pause_all_threads are defined.

	// TODO: this condition could be more specific: only if there could be
	// something still running (i.e., in non-stop mode or something in
	// running_threads in all-stop mode).
	if (!breakpoint_step_map_empty(&breakpoints)) {
		err = ctrl->ops.pause_all_threads(ctrl->arg, prog);
		if (err)
			return err;
		// TODO: how should we update state for this? Pretend we're in
		// all-stop, or add a specific paused flag?
		// TODO: could the controller queue things that mess up the
		// states of the threads we're about to work on?
	}

	hash_table_for_each(breakpoint_step_map, it, &breakpoints) {
		err = ctrl->ops.disable_breakpoint_sites(ctrl->arg,
							 &it->entry.key, 1);
		if (err)
			return err;

		err = ctrl->ops.resume_threads(ctrl->arg, prog,
					       drgn_thread_resume_action_vector_begin(&it->entry.value),
					       drgn_thread_resume_action_vector_size(&it->entry.value),
					       false);
		if (err)
			return err;

		vector_for_each(drgn_thread_resume_action_vector, action,
				&it->entry.value) {
			struct drgn_thread *thread = action->thread;
			if (!thread->resuming) {
				// Thread stopped while stepping.
				continue;
			}

			if (thread->resuming == DRGN_RESUME_MODE_CONTINUE) {
				struct drgn_thread_resume_action tmp_action = {
					.thread = thread,
					.mode = DRGN_RESUME_MODE_CONTINUE,
				};
				// TODO: reserve so this can't fail.
				drgn_thread_resume_action_vector_append(&controller_actions,
									&tmp_action);
			}

			thread->last_signal = -1;
			thread->resume_signal = -1;
			move_thread(thread, &prog->stopped_threads);
		}

		err = ctrl->ops.enable_breakpoint_sites(ctrl->arg,
							&it->entry.key, 1);
		if (err)
			return err;
	}

	if (!actions[new_num_actions - 1].thread) {
		// TODO: reserve so this can't fail.
		drgn_thread_resume_action_vector_append(&controller_actions,
							&actions[new_num_actions - 1]);
	}

	err = ctrl->ops.resume_threads(ctrl->arg, prog,
				       drgn_thread_resume_action_vector_begin(&controller_actions),
				       drgn_thread_resume_action_vector_size(&controller_actions),
				       !breakpoint_step_map_empty(&breakpoints));
	if (err)
		return err;

	if (!drgn_thread_resume_action_vector_last(&controller_actions)->thread) {
		struct drgn_thread_resume_action *action =
			drgn_thread_resume_action_vector_pop(&controller_actions);
		SWITCH_ENUM(action->mode) {
		case DRGN_RESUME_MODE_CONTINUE:
			// As long as no other threads stopped, we're no longer
			// in all-stop.
			if (prog->in_all_stop && prog->resuming) {
				prog->in_all_stop = false;
				clear_running_threads(prog);
			}
			break;
		case DRGN_RESUME_MODE_STEP:
			if (prog->all_stop) {
				prog->in_all_stop = true;
				clear_running_threads(prog);
			}
			break;
		default:
			UNREACHABLE();
		}
	}

	vector_for_each(drgn_thread_resume_action_vector, action,
			&controller_actions) {
		struct drgn_thread *thread = action->thread;
		if (!thread->resuming) {
			// Thread stopped while resuming.
			continue;
		}

		thread->last_signal = -1;
		thread->resume_signal = -1;
		SWITCH_ENUM(action->mode) {
		case DRGN_RESUME_MODE_CONTINUE:
			if (prog->in_all_stop)
				move_thread(thread, &prog->running_threads);
			else
				unleash_thread(thread);
			break;
		case DRGN_RESUME_MODE_STEP:
			move_thread(thread, &prog->stopped_threads);
			break;
		default:
			UNREACHABLE();
		}
	}

	return NULL;
}
#endif

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

#if 0
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
#endif

#define modifying_breakpoints_guard(prog, reason) do { } while (0) /* TODO */

static void rollback_set_breakpoint(struct drgn_breakpoint **bpp)
{
	if (*bpp) {
		drgn_breakpoint_remove_impl(*bpp);
		drgn_breakpoint_decref(*bpp);
	}
}

struct breakpoint_sites_result {
	struct result_arg result;
	struct drgn_breakpoint_site **sites;
	size_t num_sites;
};

static void breakpoint_sites_abort(void *arg, struct drgn_error *err)
{
	struct breakpoint_sites_result *result = arg;
	// The caller is going to return and destroy the new breakpoint, so we
	// need to keep the sites alive for the controller.
	for (size_t i = 0; i < result->num_sites; i++)
		drgn_breakpoint_site_incref(result->sites[i]);
	set_result(&result->result, err);
}

static void breakpoint_sites_error(void *arg, struct drgn_error *err)
{
	struct breakpoint_sites_result *result = arg;
	if (result->result.err == &result_aborted) {
		for (size_t i = 0; i < result->num_sites; i++)
			drgn_breakpoint_site_decref(result->sites[i]);
	}
	free(result->sites);
	set_result(&result->result, err);
}

static void breakpoint_sites_success(void *arg)
{
	breakpoint_sites_error(arg, NULL);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_breakpoint(struct drgn_program *prog,
			    const uint64_t *addresses, size_t n, bool hardware,
			    bool enable, struct drgn_breakpoint **ret)
{
	struct drgn_error *err;
	if (n == 0) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "breakpoint must have at least one address");
	}

	err = check_attached(prog);
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
			struct breakpoint_sites_result *result =
				malloc(sizeof(*result));
			if (!result)
				return &drgn_enomem;
			result_arg_init(&result->result, prog);
			result->sites = sites_to_enable;
			result->num_sites = num_sites_to_enable;
			ctrl->ops.enable_breakpoint_sites(ctrl->arg,
							  sites_to_enable,
							  num_sites_to_enable,
							  breakpoint_sites_success,
							  breakpoint_sites_error,
							  result);
			sites_to_enable = NULL; // Owned by result now.
			err = wait_for_result(&result->result,
					      breakpoint_sites_abort);
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
		struct drgn_program *prog = drgn_breakpoint_program(bp);
		struct drgn_execution_controller *ctrl =
			get_enabled_controller(prog);

		struct breakpoint_sites_result *result =
			malloc(sizeof(*result));
		if (!result)
			return &drgn_enomem;
		result_arg_init(&result->result, prog);
		result->sites = sites_to_disable;
		result->num_sites = num_sites_to_disable;
		ctrl->ops.disable_breakpoint_sites(ctrl->arg, sites_to_disable,
						   num_sites_to_disable,
						   breakpoint_sites_success,
						   breakpoint_sites_error,
						   result);
		sites_to_disable = NULL; // Owned by result now.
		err = wait_for_result(&result->result, breakpoint_sites_abort);
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
drgn_breakpoint_remove(struct drgn_breakpoint *bp)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_breakpoint_program(bp);

	if (list_empty(&bp->prog_node))
		return NULL;

	// Breakpoints can only be set while attached to the program, so we
	// don't need to check.

	modifying_breakpoints_guard(prog, "removing");

	err = drgn_breakpoint_disable_impl(bp);
	if (err)
		return err;
	drgn_breakpoint_remove_impl(bp);
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_breakpoint_enable(struct drgn_breakpoint *bp)
{
	struct drgn_error *err;
	struct drgn_program *prog = bp->prog;

	if (bp->enabled)
		return NULL;
	if (list_empty(&bp->prog_node)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "can't enable removed breakpoint");
	}

	// Breakpoints can only be set while attached to the program, so we
	// don't need to check.

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

		struct breakpoint_sites_result *result =
			malloc(sizeof(*result));
		if (!result)
			return &drgn_enomem;
		result_arg_init(&result->result, prog);
		result->sites = sites_to_enable;
		result->num_sites = num_sites_to_enable;
		ctrl->ops.enable_breakpoint_sites(ctrl->arg, sites_to_enable,
						  num_sites_to_enable,
						  breakpoint_sites_success,
						  breakpoint_sites_error,
						  result);
		sites_to_enable = NULL; // Owned by result now.
		err = wait_for_result(&result->result, breakpoint_sites_abort);
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
struct drgn_error *drgn_breakpoint_disable(struct drgn_breakpoint *bp)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_breakpoint_program(bp);

	if (!bp->enabled) // TODO: remove redundant check?
		return NULL;

	// Breakpoints can only be enabled while attached to the program, so we
	// don't need to check.

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

#if 0
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
#endif

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

LIBDRGN_PUBLIC struct drgn_program *
drgn_event_listener_program(const struct drgn_event_listener *listener)
{
	return listener->prog;
}

LIBDRGN_PUBLIC
void drgn_event_listener_remove(struct drgn_event_listener *listener)
{
	struct drgn_program *prog = listener->prog;
	listener->callback(prog, NULL, listener->arg);
	if (prog->event_listeners_to_free) {
		listener->callback = NULL;
		listener->next_to_free = prog->event_listeners_to_free;
		prog->event_listeners_to_free = listener;
		return;
	}
	list_del(&listener->node);
	free(listener);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_add_event_listener(struct drgn_program *prog,
				drgn_event_listener_fn *callback, void *arg,
				struct drgn_event_listener **ret)
{
	if (!callback) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid callback");
	}

	struct drgn_event_listener *listener = malloc(sizeof(*listener));
	if (!listener)
		return &drgn_enomem;
	listener->prog = prog;
	listener->callback = callback;
	listener->arg = arg;
	list_add_tail(&listener->node, &prog->event_listeners);
	if (ret)
		*ret = listener;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_notify_program_exit(struct drgn_program *prog, int status)
{
	SWITCH_ENUM(prog->attach_state) {
	case DRGN_ATTACH_STATE_DETACHED:
	case DRGN_ATTACH_STATE_ATTACHING:
		return drgn_error_create(DRGN_ERROR_NOT_ATTACHED,
					 "not attached to program");
	case DRGN_ATTACH_STATE_ATTACHED:
		prog->attach_state = DRGN_ATTACH_STATE_EXITED;
		break;
	case DRGN_ATTACH_STATE_DETACHING:
		// A controller can discover that the program exited while
		// detaching, so we allow this and still emit the event, but the
		// DETACHING state takes precedence over EXITED.
		break;
	case DRGN_ATTACH_STATE_EXITED:
		return drgn_error_create(DRGN_ERROR_PROGRAM_EXITED,
					 "program exited");
	default:
		UNREACHABLE();
	}

	struct drgn_event event = {
		.type = DRGN_EVENT_PROGRAM_EXIT,
		.exit_status = status,
	};
	emit_event(prog, &event);
	return NULL;
}

static bool ignore_notify_thread_stop(struct drgn_thread *thread)
{
	struct drgn_program *prog = drgn_thread_program(thread);
	if (prog->in_all_stop) {
		drgn_log_warning(prog,
				 "ignored thread stop notification while in all-stop");
		return true;
	}
	if (thread->stop_reason != DRGN_STOP_REASON_NONE) {
		drgn_log_warning(prog,
				 "ignored thread stop notification on stopped thread");
		return true;
	}
	return false;
}

static void drgn_notify_thread_stop_common(struct drgn_thread *thread)
{
	struct drgn_program *prog = drgn_thread_program(thread);
	move_thread(thread, &prog->stopped_threads);
	if (!prog->all_stop)
		emit_thread_stop_event(thread);
}

static void
drgn_notify_thread_breakpoint_impl(struct drgn_thread *thread,
				   struct drgn_breakpoint_site *site)
{
	thread->stop_reason = DRGN_STOP_REASON_BREAKPOINT;
	thread->stop_signal = SIGTRAP;
	drgn_breakpoint_site_incref(site);
	thread->stop_site = site;

	drgn_notify_thread_stop_common(thread);
}

LIBDRGN_PUBLIC void drgn_notify_thread_stop(struct drgn_thread *thread, int sig,
					    uint64_t pc, uint64_t reason_mask)
{
	if (ignore_notify_thread_stop(thread))
		return;

	if (reason_mask & (1 << DRGN_STOP_REASON_BREAKPOINT)
	    && sig == SIGTRAP) {
		struct drgn_program *prog = drgn_thread_program(thread);
		auto it = drgn_breakpoint_site_table_search(&prog->breakpoint_sites,
							    &pc);
		if (it.entry && drgn_breakpoint_site_enabled(*it.entry)) {
			drgn_notify_thread_breakpoint_impl(thread, *it.entry);
			return;
		}
	}

	thread->stop_reason = DRGN_STOP_REASON_SIGNAL;
	// TODO: we don't check sig now
	thread->stop_signal = sig;

	drgn_notify_thread_stop_common(thread);
}

LIBDRGN_PUBLIC
void drgn_notify_thread_breakpoint(struct drgn_thread *thread,
				   struct drgn_breakpoint_site *site)
{
	if (!ignore_notify_thread_stop(thread))
		drgn_notify_thread_breakpoint_impl(thread, site);
}

LIBDRGN_PUBLIC void drgn_notify_all_stop(struct drgn_program *prog)
{
	if (!prog->all_stop) {
		drgn_log_warning(prog,
				 "ignored all-stop notification in non-stop mode");
		return;
	}
	if (prog->in_all_stop) {
		drgn_log_warning(prog,
				 "ignored all-stop notification while already in all-stop");
		return;
	}

	prog->in_all_stop = true;

	struct drgn_thread *thread;
	if (list_is_singular(&prog->stopped_threads)) {
		// Common case: only one thread stopped.
		thread = list_first_entry(&prog->stopped_threads,
					  struct drgn_thread, node);
	} else {
		// Multiple threads stopped simultaneously. Pick the first
		// thread to emit a stop event for randomly using reservoir
		// sampling. TODO: explain why
		thread = NULL;
		struct drgn_thread *thread2;
		long i = 0;
		list_for_each_entry(thread2, &prog->stopped_threads, node) {
			i++;
			if (random() % i == 0)
				thread = thread2;
		}
		if (!thread)
			return; // TODO: no stopped threads?
		list_rotate_to_front(&thread->node, &prog->stopped_threads);
	}
	emit_thread_stop_event(thread);
}

static inline uint32_t drgn_fd_events_to_epoll(enum drgn_fd_events events)
{
	uint32_t ret = 0;
	if (events & DRGN_FD_EVENT_READ)
		ret |= EPOLLIN;
	if (events & DRGN_FD_EVENT_WRITE)
		ret |= EPOLLOUT;
	return ret;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_program_register_fd(struct drgn_program *prog, int fd,
					    enum drgn_fd_events events,
					    drgn_fd_handler_fn *callback,
					    void *arg)
{
	struct drgn_error *err;
	if (!events || (events & ~(DRGN_FD_EVENT_READ | DRGN_FD_EVENT_WRITE))) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid events");
	}
	if (!callback) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid callback");
	}

	struct hash_pair hp = fd_handler_table_hash(&fd);
	if (fd_handler_table_search_hashed(&prog->fd_handlers, &fd, hp).entry) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "fd is already registered");
	}

	err = drgn_program_ensure_epoll_fd(prog);
	if (err)
		return err;

	struct fd_handler *handler = malloc(sizeof(*handler));
	if (!handler)
		return &drgn_enomem;
	handler->fd = fd;
	handler->events = events;
	handler->callback = callback;
	handler->arg = arg;
	if (fd_handler_table_insert_searched(&prog->fd_handlers, &handler, hp,
					     NULL) < 0) {
		free(handler);
		return &drgn_enomem;
	}

	struct epoll_event event = {
		.events = drgn_fd_events_to_epoll(events),
		.data.ptr = handler,
	};
	if (epoll_ctl(prog->epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
		int saved_errno = errno;
		fd_handler_table_delete(&prog->fd_handlers, &fd);
		free(handler);
		return drgn_error_create_os("epoll_ctl", saved_errno, NULL);
	}
	return NULL;
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_program_modify_fd(struct drgn_program *prog, int fd,
					  enum drgn_fd_events events,
					  drgn_fd_handler_fn *callback,
					  void *arg)
{
	if (!events || (events & ~(DRGN_FD_EVENT_READ | DRGN_FD_EVENT_WRITE))) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid events");
	}

	auto it = fd_handler_table_search(&prog->fd_handlers, &fd);
	if (!it.entry) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "fd is not registered");
	}

	struct fd_handler *handler = *it.entry;
	if (events != handler->events) {
		struct epoll_event event = {
			.events = drgn_fd_events_to_epoll(events),
			.data.ptr = handler,
		};
		if (epoll_ctl(prog->epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0)
			return drgn_error_create_os("epoll_ctl", errno, NULL);
		handler->events = events;
	}

	if (callback) {
		handler->callback(prog, handler->fd, 0, handler->arg);
		handler->callback = callback;
		handler->arg = arg;
	}
	return NULL;
}

struct drgn_error *drgn_program_unregister_fd(struct drgn_program *prog, int fd)
{
	struct hash_pair hp = fd_handler_table_hash(&fd);
	auto it = fd_handler_table_search_hashed(&prog->fd_handlers, &fd, hp);
	if (!it.entry) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "fd is not registered");
	}

	if (epoll_ctl(prog->epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0
	    // Caller could've closed the fd first.
	    && errno != EBADF && errno != ENOENT)
		return drgn_error_create_os("epoll_ctl", errno, NULL);

	struct fd_handler *handler = *it.entry;
	fd_handler_table_delete_iterator_hashed(&prog->fd_handlers, it, hp);

	handler->callback(prog, handler->fd, 0, handler->arg);
	if (prog->fd_handlers_to_free) {
		handler->events = 0;
		handler->callback = NULL;
		handler->arg = NULL;
		handler->next_to_free = prog->fd_handlers_to_free;
		prog->fd_handlers_to_free = handler;
	} else {
		free(handler);
	}
	return NULL;
}

LIBDRGN_PUBLIC enum drgn_fd_events
drgn_program_registered_fd(struct drgn_program *prog, int fd,
			   drgn_fd_handler_fn **callback_ret, void **arg_ret)
{
	auto it = fd_handler_table_search(&prog->fd_handlers, &fd);
	if (!it.entry) {
		*callback_ret = NULL;
		*arg_ret = NULL;
		return 0;
	}
	*callback_ret = (*it.entry)->callback;
	*arg_ret = (*it.entry)->arg;
	return (*it.entry)->events;
}
