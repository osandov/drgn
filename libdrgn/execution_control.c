// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <inttypes.h>
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

static struct drgn_error promise_new =
	DRGN_ERROR_INIT(DRGN_ERROR_RUNTIME, "new promise");
static struct drgn_error promise_pending =
	DRGN_ERROR_INIT(DRGN_ERROR_RUNTIME, "promise pending");
static struct drgn_error promise_error =
	DRGN_ERROR_INIT(DRGN_ERROR_RUNTIME, "promise error");
static struct drgn_error promise_cancelled =
	DRGN_ERROR_INIT(DRGN_ERROR_RUNTIME, "promise cancelled");

struct drgn_promise {
	struct drgn_error *err;
	void (*free)(struct drgn_promise *);
	void (*then)(struct drgn_promise *);
};

struct drgn_void_promise {
	struct drgn_promise promise;
};

struct drgn_bool_promise {
	struct drgn_promise promise;
	bool result;
};

static inline void drgn_promise_init(struct drgn_promise *promise,
				     void (*free)(struct drgn_promise *))
{
	promise->err = &promise_new;
	promise->free = free;
	promise->then = NULL;
}

static void drgn_promise_default_free(struct drgn_promise *promise)
{
	drgn_error_destroy(promise->err);
	free(promise);
}

static void drgn_promise_destroy(struct drgn_promise *promise)
{
	(promise->free ?: drgn_promise_default_free)(promise);
}

// Returns false and destroys promise and err if promise was already cancelled,
// returns true and sets promise->err to err otherwise.
static inline bool drgn_promise_set_common(struct drgn_promise *promise,
					   struct drgn_error *err)
{
	if (promise->err == &promise_cancelled) {
		drgn_error_destroy(err);
		drgn_promise_destroy(promise);
		return false;
	}
	// This catches forgotten drgn_promise_share() and some double
	// completion bugs. Note that in the latter case, the promise may have
	// already been freed.
	assert(promise->err == &promise_pending);
	promise->err = err;
	return true;
}

// Parentheses around function names to suppress expansion of wrapper macros.
LIBDRGN_PUBLIC void (drgn_promise_set_error)(struct drgn_promise *promise,
					     struct drgn_error *err)
{
	if (drgn_promise_set_common(promise, err) && promise->then)
		promise->then(promise);
}

LIBDRGN_PUBLIC bool (drgn_promise_cancelled)(struct drgn_promise *promise)
{
	return promise->err == &promise_cancelled;
}

static struct drgn_void_promise *drgn_void_promise_create(void)
{
	struct drgn_void_promise *promise = malloc(sizeof(*promise));
	if (promise)
		drgn_promise_init(&promise->promise, NULL);
	return promise;
}

LIBDRGN_PUBLIC void
drgn_void_promise_set_result(struct drgn_void_promise *promise)
{
	if (drgn_promise_set_common(&promise->promise, NULL)
	    && promise->promise.then)
		promise->promise.then(&promise->promise);
}

static struct drgn_bool_promise *drgn_bool_promise_create(void)
{
	struct drgn_bool_promise *promise = malloc(sizeof(*promise));
	if (promise)
		drgn_promise_init(&promise->promise, NULL);
	return promise;
}

LIBDRGN_PUBLIC void
drgn_bool_promise_set_result(struct drgn_bool_promise *promise, bool result)
{
	if (!drgn_promise_set_common(&promise->promise, NULL))
		return;
	promise->result = result;
	if (promise->promise.then)
		promise->promise.then(&promise->promise);
}

static inline struct drgn_promise *
drgn_promise_share(struct drgn_promise *promise)
{
	assert(promise->err == &promise_new);
	promise->err = &promise_pending;
	return promise;
}

#define drgn_promise_share(promise) ({				\
	auto _promise_ = (promise);				\
	drgn_promise_share(drgn_cast_promise(_promise_));	\
	_promise_;						\
})

static void drgn_promise_cancel(struct drgn_promise *promise)
{
	if (promise->err == &promise_pending)
		promise->err = &promise_cancelled;
	else
		drgn_promise_destroy(promise);
}

static void drgn_promise_cleanup(void *p)
{
	if (*(struct drgn_promise **)p)
		drgn_promise_cancel(*(struct drgn_promise **)p);
}

#define _cleanup_promise_ _cleanup_(drgn_promise_cleanup)

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
	case DRGN_ATTACH_STATE_LOST:
		return drgn_error_create(DRGN_ERROR_PROGRAM_LOST,
					 "lost program");
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
	initstate_r(time(NULL) ^ getpid(), prog->random_buf,
		    sizeof(prog->random_buf), &prog->random_data);
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
		list_del_init(&thread->node);
		drgn_thread_decref(thread);
	}
	list_for_each_entry_safe(thread, tmp, &prog->resumed_threads, node) {
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

static struct drgn_error *wait_for_promise(struct drgn_program *prog,
					   struct drgn_promise *promise)
{
	struct drgn_error *err;
	assert(promise->err != &promise_new);
	while (promise->err == &promise_pending) {
		err = drgn_program_poll(prog, -1, NULL);
		if (err)
			return err;
	}
	if (promise->err) {
		err = promise->err;
		promise->err = &promise_error;
		return err;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_attach(struct drgn_program *prog, enum drgn_attach_flags flags)
{
	struct drgn_error *err;

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

	_cleanup_promise_ struct drgn_bool_promise *promise =
		drgn_bool_promise_create();
	if (!promise)
		return &drgn_enomem;

	prog->attach_state = DRGN_ATTACH_STATE_ATTACHING;

	ctrl->ops.attach(ctrl->arg, prog, flags, drgn_promise_share(promise));
	err = wait_for_promise(prog, &promise->promise);
	if (err) {
		prog->attach_state = DRGN_ATTACH_STATE_DETACHED;
		return err;
	}

	// The state may have changed to EXITED or LOST while attaching.
	if (prog->attach_state == DRGN_ATTACH_STATE_ATTACHING)
		prog->attach_state = DRGN_ATTACH_STATE_ATTACHED;
	prog->all_stop = promise->result;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_detach(struct drgn_program *prog)
{
	struct drgn_error *err;

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

	_cleanup_promise_ struct drgn_void_promise *promise =
		drgn_void_promise_create();
	if (!promise)
		return &drgn_enomem;

	enum drgn_attach_state orig_attach_state = prog->attach_state;
	prog->attach_state = DRGN_ATTACH_STATE_DETACHING;

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	ctrl->ops.detach(ctrl->arg, prog, drgn_promise_share(promise));
	err = wait_for_promise(prog, &promise->promise);
	if (err) {
		prog->attach_state = orig_attach_state;
		return err;
	}

	prog->attach_state = DRGN_ATTACH_STATE_DETACHED;
	prog->in_all_stop_ = DRGN_NOT_ALL_STOPPED;
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

	_cleanup_promise_ struct drgn_void_promise *promise =
		drgn_void_promise_create();
	if (!promise)
		return &drgn_enomem;
	ctrl->ops.interrupt_any_thread(ctrl->arg, prog,
				       drgn_promise_share(promise));
	return wait_for_promise(prog, &promise->promise);
}

LIBDRGN_PUBLIC
enum drgn_stop_reason drgn_thread_stop_reason(struct drgn_thread *thread)
{
	if (thread->stop_event_emitted)
		return thread->stop_reason;
	if (drgn_thread_program(thread)->in_all_stop_ == DRGN_ALL_STOPPED)
		return DRGN_STOP_REASON_SYNTHETIC;
	return DRGN_STOP_REASON_NONE;
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

static void emit_event(struct drgn_program *prog, struct drgn_event *event)
{
	if (list_empty(&prog->event_listeners))
		return;
	bool free_listeners = !prog->event_listeners_to_free;
	if (free_listeners)
		prog->event_listeners_to_free = &sentinel_event_listener;

	struct drgn_event_listener *listener =
		list_first_entry(&prog->event_listeners,
				 struct drgn_event_listener, node);
	struct drgn_event_listener *last_listener =
		list_last_entry(&prog->event_listeners,
				struct drgn_event_listener, node);
	for (;;) {
		if (!listener->callback) {
			// Listener was removed from another listener.
			continue;
		}
		listener->callback(prog, event, listener->arg);
		if (listener == last_listener)
			break;
		listener = list_next_entry(listener, node);
	}

	if (free_listeners) {
		listener = prog->event_listeners_to_free;
		while (listener != &sentinel_event_listener) {
			struct drgn_event_listener *next = listener->next_to_free;
			list_del(&listener->node);
			free(listener);
			listener = next;
		}
		prog->event_listeners_to_free = NULL;
	}
}

static void emit_thread_stop_event(struct drgn_thread *thread)
{
	struct drgn_program *prog = drgn_thread_program(thread);
	thread->stop_event_emitted = true;
	struct drgn_event event = {
		.type = DRGN_EVENT_THREAD_STOP,
		.thread = thread,
	};
	emit_event(prog, &event);
}

static void emit_random_thread_stop_event(struct drgn_program *prog)
{
	struct drgn_thread *thread;
	if (list_is_singular(&prog->stopped_threads)) {
		// Common case: only one thread stopped.
		thread = list_first_entry(&prog->stopped_threads,
					  struct drgn_thread, node);
	} else {
		// Multiple threads stopped simultaneously.
		size_t n = list_count_nodes(&prog->stopped_threads);
		if (n == 0)
			return; // TODO: no stopped threads?
#ifndef TODO
		int32_t i;
		random_r(&prog->random_data, &i);
		i %= n;
#else
		int32_t i = 0;
#endif
		list_for_each_entry(thread, &prog->stopped_threads, node) {
			if (i == 0)
				break;
			i--;
		}
		list_move(&thread->node, &prog->stopped_threads);
	}
	emit_thread_stop_event(thread);
}

struct breakpoint_sites_promise {
	struct drgn_void_promise promise;
	size_t num_sites;
	struct drgn_breakpoint_site *sites[];
};

static void breakpoint_sites_promise_free(struct drgn_promise *p)
{
	struct breakpoint_sites_promise *promise =
		(struct breakpoint_sites_promise *)p;
	for (size_t i = 0; i < promise->num_sites; i++)
		drgn_breakpoint_site_decref(promise->sites[i]);
	drgn_promise_default_free(p);
}

static struct breakpoint_sites_promise *
breakpoint_sites_promise_create(size_t capacity)
{
	struct breakpoint_sites_promise *promise =
		malloc_flexible_array(struct breakpoint_sites_promise, sites,
				      capacity);
	if (promise) {
		drgn_promise_init(&promise->promise.promise,
				  breakpoint_sites_promise_free);
		promise->num_sites = 0;
	}
	return promise;
}

#if 0
static struct drgn_error *
drgn_breakpoint_site_disable(struct drgn_breakpoint_site *site)
{
	struct breakpoint_sites_result *result =
		malloc_flexible_array(struct drgn_breakpoint_site_result, sites,
				      1);
	if (!result)
		return &drgn_enomem;
	result_arg_init(&result->result, prog);
	result->sites[0] = site;
	result->num_sites = 1;
	ctrl->ops.enable_breakpoint_sites(ctrl->arg, result->sites, 1,
					  breakpoint_sites_success,
					  breakpoint_sites_error, result);
	return wait_for_result(&result->result, breakpoint_sites_error);
}

static struct drgn_error *
drgn_breakpoint_site_disable(struct drgn_breakpoint_site *site)
{
	struct breakpoint_sites_result *result =
		malloc_flexible_array(struct drgn_breakpoint_site_result, sites,
				      1);
	if (!result)
		return &drgn_enomem;
	result_arg_init(&result->result, prog);
	result->sites[0] = site;
	result->num_sites = 1;
	ctrl->ops.disable_breakpoint_sites(ctrl->arg, result->sites, 1,
					   breakpoint_sites_success,
					   breakpoint_sites_error, result);
	return wait_for_result(&result->result, breakpoint_sites_error);
}
#endif

struct resume_threads_promise {
	struct drgn_void_promise promise;
	size_t capacity;
	size_t num_actions;
	struct drgn_resume_action actions[];
};

static struct resume_threads_promise *
resume_threads_promise_create(size_t capacity)
{
	struct resume_threads_promise *promise =
		malloc_flexible_array(struct resume_threads_promise, actions,
				      capacity);
	if (promise) {
		drgn_promise_init(&promise->promise.promise, NULL);
		promise->capacity = capacity;
		promise->num_actions = 0;
	}
	return promise;
}

static bool
resume_threads_promise_append_action(struct resume_threads_promise **promisep,
				     struct drgn_resume_action *action)
{
	struct resume_threads_promise *promise = *promisep;
	if (promise->num_actions == promise->capacity) {
		size_t new_capacity;
		if (promise->capacity == 0)
			new_capacity = 1;
		else if (__builtin_mul_overflow(promise->capacity, 2U,
						&new_capacity))
			return false;
		promise = realloc_flexible_array(promise, actions,
						 new_capacity);
		if (!promise)
			return false;
		promise->capacity = new_capacity;
		*promisep = promise;
	}
	promise->actions[promise->num_actions++] = *action;
	return true;
}

static void bypass_breakpoint_resume_done(struct drgn_promise *p)
{
	if (p->err)
		return;

	struct resume_threads_promise *promise =
		container_of(p, struct resume_threads_promise, promise.promise);
	struct drgn_thread *thread = promise->actions[0].thread;
	struct drgn_program *prog = drgn_thread_program(thread);

	thread->stop_reason = DRGN_STOP_REASON_NONE;
	thread->stop_signal = -1;
	thread->resume_signal = 0;
	drgn_clear_ref(thread->stop_site);
	thread->stepping = true;

	prog->bypassing_breakpoint = thread;
}

static struct drgn_error *bypass_breakpoint(struct drgn_thread *thread)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_thread_program(thread);
	struct drgn_breakpoint_site *site = thread->stop_site;

	_cleanup_promise_ struct breakpoint_sites_promise *site_promise =
		breakpoint_sites_promise_create(1);
	if (!site_promise)
		return &drgn_enomem;
	drgn_breakpoint_site_incref(site);
	site_promise->sites[0] = site;
	site_promise->num_sites = 1;

	_cleanup_promise_ struct resume_threads_promise *step_promise =
		resume_threads_promise_create(1);
	if (!step_promise)
		return &drgn_enomem;
	struct drgn_resume_action action = {
		.thread = thread,
		.mode = DRGN_RESUME_MODE_STEPI,
		.sig = thread->resume_signal,
	};
	resume_threads_promise_append_action(&step_promise, &action);
	step_promise->promise.promise.then = bypass_breakpoint_resume_done;

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	ctrl->ops.disable_breakpoint_sites(ctrl->arg, site_promise->sites, 1,
					   drgn_promise_share(&site_promise->promise));
	err = wait_for_promise(prog, &site_promise->promise.promise);
	if (err)
		return err;

	ctrl->ops.resume_threads(ctrl->arg, prog, step_promise->actions,
				 step_promise->num_actions,
				 drgn_promise_share(&step_promise->promise));
	err = wait_for_promise(prog, &step_promise->promise.promise);
	if (err)
		return err;

	while (prog->bypassing_breakpoint) {
		err = drgn_program_poll(prog, -1, NULL);
		if (err)
			return err;
	}

	// TODO: add a real way to do this?
	site_promise->promise.promise.err = &promise_new;
	ctrl->ops.enable_breakpoint_sites(ctrl->arg, site_promise->sites, 1,
					  drgn_promise_share(&site_promise->promise));
	return wait_for_promise(prog, &site_promise->promise.promise);
}

static struct drgn_error *continue_all_threads(struct drgn_program *prog)
{
	struct drgn_error *err;

	_cleanup_promise_ struct resume_threads_promise *promise =
		resume_threads_promise_create(1);
	if (!promise)
		return &drgn_enomem;

	struct drgn_thread *thread, *tmp;
	list_for_each_entry(thread, &prog->resumed_threads, node) {
		if (thread->resume_signal == 0)
			continue;
		struct drgn_resume_action action = {
			.thread = thread,
			.mode = DRGN_RESUME_MODE_CONTINUE,
			.sig = thread->resume_signal,
		};
		if (!resume_threads_promise_append_action(&promise, &action))
			return &drgn_enomem;
	}

	struct drgn_resume_action action = {
		.mode = DRGN_RESUME_MODE_CONTINUE,
	};
	if (!resume_threads_promise_append_action(&promise, &action))
		return &drgn_enomem;

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	ctrl->ops.resume_threads(ctrl->arg, prog, promise->actions,
				 promise->num_actions,
				 drgn_promise_share(&promise->promise));
	err = wait_for_promise(prog, &promise->promise.promise);
	if (err)
		return err;

	list_for_each_entry_safe(thread, tmp, &prog->resumed_threads, node) {
		thread->stop_reason = DRGN_STOP_REASON_NONE;
		thread->stop_signal = -1;
		thread->resume_signal = -1;
		drgn_clear_ref(thread->stop_site);
		unleash_thread(thread);
	}
#if 0
	clear_running_threads(prog);
#endif
	prog->in_all_stop_ = DRGN_NOT_ALL_STOPPED;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_continue(struct drgn_thread *thread, int sig, bool only)
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

	// TODO: can the thread even be stopped if not attached?
	err = check_attached(prog);
	if (err)
		return err;

	if (prog->in_all_stop_ != DRGN_ALL_STOPPED || only) {
		return drgn_error_format(DRGN_ERROR_OTHER, "TODO %d %d",
					 prog->in_all_stop_, only);
	}

	set_resume_signal(thread, sig);
	fprintf(stderr, "set thread %u sig to %d\n", thread->tid, thread->resume_signal);
	if (!thread->stop_event_emitted) {
		if (list_empty(&thread->node))
			move_thread(thread, &prog->resumed_threads);
		thread = list_first_entry(&prog->stopped_threads,
					  struct drgn_thread, node);
		assert(thread->stop_event_emitted);
		set_resume_signal(thread, DRGN_RESUME_DEFAULT_SIGNAL);
		fprintf(stderr, "set stopped thread %u sig to default (%d)\n", thread->tid, thread->resume_signal);
	}
	move_thread(thread, &prog->resumed_threads);
	thread->stop_event_emitted = false;

	// Not drgn_thread_stop_reason() because we just cleared
	// stop_event_emitted.
	if (thread->stop_reason == DRGN_STOP_REASON_BREAKPOINT) {
		err = bypass_breakpoint(thread);
		if (err)
			return err;
	}

	if (!list_empty(&prog->stopped_threads)) {
		thread = list_first_entry(&prog->stopped_threads,
					  struct drgn_thread, node);
		if (thread->resume_signal > 0) {
			char sig_buf[SIGNAL_STR_BUF_LEN];
			drgn_log_warning(prog,
					 "couldn't send %s to thread %" PRIu32,
					 signal_str(thread->resume_signal, sig_buf),
					 thread->tid);
		}
		thread->resume_signal = -1;
		emit_random_thread_stop_event(prog);
		return NULL;
	}
	return continue_all_threads(prog);
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

	_cleanup_promise_ struct breakpoint_sites_promise *promise = NULL;
	if (enable) {
		promise = breakpoint_sites_promise_create(n);
		if (!promise)
			return &drgn_enomem;
	}

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
		if (enable && list_empty(&site->enabled_breakpoints)) {
			drgn_breakpoint_site_incref(site);
			promise->sites[promise->num_sites++] = site;
		}
	}

	// prog->breakpoints holds a reference.
	drgn_breakpoint_incref(bp);
	list_add_tail(&bp->prog_node, &prog->breakpoints);
	prog->breakpoints_generation++;

	if (enable) {
		if (promise->num_sites) {
			ctrl->ops.enable_breakpoint_sites(ctrl->arg,
							  promise->sites,
							  promise->num_sites,
							  drgn_promise_share(&promise->promise));
			err = wait_for_promise(prog, &promise->promise.promise);
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

	_cleanup_promise_ struct breakpoint_sites_promise *promise =
		breakpoint_sites_promise_create(bp->num_sites);
	if (!promise)
		return &drgn_enomem;

	for (size_t i = 0; i < bp->num_sites; i++) {
		struct drgn_breakpoint_site_node *site_node =
			&bp->site_nodes[i];
		struct drgn_breakpoint_site *site = site_node->site;
		if (list_is_singular(&site->enabled_breakpoints)
		    && site->enabled_breakpoints.next == &site_node->node) {
			drgn_breakpoint_site_incref(site);
			promise->sites[promise->num_sites++] = site;
		}
	}

	if (promise->num_sites) {
		struct drgn_program *prog = drgn_breakpoint_program(bp);
		struct drgn_execution_controller *ctrl =
			get_enabled_controller(prog);

		ctrl->ops.disable_breakpoint_sites(ctrl->arg, promise->sites,
						   promise->num_sites,
						   drgn_promise_share(&promise->promise));
		err = wait_for_promise(prog, &promise->promise.promise);
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

	_cleanup_promise_ struct breakpoint_sites_promise *promise =
		breakpoint_sites_promise_create(bp->num_sites);
	if (!promise)
		return &drgn_enomem;

	for (size_t i = 0; i < bp->num_sites; i++) {
		struct drgn_breakpoint_site_node *site_node =
			&bp->site_nodes[i];
		struct drgn_breakpoint_site *site = site_node->site;
		if (list_empty(&site->enabled_breakpoints)) {
			drgn_breakpoint_site_incref(site);
			promise->sites[promise->num_sites++] = site;
		}
	}

	if (promise->num_sites) {
		struct drgn_execution_controller *ctrl =
			get_enabled_controller(prog);

		ctrl->ops.enable_breakpoint_sites(ctrl->arg, promise->sites,
						  promise->num_sites,
						  drgn_promise_share(&promise->promise));
		err = wait_for_promise(prog, &promise->promise.promise);
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
	struct drgn_error *err;
	// A controller can discover that the program exited while attaching or
	// detaching, so we allow it and still emit the event.
	if (prog->attach_state != DRGN_ATTACH_STATE_ATTACHING
	    && prog->attach_state != DRGN_ATTACH_STATE_DETACHING) {
		err = check_attached(prog);
		if (err)
			return err;
	}
	// The DETACHING state takes precedence over EXITED.
	if (prog->attach_state != DRGN_ATTACH_STATE_DETACHING)
		prog->attach_state = DRGN_ATTACH_STATE_EXITED;

	struct drgn_event event = {
		.type = DRGN_EVENT_PROGRAM_EXIT,
		.exit_status = status,
	};
	emit_event(prog, &event);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_notify_program_lost(struct drgn_program *prog, struct drgn_error *_err)
{
	struct drgn_error *err;
	_cleanup_(drgn_error_destroyp) struct drgn_error *event_err = _err;

	// Similar to drgn_notify_program_exit(), the program can be lost while
	// attach or detaching.
	if (prog->attach_state != DRGN_ATTACH_STATE_ATTACHING
	    && prog->attach_state != DRGN_ATTACH_STATE_DETACHING) {
		err = check_attached(prog);
		if (err)
			return err;
	}
	if (prog->attach_state != DRGN_ATTACH_STATE_DETACHING)
		prog->attach_state = DRGN_ATTACH_STATE_LOST;

	struct drgn_event event = {
		.type = DRGN_EVENT_PROGRAM_LOST,
		.err = event_err,
	};
	emit_event(prog, &event);
	return NULL;
}

static struct drgn_error *check_notify_thread_stop(struct drgn_thread *thread)
{
	struct drgn_program *prog = drgn_thread_program(thread);
	if (prog->in_all_stop_ == DRGN_ALL_STOPPED
	    && !prog->bypassing_breakpoint) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT, // TODO: better error code?
					 "thread stop notification while in all-stop");
	}
	if (thread->stop_reason != DRGN_STOP_REASON_NONE) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT, // TODO: better error code?
					 "thread stop notification on stopped thread");
	}
	return NULL;
}

struct all_stop_promise {
	struct drgn_void_promise promise;
	struct drgn_program *prog;
};

static void all_stop_done(struct drgn_promise *p)
{
	struct all_stop_promise *promise =
		container_of(p, struct all_stop_promise, promise.promise);
	struct drgn_program *prog = promise->prog;
	// TODO: what if there's an error?
	prog->in_all_stop_ = DRGN_ALL_STOPPED;
	emit_random_thread_stop_event(prog);
}

static struct drgn_error *
drgn_notify_thread_stop_common(struct drgn_thread *thread)
{
	struct drgn_program *prog = drgn_thread_program(thread);

	move_thread(thread, &prog->stopped_threads);

	if (!prog->all_stop) {
		emit_thread_stop_event(thread);
		return NULL;
	}
	if (prog->in_all_stop_ == DRGN_ALL_STOPPING)
		return NULL;

	struct drgn_execution_controller *ctrl = get_enabled_controller(prog);
	if (!ctrl->ops.stop_all_threads) {
		// TODO: we should check this earlier
		return drgn_error_create(DRGN_ERROR_UNSUPPORTED_OPERATION,
					 "TODO");
	}

	struct all_stop_promise *promise = malloc(sizeof(*promise));
	if (!promise)
		return &drgn_enomem;
	drgn_promise_init(&promise->promise.promise, NULL);
	promise->prog = prog;
	promise->promise.promise.then = all_stop_done;
	prog->in_all_stop_ = DRGN_ALL_STOPPING;
	ctrl->ops.stop_all_threads(ctrl->arg, prog,
				   drgn_promise_share(&promise->promise));
	return NULL;
}

static struct drgn_error *
drgn_notify_thread_breakpoint_impl(struct drgn_thread *thread,
				   struct drgn_breakpoint_site *site)
{
	thread->stop_reason = DRGN_STOP_REASON_BREAKPOINT;
	thread->stop_signal = SIGTRAP;
	drgn_breakpoint_site_incref(site);
	thread->stop_site = site;

	return drgn_notify_thread_stop_common(thread);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_notify_thread_stop(struct drgn_thread *thread, int sig, uint64_t pc,
			uint64_t reason_mask)
{
	struct drgn_error *err = check_notify_thread_stop(thread);
	if (err)
		return err;

	enum drgn_stop_reason stop_reason = DRGN_STOP_REASON_SIGNAL;
	if (sig == SIGTRAP) {
		struct drgn_program *prog = drgn_thread_program(thread);
		if (reason_mask & (1 << DRGN_STOP_REASON_BREAKPOINT)) {
			auto it = drgn_breakpoint_site_table_search(&prog->breakpoint_sites,
								    &pc);
			if (it.entry && drgn_breakpoint_site_enabled(*it.entry)) {
				return drgn_notify_thread_breakpoint_impl(thread,
									  *it.entry);
			}
		}
		if (reason_mask & (1 << DRGN_STOP_REASON_STEP)
		    && thread->stepping) {
			thread->stepping = false;
			if (thread == prog->bypassing_breakpoint)
				return NULL; // TODO
			stop_reason = DRGN_STOP_REASON_STEP;
		}
	}

	thread->stop_reason = stop_reason;
	thread->stop_signal = sig;

	return drgn_notify_thread_stop_common(thread);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_notify_thread_breakpoint(struct drgn_thread *thread,
			      struct drgn_breakpoint_site *site)
{
	struct drgn_error *err = check_notify_thread_stop(thread);
	if (err)
		return err;

	return drgn_notify_thread_breakpoint_impl(thread, site);
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
