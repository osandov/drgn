// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdlib.h>

#include "program.h"
#include "thread.h"
#include "util.h"

struct drgn_thread_key {
	uint32_t tid;
	uint64_t generation;
};

static struct drgn_thread_key drgn_thread_key(struct drgn_thread * const *thread)
{
	return (struct drgn_thread_key){ (*thread)->tid, (*thread)->generation };
}

static struct hash_pair drgn_thread_key_hash(const struct drgn_thread_key *key)
{
	return hash_pair_from_avalanching_hash(hash_combine(key->tid, key->generation));
}

static bool drgn_thread_key_eq(const struct drgn_thread_key *a,
			       const struct drgn_thread_key *b)
{
	return a->tid == b->tid && a->generation == b->generation;
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_thread_set, drgn_thread_key,
			    drgn_thread_key_hash, drgn_thread_key_eq);

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_object(struct drgn_thread *thread, const struct drgn_object **ret)
{
	struct drgn_error *err;
	if (!thread->have_object) {
		if (!thread->finder->ops.thread_object) {
			return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						 "thread object is not defined in this program");
		}
		err = thread->finder->ops.thread_object(thread->finder->arg,
							thread,
							&thread->object);
		if (err)
			return err;
		thread->have_object = true;
	}
	*ret = &thread->object;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *drgn_thread_name(struct drgn_thread *thread,
						   char **ret)
{
	struct drgn_error *err;
	if (thread->finder->ops.thread_name) {
		err = thread->finder->ops.thread_name(thread->finder->arg,
						      thread, ret);
		if (err)
			return err;
	} else {
		*ret = NULL;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_register_state(struct drgn_thread *thread,
			   struct drgn_register_state **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_thread_program(thread);
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program architecture is not known");
	}
	drgn_handler_list_for_each_enabled(struct drgn_register_state_finder,
					   finder,
					   &prog->register_state_finders) {
		struct drgn_register_state *regs;
		err = finder->ops.thread_register_state(finder->arg, thread,
							&regs);
		if (err)
			return err;
		if (regs) {
			*ret = regs;
			return NULL;
		}
	}
	*ret = NULL;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_iterator_create(struct drgn_program *prog,
			    struct drgn_thread_iterator **ret)
{
	struct drgn_thread_finder *finder =
		drgn_handler_list_first_enabled(&prog->thread_finders);
	if (!finder || !finder->ops.iterator_next) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "can't iterate threads in this program");
	}
	struct drgn_error *err;
	struct drgn_thread_iterator *it = malloc(sizeof(*it));
	if (!it)
		return &drgn_enomem;
	it->finder = finder;
	if (finder->ops.iterator_create) {
		err = finder->ops.iterator_create(finder->arg, &finder->cache, &it->data);
		if (err) {
			free(it);
			return err;
		}
	} else {
		it->data = NULL;
	}
	*ret = it;
	return NULL;
}

LIBDRGN_PUBLIC void
drgn_thread_iterator_destroy(struct drgn_thread_iterator *it)
{
	if (!it)
		return;
	struct drgn_thread_finder *finder = it->finder;
	if (finder->ops.iterator_destroy)
		finder->ops.iterator_destroy(it->data);
	free(it);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_iterator_next(struct drgn_thread_iterator *it,
			  struct drgn_thread **ret)
{
	struct drgn_thread_finder *finder = it->finder;
	return finder->ops.iterator_next(finder->arg, &finder->cache, it->data,
					 ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_thread(struct drgn_program *prog, uint32_t tid,
			 struct drgn_thread **ret)
{
	struct drgn_thread_finder *finder =
		drgn_handler_list_first_enabled(&prog->thread_finders);
	if (!finder || !finder->ops.find_thread) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "can't find threads in this program");
	}
	return finder->ops.find_thread(finder->arg, &finder->cache, tid, ret);
}

LIBDRGN_PUBLIC
struct drgn_error *drgn_thread_from_object(const struct drgn_object *obj,
					   struct drgn_thread **ret)
{
	struct drgn_program *prog = drgn_object_program(obj);
	struct drgn_thread_finder *finder =
		drgn_handler_list_first_enabled(&prog->thread_finders);
	if (!finder || !finder->ops.thread_from_object) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "can't get thread from object in this program");
	}
	return finder->ops.thread_from_object(finder->arg, &finder->cache, obj,
					      ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_main_thread(struct drgn_program *prog, struct drgn_thread **ret)
{
	struct drgn_thread_finder *finder =
		drgn_handler_list_first_enabled(&prog->thread_finders);
	if (!finder || !finder->ops.main_thread) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "main thread is not defined in this program");
	}
	return finder->ops.main_thread(finder->arg, &finder->cache, ret);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_crashed_thread(struct drgn_program *prog, struct drgn_thread **ret)
{
	struct drgn_thread_finder *finder =
		drgn_handler_list_first_enabled(&prog->thread_finders);
	if (!finder || !finder->ops.crashed_thread) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "crashed thread is not defined in this program");
	}
	return finder->ops.crashed_thread(finder->arg, &finder->cache, ret);
}

LIBDRGN_PUBLIC struct drgn_program *
drgn_thread_cache_program(const struct drgn_thread_cache *cache)
{
	return cache->prog;
}

LIBDRGN_PUBLIC
struct drgn_thread *drgn_thread_cache_find(struct drgn_thread_cache *cache,
					   uint32_t tid, uint64_t generation)
{
	const struct drgn_thread_key key = { tid, generation };
	struct drgn_thread_set_iterator it =
		drgn_thread_set_search(&cache->threads, &key);
	if (!it.entry)
		return NULL;
	drgn_thread_incref(*it.entry);
	return *it.entry;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_thread_cache_find_or_create(struct drgn_thread_cache *cache, uint32_t tid,
				 uint64_t generation,
				 const struct drgn_object *object,
				 struct drgn_thread **ret, bool *new_ret)
{
	struct drgn_error *err;
	struct drgn_thread_finder *finder =
		container_of(cache, struct drgn_thread_finder, cache);

	const struct drgn_thread_key key = { tid, generation };
	struct hash_pair hp = drgn_thread_set_hash(&key);
	struct drgn_thread_set_iterator it =
		drgn_thread_set_search_hashed(&cache->threads, &key, hp);
	if (it.entry) {
		drgn_thread_incref(*it.entry);
		*ret = *it.entry;
		if (new_ret)
			*new_ret = false;
		return NULL;
	}

	struct drgn_thread *thread = drgn_thread_alloc(cache->prog);
	if (!thread)
		return &drgn_enomem;
	thread->tid = tid;
	thread->generation = generation;
	thread->finder = finder;
	if (object) {
		err = drgn_object_copy(&thread->object, object);
		if (err) {
			drgn_thread_decref(thread);
			return err;
		}
		thread->have_object = true;
	}

	if (drgn_thread_set_insert_searched(&cache->threads, &thread, hp,
					    NULL) < 0) {
		drgn_thread_decref(thread);
		return &drgn_enomem;
	}
	*ret = thread;
	if (new_ret)
		*new_ret = true;
	return NULL;
}

void drgn_thread_deinit(struct drgn_thread *thread)
{
	drgn_thread_set_delete_entry(&thread->finder->cache.threads, &thread);
	if (thread->finder_data && thread->finder->ops.thread_data_destroy)
		thread->finder->ops.thread_data_destroy(thread->finder_data);
	drgn_object_deinit(&thread->object);
}

LIBDRGN_PUBLIC
void *drgn_thread_get_finder_data(const struct drgn_thread *thread)
{
	return thread->finder_data;
}

LIBDRGN_PUBLIC
void drgn_thread_set_finder_data(struct drgn_thread *thread, void *data)
{
	// Use a temporary variable like Py_CLEAR() does so that the object
	// remains consistent.
	void *old_data = thread->finder_data;
	thread->finder_data = data;
	if (old_data && thread->finder->ops.thread_data_destroy)
		thread->finder->ops.thread_data_destroy(old_data);
}

struct drgn_error *
drgn_register_state_finder_init(struct drgn_program *prog,
				struct drgn_register_state_finder *finder)
{
	if (!finder->ops.thread_register_state) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "drgn_register_state_finder_ops::thread_register_state is required");
	}
	return NULL;
}

struct drgn_error *drgn_thread_finder_init(struct drgn_program *prog,
					   struct drgn_thread_finder *finder)
{
	if (!finder->ops.iterator_next
	    && !finder->ops.find_thread
	    && !finder->ops.thread_from_object
	    && !finder->ops.main_thread
	    && !finder->ops.crashed_thread) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "at least one of iterator_next, "
					 "find_thread, thread_from_object, "
					 "main_thread, or crashed_thread "
					 "is required in drgn_thread_finder_ops");
	}
	finder->cache.prog = prog;
	drgn_thread_set_init(&finder->cache.threads);
	return NULL;
}

void drgn_thread_finder_deinit(struct drgn_thread_finder *finder)
{
	drgn_thread_set_deinit(&finder->cache.threads);
}
