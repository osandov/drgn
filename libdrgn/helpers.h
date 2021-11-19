// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Helpers implemented in C.
 *
 * Most drgn helpers are implemented in Python. However, there are a few that we
 * need internally in libdrgn, so they are implemented in C, instead.
 */

#ifndef DRGN_HELPERS_H
#define DRGN_HELPERS_H

#include <stddef.h>
#include <stdint.h>

#include "drgn.h"

struct drgn_object;
struct drgn_program;

struct drgn_error *linux_helper_read_vm(struct drgn_program *prog,
					uint64_t pgtable, uint64_t virt_addr,
					void *buf, size_t count);

struct drgn_error *linux_helper_per_cpu_ptr(struct drgn_object *res,
					    const struct drgn_object *ptr,
					    uint64_t cpu);

struct drgn_error *linux_helper_idle_task(struct drgn_object *res,
					  uint64_t cpu);

struct drgn_error *
linux_helper_radix_tree_lookup(struct drgn_object *res,
			       const struct drgn_object *root, uint64_t index);

struct drgn_error *linux_helper_idr_find(struct drgn_object *res,
					 const struct drgn_object *idr,
					 uint64_t id);

struct drgn_error *linux_helper_find_pid(struct drgn_object *res,
					 const struct drgn_object *ns,
					 uint64_t pid);

struct drgn_error *linux_helper_pid_task(struct drgn_object *res,
					 const struct drgn_object *pid,
					 uint64_t pid_type);

struct drgn_error *linux_helper_find_task(struct drgn_object *res,
					  const struct drgn_object *ns,
					  uint64_t pid);

struct linux_helper_task_iterator {
	struct drgn_object task;
	struct drgn_qualified_type task_struct_type;
	uint64_t init_task_address;
	uint64_t thread_group_address;
	bool done;
};

struct drgn_error *
linux_helper_task_iterator_init(struct linux_helper_task_iterator *it,
				struct drgn_program *prog);

void linux_helper_task_iterator_deinit(struct linux_helper_task_iterator *it);

/**
 * Get the next task from a @ref linux_helper_task_iterator.
 *
 * @param[out] ret Returned `struct task_struct *` object. This is valid until
 * the next call to this function on the same @p it or until @p it is destroyed.
 */
struct drgn_error *
linux_helper_task_iterator_next(struct linux_helper_task_iterator *it,
				const struct drgn_object **ret);

#endif /* DRGN_HELPERS_H */
