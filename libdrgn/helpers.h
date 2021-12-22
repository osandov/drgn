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
#include "vector.h"

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

/**
 * Iterator convention:
 *
 * For all of the iterators defined below, the convention for each of the
 * `*_next` functions is that upon returning, `*ret` will point to space
 * allocated inside of `iter`. The caller is free to do what they wish with
 * this return value, but should note that it will be overwritten the next time
 * the `*_next` function is called.
 */

DEFINE_VECTOR_TYPE(linux_helper_radix_tree_iter_frame_vector,
		   struct linux_helper_radix_tree_iter_frame)

struct linux_helper_radix_tree_iter_entry {
	uint64_t index;
	struct drgn_object node;
};

struct linux_helper_radix_tree_iter {
	bool started;
	struct drgn_object root;
	// Current value to be yielded
	struct linux_helper_radix_tree_iter_entry entry;
	// We need this for later initialization of `drgn_object`s
	struct drgn_program *prog;
	// Frames to keep track of generator state
	struct linux_helper_radix_tree_iter_frame_vector frames;
	// One-time setup values that are persistent
	uint64_t RADIX_TREE_INTERNAL_NODE;
	uint64_t RADIX_TREE_MAP_MASK;
	struct drgn_qualified_type node_type;
};

struct drgn_error *linux_helper_radix_tree_iter_init(struct linux_helper_radix_tree_iter *iter,
						     const struct drgn_object *root);

void linux_helper_radix_tree_iter_deinit(struct linux_helper_radix_tree_iter *iter);

struct drgn_error *linux_helper_radix_tree_iter_next(struct linux_helper_radix_tree_iter *iter,
						     struct linux_helper_radix_tree_iter_entry **ret);

struct linux_helper_idr_iter {
	struct linux_helper_radix_tree_iter iter;
	uint64_t base;
};

struct drgn_error *linux_helper_idr_iter_init(struct linux_helper_idr_iter *iter,
					      const struct drgn_object *idr);

void linux_helper_idr_iter_deinit(struct linux_helper_idr_iter *iter);

struct drgn_error *linux_helper_idr_iter_next(struct linux_helper_idr_iter *iter,
					      struct linux_helper_radix_tree_iter_entry **ret);

struct linux_helper_pid_iter {
	bool has_idr;
	struct drgn_qualified_type pid_type;
	union {
		// if has_idr
		struct linux_helper_idr_iter iter;
		// else
		struct {
			struct drgn_qualified_type upid_type;
			struct drgn_object pid_hash;
			struct drgn_object pos; // a `struct hlist_node*`
			struct drgn_object ns;
			struct drgn_object entry; // Current value of the iterator
			size_t index; // Current loop index
			char member_specifier[sizeof("numbers[]") + 20];
			// 20 = maximum length of a uint64_t as a string
			// Space for the null terminator is included as part of the sizeof on the string literal
		};
	};
};

struct drgn_error *linux_helper_pid_iter_init(struct linux_helper_pid_iter *iter,
					      const struct drgn_object *ns);

void linux_helper_pid_iter_deinit(struct linux_helper_pid_iter *iter);

struct drgn_error *linux_helper_pid_iter_next(struct linux_helper_pid_iter *iter,
					      struct drgn_object **ret);

struct linux_helper_task_iter {
	struct linux_helper_pid_iter iter;
	uint64_t PIDTYPE_PID;
};

struct drgn_error *linux_helper_task_iter_init(struct linux_helper_task_iter *iter,
					       const struct drgn_object *ns);

void linux_helper_task_iter_deinit(struct linux_helper_task_iter *iter);

struct drgn_error *linux_helper_task_iter_next(struct linux_helper_task_iter *iter,
					       struct drgn_object **ret);

#endif /* DRGN_HELPERS_H */
