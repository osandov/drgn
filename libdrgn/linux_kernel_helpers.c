// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "drgn.h"
#include "helpers.h"
#include "minmax.h"
#include "platform.h"
#include "program.h"

static const uint64_t RADIX_TREE_ENTRY_MASK = 3;

struct drgn_error *linux_helper_read_vm(struct drgn_program *prog,
					uint64_t pgtable, uint64_t virt_addr,
					void *buf, size_t count)
{
	struct drgn_error *err;
	struct pgtable_iterator *it;
	pgtable_iterator_next_fn *next;
	uint64_t read_addr = 0;
	size_t read_size = 0;

	if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "virtual address translation is only available for the Linux kernel");
	}
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "cannot do virtual address translation without platform");
	}
	if (!prog->platform.arch->linux_kernel_pgtable_iterator_next) {
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					 "virtual address translation is not implemented for %s architecture",
					 prog->platform.arch->name);
	}

	if (!count)
		return NULL;

	if (prog->pgtable_it_in_use) {
		return drgn_error_create_fault("recursive address translation; "
					       "page table may be missing from core dump",
					       virt_addr);
	}

	if (prog->pgtable_it) {
		it = prog->pgtable_it;
	} else {
		it = malloc(sizeof(*it) +
			    prog->platform.arch->pgtable_iterator_arch_size);
		if (!it)
			return &drgn_enomem;
		prog->pgtable_it = it;
		it->prog = prog;
	}
	it->pgtable = pgtable;
	it->virt_addr = virt_addr;
	prog->pgtable_it_in_use = true;
	prog->platform.arch->pgtable_iterator_arch_init(it->arch);
	next = prog->platform.arch->linux_kernel_pgtable_iterator_next;
	do {
		uint64_t virt_addr, start_virt_addr, end_virt_addr;
		uint64_t start_phys_addr, end_phys_addr;
		size_t n;

		virt_addr = it->virt_addr;
		err = next(it, &start_virt_addr, &start_phys_addr);
		if (err)
			break;
		if (start_phys_addr == UINT64_MAX) {
			err = drgn_error_create_fault("address is not mapped",
						      virt_addr);
			break;
		}
		end_virt_addr = it->virt_addr;
		end_phys_addr = start_phys_addr + (end_virt_addr - start_virt_addr);
		n = min(end_virt_addr - virt_addr, (uint64_t)count);
		if (read_size && end_phys_addr == read_addr + read_size) {
			read_size += n;
		} else {
			if (read_size) {
				err = drgn_program_read_memory(prog, buf,
							       read_addr,
							       read_size, true);
				if (err)
					break;
				buf = (char *)buf + read_size;
			}
			read_addr = start_phys_addr + (virt_addr - start_virt_addr);
			read_size = n;
		}
		count -= n;
	} while (count);
	if (!err) {
		err = drgn_program_read_memory(prog, buf, read_addr, read_size,
					       true);
	}
	prog->pgtable_it_in_use = false;
	return err;
}

struct drgn_error *linux_helper_per_cpu_ptr(struct drgn_object *res,
					    const struct drgn_object *ptr,
					    uint64_t cpu)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(ptr);

	struct drgn_object tmp;
	drgn_object_init(&tmp, prog);
	err = drgn_program_find_object(prog, "__per_cpu_offset", NULL,
				       DRGN_FIND_OBJECT_ANY, &tmp);
	if (!err) {
		err = drgn_object_subscript(&tmp, &tmp, cpu);
		if (err)
			goto out;
		union drgn_value per_cpu_offset;
		err = drgn_object_read_integer(&tmp, &per_cpu_offset);
		if (err)
			goto out;

		uint64_t ptr_value;
		err = drgn_object_read_unsigned(ptr, &ptr_value);
		if (err)
			goto out;

		err = drgn_object_set_unsigned(res,
					       drgn_object_qualified_type(ptr),
					       ptr_value + per_cpu_offset.uvalue,
					       0);
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		err = drgn_object_copy(res, ptr);
	}
out:
	drgn_object_deinit(&tmp);
	return err;
}

struct drgn_error *linux_helper_idle_task(struct drgn_object *res, uint64_t cpu)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(res);

	struct drgn_object tmp;
	drgn_object_init(&tmp, prog);
	err = drgn_program_find_object(prog, "runqueues", NULL,
				       DRGN_FIND_OBJECT_ANY, &tmp);
	if (err)
		goto out;
	err = drgn_object_address_of(&tmp, &tmp);
	if (err)
		goto out;
	err = linux_helper_per_cpu_ptr(&tmp, &tmp, cpu);
	if (err)
		goto out;
	err = drgn_object_member_dereference(res, &tmp, "idle");
out:
	drgn_object_deinit(&tmp);
	return err;
}

static struct drgn_error *
radix_tree_init(struct drgn_program *prog, const struct drgn_object *root,
		uint64_t *RADIX_TREE_INTERNAL_NODE_ret,
		uint64_t *RADIX_TREE_MAP_MASK_ret,
		struct drgn_qualified_type *node_type_ret,
		struct drgn_object *node_ret)
{
	struct drgn_error *err =
		drgn_object_member_dereference(node_ret, root, "xa_head");
	/* node = root->xa_head */
	if (!err) {
		err = drgn_program_find_type(prog, "struct xa_node *", NULL,
					     node_type_ret);
		if (err)
			return err;
		*RADIX_TREE_INTERNAL_NODE_ret = 2;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		/* node = (void *)root.rnode */
		err = drgn_object_member_dereference(node_ret, root, "rnode");
		if (err)
			return err;
		err = drgn_program_find_type(prog, "void *", NULL,
					     node_type_ret);
		if (err)
			return err;
		err = drgn_object_cast(node_ret, *node_type_ret, node_ret);
		if (err)
			return err;
		err = drgn_program_find_type(prog, "struct radix_tree_node *",
					     NULL, node_type_ret);
		if (err)
			return err;
		*RADIX_TREE_INTERNAL_NODE_ret = 1;
	} else {
		return err;
	}

	struct drgn_type_member *member;
	uint64_t member_bit_offset;
	err = drgn_type_find_member(drgn_type_type(node_type_ret->type).type,
				    "slots", &member, &member_bit_offset);
	if (err)
		return err;
	struct drgn_qualified_type member_type;
	err = drgn_member_type(member, &member_type, NULL);
	if (err)
		return err;
	if (drgn_type_kind(member_type.type) != DRGN_TYPE_ARRAY)
		return drgn_error_create(
			DRGN_ERROR_TYPE,
			"struct radix_tree_node slots member is not an array");
	*RADIX_TREE_MAP_MASK_ret = drgn_type_length(member_type.type) - 1;
	return NULL;
}

struct drgn_error *
linux_helper_radix_tree_lookup(struct drgn_object *res,
			       const struct drgn_object *root, uint64_t index)
{
	struct drgn_error *err;
	uint64_t RADIX_TREE_INTERNAL_NODE;
	uint64_t RADIX_TREE_MAP_MASK;
	struct drgn_object node, tmp;
	struct drgn_qualified_type node_type;

	drgn_object_init(&node, drgn_object_program(res));
	drgn_object_init(&tmp, drgn_object_program(res));
	err = radix_tree_init(drgn_object_program(root), root,
				  &RADIX_TREE_INTERNAL_NODE, &RADIX_TREE_MAP_MASK,
				  &node_type, &node);
	if (err)
		goto out;

	for (;;) {
		uint64_t value;
		union drgn_value shift;
		uint64_t offset;

		err = drgn_object_read(&node, &node);
		if (err)
			goto out;
		err = drgn_object_read_unsigned(&node, &value);
		if (err)
			goto out;
		if ((value & RADIX_TREE_ENTRY_MASK) != RADIX_TREE_INTERNAL_NODE)
			break;
		err = drgn_object_set_unsigned(&node, node_type,
					       value & ~RADIX_TREE_INTERNAL_NODE,
					       0);
		if (err)
			goto out;
		err = drgn_object_member_dereference(&tmp, &node, "shift");
		if (err)
			goto out;
		err = drgn_object_read_integer(&tmp, &shift);
		if (err)
			goto out;
		if (shift.uvalue >= 64)
			offset = 0;
		else
			offset = (index >> shift.uvalue) & RADIX_TREE_MAP_MASK;
		err = drgn_object_member_dereference(&tmp, &node, "slots");
		if (err)
			goto out;
		err = drgn_object_subscript(&node, &tmp, offset);
		if (err)
			goto out;
	}

	err = drgn_object_copy(res, &node);
out:
	drgn_object_deinit(&tmp);
	drgn_object_deinit(&node);
	return err;
}

struct drgn_error *linux_helper_idr_find(struct drgn_object *res,
					 const struct drgn_object *idr,
					 uint64_t id)
{
	struct drgn_error *err;
	struct drgn_object tmp;

	drgn_object_init(&tmp, drgn_object_program(res));

	/* id -= idr->idr_base */
	err = drgn_object_member_dereference(&tmp, idr, "idr_base");
	if (!err) {
		union drgn_value idr_base;

		err = drgn_object_read_integer(&tmp, &idr_base);
		if (err)
			goto out;
		id -= idr_base.uvalue;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		/* idr_base was added in v4.16. */
		drgn_error_destroy(err);
	} else {
		goto out;
	}

	/* radix_tree_lookup(&idr->idr_rt, id) */
	err = drgn_object_member_dereference(&tmp, idr, "idr_rt");
	if (err)
		goto out;
	err = drgn_object_address_of(&tmp, &tmp);
	if (err)
		goto out;
	err = linux_helper_radix_tree_lookup(res, &tmp, id);
out:
	drgn_object_deinit(&tmp);
	return err;
}

static struct drgn_error *pid_hash_init(struct drgn_program *prog,
					       const struct drgn_object *ns,
					       struct drgn_qualified_type *upid_type_ret,
					       uint64_t *pidhash_length_ret, uint64_t *ns_level_ret)
{
	struct drgn_error *err;
	struct drgn_object ns_level, pidhash_shift;
	drgn_object_init(&ns_level, prog);
	drgn_object_init(&pidhash_shift, prog);
	err = drgn_program_find_type(prog, "struct upid", NULL, upid_type_ret);
	if (err)
		goto out;
	err = drgn_program_find_object(prog, "pidhash_shift", NULL, DRGN_FIND_OBJECT_ANY,
				       &pidhash_shift);
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&pidhash_shift, pidhash_length_ret);
	if (err)
		goto out;
	// *pidhash_length_ret = 1 << pidhash_shift
	*pidhash_length_ret = *pidhash_length_ret >= 64 ? 0 : UINT64_C(1) << *pidhash_length_ret;
	err = drgn_object_member_dereference(&ns_level, ns, "level");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&ns_level, ns_level_ret);
out:
	drgn_object_deinit(&ns_level);
	return err;
}

/*
 * Before Linux kernel commit 95846ecf9dac ("pid: replace pid bitmap
 * implementation with IDR API") (in v4.15), (struct pid_namespace).idr does not
 * exist, so we have to search pid_hash. We could implement pid_hashfn() and
 * only search that bucket, but it's different for 32-bit and 64-bit systems,
 * and it has changed at least once, in v4.7. Searching the whole hash table is
 * slower but foolproof.
 */
static struct drgn_error *
find_pid_in_pid_hash(struct drgn_object *res, const struct drgn_object *ns,
		     const struct drgn_object *pid_hash, uint64_t pid)
{
	struct drgn_error *err;

	struct drgn_object node, tmp;
	drgn_object_init(&node, drgn_object_program(res));
	drgn_object_init(&tmp, drgn_object_program(res));

	err = drgn_object_read(&tmp, ns);
	if (err)
		goto out;
	struct drgn_qualified_type upid_type;
	uint64_t i, ns_level;
	err = pid_hash_init(drgn_object_program(res), &tmp, &upid_type, &i,
				   &ns_level);
	if (err)
		goto out;
	struct drgn_qualified_type pidp_type;
	err = drgn_program_find_type(drgn_object_program(res), "struct pid *", NULL,
					 &pidp_type);
	if (err)
		return err;

	uint64_t ns_addr;
	err = drgn_object_read_unsigned(&tmp, &ns_addr);
	if (err)
		return err;

	struct drgn_type_member *pid_chain_member;
	uint64_t pid_chain_bit_offset;
	err = drgn_type_find_member(upid_type.type, "pid_chain",
				    &pid_chain_member, &pid_chain_bit_offset);
	if (err)
		return err;

	struct drgn_type_member *nr_member;
	uint64_t nr_bit_offset;
	err = drgn_type_find_member(upid_type.type, "nr", &nr_member,
				    &nr_bit_offset);
	if (err)
		return err;
	struct drgn_qualified_type nr_type;
	err = drgn_member_type(nr_member, &nr_type, NULL);
	if (err)
		return err;

	struct drgn_type_member *ns_member;
	uint64_t ns_bit_offset;
	err = drgn_type_find_member(upid_type.type, "ns", &ns_member,
				    &ns_bit_offset);
	if (err)
		return err;
	struct drgn_qualified_type ns_type;
	err = drgn_member_type(ns_member, &ns_type, NULL);
	if (err)
		return err;

	while (i--) {
		/* for (node = pid_hash[i].first; node; node = node->next) */
		err = drgn_object_subscript(&node, pid_hash, i);
		if (err)
			goto out;
		err = drgn_object_member(&node, &node, "first");
		if (err)
			goto out;
		for (;;) {
			uint64_t addr, tmp_addr;
			union drgn_value node_nr;
			uint64_t node_ns;
			char member[64];

			err = drgn_object_read(&node, &node);
			if (err)
				goto out;
			err = drgn_object_read_unsigned(&node, &addr);
			if (err)
				goto out;
			if (!addr)
				break;
			addr -= pid_chain_bit_offset / 8;

			/* tmp = container_of(node, struct upid, pid_chain)->nr */
			tmp_addr = addr + nr_bit_offset / 8;
			err = drgn_object_set_reference(&tmp, nr_type, tmp_addr,
							0, 0);
			if (err)
				goto out;
			err = drgn_object_read_integer(&tmp, &node_nr);
			if (err)
				goto out;
			if (node_nr.uvalue != pid)
				goto next;

			/* tmp = container_of(node, struct upid, pid_chain)->ns */
			tmp_addr = addr + ns_bit_offset / 8;
			err = drgn_object_set_reference(&tmp, ns_type, tmp_addr,
							0, 0);
			if (err)
				goto out;

			err = drgn_object_read_unsigned(&tmp, &node_ns);
			if (err)
				goto out;
			if (node_ns != ns_addr)
				goto next;

			sprintf(member, "numbers[%" PRIu64 "].pid_chain",
				ns_level);
			err = drgn_object_container_of(res, &node,
						       drgn_type_type(pidp_type.type),
						       member);
			goto out;

next:
			err = drgn_object_member_dereference(&node, &node, "next");
			if (err)
				goto out;
		}
	}

	err = drgn_object_set_unsigned(res, pidp_type, 0, 0);
out:
	drgn_object_deinit(&tmp);
	drgn_object_deinit(&node);
	return err;
}

struct drgn_error *linux_helper_find_pid(struct drgn_object *res,
					 const struct drgn_object *ns,
					 uint64_t pid)
{
	struct drgn_error *err;
	struct drgn_object tmp;

	drgn_object_init(&tmp, drgn_object_program(res));

	/* (struct pid *)idr_find(&ns->idr, pid) */
	err = drgn_object_member_dereference(&tmp, ns, "idr");
	if (!err) {
		struct drgn_qualified_type qualified_type;

		err = drgn_object_address_of(&tmp, &tmp);
		if (err)
			goto out;
		err = linux_helper_idr_find(&tmp, &tmp, pid);
		if (err)
			goto out;
		err = drgn_program_find_type(drgn_object_program(res),
					     "struct pid *", NULL,
					     &qualified_type);
		if (err)
			goto out;
		err = drgn_object_cast(res, qualified_type, &tmp);
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		err = drgn_program_find_object(drgn_object_program(res),
					       "pid_hash", NULL,
					       DRGN_FIND_OBJECT_ANY, &tmp);
		if (err)
			goto out;
		err = find_pid_in_pid_hash(res, ns, &tmp, pid);
	}
out:
	drgn_object_deinit(&tmp);
	return err;
}

struct drgn_error *linux_helper_pid_task(struct drgn_object *res,
					 const struct drgn_object *pid,
					 uint64_t pid_type)
{
	struct drgn_error *err;
	struct drgn_qualified_type task_structp_type;
	struct drgn_qualified_type task_struct_type;
	bool truthy;
	struct drgn_object first;
	char member[64];

	drgn_object_init(&first, drgn_object_program(res));

	err = drgn_program_find_type(drgn_object_program(res),
				     "struct task_struct *", NULL,
				     &task_structp_type);
	if (err)
		goto out;
	task_struct_type = drgn_type_type(task_structp_type.type);

	err = drgn_object_bool(pid, &truthy);
	if (err)
		goto out;
	if (!truthy)
		goto null;

	/* first = &pid->tasks[pid_type].first */
	err = drgn_object_member_dereference(&first, pid, "tasks");
	if (err)
		goto out;
	err = drgn_object_subscript(&first, &first, pid_type);
	if (err)
		goto out;
	err = drgn_object_member(&first, &first, "first");
	if (err)
		goto out;

	err = drgn_object_bool(&first, &truthy);
	if (err)
		goto out;
	if (!truthy)
		goto null;

	/* container_of(first, struct task_struct, pid_links[pid_type]) */
	sprintf(member, "pid_links[%" PRIu64 "]", pid_type);
	err = drgn_object_container_of(res, &first, task_struct_type, member);
	if (err && err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		/* container_of(first, struct task_struct, pids[pid_type].node) */
		sprintf(member, "pids[%" PRIu64 "].node", pid_type);
		err = drgn_object_container_of(res, &first, task_struct_type,
					       member);
	}
out:
	drgn_object_deinit(&first);
	return err;

null:
	err = drgn_object_set_unsigned(res, task_structp_type, 0, 0);
	goto out;
}

struct drgn_error *linux_helper_find_task(struct drgn_object *res,
					  const struct drgn_object *ns,
					  uint64_t pid)
{
	struct drgn_error *err;
	struct drgn_object pid_obj;
	struct drgn_object pid_type_obj;
	union drgn_value pid_type;

	drgn_object_init(&pid_obj, drgn_object_program(res));
	drgn_object_init(&pid_type_obj, drgn_object_program(res));

	err = linux_helper_find_pid(&pid_obj, ns, pid);
	if (err)
		goto out;
	err = drgn_program_find_object(drgn_object_program(res), "PIDTYPE_PID",
				       NULL, DRGN_FIND_OBJECT_CONSTANT,
				       &pid_type_obj);
	if (err)
		goto out;
	err = drgn_object_read_integer(&pid_type_obj, &pid_type);
	if (err)
		goto out;
	err = linux_helper_pid_task(res, &pid_obj, pid_type.uvalue);
out:
	drgn_object_deinit(&pid_type_obj);
	drgn_object_deinit(&pid_obj);
	return err;
}

struct linux_helper_radix_tree_iter_frame {
	struct drgn_object slots;
	uint64_t index;
	uint64_t shift;
	uint64_t next_slot;
};

DEFINE_VECTOR_FUNCTIONS(linux_helper_radix_tree_iter_frame_vector)

struct drgn_error *linux_helper_radix_tree_iter_init(struct linux_helper_radix_tree_iter *iter,
						     const struct drgn_object *root)
{
	struct drgn_program *prog = drgn_object_program(root);
	iter->started = false;
	drgn_object_init(&iter->root, prog);
	drgn_object_init(&iter->entry.node, prog);
	iter->entry.index = 0;
	iter->prog = prog;

	struct drgn_error *err =
		radix_tree_init(prog, root, &iter->RADIX_TREE_INTERNAL_NODE,
				&iter->RADIX_TREE_MAP_MASK, &iter->node_type, &iter->root);

	if (err) {
		drgn_object_deinit(&iter->root);
		drgn_object_deinit(&iter->entry.node);
		return err;
	}

	linux_helper_radix_tree_iter_frame_vector_init(&iter->frames);
	return NULL;
}

void linux_helper_radix_tree_iter_deinit(struct linux_helper_radix_tree_iter *iter)
{
	drgn_object_deinit(&iter->root);
	drgn_object_deinit(&iter->entry.node);
	while (iter->frames.size) {
		drgn_object_deinit(
			&linux_helper_radix_tree_iter_frame_vector_pop(&iter->frames)->slots);
	}
	linux_helper_radix_tree_iter_frame_vector_deinit(&iter->frames);
}

static struct drgn_error *radix_tree_iter_handle_node(struct linux_helper_radix_tree_iter *iter,
						      struct drgn_object *_node, uint64_t index,
						      bool *entry_populated_ret)
{
	struct drgn_object *node = &iter->entry.node;
	struct drgn_error *err;
	uint64_t value;

	err = drgn_object_read(node, _node);
	if (err)
		return err;
	err = drgn_object_read_unsigned(node, &value);
	if (err)
		return err;
	if ((value & RADIX_TREE_ENTRY_MASK) != iter->RADIX_TREE_INTERNAL_NODE) {
		// Base-case, node is NOT internal
		if (value) {
			*entry_populated_ret = true;
			iter->entry.index = index;
		}
		return NULL;
	}

	*entry_populated_ret = false;

	// We are dealing with an internal node, and must iterate over its slots

	err = drgn_object_set_unsigned(node, iter->node_type,
				       value & ~iter->RADIX_TREE_INTERNAL_NODE, 0);
	if (err)
		return err;
	struct linux_helper_radix_tree_iter_frame *frame =
		linux_helper_radix_tree_iter_frame_vector_append_entry(&iter->frames);
	if (!frame)
		return &drgn_enomem;
	frame->index = index;
	frame->next_slot = 0;
	drgn_object_init(&frame->slots, iter->prog);
	// We temporarily use `frame->slots` to hold `shift` in order to avoid
	// using another `struct drgn_object`.
	err = drgn_object_member_dereference(&frame->slots, node, "shift");
	if (err)
		goto err_frame;
	err = drgn_object_read_unsigned(&frame->slots, &frame->shift);
	if (err)
		goto err_frame;
	// Now `frame->slots` is actually used for `slots`.
	err = drgn_object_member_dereference(&frame->slots, node, "slots");
	if (err)
		goto err_frame;
	return NULL;

err_frame:
	drgn_object_deinit(&frame->slots);
	linux_helper_radix_tree_iter_frame_vector_pop(&iter->frames);
	return err;
}

struct drgn_error *linux_helper_radix_tree_iter_next(struct linux_helper_radix_tree_iter *iter,
						     struct linux_helper_radix_tree_iter_entry **ret)
{
	bool entry_populated = false;
	struct drgn_error *err = NULL;
	struct drgn_object node;
	drgn_object_init(&node, iter->prog);
	if (!iter->started) {
		iter->started = true;
		err = radix_tree_iter_handle_node(iter, &iter->root, 0, &entry_populated);
	}

	while (!err && !entry_populated && iter->frames.size) {
		struct linux_helper_radix_tree_iter_frame *frame =
			&iter->frames.data[iter->frames.size - 1];
		if (frame->next_slot <= iter->RADIX_TREE_MAP_MASK) {
			err = drgn_object_subscript(&node, &frame->slots, frame->next_slot);
			if (!err)
				err = radix_tree_iter_handle_node(iter, &node,
								  frame->index + (frame->next_slot++
										  << frame->shift),
								  &entry_populated);
		} else {
			drgn_object_deinit(&frame->slots);
			linux_helper_radix_tree_iter_frame_vector_pop(&iter->frames);
		}
	}
	if (!err)
		*ret = entry_populated ? &iter->entry : NULL;
	drgn_object_deinit(&node);
	return err;
}

struct drgn_error *linux_helper_idr_iter_init(struct linux_helper_idr_iter *iter,
					      const struct drgn_object *idr)
{
	struct drgn_error *err;
	struct drgn_object idr_rt, idr_base;
	drgn_object_init(&idr_rt, drgn_object_program(idr));
	drgn_object_init(&idr_base, drgn_object_program(idr));

	err = drgn_object_member(&idr_base, idr, "idr_base");
	if (!err) {
		err = drgn_object_read_unsigned(&idr_base, &iter->base);
		if (err)
			goto out;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		iter->base = 0;
	} else {
		goto out;
	}

	err = drgn_object_member(&idr_rt, idr, "idr_rt");
	if (err)
		goto out;
	err = drgn_object_address_of(&idr_rt, &idr_rt);
	if (err)
		goto out;
	err = linux_helper_radix_tree_iter_init(&iter->iter, &idr_rt);
out:
	drgn_object_deinit(&idr_rt);
	drgn_object_deinit(&idr_base);
	return err;
}

void linux_helper_idr_iter_deinit(struct linux_helper_idr_iter *iter)
{
	linux_helper_radix_tree_iter_deinit(&iter->iter);
}

struct drgn_error *linux_helper_idr_iter_next(struct linux_helper_idr_iter *iter,
					      struct linux_helper_radix_tree_iter_entry **ret)
{
	struct drgn_error *err = linux_helper_radix_tree_iter_next(&iter->iter, ret);
	if (!err && *ret)
		(*ret)->index += iter->base;
	return err;
}

// See `find_pid_in_pid_hash`
static struct drgn_error *pid_iter_init_pid_hash(struct drgn_program *prog,
						 const struct drgn_object *ns,
						 struct linux_helper_pid_iter *iter)
{
	struct drgn_error *err;
	drgn_object_init(&iter->pid_hash, prog);
	drgn_object_init(&iter->pos, prog);
	drgn_object_init(&iter->ns, prog);
	drgn_object_init(&iter->entry, prog);
	err = drgn_program_find_object(prog, "pid_hash", NULL, DRGN_FIND_OBJECT_VARIABLE,
				       &iter->pid_hash);
	if (err)
		goto out;
	struct drgn_qualified_type void_star_type;
	err = drgn_program_find_type(prog, "void *", NULL, &void_star_type);
	if (err)
		goto out;
	err = drgn_object_set_unsigned(&iter->pos, void_star_type, 0, 0);
	if (err)
		goto out;
	err = drgn_object_copy(&iter->ns, ns);
	if (err)
		goto out;
	uint64_t ns_level;
	err = pid_hash_init(prog, ns, &iter->upid_type, &iter->index, &ns_level);
	if (err)
		goto out;
	snprintf(iter->member_specifier, sizeof(iter->member_specifier), "numbers[%" PRIu64 "]",
		 ns_level);
	err = drgn_program_find_type(prog, "struct pid", NULL, &iter->pid_type);
	if (err)
		goto out;
	err = drgn_program_find_type(prog, "struct upid", NULL, &iter->upid_type);
	if (err)
		goto out;
out:
	if (err) {
		drgn_object_deinit(&iter->pid_hash);
		drgn_object_deinit(&iter->pos);
		drgn_object_deinit(&iter->ns);
		drgn_object_deinit(&iter->entry);
	}
	return err;
}

struct drgn_error *linux_helper_pid_iter_init(struct linux_helper_pid_iter *iter,
					      const struct drgn_object *ns)
{
	struct drgn_program *prog = drgn_object_program(ns);
	struct drgn_error *err;
	struct drgn_object idr;
	drgn_object_init(&idr, prog);

	err = drgn_object_member_dereference(&idr, ns, "idr");
	if (!err) {
		iter->has_idr = true;
		err = drgn_program_find_type(prog, "struct pid *", NULL, &iter->pid_type);
		if (!err)
			err = linux_helper_idr_iter_init(&iter->iter, &idr);
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		iter->has_idr = false;
		drgn_error_destroy(err);
		err = pid_iter_init_pid_hash(prog, ns, iter);
	}

	drgn_object_deinit(&idr);
	return err;
}

void linux_helper_pid_iter_deinit(struct linux_helper_pid_iter *iter)
{
	if (iter->has_idr) {
		linux_helper_idr_iter_deinit(&iter->iter);
	} else {
		drgn_object_deinit(&iter->pid_hash);
		drgn_object_deinit(&iter->pos);
		drgn_object_deinit(&iter->ns);
		drgn_object_deinit(&iter->entry);
	}
}

struct drgn_error *linux_helper_pid_iter_next(struct linux_helper_pid_iter *iter,
					      struct drgn_object **ret)
{
	if (iter->has_idr) {
		struct linux_helper_radix_tree_iter_entry *entry;
		struct drgn_error *err = linux_helper_idr_iter_next(&iter->iter, &entry);
		if (err)
			return err;
		if (!entry) {
			*ret = NULL;
			return NULL;
		}
		err = drgn_object_cast(&entry->node, iter->pid_type, &entry->node);
		if (!err)
			*ret = &entry->node;
		return err;
	}

	struct drgn_error *err = NULL;
	struct drgn_object upid, upid_ns;
	drgn_object_init(&upid, drgn_object_program(&iter->ns));
	drgn_object_init(&upid_ns, drgn_object_program(&iter->ns));

	for (;;) {
		for (;;) {
			bool is_truthy;
			err = drgn_object_bool(&iter->pos, &is_truthy);
			if (err)
				goto out;
			if (is_truthy)
				break;
			if (iter->index == 0) {
				*ret = NULL;
				goto out;
			}
			err = drgn_object_subscript(&iter->pos, &iter->pid_hash, --iter->index);
			if (err)
				goto out;
			err = drgn_object_member(&iter->pos, &iter->pos, "first");
			if (err)
				goto out;
			err = drgn_object_bool(&iter->pos, &is_truthy);
			if (err)
				goto out;
		}
		err = drgn_object_container_of(&upid, &iter->pos, iter->upid_type, "pid_chain");
		if (err)
			goto out;
		err = drgn_object_member_dereference(&iter->pos, &iter->pos, "next");
		if (err)
			goto out;
		err = drgn_object_member_dereference(&upid_ns, &upid, "ns");
		if (err)
			goto out;
		int ns_cmp_result;
		err = drgn_object_cmp(&upid_ns, &iter->ns, &ns_cmp_result);
		if (err)
			goto out;
		if (ns_cmp_result == 0) {
			err = drgn_object_container_of(&iter->entry, &upid, iter->pid_type,
						       iter->member_specifier);
			if (!err)
				*ret = &iter->entry;
			goto out;
		}
	}

out:
	drgn_object_deinit(&upid);
	drgn_object_deinit(&upid_ns);
	return err;
}

struct drgn_error *linux_helper_task_iter_init(struct linux_helper_task_iter *iter,
					       const struct drgn_object *ns)
{
	struct drgn_program *prog = drgn_object_program(ns);
	struct drgn_error *err = linux_helper_pid_iter_init(&iter->iter, ns);
	if (err)
		return err;
	struct drgn_object PIDTYPE_PID;
	drgn_object_init(&PIDTYPE_PID, prog);
	err = drgn_program_find_object(prog, "PIDTYPE_PID", NULL, DRGN_FIND_OBJECT_CONSTANT,
				       &PIDTYPE_PID);
	if (!err)
		err = drgn_object_read_unsigned(&PIDTYPE_PID, &iter->PIDTYPE_PID);
	if (err)
		linux_helper_pid_iter_deinit(&iter->iter);
	drgn_object_deinit(&PIDTYPE_PID);
	return err;
}

struct drgn_error *linux_helper_task_iter_next(struct linux_helper_task_iter *iter,
					       struct drgn_object **ret)
{
	struct drgn_error *err;
	bool value_is_truthy;
	do {
		err = linux_helper_pid_iter_next(&iter->iter, ret);
		if (err || !*ret)
			return err;
		err = linux_helper_pid_task(*ret, *ret, iter->PIDTYPE_PID);
		if (err)
			return err;
		err = drgn_object_bool(*ret, &value_is_truthy);
	} while (!err && !value_is_truthy);
	return err;
}

void linux_helper_task_iter_deinit(struct linux_helper_task_iter *iter)
{
	linux_helper_pid_iter_deinit(&iter->iter);
}
