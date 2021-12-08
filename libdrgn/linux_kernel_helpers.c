// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "drgn.h"
#include "minmax.h"
#include "platform.h"
#include "program.h"

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

struct drgn_error *
linux_helper_radix_tree_lookup(struct drgn_object *res,
			       const struct drgn_object *root, uint64_t index)
{
	struct drgn_error *err;
	static const uint64_t RADIX_TREE_ENTRY_MASK = 3;
	uint64_t RADIX_TREE_INTERNAL_NODE;
	uint64_t RADIX_TREE_MAP_MASK;
	struct drgn_object node, tmp;
	struct drgn_qualified_type node_type;

	drgn_object_init(&node, drgn_object_program(res));
	drgn_object_init(&tmp, drgn_object_program(res));

	/* node = root->xa_head */
	err = drgn_object_member_dereference(&node, root, "xa_head");
	if (!err) {
		err = drgn_program_find_type(drgn_object_program(res),
					     "struct xa_node *", NULL,
					     &node_type);
		if (err)
			goto out;
		RADIX_TREE_INTERNAL_NODE = 2;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		/* node = (void *)root.rnode */
		err = drgn_object_member_dereference(&node, root, "rnode");
		if (err)
			goto out;
		err = drgn_program_find_type(drgn_object_program(res), "void *",
					     NULL, &node_type);
		if (err)
			goto out;
		err = drgn_object_cast(&node, node_type, &node);
		if (err)
			goto out;
		err = drgn_program_find_type(drgn_object_program(res),
					     "struct radix_tree_node *", NULL,
					     &node_type);
		if (err)
			goto out;
		RADIX_TREE_INTERNAL_NODE = 1;
	} else {
		goto out;
	}

	struct drgn_type_member *member;
	uint64_t member_bit_offset;
	err = drgn_type_find_member(drgn_type_type(node_type.type).type,
				    "slots", &member, &member_bit_offset);
	if (err)
		goto out;
	struct drgn_qualified_type member_type;
	err = drgn_member_type(member, &member_type, NULL);
	if (err)
		goto out;
	if (drgn_type_kind(member_type.type) != DRGN_TYPE_ARRAY) {
		err = drgn_error_create(DRGN_ERROR_TYPE,
					"struct radix_tree_node slots member is not an array");
		goto out;
	}
	RADIX_TREE_MAP_MASK = drgn_type_length(member_type.type) - 1;

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

	struct drgn_qualified_type pidp_type;
	err = drgn_program_find_type(drgn_object_program(res), "struct pid *",
				     NULL, &pidp_type);
	if (err)
		return err;

	struct drgn_qualified_type upid_type;
	err = drgn_program_find_type(drgn_object_program(res), "struct upid",
				     NULL, &upid_type);
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

	struct drgn_object node, tmp;
	drgn_object_init(&node, drgn_object_program(res));
	drgn_object_init(&tmp, drgn_object_program(res));

	err = drgn_object_read(&tmp, ns);
	if (err)
		goto out;
	uint64_t ns_addr;
	err = drgn_object_read_unsigned(&tmp, &ns_addr);
	if (err)
		goto out;
	union drgn_value ns_level;
	err = drgn_object_member_dereference(&tmp, &tmp, "level");
	if (err)
		goto out;
	err = drgn_object_read_integer(&tmp, &ns_level);
	if (err)
		goto out;

	/* i = 1 << pidhash_shift */
	err = drgn_program_find_object(drgn_object_program(res),
				       "pidhash_shift", NULL,
				       DRGN_FIND_OBJECT_ANY, &tmp);
	if (err)
		goto out;
	union drgn_value pidhash_shift;
	err = drgn_object_read_integer(&tmp, &pidhash_shift);
	if (err)
		goto out;
	uint64_t i;
	if (pidhash_shift.uvalue >= 64)
		i = 0;
	else
		i = UINT64_C(1) << pidhash_shift.uvalue;
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
				ns_level.uvalue);
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
