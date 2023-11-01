// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <inttypes.h>
#include <stdio.h>

#include "drgn.h"
#include "helpers.h"
#include "minmax.h"
#include "platform.h"
#include "program.h"
#include "util.h"

static void end_virtual_address_translation(struct drgn_program *prog)
{
	prog->in_address_translation = false;
}

static struct drgn_error *
begin_virtual_address_translation(struct drgn_program *prog, uint64_t pgtable,
				  uint64_t virt_addr)
{
	struct drgn_error *err;

	if (prog->in_address_translation) {
		return drgn_error_create_fault("recursive address translation; "
					       "page table may be missing from core dump",
					       virt_addr);
	}
	prog->in_address_translation = true;
	if (!prog->pgtable_it) {
		if (!(prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)) {
			err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						"virtual address translation is only available for the Linux kernel");
			goto err;
		}
		if (!prog->has_platform) {
			err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
						"cannot do virtual address translation without platform");
			goto err;
		}
		if (!prog->platform.arch->linux_kernel_pgtable_iterator_next) {
			err = drgn_error_format(DRGN_ERROR_NOT_IMPLEMENTED,
						"virtual address translation is not implemented for %s architecture",
						prog->platform.arch->name);
			goto err;
		}
		err = prog->platform.arch->linux_kernel_pgtable_iterator_create(prog,
										&prog->pgtable_it);
		if (err) {
			prog->pgtable_it = NULL;
			goto err;
		}
	}
	prog->pgtable_it->pgtable = pgtable;
	prog->pgtable_it->virt_addr = virt_addr;
	prog->platform.arch->linux_kernel_pgtable_iterator_init(prog, prog->pgtable_it);
	return NULL;

err:
	end_virtual_address_translation(prog);
	return err;
}

struct drgn_error *linux_helper_direct_mapping_offset(struct drgn_program *prog,
						      uint64_t *ret)
{
	struct drgn_error *err;

	if (prog->direct_mapping_offset_cached) {
		*ret = prog->direct_mapping_offset;
		return NULL;
	}

	// The direct mapping offset can vary depending on architecture, kernel
	// version, configuration options, and KASLR. Rather than dealing with
	// all of that, get a virtual address in the direct mapping and
	// translate it to a physical address via the page table. The difference
	// is the offset.
	//
	// The virtual address we pick doesn't matter as long as:
	//
	// 1. It is in the direct mapping on all configurations of all supported
	//    kernel versions on all architectures.
	// 2. That is unlikely to change in the future.
	//
	// This is our current arbitrary choice.
	static const char direct_mapping_variable[] = "saved_command_line";

	struct drgn_object tmp;
	drgn_object_init(&tmp, prog);
	err = drgn_program_find_object(prog, direct_mapping_variable, NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &tmp);
	uint64_t virt_addr;
	if (!err) {
		err = drgn_object_read_unsigned(&tmp, &virt_addr);
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		// Avoid a confusing error message with our arbitrary variable
		// name.
		drgn_error_destroy(err);
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"could not find variable in direct mapping");
	}
	drgn_object_deinit(&tmp);
	if (err)
		return err;

	err = begin_virtual_address_translation(prog,
						prog->vmcoreinfo.swapper_pg_dir,
						virt_addr);
	if (err)
		return err;
	uint64_t start_virt_addr, start_phys_addr;
	err = prog->platform.arch->linux_kernel_pgtable_iterator_next(prog,
								      prog->pgtable_it,
								      &start_virt_addr,
								      &start_phys_addr);
	if (err)
		goto out;
	if (start_phys_addr == UINT64_MAX) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"could not determine direct mapping offset");
		goto out;
	}
	prog->direct_mapping_offset = start_virt_addr - start_phys_addr;
	prog->direct_mapping_offset_cached = true;
	*ret = prog->direct_mapping_offset;
	err = NULL;
out:
	end_virtual_address_translation(prog);
	return err;
}

struct drgn_error *linux_helper_read_vm(struct drgn_program *prog,
					uint64_t pgtable, uint64_t virt_addr,
					void *buf, size_t count)
{
	struct drgn_error *err;

	err = begin_virtual_address_translation(prog, pgtable, virt_addr);
	if (err)
		return err;
	if (!count) {
		err = NULL;
		goto out;
	}

	struct pgtable_iterator *it = prog->pgtable_it;
	pgtable_iterator_next_fn *next =
		prog->platform.arch->linux_kernel_pgtable_iterator_next;
	uint64_t read_addr = 0;
	size_t read_size = 0;
	do {
		uint64_t start_virt_addr, start_phys_addr;
		err = next(prog, it, &start_virt_addr, &start_phys_addr);
		if (err)
			break;
		if (start_phys_addr == UINT64_MAX) {
			err = drgn_error_create_fault("address is not mapped",
						      virt_addr);
			break;
		}

		uint64_t phys_addr =
			start_phys_addr + (virt_addr - start_virt_addr);
		size_t n = min(it->virt_addr - virt_addr, (uint64_t)count);
		if (read_size && phys_addr == read_addr + read_size) {
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
			read_addr = phys_addr;
			read_size = n;
		}
		virt_addr = it->virt_addr;
		count -= n;
	} while (count);
	if (!err) {
		err = drgn_program_read_memory(prog, buf, read_addr, read_size,
					       true);
	}
out:
	end_virtual_address_translation(prog);
	return err;
}

struct drgn_error *linux_helper_follow_phys(struct drgn_program *prog,
					    uint64_t pgtable,
					    uint64_t virt_addr, uint64_t *ret)
{
	struct drgn_error *err;

	err = begin_virtual_address_translation(prog, pgtable, virt_addr);
	if (err)
		return err;

	struct pgtable_iterator *it = prog->pgtable_it;
	pgtable_iterator_next_fn *next =
		prog->platform.arch->linux_kernel_pgtable_iterator_next;
	uint64_t start_virt_addr, start_phys_addr;
	err = next(prog, it, &start_virt_addr, &start_phys_addr);
	if (err)
		goto out;
	if (start_phys_addr == UINT64_MAX) {
		err = drgn_error_create_fault("address is not mapped",
					      virt_addr);
		goto out;
	}
	*ret = start_phys_addr + (virt_addr - start_virt_addr);
	err = NULL;
out:
	end_virtual_address_translation(prog);
	return err;
}

struct drgn_error *linux_helper_per_cpu_ptr(struct drgn_object *res,
					    const struct drgn_object *ptr,
					    uint64_t cpu)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(ptr);

	DRGN_OBJECT(tmp, prog);
	err = drgn_program_find_object(prog, "__per_cpu_offset", NULL,
				       DRGN_FIND_OBJECT_ANY, &tmp);
	if (!err) {
		err = drgn_object_subscript(&tmp, &tmp, cpu);
		if (err)
			return err;
		union drgn_value per_cpu_offset;
		err = drgn_object_read_integer(&tmp, &per_cpu_offset);
		if (err)
			return err;

		uint64_t ptr_value;
		err = drgn_object_read_unsigned(ptr, &ptr_value);
		if (err)
			return err;

		return drgn_object_set_unsigned(res,
						drgn_object_qualified_type(ptr),
						ptr_value + per_cpu_offset.uvalue,
						0);
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		return drgn_object_copy(res, ptr);
	} else {
		return err;
	}
}

static struct drgn_error *cpu_rq_member(struct drgn_object *res, uint64_t cpu,
					const char *member_name)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(res);

	DRGN_OBJECT(tmp, prog);
	err = drgn_program_find_object(prog, "runqueues", NULL,
				       DRGN_FIND_OBJECT_ANY, &tmp);
	if (err)
		return err;
	err = drgn_object_address_of(&tmp, &tmp);
	if (err)
		return err;
	err = linux_helper_per_cpu_ptr(&tmp, &tmp, cpu);
	if (err)
		return err;
	err = drgn_object_member_dereference(&tmp, &tmp, member_name);
	if (err)
		return err;
	return drgn_object_read(res, &tmp);
}

struct drgn_error *linux_helper_cpu_curr(struct drgn_object *res, uint64_t cpu)
{
	return cpu_rq_member(res, cpu, "curr");
}

struct drgn_error *linux_helper_idle_task(struct drgn_object *res, uint64_t cpu)
{
	return cpu_rq_member(res, cpu, "idle");
}

struct drgn_error *linux_helper_task_cpu(const struct drgn_object *task,
					 uint64_t *ret)
{
	struct drgn_error *err;
	DRGN_OBJECT(tmp, drgn_object_program(task));

	// If CONFIG_THREAD_INFO_IN_TASK=y and since Linux kernel commit
	// bcf9033e5449 ("sched: move CPU field back into thread_info if
	// THREAD_INFO_IN_TASK=y") (in v5.16), the CPU is task->thread_info.cpu.
	//
	// If CONFIG_THREAD_INFO_IN_TASK=y but before that commit, the cpu is
	// task->cpu.
	//
	// If CONFIG_THREAD_INFO_IN_TASK=n or before Linux kernel commit
	// c65eacbe290b ("sched/core: Allow putting thread_info into
	// task_struct") (in v4.9), the CPU is
	// ((struct thread_info *)task->stack)->cpu.
	//
	// If none of those exist, then the kernel must be !SMP.
	err = drgn_object_member_dereference(&tmp, task, "thread_info");
	if (!err) {
		err = drgn_object_member(&tmp, &tmp, "cpu");
		if (err && err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			err = drgn_object_member_dereference(&tmp, task, "cpu");
		}
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		// CONFIG_THREAD_INFO_IN_TASK=n
		drgn_error_destroy(err);
		err = drgn_object_member_dereference(&tmp, task, "stack");
		if (err)
			return err;
		struct drgn_qualified_type thread_info_type;
		err = drgn_program_find_type(drgn_object_program(task),
					     "struct thread_info *", NULL,
					     &thread_info_type);
		if (err)
			return err;
		err = drgn_object_cast(&tmp, thread_info_type, &tmp);
		if (err)
			return err;
		err = drgn_object_member_dereference(&tmp, &tmp, "cpu");
	}
	if (!err) {
		union drgn_value value;
		err = drgn_object_read_integer(&tmp, &value);
		if (!err)
			*ret = value.uvalue;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		// CONFIG_SMP=n
		drgn_error_destroy(err);
		*ret = 0;
		err = NULL;
	}
	return err;
}

struct drgn_error *
linux_helper_xa_load(struct drgn_object *res,
		     const struct drgn_object *xa, uint64_t index)
{
	struct drgn_error *err;

	struct drgn_qualified_type node_type;
	uint64_t internal_flag, node_min;

	DRGN_OBJECT(entry, drgn_object_program(res));
	DRGN_OBJECT(node, drgn_object_program(res));
	DRGN_OBJECT(tmp, drgn_object_program(res));

	// See xa_for_each() in drgn/helpers/linux/xarray.py for a description
	// of the cases we have to handle.
	// entry = xa->xa_head
	err = drgn_object_member_dereference(&entry, xa, "xa_head");
	if (!err) {
		err = drgn_object_read(&entry, &entry);
		if (err)
			return err;
		// node_type = struct xa_node *
		err = drgn_program_find_type(drgn_object_program(res),
					     "struct xa_node *", NULL,
					     &node_type);
		if (err)
			return err;
		internal_flag = 2;
		node_min = 4097;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		// entry = (void *)xa->rnode
		err = drgn_object_member_dereference(&entry, xa, "rnode");
		if (err)
			return err;
		// node_type = typeof(xa->rnode)
		node_type = drgn_object_qualified_type(&entry);
		struct drgn_qualified_type voidp_type;
		err = drgn_program_find_type(drgn_object_program(res), "void *",
					     NULL, &voidp_type);
		if (err)
			return err;
		err = drgn_object_cast(&entry, voidp_type, &entry);
		if (err)
			return err;
		internal_flag = 1;
		node_min = 0;
	} else {
		return err;
	}

	// xa_is_node() or radix_tree_is_internal_node()
#define is_node(entry_value) \
	(((entry_value) & 3) == internal_flag && (entry_value) >= node_min)

	struct drgn_type_member *member;
	uint64_t member_bit_offset;
	err = drgn_type_find_member(drgn_type_type(node_type.type).type,
				    "slots", &member, &member_bit_offset);
	if (err)
		return err;
	struct drgn_qualified_type member_type;
	err = drgn_member_type(member, &member_type, NULL);
	if (err)
		return err;
	if (drgn_type_kind(member_type.type) != DRGN_TYPE_ARRAY) {
		return drgn_error_create(DRGN_ERROR_TYPE,
					 "struct xa_node slots member is not an array");
	}
	uint64_t XA_CHUNK_MASK = drgn_type_length(member_type.type) - 1;
	uint64_t sizeof_slots;
	if (node_min == 0) { // !xarray
		err = drgn_type_sizeof(member_type.type, &sizeof_slots);
		if (err)
			return err;
	}

	uint64_t entry_value;
	err = drgn_object_read_unsigned(&entry, &entry_value);
	if (err)
		return err;
	if (is_node(entry_value)) {
		// node = xa_to_node(entry)
		// or
		// node = entry_to_node(entry)
		err = drgn_object_set_unsigned(&node, node_type,
					       entry_value - internal_flag, 0);
		if (err)
			return err;
		// node_shift = node->shift
		err = drgn_object_member_dereference(&tmp, &node, "shift");
		if (err)
			return err;
		union drgn_value node_shift;
		err = drgn_object_read_integer(&tmp, &node_shift);
		if (err)
			return err;

		uint64_t offset;
		if (node_shift.uvalue >= 64) // Avoid undefined behavior.
			offset = 0;
		else
			offset = index >> node_shift.uvalue;
		if (offset > XA_CHUNK_MASK)
			goto null;

		for (;;) {
			// entry = node->slots[offset]
			err = drgn_object_member_dereference(&tmp, &node,
							     "slots");
			if (err)
				return err;
			err = drgn_object_subscript(&entry, &tmp, offset);
			if (err)
				return err;
			err = drgn_object_read(&entry, &entry);
			if (err)
				return err;
			err = drgn_object_read_unsigned(&entry, &entry_value);
			if (err)
				return err;

			if ((entry_value & 3) == internal_flag) {
				if (node_min != 0 && // xarray
				    entry_value < 256) { // xa_is_sibling()
					// entry = node->slots[xa_to_sibling(entry)]
					err = drgn_object_subscript(&entry,
								    &tmp,
								    entry_value >> 2);
					if (err)
						return err;
					err = drgn_object_read(&entry, &entry);
					if (err)
						return err;
					err = drgn_object_read_unsigned(&entry,
									&entry_value);
					if (err)
						return err;
				} else if (node_min == 0 && // !xarray
					   tmp.address <= entry_value &&
					   entry_value < tmp.address + sizeof_slots) { // is_sibling_entry()
					// entry = *(void **)entry_to_node(entry)
					struct drgn_qualified_type voidpp_type;
					err = drgn_program_find_type(drgn_object_program(res),
								     "void **",
								     NULL,
								     &voidpp_type);
					if (err)
						return err;
					err = drgn_object_set_unsigned(&entry,
								       voidpp_type,
								       entry_value - 1,
								       0);
					if (err)
						return err;
					err = drgn_object_dereference(&entry,
								      &entry);
					if (err)
						return err;
					err = drgn_object_read(&entry, &entry);
					if (err)
						return err;
					err = drgn_object_read_unsigned(&entry,
									&entry_value);
					if (err)
						return err;
				}
			}

			if (node_shift.uvalue == 0 || !is_node(entry_value))
				break;

			// node = xa_to_node(entry)
			// or
			// node = entry_to_node(entry)
			err = drgn_object_set_unsigned(&node, node_type,
						       entry_value - internal_flag,
						       0);
			if (err)
				return err;
			// node_shift = node->shift
			err = drgn_object_member_dereference(&tmp, &node,
							     "shift");
			if (err)
				return err;
			err = drgn_object_read_integer(&tmp, &node_shift);
			if (err)
				return err;

			if (node_shift.uvalue >= 64) // Avoid undefined behavior.
				offset = 0;
			else
				offset = (index >> node_shift.uvalue) & XA_CHUNK_MASK;
		}
	} else if (index) {
		goto null;
	}

	return drgn_object_copy(res, &entry);

null:
	return drgn_object_set_unsigned(res, drgn_object_qualified_type(&entry),
					0, 0);

#undef is_node
}

// Note that this only works since Linux kernel commit 0a835c4f090a
// ("Reimplement IDR and IDA using the radix tree") (in v4.11). We only need
// this since Linux kernel commit 95846ecf9dac ("pid: replace pid bitmap
// implementation with IDR API") (in v4.15) (see find_pid_in_pid_hash()), so
// that's okay.
struct drgn_error *linux_helper_idr_find(struct drgn_object *res,
					 const struct drgn_object *idr,
					 uint64_t id)
{
	struct drgn_error *err;

	DRGN_OBJECT(tmp, drgn_object_program(res));

	/* id -= idr->idr_base */
	err = drgn_object_member_dereference(&tmp, idr, "idr_base");
	if (!err) {
		union drgn_value idr_base;

		err = drgn_object_read_integer(&tmp, &idr_base);
		if (err)
			return err;
		id -= idr_base.uvalue;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		/* idr_base was added in v4.16. */
		drgn_error_destroy(err);
	} else {
		return err;
	}

	/* radix_tree_lookup(&idr->idr_rt, id) */
	err = drgn_object_member_dereference(&tmp, idr, "idr_rt");
	if (err)
		return err;
	err = drgn_object_address_of(&tmp, &tmp);
	if (err)
		return err;
	return linux_helper_xa_load(res, &tmp, id);
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

	DRGN_OBJECT(node, drgn_object_program(res));
	DRGN_OBJECT(tmp, drgn_object_program(res));

	err = drgn_object_read(&tmp, ns);
	if (err)
		return err;
	uint64_t ns_addr;
	err = drgn_object_read_unsigned(&tmp, &ns_addr);
	if (err)
		return err;
	union drgn_value ns_level;
	err = drgn_object_member_dereference(&tmp, &tmp, "level");
	if (err)
		return err;
	err = drgn_object_read_integer(&tmp, &ns_level);
	if (err)
		return err;

	/* i = 1 << pidhash_shift */
	err = drgn_program_find_object(drgn_object_program(res),
				       "pidhash_shift", NULL,
				       DRGN_FIND_OBJECT_ANY, &tmp);
	if (err)
		return err;
	union drgn_value pidhash_shift;
	err = drgn_object_read_integer(&tmp, &pidhash_shift);
	if (err)
		return err;
	uint64_t i;
	if (pidhash_shift.uvalue >= 64)
		i = 0;
	else
		i = UINT64_C(1) << pidhash_shift.uvalue;
	while (i--) {
		/* for (node = pid_hash[i].first; node; node = node->next) */
		err = drgn_object_subscript(&node, pid_hash, i);
		if (err)
			return err;
		err = drgn_object_member(&node, &node, "first");
		if (err)
			return err;
		for (;;) {
			uint64_t addr, tmp_addr;
			union drgn_value node_nr;
			uint64_t node_ns;

			err = drgn_object_read(&node, &node);
			if (err)
				return err;
			err = drgn_object_read_unsigned(&node, &addr);
			if (err)
				return err;
			if (!addr)
				break;
			addr -= pid_chain_bit_offset / 8;

			/* tmp = container_of(node, struct upid, pid_chain)->nr */
			tmp_addr = addr + nr_bit_offset / 8;
			err = drgn_object_set_reference(&tmp, nr_type, tmp_addr,
							0, 0);
			if (err)
				return err;
			err = drgn_object_read_integer(&tmp, &node_nr);
			if (err)
				return err;
			if (node_nr.uvalue != pid)
				goto next;

			/* tmp = container_of(node, struct upid, pid_chain)->ns */
			tmp_addr = addr + ns_bit_offset / 8;
			err = drgn_object_set_reference(&tmp, ns_type, tmp_addr,
							0, 0);
			if (err)
				return err;

			err = drgn_object_read_unsigned(&tmp, &node_ns);
			if (err)
				return err;
			if (node_ns != ns_addr)
				goto next;

#define FORMAT "numbers[%" PRIu64 "].pid_chain"
			char member[sizeof(FORMAT)
				    - sizeof("%" PRIu64)
				    + max_decimal_length(uint64_t)
				    + 1];
			snprintf(member, sizeof(member), FORMAT,
				 ns_level.uvalue);
#undef FORMAT
			return drgn_object_container_of(res, &node,
							drgn_type_type(pidp_type.type),
							member);

next:
			err = drgn_object_member_dereference(&node, &node, "next");
			if (err)
				return err;
		}
	}

	return drgn_object_set_unsigned(res, pidp_type, 0, 0);
}

struct drgn_error *linux_helper_find_pid(struct drgn_object *res,
					 const struct drgn_object *ns,
					 uint64_t pid)
{
	struct drgn_error *err;

	DRGN_OBJECT(tmp, drgn_object_program(res));

	/* (struct pid *)idr_find(&ns->idr, pid) */
	err = drgn_object_member_dereference(&tmp, ns, "idr");
	if (!err) {
		struct drgn_qualified_type qualified_type;

		err = drgn_object_address_of(&tmp, &tmp);
		if (err)
			return err;
		err = linux_helper_idr_find(&tmp, &tmp, pid);
		if (err)
			return err;
		err = drgn_program_find_type(drgn_object_program(res),
					     "struct pid *", NULL,
					     &qualified_type);
		if (err)
			return err;
		return drgn_object_cast(res, qualified_type, &tmp);
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		err = drgn_program_find_object(drgn_object_program(res),
					       "pid_hash", NULL,
					       DRGN_FIND_OBJECT_ANY, &tmp);
		if (err)
			return err;
		return find_pid_in_pid_hash(res, ns, &tmp, pid);
	} else {
		return err;
	}
}

struct drgn_error *linux_helper_pid_task(struct drgn_object *res,
					 const struct drgn_object *pid,
					 uint64_t pid_type)
{
	struct drgn_error *err;
	struct drgn_qualified_type task_structp_type;
	struct drgn_qualified_type task_struct_type;
	bool truthy;

	DRGN_OBJECT(first, drgn_object_program(res));

	err = drgn_program_find_type(drgn_object_program(res),
				     "struct task_struct *", NULL,
				     &task_structp_type);
	if (err)
		return err;
	task_struct_type = drgn_type_type(task_structp_type.type);

	err = drgn_object_bool(pid, &truthy);
	if (err)
		return err;
	if (!truthy)
		goto null;

	/* first = &pid->tasks[pid_type].first */
	err = drgn_object_member_dereference(&first, pid, "tasks");
	if (err)
		return err;
	err = drgn_object_subscript(&first, &first, pid_type);
	if (err)
		return err;
	err = drgn_object_member(&first, &first, "first");
	if (err)
		return err;

	err = drgn_object_bool(&first, &truthy);
	if (err)
		return err;
	if (!truthy)
		goto null;

	/* container_of(first, struct task_struct, pid_links[pid_type]) */
#define PID_LINKS_FORMAT "pid_links[%" PRIu64 "]"
#define PIDS_NODE_FORMAT "pids[%" PRIu64 "].node"
	char member[max_iconst(sizeof(PID_LINKS_FORMAT),
			       sizeof(PIDS_NODE_FORMAT))
		    - sizeof("%" PRIu64)
		    + max_decimal_length(uint64_t)
		    + 1];
	snprintf(member, sizeof(member), PID_LINKS_FORMAT, pid_type);
	err = drgn_object_container_of(res, &first, task_struct_type, member);
	if (err && err->code == DRGN_ERROR_LOOKUP) {
		drgn_error_destroy(err);
		/* container_of(first, struct task_struct, pids[pid_type].node) */
		snprintf(member, sizeof(member), PIDS_NODE_FORMAT, pid_type);
#undef PID_LINKS_FORMAT
#undef PIDS_NODE_FORMAT
		err = drgn_object_container_of(res, &first, task_struct_type,
					       member);
	}
	return err;

null:
	return drgn_object_set_unsigned(res, task_structp_type, 0, 0);
}

struct drgn_error *linux_helper_find_task(struct drgn_object *res,
					  const struct drgn_object *ns,
					  uint64_t pid)
{
	struct drgn_error *err;
	union drgn_value pid_type;

	DRGN_OBJECT(pid_obj, drgn_object_program(res));
	DRGN_OBJECT(pid_type_obj, drgn_object_program(res));

	err = linux_helper_find_pid(&pid_obj, ns, pid);
	if (err)
		return err;
	err = drgn_program_find_object(drgn_object_program(res), "PIDTYPE_PID",
				       NULL, DRGN_FIND_OBJECT_CONSTANT,
				       &pid_type_obj);
	if (err)
		return err;
	err = drgn_object_read_integer(&pid_type_obj, &pid_type);
	if (err)
		return err;
	return linux_helper_pid_task(res, &pid_obj, pid_type.uvalue);
}

struct drgn_error *
linux_helper_task_iterator_init(struct linux_helper_task_iterator *it,
				struct drgn_program *prog)
{
	struct drgn_error *err;
	it->done = false;
	drgn_object_init(&it->task, prog);
	err = drgn_program_find_object(prog, "init_task", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &it->task);
	if (err)
		goto err;
	it->task_struct_type = drgn_object_qualified_type(&it->task);
	err = drgn_object_address_of(&it->task, &it->task);
	if (err)
		goto err;
	err = drgn_object_read_unsigned(&it->task, &it->init_task_address);
	if (err)
		goto err;
	it->thread_group_address = it->init_task_address;
	return NULL;

err:
	drgn_object_deinit(&it->task);
	return err;
}

void linux_helper_task_iterator_deinit(struct linux_helper_task_iterator *it)
{
	drgn_object_deinit(&it->task);
}

struct drgn_error *
linux_helper_task_iterator_next(struct linux_helper_task_iterator *it,
				const struct drgn_object **ret)
{
	if (it->done) {
		*ret = NULL;
		return NULL;
	}
	struct drgn_error *err;
	struct drgn_object *task = &it->task;
	err = drgn_object_member_dereference(task, task, "thread_group");
	if (err)
		return err;
	err = drgn_object_member(task, task, "next");
	if (err)
		return err;
	err = drgn_object_container_of(task, task, it->task_struct_type,
				       "thread_group");
	if (err)
		return err;
	uint64_t task_address;
	err = drgn_object_read_unsigned(task, &task_address);
	if (err)
		return err;
	if (task_address == it->thread_group_address) {
		err = drgn_object_member_dereference(task, task, "tasks");
		if (err)
			return err;
		err = drgn_object_member(task, task, "next");
		if (err)
			return err;
		err = drgn_object_container_of(task, task,
					       it->task_struct_type, "tasks");
		if (err)
			return err;
		err = drgn_object_read_unsigned(task,
						&it->thread_group_address);
		if (err)
			return err;
		if (it->thread_group_address == it->init_task_address)
			it->done = true;
	}
	*ret = task;
	return NULL;
}
