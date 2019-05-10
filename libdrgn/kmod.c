// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "kmod.h"

struct drgn_error *
kernel_module_iterator_init(struct kernel_module_iterator *it,
			    struct drgn_program *prog)
{
	struct drgn_error *err;

	it->name = NULL;

	err = drgn_program_find_type(prog, "struct module", NULL,
				     &it->module_type);
	if (err)
		return err;

	drgn_object_init(&it->mod, prog);
	drgn_object_init(&it->node, prog);
	drgn_object_init(&it->mod_name, prog);

	err = drgn_program_find_object(prog, "modules", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &it->node);
	if (err)
		goto err;
	err = drgn_object_address_of(&it->node, &it->node);
	if (err)
		goto err;
	err = drgn_object_read(&it->node, &it->node);
	if (err)
		goto err;
	err = drgn_object_read_unsigned(&it->node, &it->head);
	if (err)
		goto err;

	return NULL;

err:
	kernel_module_iterator_deinit(it);
	return err;
}

void kernel_module_iterator_deinit(struct kernel_module_iterator *it)
{
	drgn_object_deinit(&it->mod_name);
	drgn_object_deinit(&it->node);
	drgn_object_deinit(&it->mod);
	free(it->name);
}

struct drgn_error *
kernel_module_iterator_next(struct kernel_module_iterator *it)
{
	struct drgn_error *err;
	uint64_t addr;
	char *name;

	err = drgn_object_member_dereference(&it->node, &it->node, "next");
	if (err)
		return err;
	err = drgn_object_read(&it->node, &it->node);
	if (err)
		return err;
	err = drgn_object_read_unsigned(&it->node, &addr);
	if (err)
		return err;
	if (addr == it->head)
		return &drgn_stop;

	err = drgn_object_container_of(&it->mod, &it->node, it->module_type,
				       "list");
	if (err)
		return err;

	err = drgn_object_member_dereference(&it->mod_name, &it->mod, "name");
	if (err)
		return err;
	err = drgn_object_read_c_string(&it->mod_name, &name);
	if (err)
		return err;
	free(it->name);
	it->name = name;
	return NULL;
}

static struct drgn_error *find_section_address(struct drgn_object *mod,
					       const char *section_name,
					       uint64_t *ret)
{
	struct drgn_error *err;
	struct drgn_object attrs, attr, tmp;
	uint64_t i, nsections;

	drgn_object_init(&attrs, mod->prog);
	drgn_object_init(&attr, mod->prog);
	drgn_object_init(&tmp, mod->prog);

	err = drgn_object_member_dereference(&attrs, mod, "sect_attrs");
	if (err)
		goto out;
	err = drgn_object_member_dereference(&tmp, &attrs, "nsections");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&tmp, &nsections);
	if (err)
		goto out;
	err = drgn_object_member_dereference(&attrs, &attrs, "attrs");
	if (err)
		goto out;

	for (i = 0; i < nsections; i++) {
		char *name;
		int cmp;

		err = drgn_object_subscript(&attr, &attrs, i);
		if (err)
			goto out;
		err = drgn_object_member(&tmp, &attr, "name");
		if (err)
			goto out;

		err = drgn_object_read_c_string(&tmp, &name);
		if (err)
			goto out;
		cmp = strcmp(name, section_name);
		free(name);
		if (cmp == 0) {
			err = drgn_object_member(&tmp, &attr, "address");
			if (err)
				goto out;
			err = drgn_object_read_unsigned(&tmp, ret);
			goto out;
		}
	}

	err = drgn_error_format(DRGN_ERROR_LOOKUP,
				"could not find module section %s",
				section_name);
out:
	drgn_object_deinit(&tmp);
	drgn_object_deinit(&attr);
	drgn_object_deinit(&attrs);
	return err;
}

struct drgn_error *kernel_module_section_address(struct drgn_program *prog,
						 const char *module_name,
						 const char *section_name,
						 uint64_t *ret)
{
	struct drgn_error *err;
	struct kernel_module_iterator it;

	err = kernel_module_iterator_init(&it, prog);
	if (err)
		return err;
	while (!(err = kernel_module_iterator_next(&it))) {
		if (strcmp(it.name, module_name) == 0) {
			/*
			 * kernel_module_iterator_next() leaves mod set to the
			 * struct module * object.
			 */
			err = find_section_address(&it.mod, section_name, ret);
			break;
		}
	}
	kernel_module_iterator_deinit(&it);
	if (err && err->code == DRGN_ERROR_STOP) {
		err = drgn_error_format(DRGN_ERROR_LOOKUP, "%s is not loaded",
					module_name);
	}
	return err;
}
