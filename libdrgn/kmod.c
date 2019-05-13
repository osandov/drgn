// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "kmod.h"
#include "program.h"

struct drgn_error *
kernel_module_iterator_init(struct kernel_module_iterator *it,
			    struct drgn_program *prog)
{
	struct drgn_error *err;

	it->name = NULL;
	if (prog->flags & DRGN_PROGRAM_IS_RUNNING_KERNEL) {
		it->file = fopen("/proc/modules", "r");
		if (!it->file) {
			return drgn_error_create_os(errno, "/proc/modules",
						    "fopen");
		}
		it->name_capacity = 0;
	} else {
		it->file = NULL;

		err = drgn_program_find_type(prog, "struct module", NULL,
					     &it->module_type);
		if (err)
			return err;

		drgn_object_init(&it->mod, prog);
		drgn_object_init(&it->node, prog);
		drgn_object_init(&it->mod_name, prog);

		err = drgn_program_find_object(prog, "modules", NULL,
					       DRGN_FIND_OBJECT_VARIABLE,
					       &it->node);
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
	}

	return NULL;

err:
	kernel_module_iterator_deinit(it);
	return err;
}

void kernel_module_iterator_deinit(struct kernel_module_iterator *it)
{
	if (it->file) {
		fclose(it->file);
	} else {
		drgn_object_deinit(&it->mod_name);
		drgn_object_deinit(&it->node);
		drgn_object_deinit(&it->mod);
	}
	free(it->name);
}

static struct drgn_error *
kernel_module_iterator_next_procfs(struct kernel_module_iterator *it)
{
	ssize_t ret;
	char *p;

	errno = 0;
	ret = getline(&it->name, &it->name_capacity, it->file);
	if (ret == -1) {
		if (errno) {
			return drgn_error_create_os(errno, "/proc/modules",
						    "getline");
		} else {
			return &drgn_stop;
		}
	}
	p = strchr(it->name, ' ');
	if (p)
		*p = '\0';
	return NULL;
}

struct drgn_error *
kernel_module_iterator_next(struct kernel_module_iterator *it)
{
	struct drgn_error *err;
	uint64_t addr;
	char *name;

	if (it->file)
		return kernel_module_iterator_next_procfs(it);

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

struct drgn_error *
kernel_module_section_address_from_sysfs(struct drgn_program *prog,
					 const char *module_name,
					 const char *section_name,
					 uint64_t *ret)
{
	struct drgn_error *err;
	FILE *file;
	char *path;

	if (asprintf(&path, "/sys/module/%s/sections/%s", module_name,
		     section_name) == -1) {
		return &drgn_enomem;
	}
	file = fopen(path, "r");
	if (!file) {
		if (errno == ENOENT) {
			err = drgn_error_format(DRGN_ERROR_LOOKUP,
						"%s is not loaded",
						module_name);
		} else {
			err = drgn_error_create_os(errno, path, "fopen");
		}
		goto out_path;
	}
	if (fscanf(file, "%" SCNx64, ret) != 1) {
		err = drgn_error_format(DRGN_ERROR_OTHER, "could not parse %s",
					path);
	} else {
		err = NULL;
	}
	fclose(file);
out_path:
	free(path);
	return err;
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

	/*
	 * For the running kernel, we can take a shortcut by looking at sysfs.
	 * Otherwise, we have to walk the list of modules in the kernel.
	 */
	if (prog->flags & DRGN_PROGRAM_IS_RUNNING_KERNEL) {
		return kernel_module_section_address_from_sysfs(prog,
								module_name,
								section_name,
								ret);
	}

	err = kernel_module_iterator_init(&it, prog);
	if (err)
		return err;
	while (!(err = kernel_module_iterator_next(&it))) {
		if (strcmp(it.name, module_name) == 0) {
			/*
			 * Since this isn't the running kernel,
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
