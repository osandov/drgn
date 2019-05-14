// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "internal.h"
#include "kmod.h"
#include "program.h"
#include "read.h"

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

/*
 * /lib/modules/$(uname -r)/modules.dep.bin maps all installed kernel modules to
 * their filesystem path (and dependencies, which we don't care about). It is
 * generated by depmod; the format is a fairly simple serialized radix tree.
 *
 * modules.dep(5) contains a warning: "These files are not intended for editing
 * or use by any additional utilities as their format is subject to change in
 * the future." But, the format hasn't changed since 2009, and pulling in
 * libkmod is overkill since we only need a very small subset of its
 * functionality (plus our minimal parser is more efficient). If the format
 * changes in the future, we can reevaluate this.
 */

static struct drgn_error *kmod_index_validate(struct kmod_index *index,
					      const char *path)
{
	const char *ptr;
	uint32_t magic, version;

	ptr = index->ptr;
	if (!read_be32(&ptr, index->end, &magic) ||
	    !read_be32(&ptr, index->end, &version)) {
		return drgn_error_format(DRGN_ERROR_OTHER, "%s is too short",
					 path);
	}
	if (magic != 0xb007f457) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has invalid magic (0x%" PRIx32 ")",
					 path, magic);
	}
	if (version != 0x00020001) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s has unknown version (0x%" PRIx32 ")",
					 path, version);
	}
	return NULL;
}

static void kmod_index_deinit(struct kmod_index *index)
{
	munmap((void *)index->ptr, index->end - index->ptr);
}

static struct drgn_error *kmod_index_init(struct kmod_index *index,
					  const char *path)
{
	struct drgn_error *err;
	int fd;
	struct stat st;
	void *map;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return drgn_error_create_os(errno, path, "open");

	if (fstat(fd, &st) == -1) {
		err = drgn_error_create_os(errno, path, "fstat");
		goto out;
	}

	if (st.st_size < 0 || st.st_size > SIZE_MAX) {
		err = &drgn_enomem;
		goto out;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		err = drgn_error_create_os(errno, path, "mmap");
		goto out;
	}
	index->ptr = map;
	index->end = index->ptr + st.st_size;

	err = kmod_index_validate(index, path);
	if (err)
		kmod_index_deinit(index);
out:
	close(fd);
	return err;
}

static const char *kmod_index_find(struct kmod_index *index, const char *key)
{
	const char *ptr = index->ptr + 8;
	uint32_t offset;

	for (;;) {
		if (!read_be32(&ptr, index->end, &offset))
			return NULL;
		ptr = index->ptr + (offset & 0x0fffffffU);

		if (offset & 0x80000000U) {
			const char *prefix;
			size_t prefix_len;

			if (!read_string(&ptr, index->end, &prefix,
					 &prefix_len))
				return NULL;
			if (strncmp(key, prefix, prefix_len) != 0)
				return NULL;
			key += prefix_len;
		}

		if (offset & 0x20000000U) {
			uint8_t first, last;

			if (!read_u8(&ptr, index->end, &first) ||
			    !read_u8(&ptr, index->end, &last))
				return NULL;
			if (*key) {
				uint8_t cur = *key;

				if (cur < first || cur > last)
					return NULL;
				ptr += 4 * (cur - first);
				key++;
				continue;
			} else {
				ptr += 4 * (last - first + 1);
				break;
			}
		} else if (*key) {
			return NULL;
		} else {
			break;
		}
	}
	if (!(offset & 0x40000000U))
		return NULL;
	return ptr;
}

struct drgn_error *depmod_index_init(struct depmod_index *depmod,
				     const char *osrelease)
{
	char path[256];

	snprintf(path, sizeof(path), "/lib/modules/%s/modules.dep.bin",
		 osrelease);
	return kmod_index_init(&depmod->modules_dep, path);
}

void depmod_index_deinit(struct depmod_index *depmod)
{
	kmod_index_deinit(&depmod->modules_dep);
}

bool depmod_index_find(struct depmod_index *depmod, const char *name,
		       const char **path_ret, size_t *len_ret)
{
	const char *ptr;
	uint32_t value_count;
	const char *deps;
	size_t deps_len;
	char *colon;

	ptr = kmod_index_find(&depmod->modules_dep, name);
	if (!ptr)
		return false;

	if (!read_be32(&ptr, depmod->modules_dep.end, &value_count) ||
	    !value_count)
		return false;

	/* Skip over priority. */
	ptr += 4;
	if (!read_string(&ptr, depmod->modules_dep.end, &deps,
			 &deps_len))
		return false;

	colon = strchr(deps, ':');
	if (!colon)
		return false;

	*path_ret = deps;
	*len_ret = colon - deps;
	return true;
}
