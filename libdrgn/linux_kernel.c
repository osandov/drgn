// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <dirent.h>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "binary_buffer.h"
#include "bitops.h"
#include "debug_info.h"
#include "drgn.h"
#include "error.h"
#include "hash_table.h"
#include "helpers.h"
#include "language.h"
#include "linux_kernel.h"
#include "platform.h"
#include "program.h"
#include "type.h"
#include "util.h"

struct drgn_error *read_memory_via_pgtable(void *buf, uint64_t address,
					   size_t count, uint64_t offset,
					   void *arg, bool physical)
{
	struct drgn_program *prog = arg;
	return linux_helper_read_vm(prog, prog->vmcoreinfo.swapper_pg_dir,
				    address, buf, count);
}

static inline bool linematch(const char **line, const char *prefix)
{
	size_t len = strlen(prefix);

	if (strncmp(*line, prefix, len) == 0) {
		*line += len;
		return true;
	} else {
		return false;
	}
}

static struct drgn_error *line_to_u64(const char *line, const char *newline,
				      int base, uint64_t *ret)
{
	unsigned long long value;
	char *end;

	errno = 0;
	value = strtoull(line, &end, base);
	if (errno == ERANGE) {
		return drgn_error_create(DRGN_ERROR_OVERFLOW,
					 "number in VMCOREINFO is too large");
	} else if (errno || end == line || end != newline) {
		return drgn_error_create(DRGN_ERROR_OVERFLOW,
					 "number in VMCOREINFO is invalid");
	}
	*ret = value;
	return NULL;
}

struct drgn_error *parse_vmcoreinfo(const char *desc, size_t descsz,
				    struct vmcoreinfo *ret)
{
	struct drgn_error *err;
	const char *line = desc, *end = &desc[descsz];

	ret->osrelease[0] = '\0';
	ret->page_size = 0;
	ret->kaslr_offset = 0;
	ret->pgtable_l5_enabled = false;
	while (line < end) {
		const char *newline;

		newline = memchr(line, '\n', end - line);
		if (!newline)
			break;

		if (linematch(&line, "OSRELEASE=")) {
			if ((size_t)(newline - line) >=
			    sizeof(ret->osrelease)) {
				return drgn_error_create(DRGN_ERROR_OTHER,
							 "OSRELEASE in VMCOREINFO is too long");
			}
			memcpy(ret->osrelease, line, newline - line);
			ret->osrelease[newline - line] = '\0';
		} else if (linematch(&line, "PAGESIZE=")) {
			err = line_to_u64(line, newline, 0, &ret->page_size);
			if (err)
				return err;
		} else if (linematch(&line, "KERNELOFFSET=")) {
			err = line_to_u64(line, newline, 16,
					  &ret->kaslr_offset);
			if (err)
				return err;
		} else if (linematch(&line, "SYMBOL(swapper_pg_dir)=")) {
			err = line_to_u64(line, newline, 16,
					  &ret->swapper_pg_dir);
			if (err)
				return err;
		} else if (linematch(&line, "NUMBER(pgtable_l5_enabled)=")) {
			uint64_t tmp;

			err = line_to_u64(line, newline, 0, &tmp);
			if (err)
				return err;
			ret->pgtable_l5_enabled = tmp;
		}
		line = newline + 1;
	}
	if (!ret->osrelease[0]) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "VMCOREINFO does not contain valid OSRELEASE");
	}
	if (!ret->page_size) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "VMCOREINFO does not contain valid PAGESIZE");
	}
	if (!ret->swapper_pg_dir) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "VMCOREINFO does not contain valid swapper_pg_dir");
	}
	/* KERNELOFFSET and pgtable_l5_enabled are optional. */
	return NULL;
}

struct drgn_error *proc_kallsyms_symbol_addr(const char *name,
					     unsigned long *ret)
{
	struct drgn_error *err;
	FILE *file;
	char *line = NULL;
	size_t n = 0;

	file = fopen("/proc/kallsyms", "r");
	if (!file)
		return drgn_error_create_os("fopen", errno, "/proc/kallsyms");

	for (;;) {
		char *addr_str, *sym_str, *saveptr, *end;

		errno = 0;
		if (getline(&line, &n, file) == -1) {
			if (errno) {
				err = drgn_error_create_os("getline", errno,
							   "/proc/kallsyms");
			} else {
				err = &drgn_not_found;
			}
			break;
		}

		addr_str = strtok_r(line, "\t ", &saveptr);
		if (!addr_str || !*addr_str)
			goto invalid;
		if (!strtok_r(NULL, "\t ", &saveptr))
			goto invalid;
		sym_str = strtok_r(NULL, "\t\n ", &saveptr);
		if (!sym_str)
			goto invalid;

		if (strcmp(sym_str, name) != 0)
			continue;

		errno = 0;
		*ret = strtoul(line, &end, 16);
		if (errno || *end) {
invalid:
			err = drgn_error_create(DRGN_ERROR_OTHER,
						"could not parse /proc/kallsyms");
			break;
		}
		err = NULL;
		break;
	}
	free(line);
	fclose(file);
	return err;
}

/*
 * Before Linux kernel commit 23c85094fe18 ("proc/kcore: add vmcoreinfo note to
 * /proc/kcore") (in v4.19), /proc/kcore didn't have a VMCOREINFO note. Instead,
 * we can read from the physical address of the vmcoreinfo note exported in
 * sysfs.
 */
struct drgn_error *read_vmcoreinfo_fallback(struct drgn_program *prog)
{
	struct drgn_error *err;
	FILE *file;
	uint64_t address;
	size_t size;
	char *buf;
	Elf64_Nhdr *nhdr;

	file = fopen("/sys/kernel/vmcoreinfo", "r");
	if (!file) {
		return drgn_error_create_os("fopen", errno,
					    "/sys/kernel/vmcoreinfo");
	}
	if (fscanf(file, "%" SCNx64 "%zx", &address, &size) != 2) {
		fclose(file);
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "could not parse /sys/kernel/vmcoreinfo");
	}
	fclose(file);

	buf = malloc(size);
	if (!buf)
		return &drgn_enomem;

	err = drgn_program_read_memory(prog, buf, address, size, true);
	if (err)
		goto out;

	/*
	 * The first 12 bytes are the Elf{32,64}_Nhdr (it's the same in both
	 * formats). The name is padded up to 4 bytes, so the descriptor starts
	 * at byte 24.
	 */
	nhdr = (Elf64_Nhdr *)buf;
	if (size < 24 || nhdr->n_namesz != 11 ||
	    memcmp(buf + sizeof(*nhdr), "VMCOREINFO", 10) != 0 ||
	    nhdr->n_descsz > size - 24) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"VMCOREINFO is invalid");
		goto out;
	}

	err = parse_vmcoreinfo(buf + 24, nhdr->n_descsz, &prog->vmcoreinfo);
out:
	free(buf);
	return err;
}

struct drgn_error *linux_kernel_object_find(const char *name, size_t name_len,
					    const char *filename,
					    enum drgn_find_object_flags flags,
					    void *arg, struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = arg;

	if (!filename && (flags & DRGN_FIND_OBJECT_CONSTANT)) {
		struct drgn_qualified_type qualified_type = {};

		if (name_len == strlen("PAGE_OFFSET") &&
		    memcmp(name, "PAGE_OFFSET", name_len) == 0) {
			if (prog->page_offset.kind == DRGN_OBJECT_ABSENT) {
				if (!prog->has_platform ||
				    !prog->platform.arch->linux_kernel_get_page_offset)
					return &drgn_not_found;
				err = prog->platform.arch->linux_kernel_get_page_offset(&prog->page_offset);
				if (err)
					return err;
			}
			return drgn_object_copy(ret, &prog->page_offset);
		} else if (name_len == strlen("PAGE_SHIFT") &&
			   memcmp(name, "PAGE_SHIFT", name_len) == 0) {
			err = drgn_program_find_primitive_type(prog,
							       DRGN_C_TYPE_INT,
							       &qualified_type.type);
			if (err)
				return err;
			return drgn_object_set_signed(ret, qualified_type,
						      ctz(prog->vmcoreinfo.page_size),
						      0);
		} else if (name_len == strlen("PAGE_SIZE") &&
			   memcmp(name, "PAGE_SIZE", name_len) == 0) {
			err = drgn_program_find_primitive_type(prog,
							       DRGN_C_TYPE_UNSIGNED_LONG,
							       &qualified_type.type);
			if (err)
				return err;
			return drgn_object_set_unsigned(ret, qualified_type,
							prog->vmcoreinfo.page_size,
							0);
		} else if (name_len == strlen("PAGE_MASK") &&
			   memcmp(name, "PAGE_MASK", name_len) == 0) {
			err = drgn_program_find_primitive_type(prog,
							       DRGN_C_TYPE_UNSIGNED_LONG,
							       &qualified_type.type);
			if (err)
				return err;
			return drgn_object_set_unsigned(ret, qualified_type,
							~(prog->vmcoreinfo.page_size - 1),
							0);
		} else if (name_len == strlen("UTS_RELEASE") &&
			   memcmp(name, "UTS_RELEASE", name_len) == 0) {
			size_t len;

			err = drgn_program_find_primitive_type(prog,
							       DRGN_C_TYPE_CHAR,
							       &qualified_type.type);
			if (err)
				return err;
			qualified_type.qualifiers = DRGN_QUALIFIER_CONST;
			len = strlen(prog->vmcoreinfo.osrelease);
			err = drgn_array_type_create(prog, qualified_type,
						     len + 1, &drgn_language_c,
						     &qualified_type.type);
			if (err)
				return err;
			qualified_type.qualifiers = 0;
			return drgn_object_set_from_buffer(ret, qualified_type,
							   prog->vmcoreinfo.osrelease,
							   len + 1, 0, 0);
		} else if (name_len == strlen("vmemmap") &&
			   memcmp(name, "vmemmap", name_len) == 0) {
			if (prog->vmemmap.kind == DRGN_OBJECT_ABSENT) {
				if (!prog->has_platform ||
				    !prog->platform.arch->linux_kernel_get_vmemmap)
					return &drgn_not_found;
				err = prog->platform.arch->linux_kernel_get_vmemmap(&prog->vmemmap);
				if (err)
					return err;
			}
			return drgn_object_copy(ret, &prog->vmemmap);
		}
	}
	return &drgn_not_found;
}

struct kernel_module_iterator {
	char *name;
	/* /proc/modules file or NULL. */
	FILE *modules_file;
	union {
		/* If using /proc/modules. */
		struct {
			size_t name_capacity;
			uint64_t start, end;
		};
		/* If not using /proc/modules. */
		struct {
			struct drgn_qualified_type module_type;
			struct drgn_object mod, node, tmp1, tmp2, tmp3;
			uint64_t head;
		};
	};
};

static void kernel_module_iterator_deinit(struct kernel_module_iterator *it)
{
	if (it->modules_file) {
		fclose(it->modules_file);
	} else {
		drgn_object_deinit(&it->tmp3);
		drgn_object_deinit(&it->tmp2);
		drgn_object_deinit(&it->tmp1);
		drgn_object_deinit(&it->node);
		drgn_object_deinit(&it->mod);
	}
	free(it->name);
}

static struct drgn_error *
kernel_module_iterator_init(struct kernel_module_iterator *it,
			    struct drgn_program *prog, bool use_proc_and_sys)
{
	struct drgn_error *err;

	it->name = NULL;
	if (use_proc_and_sys) {
		it->modules_file = fopen("/proc/modules", "r");
		if (!it->modules_file) {
			return drgn_error_create_os("fopen", errno,
						    "/proc/modules");
		}
		it->name_capacity = 0;
	} else {
		it->modules_file = NULL;

		err = drgn_program_find_type(prog, "struct module", NULL,
					     &it->module_type);
		if (err)
			return err;

		drgn_object_init(&it->mod, prog);
		drgn_object_init(&it->node, prog);
		drgn_object_init(&it->tmp1, prog);
		drgn_object_init(&it->tmp2, prog);
		drgn_object_init(&it->tmp3, prog);

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

static struct drgn_error *
kernel_module_iterator_next_live(struct kernel_module_iterator *it)
{

	errno = 0;
	ssize_t ret = getline(&it->name, &it->name_capacity, it->modules_file);
	if (ret == -1) {
		if (errno) {
			return drgn_error_create_os("getline", errno,
						    "/proc/modules");
		} else {
			return &drgn_stop;
		}
	}
	char *p = strchr(it->name, ' ');
	size_t size;
	if (!p ||
	    sscanf(p + 1, "%zu %*s %*s %*s %" SCNx64, &size, &it->start) != 2) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "could not parse /proc/modules");
	}
	*p = '\0';
	it->end = it->start + size;
	return NULL;
}

/**
 * Get the the next loaded kernel module.
 *
 * After this is called, @c it->name is set to the name of the kernel module,
 * and @c it->start and @c it->end are set to the address range of the kernel
 * module. These are valid until the next time this is called or the iterator is
 * destroyed.
 *
 * @return @c NULL on success, non-@c NULL on error. In particular, when there
 * are no more modules, returns &@ref drgn_stop.
 */
static struct drgn_error *
kernel_module_iterator_next(struct kernel_module_iterator *it)
{
	if (it->modules_file)
		return kernel_module_iterator_next_live(it);

	struct drgn_error *err;

	err = drgn_object_member_dereference(&it->node, &it->node, "next");
	if (err)
		return err;
	err = drgn_object_read(&it->node, &it->node);
	if (err)
		return err;
	uint64_t addr;
	err = drgn_object_read_unsigned(&it->node, &addr);
	if (err)
		return err;
	if (addr == it->head)
		return &drgn_stop;

	err = drgn_object_container_of(&it->mod, &it->node, it->module_type,
				       "list");
	if (err)
		return err;

	err = drgn_object_member_dereference(&it->tmp1, &it->mod, "name");
	if (err)
		return err;
	char *name;
	err = drgn_object_read_c_string(&it->tmp1, &name);
	if (err)
		return err;
	free(it->name);
	it->name = name;
	return NULL;
}

struct kernel_module_section_iterator {
	struct kernel_module_iterator *kmod_it;
	/* /sys/module/$module/sections directory or NULL. */
	DIR *sections_dir;
	/* If not using /sys/module/$module/sections. */
	uint64_t i;
	uint64_t nsections;
	char *name;
};

static struct drgn_error *
kernel_module_section_iterator_init(struct kernel_module_section_iterator *it,
				    struct kernel_module_iterator *kmod_it)
{
	struct drgn_error *err;

	it->kmod_it = kmod_it;
	if (kmod_it->modules_file) {
		char *path;
		if (asprintf(&path, "/sys/module/%s/sections",
			     kmod_it->name) == -1)
			return &drgn_enomem;
		it->sections_dir = opendir(path);
		free(path);
		if (!it->sections_dir) {
			return drgn_error_format_os("opendir", errno,
						    "/sys/module/%s/sections",
						    kmod_it->name);
		}
		return NULL;
	} else {
		it->sections_dir = NULL;
		it->i = 0;
		it->name = NULL;
		/* it->nsections = mod->sect_attrs->nsections */
		err = drgn_object_member_dereference(&kmod_it->tmp1,
						     &kmod_it->mod,
						     "sect_attrs");
		if (err)
			return err;
		err = drgn_object_member_dereference(&kmod_it->tmp2,
						     &kmod_it->tmp1,
						     "nsections");
		if (err)
			return err;
		err = drgn_object_read_unsigned(&kmod_it->tmp2,
						&it->nsections);
		if (err)
			return err;
		/* kmod_it->tmp1 = mod->sect_attrs->attrs */
		return drgn_object_member_dereference(&kmod_it->tmp1,
						      &kmod_it->tmp1, "attrs");
	}
}

static void
kernel_module_section_iterator_deinit(struct kernel_module_section_iterator *it)
{
	if (it->sections_dir)
		closedir(it->sections_dir);
	else
		free(it->name);
}

static struct drgn_error *
kernel_module_section_iterator_next_live(struct kernel_module_section_iterator *it,
					 const char **name_ret,
					 uint64_t *address_ret)
{
	struct dirent *ent;
	while ((errno = 0, ent = readdir(it->sections_dir))) {
		if (ent->d_type == DT_DIR)
			continue;
		if (ent->d_type == DT_UNKNOWN) {
			struct stat st;

			if (fstatat(dirfd(it->sections_dir), ent->d_name, &st,
				    0) == -1) {
				return drgn_error_format_os("fstatat", errno,
							    "/sys/module/%s/sections/%s",
							    it->kmod_it->name,
							    ent->d_name);
			}
			if (S_ISDIR(st.st_mode))
				continue;
		}

		int fd = openat(dirfd(it->sections_dir), ent->d_name, O_RDONLY);
		if (fd == -1) {
			return drgn_error_format_os("openat", errno,
						    "/sys/module/%s/sections/%s",
						    it->kmod_it->name,
						    ent->d_name);
		}
		FILE *file = fdopen(fd, "r");
		if (!file) {
			close(fd);
			return drgn_error_create_os("fdopen", errno, NULL);
		}
		int ret = fscanf(file, "%" SCNx64, address_ret);
		fclose(file);
		if (ret != 1) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "could not parse /sys/module/%s/sections/%s",
						 it->kmod_it->name,
						 ent->d_name);
		}
		*name_ret = ent->d_name;
		return NULL;
	}
	if (errno) {
		return drgn_error_format_os("readdir", errno,
					    "/sys/module/%s/sections",
					    it->kmod_it->name);
	} else {
		return &drgn_stop;
	}
}

static struct drgn_error *
kernel_module_section_iterator_next(struct kernel_module_section_iterator *it,
				    const char **name_ret,
				    uint64_t *address_ret)
{
	if (it->sections_dir) {
		return kernel_module_section_iterator_next_live(it, name_ret,
								address_ret);
	}

	struct drgn_error *err;
	struct kernel_module_iterator *kmod_it = it->kmod_it;

	if (it->i >= it->nsections)
		return &drgn_stop;
	err = drgn_object_subscript(&kmod_it->tmp2, &kmod_it->tmp1, it->i++);
	if (err)
		return err;
	err = drgn_object_member(&kmod_it->tmp3, &kmod_it->tmp2, "address");
	if (err)
		return err;
	err = drgn_object_read_unsigned(&kmod_it->tmp3, address_ret);
	if (err)
		return err;
	/*
	 * Since Linux kernel commit ed66f991bb19 ("module: Refactor section
	 * attr into bin attribute") (in v5.8), the section name is
	 * module_sect_attr.battr.attr.name. Before that, it is simply
	 * module_sect_attr.name.
	 */
	err = drgn_object_member(&kmod_it->tmp2, &kmod_it->tmp2, "battr");
	if (!err) {
		err = drgn_object_member(&kmod_it->tmp2, &kmod_it->tmp2,
					 "attr");
		if (err)
			return err;
	} else {
		if (err->code != DRGN_ERROR_LOOKUP)
			return err;
		drgn_error_destroy(err);
	}
	err = drgn_object_member(&kmod_it->tmp3, &kmod_it->tmp2, "name");
	if (err)
		return err;
	char *name;
	err = drgn_object_read_c_string(&kmod_it->tmp3, &name);
	if (err)
		return err;
	free(it->name);
	*name_ret = it->name = name;
	return NULL;
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

struct depmod_index {
	void *addr;
	size_t len;
	char path[256];
};

static void depmod_index_deinit(struct depmod_index *depmod)
{
	munmap(depmod->addr, depmod->len);
}

struct depmod_index_buffer {
	struct binary_buffer bb;
	struct depmod_index *depmod;
};

static struct drgn_error *depmod_index_buffer_error(struct binary_buffer *bb,
						    const char *pos,
						    const char *message)
{
	struct depmod_index_buffer *buffer =
		container_of(bb, struct depmod_index_buffer, bb);
	return drgn_error_format(DRGN_ERROR_OTHER, "%s: %#tx: %s",
				 buffer->depmod->path,
				 pos - (const char *)buffer->depmod->addr,
				 message);
}

static void depmod_index_buffer_init(struct depmod_index_buffer *buffer,
				     struct depmod_index *depmod)
{
	binary_buffer_init(&buffer->bb, depmod->addr, depmod->len, false,
			   depmod_index_buffer_error);
	buffer->depmod = depmod;
}

static struct drgn_error *depmod_index_validate(struct depmod_index *depmod)
{
	struct drgn_error *err;
	struct depmod_index_buffer buffer;
	depmod_index_buffer_init(&buffer, depmod);
	uint32_t magic;
	if ((err = binary_buffer_next_u32(&buffer.bb, &magic)))
		return err;
	if (magic != 0xb007f457) {
		return binary_buffer_error(&buffer.bb,
					   "invalid magic 0x%" PRIx32, magic);
	}
	uint32_t version;
	if ((err = binary_buffer_next_u32(&buffer.bb, &version)))
		return err;
	if (version != 0x00020001) {
		return binary_buffer_error(&buffer.bb,
					   "unknown version 0x%" PRIx32,
					   version);
	}
	return NULL;
}

static struct drgn_error *depmod_index_init(struct depmod_index *depmod,
					    const char *osrelease)
{
	struct drgn_error *err;

	snprintf(depmod->path, sizeof(depmod->path),
		 "/lib/modules/%s/modules.dep.bin", osrelease);

	int fd = open(depmod->path, O_RDONLY);
	if (fd == -1)
		return drgn_error_create_os("open", errno, depmod->path);

	struct stat st;
	if (fstat(fd, &st) == -1) {
		err = drgn_error_create_os("fstat", errno, depmod->path);
		goto out;
	}

	if (st.st_size < 0 || st.st_size > SIZE_MAX) {
		err = &drgn_enomem;
		goto out;
	}

	void *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		err = drgn_error_create_os("mmap", errno, depmod->path);
		goto out;
	}

	depmod->addr = addr;
	depmod->len = st.st_size;

	err = depmod_index_validate(depmod);
	if (err)
		depmod_index_deinit(depmod);
out:
	close(fd);
	return err;
}

/*
 * Look up the path of the kernel module with the given name.
 *
 * @param[in] name Name of the kernel module.
 * @param[out] path_ret Returned path of the kernel module, relative to
 * /lib/modules/$(uname -r). This is @em not null-terminated. @c NULL if not
 * found.
 * @param[out] len_ret Returned length of @p path_ret.
 */
static struct drgn_error *depmod_index_find(struct depmod_index *depmod,
					    const char *name,
					    const char **path_ret,
					    size_t *len_ret)
{
	static const uint32_t INDEX_NODE_MASK = UINT32_C(0x0fffffff);
	static const uint32_t INDEX_NODE_CHILDS = UINT32_C(0x20000000);
	static const uint32_t INDEX_NODE_VALUES = UINT32_C(0x40000000);
	static const uint32_t INDEX_NODE_PREFIX = UINT32_C(0x80000000);

	struct drgn_error *err;
	struct depmod_index_buffer buffer;
	depmod_index_buffer_init(&buffer, depmod);

	/* depmod_index_validate() already checked that this is within bounds. */
	buffer.bb.pos += 8;
	uint32_t offset;
	for (;;) {
		if ((err = binary_buffer_next_u32(&buffer.bb, &offset)))
			return err;
		if ((offset & INDEX_NODE_MASK) > depmod->len) {
			return binary_buffer_error(&buffer.bb,
						   "offset is out of bounds");
		}
		buffer.bb.pos = (const char *)depmod->addr + (offset & INDEX_NODE_MASK);

		if (offset & INDEX_NODE_PREFIX) {
			const char *prefix;
			size_t prefix_len;
			if ((err = binary_buffer_next_string(&buffer.bb,
							     &prefix,
							     &prefix_len)))
				return err;
			if (strncmp(name, prefix, prefix_len) != 0)
				goto not_found;
			name += prefix_len;
		}

		if (offset & INDEX_NODE_CHILDS) {
			uint8_t first, last;
			if ((err = binary_buffer_next_u8(&buffer.bb, &first)) ||
			    (err = binary_buffer_next_u8(&buffer.bb, &last)))
				return err;
			if (*name) {
				uint8_t cur = *name;
				if (cur < first || cur > last)
					goto not_found;
				if ((err = binary_buffer_skip(&buffer.bb,
							      4 * (cur - first))))
					return err;
				name++;
				continue;
			} else {
				if ((err = binary_buffer_skip(&buffer.bb,
							      4 * (last - first + 1))))
					return err;
				break;
			}
		} else if (*name) {
			goto not_found;
		} else {
			break;
		}
	}
	if (!(offset & INDEX_NODE_VALUES))
		goto not_found;

	uint32_t value_count;
	if ((err = binary_buffer_next_u32(&buffer.bb, &value_count)))
		return err;
	if (!value_count)
		goto not_found; /* Or is this malformed? */

	/* Skip over priority. */
	if ((err = binary_buffer_skip(&buffer.bb, 4)))
		return err;

	const char *colon = memchr(buffer.bb.pos, ':',
				   buffer.bb.end - buffer.bb.pos);
	if (!colon) {
		return binary_buffer_error(&buffer.bb,
					   "expected string containing ':'");
	}
	*path_ret = buffer.bb.pos;
	*len_ret = colon - buffer.bb.pos;
	return NULL;

not_found:
	*path_ret = NULL;
	return NULL;
}

/*
 * Identify an ELF file as a kernel module, vmlinux, or neither. A kernel module
 * should have sections named .gnu.linkonce.this_module and .modinfo; we return
 * those sections and classify the file as a kernel module if either is present.
 *
 * If neither is present, and the file has a section named .init.text, we
 * classify it as vmlinux.
 */
static struct drgn_error *identify_kernel_elf(Elf *elf,
					      Elf_Scn **this_module_scn_ret,
					      Elf_Scn **modinfo_scn_ret,
					      bool *is_vmlinux_ret)
{
	size_t shstrndx;
	Elf_Scn *scn;
	bool have_init_text = false;

	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	scn = *this_module_scn_ret = *modinfo_scn_ret = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr *shdr, shdr_mem;
		const char *scnname;

		shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			continue;

		scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname)
			return drgn_error_libelf();
		if (strcmp(scnname, ".gnu.linkonce.this_module") == 0)
			*this_module_scn_ret = scn;
		else if (strcmp(scnname, ".modinfo") == 0)
			*modinfo_scn_ret = scn;
		else if (strcmp(scnname, ".init.text") == 0)
			have_init_text = true;
	}
	*is_vmlinux_ret = (!*this_module_scn_ret && !*modinfo_scn_ret &&
			   have_init_text);
	return NULL;
}
/*
 * Since Linux kernel commit 3e2e857f9c3a ("module: Add module name to modinfo")
 * (in v4.13), we can get the module name from .modinfo.
 */
static struct drgn_error *
get_kernel_module_name_from_modinfo(Elf_Scn *modinfo_scn, const char **ret)
{
	struct drgn_error *err;
	Elf_Data *data;
	const char *p, *end, *nul;

	if (modinfo_scn) {
		err = read_elf_section(modinfo_scn, &data);
		if (err)
			return err;
		p = data->d_buf;
		end = p + data->d_size;
		while (p < end) {
			nul = memchr(p, 0, end - p);
			if (!nul)
				break;
			if (strstartswith(p, "name=")) {
				*ret = p + 5;
				return NULL;
			}
			p = nul + 1;
		}
	}
	*ret = NULL;
	return NULL;
}

/*
 * If the module name isn't in .modinfo, we need to get it from
 * .gnu.linkonce.this_module, which contains a struct module. name_offset is
 * offsetof(struct module, name).
 */
static struct drgn_error *
get_kernel_module_name_from_this_module(Elf_Scn *this_module_scn,
					size_t name_offset, const char **ret)
{
	struct drgn_error *err;
	Elf_Data *data;
	const char *p, *nul;

	if (this_module_scn) {
		err = read_elf_section(this_module_scn, &data);
		if (err)
			return err;
		if (name_offset < data->d_size) {
			p = data->d_buf + name_offset;
			nul = memchr(p, 0, data->d_size - name_offset);
			if (nul && nul != p) {
				*ret = p;
				return NULL;
			}
		}
	}
	*ret = NULL;
	return NULL;
}

DEFINE_HASH_MAP(elf_scn_name_map, const char *, Elf_Scn *,
		c_string_key_hash_pair, c_string_key_eq)

static struct drgn_error *
cache_kernel_module_sections(struct kernel_module_iterator *kmod_it, Elf *elf,
			     uint64_t *start_ret, uint64_t *end_ret)
{
	struct drgn_error *err;

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	struct elf_scn_name_map scn_map = HASH_TABLE_INIT;
	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr shdr_mem;
		GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr) {
			err = drgn_error_libelf();
			goto out_scn_map;
		}

		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		struct elf_scn_name_map_entry entry = {
			.key = elf_strptr(elf, shstrndx, shdr->sh_name),
			.value = scn,
		};
		if (!entry.key) {
			err = drgn_error_libelf();
			goto out_scn_map;
		}

		if (elf_scn_name_map_insert(&scn_map, &entry, NULL) == -1) {
			err = &drgn_enomem;
			goto out_scn_map;
		}
	}

	uint64_t start = UINT64_MAX, end = 0;
	struct kernel_module_section_iterator section_it;
	err = kernel_module_section_iterator_init(&section_it, kmod_it);
	if (err)
		goto out_scn_map;
	const char *name;
	uint64_t address;
	while (!(err = kernel_module_section_iterator_next(&section_it, &name,
							   &address))) {
		struct elf_scn_name_map_iterator it =
			elf_scn_name_map_search(&scn_map, &name);
		if (it.entry) {
			GElf_Shdr shdr_mem;
			GElf_Shdr *shdr = gelf_getshdr(it.entry->value,
						       &shdr_mem);
			if (!shdr) {
				err = drgn_error_libelf();
				break;
			}
			shdr->sh_addr = address;
			if (!gelf_update_shdr(it.entry->value, shdr)) {
				err = drgn_error_libelf();
				break;
			}
			/*
			 * .init sections are freed once the module is
			 * initialized, but they remain in the section list.
			 * Ignore them for the purpose of determining the
			 * module's address range.
			 */
			if (!strstartswith(name, ".init")) {
				uint64_t section_end;
				if (__builtin_add_overflow(address,
							   shdr->sh_size,
							   &section_end))
					section_end = UINT64_MAX;
				if (address < section_end) {
					if (address < start)
						start = address;
					if (section_end > end)
						end = section_end;
				}
			}
		}
	}
	if (err && err != &drgn_stop)
		goto out_section_it;
	err = NULL;
	if (start >= end)
		start = end = 0;
	*start_ret = start;
	*end_ret = end;
out_section_it:
	kernel_module_section_iterator_deinit(&section_it);
out_scn_map:
	elf_scn_name_map_deinit(&scn_map);
	return err;
}

struct kernel_module_file {
	const char *path;
	int fd;
	Elf *elf;
	/*
	 * Kernel module name. This is owned by the Elf handle. Because we use
	 * this as the key in the kernel_module_table, the file must always be
	 * removed from the table before it is reported to the DWARF index
	 * (which takes ownership of the Elf handle).
	 */
	const char *name;
	Elf_Scn *this_module_scn;
	/* Next file with the same name. */
	struct kernel_module_file *next;
};

static const char *
kernel_module_table_key(struct kernel_module_file * const *entry)
{
	return (*entry)->name;
}

DEFINE_HASH_TABLE(kernel_module_table, struct kernel_module_file *,
		  kernel_module_table_key, c_string_key_hash_pair,
		  c_string_key_eq)

static struct drgn_error *
report_loaded_kernel_module(struct drgn_debug_info_load_state *load,
			    struct kernel_module_iterator *kmod_it,
			    struct kernel_module_table *kmod_table)
{
	struct drgn_error *err;

	const char *name = kmod_it->name;
	struct hash_pair hp = kernel_module_table_hash(&name);
	struct kernel_module_table_iterator it =
		kernel_module_table_search_hashed(kmod_table, &name, hp);
	if (!it.entry)
		return &drgn_not_found;

	struct kernel_module_file *kmod = *it.entry;
	kernel_module_table_delete_iterator_hashed(kmod_table, it, hp);
	do {
		uint64_t start, end;
		err = cache_kernel_module_sections(kmod_it, kmod->elf, &start,
						   &end);
		if (err) {
			err = drgn_debug_info_report_error(load, kmod->path,
							   "could not get section addresses",
							   err);
			if (err)
				return err;
			goto next;
		}

		err = drgn_debug_info_report_elf(load, kmod->path, kmod->fd,
						 kmod->elf, start, end,
						 kmod->name, NULL);
		kmod->elf = NULL;
		kmod->fd = -1;
		if (err)
			return err;
next:
		kmod = kmod->next;
	} while (kmod);
	return NULL;
}

static struct drgn_error *
report_default_kernel_module(struct drgn_debug_info_load_state *load,
			     struct kernel_module_iterator *kmod_it,
			     struct depmod_index *depmod)
{
	static const char * const module_paths[] = {
		"/usr/lib/debug/lib/modules/%s/%.*s",
		"/usr/lib/debug/lib/modules/%s/%.*s.debug",
		"/lib/modules/%s/%.*s%.*s",
		NULL,
	};
	struct drgn_error *err;

	const char *depmod_path;
	size_t depmod_path_len;
	err = depmod_index_find(depmod, kmod_it->name, &depmod_path,
				&depmod_path_len);
	if (err) {
		return drgn_debug_info_report_error(load,
						    "kernel modules",
						    "could not parse depmod",
						    err);
	} else if (!depmod_path) {
		return drgn_debug_info_report_error(load, kmod_it->name,
						    "could not find module in depmod",
						    NULL);
	}

	size_t extension_len;
	if (depmod_path_len >= 3 &&
	    (memcmp(depmod_path + depmod_path_len - 3, ".gz", 3) == 0 ||
	     memcmp(depmod_path + depmod_path_len - 3, ".xz", 3) == 0))
		extension_len = 3;
	else
		extension_len = 0;
	char *path;
	int fd;
	Elf *elf;
	err = find_elf_file(&path, &fd, &elf, module_paths,
			    load->dbinfo->prog->vmcoreinfo.osrelease,
			    depmod_path_len - extension_len, depmod_path,
			    extension_len,
			    depmod_path + depmod_path_len - extension_len);
	if (err)
		return drgn_debug_info_report_error(load, NULL, NULL, err);
	if (!elf) {
		return drgn_debug_info_report_error(load, kmod_it->name,
						    "could not find .ko",
						    NULL);
	}

	uint64_t start, end;
	err = cache_kernel_module_sections(kmod_it, elf, &start, &end);
	if (err) {
		err = drgn_debug_info_report_error(load, path,
						   "could not get section addresses",
						   err);
		elf_end(elf);
		close(fd);
		free(path);
		return err;
	}

	err = drgn_debug_info_report_elf(load, path, fd, elf, start, end,
					 kmod_it->name, NULL);
	free(path);
	return err;
}

static struct drgn_error *
report_loaded_kernel_modules(struct drgn_debug_info_load_state *load,
			     struct kernel_module_table *kmod_table,
			     struct depmod_index *depmod,
			     bool use_proc_and_sys)
{
	struct drgn_program *prog = load->dbinfo->prog;
	struct drgn_error *err;

	struct kernel_module_iterator kmod_it;
	err = kernel_module_iterator_init(&kmod_it, prog, use_proc_and_sys);
	if (err) {
kernel_module_iterator_error:
		return drgn_debug_info_report_error(load, "kernel modules",
						    "could not find loaded kernel modules",
						    err);
	}
	for (;;) {
		err = kernel_module_iterator_next(&kmod_it);
		if (err == &drgn_stop) {
			err = NULL;
			break;
		} else if (err) {
			kernel_module_iterator_deinit(&kmod_it);
			goto kernel_module_iterator_error;
		}

		/* Look for an explicitly-reported file first. */
		if (kmod_table) {
			err = report_loaded_kernel_module(load, &kmod_it,
							  kmod_table);
			if (!err)
				continue;
			else if (err != &drgn_not_found)
				break;
		}

		/*
		 * If it was not reported explicitly and we're also reporting the
		 * defaults, look for the module at the standard locations unless we've
		 * already indexed that module.
		 */
		if (depmod &&
		    !drgn_debug_info_is_indexed(load->dbinfo, kmod_it.name)) {
			if (!depmod->addr) {
				err = depmod_index_init(depmod,
							prog->vmcoreinfo.osrelease);
				if (err) {
					depmod->addr = NULL;
					err = drgn_debug_info_report_error(load,
									   "kernel modules",
									   "could not read depmod",
									   err);
					if (err)
						break;
					depmod = NULL;
					continue;
				}
			}
			err = report_default_kernel_module(load, &kmod_it,
							   depmod);
			if (err)
				break;
		}
	}
	kernel_module_iterator_deinit(&kmod_it);
	return err;
}

static struct drgn_error *
report_kernel_modules(struct drgn_debug_info_load_state *load,
		      struct kernel_module_file *kmods, size_t num_kmods,
		      bool need_module_definition, bool vmlinux_is_pending)
{
	struct drgn_program *prog = load->dbinfo->prog;
	struct drgn_error *err;

	if (!num_kmods && !load->load_default)
		return NULL;

	/*
	 * If we're debugging the running kernel, we can get the loaded kernel
	 * modules from /proc and /sys instead of from the core dump. This fast
	 * path can be disabled via an environment variable for testing.
	 */
	bool use_proc_and_sys = false;
	if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
		char *env = getenv("DRGN_USE_PROC_AND_SYS_MODULES");
		use_proc_and_sys = !env || atoi(env);
	}
	/*
	 * If we're not using /proc and /sys, then we need to index vmlinux now
	 * so that we can walk the list of modules in the kernel.
	 *
	 * If we need the definition of struct module to get the name of any
	 * kernel modules, then we also need to index vmlinux now.
	 */
	if (vmlinux_is_pending &&
	    (!use_proc_and_sys || need_module_definition)) {
		err = drgn_debug_info_report_flush(load);
		if (err)
			return err;
	}

	size_t module_name_offset = 0;
	if (need_module_definition) {
		struct drgn_qualified_type module_type;
		struct drgn_type_member *name_member;
		uint64_t name_bit_offset;
		err = drgn_program_find_type(prog, "struct module", NULL,
					     &module_type);
		if (!err) {
			err = drgn_type_find_member(module_type.type, "name",
						    &name_member,
						    &name_bit_offset);
		}
		if (err) {
			return drgn_debug_info_report_error(load,
							    "kernel modules",
							    "could not get kernel module names",
							    err);
		}
		module_name_offset = name_bit_offset / 8;
	}

	struct kernel_module_table kmod_table = HASH_TABLE_INIT;
	struct depmod_index depmod;
	depmod.addr = NULL;
	struct kernel_module_table_iterator it;
	for (size_t i = 0; i < num_kmods; i++) {
		struct kernel_module_file *kmod = &kmods[i];
		if (!kmod->name) {
			err = get_kernel_module_name_from_this_module(kmod->this_module_scn,
								      module_name_offset,
								      &kmod->name);
			if (err) {
				err = drgn_debug_info_report_error(load,
								   kmod->path,
								   NULL, err);
				if (err)
					goto out;
				continue;
			}
			if (!kmod->name) {
				err = drgn_debug_info_report_error(load,
								   kmod->path,
								   "could not find kernel module name",
								   NULL);
				if (err)
					goto out;
				continue;
			}
		}

		struct hash_pair hp = kernel_module_table_hash(&kmod->name);
		it = kernel_module_table_search_hashed(&kmod_table, &kmod->name,
						       hp);
		if (it.entry) {
			kmod->next = *it.entry;
			*it.entry = kmod;
		} else {
			if (kernel_module_table_insert_searched(&kmod_table,
								&kmod, hp,
								NULL) == -1) {
				err = &drgn_enomem;
				goto out;
			}
			kmod->next = NULL;
		}
	}

	err = report_loaded_kernel_modules(load,
					   num_kmods ? &kmod_table : NULL,
					   load->load_default ? &depmod : NULL,
					   use_proc_and_sys);
	if (err)
		goto out;

	/* Anything left over was not loaded. */
	for (it = kernel_module_table_first(&kmod_table); it.entry; ) {
		struct kernel_module_file *kmod = *it.entry;
		it = kernel_module_table_delete_iterator(&kmod_table, it);
		do {
			err = drgn_debug_info_report_elf(load, kmod->path,
							 kmod->fd, kmod->elf, 0,
							 0, kmod->name, NULL);
			kmod->elf = NULL;
			kmod->fd = -1;
			if (err)
				goto out;
			kmod = kmod->next;
		} while (kmod);
	}
	err = NULL;
out:
	if (depmod.addr)
		depmod_index_deinit(&depmod);
	kernel_module_table_deinit(&kmod_table);
	return err;
}

static struct drgn_error *
report_vmlinux(struct drgn_debug_info_load_state *load,
	       bool *vmlinux_is_pending)
{
	static const char * const vmlinux_paths[] = {
		/*
		 * The files under /usr/lib/debug should always have debug
		 * information, so check for those first.
		 */
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
		"/boot/vmlinux-%s",
		"/lib/modules/%s/build/vmlinux",
		"/lib/modules/%s/vmlinux",
		NULL,
	};
	struct drgn_program *prog = load->dbinfo->prog;
	struct drgn_error *err;

	char *path;
	int fd;
	Elf *elf;
	err = find_elf_file(&path, &fd, &elf, vmlinux_paths,
			    prog->vmcoreinfo.osrelease);
	if (err)
		return drgn_debug_info_report_error(load, NULL, NULL, err);
	if (!elf) {
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"could not find vmlinux for %s",
					prog->vmcoreinfo.osrelease);
		return drgn_debug_info_report_error(load, "kernel", NULL, err);
	}

	uint64_t start, end;
	err = elf_address_range(elf, prog->vmcoreinfo.kaslr_offset, &start,
				&end);
	if (err) {
		err = drgn_debug_info_report_error(load, path, NULL, err);
		elf_end(elf);
		close(fd);
		free(path);
		return err;
	}

	err = drgn_debug_info_report_elf(load, path, fd, elf, start, end,
					 "kernel", vmlinux_is_pending);
	free(path);
	return err;
}

struct drgn_error *
linux_kernel_report_debug_info(struct drgn_debug_info_load_state *load)
{
	struct drgn_program *prog = load->dbinfo->prog;
	struct drgn_error *err;

	struct kernel_module_file *kmods;
	if (load->num_paths) {
		kmods = malloc_array(load->num_paths, sizeof(*kmods));
		if (!kmods)
			return &drgn_enomem;
	} else {
		kmods = NULL;
	}

	/*
	 * We may need to index vmlinux before we can properly report kernel
	 * modules. So, this sets aside kernel modules and reports everything
	 * else.
	 */
	size_t num_kmods = 0;
	bool need_module_definition = false;
	bool vmlinux_is_pending = false;
	for (size_t i = 0; i < load->num_paths; i++) {
		const char *path = load->paths[i];
		int fd;
		Elf *elf;
		err = open_elf_file(path, &fd, &elf);
		if (err) {
			err = drgn_debug_info_report_error(load, path, NULL,
							   err);
			if (err)
				goto out;
			continue;
		}

		Elf_Scn *this_module_scn, *modinfo_scn;
		bool is_vmlinux;
		err = identify_kernel_elf(elf, &this_module_scn, &modinfo_scn,
					  &is_vmlinux);
		if (err) {
			err = drgn_debug_info_report_error(load, path, NULL,
							   err);
			elf_end(elf);
			close(fd);
			if (err)
				goto out;
			continue;
		}
		if (this_module_scn || modinfo_scn) {
			struct kernel_module_file *kmod = &kmods[num_kmods++];
			kmod->path = path;
			kmod->fd = fd;
			kmod->elf = elf;
			err = get_kernel_module_name_from_modinfo(modinfo_scn,
								  &kmod->name);
			if (err) {
				err = drgn_debug_info_report_error(load, path,
								   NULL, err);
				if (err)
					goto out;
				continue;
			}
			if (!kmod->name) {
				kmod->this_module_scn = this_module_scn;
				need_module_definition = true;
			}
		} else if (is_vmlinux) {
			uint64_t start, end;
			err = elf_address_range(elf,
						prog->vmcoreinfo.kaslr_offset,
						&start, &end);
			if (err) {
				elf_end(elf);
				close(fd);
				err = drgn_debug_info_report_error(load, path,
								   NULL, err);
				if (err)
					goto out;
				continue;
			}

			bool is_new;
			err = drgn_debug_info_report_elf(load, path, fd, elf,
							 start, end, "kernel",
							 &is_new);
			if (err)
				goto out;
			if (is_new)
				vmlinux_is_pending = true;
		} else {
			err = drgn_debug_info_report_elf(load, path, fd, elf, 0,
							 0, NULL, NULL);
			if (err)
				goto out;
		}
	}

	if (load->load_main && !vmlinux_is_pending &&
	    !drgn_debug_info_is_indexed(load->dbinfo, "kernel")) {
		err = report_vmlinux(load, &vmlinux_is_pending);
		if (err)
			goto out;
	}

	err = report_kernel_modules(load, kmods, num_kmods,
				    need_module_definition, vmlinux_is_pending);
out:
	for (size_t i = 0; i < num_kmods; i++) {
		elf_end(kmods[i].elf);
		if (kmods[i].fd != -1)
			close(kmods[i].fd);
	}
	free(kmods);
	return err;
}
