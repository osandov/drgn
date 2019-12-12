// Copyright 2018-2019 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "internal.h"
#include "dwarf_index.h"
#include "linux_kernel.h"
#include "program.h"
#include "read.h"

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
	/* KERNELOFFSET is optional. */
	return NULL;
}

static struct drgn_error *proc_kallsyms_symbol_addr(const char *name,
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
				err = drgn_error_format(DRGN_ERROR_OTHER,
							"could not find %s symbol in /proc/kallsyms",
							name);
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
 * /proc/kcore") (in v4.19), /proc/kcore didn't have a VMCOREINFO note, so we
 * have to get it by other means. Since Linux kernel commit 464920104bf7
 * ("/proc/kcore: update physical address for kcore ram and text") (in v4.11),
 * we can read from the physical address of the vmcoreinfo note exported in
 * sysfs. Before that, p_paddr in /proc/kcore is always zero, but we can read
 * from the virtual address in /proc/kallsyms.
 */
struct drgn_error *read_vmcoreinfo_fallback(struct drgn_memory_reader *reader,
					    bool have_non_zero_phys_addr,
					    struct vmcoreinfo *ret)
{
	struct drgn_error *err;
	FILE *file;
	unsigned long address;
	size_t size;
	char *buf;
	Elf64_Nhdr *nhdr;

	file = fopen("/sys/kernel/vmcoreinfo", "r");
	if (!file) {
		return drgn_error_create_os("fopen", errno,
					    "/sys/kernel/vmcoreinfo");
	}
	if (fscanf(file, "%lx %zx", &address, &size) != 2) {
		fclose(file);
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "could not parse /sys/kernel/vmcoreinfo");
	}
	fclose(file);

	if (!have_non_zero_phys_addr) {
		/*
		 * Since Linux kernel commit 203e9e41219b ("kexec: move
		 * vmcoreinfo out of the kernel's .bss section") (in v4.13),
		 * vmcoreinfo_note is a pointer; before that, it is an array. We
		 * only do this for kernels before v4.11, so we can assume that
		 * it's an array.
		 */
		err = proc_kallsyms_symbol_addr("vmcoreinfo_note", &address);
		if (err)
			return err;
	}

	buf = malloc(size);
	if (!buf)
		return &drgn_enomem;

	err = drgn_memory_reader_read(reader, buf, address, size,
				      have_non_zero_phys_addr);
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

	err = parse_vmcoreinfo(buf + 24, nhdr->n_descsz, ret);
out:
	free(buf);
	return err;
}

static struct drgn_error *
vmcoreinfo_object_find(const char *name, size_t name_len, const char *filename,
		       enum drgn_find_object_flags flags, void *arg,
		       struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = arg;

	if (!filename && (flags & DRGN_FIND_OBJECT_CONSTANT)) {
		struct drgn_qualified_type qualified_type = {};

		if (name_len == strlen("PAGE_SHIFT") &&
		    memcmp(name, "PAGE_SHIFT", name_len) == 0) {
			err = drgn_type_index_find_primitive(&prog->tindex,
							     DRGN_C_TYPE_INT,
							     &qualified_type.type);
			if (err)
				return err;
			return drgn_object_set_signed(ret, qualified_type,
						      ctz(prog->vmcoreinfo.page_size),
						      0);
		} else if (name_len == strlen("PAGE_SIZE") &&
			   memcmp(name, "PAGE_SIZE", name_len) == 0) {
			err = drgn_type_index_find_primitive(&prog->tindex,
							     DRGN_C_TYPE_UNSIGNED_LONG,
							     &qualified_type.type);
			if (err)
				return err;
			return drgn_object_set_unsigned(ret, qualified_type,
							prog->vmcoreinfo.page_size,
							0);
		} else if (name_len == strlen("PAGE_MASK") &&
			   memcmp(name, "PAGE_MASK", name_len) == 0) {
			err = drgn_type_index_find_primitive(&prog->tindex,
							     DRGN_C_TYPE_UNSIGNED_LONG,
							     &qualified_type.type);
			if (err)
				return err;
			return drgn_object_set_unsigned(ret, qualified_type,
							~(prog->vmcoreinfo.page_size - 1),
							0);
		}
	}
	return &drgn_not_found;
}

struct kernel_module_iterator {
	char *name;
	FILE *file;
	char *notes;
	size_t notes_len, notes_capacity;
	union {
		struct {
			size_t name_capacity;
			uint64_t start, end;
		};
		struct {
			struct drgn_qualified_type module_type;
			struct drgn_object mod, node, tmp1, tmp2, tmp3;
			uint64_t head;
		};
	};
};

static void kernel_module_iterator_deinit(struct kernel_module_iterator *it)
{
	if (it->file) {
		fclose(it->file);
	} else {
		drgn_object_deinit(&it->tmp3);
		drgn_object_deinit(&it->tmp2);
		drgn_object_deinit(&it->tmp1);
		drgn_object_deinit(&it->node);
		drgn_object_deinit(&it->mod);
	}
	free(it->notes);
	free(it->name);
}

static struct drgn_error *
kernel_module_iterator_init(struct kernel_module_iterator *it,
			    struct drgn_program *prog)
{
	struct drgn_error *err;

	it->name = NULL;
	it->notes = NULL;
	it->notes_len = it->notes_capacity = 0;
	if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
		it->file = fopen("/proc/modules", "r");
		if (!it->file) {
			return drgn_error_create_os("fopen", errno,
						    "/proc/modules");
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
	ssize_t ret;
	char *p;
	size_t size;

	errno = 0;
	ret = getline(&it->name, &it->name_capacity, it->file);
	if (ret == -1) {
		if (errno) {
			return drgn_error_create_os("getline", errno,
						    "/proc/modules");
		} else {
			return &drgn_stop;
		}
	}
	p = strchr(it->name, ' ');
	if (!p || sscanf(p + 1, "%zu %*s %*s %*s %" SCNx64, &size,
			 &it->start) != 2) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "could not parse /proc/modules");
	}
	*p = '\0';
	it->end = it->start + size;
	return NULL;
}

static struct drgn_error *
kernel_module_iterator_next_offline(struct kernel_module_iterator *it)
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

	err = drgn_object_member_dereference(&it->tmp1, &it->mod, "name");
	if (err)
		return err;
	err = drgn_object_read_c_string(&it->tmp1, &name);
	if (err)
		return err;
	free(it->name);
	it->name = name;
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
 * are no more modules, a @ref DRGN_ERROR_STOP error is returned.
 */
static struct drgn_error *
kernel_module_iterator_next(struct kernel_module_iterator *it)
{
	if (it->file)
		return kernel_module_iterator_next_live(it);
	else
		return kernel_module_iterator_next_offline(it);
}

struct kernel_module_section_iterator {
	struct kernel_module_iterator *kmod_it;
	DIR *dir;
	union {
		int dirfd;
		struct {
			uint64_t i;
			uint64_t nsections;
			char *name;
		};
	};
};

static struct drgn_error *
kernel_module_section_iterator_init(struct kernel_module_section_iterator *it,
				    struct kernel_module_iterator *kmod_it)
{
	struct drgn_error *err;

	it->kmod_it = kmod_it;
	if (kmod_it->file) {
		char *path;

		if (asprintf(&path, "/sys/module/%s/sections",
			     kmod_it->name) == -1)
			return &drgn_enomem;
		it->dir = opendir(path);
		free(path);
		if (!it->dir) {
			err = drgn_error_format_os("opendir", errno,
						   "/sys/module/%s/sections",
						   kmod_it->name);
			return err;
		}
		it->dirfd = dirfd(it->dir);
		if (it->dirfd == -1) {
			err = drgn_error_format_os("dirfd", errno,
						   "/sys/module/%s/sections",
						   kmod_it->name);
			closedir(it->dir);
			return err;
		}
		return NULL;
	} else {
		it->dir = NULL;
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
	if (it->dir)
		closedir(it->dir);
	else
		free(it->name);
}

static struct drgn_error *
kernel_module_section_iterator_next_live(struct kernel_module_section_iterator *it,
					 const char **name_ret,
					 uint64_t *address_ret)
{
	struct dirent *ent;

	while ((errno = 0, ent = readdir(it->dir))) {
		int fd;
		FILE *file;
		int ret;

		if (ent->d_type == DT_DIR)
			continue;
		if (ent->d_type == DT_UNKNOWN) {
			struct stat st;

			if (fstatat(it->dirfd, ent->d_name, &st, 0) == -1) {
				return drgn_error_format_os("fstatat", errno,
							    "/sys/module/%s/sections/%s",
							    it->kmod_it->name,
							    ent->d_name);
			}
			if (S_ISDIR(st.st_mode))
				continue;
		}

		fd = openat(it->dirfd, ent->d_name, O_RDONLY);
		if (fd == -1) {
			return drgn_error_format_os("openat", errno,
						    "/sys/module/%s/sections/%s",
						    it->kmod_it->name,
						    ent->d_name);
		}
		file = fdopen(fd, "r");
		if (!file) {
			close(fd);
			return drgn_error_create_os("fdopen", errno, NULL);
		}
		ret = fscanf(file, "%" SCNx64, address_ret);
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
kernel_module_section_iterator_next_offline(struct kernel_module_section_iterator *it,
					    const char **name_ret,
					    uint64_t *address_ret)
{
	struct drgn_error *err;
	struct kernel_module_iterator *kmod_it = it->kmod_it;
	char *name;

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
	err = drgn_object_member(&kmod_it->tmp3, &kmod_it->tmp2, "name");
	if (err)
		return err;
	err = drgn_object_read_c_string(&kmod_it->tmp3, &name);
	if (err)
		return err;
	free(it->name);
	*name_ret = it->name = name;
	return NULL;
}

static struct drgn_error *
kernel_module_section_iterator_next(struct kernel_module_section_iterator *it,
				    const char **name_ret,
				    uint64_t *address_ret)
{
	if (it->dir) {
		return kernel_module_section_iterator_next_live(it, name_ret,
								address_ret);
	} else {
		return kernel_module_section_iterator_next_offline(it, name_ret,
								   address_ret);
	}
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

struct kmod_index {
	const char *ptr, *end;
};

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
		return drgn_error_create_os("open", errno, path);

	if (fstat(fd, &st) == -1) {
		err = drgn_error_create_os("fstat", errno, path);
		goto out;
	}

	if (st.st_size < 0 || st.st_size > SIZE_MAX) {
		err = &drgn_enomem;
		goto out;
	}

	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		err = drgn_error_create_os("mmap", errno, path);
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

struct depmod_index {
	struct kmod_index modules_dep;
};

static struct drgn_error *depmod_index_init(struct depmod_index *depmod,
					    const char *osrelease)
{
	char path[256];

	snprintf(path, sizeof(path), "/lib/modules/%s/modules.dep.bin",
		 osrelease);
	return kmod_index_init(&depmod->modules_dep, path);
}

static void depmod_index_deinit(struct depmod_index *depmod)
{
	kmod_index_deinit(&depmod->modules_dep);
}

/*
 * Look up the path of the kernel module with the given name.
 *
 * @param[in] name Name of the kernel module.
 * @param[out] path_ret Returned path of the kernel module, relative to
 * /lib/modules/$(uname -r). This is @em not null-terminated.
 * @param[out] len_ret Returned length of @p path_ret.
 * @return Whether the module was found.
 */
static bool depmod_index_find(struct depmod_index *depmod, const char *name,
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
			continue;
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
			if (strstartswith(p, "name=") == 0) {
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

DEFINE_HASH_MAP(elf_scn_name_map, const char *, Elf_Scn *, c_string_hash,
		c_string_eq)

static struct drgn_error *
cache_kernel_module_sections(struct kernel_module_iterator *kmod_it, Elf *elf,
			     uint64_t *start_ret, uint64_t *end_ret)
{
	struct drgn_error *err;
	uint64_t start = UINT64_MAX, end = 0;
	size_t shstrndx;
	Elf_Scn *scn = NULL;
	struct elf_scn_name_map scn_map;
	struct kernel_module_section_iterator section_it;
	const char *name;
	uint64_t address;

	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	elf_scn_name_map_init(&scn_map);
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr *shdr, shdr_mem;
		struct elf_scn_name_map_entry entry;

		shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr) {
			err = drgn_error_libelf();
			goto out_scn_map;
		}

		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		entry.key = elf_strptr(elf, shstrndx, shdr->sh_name);
		/*
		 * .init sections are freed once the module is initialized, but
		 * they remain in the section list. Ignore them so we don't get
		 * confused if the address gets reused for another module.
		 */
		if (!entry.key || strstartswith(entry.key, ".init"))
			continue;
		entry.value = scn;

		if (elf_scn_name_map_insert(&scn_map, &entry, NULL) == -1) {
			err = &drgn_enomem;
			goto out_scn_map;
		}
	}

	err = kernel_module_section_iterator_init(&section_it, kmod_it);
	if (err)
		goto out_scn_map;
	while (!(err = kernel_module_section_iterator_next(&section_it, &name,
							   &address))) {
		struct elf_scn_name_map_iterator it;

		it = elf_scn_name_map_search(&scn_map, &name);
		if (it.entry) {
			GElf_Shdr *shdr, shdr_mem;
			uint64_t section_end;

			shdr = gelf_getshdr(it.entry->value, &shdr_mem);
			if (!shdr) {
				err = drgn_error_libelf();
				break;
			}
			shdr->sh_addr = address;
			if (!gelf_update_shdr(it.entry->value, shdr)) {
				err = drgn_error_libelf();
				break;
			}
			if (__builtin_add_overflow(address, shdr->sh_size,
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
	if (err && err->code != DRGN_ERROR_STOP)
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
		  kernel_module_table_key, c_string_hash, c_string_eq)

static struct drgn_error *
report_loaded_kernel_module(struct drgn_program *prog,
			    struct drgn_dwarf_index *dindex,
			    struct kernel_module_iterator *kmod_it,
			    struct kernel_module_table *kmod_table)
{
	struct drgn_error *err;
	const char *name = kmod_it->name;
	struct hash_pair hp;
	struct kernel_module_table_iterator it;
	struct kernel_module_file *kmod;

	hp = kernel_module_table_hash(&name);
	it = kernel_module_table_search_hashed(kmod_table, &name, hp);
	if (!it.entry)
		return &drgn_not_found;

	kmod = *it.entry;
	kernel_module_table_delete_iterator_hashed(kmod_table, it, hp);
	do {
		uint64_t start, end;

		err = cache_kernel_module_sections(kmod_it, kmod->elf, &start,
						   &end);
		if (err) {
			err = drgn_dwarf_index_report_error(dindex,
							    kmod->path,
							    "could not get section addresses",
							    err);
			if (err)
				return err;
			continue;
		}

		err = drgn_dwarf_index_report_elf(dindex, kmod->path, kmod->fd,
						  kmod->elf, start, end,
						  kmod->name, NULL);
		kmod->elf = NULL;
		kmod->fd = -1;
		if (err)
			return err;
		kmod = kmod->next;
	} while (kmod);
	return NULL;
}

static struct drgn_error *
report_default_kernel_module(struct drgn_program *prog,
			     struct drgn_dwarf_index *dindex,
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
	size_t extension_len;
	char *path;
	int fd;
	Elf *elf;
	uint64_t start, end;

	if (!depmod_index_find(depmod, kmod_it->name, &depmod_path,
			       &depmod_path_len)) {
		return drgn_dwarf_index_report_error(dindex, kmod_it->name,
						     "could not find module in depmod",
						     NULL);
	}

	if (depmod_path_len >= 3 &&
	    (memcmp(depmod_path + depmod_path_len - 3, ".gz", 3) == 0 ||
	     memcmp(depmod_path + depmod_path_len - 3, ".xz", 3) == 0))
		extension_len = 3;
	else
		extension_len = 0;
	err = find_elf_file(&path, &fd, &elf, module_paths,
			    prog->vmcoreinfo.osrelease,
			    depmod_path_len - extension_len, depmod_path,
			    extension_len,
			    depmod_path + depmod_path_len - extension_len);
	if (err)
		return drgn_dwarf_index_report_error(dindex, NULL, NULL, err);
	if (!elf) {
		return drgn_dwarf_index_report_error(dindex, kmod_it->name,
						     "could not find .ko",
						     NULL);
	}

	err = cache_kernel_module_sections(kmod_it, elf, &start, &end);
	if (err) {
		elf_end(elf);
		close(fd);
		free(path);
		return drgn_dwarf_index_report_error(dindex, path,
						     "could not get section addresses",
						     err);
	}

	err = drgn_dwarf_index_report_elf(dindex, path, fd, elf, start, end,
					  kmod_it->name, NULL);
	free(path);
	return err;
}

static struct drgn_error *
report_loaded_kernel_modules(struct drgn_program *prog,
			     struct drgn_dwarf_index *dindex,
			     struct kernel_module_table *kmod_table,
			     struct depmod_index *depmod)
{
	struct drgn_error *err;
	struct kernel_module_iterator kmod_it;

	err = kernel_module_iterator_init(&kmod_it, prog);
	if (err) {
kernel_module_iterator_error:
		return drgn_dwarf_index_report_error(dindex, "kernel modules",
						     "could not find loaded kernel modules",
						     err);
	}
	for (;;) {
		err = kernel_module_iterator_next(&kmod_it);
		if (err && err->code == DRGN_ERROR_STOP) {
			err = NULL;
			break;
		} else if (err) {
			kernel_module_iterator_deinit(&kmod_it);
			goto kernel_module_iterator_error;
		}

		/* Look for an explicitly-reported file first. */
		if (kmod_table) {
			err = report_loaded_kernel_module(prog, dindex,
							  &kmod_it, kmod_table);
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
		    !drgn_dwarf_index_is_indexed(dindex, kmod_it.name)) {
			if (!depmod->modules_dep.ptr) {
				err = depmod_index_init(depmod,
							prog->vmcoreinfo.osrelease);
				if (err) {
					depmod->modules_dep.ptr = NULL;
					err = drgn_dwarf_index_report_error(dindex,
									    "kernel modules",
									    "could not read depmod",
									    err);
					if (err)
						break;
					depmod = NULL;
					continue;
				}
			}
			err = report_default_kernel_module(prog, dindex,
							   &kmod_it, depmod);
			if (err)
				break;
		}
	}
	kernel_module_iterator_deinit(&kmod_it);
	return err;
}

static struct drgn_error *
report_kernel_modules(struct drgn_program *prog,
		      struct drgn_dwarf_index *dindex,
		      struct kernel_module_file *kmods, size_t num_kmods,
		      bool report_default, bool need_module_definition,
		      bool vmlinux_is_pending)
{
	struct drgn_error *err;
	struct kernel_module_table kmod_table;
	struct depmod_index depmod;
	size_t module_name_offset = 0;
	size_t i;
	struct kernel_module_table_iterator it;

	if (!num_kmods && !report_default)
		return NULL;

	/*
	 * If we're not debugging the running kernel, then we need to index
	 * vmlinux now so that we can walk the list of modules in the kernel.
	 *
	 * If we need the definition of struct module to get the name of any
	 * kernel modules, then we also need to index vmlinux now.
	 */
	if (vmlinux_is_pending &&
	    (!(prog->flags & DRGN_PROGRAM_IS_LIVE) || need_module_definition)) {
		err = drgn_dwarf_index_flush(dindex, false);
		if (err)
			return err;
	}

	if (need_module_definition) {
		struct drgn_qualified_type module_type;
		struct drgn_member_info name_member;

		err = drgn_program_find_type(prog, "struct module", NULL,
					     &module_type);
		if (!err) {
			err = drgn_program_member_info(prog, module_type.type,
						       "name", &name_member);
		}
		if (err) {
			return drgn_dwarf_index_report_error(dindex,
							     "kernel modules",
							     "could not get kernel module names",
							     err);
		}
		module_name_offset = name_member.bit_offset / 8;
	}

	kernel_module_table_init(&kmod_table);
	depmod.modules_dep.ptr = NULL;
	for (i = 0; i < num_kmods; i++) {
		struct kernel_module_file *kmod = &kmods[i];
		struct hash_pair hp;

		if (!kmod->name) {
			err = get_kernel_module_name_from_this_module(kmod->this_module_scn,
								      module_name_offset,
								      &kmod->name);
			if (err) {
				err = drgn_dwarf_index_report_error(dindex,
								    kmod->path,
								    NULL, err);
				if (err)
					goto out;
				continue;
			}
			if (!kmod->name) {
				err = drgn_dwarf_index_report_error(dindex,
								    kmod->path,
								    "could not find kernel module name",
								    NULL);
				if (err)
					goto out;
				continue;
			}
		}

		hp = kernel_module_table_hash(&kmod->name);
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

	err = report_loaded_kernel_modules(prog, dindex,
					   num_kmods ? &kmod_table : NULL,
					   report_default ? &depmod : NULL);
	if (err)
		goto out;

	/* Anything left over was not loaded. */
	for (it = kernel_module_table_first(&kmod_table); it.entry; ) {
		struct kernel_module_file *kmod = *it.entry;

		it = kernel_module_table_delete_iterator(&kmod_table, it);
		do {
			err = drgn_dwarf_index_report_elf(dindex, kmod->path,
							  kmod->fd, kmod->elf,
							  0, 0, kmod->name,
							  NULL);
			kmod->elf = NULL;
			kmod->fd = -1;
			if (err)
				goto out;
			kmod = kmod->next;
		} while (kmod);
	}
	err = NULL;
out:
	if (depmod.modules_dep.ptr)
		depmod_index_deinit(&depmod);
	kernel_module_table_deinit(&kmod_table);
	return err;
}

static struct drgn_error *report_vmlinux(struct drgn_program *prog,
					 struct drgn_dwarf_index *dindex,
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
	struct drgn_error *err;
	char *path;
	int fd;
	Elf *elf;
	uint64_t start, end;

	err = find_elf_file(&path, &fd, &elf, vmlinux_paths,
			    prog->vmcoreinfo.osrelease);
	if (err)
		return drgn_dwarf_index_report_error(dindex, NULL, NULL, err);
	if (!elf) {
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"could not find vmlinux for %s",
					prog->vmcoreinfo.osrelease);
		return drgn_dwarf_index_report_error(dindex, "kernel", NULL,
						     err);
	}

	err = elf_address_range(elf, prog->vmcoreinfo.kaslr_offset, &start,
				&end);
	if (err) {
		err = drgn_dwarf_index_report_error(dindex, path, NULL, err);
		elf_end(elf);
		close(fd);
		free(path);
		return err;
	}

	err = drgn_dwarf_index_report_elf(dindex, path, fd, elf, start, end,
					  "kernel", vmlinux_is_pending);
	free(path);
	return err;
}

struct drgn_error *
linux_kernel_report_debug_info(struct drgn_program *prog,
			       struct drgn_dwarf_index *dindex,
			       const char **paths, size_t n,
			       bool report_default, bool report_main)
{
	struct drgn_error *err;
	struct kernel_module_file *kmods;
	size_t i, num_kmods = 0;
	bool need_module_definition = false;
	bool vmlinux_is_pending = false;

	if (report_main && !prog->added_vmcoreinfo_object_finder) {
		err = drgn_program_add_object_finder(prog,
						     vmcoreinfo_object_find,
						     prog);
		if (err)
			return err;
		prog->added_vmcoreinfo_object_finder = true;
	}

	if (n) {
		kmods = malloc_array(n, sizeof(*kmods));
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
	for (i = 0; i < n; i++) {
		const char *path = paths[i];
		int fd;
		Elf *elf;
		Elf_Scn *this_module_scn, *modinfo_scn;
		bool is_vmlinux;

		err = open_elf_file(path, &fd, &elf);
		if (err) {
			err = drgn_dwarf_index_report_error(dindex, path, NULL,
							    err);
			if (err)
				goto out;
			continue;
		}

		err = identify_kernel_elf(elf, &this_module_scn, &modinfo_scn,
					  &is_vmlinux);
		if (err) {
			err = drgn_dwarf_index_report_error(dindex, path, NULL,
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
				err = drgn_dwarf_index_report_error(dindex,
								    path, NULL,
								    err);
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
			bool is_new;

			err = elf_address_range(elf,
						prog->vmcoreinfo.kaslr_offset,
						&start, &end);
			if (err) {
				elf_end(elf);
				close(fd);
				err = drgn_dwarf_index_report_error(dindex,
								    path, NULL,
								    err);
				if (err)
					goto out;
				continue;
			}

			err = drgn_dwarf_index_report_elf(dindex, path, fd, elf,
							  start, end, "kernel",
							  &is_new);
			if (err)
				goto out;
			if (is_new)
				vmlinux_is_pending = true;
		} else {
			err = drgn_dwarf_index_report_elf(dindex, path, fd, elf,
							  0, 0, NULL, NULL);
			if (err)
				goto out;
		}
	}

	if (report_main && !vmlinux_is_pending &&
	    !drgn_dwarf_index_is_indexed(dindex, "kernel")) {
		err = report_vmlinux(prog, dindex, &vmlinux_is_pending);
		if (err)
			goto out;
	}

	err = report_kernel_modules(prog, dindex, kmods, num_kmods,
				    report_default, need_module_definition,
				    vmlinux_is_pending);
out:
	for (i = 0; i < num_kmods; i++) {
		elf_end(kmods[i].elf);
		if (kmods[i].fd != -1)
			close(kmods[i].fd);
	}
	free(kmods);
	return err;
}
