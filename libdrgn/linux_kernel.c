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
#include "linux_kernel.h"
#include "program.h"
#include "read.h"
#include "string_builder.h"

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
		return drgn_error_create_os(errno, "/proc/kallsyms", "fopen");

	for (;;) {
		char *addr_str, *sym_str, *saveptr, *end;

		errno = 0;
		if (getline(&line, &n, file) == -1) {
			if (errno) {
				err = drgn_error_create_os(errno,
							   "/proc/kallsyms",
							   "getline");
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
		return drgn_error_create_os(errno, "/sys/kernel/vmcoreinfo",
					    "fopen");
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

struct kernel_module_iterator {
	char *name;
	FILE *file;
	union {
		size_t name_capacity;
		struct {
			struct drgn_qualified_type module_type;
			struct drgn_object mod, node, mod_name;
			uint64_t head;
		};
	};
};

static void kernel_module_iterator_deinit(struct kernel_module_iterator *it)
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

/**
 * Get the name of the next loaded kernel module.
 *
 * After this is called, @c it->name is set to the name of the kernel module; it
 * is valid until the next time this is called or the iterator is destroyed.
 *
 * @return @c NULL on success, non-@c NULL on error. In particular, when there
 * are no more modules, a @ref DRGN_ERROR_STOP error is returned.
 */
static struct drgn_error *
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

static struct drgn_error *
kernel_module_section_address(struct drgn_program *prog,
			      const char *module_name, const char *section_name,
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

static struct drgn_error *get_module_name(struct drgn_program *prog,
					  Elf_Scn *this_module_scn,
					  Elf_Scn *modinfo_scn,
					  const char **ret)
{
	struct drgn_error *err;
	Elf_Data *data;
	const char *p, *end, *nul;
	struct drgn_qualified_type module_type;
	struct drgn_member_info name_member;
	size_t name_offset;

	/*
	 * Since Linux kernel commit 3e2e857f9c3a ("module: Add module name to
	 * modinfo") (in v4.13), we can get the module name from .modinfo.
	 * Before that, we need to get it from .gnu.linkonce.this_module, which
	 * contains a struct module.
	 */
	err = read_elf_section(modinfo_scn, &data);
	if (err)
		return err;
	p = data->d_buf;
	end = p + data->d_size;
	while (p < end) {
		nul = memchr(p, 0, end - p);
		if (!nul)
			break;
		if (strncmp(p, "name=", 5) == 0) {
			*ret = p + 5;
			return NULL;
		}
		p = nul + 1;
	}

	err = read_elf_section(this_module_scn, &data);
	if (err)
		return err;
	err = drgn_program_find_type(prog, "struct module", NULL,
				     &module_type);
	if (err)
		return err;
	err = drgn_program_member_info(prog, module_type.type, "name",
				       &name_member);
	if (err)
		return err;
	name_offset = name_member.bit_offset / 8;
	if (name_offset < data->d_size) {
		p = data->d_buf + name_offset;
		nul = memchr(p, 0, data->d_size - name_offset);
		if (nul && nul != p) {
			*ret = p;
			return NULL;
		}
	}
	return drgn_error_create(DRGN_ERROR_LOOKUP,
				 "could not find module name in .modinfo or .gnu.linkonce.this_module");
}

static struct drgn_error *find_elf_symbol_by_address(Elf *elf,
						     Elf_Scn *symtab_scn,
						     const char *name,
						     uint64_t address,
						     GElf_Sym *sym,
						     Elf32_Word *shndx)
{
	struct drgn_error *err;
	int xndxscnidx;
	GElf_Shdr shdr_mem, *shdr;
	Elf_Data *xndx_data = NULL, *data;
	size_t num_syms, i;

	xndxscnidx = elf_scnshndx(symtab_scn);
	if (xndxscnidx > 0)
		xndx_data = elf_getdata(elf_getscn(elf, xndxscnidx), NULL);

	err = read_elf_section(symtab_scn, &data);
	if (err)
		return err;
	shdr = gelf_getshdr(symtab_scn, &shdr_mem);
	if (!shdr)
		return drgn_error_libelf();

	num_syms = data->d_size / (gelf_getclass(elf) == ELFCLASS32 ?
				   sizeof(Elf32_Sym) : sizeof(Elf64_Sym));
	for (i = 0; i < num_syms; i++) {
		if (!gelf_getsymshndx(data, xndx_data, i, sym, shndx))
			continue;
		if (sym->st_value == address)
			return NULL;
	}
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "could not find %s symbol", name);
}

static struct drgn_error *get_symbol_section_name(Elf *elf, size_t shstrndx,
						  Elf_Scn *symtab_scn,
						  const char *name,
						  uint64_t address,
						  const char **ret)
{
	struct drgn_error *err;
	GElf_Sym sym;
	Elf32_Word shndx;
	Elf_Scn *scn;
	GElf_Shdr shdr_mem, *shdr;
	const char *scnname;

	err = find_elf_symbol_by_address(elf, symtab_scn, name, address, &sym,
					 &shndx);
	if (err)
		return err;

	if (sym.st_shndx != SHN_XINDEX)
		shndx = sym.st_shndx;
	scn = elf_getscn(elf, shndx);
	if (!scn)
		return drgn_error_libelf();
	shdr = gelf_getshdr(scn, &shdr_mem);
	if (!shdr)
		return drgn_error_libelf();
	scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
	if (!scnname)
		return drgn_error_libelf();
	*ret = scnname;
	return NULL;
}

struct drgn_error *kernel_relocation_hook(struct drgn_program *prog,
					  const char *name, Dwarf_Die *die,
					  struct drgn_symbol *sym)
{
	struct drgn_error *err;
	Elf *elf;
	GElf_Ehdr ehdr_mem, *ehdr;
	size_t shstrndx;
	Elf_Scn *scn, *this_module_scn, *modinfo_scn, *symtab_scn;
	const char *section_name, *module_name;
	uint64_t section_address;

	elf = dwarf_getelf(dwarf_cu_getdwarf(die->cu));
	ehdr = gelf_getehdr(elf, &ehdr_mem);
	if (!ehdr)
		return drgn_error_libelf();

	/* vmlinux is executable, kernel modules are relocatable. */
	if (ehdr->e_type == ET_EXEC) {
		sym->address += prog->vmcoreinfo.kaslr_offset;
		return NULL;
	}

	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	/* Find .gnu.linkonce.this_module, .modinfo, and .symtab. */
	scn = modinfo_scn = this_module_scn = symtab_scn = NULL;
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
			this_module_scn = scn;
		else if (strcmp(scnname, ".modinfo") == 0)
			modinfo_scn = scn;
		else if (strcmp(scnname, ".symtab") == 0)
			symtab_scn = scn;
	}

	if (!this_module_scn || !modinfo_scn) {
		return drgn_error_create(DRGN_ERROR_LOOKUP,
					 "'%s' is not from vmlinux or a kernel module");
	}
	err = get_module_name(prog, this_module_scn, modinfo_scn, &module_name);
	if (err)
		return err;

	if (!symtab_scn) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find .symtab section in %s",
					 module_name);
	}
	err = get_symbol_section_name(elf, shstrndx, symtab_scn, name,
				      sym->address, &section_name);
	if (err)
		return err;

	err = kernel_module_section_address(prog, module_name, section_name,
					    &section_address);
	if (err)
		return err;
	sym->address += section_address;
	return NULL;
}

static struct drgn_error *
vmcoreinfo_symbol_find(const char *name, size_t name_len, const char *filename,
		       enum drgn_find_object_flags flags, void *arg,
		       struct drgn_symbol *ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = arg;

	if (filename)
		goto not_found;

	if (flags & DRGN_FIND_OBJECT_CONSTANT) {
		if (name_len == strlen("PAGE_SHIFT") &&
		    memcmp(name, "PAGE_SHIFT", name_len) == 0) {
			err = drgn_type_index_find_primitive(&prog->tindex,
							     DRGN_C_TYPE_INT,
							     &ret->type);
			if (err)
				return err;
			ret->svalue = ctz(prog->vmcoreinfo.page_size);
		} else if (name_len == strlen("PAGE_SIZE") &&
			   memcmp(name, "PAGE_SIZE", name_len) == 0) {
			err = drgn_type_index_find_primitive(&prog->tindex,
							     DRGN_C_TYPE_UNSIGNED_LONG,
							     &ret->type);
			if (err)
				return err;
			ret->uvalue = prog->vmcoreinfo.page_size;
		} else if (name_len == strlen("PAGE_MASK") &&
			   memcmp(name, "PAGE_MASK", name_len) == 0) {
			err = drgn_type_index_find_primitive(&prog->tindex,
							     DRGN_C_TYPE_UNSIGNED_LONG,
							     &ret->type);
			if (err)
				return err;
			ret->uvalue = ~(prog->vmcoreinfo.page_size - 1);
		} else {
			goto not_found;
		}
		ret->qualifiers = 0;
		ret->kind = DRGN_SYMBOL_CONSTANT;
		return NULL;
	}

not_found:
	ret->type = NULL;
	return NULL;
}

static struct drgn_error *
open_vmlinux_debug_info(struct drgn_program *prog,
			struct string_builder *missing_debug_info)
{
	static const char * const vmlinux_paths[] = {
		/*
		 * The files under /usr/lib/debug should always have debug information,
		 * so check those first.
		 */
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
		"/boot/vmlinux-%s",
		"/lib/modules/%s/build/vmlinux",
	};
	struct drgn_error *err;
	char path[256];
	bool found_vmlinux = false;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(vmlinux_paths); i++) {
		snprintf(path, sizeof(path), vmlinux_paths[i],
			 prog->vmcoreinfo.osrelease);
		err = drgn_program_open_debug_info(prog, path, NULL);
		if (err) {
			if (err->code == DRGN_ERROR_OS &&
			    err->errnum == ENOENT) {
				drgn_error_destroy(err);
				continue;
			}
			if (err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
				found_vmlinux = true;
				drgn_error_destroy(err);
				continue;
			}
		}
		return err;
	}
	if (!string_builder_append(missing_debug_info,
				   found_vmlinux ?
				   "vmlinux does not have debug information" :
				   "could not find vmlinux"))
		return &drgn_enomem;
	return NULL;
}

static struct drgn_error *
open_kernel_module_debug_info(struct drgn_program *prog,
			      const char *module_path, size_t path_len)
{
	static const char * const module_paths[] = {
		"/usr/lib/debug/lib/modules/%s/%.*s.debug",
		"/usr/lib/debug/lib/modules/%s/%.*s",
		"/lib/modules/%s/%.*s",
	};
	struct drgn_error *err;
	size_t num_paths = ARRAY_SIZE(module_paths), i;

	if (path_len >= 3 &&
	    (memcmp(module_path + path_len - 3, ".gz", 3) == 0 ||
	     memcmp(module_path + path_len - 3, ".xz", 3) == 0)) {
		/*
		 * Don't bother trying the compressed module in /lib/modules,
		 * it's not an ELF file.
		 */
		num_paths--;
		/*
		 * The debuginfo ELF file in /usr/lib/debug doesn't have the
		 * compressed extension.
		 */
		path_len -= 3;
	}

	for (i = 0; i < num_paths; i++) {
		char *debuginfo_path;

		if (asprintf(&debuginfo_path, module_paths[i],
			     prog->vmcoreinfo.osrelease, (int)path_len,
			     module_path) == -1)
			return &drgn_enomem;
		err = drgn_program_open_debug_info(prog, debuginfo_path, NULL);
		free(debuginfo_path);
		if (!err)
			return NULL;
		drgn_error_destroy(err);
	}
	return &drgn_stop;
}

/*
 * Append a newline character if the string isn't empty and doesn't already end
 * in a newline.
 */
static bool string_builder_line_break(struct string_builder *sb)
{
	if (!sb->len || sb->str[sb->len - 1] == '\n')
		return true;
	return string_builder_appendc(sb, '\n');
}

static struct drgn_error *
open_loaded_kernel_modules(struct drgn_program *prog,
			   struct string_builder *missing_debug_info)
{
	struct drgn_error *err;
	struct depmod_index depmod;
	struct kernel_module_iterator kmod_it;
	static const size_t max_no_symbols = 5;
	size_t no_symbols = 0;

	err = depmod_index_init(&depmod, prog->vmcoreinfo.osrelease);
	if (err && err->code != DRGN_ERROR_NO_MEMORY) {
		if (!string_builder_line_break(missing_debug_info) ||
		    !string_builder_append(missing_debug_info,
					   "could not find installed kernel modules (") ||
		    !string_builder_append_error(missing_debug_info, err) ||
		    !string_builder_appendc(missing_debug_info, ')')) {
			drgn_error_destroy(err);
			return &drgn_enomem;
		}
		drgn_error_destroy(err);
		return NULL;
	} else if (err) {
		return err;
	}

	err = kernel_module_iterator_init(&kmod_it, prog);
	if (err)
		goto kernel_module_iterator_error;
	while (!(err = kernel_module_iterator_next(&kmod_it))) {
		const char *module_path;
		size_t path_len;
		bool found;

		found = depmod_index_find(&depmod, kmod_it.name, &module_path,
					  &path_len);
		if (found) {
			err = open_kernel_module_debug_info(prog, module_path,
							    path_len);
			if (err) {
				if (err->code == DRGN_ERROR_NO_MEMORY)
					break;
				drgn_error_destroy(err);
				found = false;
			}
		}
		if (!found) {
			if (no_symbols == 0) {
				if (!string_builder_line_break(missing_debug_info) ||
				    !string_builder_append(missing_debug_info,
							   "missing debug information for modules:")) {
					err = &drgn_enomem;
					break;
				}
			}
			if (no_symbols < max_no_symbols) {
				if (!string_builder_line_break(missing_debug_info) ||
				    !string_builder_append(missing_debug_info,
							   kmod_it.name)) {
					err = &drgn_enomem;
					break;
				}
			}
			no_symbols++;
			continue;
		}
	}
	kernel_module_iterator_deinit(&kmod_it);
	if (err && err->code != DRGN_ERROR_STOP) {
kernel_module_iterator_error:
		if (err->code != DRGN_ERROR_NO_MEMORY) {
			if (!string_builder_line_break(missing_debug_info) ||
			    !string_builder_append(missing_debug_info,
						   "could not find loaded kernel modules (") ||
			    !string_builder_append_error(missing_debug_info,
							 err) ||
			    !string_builder_appendc(missing_debug_info, ')')) {
				drgn_error_destroy(err);
				err = &drgn_enomem;
				goto out;
			}
			drgn_error_destroy(err);
			err = NULL;
			goto out;
		}
		goto out;
	}

	if (no_symbols > max_no_symbols) {
		if (!string_builder_line_break(missing_debug_info) ||
		    !string_builder_appendf(missing_debug_info,
					    "... %zu more",
					    no_symbols - max_no_symbols)) {
			err = &drgn_enomem;
			goto out;
		}
	}

	err = NULL;
out:
	depmod_index_deinit(&depmod);
	return err;
}

struct drgn_error *load_kernel_debug_info(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct string_builder missing_debug_info = {};

	if (!prog->added_vmcoreinfo_symbol_finder) {
		err = drgn_program_add_symbol_finder(prog,
						     vmcoreinfo_symbol_find,
						     prog);
		if (err)
			return err;
		prog->added_vmcoreinfo_symbol_finder = true;
	}

	err = open_vmlinux_debug_info(prog, &missing_debug_info);
	if (err)
		goto err;

	/*
	 * If we're not debugging the running kernel, then we need to load
	 * vmlinux now so that we can walk the list of modules in the kernel.
	 * Otherwise, we can get the list from procfs, and it's more efficient
	 * to load vmlinux in parallel with the kernel modules.
	 */
	if (!(prog->flags & DRGN_PROGRAM_IS_RUNNING_KERNEL)) {
		err = drgn_program_update_debug_info(prog);
		if (err)
			goto err;
	}

	err = open_loaded_kernel_modules(prog, &missing_debug_info);
	if (err)
		goto err;
	err = drgn_program_update_debug_info(prog);
	if (err)
		goto err;

	if (missing_debug_info.len) {
		return drgn_error_from_string_builder(DRGN_ERROR_MISSING_DEBUG_INFO,
						      &missing_debug_info);
	}
	return NULL;

err:
	free(missing_debug_info.str);
	drgn_program_close_unindexed_debug_info(prog);
	return err;
}
