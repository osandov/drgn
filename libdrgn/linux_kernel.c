// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <byteswap.h>
#include <dirent.h>
#include <elf.h>
#include <elfutils/libdwelf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "array.h"
#include "binary_buffer.h"
#include "debug_info.h"
#include "drgn.h"
#include "error.h"
#include "hash_table.h"
#include "helpers.h"
#include "io.h"
#include "linux_kernel.h"
#include "program.h"
#include "type.h"
#include "util.h"

#include "drgn_program_parse_vmcoreinfo.inc"

struct drgn_error *read_memory_via_pgtable(void *buf, uint64_t address,
					   size_t count, uint64_t offset,
					   void *arg, bool physical)
{
	struct drgn_program *prog = arg;
	return linux_helper_read_vm(prog, prog->vmcoreinfo.swapper_pg_dir,
				    address, buf, count);
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

	err = drgn_program_parse_vmcoreinfo(prog, buf + 24, nhdr->n_descsz);
out:
	free(buf);
	return err;
}

static struct drgn_error *linux_kernel_get_page_shift(struct drgn_program *prog,
						      struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_INT,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_signed(ret, qualified_type,
				      prog->vmcoreinfo.page_shift, 0);
}

static struct drgn_error *linux_kernel_get_page_size(struct drgn_program *prog,
						     struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_UNSIGNED_LONG,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_unsigned(ret, qualified_type,
					prog->vmcoreinfo.page_size, 0);
}

static struct drgn_error *linux_kernel_get_page_mask(struct drgn_program *prog,
						     struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_UNSIGNED_LONG,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_unsigned(ret, qualified_type,
					~(prog->vmcoreinfo.page_size - 1), 0);
}

static struct drgn_error *
linux_kernel_get_uts_release(struct drgn_program *prog, struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog,
					       DRGN_C_TYPE_CHAR,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = DRGN_QUALIFIER_CONST;
	size_t len = strlen(prog->vmcoreinfo.osrelease);
	err = drgn_array_type_create(prog, qualified_type, len + 1,
				     &drgn_language_c, &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_from_buffer(ret, qualified_type,
					   prog->vmcoreinfo.osrelease, len + 1,
					   0, 0);
}

// jiffies is defined as an alias of jiffies_64 via the Linux kernel linker
// script, so it is not included in debug info.
static struct drgn_error *linux_kernel_get_jiffies(struct drgn_program *prog,
						   struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_object jiffies_64;
	drgn_object_init(&jiffies_64, prog);
	err = drgn_program_find_object(prog, "jiffies_64", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &jiffies_64);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			err = &drgn_not_found;
		}
		goto out;
	}
	if (jiffies_64.kind != DRGN_OBJECT_REFERENCE) {
		err = &drgn_not_found;
		goto out;
	}
	uint64_t address = jiffies_64.address;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog, DRGN_C_TYPE_UNSIGNED_LONG,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = DRGN_QUALIFIER_VOLATILE;
	if (drgn_type_size(qualified_type.type) == 4 &&
	    !drgn_type_little_endian(qualified_type.type))
		address += 4;
	err = drgn_object_set_reference(ret, qualified_type, address, 0, 0);
out:
	drgn_object_deinit(&jiffies_64);
	return err;
}

// The vmemmap address can vary depending on architecture, kernel version,
// configuration options, and KASLR. However, we can get it generically from the
// section_mem_map of any valid mem_section.
static struct drgn_error *
linux_kernel_get_vmemmap_address(struct drgn_program *prog, uint64_t *ret)
{
	static const uint64_t SECTION_HAS_MEM_MAP = 0x2;
	static const uint64_t SECTION_MAP_MASK = ~((UINT64_C(1) << 6) - 1);
	struct drgn_error *err;

	struct drgn_object mem_section, root, section;
	drgn_object_init(&mem_section, prog);
	drgn_object_init(&root, prog);
	drgn_object_init(&section, prog);

	err = drgn_program_find_object(prog, "vmemmap_populate", NULL,
				       DRGN_FIND_OBJECT_FUNCTION, &mem_section);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			// !CONFIG_SPARSEMEM_VMEMMAP
			drgn_error_destroy(err);
			err = &drgn_not_found;
		}
		goto out;
	}

	err = drgn_program_find_object(prog, "mem_section", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &mem_section);
	if (err)
		goto out;

	const uint64_t nr_section_roots = prog->vmcoreinfo.mem_section_length;
	uint64_t sections_per_root;
	if (drgn_type_kind(mem_section.type) == DRGN_TYPE_ARRAY) {
		// If !CONFIG_SPARSEMEM_EXTREME, mem_section is
		// struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT],
		// and SECTIONS_PER_ROOT is 1.
		sections_per_root = 1;
	} else {
		// If CONFIG_SPARSEMEM_EXTREME, mem_section is
		// struct mem_section **mem_section, and SECTIONS_PER_ROOT is
		// PAGE_SIZE / sizeof(struct mem_section).
		struct drgn_type *mem_section_type = mem_section.type;
		for (int i = 0; i < 2; i++) {
			if (drgn_type_kind(mem_section_type) != DRGN_TYPE_POINTER) {
unrecognized_mem_section_type:
				err = drgn_type_error("mem_section has unrecognized type '%s'",
						      mem_section.type);
				goto out;
			}
			mem_section_type = drgn_type_type(mem_section_type).type;
		}
		if (drgn_type_kind(mem_section_type) != DRGN_TYPE_STRUCT)
			goto unrecognized_mem_section_type;
		uint64_t sizeof_mem_section = drgn_type_size(mem_section_type);
		if (sizeof_mem_section == 0)
			goto unrecognized_mem_section_type;
		sections_per_root =
			prog->vmcoreinfo.page_size / sizeof_mem_section;
	}

	// Find a valid section.
	for (uint64_t i = 0; i < nr_section_roots; i++) {
		err = drgn_object_subscript(&root, &mem_section, i);
		if (err)
			goto out;
		bool truthy;
		err = drgn_object_bool(&root, &truthy);
		if (err)
			goto out;
		if (!truthy)
			continue;

		for (uint64_t j = 0; j < sections_per_root; j++) {
			err = drgn_object_subscript(&section, &root, j);
			if (err)
				goto out;
			err = drgn_object_member(&section, &section,
						 "section_mem_map");
			if (err)
				goto out;
			uint64_t section_mem_map;
			err = drgn_object_read_unsigned(&section,
							&section_mem_map);
			if (err)
				goto out;
			if (section_mem_map & SECTION_HAS_MEM_MAP) {
				*ret = section_mem_map & SECTION_MAP_MASK;
				err = NULL;
				goto out;
			}
		}
	}
	err = &drgn_not_found;

out:
	drgn_object_deinit(&section);
	drgn_object_deinit(&root);
	drgn_object_deinit(&mem_section);
	return err;
}

static struct drgn_error *linux_kernel_get_vmemmap(struct drgn_program *prog,
						   struct drgn_object *ret)
{
	struct drgn_error *err;
	if (prog->vmemmap.kind == DRGN_OBJECT_ABSENT) {
		uint64_t address;
		err = linux_kernel_get_vmemmap_address(prog, &address);
		if (err)
			return err;
		struct drgn_qualified_type qualified_type;
		err = drgn_program_find_type(prog, "struct page *", NULL,
					     &qualified_type);
		if (err)
			return err;
		err = drgn_object_set_unsigned(&prog->vmemmap, qualified_type,
					       address, 0);
		if (err)
			return err;
	}
	return drgn_object_copy(ret, &prog->vmemmap);
}

#include "linux_kernel_object_find.inc" // IWYU pragma: keep

struct kernel_module_iterator {
	char *name;
	uint64_t start, end;
	void *build_id_buf;
	size_t build_id_buf_capacity;
	/* `struct module` type. */
	struct drgn_qualified_type module_type;
	/* Current `struct module` (not a pointer). */
	struct drgn_object mod;
	/* `struct list_head *` in next module to return. */
	struct drgn_object node;
	/* Temporary objects reused for various purposes. */
	struct drgn_object tmp1, tmp2, tmp3;
	/* Address of `struct list_head modules`. */
	uint64_t head;
	bool use_sys_module;
};

static void kernel_module_iterator_deinit(struct kernel_module_iterator *it)
{
	drgn_object_deinit(&it->tmp3);
	drgn_object_deinit(&it->tmp2);
	drgn_object_deinit(&it->tmp1);
	drgn_object_deinit(&it->node);
	drgn_object_deinit(&it->mod);
	free(it->build_id_buf);
	free(it->name);
}

static struct drgn_error *
kernel_module_iterator_init(struct kernel_module_iterator *it,
			    struct drgn_program *prog, bool use_sys_module)
{
	struct drgn_error *err;

	it->name = NULL;
	it->build_id_buf = NULL;
	it->build_id_buf_capacity = 0;
	it->use_sys_module = use_sys_module;
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
				       DRGN_FIND_OBJECT_VARIABLE, &it->node);
	if (err)
		goto err;
	if (it->node.kind != DRGN_OBJECT_REFERENCE) {
		err = drgn_error_create(DRGN_ERROR_OTHER,
					"can't get address of modules list");
	      goto err;
	}
	it->head = it->node.address;
	err = drgn_object_member(&it->node, &it->node, "next");
	if (err)
		goto err;
	err = drgn_object_read(&it->node, &it->node);
	if (err)
		goto err;

	return NULL;

err:
	kernel_module_iterator_deinit(it);
	return err;
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
	struct drgn_error *err;

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
	err = drgn_object_dereference(&it->mod, &it->mod);
	if (err)
		return err;
	// We need several fields from the `struct module`. Especially for
	// /proc/kcore, it is faster to read the entire structure (which is <1kB
	// as of Linux 6.0) from the core dump all at once than it is to read
	// each field individually.
	err = drgn_object_read(&it->mod, &it->mod);
	if (err)
		return err;
	err = drgn_object_member(&it->node, &it->mod, "list");
	if (err)
		return err;
	err = drgn_object_member(&it->node, &it->node, "next");
	if (err)
		return err;

	// Set tmp1 to the module base address and tmp2 to the size.
	err = drgn_object_member(&it->tmp1, &it->mod, "core_layout");
	if (!err) {
		// Since Linux kernel commit 7523e4dc5057 ("module: use a
		// structure to encapsulate layout.") (in v4.5), the base and
		// size are in the `struct module_layout core_layout` member of
		// `struct module`.
		err = drgn_object_member(&it->tmp2, &it->tmp1, "size");
		if (err)
			return err;
		err = drgn_object_member(&it->tmp1, &it->tmp1, "base");
		if (err)
			return err;
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		// Before that, they are directly in the `struct module`.
		drgn_error_destroy(err);

		err = drgn_object_member(&it->tmp2, &it->mod, "core_size");
		if (err)
			return err;
		err = drgn_object_member(&it->tmp1, &it->mod, "module_core");
		if (err)
			return err;
	} else {
		return err;
	}
	err = drgn_object_read_unsigned(&it->tmp1, &it->start);
	if (err)
		return err;
	err = drgn_object_read_unsigned(&it->tmp2, &it->end);
	if (err)
		return err;
	it->end += it->start;

	err = drgn_object_member(&it->tmp2, &it->mod, "name");
	if (err)
		return err;
	char *name;
	err = drgn_object_read_c_string(&it->tmp2, &name);
	if (err)
		return err;
	free(it->name);
	it->name = name;
	return NULL;
}

static size_t parse_gnu_build_id_from_note(const void *note, size_t note_size,
					   bool bswap, const void **ret)
{
	const char *p = note;
	const char *end = p + note_size;
	// Elf64_Nhdr is the same as Elf32_Nhdr.
	Elf32_Nhdr nhdr;
	while (end - p >= sizeof(nhdr)) {
#define ALIGN_NOTE() do {						\
		size_t to_align = (size_t)-(p - (char *)note) % 4;	\
		if (to_align > end - p)					\
			break;						\
		p += to_align;						\
} while (0)

		memcpy(&nhdr, p, sizeof(nhdr));
		if (bswap) {
			nhdr.n_namesz = bswap_32(nhdr.n_namesz);
			nhdr.n_descsz = bswap_32(nhdr.n_descsz);
			nhdr.n_type = bswap_32(nhdr.n_type);
		}
		p += sizeof(nhdr);

		if (nhdr.n_namesz > end - p)
			break;
		const char *name = p;
		p += nhdr.n_namesz;
		ALIGN_NOTE();

		if (nhdr.n_namesz == sizeof("GNU") &&
		    memcmp(name, "GNU", sizeof("GNU")) == 0 &&
		    nhdr.n_type == NT_GNU_BUILD_ID &&
		    nhdr.n_descsz > 0) {
			if (nhdr.n_descsz > end - p)
				break;
			*ret = p;
			return nhdr.n_descsz;
		}

		p += nhdr.n_descsz;
		ALIGN_NOTE();

#undef ALIGN_NOTE
	}
	*ret = NULL;
	return 0;
}

static struct drgn_error *
kernel_module_iterator_gnu_build_id_live(struct kernel_module_iterator *it,
					 const void **build_id_ret,
					 size_t *build_id_len_ret)
{
	struct drgn_error *err;

	char *path;
	if (asprintf(&path, "/sys/module/%s/notes", it->name) == -1)
		return &drgn_enomem;
	DIR *dir = opendir(path);
	if (!dir) {
		err = drgn_error_create_os("opendir", errno, path);
		goto out_path;
	}

	struct dirent *ent;
	while ((errno = 0, ent = readdir(dir))) {
		if (ent->d_type == DT_DIR)
			continue;

		int fd = openat(dirfd(dir), ent->d_name, O_RDONLY);
		if (fd == -1) {
			err = drgn_error_format_os("openat", errno, "%s/%s",
						   path, ent->d_name);
			goto out;
		}

		struct stat st;
		if (fstat(fd, &st) < 0) {
			err = drgn_error_format_os("fstat", errno, "%s/%s",
						   path, ent->d_name);
			close(fd);
			goto out;
		}

		if (st.st_size > SIZE_MAX ||
		    !alloc_or_reuse(&it->build_id_buf,
				    &it->build_id_buf_capacity, st.st_size)) {
			err = &drgn_enomem;
			close(fd);
			goto out;
		}

		ssize_t r = read_all(fd, it->build_id_buf, st.st_size);
		if (r < 0) {
			err = drgn_error_format_os("read", errno, "%s/%s", path,
						   ent->d_name);
			close(fd);
			goto out;
		}
		close(fd);

		*build_id_len_ret =
			parse_gnu_build_id_from_note(it->build_id_buf, r, false,
						     build_id_ret);
		if (*build_id_len_ret) {
			err = NULL;
			goto out;
		}
	}
	if (errno) {
		err = drgn_error_create_os("readdir", errno, path);
	} else {
		*build_id_ret = NULL;
		*build_id_len_ret = 0;
		err = NULL;
	}

out:
	closedir(dir);
out_path:
	free(path);
	return err;
}

static struct drgn_error *
kernel_module_iterator_gnu_build_id(struct kernel_module_iterator *it,
				    const void **build_id_ret,
				    size_t *build_id_len_ret)
{
	if (it->use_sys_module) {
		return kernel_module_iterator_gnu_build_id_live(it,
								build_id_ret,
								build_id_len_ret);
	}

	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(&it->mod);
	const bool bswap = drgn_platform_bswap(&prog->platform);

	struct drgn_object attrs, attr, tmp;
	drgn_object_init(&attrs, prog);
	drgn_object_init(&attr, prog);
	drgn_object_init(&tmp, prog);

	// n = mod->notes_attrs->notes
	uint64_t n;
	err = drgn_object_member(&attrs, &it->mod, "notes_attrs");
	if (err)
		goto out;
	err = drgn_object_member_dereference(&tmp, &attrs, "notes");
	if (err)
		goto out;
	err = drgn_object_read_unsigned(&tmp, &n);
	if (err)
		goto out;

	// attrs = mod->notes_attrs->attrs
	err = drgn_object_member_dereference(&attrs, &attrs, "attrs");
	if (err)
		goto out;

	for (uint64_t i = 0; i < n; i++) {
		// attr = attrs[i]
		err = drgn_object_subscript(&attr, &attrs, i);
		if (err)
			goto out;

		// address = attr.private
		err = drgn_object_member(&tmp, &attr, "private");
		if (err)
			goto out;
		uint64_t address;
		err = drgn_object_read_unsigned(&tmp, &address);
		if (err)
			goto out;

		// size = attr.size
		err = drgn_object_member(&tmp, &attr, "size");
		if (err)
			goto out;
		uint64_t size;
		err = drgn_object_read_unsigned(&tmp, &size);
		if (err)
			goto out;

		if (size > SIZE_MAX ||
		    !alloc_or_reuse(&it->build_id_buf,
				    &it->build_id_buf_capacity, size)) {
			err = &drgn_enomem;
			goto out;
		}

		err = drgn_program_read_memory(prog, it->build_id_buf, address,
					       size, false);
		if (err)
			goto out;

		*build_id_len_ret =
			parse_gnu_build_id_from_note(it->build_id_buf, size,
						     bswap, build_id_ret);
		if (*build_id_len_ret) {
			err = NULL;
			goto out;
		}
	}
	*build_id_ret = NULL;
	*build_id_len_ret = 0;
	err = NULL;

out:
	drgn_object_deinit(&tmp);
	drgn_object_deinit(&attr);
	drgn_object_deinit(&attrs);
	return err;
}

struct kernel_module_section_iterator {
	struct kernel_module_iterator *kmod_it;
	bool yielded_percpu;
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
	it->yielded_percpu = false;
	if (kmod_it->use_sys_module) {
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
		err = drgn_object_member(&kmod_it->tmp1, &kmod_it->mod,
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
	struct drgn_error *err;
	struct kernel_module_iterator *kmod_it = it->kmod_it;

	// As of Linux 6.0, the .data..percpu section is not included in the
	// section attributes. (kernel/module/sysfs.c:add_sect_attrs() only
	// creates attributes for sections with the SHF_ALLOC flag set, but
	// kernel/module/main.c:layout_and_allocate() clears the SHF_ALLOC flag
	// for the .data..percpu section.) However, we need this address so that
	// global per-CPU variables will be relocated correctly. Get it from
	// `struct module`.
	if (!it->yielded_percpu) {
		it->yielded_percpu = true;
		err = drgn_object_member(&kmod_it->tmp2, &kmod_it->mod,
					 "percpu");
		if (!err) {
			err = drgn_object_read_unsigned(&kmod_it->tmp2, address_ret);
			if (err)
				return err;
			// struct module::percpu is NULL if the module doesn't
			// have any per-CPU data.
			if (*address_ret) {
				*name_ret = ".data..percpu";
				return NULL;
			}
		} else if (err->code == DRGN_ERROR_LOOKUP) {
			// struct module::percpu doesn't exist if !SMP.
			drgn_error_destroy(err);
		} else {
			return err;
		}
	}

	if (it->sections_dir) {
		return kernel_module_section_iterator_next_live(it, name_ret,
								address_ret);
	}

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
 * Identify an ELF file as a kernel module, vmlinux, or neither. We classify a
 * file as a kernel module if it has a section named .gnu.linkonce.this_module.
 * If it doesn't, but it does have a section named .init.text, we classify it as
 * vmlinux.
 */
static struct drgn_error *identify_kernel_elf(Elf *elf,
					      bool *is_vmlinux_ret,
					      bool *is_module_ret)
{
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx))
		return drgn_error_libelf();

	Elf_Scn *scn = NULL;
	bool have_init_text = false;
	while ((scn = elf_nextscn(elf, scn))) {
		GElf_Shdr *shdr, shdr_mem;
		const char *scnname;

		shdr = gelf_getshdr(scn, &shdr_mem);
		if (!shdr)
			continue;

		scnname = elf_strptr(elf, shstrndx, shdr->sh_name);
		if (!scnname)
			return drgn_error_libelf();
		if (strcmp(scnname, ".gnu.linkonce.this_module") == 0) {
			*is_vmlinux_ret = false;
			*is_module_ret = true;
			return NULL;
		} else if (strcmp(scnname, ".init.text") == 0) {
			have_init_text = true;
		}
	}
	*is_vmlinux_ret = have_init_text;
	*is_module_ret = false;
	return NULL;
}

DEFINE_HASH_MAP(elf_scn_name_map, const char *, Elf_Scn *,
		c_string_key_hash_pair, c_string_key_eq)

static struct drgn_error *
cache_kernel_module_sections(struct kernel_module_iterator *kmod_it, Elf *elf)
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
		}
	}
	if (err && err != &drgn_stop)
		goto out_section_it;
	err = NULL;
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
	 * Kernel module build ID. This is owned by the Elf handle. Because we
	 * use this as the key in the kernel_module_table, the file must always
	 * be removed from the table before it is reported to the DWARF index
	 * (which takes ownership of the Elf handle).
	 */
	const void *gnu_build_id;
	size_t gnu_build_id_len;
	/* Next file with the same build ID. */
	struct kernel_module_file *next;
};

static struct nstring
kernel_module_table_key(struct kernel_module_file * const *entry)
{
	return (struct nstring){
		(*entry)->gnu_build_id, (*entry)->gnu_build_id_len
	};
}

DEFINE_HASH_TABLE(kernel_module_table, struct kernel_module_file *,
		  kernel_module_table_key, nstring_hash_pair, nstring_eq)

static struct drgn_error *
report_loaded_kernel_module(struct drgn_debug_info_load_state *load,
			    struct kernel_module_iterator *kmod_it,
			    struct kernel_module_table *kmod_table)
{
	struct drgn_error *err;

	struct nstring key;
	err = kernel_module_iterator_gnu_build_id(kmod_it,
						  (const void **)&key.str,
						  &key.len);
	if (err || key.len == 0) {
		return drgn_debug_info_report_error(load, kmod_it->name,
						    "could not find GNU build ID",
						    err);
	}

	struct hash_pair hp = kernel_module_table_hash(&key);
	struct kernel_module_table_iterator it =
		kernel_module_table_search_hashed(kmod_table, &key, hp);
	if (!it.entry)
		return &drgn_not_found;

	struct kernel_module_file *kmod = *it.entry;
	kernel_module_table_delete_iterator_hashed(kmod_table, it, hp);
	do {
		err = cache_kernel_module_sections(kmod_it, kmod->elf);
		if (err) {
			err = drgn_debug_info_report_error(load, kmod->path,
							   "could not get section addresses",
							   err);
			if (err)
				return err;
			goto next;
		}

		err = drgn_debug_info_report_elf(load, kmod->path, kmod->fd,
						 kmod->elf, kmod_it->start,
						 kmod_it->end, kmod_it->name,
						 NULL);
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

	err = cache_kernel_module_sections(kmod_it, elf);
	if (err) {
		err = drgn_debug_info_report_error(load, path,
						   "could not get section addresses",
						   err);
		elf_end(elf);
		close(fd);
		free(path);
		return err;
	}

	err = drgn_debug_info_report_elf(load, path, fd, elf, kmod_it->start,
					 kmod_it->end, kmod_it->name, NULL);
	free(path);
	return err;
}

static struct drgn_error *
report_loaded_kernel_modules(struct drgn_debug_info_load_state *load,
			     struct kernel_module_table *kmod_table,
			     struct depmod_index *depmod, bool use_sys_module)
{
	struct drgn_program *prog = load->dbinfo->prog;
	struct drgn_error *err;

	struct kernel_module_iterator kmod_it;
	err = kernel_module_iterator_init(&kmod_it, prog, use_sys_module);
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
		      bool vmlinux_is_pending)
{
	struct drgn_program *prog = load->dbinfo->prog;
	struct drgn_error *err;

	if (!num_kmods && !load->load_default)
		return NULL;

	/*
	 * If we're debugging the running kernel, we can use
	 * /sys/module/$module/notes and /sys/module/$module/sections instead of
	 * getting the equivalent information from the core dump. This fast path
	 * can be disabled via an environment variable for testing.
	 */
	bool use_sys_module = false;
	if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
		char *env = getenv("DRGN_USE_SYS_MODULE");
		use_sys_module = !env || atoi(env);
	}
	/*
	 * We need to index vmlinux now so that we can walk the list of modules
	 * in the kernel.
	 */
	if (vmlinux_is_pending) {
		err = drgn_debug_info_report_flush(load);
		if (err)
			return err;
	}

	struct kernel_module_table kmod_table = HASH_TABLE_INIT;
	struct depmod_index depmod;
	depmod.addr = NULL;
	struct kernel_module_table_iterator it;
	for (size_t i = 0; i < num_kmods; i++) {
		struct kernel_module_file *kmod = &kmods[i];

		ssize_t build_id_len =
			dwelf_elf_gnu_build_id(kmod->elf, &kmod->gnu_build_id);
		if (build_id_len < 0) {
			err = drgn_debug_info_report_error(load, kmod->path,
							   NULL,
							   drgn_error_libelf());
			if (err)
				goto out;
			continue;
		}
		kmod->gnu_build_id_len = build_id_len;

		struct nstring key = kernel_module_table_key(&kmod);
		struct hash_pair hp = kernel_module_table_hash(&key);
		it = kernel_module_table_search_hashed(&kmod_table, &key, hp);
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

	err = report_loaded_kernel_modules(load, num_kmods ? &kmod_table : NULL,
					   load->load_default ? &depmod : NULL,
					   use_sys_module);
	if (err)
		goto out;

	/* Anything left over was not loaded. */
	for (it = kernel_module_table_first(&kmod_table); it.entry; ) {
		struct kernel_module_file *kmod = *it.entry;
		it = kernel_module_table_delete_iterator(&kmod_table, it);
		do {
			err = drgn_debug_info_report_elf(load, kmod->path,
							 kmod->fd, kmod->elf, 0,
							 0, kmod->path, NULL);
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
	static const char * vmlinux_paths[] = {
		/*
		 * The files under /usr/lib/debug should always have debug
		 * information, so check for those first.
		 */
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
		"/boot/vmlinux-%s",
		"/lib/modules/%s/build/vmlinux",
		"/lib/modules/%s/vmlinux",
		NULL, /* Space for an extra argument. */
		NULL,
	};
	struct drgn_program *prog = load->dbinfo->prog;
	struct drgn_error *err;

	char corefile[PATH_MAX];
	if (prog->core_path != NULL)
		if (realpath(prog->core_path, corefile) != NULL) {
			/* Skip filename from the path.  */
			*strrchr(corefile, '/') = '\0';

			char *extra = malloc (strlen(corefile) + 16);
			strcpy(extra, corefile);
			strcat(extra, "/vmlinux-%s");
			vmlinux_paths[array_size(vmlinux_paths) - 2] = extra;
		}

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

		bool is_vmlinux, is_module;
		err = identify_kernel_elf(elf, &is_vmlinux, &is_module);
		if (err) {
			err = drgn_debug_info_report_error(load, path, NULL,
							   err);
			elf_end(elf);
			close(fd);
			if (err)
				goto out;
			continue;
		}
		if (is_module) {
			struct kernel_module_file *kmod = &kmods[num_kmods++];
			kmod->path = path;
			kmod->fd = fd;
			kmod->elf = elf;
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

	err = report_kernel_modules(load, kmods, num_kmods, vmlinux_is_pending);
out:
	for (size_t i = 0; i < num_kmods; i++) {
		elf_end(kmods[i].elf);
		if (kmods[i].fd != -1)
			close(kmods[i].fd);
	}
	free(kmods);
	return err;
}
