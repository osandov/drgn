// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <dirent.h>
#include <elf.h>
#include <elfutils/libdwelf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "array.h"
#include "binary_buffer.h"
#include "cleanup.h"
#include "debug_info.h"
#include "drgn_internal.h"
#include "elf_file.h"
#include "elf_notes.h"
#include "error.h"
#include "hash_table.h"
#include "helpers.h"
#include "hexlify.h"
#include "io.h"
#include "log.h"
#include "linux_kernel.h"
#include "log.h"
#include "platform.h"
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

	_cleanup_free_ char *buf = malloc(size);
	if (!buf)
		return &drgn_enomem;

	err = drgn_program_read_memory(prog, buf, address, size, true);
	if (err)
		return err;

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
		return err;
	}

	return drgn_program_parse_vmcoreinfo(prog, buf + 24, nhdr->n_descsz);
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
	DRGN_OBJECT(jiffies_64, prog);
	err = drgn_program_find_object(prog, "jiffies_64", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &jiffies_64);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			drgn_error_destroy(err);
			err = &drgn_not_found;
		}
		return err;
	}
	if (jiffies_64.kind != DRGN_OBJECT_REFERENCE)
		return &drgn_not_found;
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
	return drgn_object_set_reference(ret, qualified_type, address, 0, 0);
}

static struct drgn_error *
linux_kernel_get_vmcoreinfo(struct drgn_program *prog, struct drgn_object *ret)
{
	struct drgn_error *err;
	struct drgn_qualified_type qualified_type;
	err = drgn_program_find_primitive_type(prog,
					       DRGN_C_TYPE_CHAR,
					       &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = DRGN_QUALIFIER_CONST;
	err = drgn_array_type_create(prog, qualified_type, prog->vmcoreinfo.raw_size,
				     &drgn_language_c, &qualified_type.type);
	if (err)
		return err;
	qualified_type.qualifiers = 0;
	return drgn_object_set_from_buffer(ret, qualified_type, prog->vmcoreinfo.raw,
					   prog->vmcoreinfo.raw_size, 0, 0);
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

	DRGN_OBJECT(mem_section, prog);
	DRGN_OBJECT(root, prog);
	DRGN_OBJECT(section, prog);

	err = drgn_program_find_object(prog, "vmemmap_populate", NULL,
				       DRGN_FIND_OBJECT_FUNCTION, &mem_section);
	if (err) {
		if (err->code == DRGN_ERROR_LOOKUP) {
			// !CONFIG_SPARSEMEM_VMEMMAP
			drgn_error_destroy(err);
			err = &drgn_not_found;
		}
		return err;
	}

	err = drgn_program_find_object(prog, "mem_section", NULL,
				       DRGN_FIND_OBJECT_VARIABLE, &mem_section);
	if (err)
		return err;

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
				return drgn_type_error("mem_section has unrecognized type '%s'",
						       mem_section.type);
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
			return err;
		bool truthy;
		err = drgn_object_bool(&root, &truthy);
		if (err)
			return err;
		if (!truthy)
			continue;

		for (uint64_t j = 0; j < sections_per_root; j++) {
			err = drgn_object_subscript(&section, &root, j);
			if (err)
				return err;
			err = drgn_object_member(&section, &section,
						 "section_mem_map");
			if (err)
				return err;
			uint64_t section_mem_map;
			err = drgn_object_read_unsigned(&section,
							&section_mem_map);
			if (err)
				return err;
			if (section_mem_map & SECTION_HAS_MEM_MAP) {
				*ret = section_mem_map & SECTION_MAP_MASK;
				return NULL;
			}
		}
	}
	return &drgn_not_found;
}

static struct drgn_error *linux_kernel_get_vmemmap(struct drgn_program *prog,
						   struct drgn_object *ret)
{
	struct drgn_error *err;
	if (prog->vmemmap.kind == DRGN_OBJECT_ABSENT) {
		// Silence -Wmaybe-uninitialized false positive last seen with
		// GCC 13 by initializing to zero.
		uint64_t address = 0;
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

struct drgn_error *drgn_program_finish_set_kernel(struct drgn_program *prog)
{
	struct drgn_error *err;
	const struct drgn_object_finder_ops ops = {
		.find = linux_kernel_object_find,
	};
	err = drgn_program_register_object_finder(prog, "linux", &ops, prog, 0);
	if (err)
		return err;
	if (!prog->lang)
		prog->lang = &drgn_language_c;
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

static void depmod_index_deinit(struct depmod_index *depmod)
{
	if (depmod->len > 0)
		munmap(depmod->addr, depmod->len);
	free(depmod->path);
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
					    char *_path, int fd)
{
	struct drgn_error *err;
	_cleanup_free_ char *path = _path; // Take ownership of path.

	struct stat st;
	if (fstat(fd, &st) == -1)
		return drgn_error_create_os("fstat", errno, path);

	if (st.st_size > SIZE_MAX)
		return &drgn_enomem;

	void *addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
		return drgn_error_create_os("mmap", errno, path);

	depmod->path = no_cleanup_ptr(path);
	depmod->addr = addr;
	depmod->len = st.st_size;
	err = depmod_index_validate(depmod);
	if (err) {
		depmod_index_deinit(depmod);
		depmod->path = NULL;
		depmod->len = 0;
	}
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

DEFINE_VECTOR_FUNCTIONS(char_p_vector);

DEFINE_HASH_MAP_FUNCTIONS(drgn_kmod_walk_module_map, c_string_key_hash_pair,
			  c_string_key_eq);

struct drgn_kmod_walk_stack_entry {
	DIR *dir;
	size_t path_len;
};

DEFINE_VECTOR_FUNCTIONS(drgn_kmod_walk_stack);

static inline struct hash_pair
drgn_kmod_walk_inode_hash_pair(const struct drgn_kmod_walk_inode *entry)
{
	return hash_pair_from_avalanching_hash(hash_combine(entry->dev, entry->ino));
}

static inline bool
drgn_kmod_walk_inode_eq(const struct drgn_kmod_walk_inode *a,
			const struct drgn_kmod_walk_inode *b)
{
	return a->dev == b->dev && a->ino == b->ino;
}

DEFINE_HASH_SET_FUNCTIONS(drgn_kmod_walk_inode_set,
			  drgn_kmod_walk_inode_hash_pair,
			  drgn_kmod_walk_inode_eq);

static void
drgn_kmod_walk_module_map_entry_deinit(struct drgn_kmod_walk_module_map_entry *entry)
{
	vector_for_each(char_p_vector, path, &entry->value)
		free(*path);
	char_p_vector_deinit(&entry->value);
}

static void
drgn_kmod_walk_state_deinit(struct drgn_kmod_walk_state *state)
{
	drgn_kmod_walk_inode_set_deinit(&state->visited_dirs);
	string_builder_deinit(&state->path);
	vector_for_each(drgn_kmod_walk_stack, entry, &state->stack)
		closedir(entry->dir);
	drgn_kmod_walk_stack_deinit(&state->stack);
	hash_table_for_each(drgn_kmod_walk_module_map, it, &state->modules)
		drgn_kmod_walk_module_map_entry_deinit(it.entry);
	drgn_kmod_walk_module_map_deinit(&state->modules);
}

void
drgn_standard_debug_info_find_state_deinit(struct drgn_standard_debug_info_find_state *state)
{
	drgn_kmod_walk_state_deinit(&state->kmod_walk);
	depmod_index_deinit(&state->modules_dep);
}

static struct drgn_error *
drgn_module_try_vmlinux_in_debug_directories(struct drgn_module *module,
					     const struct drgn_debug_info_options *options,
					     struct string_builder *sb)
{
	struct drgn_error *err;
	// Paths relative to the debug directory where vmlinux might be
	// installed.
	static const char * const debug_dir_paths[] = {
		// Debian, Ubuntu:
		"/boot/vmlinux-%s",
		// Fedora, CentOS:
		"/lib/modules/%s/vmlinux",
		// SUSE:
		"/lib/modules/%s/vmlinux.debug",
	};
	for (size_t i = 0; options->directories[i]; i++) {
		const char *debug_dir = options->directories[i];
		if (debug_dir[0] != '/')
			continue;
		sb->len = 0;
		if (!string_builder_append(sb, debug_dir))
			return &drgn_enomem;
		size_t debug_dir_len = sb->len;
		array_for_each(format, debug_dir_paths) {
			sb->len = debug_dir_len;
			if (!string_builder_appendf(sb, *format,
						    module->prog->vmcoreinfo.osrelease)
			    || !string_builder_null_terminate(sb))
				return &drgn_enomem;
			err = drgn_module_try_standard_file(module, options,
							    sb->str, -1, true,
							    NULL);
			if (err || !drgn_module_wants_file(module))
				return err;
		}
	}
	return NULL;
}

struct drgn_error *
drgn_module_try_vmlinux_files(struct drgn_module *module,
			      const struct drgn_debug_info_options *options)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	const char *osrelease = prog->vmcoreinfo.osrelease;
	STRING_BUILDER(sb);
	for (size_t i = 0; options->kernel_directories[i]; i++) {
		const char *kernel_dir = options->kernel_directories[i];

		if (kernel_dir[0]) {
			sb.len = 0;
			if (!string_builder_append(&sb, kernel_dir))
				return &drgn_enomem;
		} else {
			// Empty path. Try under the debug directories first.
			err = drgn_module_try_vmlinux_in_debug_directories(module,
									   options,
									   &sb);
			if (err || !drgn_module_wants_file(module))
				return err;

			// Try /boot/vmlinux-$osrelease.
			sb.len = 0;
			if (!string_builder_append(&sb, "/boot/vmlinux-")
			    || !string_builder_append(&sb, osrelease)
			    || !string_builder_null_terminate(&sb))
				return &drgn_enomem;
			err = drgn_module_try_standard_file(module, options,
							    sb.str, -1, true,
							    NULL);
			if (err || !drgn_module_wants_file(module))
				return err;

			// Try /lib/modules/$osrelease as the kernel directory.
			sb.len = 0;
			if (!string_builder_append(&sb, "/lib/modules/")
			    || !string_builder_append(&sb, osrelease))
				return &drgn_enomem;
		}

		// Paths relative to the kernel directory where vmlinux might be
		// installed.
		static const char * const kernel_dir_paths[] = {
			"/build/vmlinux",
			"/vmlinux",
		};
		size_t kernel_dir_len = sb.len;
		array_for_each(path, kernel_dir_paths) {
			if (!string_builder_append(&sb, *path)
			    || !string_builder_null_terminate(&sb))
				return &drgn_enomem;
			err = drgn_module_try_standard_file(module, options,
							    sb.str, -1, true,
							    NULL);
			if (err || !drgn_module_wants_file(module))
				return err;
			sb.len = kernel_dir_len;
		}
	}

	return NULL;
}

static struct drgn_error *
drgn_open_modules_dep(struct drgn_program *prog,
		      const struct drgn_debug_info_options *options,
		      struct depmod_index *modules_dep)
{
	struct drgn_error *err;

	if (modules_dep->addr)
		return NULL;

	STRING_BUILDER(sb);
	_cleanup_close_ int fd = -1;
	for (size_t i = 0; options->kernel_directories[i]; i++) {
		const char *kernel_dir = options->kernel_directories[i];

		sb.len = 0;
		if (kernel_dir[0]) {
			if (!string_builder_append(&sb, kernel_dir))
				return &drgn_enomem;
		} else {
			// Empty path. Try /lib/modules/$osrelease.
			if (!string_builder_append(&sb, "/lib/modules/")
			    || !string_builder_append(&sb,
						      prog->vmcoreinfo.osrelease))
				return &drgn_enomem;
		}
		if (!string_builder_append(&sb, "/modules.dep.bin")
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		fd = open(sb.str, O_RDONLY);
		if (fd >= 0)
			break;
		drgn_log_debug(prog, "%s: %m", sb.str);
	}
	if (fd < 0) {
		drgn_log_debug(prog, "couldn't find depmod index");
fail:
		// Set addr so that we don't try again.
		modules_dep->addr = MAP_FAILED;
		return NULL;
	}

	err = depmod_index_init(modules_dep, string_builder_steal(&sb), fd);
	if (err) {
		if (drgn_error_is_fatal(err))
			return err;
		drgn_error_log_warning(prog, err,
				       "couldn't open depmod index: ");
		drgn_error_destroy(err);
		goto fail;
	}
	drgn_log_debug(prog, "found depmod index %s", modules_dep->path);
	return NULL;
}

static struct drgn_error *
drgn_module_try_depmod_in_debug_directories(struct drgn_module *module,
					    const struct drgn_debug_info_options *options,
					    struct string_builder *sb,
					    const char *depmod_path, size_t ko_len)
{
	struct drgn_error *err;
	for (size_t i = 0; options->directories[i]; i++) {
		const char *debug_dir = options->directories[i];
		if (debug_dir[0] != '/')
			continue;
		sb->len = 0;
		// Debian, Ubuntu:
		// $debug_dir/lib/modules/$(uname -r)/$ko_name
		if (!string_builder_append(sb, debug_dir)
		    || !string_builder_append(sb, "/lib/modules/")
		    || !string_builder_append(sb,
					      module->prog->vmcoreinfo.osrelease)
		    || !string_builder_appendc(sb, '/')
		    || !string_builder_appendn(sb, depmod_path, ko_len)
		    || !string_builder_null_terminate(sb))
			return &drgn_enomem;
		err = drgn_module_try_standard_file(module, options, sb->str,
						    -1, true, NULL);
		if (err || !drgn_module_wants_file(module))
			return err;

		// Fedora, CentOS, SUSE:
		// $debug_dir/lib/modules/$(uname -r)/$ko_name.debug
		if (!string_builder_append(sb, ".debug")
		    || !string_builder_null_terminate(sb))
			return &drgn_enomem;
		err = drgn_module_try_standard_file(module, options, sb->str,
						    -1, true, NULL);
		if (err || !drgn_module_wants_file(module))
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_module_try_linux_kmod_depmod(struct drgn_module *module,
				  const struct drgn_debug_info_options *options,
				  struct drgn_standard_debug_info_find_state *state)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	const char *depmod_path;
	size_t depmod_path_len;
	err = depmod_index_find(&state->modules_dep, module->name, &depmod_path,
				&depmod_path_len);
	if (err) {
		drgn_error_log_warning(prog, err,
				       "couldn't parse depmod index: ");
		drgn_error_destroy(err);
		return NULL;
	}
	if (!depmod_path) {
		drgn_log_debug(prog, "couldn't find %s in depmod index",
			       module->name);
		return NULL;
	}
	drgn_log_debug(prog, "found %.*s in depmod index",
		       depmod_path_len > INT_MAX
		       ? INT_MAX : (int)depmod_path_len,
		       depmod_path);

	// Get the length of the path with one extension after ".ko" removed if
	// present (e.g., ".gz", ".xz", or ".zst").
	const char *name = memrchr(depmod_path, '/', depmod_path_len);
	if (name)
		name = name + 1;
	else
		name = depmod_path;
	const char *name_end = depmod_path + depmod_path_len;
	size_t ko_len = depmod_path_len;
	for (int j = 0; j < 2; j++) {
		char *dot = memrchr(name, '.', name_end - name);
		if (!dot)
			break;
		if (name_end - dot == 3
		    && dot[1] == 'k' && dot[2] == 'o') {
			ko_len = name_end - depmod_path;
			break;
		}
		name_end = dot;
	}

	STRING_BUILDER(sb);
	for (size_t i = 0; options->kernel_directories[i]; i++) {
		const char *kernel_dir = options->kernel_directories[i];

		if (kernel_dir[0]) {
			sb.len = 0;
			if (!string_builder_append(&sb, kernel_dir))
				return &drgn_enomem;
		} else {
			// Empty path. Try under the debug directories first.
			err = drgn_module_try_depmod_in_debug_directories(module,
									  options,
									  &sb,
									  depmod_path,
									  ko_len);
			if (err || !drgn_module_wants_file(module))
				return err;

			// Try /lib/modules/$osrelease as the kernel directory.
			sb.len = 0;
			if (!string_builder_append(&sb, "/lib/modules/")
			    || !string_builder_append(&sb,
						      prog->vmcoreinfo.osrelease))
				return &drgn_enomem;
		}
		if (!string_builder_appendc(&sb, '/')
		    || !string_builder_appendn(&sb, depmod_path, depmod_path_len)
		    || !string_builder_null_terminate(&sb))
			return &drgn_enomem;
		err = drgn_module_try_standard_file(module, options, sb.str, -1,
						    true, NULL);
		if (err || !drgn_module_wants_file(module))
			return err;
	}
	return NULL;
}

static struct drgn_error *
drgn_kmod_walk_next_dir(struct drgn_program *prog,
			const struct drgn_debug_info_options *options,
			struct drgn_kmod_walk_state *state)
{
	struct string_builder *path = &state->path;
	for (;;) {
		if (state->next_debug_dir) {
			const char *debug_dir = *state->next_debug_dir++;
			if (debug_dir && debug_dir[0] != '/')
				continue;

			path->len = 0;
			if (debug_dir) {
				if (!string_builder_append(path, debug_dir))
					return &drgn_enomem;
			} else {
				state->next_debug_dir = NULL;
			}
			if (!string_builder_append(path, "/lib/modules/")
			    || !string_builder_append(path,
						      prog->vmcoreinfo.osrelease))
				return &drgn_enomem;
		} else {
			const char *kernel_dir = *state->next_kernel_dir;
			if (!kernel_dir)
				return &drgn_stop;
			state->next_kernel_dir++;
			if (kernel_dir[0]) {
				path->len = 0;
				if (!string_builder_append(path, kernel_dir))
					return &drgn_enomem;
			} else {
				state->next_debug_dir = options->directories;
				continue;
			}
		}

		if (!string_builder_null_terminate(path))
			return &drgn_enomem;
		struct drgn_kmod_walk_stack_entry entry = {
			.dir = opendir(path->str),
			.path_len = path->len,
		};
		if (!entry.dir) {
			drgn_log_debug(prog, "opendir: %s: %m", path->str);
			continue;
		}
		if (!drgn_kmod_walk_stack_append(&state->stack, &entry)) {
			closedir(entry.dir);
			return &drgn_enomem;
		}
		drgn_log_debug(prog, "searching for kernel modules in %s",
			       path->str);
		return NULL;
	}
}

static struct drgn_error *
drgn_kmod_walk(struct drgn_program *prog,
	       const struct drgn_debug_info_options *options,
	       struct drgn_kmod_walk_state *state,
	       struct drgn_kmod_walk_module_map_entry *current)
{
	struct drgn_error *err;
	struct string_builder *path = &state->path;

	for (;;) {
		if (drgn_kmod_walk_stack_empty(&state->stack)) {
			err = drgn_kmod_walk_next_dir(prog, options, state);
			if (err)
				return err;
		}

		struct drgn_kmod_walk_stack_entry *top =
			drgn_kmod_walk_stack_last(&state->stack);
		errno = 0;
		struct dirent *ent = readdir(top->dir);
		if (!ent) {
			if (errno) {
				path->str[top->path_len] = '\0';
				drgn_log_debug(prog, "%s: readdir: %m",
					       path->str);
			}
			closedir(top->dir);
			drgn_kmod_walk_stack_pop(&state->stack);
			continue;
		}

		// Skip "." and "..".
		if (ent->d_name[0] == '.'
		    && (!ent->d_name[1]
			|| (ent->d_name[1] == '.' && !ent->d_name[2])))
			continue;

		bool is_directory = false;
		if (ent->d_type == DT_LNK || ent->d_type == DT_UNKNOWN) {
			struct stat st;
			if (fstatat(dirfd(top->dir), ent->d_name, &st, 0) < 0) {
				path->str[top->path_len] = '\0';
				drgn_log_debug(prog, "%s/%s: fstatat: %m",
					       path->str, ent->d_name);
				continue;
			}
			if (S_ISDIR(st.st_mode))
				is_directory = true;
			else if (!S_ISREG(st.st_mode))
				continue;
		} else if (ent->d_type == DT_DIR) {
			is_directory = true;
		} else if (ent->d_type != DT_REG) {
			continue;
		}

		if (is_directory) {
			path->len = top->path_len;
			if (!string_builder_appendc(path, '/')
			    || !string_builder_append(path, ent->d_name)
			    || !string_builder_null_terminate(path))
				return &drgn_enomem;

			_cleanup_close_ int fd =
				openat(dirfd(top->dir), ent->d_name,
				       O_RDONLY | O_DIRECTORY);
			if (fd < 0) {
				drgn_log_debug(prog, "openat: %s: %m",
					       path->str);
				continue;
			}

			struct stat st;
			if (fstat(fd, &st) < 0) {
				drgn_log_debug(prog, "fstat: %s: %m",
					       path->str);
				continue;
			}
			struct drgn_kmod_walk_inode inode = {
				.dev = st.st_dev,
				.ino = st.st_ino,
			};
			int r = drgn_kmod_walk_inode_set_insert(&state->visited_dirs,
								&inode, NULL);
			if (r < 0)
				return &drgn_enomem;
			if (r == 0) {
				drgn_log_debug(prog,
					       "%s is cycle or duplicate; skipping",
					       path->str);
				continue;
			}

			struct drgn_kmod_walk_stack_entry entry = {
				.dir = fdopendir(fd),
				.path_len = path->len,
			};
			if (!entry.dir) {
				drgn_log_debug(prog, "fdopendir: %s: %m",
					       path->str);
				continue;
			}
			fd = -1; // entry.dir owns fd now.
			if (!drgn_kmod_walk_stack_append(&state->stack,
							 &entry)) {
				closedir(entry.dir);
				return &drgn_enomem;
			}
		} else {
			// Match anything where the first extension is ".ko".
			char *dot = strchr(ent->d_name, '.');
			if (!dot || dot[1] != 'k' || dot[2] != 'o'
			    || (dot[3] != '\0' && dot[3] != '.'))
				continue;

			// Borrow the path string builder to build the module
			// name (removing extensions and replacing '-' with
			// '_').
			path->len = top->path_len;
			if (!string_builder_appendn(path, ent->d_name,
						    dot - ent->d_name)
			    || !string_builder_null_terminate(path))
				return &drgn_enomem;
			char *dash = &path->str[top->path_len];
			while ((dash = strchr(dash, '-')))
				*dash++ = '_';

			// Find the module (if wanted).
			const char *module_name = &path->str[top->path_len];
			auto it = drgn_kmod_walk_module_map_search(&state->modules,
								   &module_name);
			if (!it.entry)
				continue;

			size_t name_len = strlen(ent->d_name);
			size_t path_len;
			if (__builtin_add_overflow(top->path_len, name_len,
						   &path_len)
			    || __builtin_add_overflow(path_len, 2, &path_len))
				return &drgn_enomem;
			_cleanup_free_ char *file_path = malloc(path_len);
			if (!file_path)
				return &drgn_enomem;
			memcpy(file_path, path->str, top->path_len);
			file_path[top->path_len] = '/';
			memcpy(&file_path[top->path_len + 1], ent->d_name,
			       name_len + 1);
			drgn_log_debug(prog, "found kernel module %s", file_path);

			if (!char_p_vector_append(&it.entry->value, &file_path))
				return &drgn_enomem;
			file_path = NULL; // it.entry->value owns file_path now.

			// If the file matches the current module, return it.
			// Otherwise, keep going.
			if (it.entry == current)
				return NULL;
		}
	}
}

struct drgn_error *
drgn_module_try_linux_kmod_files(struct drgn_module *module,
				 const struct drgn_debug_info_options *options,
				 struct drgn_standard_debug_info_find_state *state)
{
	struct drgn_error *err;

	if (options->try_kmod == DRGN_KMOD_SEARCH_NONE)
		return NULL;

	if (options->try_kmod != DRGN_KMOD_SEARCH_WALK) {
		err = drgn_open_modules_dep(module->prog, options,
					    &state->modules_dep);
		if (err)
			return err;
		if (state->modules_dep.len > 0) {
			err = drgn_module_try_linux_kmod_depmod(module, options,
								state);
			if (err
			    || options->try_kmod != DRGN_KMOD_SEARCH_DEPMOD_AND_WALK
			    || !drgn_module_wants_file(module))
				return err;
		}
		if (options->try_kmod == DRGN_KMOD_SEARCH_DEPMOD)
			return NULL;
	}

	if (drgn_kmod_walk_module_map_empty(&state->kmod_walk.modules)) {
		for (size_t i = 0; i < state->num_modules; i++) {
			if (!drgn_module_wants_file(state->modules[i]))
				continue;
			struct drgn_kmod_walk_module_map_entry entry = {
				.key = state->modules[i]->name,
				.value = VECTOR_INIT,
			};
			if (drgn_kmod_walk_module_map_insert(&state->kmod_walk.modules,
							     &entry, NULL) < 0)
				return &drgn_enomem;
		}
	}

	const char *module_name = module->name;
	auto it = drgn_kmod_walk_module_map_search(&state->kmod_walk.modules,
						   &module_name);
	size_t i = 0;
	for (;;) {
		if (i >= char_p_vector_size(&it.entry->value)) {
			// No matches remaining for this module. Clear the old
			// matches and find another one.
			vector_for_each(char_p_vector, path, &it.entry->value)
				free(*path);
			char_p_vector_clear(&it.entry->value);
			i = 0;

			err = drgn_kmod_walk(module->prog, options,
					     &state->kmod_walk, it.entry);
			if (err == &drgn_stop)
				break;
			else if (err)
				return err;
		}
		char *path = *char_p_vector_at(&it.entry->value, i++);
		err = drgn_module_try_standard_file(module, options, path, -1,
						    true, NULL);
		if (err)
			return err;
		if (!drgn_module_wants_file(module))
			break;
	}
	// We won't need any more matches for this module.
	drgn_kmod_walk_module_map_entry_deinit(it.entry);
	drgn_kmod_walk_module_map_delete_iterator(&state->kmod_walk.modules,
						  it);
	return NULL;
}

// This has a weird calling convention so that the caller can call
// drgn_error_format_os() itself.
static const char *get_gnu_build_id_from_note_file(int fd,
						   void **bufp,
						   size_t *buf_capacityp,
						   const void **build_id_ret,
						   size_t *build_id_len_ret)
{
	struct stat st;
	if (fstat(fd, &st) < 0)
		return "fstat";

	if (st.st_size > SSIZE_MAX
	    || !alloc_or_reuse(bufp, buf_capacityp, st.st_size))
		return "";

	ssize_t r = read_all(fd, *bufp, st.st_size);
	if (r < 0)
		return "read";
	*build_id_len_ret = parse_gnu_build_id_from_notes(*bufp, r, 4, false,
							  build_id_ret);
	return NULL;
}

static struct drgn_error *
get_build_id_from_sys_kernel_notes(void **buf_ret,
				   const void **build_id_ret,
				   size_t *build_id_len_ret)
{
	static const char path[] = "/sys/kernel/notes";
	_cleanup_close_ int fd = open(path, O_RDONLY);
	if (fd == -1)
		return drgn_error_create_os("open", errno, path);

	_cleanup_free_ void *buf = NULL;
	size_t buf_capacity = 0;
	const char *message = get_gnu_build_id_from_note_file(fd, &buf,
							      &buf_capacity,
							      build_id_ret,
							      build_id_len_ret);
	if (message && message[0])
		return drgn_error_create_os(message, errno, path);
	else if (message)
		return &drgn_enomem;
	*buf_ret = no_cleanup_ptr(buf);
	return NULL;
}

// Arbitrary limit on the number iterations to make through the modules list in
// order to avoid getting stuck in a cycle.
static const int MAX_MODULE_LIST_ITERATIONS = 10000;

struct linux_kernel_loaded_module_iterator {
	struct drgn_module_iterator it;
	bool yielded_vmlinux;
	int module_list_iterations_remaining;
	// `struct module` type.
	struct drgn_qualified_type module_type;
	// `struct list_head *` in next module to yield.
	struct drgn_object node;
	// Address of `struct list_head modules`.
	uint64_t modules_head;
};

static void
linux_kernel_loaded_module_iterator_destroy(struct drgn_module_iterator *_it)
{
	struct linux_kernel_loaded_module_iterator *it =
		container_of(_it, struct linux_kernel_loaded_module_iterator, it);
	drgn_object_deinit(&it->node);
	free(it);
}

static struct drgn_error *
yield_vmlinux(struct linux_kernel_loaded_module_iterator *it,
	      struct drgn_module **ret, bool *new_ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	_cleanup_(drgn_module_deletep) struct drgn_module *module = NULL;
	bool new;
	err = drgn_module_find_or_create_main(prog, "kernel", &module, &new);
	if (err)
		return err;
	if (!new) {
		*ret = no_cleanup_ptr(module);
		if (new_ret)
			*new_ret = new;
		return NULL;
	}

	if (prog->vmcoreinfo.build_id_len > 0) {
		// Since Linux kernel commit 0935288c6e00 ("kdump: append kernel
		// build-id string to VMCOREINFO") (in v5.9), we can get the
		// build ID from VMCOREINFO.
		err = drgn_module_set_build_id(module, prog->vmcoreinfo.build_id,
					       prog->vmcoreinfo.build_id_len);
		if (err)
			return err;
		drgn_log_debug(prog,
			       "found kernel build ID %s in VMCOREINFO",
			       module->build_id_str);
	} else if (prog->flags & DRGN_PROGRAM_IS_LIVE) {
		// Before that, on the live kernel, we can get the build ID from
		// /sys/kernel/notes.
		_cleanup_free_ void *build_id_buf = NULL;
		const void *build_id;
		size_t build_id_len;
		err = get_build_id_from_sys_kernel_notes(&build_id_buf,
							 &build_id,
							 &build_id_len);
		if (err)
			return err;
		if (build_id_len > 0) {
			err = drgn_module_set_build_id(module, build_id,
						       build_id_len);
			if (err)
				return err;
			drgn_log_debug(prog,
				       "found kernel build ID %s in /sys/kernel/notes",
				       module->build_id_str);
		} else {
			drgn_log_debug(prog,
				       "couldn't find kernel build ID in /sys/kernel/notes");
		}
	} else {
		// Otherwise, we can't get the build ID.
		drgn_log_debug(prog, "couldn't find kernel build ID");
	}
	*ret = no_cleanup_ptr(module);
	if (new_ret)
		*new_ret = new;
	return NULL;
}

static struct drgn_error *
kernel_module_set_build_id_live(struct drgn_module *module)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	_cleanup_free_ char *path;
	if (asprintf(&path, "/sys/module/%s/notes", module->name) < 0) {
		path = NULL;
		return &drgn_enomem;
	}
	_cleanup_closedir_ DIR *dir = opendir(path);
	if (!dir) {
		if (errno == ENOENT) {
			drgn_log_debug(prog, "opendir: %s: %m", path);
			return NULL;
		} else {
			return drgn_error_create_os("opendir", errno, path);
		}
	}

	_cleanup_free_ void *buf = NULL;
	size_t capacity = 0;

	struct dirent *ent;
	while ((errno = 0, ent = readdir(dir))) {
		if (ent->d_type == DT_DIR)
			continue;

		_cleanup_close_ int fd = openat(dirfd(dir), ent->d_name,
						O_RDONLY);
		if (fd < 0) {
			return drgn_error_format_os("openat", errno, "%s/%s",
						    path, ent->d_name);
		}

		const void *build_id;
		size_t build_id_len;
		const char *message =
			get_gnu_build_id_from_note_file(fd, &buf, &capacity,
							&build_id,
							&build_id_len);
		if (message && message[0]) {
			return drgn_error_format_os(message, errno, "%s/%s",
						    path, ent->d_name);
		} else if (message) {
			return &drgn_enomem;
		}
		if (build_id_len > 0) {
			err = drgn_module_set_build_id(module, build_id,
						       build_id_len);
			if (!err) {
				drgn_log_debug(prog,
					       "found build ID %s in %s/%s",
					       module->build_id_str, path,
					       ent->d_name);
			}
			return err;
		}
	}
	if (errno)
		return drgn_error_create_os("readdir", errno, path);
	drgn_log_debug(prog, "couldn't find build ID in %s", path);
	return NULL;
}

static struct drgn_error *
kernel_module_set_build_id(struct drgn_module *module,
			   const struct drgn_object *module_obj,
			   bool use_sys_module)
{
	if (use_sys_module)
		return kernel_module_set_build_id_live(module);

	struct drgn_error *err;
	struct drgn_program *prog = module->prog;
	const bool bswap = drgn_platform_bswap(&prog->platform);

	DRGN_OBJECT(attrs, prog);
	DRGN_OBJECT(attr, prog);
	DRGN_OBJECT(tmp, prog);
	_cleanup_free_ void *buf = NULL;
	size_t capacity = 0;

	err = drgn_object_member(&attrs, module_obj, "notes_attrs");
	if (err)
		return err;

	bool group = true;
	uint64_t n;
	err = drgn_object_member_dereference(&attrs, &attrs, "grp");
	if (!err) {
		// Since Linux kernel commit 4723f16de64e ("module: sysfs: Add
		// notes attributes through attribute_group") (in v6.14), we
		// have to iterate over struct attribute_group::bin_attrs, a
		// null-terminated array of struct bin_attribute pointers.

		// attr = mod->notes_attrs->grp.bin_attrs
		err = drgn_object_member(&attrs, &attrs, "bin_attrs");
		if (err)
			return err;
	} else if (drgn_error_catch(&err, DRGN_ERROR_LOOKUP)) {
		// Before that, there was no struct attribute_group for notes,
		// so we iterate over struct module_notes_attrs::attrs, an array
		// of struct bin_attribute with a length given by struct
		// module_notes_attrs::notes.
		group = false;
		// n = mod->notes_attrs->notes
		err = drgn_object_member_dereference(&tmp, &attrs, "notes");
		if (err)
			return err;
		err = drgn_object_read_unsigned(&tmp, &n);
		if (err)
			return err;

		// attrs = mod->notes_attrs->attrs
		err = drgn_object_member_dereference(&attrs, &attrs, "attrs");
		if (err)
			return err;
	} else {
		return err;
	}

	// If we're not using struct attribute_group, we know how many
	// attributes there are.
	for (uint64_t i = 0; group || i < n; i++) {
		// attr = attrs[i]
		err = drgn_object_subscript(&attr, &attrs, i);
		if (err)
			return err;

		if (group) {
			// If we're using struct attribute_group, we stop when
			// we hit a NULL pointer.
			err = drgn_object_read(&attr, &attr);
			if (err)
				return err;
			bool truthy;
			err = drgn_object_bool(&attr, &truthy);
			if (err)
				return err;
			if (!truthy)
				break;
		} else {
			// attr = &attrs[i]
			err = drgn_object_address_of(&attr, &attr);
			if (err)
				return err;
		}

		// address = attr->private
		err = drgn_object_member_dereference(&tmp, &attr, "private");
		if (err)
			return err;
		uint64_t address;
		err = drgn_object_read_unsigned(&tmp, &address);
		if (err)
			return err;

		// size = attr->size
		err = drgn_object_member_dereference(&tmp, &attr, "size");
		if (err)
			return err;
		uint64_t size;
		err = drgn_object_read_unsigned(&tmp, &size);
		if (err)
			return err;

		if (size > SIZE_MAX || !alloc_or_reuse(&buf, &capacity, size))
			return &drgn_enomem;

		err = drgn_program_read_memory(prog, buf, address, size, false);
		if (err)
			return err;

		const void *build_id;
		size_t build_id_len =
			parse_gnu_build_id_from_notes(buf, size, 4, bswap,
						      &build_id);
		if (build_id_len > 0) {
			err = drgn_module_set_build_id(module, build_id,
						       build_id_len);
			if (!err) {
				drgn_log_debug(prog,
					       "found build ID %s in notes_attrs",
					       module->build_id_str);
			}
			return err;
		}
	}
	drgn_log_debug(prog,
		       "couldn't find build ID in notes_attrs");
	return NULL;
}

static struct drgn_error *
kernel_module_set_section_addresses_live(struct drgn_module *module)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	_cleanup_free_ char *path;
	if (asprintf(&path, "/sys/module/%s/sections", module->name) < 0) {
		path = NULL;
		return &drgn_enomem;
	}
	_cleanup_closedir_ DIR *dir = opendir(path);
	if (!dir)
		return drgn_error_create_os("opendir", errno, path);

	struct dirent *ent;
	while ((errno = 0, ent = readdir(dir))) {
		if (ent->d_type == DT_DIR)
			continue;

		_cleanup_close_ int fd = openat(dirfd(dir), ent->d_name,
						O_RDONLY);
		if (fd < 0) {
			return drgn_error_format_os("openat", errno, "%s/%s",
						    path, ent->d_name);
		}

		_cleanup_fclose_ FILE *file = fdopen(fd, "r");
		if (!file)
			return drgn_error_create_os("fdopen", errno, NULL);
		uint64_t address;
		if (fscanf(file, "%" SCNx64, &address) != 1) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "could not parse %s/%s",
						 path, ent->d_name);
		}

		drgn_log_debug(prog, "found section %s@0x%" PRIx64 " in %s",
			       ent->d_name, address, path);
		err = drgn_module_set_section_address(module, ent->d_name,
						      address);
		if (err)
			return err;
	}
	if (errno)
		return drgn_error_create_os("readdir", errno, path);
	return NULL;
}

static struct drgn_error *
kernel_module_set_section_addresses(struct drgn_module *module,
				    const struct drgn_object *module_obj,
				    bool use_sys_module)
{
	struct drgn_error *err;
	struct drgn_program *prog = module->prog;

	DRGN_OBJECT(tmp, prog);

	// As of Linux 6.0, the .data..percpu section is not included in the
	// section attributes. (kernel/module/sysfs.c:add_sect_attrs() only
	// creates attributes for sections with the SHF_ALLOC flag set, but
	// kernel/module/main.c:layout_and_allocate() clears the SHF_ALLOC flag
	// for the .data..percpu section.) However, we need this address so that
	// global per-CPU variables will be relocated correctly. Get it from
	// `struct module`.
	err = drgn_object_member(&tmp, module_obj, "percpu");
	if (!err) {
		uint64_t address;
		err = drgn_object_read_unsigned(&tmp, &address);
		if (err)
			return err;
		drgn_log_debug(prog, "module percpu is 0x%" PRIx64, address);
		// struct module::percpu is NULL if the module doesn't have any
		// per-CPU data.
		if (address) {
			err = drgn_module_set_section_address(module,
							      ".data..percpu",
							      address);
			if (err)
				return err;
		}
	} else if (err->code == DRGN_ERROR_LOOKUP) {
		// struct module::percpu doesn't exist if !SMP.
		drgn_error_destroy(err);
	} else {
		return err;
	}

	if (use_sys_module) {
		err = kernel_module_set_section_addresses_live(module);
		// We could be debugging /proc/kcore without root privileges via
		// an fd that we were passed. If we didn't have permission to
		// access the files in /sys/module/$module/sections, fall back
		// to the non-live path.
		if (!err || err->code != DRGN_ERROR_OS || err->errnum != EACCES)
			return err;
		drgn_error_log_debug(prog, err, "falling back to sect_attrs: ");
		drgn_error_destroy(err);
	}

	DRGN_OBJECT(attrs, prog);
	DRGN_OBJECT(attr, prog);

	err = drgn_object_member(&attrs, module_obj, "sect_attrs");
	if (err)
		return err;

	bool group = true;
	uint64_t nsections;
	err = drgn_object_member_dereference(&tmp, &attrs, "nsections");
	if (drgn_error_catch(&err, DRGN_ERROR_LOOKUP)) {
		// Since Linux kernel commit d8959b947a8d ("module: sysfs: Drop
		// member 'module_sect_attrs::nsections'") (in v6.14), we have
		// to iterate over struct attribute_group::bin_attrs, a
		// null-terminated array of struct bin_attribute pointers.

		// attrs = mod->sect_attrs->grp.bin_attrs
		err = drgn_object_member_dereference(&attrs, &attrs, "grp");
		if (err)
			return err;
		err = drgn_object_member(&attrs, &attrs, "bin_attrs");
		if (err)
			return err;
	} else if (!err) {
		// Before that, struct module_sect_attrs::grp still exists.
		// However, since Linux kernel commit ed66f991bb19 ("module:
		// Refactor section attr into bin attribute") (in v5.8), the
		// sections are in struct attribute_group::bin_attrs, and before
		// that, they're in struct attribute_group::attrs. Additionally,
		// we'd then have to get the containing struct module_sect_attr
		// to get the section address.
		//
		// Instead, it's easier to iterate over struct
		// module_sect_attrs::attrs, an array of struct module_sect_attr
		// with a length given by struct module_sect_attrs::nsections.
		group = false;
		// nsections = mod->sect_attrs->nsections
		err = drgn_object_read_unsigned(&tmp, &nsections);
		if (err)
			return err;

		// attrs = mod->sect_attrs->attrs
		err = drgn_object_member_dereference(&attrs, &attrs, "attrs");
		if (err)
			return err;
	} else {
		return err;
	}

	// If we're not using struct attribute_group, we know how many
	// attributes there are.
	for (uint64_t i = 0; group || i < nsections; i++) {
		// attr = attrs[i]
		err = drgn_object_subscript(&attr, &attrs, i);
		if (err)
			return err;

		if (group) {
			// If we're using struct attribute_group, we stop when
			// we hit a NULL pointer.
			err = drgn_object_read(&attr, &attr);
			if (err)
				return err;
			bool truthy;
			err = drgn_object_bool(&attr, &truthy);
			if (err)
				return err;
			if (!truthy)
				break;
			// Since Linux kernel commit 4b2c11e4aaf7 ("module:
			// sysfs: Drop member 'module_sect_attr::address'") (in
			// v6.14), the section address is in struct
			// bin_attribute::private.
			err = drgn_object_member_dereference(&tmp, &attr,
							     "private");
		} else {
			// Before that, the section address is in struct
			// module_sect_attr::address.
			err = drgn_object_member(&tmp, &attr, "address");
			if (err)
				return err;
		}
		uint64_t address;
		err = drgn_object_read_unsigned(&tmp, &address);
		if (err)
			return err;

		if (group) {
			// attr = attr->attr
			err = drgn_object_member_dereference(&attr, &attr,
							     "attr");
			if (err)
				return err;
		} else {
			// Since Linux kernel commit ed66f991bb19 ("module:
			// Refactor section attr into bin attribute") (in v5.8),
			// the section name is module_sect_attr.battr.attr.name.
			// Before that, it is simply module_sect_attr.name.

			// attr = attr.battr.attr
			err = drgn_object_member(&attr, &attr, "battr");
			if (!err) {
				err = drgn_object_member(&attr, &attr, "attr");
				if (err)
					return err;
			} else if (!drgn_error_catch(&err, DRGN_ERROR_LOOKUP)) {
				return err;
			}
		}
		err = drgn_object_member(&tmp, &attr, "name");
		if (err)
			return err;
		_cleanup_free_ char *name = NULL;
		err = drgn_object_read_c_string(&tmp, &name);
		if (err)
			return err;

		drgn_log_debug(prog,
			       "found section %s@0x%" PRIx64 " in sect_attrs",
			       name, address);
		err = drgn_module_set_section_address(module, name, address);
		if (err)
			return err;
	}
	return NULL;
}

static struct drgn_error *
kernel_module_find_or_create_internal(const struct drgn_object *module_obj,
				      struct drgn_module **ret, bool *new_ret,
				      bool create, bool log)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_object_program(module_obj);

	struct drgn_module_key key;
	key.kind = DRGN_MODULE_RELOCATABLE;
	uint64_t name_offset;
	err = drgn_type_offsetof(module_obj->type, "name", &name_offset);
	if (err)
		return err;
	if (name_offset >= drgn_object_size(module_obj)
	    || !memchr(drgn_object_buffer(module_obj) + name_offset, '\0',
		       drgn_object_size(module_obj) - name_offset)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "couldn't read module name");
	}
	key.relocatable.name = drgn_object_buffer(module_obj) + name_offset;

	DRGN_OBJECT(mem, prog);
	DRGN_OBJECT(val, prog);
	bool layout_in_module = false;
	err = drgn_object_member(&mem, module_obj, "mem");
	if (!err) {
		// Since Linux kernel commit ac3b43283923 ("module: replace
		// module_layout with module_memory") (in v6.4), the base and
		// size are in the `struct module_memory mem[MOD_TEXT]` member
		// of `struct module`.
		if (!prog->mod_text_cached) {
			err = drgn_program_find_object(prog, "MOD_TEXT", NULL,
						       DRGN_FIND_OBJECT_CONSTANT,
						       &val);
			if (err)
				return err;
			union drgn_value mod_text_value;
			err = drgn_object_read_integer(&val, &mod_text_value);
			if (err)
				return err;
			prog->mod_text = mod_text_value.uvalue;
			prog->mod_text_cached = true;
		}
		err = drgn_object_subscript(&mem, &mem, prog->mod_text);
		if (err)
			return err;
	} else {
		if (err->code != DRGN_ERROR_LOOKUP)
			return err;
		drgn_error_destroy(err);
		// Between that and Linux kernel commit 7523e4dc5057 ("module:
		// use a structure to encapsulate layout.") (in v4.5), the base
		// and size are in the `struct module_layout core_layout` member
		// of `struct module`.
		err = drgn_object_member(&mem, module_obj, "core_layout");
		if (err) {
			if (err->code != DRGN_ERROR_LOOKUP)
				return err;
			drgn_error_destroy(err);
			// Before that, they are directly in the `struct
			// module`.
			layout_in_module = true;
		}
	}
	if (layout_in_module)
		err = drgn_object_member(&val, module_obj, "module_core");
	else
		err = drgn_object_member(&val, &mem, "base");
	if (err)
		return err;
	err = drgn_object_read_unsigned(&val, &key.relocatable.address);
	if (err)
		return err;

	if (log) {
		drgn_log_debug(prog, "found loaded kernel module %s@0x%" PRIx64,
			       key.relocatable.name, key.relocatable.address);
	}

	if (!create) {
		*ret = drgn_module_find(prog, &key);
		if (new_ret)
			*new_ret = false;
		return NULL;
	}

	_cleanup_(drgn_module_deletep) struct drgn_module *module = NULL;
	bool new;
	err = drgn_module_find_or_create(prog, &key, key.relocatable.name,
					 &module, &new);
	if (err)
		return err;
	if (!new) {
		*ret = no_cleanup_ptr(module);
		if (new_ret)
			*new_ret = new;
		return NULL;
	}

	if (layout_in_module)
		err = drgn_object_member(&val, module_obj, "core_size");
	else
		err = drgn_object_member(&val, &mem, "size");
	if (err)
		return err;
	uint64_t size;
	err = drgn_object_read_unsigned(&val, &size);
	if (err)
		return err;

	drgn_log_debug(prog, "module size is %" PRIu64, size);
	err = drgn_module_set_address_range(module, key.relocatable.address,
					    key.relocatable.address + size);
	if (err)
		return err;

	// If we're debugging the running kernel, we can use
	// /sys/module/$module/notes and /sys/module/$module/sections instead of
	// getting the equivalent information from the core dump. This fast path
	// can be disabled via an environment variable for testing. It may also
	// be disabled if we encounter permission issues using
	// /sys/module/$module/sections.
	bool use_sys_module = false;
	if (prog->flags & DRGN_PROGRAM_IS_LOCAL) {
		char *env = getenv("DRGN_USE_SYS_MODULE");
		use_sys_module = !env || atoi(env);
	}
	err = kernel_module_set_build_id(module, module_obj, use_sys_module);
	if (err)
		return err;
	err = kernel_module_set_section_addresses(module, module_obj,
						  use_sys_module);
	if (err)
		return err;

	*ret = no_cleanup_ptr(module);
	if (new_ret)
		*new_ret = new;
	return NULL;
}

static struct drgn_error *
drgn_module_find_or_create_linux_kernel_loadable_internal(const struct drgn_object *module_obj,
							  struct drgn_module **ret,
							  bool *new_ret,
							  bool create)
{
	struct drgn_error *err;

	// kernel_module_find_or_create_internal() expects a `struct module`
	// value.
	struct drgn_object mod;
	if (drgn_type_kind(drgn_underlying_type(module_obj->type))
	    == DRGN_TYPE_POINTER) {
		drgn_object_init(&mod, drgn_object_program(module_obj));
		err = drgn_object_dereference(&mod, module_obj);
		if (!err)
			err = drgn_object_read(&mod, &mod);
		module_obj = &mod;
		if (err)
			goto out;
	} else if (module_obj->kind != DRGN_OBJECT_VALUE) {
		drgn_object_init(&mod, drgn_object_program(module_obj));
		err = drgn_object_read(&mod, module_obj);
		module_obj = &mod;
		if (err)
			goto out;
	}

	err = kernel_module_find_or_create_internal(module_obj, ret, new_ret,
						    create, false);
out:
	if (module_obj == &mod)
		drgn_object_deinit(&mod);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_find_linux_kernel_loadable(const struct drgn_object *module_obj,
				       struct drgn_module **ret)
{
	return drgn_module_find_or_create_linux_kernel_loadable_internal(module_obj,
									 ret,
									 NULL,
									 false);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_module_find_or_create_linux_kernel_loadable(const struct drgn_object *module_obj,
						 struct drgn_module **ret,
						 bool *new_ret)
{
	return drgn_module_find_or_create_linux_kernel_loadable_internal(module_obj,
									 ret,
									 new_ret,
									 true);
}

static struct drgn_error *
yield_kernel_module(struct linux_kernel_loaded_module_iterator *it,
		    struct drgn_module **ret, bool *new_ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = it->it.prog;

	DRGN_OBJECT(mod, prog);
	for (;;) {
		uint64_t addr;
		err = drgn_object_read_unsigned(&it->node, &addr);
		if (err) {
list_walk_err:
			if (!drgn_error_is_fatal(err)) {
				drgn_error_log_warning(prog, err,
						       "can't find remaining kernel modules: "
						       "couldn't read next module: ");
				drgn_error_destroy(err);
				*ret = NULL;
				err = NULL;
			}
			return err;
		}
		if (addr == it->modules_head) {
			drgn_log_debug(prog,
				       "found end of loaded kernel module list");
			*ret = NULL;
			return NULL;
		}

		if (it->module_list_iterations_remaining == 0) {
			drgn_log_warning(prog,
					 "can't find remaining kernel modules: "
					 "too many entries or cycle in modules list");
			*ret = NULL;
			return NULL;
		}
		it->module_list_iterations_remaining--;

		err = drgn_object_container_of(&mod, &it->node, it->module_type,
					       "list");
		if (err)
			goto list_walk_err;

		err = drgn_object_dereference(&mod, &mod);
		if (err)
			goto list_walk_err;
		// We need several fields from the `struct module`. Especially
		// for /proc/kcore, it is faster to read the entire structure
		// (which is <2kB as of Linux 6.5) from the core dump all at
		// once than it is to read each field individually.
		err = drgn_object_read(&mod, &mod);
		if (err)
			goto list_walk_err;

		err = drgn_object_member(&it->node, &mod, "list");
		if (err)
			goto list_walk_err;
		err = drgn_object_member(&it->node, &it->node, "next");
		if (err)
			goto list_walk_err;

		err = kernel_module_find_or_create_internal(&mod, ret, new_ret,
							    true, true);
		if (err && !drgn_error_is_fatal(err)) {
			drgn_error_log_warning(prog, err, "ignoring module: ");
			drgn_error_destroy(err);
			continue;
		}
		return err;
	}
}

static struct drgn_error *
linux_kernel_loaded_module_iterator_next(struct drgn_module_iterator *_it,
					 struct drgn_module **ret,
					 bool *new_ret)
{
	struct drgn_error *err;
	struct linux_kernel_loaded_module_iterator *it =
		container_of(_it, struct linux_kernel_loaded_module_iterator, it);
	struct drgn_program *prog = it->it.prog;

	if (!it->yielded_vmlinux) {
		it->yielded_vmlinux = true;
		return yield_vmlinux(it, ret, new_ret);
	}

	// Start the module list walk if we haven't yet.
	if (!it->module_type.type) {
		for (int attempt = 1; attempt <= 2; attempt++) {
			err = drgn_program_find_type(prog, "struct module",
						     NULL, &it->module_type);
			if (!err) {
				err = drgn_program_find_object(prog, "modules",
							       NULL,
							       DRGN_FIND_OBJECT_VARIABLE,
							       &it->node);
			}
			if (err && err->code == DRGN_ERROR_LOOKUP) {
				drgn_error_destroy(err);
				if (attempt == 1 && prog->dbinfo.main_module) {
					struct drgn_module *module =
						prog->dbinfo.main_module;
				    if (module->debug_file_status
					== DRGN_MODULE_FILE_DONT_WANT) {
					    module->debug_file_status =
						    DRGN_MODULE_FILE_WANT;
				    }
				    if (drgn_module_wants_debug_file(module)) {
					    err = drgn_load_module_debug_info(&module,
									      &(size_t){1});
					    if (err)
						    return err;
					    continue;
				    }
				}
				if (!prog->dbinfo.main_module
				    || drgn_module_wants_debug_file(prog->dbinfo.main_module)) {
					drgn_log_warning(prog,
							 "can't find loaded modules without kernel debug info");
				} else {
					drgn_log_debug(prog,
						       "kernel does not have loadable module support");
				}
				*ret = NULL;
				return NULL;
			} else if (err) {
				return err;
			}
		}
		if (it->node.kind != DRGN_OBJECT_REFERENCE) {
			drgn_log_warning(prog,
					 "can't find kernel modules: "
					 "can't get address of modules list");
			*ret = NULL;
			return NULL;
		}
		it->modules_head = it->node.address;
		err = drgn_object_member(&it->node, &it->node, "next");
		if (!err)
			err = drgn_object_read(&it->node, &it->node);
		if (err) {
			if (drgn_error_is_fatal(err))
				return err;
			drgn_error_log_warning(prog, err,
					       "can't find kernel modules: "
					       "couldn't read modules list: ");
			drgn_error_destroy(err);
			*ret = NULL;
			return NULL;
		}
	}

	return yield_kernel_module(it, ret, new_ret);
}

struct drgn_error *
linux_kernel_loaded_module_iterator_create(struct drgn_program *prog,
					   struct drgn_module_iterator **ret)
{
	struct linux_kernel_loaded_module_iterator *it = calloc(1, sizeof(*it));
	if (!it)
		return &drgn_enomem;
	drgn_module_iterator_init(&it->it, prog,
				  linux_kernel_loaded_module_iterator_destroy,
				  linux_kernel_loaded_module_iterator_next);
	it->module_list_iterations_remaining = MAX_MODULE_LIST_ITERATIONS;
	drgn_object_init(&it->node, prog);
	*ret = &it->it;
	return NULL;
}
