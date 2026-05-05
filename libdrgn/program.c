// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <assert.h>
#include <byteswap.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "cleanup.h"
#include "debug_info.h"
#include "elf_notes.h"
#include "error.h"
#include "io.h"
#include "language.h"
#include "linux_kernel.h"
#include "log.h"
#include "memory_reader.h"
#include "minmax.h"
#include "object.h"
#include "plugins.h"
#include "program.h"
#include "register_state.h"
#include "serialize.h"
#include "symbol.h"
#include "thread.h"
#include "util.h"
#include "vector.h"

DEFINE_VECTOR(drgn_prstatus_vector, struct drgn_prstatus);

static inline uint32_t drgn_prstatus_to_key(struct drgn_prstatus * const *entry)
{
	return (*entry)->tid;
}

DEFINE_HASH_TABLE_FUNCTIONS(drgn_prstatus_table, drgn_prstatus_to_key,
			    int_key_hash_pair, scalar_key_eq);

LIBDRGN_PUBLIC enum drgn_program_flags
drgn_program_flags(struct drgn_program *prog)
{
	return prog->flags;
}

LIBDRGN_PUBLIC const struct drgn_platform *
drgn_program_platform(struct drgn_program *prog)
{
	return prog->has_platform ? &prog->platform : NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_address_size(struct drgn_program *prog, uint64_t *ret)
{
	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program address size is not known");
	}
	*ret = drgn_platform_address_size(&prog->platform);
	return NULL;
}

LIBDRGN_PUBLIC
const char *drgn_program_core_dump_path(struct drgn_program *prog)
{
	return prog->core_path;
}

LIBDRGN_PUBLIC const struct drgn_language *
drgn_program_language(struct drgn_program *prog)
{
	if (prog->lang)
		return prog->lang;
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		prog->lang = &drgn_language_c;
		return prog->lang;
	}
	if (!prog->tried_main_language) {
		prog->tried_main_language = true;
		prog->lang = drgn_debug_info_main_language(&prog->dbinfo);
		if (prog->lang) {
			drgn_log_debug(prog,
				       "set default language to %s from main()",
				       prog->lang->name);
			return prog->lang;
		} else {
			drgn_log_debug(prog,
				       "couldn't find language of main(); defaulting to %s",
				       drgn_default_language.name);
		}
	}
	return &drgn_default_language;
}

LIBDRGN_PUBLIC void drgn_program_set_language(struct drgn_program *prog,
					      const struct drgn_language *lang)
{
	prog->lang = lang;
}

void drgn_program_set_platform(struct drgn_program *prog,
			       const struct drgn_platform *platform)
{
	if (!prog->has_platform) {
		prog->platform = *platform;
		prog->has_platform = true;
	}
}

#define type_finder_only_one_enabled 0
#define object_finder_only_one_enabled 0
#define symbol_finder_only_one_enabled 0
#define debug_info_finder_only_one_enabled 0
#define thread_finder_only_one_enabled 1
#define register_state_finder_only_one_enabled 0

#define X(which)								\
static void drgn_##which##_destroy(struct drgn_##which *handler)		\
{										\
	if (handler->ops.destroy)						\
		handler->ops.destroy(handler->arg);				\
	drgn_##which##_deinit(handler);						\
	drgn_handler_destroy(&handler->handler);				\
}										\
										\
struct drgn_error *								\
drgn_program_register_##which##_impl(struct drgn_program *prog,			\
				     struct drgn_##which **handlerp,		\
				     const char *name,				\
				     const struct drgn_##which##_ops *ops,	\
				     size_t ops_size, void *arg,		\
				     size_t enable_index)			\
{										\
	struct drgn_error *err;							\
	if (ops_size > sizeof(*ops)						\
	    && !mem_is_zero(ops + 1, ops_size - sizeof(*ops))) {		\
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,		\
					 "drgn_" #which "_ops size is too large");\
	}									\
	if (which##_only_one_enabled						\
	    && enable_index != DRGN_HANDLER_REGISTER_DONT_ENABLE		\
	    && drgn_handler_list_has_enabled(&prog->which##s)) {		\
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,		\
					 "only one " #which " may be enabled");	\
	}									\
	struct drgn_##which *handler = handlerp ? *handlerp : NULL;		\
	if (handler) {								\
		handler->handler.name = name;					\
		handler->handler.free = false;					\
	} else {								\
		handler = malloc(sizeof(*handler));				\
		if (!handler)							\
			return &drgn_enomem;					\
		handler->handler.name = strdup(name);				\
		if (!handler->handler.name) {					\
			free(handler);						\
			return &drgn_enomem;					\
		}								\
		handler->handler.free = true;					\
	}									\
	memcpy(&handler->ops, ops, min(ops_size, sizeof(handler->ops)));	\
	if (ops_size < sizeof(handler->ops)) {					\
		memset((char *)&handler->ops + ops_size, 0,			\
		       sizeof(handler->ops) - ops_size);			\
	}									\
	handler->arg = arg;							\
	err = drgn_##which##_init(prog, handler);				\
	if (err)								\
		goto err_free;							\
	err = drgn_handler_list_register(&prog->which##s, &handler->handler,	\
					 enable_index, #which);			\
	if (err)								\
		goto err_deinit;						\
	if (handlerp)								\
		*handlerp = handler;						\
	return NULL;								\
										\
err_deinit:									\
	drgn_##which##_deinit(handler);						\
err_free:									\
	drgn_handler_destroy(&handler->handler);				\
	return err;								\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_register_##which(struct drgn_program *prog, const char *name,	\
			      const struct drgn_##which##_ops *ops,		\
			      size_t ops_size, void *arg, size_t enable_index)	\
{										\
	return drgn_program_register_##which##_impl(prog, NULL, name, ops,	\
						    ops_size, arg,		\
						    enable_index);		\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_registered_##which##s(struct drgn_program *prog,			\
				   const char ***names_ret, size_t *count_ret)	\
{										\
	return drgn_handler_list_registered(&prog->which##s, names_ret,		\
					    count_ret);				\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_set_enabled_##which##s(struct drgn_program *prog,			\
				    const char * const *names, size_t count)	\
{										\
	if (which##_only_one_enabled && count > 1) {				\
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,		\
					 "only one " #which " may be enabled");	\
	}									\
	return drgn_handler_list_set_enabled(&prog->which##s, names, count,	\
					     #which);				\
}										\
										\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_enabled_##which##s(struct drgn_program *prog,			\
				const char ***names_ret, size_t *count_ret)	\
{										\
	return drgn_handler_list_enabled(&prog->which##s, names_ret, count_ret);\
}										\
										\
/*										\
 * This may only be used to clean up a handler that was just registered before	\
 * it could be exposed to the user.						\
 */										\
void drgn_program_unregister_##which(struct drgn_program *prog,			\
				     const char *name)				\
{										\
	struct drgn_handler *handler =						\
		drgn_handler_list_unregister(&prog->which##s, name);		\
	if (handler)								\
		drgn_##which##_destroy((void *)handler);			\
}
DRGN_PROGRAM_HANDLERS
#undef X

void drgn_program_init(struct drgn_program *prog,
		       const struct drgn_platform *platform)
{
	memset(prog, 0, sizeof(*prog));
	drgn_memory_reader_init(&prog->reader);
	drgn_program_init_types(prog);
	drgn_debug_info_init(&prog->dbinfo, prog);
	prog->core_fd = -1;
	drgn_qmp_conn_init(&prog->qmp_conn);
	if (platform)
		drgn_program_set_platform(prog, platform);
	drgn_prstatus_table_init(&prog->prstatus_table);
	drgn_program_set_log_level(prog, DRGN_LOG_NONE);
	drgn_program_set_log_file(prog, stderr);
	prog->default_progress_file = true;
	drgn_object_init(&prog->vmemmap, prog);
}

void drgn_program_deinit(struct drgn_program *prog)
{
	drgn_prstatus_table_deinit(&prog->prstatus_table);
	free(prog->prstatuses);
	if (prog->pgtable_it)
		prog->platform.arch->linux_kernel_pgtable_iterator_destroy(prog->pgtable_it);

	drgn_object_deinit(&prog->vmemmap);

#define X(which)								\
	drgn_handler_list_for_each_safe(struct drgn_##which, handler, next,	\
					&prog->which##s)			\
		drgn_##which##_destroy(handler);
	DRGN_PROGRAM_HANDLERS
#undef X
	drgn_program_deinit_types(prog);
	drgn_memory_reader_deinit(&prog->reader);

	free(prog->file_segments);
	free(prog->vmcoreinfo.raw);
	free(prog->irq_regs_cached);

	drgn_qmp_conn_deinit(&prog->qmp_conn);
#ifdef WITH_LIBKDUMPFILE
	if (prog->kdump_ctx)
		kdump_free(prog->kdump_ctx);
#endif
	free(prog->core_path);
	elf_end(prog->core);
	if (prog->core_fd != -1)
		close(prog->core_fd);

	drgn_debug_info_deinit(&prog->dbinfo);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_add_memory_segment(struct drgn_program *prog, uint64_t address,
				uint64_t size, drgn_memory_read_fn read_fn,
				void *arg, bool physical)
{
	uint64_t address_mask;
	struct drgn_error *err = drgn_program_address_mask(prog, &address_mask);
	if (err)
		return err;
	if (size == 0 || address > address_mask)
		return NULL;
	uint64_t max_address = address + min(size - 1, address_mask - address);
	return drgn_memory_reader_add_segment(&prog->reader, address,
					      max_address, read_fn, arg,
					      physical);
}

struct drgn_error *
drgn_program_check_initialized(struct drgn_program *prog)
{
	if (prog->core_fd != -1 || !drgn_memory_reader_empty(&prog->reader)) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "program memory was already initialized");
	}
	return NULL;
}

static struct drgn_error *
has_kdump_signature(struct drgn_program *prog, const char *path, bool *ret)
{
	char signature[max_iconst(KDUMP_SIG_LEN, FLATTENED_SIG_LEN)];
	ssize_t r = pread_all(prog->core_fd, signature, sizeof(signature), 0);
	if (r < 0)
		return drgn_error_create_os("pread", errno, path);
	*ret = false;
	if (r >= FLATTENED_SIG_LEN
	    && memcmp(signature, FLATTENED_SIGNATURE, FLATTENED_SIG_LEN) == 0) {
		drgn_log_warning(prog,
				 "the given file is in the makedumpfile flattened "
				 "format; if open fails or is too slow, reassemble "
				 "it with 'makedumpfile -R newfile <oldfile'");
		*ret = true;
	} else if (r >= KDUMP_SIG_LEN
		   && memcmp(signature, KDUMP_SIGNATURE, KDUMP_SIG_LEN) == 0)
		*ret = true;
	return NULL;
}

static struct drgn_error *drgn_cache_prpsinfo(struct drgn_program *prog,
					      const char *data, size_t size)
{
	bool is_64_bit, bswap;
	struct drgn_error *err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;

	size_t pid_offset = is_64_bit ? 24 : 12;
	size_t fname_offset = is_64_bit ? 40 : 28;
	static const size_t pr_fname_size = 16;

	if (size < fname_offset + pr_fname_size) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "NT_PRPSINFO is truncated");
	}

	uint32_t pr_pid;
	memcpy(&pr_pid, data + pid_offset, sizeof(pr_pid));
	if (bswap)
		pr_pid = bswap_32(pr_pid);
	prog->prpsinfo.pid = pr_pid;

	memcpy(prog->prpsinfo.fname, data + fname_offset, pr_fname_size);
	// Ensure that our copy is null-terminated even if the source wasn't.
	prog->prpsinfo.fname[pr_fname_size] = '\0';

	prog->prpsinfo.found = true;
	return NULL;
}

static struct drgn_error *get_prstatus_pid(struct drgn_program *prog, const char *data,
					   size_t size, uint32_t *ret)
{
	bool is_64_bit, bswap;
	struct drgn_error *err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;

	size_t offset = is_64_bit ? 32 : 24;
	uint32_t pr_pid;
	if (size < offset + sizeof(pr_pid)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "NT_PRSTATUS is truncated");
	}
	memcpy(&pr_pid, data + offset, sizeof(pr_pid));
	if (bswap)
		pr_pid = bswap_32(pr_pid);
	*ret = pr_pid;
	return NULL;
}

struct drgn_error *drgn_cache_prstatus(struct drgn_program *prog,
				       struct drgn_prstatus_vector *prstatuses,
				       const char *data, size_t size)
{
	uint32_t tid;
	struct drgn_error *err = get_prstatus_pid(prog, data, size, &tid);
	if (err)
		return err;
	struct drgn_prstatus *entry =
		drgn_prstatus_vector_append_entry(prstatuses);
	if (!entry)
		return &drgn_enomem;
	entry->tid = tid;
	entry->data = data;
	entry->size = size;
	return NULL;
}

static struct drgn_error *
drgn_program_cache_core_dump_threads(struct drgn_program *prog)
{
	struct drgn_error *err;

	if (prog->core_dump_threads_cached)
		return NULL;

	assert(!(prog->flags & DRGN_PROGRAM_IS_LIVE));

	VECTOR(drgn_prstatus_vector, prstatuses);
#ifdef WITH_LIBKDUMPFILE
	if (prog->kdump_ctx) {
		err = drgn_program_cache_kdump_threads(prog, &prstatuses);
		if (err)
			goto err;
		goto out;
	}
#endif
	if (!prog->core) {
		err = NULL;
		goto out;
	}
	size_t phnum;
	if (elf_getphdrnum(prog->core, &phnum) != 0) {
		err = drgn_error_libelf();
		goto err;
	}
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;
		phdr = gelf_getphdr(prog->core, i, &phdr_mem);
		if (!phdr) {
			err = drgn_error_libelf();
			goto err;
		}
		if (phdr->p_type != PT_NOTE)
			continue;

		Elf_Data *data = elf_getdata_rawchunk(prog->core,
						      phdr->p_offset,
						      phdr->p_filesz,
						      note_header_type(phdr->p_align));
		if (!data) {
			err = drgn_error_libelf();
			goto err;
		}

		size_t offset = 0;
		GElf_Nhdr nhdr;
		size_t name_offset, desc_offset;
		while (offset < data->d_size &&
		       (offset = gelf_getnote(data, offset, &nhdr, &name_offset,
					      &desc_offset))) {
			const char *name;

			name = (char *)data->d_buf + name_offset;
			if (strncmp(name, "CORE", nhdr.n_namesz) != 0)
				continue;

			if (nhdr.n_type == NT_PRPSINFO) {
				err = drgn_cache_prpsinfo(prog,
							  (char *)data->d_buf + desc_offset,
							  nhdr.n_descsz);
				if (err)
					goto err;
			} else if (nhdr.n_type == NT_PRSTATUS) {
				err = drgn_cache_prstatus(prog, &prstatuses,
							  (char *)data->d_buf + desc_offset,
							  nhdr.n_descsz);
				if (err)
					goto err;
			}
		}
	}

out:
	drgn_prstatus_vector_shrink_to_fit(&prstatuses);
	drgn_prstatus_vector_steal(&prstatuses, &prog->prstatuses,
				   &prog->num_prstatuses);
	for (size_t i = 0; i < prog->num_prstatuses; i++) {
		struct drgn_prstatus *prstatus = &prog->prstatuses[i];
		if (drgn_prstatus_table_insert(&prog->prstatus_table, &prstatus,
					       NULL) < 0) {
			err = &drgn_enomem;
			goto err;
		}
	}

	prog->core_dump_threads_cached = true;
	return NULL;

err:
	prog->prpsinfo.found = false;
	drgn_prstatus_table_deinit(&prog->prstatus_table);
	drgn_prstatus_table_init(&prog->prstatus_table);
	free(prog->prstatuses);
	prog->prstatuses = NULL;
	prog->num_prstatuses = 0;
	return err;
}

static struct drgn_error *
userspace_core_thread_iterator_create(void *arg,
				     struct drgn_thread_cache *cache,
				     void **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_thread_cache_program(cache);
	err = drgn_program_cache_core_dump_threads(prog);
	if (err)
		return err;
	size_t *index = calloc(1, sizeof(*index));
	if (!index)
		return &drgn_enomem;
	*ret = index;
	return NULL;
}

static struct drgn_error *
userspace_core_thread_create(struct drgn_thread_cache *cache,
			     struct drgn_prstatus *prstatus,
			     struct drgn_thread **ret)
{
	struct drgn_error *err;
	bool new;
	err = drgn_thread_cache_find_or_create(cache, prstatus->tid, 0, NULL,
					       ret, &new);
	if (!err && new)
		drgn_thread_set_finder_data(*ret, prstatus);
	return err;
}

static struct drgn_error *
userspace_core_thread_iterator_next(void *arg, struct drgn_thread_cache *cache,
				    void *it, struct drgn_thread **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_thread_cache_program(cache);

	size_t *index = it;
	if (*index >= prog->num_prstatuses) {
		*ret = NULL;
		return NULL;
	}
	struct drgn_prstatus *prstatus = &prog->prstatuses[*index];

	err = userspace_core_thread_create(cache, prstatus, ret);
	if (!err)
		(*index)++;
	return err;
}

static struct drgn_error *
userspace_core_find_thread(void *arg, struct drgn_thread_cache *cache,
			   uint32_t tid, struct drgn_thread **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_thread_cache_program(cache);
	err = drgn_program_cache_core_dump_threads(prog);
	if (err)
		return err;

	struct drgn_prstatus_table_iterator it =
		drgn_prstatus_table_search(&prog->prstatus_table, &tid);
	if (!it.entry) {
		*ret = NULL;
		return NULL;
	}
	return userspace_core_thread_create(cache, *it.entry, ret);
}

static struct drgn_error *
userspace_core_main_thread(void *arg, struct drgn_thread_cache *cache,
			   struct drgn_thread **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_thread_cache_program(cache);
	err = drgn_program_cache_core_dump_threads(prog);
	if (err)
		return err;

	if (!prog->prpsinfo.found) {
		*ret = NULL;
		return NULL;
	}

	return userspace_core_find_thread(arg, cache, prog->prpsinfo.pid, ret);
}

static struct drgn_error *
userspace_core_crashed_thread(void *arg, struct drgn_thread_cache *cache,
			      struct drgn_thread **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_thread_cache_program(cache);
	err = drgn_program_cache_core_dump_threads(prog);
	if (err)
		return err;

	// The first PRSTATUS note is the crashed thread. See
	// fs/binfmt_elf.c:fill_note_info in the Linux kernel and
	// bfd/elf.c:elfcore_grok_prstatus in BFD.
	if (prog->num_prstatuses == 0) {
		*ret = NULL;
		return NULL;
	}
	return userspace_core_thread_create(cache, &prog->prstatuses[0], ret);
}

static struct drgn_error *
userspace_core_thread_name(void *arg, struct drgn_thread *thread, char **ret)
{
	struct drgn_program *prog = drgn_thread_program(thread);

	if (!prog->prpsinfo.found) {
		*ret = NULL;
		return NULL;
	}

	// Core dumps only contain the main thread name.
	if (drgn_thread_tid(thread) != prog->prpsinfo.pid) {
		*ret = NULL;
		return NULL;
	}

	char *name = strdup(prog->prpsinfo.fname);
	if (!name)
		return &drgn_enomem;
	*ret = name;
	return NULL;
}

static const struct drgn_thread_finder_ops userspace_core_thread_finder_ops = {
	.iterator_create = userspace_core_thread_iterator_create,
	.iterator_destroy = free,
	.iterator_next = userspace_core_thread_iterator_next,
	.find_thread = userspace_core_find_thread,
	.main_thread = userspace_core_main_thread,
	.crashed_thread = userspace_core_crashed_thread,
	.thread_name = userspace_core_thread_name,
};

static struct drgn_error *
userspace_core_thread_register_state(void *arg, struct drgn_thread *thread,
				     struct drgn_register_state **ret)
{
	struct drgn_error *err;
	struct drgn_program *prog = drgn_thread_program(thread);

	// If the thread came from our corresponding thread finder, then we can
	// use the saved prstatus. Otherwise, we have to find it.
	const struct drgn_prstatus *prstatus;
	if (thread->finder->ops.find_thread == userspace_core_find_thread) {
		prstatus = drgn_thread_get_finder_data(thread);
	} else {
		err = drgn_program_find_prstatus(prog, drgn_thread_tid(thread),
						 &prstatus);
		if (err)
			return err;
		if (!prstatus) {
			*ret = NULL;
			return NULL;
		}
	}
	return drgn_register_state_from_prstatus(prog, prstatus->data,
						 prstatus->size, ret);
}

static const struct drgn_register_state_finder_ops
userspace_core_register_state_finder_ops = {
	.thread_register_state = userspace_core_thread_register_state,
};

static struct drgn_error *
drgn_program_set_core_dump_fd_internal(struct drgn_program *prog, int fd,
				       const char *path)
{
	struct drgn_error *err;
	GElf_Ehdr ehdr_mem, *ehdr;
	bool had_platform;
	bool is_64_bit, little_endian, is_kdump;
	size_t phnum, i;
	size_t num_file_segments, j;
	bool have_phys_addrs = false;
	bool have_qemu_note = false;
	const char *vmcoreinfo_note = NULL;
	size_t vmcoreinfo_size = 0;
	bool have_nt_taskstruct = false, is_proc_kcore;
	bool have_vmcoreinfo = prog->vmcoreinfo.raw;
	bool had_vmcoreinfo = have_vmcoreinfo;

	prog->core_fd = fd;
	prog->core_path = fd_canonical_path(fd, path);
	if (!prog->core_path) {
		err = &drgn_enomem;
		goto out_fd;
	}

	err = has_kdump_signature(prog, prog->core_path, &is_kdump);
	if (err)
		goto out_path;
	if (is_kdump) {
		err = drgn_program_set_kdump(prog);
		if (err)
			goto out_path;
		return NULL;
	}

	elf_version(EV_CURRENT);

	prog->core = elf_begin(prog->core_fd, ELF_C_READ, NULL);
	if (!prog->core) {
		err = drgn_error_libelf();
		goto out_path;
	}

	ehdr = gelf_getehdr(prog->core, &ehdr_mem);
	if (!ehdr || ehdr->e_type != ET_CORE) {
		err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					"not an ELF core file");
		goto out_elf;
	}
	had_platform = prog->has_platform;
	if (!had_platform) {
		struct drgn_platform platform;
		drgn_platform_from_elf(ehdr, &platform);
		drgn_program_set_platform(prog, &platform);
	}
	is_64_bit = ehdr->e_ident[EI_CLASS] == ELFCLASS64;
	little_endian = ehdr->e_ident[EI_DATA] == ELFDATA2LSB;

	if (elf_getphdrnum(prog->core, &phnum) != 0) {
		err = drgn_error_libelf();
		goto out_platform;
	}

	/*
	 * First pass: count the number of loadable segments, check if p_paddr
	 * is valid, and check for notes.
	 */
	num_file_segments = 0;
	for (i = 0; i < phnum; i++) {
		GElf_Phdr phdr_mem, *phdr;

		phdr = gelf_getphdr(prog->core, i, &phdr_mem);
		if (!phdr) {
			err = drgn_error_libelf();
			goto out_notes;
		}

		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_paddr)
				have_phys_addrs = true;
			num_file_segments++;
		} else if (phdr->p_type == PT_NOTE) {
			Elf_Data *data;
			size_t offset;
			GElf_Nhdr nhdr;
			size_t name_offset, desc_offset;

			data = elf_getdata_rawchunk(prog->core, phdr->p_offset,
						    phdr->p_filesz,
						    note_header_type(phdr->p_align));
			if (!data) {
				err = drgn_error_libelf();
				goto out_notes;
			}

			offset = 0;
			while (offset < data->d_size &&
			       (offset = gelf_getnote(data, offset, &nhdr,
						      &name_offset,
						      &desc_offset))) {
				const char *name, *desc;

				name = (char *)data->d_buf + name_offset;
				desc = (char *)data->d_buf + desc_offset;
				if (nhdr.n_namesz == sizeof("CORE") &&
				    memcmp(name, "CORE", sizeof("CORE")) == 0) {
					if (nhdr.n_type == NT_TASKSTRUCT)
						have_nt_taskstruct = true;
				} else if (nhdr.n_namesz == sizeof("LINUX") &&
					   memcmp(name, "LINUX",
						  sizeof("LINUX")) == 0) {
					if (nhdr.n_type == NT_ARM_PAC_MASK &&
					    nhdr.n_descsz >=
					    2 * sizeof(uint64_t)) {
						memcpy(&prog->aarch64_insn_pac_mask,
						       (uint64_t *)desc + 1,
						       sizeof(uint64_t));
						if (little_endian !=
						    HOST_LITTLE_ENDIAN)
							bswap_64(prog->aarch64_insn_pac_mask);
					}
				} else if (nhdr.n_namesz == sizeof("VMCOREINFO") &&
					   memcmp(name, "VMCOREINFO",
						  sizeof("VMCOREINFO")) == 0) {
					vmcoreinfo_note = desc;
					vmcoreinfo_size = nhdr.n_descsz;
					/*
					 * This is either a vmcore or
					 * /proc/kcore, so even a p_paddr of 0
					 * may be valid.
					 */
					have_phys_addrs = true;
					have_vmcoreinfo = true;
				} else if (nhdr.n_namesz == sizeof("QEMU") &&
					   memcmp(name, "QEMU",
						  sizeof("QEMU")) == 0) {
					have_qemu_note = true;
				}
			}
		}
	}

	if (have_nt_taskstruct) {
		/*
		 * If the core file has an NT_TASKSTRUCT note and is in /proc,
		 * then it's probably /proc/kcore.
		 */
		struct statfs fs;

		if (fstatfs(prog->core_fd, &fs) == -1) {
			err = drgn_error_create_os("fstatfs", errno,
						   prog->core_path);
			if (err)
				goto out_notes;
		}
		is_proc_kcore = fs.f_type == 0x9fa0; /* PROC_SUPER_MAGIC */
	} else {
		is_proc_kcore = false;
	}

	if (have_vmcoreinfo && !is_proc_kcore) {
		char *env;

		/* Use libkdumpfile for ELF vmcores if it was requested. */
		env = getenv("DRGN_USE_LIBKDUMPFILE_FOR_ELF");
		if (env && atoi(env)) {
			err = drgn_program_set_kdump(prog);
			if (err)
				goto out_notes;
			return NULL;
		}
	}

	prog->file_segments = malloc_array(num_file_segments,
					   sizeof(*prog->file_segments));
	if (!prog->file_segments) {
		err = &drgn_enomem;
		goto out_notes;
	}

	bool pgtable_reader =
		(is_proc_kcore || have_vmcoreinfo) &&
		prog->platform.arch->linux_kernel_pgtable_iterator_next;
	if (pgtable_reader) {
		/*
		 * Try to read any memory that isn't in the core dump via the
		 * page table.
		 */
		err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
						      read_memory_via_pgtable,
						      prog, false);
		if (err)
			goto out_segments;
	}

	/* Second pass: add the segments. */
	for (i = 0, j = 0; i < phnum && j < num_file_segments; i++) {
		GElf_Phdr phdr_mem, *phdr;

		phdr = gelf_getphdr(prog->core, i, &phdr_mem);
		if (!phdr) {
			err = drgn_error_libelf();
			goto out_segments;
		}

		if (phdr->p_type != PT_LOAD)
			continue;

		prog->file_segments[j].file_offset = phdr->p_offset;
		prog->file_segments[j].file_size = phdr->p_filesz;
		prog->file_segments[j].fd = prog->core_fd;
		prog->file_segments[j].eio_is_fault = false;
		/*
		 * p_filesz < p_memsz is ambiguous for core dumps. The ELF
		 * specification says that "if the segment's memory size p_memsz
		 * is larger than the file size p_filesz, the 'extra' bytes are
		 * defined to hold the value 0 and to follow the segment's
		 * initialized area."
		 *
		 * However, the Linux kernel generates userspace core dumps with
		 * segments with p_filesz < p_memsz to indicate that the range
		 * between p_filesz and p_memsz was filtered out (see
		 * coredump_filter in core(5)). These bytes were not necessarily
		 * zeroes in the process's memory, which contradicts the ELF
		 * specification in a way.
		 *
		 * As of Linux 5.19, /proc/kcore and /proc/vmcore never have
		 * segments with p_filesz < p_memsz. However, makedumpfile
		 * creates segments with p_filesz < p_memsz to indicate ranges
		 * that were excluded. This is similar to Linux userspace core
		 * dumps, except that makedumpfile can also exclude ranges that
		 * were all zeroes.
		 *
		 * So, for userspace core dumps, we want to fault for ranges
		 * between p_filesz and p_memsz to indicate that the memory was
		 * not saved rather than lying and returning zeroes. For
		 * /proc/kcore, we don't expect to see p_filesz < p_memsz but we
		 * fault to be safe. For Linux kernel core dumps, we can't
		 * distinguish between memory that was excluded because it was
		 * all zeroes and memory that was excluded by makedumpfile for
		 * another reason, so we're forced to always return zeroes.
		 */
		prog->file_segments[j].zerofill = have_vmcoreinfo && !is_proc_kcore;
		err = drgn_program_add_memory_segment(prog, phdr->p_vaddr,
						      phdr->p_memsz,
						      drgn_read_memory_file,
						      &prog->file_segments[j],
						      false);
		if (err)
			goto out_segments;
		if (have_phys_addrs &&
		    phdr->p_paddr != (is_64_bit ? UINT64_MAX : UINT32_MAX)) {
			err = drgn_program_add_memory_segment(prog,
							      phdr->p_paddr,
							      phdr->p_memsz,
							      drgn_read_memory_file,
							      &prog->file_segments[j],
							      true);
			if (err)
				goto out_segments;
		}
		j++;
	}
	/*
	 * Before Linux kernel commit 464920104bf7 ("/proc/kcore: update
	 * physical address for kcore ram and text") (in v4.11), p_paddr in
	 * /proc/kcore is always zero. If we know the address of the direct
	 * mapping, we can still add physical segments. This needs to be a third
	 * pass, as we may need to read virtual memory to determine the mapping.
	 */
	if (is_proc_kcore && !have_phys_addrs &&
	    prog->platform.arch->linux_kernel_live_direct_mapping_fallback) {
		uint64_t direct_mapping, direct_mapping_size;
		err = prog->platform.arch->linux_kernel_live_direct_mapping_fallback(prog,
										     &direct_mapping,
										     &direct_mapping_size);
		if (err)
			goto out_segments;

		for (i = 0, j = 0; i < phnum && j < num_file_segments; i++) {
			GElf_Phdr phdr_mem, *phdr;

			phdr = gelf_getphdr(prog->core, i, &phdr_mem);
			if (!phdr) {
				err = drgn_error_libelf();
				goto out_segments;
			}

			if (phdr->p_type != PT_LOAD)
				continue;

			if (phdr->p_vaddr >= direct_mapping &&
			    phdr->p_vaddr - direct_mapping + phdr->p_memsz <=
			    direct_mapping_size) {
				uint64_t phys_addr;

				phys_addr = phdr->p_vaddr - direct_mapping;
				err = drgn_program_add_memory_segment(prog,
								      phys_addr,
								      pgtable_reader ?
								      phdr->p_filesz :
								      phdr->p_memsz,
								      drgn_read_memory_file,
								      &prog->file_segments[j],
								      true);
				if (err)
					goto out_segments;
			}
			j++;
		}
	}
	if (vmcoreinfo_note && !prog->vmcoreinfo.raw) {
		err = drgn_program_parse_vmcoreinfo(prog, vmcoreinfo_note,
						    vmcoreinfo_size);
		if (err)
			goto out_segments;
	}

	if (is_proc_kcore) {
		if (!have_vmcoreinfo) {
			err = read_vmcoreinfo_fallback(prog);
			if (err)
				goto out_segments;
		}
		prog->flags |= (DRGN_PROGRAM_IS_LINUX_KERNEL |
				DRGN_PROGRAM_IS_LIVE |
		                DRGN_PROGRAM_IS_LOCAL);
		elf_end(prog->core);
		prog->core = NULL;
	} else if (have_vmcoreinfo) {
		prog->flags |= DRGN_PROGRAM_IS_LINUX_KERNEL;
	} else if (have_qemu_note) {
		err = drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					"unrecognized QEMU memory dump; "
					"for Linux guests, run QEMU with '-device vmcoreinfo', "
					"compile the kernel with CONFIG_FW_CFG_SYSFS and CONFIG_KEXEC, "
					"and load the qemu_fw_cfg kernel module "
					"before dumping the guest memory "
					"(requires Linux >= 4.17 and QEMU >= 2.11)");
		goto out_segments;
	}
	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL) {
		err = drgn_program_finish_set_kernel(prog);
		if (err)
			goto out_segments;
	} else {
		err = drgn_program_register_thread_finder(prog, "elf_core",
			&userspace_core_thread_finder_ops,
			sizeof(userspace_core_thread_finder_ops), NULL,
			drgn_handler_list_has_enabled(&prog->thread_finders)
			? DRGN_HANDLER_REGISTER_DONT_ENABLE : 0);
		if (err)
			goto out_segments;
		err = drgn_program_register_register_state_finder(prog, "elf_core",
			&userspace_core_register_state_finder_ops,
			sizeof(userspace_core_register_state_finder_ops),
			NULL, 0);
		if (err) {
			drgn_program_unregister_thread_finder(prog, "elf_core");
			goto out_segments;
		}
	}

	drgn_call_plugins_prog("drgn_prog_set", prog);
	return NULL;

out_segments:
	drgn_memory_reader_clear(&prog->reader);
	free(prog->file_segments);
	prog->file_segments = NULL;
out_notes:
	// Reset anything we parsed from ELF notes.
	prog->aarch64_insn_pac_mask = 0;
	// Free vmcoreinfo buffer if it was not provided by the caller
	if (!had_vmcoreinfo) {
		free(prog->vmcoreinfo.raw);
		memset(&prog->vmcoreinfo, 0, sizeof(prog->vmcoreinfo));
	}
out_platform:
	prog->has_platform = had_platform;
out_elf:
	elf_end(prog->core);
	prog->core = NULL;
out_path:
	free(prog->core_path);
	prog->core_path = NULL;
out_fd:
	close(prog->core_fd);
	prog->core_fd = -1;
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_core_dump_fd(struct drgn_program *prog, int fd)
{
	struct drgn_error *err;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	return drgn_program_set_core_dump_fd_internal(prog, fd, NULL);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_core_dump(struct drgn_program *prog, const char *path)
{
	struct drgn_error *err;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

	int fd = open(path, O_RDONLY);
	if (fd == -1)
		return drgn_error_create_os("open", errno, path);

	return drgn_program_set_core_dump_fd_internal(prog, fd, path);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_kernel(struct drgn_program *prog)
{
	return drgn_program_set_core_dump(prog, "/proc/kcore");
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_linux_kernel_custom(struct drgn_program *prog,
				     const char *vmcoreinfo,
				     size_t vmcoreinfo_size, bool is_live)
{
	struct drgn_error *err;

	if (!prog->has_platform) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
			"platform must be set before calling set_linux_kernel_custom()");
	}

	if (prog->flags & DRGN_PROGRAM_IS_LINUX_KERNEL)
		return NULL;

	// Parse vmcoreinfo if not already set via Program constructor
	bool had_vmcoreinfo = prog->vmcoreinfo.raw != NULL;
	if (!had_vmcoreinfo) {
		err = drgn_program_parse_vmcoreinfo(prog, vmcoreinfo,
						    vmcoreinfo_size);
		if (err)
			return err;
	}

	/*
	 * Register a virtual memory reader that uses page table walking.
	 * This translates virtual addresses to physical using swapper_pg_dir
	 * from vmcoreinfo, then reads physical memory from user-registered
	 * segments.
	 */
	if (prog->platform.arch->linux_kernel_pgtable_iterator_next) {
		err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
						      read_memory_via_pgtable,
						      prog, false);
		if (err)
			goto out_vmcoreinfo;
	}

	enum drgn_program_flags old_flags = prog->flags;
	prog->flags |= DRGN_PROGRAM_IS_LINUX_KERNEL;
	if (is_live)
		prog->flags |= DRGN_PROGRAM_IS_LIVE;

	err = drgn_program_finish_set_kernel(prog);
	if (err) {
		prog->flags = old_flags;
		drgn_memory_reader_clear_virtual(&prog->reader);
		goto out_vmcoreinfo;
	}

	drgn_call_plugins_prog("drgn_prog_set", prog);
	return NULL;

out_vmcoreinfo:
	// Free vmcoreinfo buffer if it was not provided by the caller
	if (!had_vmcoreinfo) {
		free(prog->vmcoreinfo.raw);
		memset(&prog->vmcoreinfo, 0, sizeof(prog->vmcoreinfo));
	}
	return err;
}

static struct drgn_error *
userspace_process_thread_iterator_create(void *arg,
					struct drgn_thread_cache *cache,
					void **ret)
{
	struct drgn_program *prog = drgn_thread_cache_program(cache);
#define FORMAT "/proc/%ld/task"
	char path[sizeof(FORMAT)
		- sizeof("%ld")
		+ max_decimal_length(long)
		+ 1];
	snprintf(path, sizeof(path), FORMAT, (long)prog->pid);
#undef FORMAT
	DIR *dir = opendir(path);
	if (!dir)
		return drgn_error_create_os("opendir", errno, path);
	*ret = dir;
	return NULL;
}

static void userspace_process_thread_iterator_destroy(void *it)
{
	closedir(it);
}

static struct drgn_error *
userspace_process_thread_iterator_next(void *arg,
				       struct drgn_thread_cache *cache,
				       void *it,
				       struct drgn_thread **ret)
{
	DIR *dir = it;
	unsigned long tid;
	char *end;
	do {
		errno = 0;
		struct dirent *task = readdir(dir);
		if (!task) {
			if (errno) {
				return drgn_error_create_os("readdir", errno,
							    NULL);
			}
			*ret = NULL;
			return NULL;
		}

		errno = 0;
		tid = strtoul(task->d_name, &end, 10);
		// Skip anything that isn't a number (like "." and "..") or
		// overflows (which is impossible normally).
	} while (*end != '\0'
		 || tid > UINT32_MAX
		 || (tid == ULONG_MAX && errno == ERANGE));

	return drgn_thread_cache_find_or_create(cache, tid, 0, NULL, ret, NULL);
}

static struct drgn_error *
userspace_process_find_thread(void *arg, struct drgn_thread_cache *cache,
			      uint32_t tid, struct drgn_thread **ret)
{
	struct drgn_program *prog = drgn_thread_cache_program(cache);
#define FORMAT "/proc/%ld/task/%" PRIu32
	char path[sizeof(FORMAT)
		  - sizeof("%ld%" PRIu32)
		  + max_decimal_length(long)
		  + max_decimal_length(uint32_t)
		  + 1];
	snprintf(path, sizeof(path), FORMAT, (long)prog->pid, tid);
#undef FORMAT
	int r = access(path, F_OK);
	if (r == 0) {
		return drgn_thread_cache_find_or_create(cache, tid, 0, NULL,
							ret, NULL);
	} else if (errno == ENOENT) {
		*ret = NULL;
		return NULL;
	} else {
		return drgn_error_create_os("access", errno, path);
	}
}

static struct drgn_error *
userspace_process_main_thread(void *arg, struct drgn_thread_cache *cache,
			      struct drgn_thread **ret)
{
	struct drgn_program *prog = drgn_thread_cache_program(cache);
	return userspace_process_find_thread(arg, cache, prog->pid, ret);
}

static struct drgn_error *
userspace_process_thread_name(void *arg, struct drgn_thread *thread, char **ret)
{
#define FORMAT "/proc/%" PRIu32 "/comm"
	char path[sizeof(FORMAT)
		  - sizeof("%" PRIu32)
		  + max_decimal_length(uint32_t)
		  + 1];
	snprintf(path, sizeof(path), FORMAT, drgn_thread_tid(thread));
#undef FORMAT

	_cleanup_close_ int fd = open(path, O_RDONLY);
	if (fd < 0)
		return drgn_error_create_os("open", errno, path);
	// While userspace threads use 16 byte buffer, kernel threads use a 64 byte buffer
	// https://github.com/torvalds/linux/blob/075dbe9f6e3c21596c5245826a4ee1f1c1676eb8/fs/proc/array.c#L101
	char buf[64];
	ssize_t bytes_read = read_all(fd, buf, sizeof(buf));
	if (bytes_read < 0)
		return drgn_error_create_os("read", errno, path);

	if (bytes_read > 0 && buf[bytes_read - 1] == '\n')
		bytes_read--;
	char *tmp = strndup(buf, bytes_read);
	if (!tmp)
		return &drgn_enomem;
	*ret = tmp;
	return NULL;
}

static const struct drgn_thread_finder_ops userspace_process_thread_finder_ops = {
	.iterator_create = userspace_process_thread_iterator_create,
	.iterator_destroy = userspace_process_thread_iterator_destroy,
	.iterator_next = userspace_process_thread_iterator_next,
	.find_thread = userspace_process_find_thread,
	.main_thread = userspace_process_main_thread,
	.thread_name = userspace_process_thread_name,
};

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_pid(struct drgn_program *prog, pid_t pid)
{
	struct drgn_error *err;

	err = drgn_program_check_initialized(prog);
	if (err)
		return err;

#define FORMAT "/proc/%ld/mem"
	char buf[sizeof(FORMAT) - sizeof("%ld") + max_decimal_length(long) + 1];
	snprintf(buf, sizeof(buf), FORMAT, (long)pid);
#undef FORMAT
	prog->core_fd = open(buf, O_RDONLY);
	if (prog->core_fd == -1)
		return drgn_error_create_os("open", errno, buf);

	bool had_platform = prog->has_platform;
	drgn_program_set_platform(prog, &drgn_host_platform);

	prog->file_segments = malloc(sizeof(*prog->file_segments));
	if (!prog->file_segments) {
		err = &drgn_enomem;
		goto out_fd;
	}
	prog->file_segments[0].file_offset = 0;
	prog->file_segments[0].file_size = UINT64_MAX;
	prog->file_segments[0].fd = prog->core_fd;
	prog->file_segments[0].eio_is_fault = true;
	prog->file_segments[0].zerofill = false;
	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_read_memory_file,
					      prog->file_segments, false);
	if (err)
		goto out_segments;

	err = drgn_program_register_thread_finder(prog, "proc",
			&userspace_process_thread_finder_ops,
			sizeof(userspace_process_thread_finder_ops), NULL,
			drgn_handler_list_has_enabled(&prog->thread_finders)
			? DRGN_HANDLER_REGISTER_DONT_ENABLE : 0);
	if (err)
		goto out_segments;

	prog->pid = pid;
	prog->flags |= DRGN_PROGRAM_IS_LIVE | DRGN_PROGRAM_IS_LOCAL;

	drgn_call_plugins_prog("drgn_prog_set", prog);
	return NULL;

out_segments:
	drgn_memory_reader_clear(&prog->reader);
	free(prog->file_segments);
	prog->file_segments = NULL;
out_fd:
	prog->has_platform = had_platform;
	close(prog->core_fd);
	prog->core_fd = -1;
	return err;
}

#ifndef WITH_JSON_C
LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_qemu_qmp_fd(struct drgn_program *prog, int fd)
{
	close(fd);
	return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
				 "drgn was not built with json-c");
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_qemu_qmp(struct drgn_program *prog, const char *address)
{
	return drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
				 "drgn was not built with json-c");
}
#endif

struct drgn_error *drgn_program_cache_auxv(struct drgn_program *prog)
{
	if (prog->auxv_cached)
		return NULL;

	_cleanup_close_ int fd = -1;
	const void *note;
	size_t note_size;
#define FORMAT "/proc/%ld/auxv"
	char path[sizeof(FORMAT)
		  - sizeof("%ld")
		  + max_decimal_length(long)
		  + 1];
	if (drgn_program_is_userspace_process(prog)) {
		snprintf(path, sizeof(path), FORMAT, (long)prog->pid);
#undef FORMAT
		fd = open(path, O_RDONLY);
		if (fd < 0)
			return drgn_error_create_os("open", errno, path);
		drgn_log_debug(prog, "parsing %s", path);
	} else {
		assert(drgn_program_is_userspace_core(prog));
		if (find_elf_note(prog->core, "CORE", NT_AUXV, &note,
				  &note_size))
			return drgn_error_libelf();
		if (!note) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "core file is missing NT_AUXV");
		}
		drgn_log_debug(prog, "parsing NT_AUXV");
	}

	memset(&prog->auxv, 0, sizeof(prog->auxv));

	bool is_64_bit = drgn_platform_is_64_bit(&prog->platform);
	bool bswap = drgn_platform_bswap(&prog->platform);
	size_t aux_size = is_64_bit ? 16 : 8;
#define visit_aux_members(visit_scalar_member, visit_raw_member) do {	\
	visit_scalar_member(a_type);					\
	visit_scalar_member(a_un.a_val);				\
} while (0)
	for (;;) {
		Elf64_auxv_t auxv;
		if (fd >= 0) {
			ssize_t r = read_all(fd, &auxv, aux_size);
			if (r < 0)
				return drgn_error_create_os("read", errno, path);
			if (r < aux_size)
				break;
			deserialize_struct64_inplace(&auxv, Elf32_auxv_t,
						     visit_aux_members,
						     is_64_bit, bswap);
		} else {
			if (note_size < aux_size)
				break;
			deserialize_struct64(&auxv, Elf32_auxv_t,
					     visit_aux_members, note, is_64_bit,
					     bswap);
			note = (char *)note + aux_size;
			note_size -= aux_size;
		}
		if (auxv.a_type == 0 && auxv.a_un.a_val == 0)
			break;
		switch (auxv.a_type) {
		case AT_PHDR:
			drgn_log_debug(prog, "found AT_PHDR 0x%" PRIx64,
				       auxv.a_un.a_val);
			prog->auxv.at_phdr = auxv.a_un.a_val;
			break;
		case AT_PHNUM:
			drgn_log_debug(prog, "found AT_PHNUM %" PRIu64,
				       auxv.a_un.a_val);
			prog->auxv.at_phnum = auxv.a_un.a_val;
			break;
		case AT_SYSINFO_EHDR:
			drgn_log_debug(prog, "found AT_SYSINFO_EHDR 0x%" PRIx64,
				       auxv.a_un.a_val);
			prog->auxv.at_sysinfo_ehdr = auxv.a_un.a_val;
			break;
		}
	}
#undef visit_aux_members
	prog->auxv_cached = true;
	return NULL;
}

struct drgn_error *drgn_program_find_prstatus(struct drgn_program *prog,
					      uint32_t tid,
					      const struct drgn_prstatus **ret)
{
	struct drgn_error *err = drgn_program_cache_core_dump_threads(prog);
	if (err)
		return err;
	struct drgn_prstatus_table_iterator it =
		drgn_prstatus_table_search(&prog->prstatus_table, &tid);
	if (!it.entry) {
		*ret = NULL;
		return NULL;
	}
	*ret = *it.entry;
	return NULL;
}

struct drgn_error *drgn_program_init_core_dump(struct drgn_program *prog,
					       const char *path)
{
	struct drgn_error *err;

	err = drgn_program_set_core_dump(prog, path);
	if (err)
		return err;
	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);
	if (err && err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
		drgn_error_destroy(err);
		err = NULL;
	}
	return err;
}

struct drgn_error *drgn_program_init_core_dump_fd(struct drgn_program *prog, int fd)
{
	struct drgn_error *err;

	err = drgn_program_set_core_dump_fd(prog, fd);
	if (err)
		return err;
	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);
	if (err && err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
		drgn_error_destroy(err);
		err = NULL;
	}
	return err;
}

struct drgn_error *drgn_program_init_kernel(struct drgn_program *prog)
{
	struct drgn_error *err;

	err = drgn_program_set_kernel(prog);
	if (err)
		return err;
	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);
	if (err && err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
		drgn_error_destroy(err);
		err = NULL;
	}
	return err;
}

struct drgn_error *drgn_program_init_pid(struct drgn_program *prog, pid_t pid)
{
	struct drgn_error *err;

	err = drgn_program_set_pid(prog, pid);
	if (err)
		return err;
	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);
	if (err && err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
		drgn_error_destroy(err);
		err = NULL;
	}
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_from_core_dump(const char *path, struct drgn_program **ret)
{
	struct drgn_program *prog;
	struct drgn_error *err = drgn_program_create(NULL, &prog);
	if (err)
		return err;

	err = drgn_program_init_core_dump(prog, path);
	if (err) {
		drgn_program_destroy(prog);
		return err;
	}

	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_from_core_dump_fd(int fd, struct drgn_program **ret)
{
	struct drgn_program *prog;
	struct drgn_error *err = drgn_program_create(NULL, &prog);
	if (err)
		return err;

	err = drgn_program_init_core_dump_fd(prog, fd);
	if (err) {
		drgn_program_destroy(prog);
		return err;
	}

	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_from_kernel(struct drgn_program **ret)
{
	struct drgn_program *prog;
	struct drgn_error *err = drgn_program_create(NULL, &prog);
	if (err)
		return err;

	err = drgn_program_init_kernel(prog);
	if (err) {
		drgn_program_destroy(prog);
		return err;
	}

	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_from_pid(pid_t pid, struct drgn_program **ret)
{
	struct drgn_program *prog;
	struct drgn_error *err = drgn_program_create(NULL, &prog);
	if (err)
		return err;

	err = drgn_program_init_pid(prog, pid);
	if (err) {
		drgn_program_destroy(prog);
		return err;
	}

	*ret = prog;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_memory(struct drgn_program *prog, void *buf, uint64_t address,
			 size_t count, bool physical)
{
	uint64_t address_mask;
	struct drgn_error *err = drgn_program_address_mask(prog, &address_mask);
	if (err)
		return err;
	err = drgn_program_untagged_addr(prog, &address);
	if (err)
		return err;
	char *p = buf;
	while (count > 0) {
		size_t n = min((uint64_t)(count - 1), address_mask - address) + 1;
		err = drgn_memory_reader_read(&prog->reader, p, address, n,
					      physical);
		if (err)
			return err;
		p += n;
		address = 0;
		count -= n;
	}
	return NULL;
}

DEFINE_VECTOR(char_vector, char);

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_c_string(struct drgn_program *prog, uint64_t address,
			   bool physical, size_t max_size, char **ret)
{
	VECTOR(char_vector, str);
	for (;;) {
		struct drgn_error *err = drgn_program_untagged_addr(prog, &address);
		if (err)
			return err;
		char *c = char_vector_append_entry(&str);
		if (!c)
			return &drgn_enomem;
		if (char_vector_size(&str) <= max_size) {
			err = drgn_memory_reader_read(&prog->reader, c, address,
						      1, physical);
			if (err)
				return err;
			if (!*c)
				break;
		} else {
			*c = '\0';
			break;
		}
		address++;
	}
	char_vector_shrink_to_fit(&str);
	char_vector_steal(&str, ret, NULL);
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_u8(struct drgn_program *prog, uint64_t address, bool physical,
		     uint8_t *ret)
{
	return drgn_program_read_memory(prog, ret, address, sizeof(*ret),
					physical);
}

#define DEFINE_PROGRAM_READ_U(n)						\
LIBDRGN_PUBLIC struct drgn_error *						\
drgn_program_read_u##n(struct drgn_program *prog, uint64_t address,		\
		       bool physical, uint##n##_t *ret)				\
{										\
	bool bswap;								\
	struct drgn_error *err = drgn_program_bswap(prog, &bswap);		\
	if (err)								\
		return err;							\
	uint##n##_t tmp;							\
	err = drgn_program_read_memory(prog, &tmp, address, sizeof(tmp),	\
				       physical);				\
	if (err)								\
		return err;							\
	if (bswap)								\
		tmp = bswap_##n(tmp);						\
	*ret = tmp;								\
	return NULL;								\
}

DEFINE_PROGRAM_READ_U(16)
DEFINE_PROGRAM_READ_U(32)
DEFINE_PROGRAM_READ_U(64)
#undef DEFINE_PROGRAM_READ_U

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_read_word(struct drgn_program *prog, uint64_t address,
		       bool physical, uint64_t *ret)
{
	bool is_64_bit, bswap;
	struct drgn_error *err = drgn_program_is_64_bit(prog, &is_64_bit);
	if (err)
		return err;
	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;
	if (is_64_bit) {
		uint64_t tmp;
		err = drgn_program_read_memory(prog, &tmp, address, sizeof(tmp),
					       physical);
		if (err)
			return err;
		if (bswap)
			tmp = bswap_64(tmp);
		*ret = tmp;
	} else {
		uint32_t tmp;
		err = drgn_program_read_memory(prog, &tmp, address, sizeof(tmp),
					       physical);
		if (err)
			return err;
		if (bswap)
			tmp = bswap_32(tmp);
		*ret = tmp;
	}
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_object(struct drgn_program *prog, const char *name,
			 const char *filename,
			 enum drgn_find_object_flags flags,
			 struct drgn_object *ret)
{
	struct drgn_error *err;

	if ((flags & ~DRGN_FIND_OBJECT_ANY) || !flags) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "invalid find object flags");
	}
	if (ret && drgn_object_program(ret) != prog) {
		return drgn_error_create(DRGN_ERROR_INVALID_ARGUMENT,
					 "object is from wrong program");
	}

	size_t name_len = strlen(name);
	drgn_handler_list_for_each_enabled(struct drgn_object_finder, finder,
					   &prog->object_finders) {
		err = finder->ops.find(name, name_len, filename, flags,
				       finder->arg, ret);
		if (err != &drgn_not_found)
			return err;
	}

	const char *kind_str;
	switch (flags) {
	case DRGN_FIND_OBJECT_CONSTANT:
		kind_str = "constant ";
		break;
	case DRGN_FIND_OBJECT_FUNCTION:
		kind_str = "function ";
		break;
	case DRGN_FIND_OBJECT_VARIABLE:
		kind_str = "variable ";
		break;
	default:
		kind_str = "";
		break;
	}
	if (filename) {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s' in '%s'",
					 kind_str, name, filename);
	} else {
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find %s'%s'", kind_str,
					 name);
	}
}

struct drgn_error *drgn_error_symbol_not_found(uint64_t address)
{
	return drgn_error_format(DRGN_ERROR_LOOKUP,
				 "could not find symbol containing 0x%" PRIx64,
				 address);
}

static struct drgn_error *
drgn_program_symbols_search(struct drgn_program *prog, const char *name,
			    uint64_t addr, enum drgn_find_symbol_flags flags,
			    struct drgn_symbol_result_builder *builder)
{
	struct drgn_error *err = NULL;
	drgn_handler_list_for_each_enabled(struct drgn_symbol_finder, finder,
					   &prog->symbol_finders) {
		err = finder->ops.find(name, addr, flags, finder->arg, builder);
		if (err ||
		    ((flags & DRGN_FIND_SYMBOL_ONE)
		     && drgn_symbol_result_builder_count(builder) > 0))
			break;
	}
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbols_by_name(struct drgn_program *prog, const char *name,
				  struct drgn_symbol ***syms_ret,
				  size_t *count_ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = name ? DRGN_FIND_SYMBOL_NAME : 0;

	drgn_symbol_result_builder_init(&builder, false);
	struct drgn_error *err = drgn_program_symbols_search(prog, name, 0,
							     flags, &builder);
	if (err)
		drgn_symbol_result_builder_abort(&builder);
	else
		drgn_symbol_result_builder_array(&builder, syms_ret, count_ret);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbols_by_address(struct drgn_program *prog,
				     uint64_t address,
				     struct drgn_symbol ***syms_ret,
				     size_t *count_ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = DRGN_FIND_SYMBOL_ADDR;

	drgn_symbol_result_builder_init(&builder, false);
	struct drgn_error *err = drgn_program_symbols_search(prog, NULL, address,
							     flags, &builder);
	if (err)
		drgn_symbol_result_builder_abort(&builder);
	else
		drgn_symbol_result_builder_array(&builder, syms_ret, count_ret);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbol_by_name(struct drgn_program *prog,
				 const char *name, struct drgn_symbol **ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = DRGN_FIND_SYMBOL_NAME | DRGN_FIND_SYMBOL_ONE;

	drgn_symbol_result_builder_init(&builder, true);
	struct drgn_error *err = drgn_program_symbols_search(prog, name, 0,
							     flags, &builder);
	if (err) {
		drgn_symbol_result_builder_abort(&builder);
		return err;
	}

	if (!drgn_symbol_result_builder_count(&builder))
		return drgn_error_format(DRGN_ERROR_LOOKUP,
					 "could not find symbol with name '%s'", name);

	*ret = drgn_symbol_result_builder_single(&builder);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_find_symbol_by_address(struct drgn_program *prog, uint64_t address,
				    struct drgn_symbol **ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = DRGN_FIND_SYMBOL_ADDR | DRGN_FIND_SYMBOL_ONE;

	drgn_symbol_result_builder_init(&builder, true);
	struct drgn_error *err = drgn_program_symbols_search(prog, NULL, address,
							     flags, &builder);

	if (err) {
		drgn_symbol_result_builder_abort(&builder);
		return err;
	}

	if (!drgn_symbol_result_builder_count(&builder))
		return drgn_error_symbol_not_found(address);

	*ret = drgn_symbol_result_builder_single(&builder);
	return err;
}

struct drgn_error *
drgn_program_find_symbol_by_address_internal(struct drgn_program *prog,
					     uint64_t address,
					     struct drgn_symbol **ret)
{
	struct drgn_symbol_result_builder builder;
	enum drgn_find_symbol_flags flags = DRGN_FIND_SYMBOL_ADDR | DRGN_FIND_SYMBOL_ONE;

	drgn_symbol_result_builder_init(&builder, true);
	struct drgn_error *err = drgn_program_symbols_search(prog, NULL, address,
							     flags, &builder);
	if (err)
		drgn_symbol_result_builder_abort(&builder);
	else
		*ret = drgn_symbol_result_builder_single(&builder);
	return err;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_element_info(struct drgn_program *prog, struct drgn_type *type,
			  struct drgn_element_info *ret)
{
	struct drgn_type *underlying_type;
	bool is_pointer, is_array;

	underlying_type = drgn_underlying_type(type);
	is_pointer = drgn_type_kind(underlying_type) == DRGN_TYPE_POINTER;
	is_array = drgn_type_kind(underlying_type) == DRGN_TYPE_ARRAY;
	if (!is_pointer && !is_array)
		return drgn_type_error("'%s' is not an array or pointer", type);

	ret->qualified_type = drgn_type_type(underlying_type);
	return drgn_type_bit_size(ret->qualified_type.type, &ret->bit_size);
}
