// Copyright 2019 - Serapheim Dimitropoulos
// SPDX-License-Identifier: GPL-3.0-or-later

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linux_kernel.h"
#include "program.h" // IWYU pragma: associated

static struct drgn_error *drgn_platform_from_kdump(kdump_ctx_t *ctx,
						   struct drgn_platform *ret)
{
	kdump_status ks;
	const char *str;
	kdump_num_t num;
	const struct drgn_architecture_info *arch;
	bool is_64_bit, is_little_endian;

	ks = kdump_get_string_attr(ctx, KDUMP_ATTR_ARCH_NAME, &str);
	if (ks != KDUMP_OK) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "kdump_get_string_attr(KDUMP_ATTR_ARCH_NAME): %s",
					 kdump_get_err(ctx));
	}
	if (strcmp(str, KDUMP_ARCH_X86_64) == 0)
		arch = &arch_info_x86_64;
	else if (strcmp(str, KDUMP_ARCH_PPC64) == 0)
		arch = &arch_info_ppc64;
	else
		arch = &arch_info_unknown;

	ks = kdump_get_number_attr(ctx, KDUMP_ATTR_PTR_SIZE, &num);
	if (ks != KDUMP_OK) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "kdump_get_number_attr(KDUMP_ATTR_PTR_SIZE): %s",
					 kdump_get_err(ctx));
	}
	is_64_bit = num == 8;

	ks = kdump_get_number_attr(ctx, KDUMP_ATTR_BYTE_ORDER, &num);
	if (ks != KDUMP_OK) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "kdump_get_number_attr(KDUMP_ATTR_BYTE_ORDER): %s",
					 kdump_get_err(ctx));
	}
	is_little_endian = num == KDUMP_LITTLE_ENDIAN;

	drgn_platform_from_arch(arch, is_64_bit, is_little_endian, ret);
	return NULL;
}

static struct drgn_error *drgn_read_kdump(void *buf, uint64_t address,
					  size_t count, uint64_t offset,
					  void *arg, bool physical)
{
	kdump_ctx_t *ctx = arg;
	kdump_status ks;

	ks = kdump_read(ctx, physical ? KDUMP_KPHYSADDR : KDUMP_KVADDR, address,
			buf, &count);
	if (ks != KDUMP_OK) {
		return drgn_error_format_fault(address,
					       "could not read memory from kdump: %s",
					       kdump_get_err(ctx));
	}
	return NULL;
}

struct drgn_error *drgn_program_set_kdump(struct drgn_program *prog)
{
	struct drgn_error *err;
	kdump_ctx_t *ctx;
	kdump_status ks;
	bool had_platform;

	ctx = kdump_new();
	if (!ctx) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "kdump_new() failed");
	}

	ks = kdump_set_number_attr(ctx, KDUMP_ATTR_FILE_FD, prog->core_fd);
	if (ks != KDUMP_OK) {
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"kdump_set_number_attr(KDUMP_ATTR_FILE_FD): %s",
					kdump_get_err(ctx));
		goto err;
	}
	ks = kdump_set_string_attr(ctx, KDUMP_ATTR_OSTYPE, "linux");
	if (ks != KDUMP_OK) {
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"kdump_set_string_attr(KDUMP_ATTR_OSTYPE): %s",
					kdump_get_err(ctx));
		goto err;
	}

#if KDUMPFILE_VERSION >= KDUMPFILE_MKVER(0, 4, 1)
	char *vmcoreinfo;
#else
	const char *vmcoreinfo;
#endif
	ks = kdump_vmcoreinfo_raw(ctx, &vmcoreinfo);
	if (ks != KDUMP_OK) {
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"kdump_vmcoreinfo_raw: %s",
					kdump_get_err(ctx));
		goto err;
	}

	err = parse_vmcoreinfo(vmcoreinfo, strlen(vmcoreinfo) + 1,
			       &prog->vmcoreinfo);
	/*
	 * As of libkdumpfile 0.4.1, the string returned by
	 * kdump_vmcoreinfo_raw() needs to be freed.
	 */
#if KDUMPFILE_VERSION >= KDUMPFILE_MKVER(0, 4, 1)
	free(vmcoreinfo);
#endif
	if (err)
		goto err;

	had_platform = prog->has_platform;
	if (!had_platform) {
		struct drgn_platform platform;
		err = drgn_platform_from_kdump(ctx, &platform);
		if (err)
			goto err;
		drgn_program_set_platform(prog, &platform);
	}

	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_read_kdump, ctx, false);
	if (err)
		goto err_platform;
	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_read_kdump, ctx, true);
	if (err) {
		drgn_memory_reader_deinit(&prog->reader);
		drgn_memory_reader_init(&prog->reader);
		goto err_platform;
	}

	prog->flags |= DRGN_PROGRAM_IS_LINUX_KERNEL;
	err = drgn_program_add_object_finder(prog, linux_kernel_object_find,
					     prog);
	if (err)
		goto err_platform;
	if (!prog->lang)
		prog->lang = &drgn_language_c;
	prog->kdump_ctx = ctx;
	return NULL;

err_platform:
	prog->has_platform = had_platform;
err:
	kdump_free(ctx);
	return err;
}

struct drgn_error *drgn_program_cache_prstatus_kdump(struct drgn_program *prog)
{
	struct drgn_error *err;
	kdump_num_t ncpus, i;
	kdump_status ks;

	ks = kdump_get_number_attr(prog->kdump_ctx, "cpu.number", &ncpus);
	if (ks != KDUMP_OK) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "kdump_get_number_attr(cpu.number): %s",
					 kdump_get_err(prog->kdump_ctx));
	}

	/*
	 * Note that in the following loop we never call kdump_attr_unref() on
	 * prstatus_ref, nor kdump_blob_unpin() on the prstatus blob that we get
	 * from libkdumpfile. Since drgn is completely read-only as a consumer
	 * of that library, we "leak" both the attribute reference and blob pin
	 * until kdump_free() is called which will clean up everything for us.
	 */
	for (i = 0; i < ncpus; i++) {
		/* Enough for the longest possible PRSTATUS attribute name. */
		char attr_name[64];
		kdump_attr_ref_t prstatus_ref;
		kdump_attr_t prstatus_attr;
		void *prstatus_data;
		size_t prstatus_size;

		snprintf(attr_name, sizeof(attr_name),
			 "cpu.%" PRIuFAST64 ".PRSTATUS", i);
		ks = kdump_attr_ref(prog->kdump_ctx, attr_name, &prstatus_ref);
		if (ks != KDUMP_OK) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "kdump_attr_ref(%s): %s",
						 attr_name,
						 kdump_get_err(prog->kdump_ctx));
		}

		ks = kdump_attr_ref_get(prog->kdump_ctx, &prstatus_ref,
					&prstatus_attr);
		if (ks != KDUMP_OK) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "kdump_attr_ref_get(%s): %s",
						 attr_name,
						 kdump_get_err(prog->kdump_ctx));
		}

		prstatus_data = kdump_blob_pin(prstatus_attr.val.blob);
		prstatus_size = kdump_blob_size(prstatus_attr.val.blob);
		err = drgn_program_cache_prstatus_entry(prog,
							prstatus_data,
							prstatus_size);
		if (err)
			return err;
	}
	return NULL;
}
