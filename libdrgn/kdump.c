// Copyright 2019 - Serapheim Dimitropoulos
// SPDX-License-Identifier: GPL-3.0+

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linux_kernel.h"
#include "program.h"

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
	const char *vmcoreinfo;
	struct drgn_platform platform;

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

	ks = kdump_vmcoreinfo_raw(ctx, &vmcoreinfo);
	if (ks != KDUMP_OK) {
		err = drgn_error_format(DRGN_ERROR_OTHER,
					"kdump_vmcoreinfo_raw: %s",
					kdump_get_err(ctx));
		goto err;
	}

	err = parse_vmcoreinfo(vmcoreinfo, strlen(vmcoreinfo) + 1,
			       &prog->vmcoreinfo);
	if (err)
		goto err;

	err = drgn_platform_from_kdump(ctx, &platform);
	if (err)
		goto err;

	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_read_kdump, ctx, false);
	if (err)
		goto err;
	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_read_kdump, ctx, true);
	if (err) {
		drgn_memory_reader_deinit(&prog->reader);
		drgn_memory_reader_init(&prog->reader);
		goto err;
	}

	prog->flags |= DRGN_PROGRAM_IS_LINUX_KERNEL;
	err = drgn_program_add_object_finder(prog, vmcoreinfo_object_find,
					     prog);
	if (err)
		goto err;
	if (!prog->lang)
		prog->lang = &drgn_language_c;
	drgn_program_set_platform(prog, &platform);
	prog->kdump_ctx = ctx;
	return NULL;

err:
	kdump_free(ctx);
	return err;
}
