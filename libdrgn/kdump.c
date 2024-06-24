// Copyright 2019 - Serapheim Dimitropoulos
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linux_kernel.h"
#include "program.h" // IWYU pragma: associated
#include "util.h"

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
	else if (strcmp(str, KDUMP_ARCH_IA32) == 0)
		arch = &arch_info_i386;
	else if (strcmp(str, KDUMP_ARCH_AARCH64) == 0)
		arch = &arch_info_aarch64;
	else if (strcmp(str, KDUMP_ARCH_ARM) == 0)
		arch = &arch_info_arm;
	else if (strcmp(str, KDUMP_ARCH_PPC64) == 0)
		arch = &arch_info_ppc64;
	else if (strcmp(str, KDUMP_ARCH_S390X) == 0)
		arch = &arch_info_s390x;
	else if (strcmp(str, KDUMP_ARCH_S390) == 0)
		arch = &arch_info_s390;
#if KDUMPFILE_VERSION >= KDUMPFILE_MKVER(0, 5, 4)
	else if (strcmp(str, KDUMP_ARCH_RISCV64) == 0)
		arch = &arch_info_riscv64;
	else if (strcmp(str, KDUMP_ARCH_RISCV32) == 0)
		arch = &arch_info_riscv32;
#endif
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

static struct drgn_error *drgn_platform_to_kdump(kdump_ctx_t *ctx,
						 const struct drgn_platform *platform)
{
	kdump_status ks;
	char *arch_str = NULL;

	if (platform->arch == &arch_info_x86_64)
		arch_str = KDUMP_ARCH_X86_64;
	else if (platform->arch == &arch_info_i386)
		arch_str = KDUMP_ARCH_IA32;
	else if (platform->arch == &arch_info_aarch64)
		arch_str = KDUMP_ARCH_AARCH64;
	else if (platform->arch == &arch_info_arm)
		arch_str = KDUMP_ARCH_ARM;
	else if (platform->arch == &arch_info_ppc64)
		arch_str = KDUMP_ARCH_PPC64;
	else if (platform->arch == &arch_info_s390x)
		arch_str = KDUMP_ARCH_S390X;
	else if (platform->arch == &arch_info_s390)
		arch_str = KDUMP_ARCH_S390;
#if KDUMPFILE_VERSION >= KDUMPFILE_MKVER(0, 5, 4)
	else if (platform->arch == &arch_info_riscv64)
		arch_str = KDUMP_ARCH_RISCV64;
	else if (platform->arch == &arch_info_riscv32)
		arch_str = KDUMP_ARCH_RISCV32;
#endif

	if (arch_str) {
		ks = kdump_set_string_attr(ctx, KDUMP_ATTR_ARCH_NAME, arch_str);
		if (ks != KDUMP_OK) {
			return drgn_error_format(DRGN_ERROR_OTHER,
						 "kdump_set_string_attr(\"%s\"): %s",
						 arch_str, kdump_get_err(ctx));
		}
	}

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
	bool had_vmcoreinfo = prog->vmcoreinfo.raw;

	ctx = kdump_new();
	if (!ctx) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "kdump_new() failed");
	}

	/*
	 * We need to be careful to set libkdumpfile attributes in the correct
	 * order, in order to achive the desired result in the rare cases when
	 * the program has the architecture and/or vmcoreinfo already set. In
	 * these cases, frequently, the information is not available to
	 * libkdumpfile, and so the user is providing it instead. We should set:
	 *
	 * - Architecture before file descriptor. This is because when
	 *   libkdumpfile reads the vmcore, it immediately parses the notes in
	 *   the header. If it doesn't know the current architecture, it will
	 *   skip the architecture-specific notes, such as the PRSTATUS. This
	 *   manifests to users as a missing "cpu.number" attribute, and thus a
	 *   failure to get accurate stack traces for on-CPU tasks.
	 * - Vmcoreinfo after architecture. This is because when libkdumpfile
	 *   gets a new vmcoreinfo note set, it marks the address translation
	 *   metadata as dirty and resets its address translation info using the
	 *   new data. If no architecture is set, it skips this setup since it
	 *   won't know how to do so. This manifests for users as FaultError
	 *   when they access almost any memory address.
	 *
	 * For the common case, where we are just setting the FD and OS type,
	 * and then letting libkdumpfile give us the vmcoreinfo and platform
	 * info, the only ordering constraint is the obvious one: we need to set
	 * the FD before getting data from libkdumpfile.
	 */

	if (prog->has_platform) {
		err = drgn_platform_to_kdump(ctx, drgn_program_platform(prog));
		if (err)
			goto err;
	}

	ks = kdump_set_number_attr(ctx, KDUMP_ATTR_FILE_FD, prog->core_fd);
	if (ks == KDUMP_ERR_NOTIMPL) {
		err = drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					"%s", kdump_get_err(ctx));
		goto err;
	}
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

	if (prog->vmcoreinfo.raw) {
#if KDUMPFILE_VERSION >= KDUMPFILE_MKVER(0, 4, 1)
		char *vmcoreinfo = memdup(prog->vmcoreinfo.raw, prog->vmcoreinfo.raw_size);
		if (!vmcoreinfo) {
			err = &drgn_enomem;
			goto err;
		}
		kdump_blob_t *blob = kdump_blob_new(vmcoreinfo, prog->vmcoreinfo.raw_size);
		if (!blob) {
			free(vmcoreinfo);
			err = &drgn_enomem;
			goto err;
		}
		kdump_attr_t attr;
		attr.type = KDUMP_BLOB;
		attr.val.blob = blob;
		ks = kdump_set_attr(ctx, "linux.vmcoreinfo.raw", &attr);
		if (ks != KDUMP_OK) {
			err = drgn_error_format(DRGN_ERROR_OTHER,
						"kdump_set_attr(linux.vmcoreinfo.raw): %s",
						kdump_get_err(ctx));
			goto err;
		}
#else
		err = drgn_error_create(DRGN_ERROR_NOT_IMPLEMENTED,
					"overriding vmcoreinfo is not supported in libkdumpfile < 0.4.1");
		goto err;
#endif
	} else {
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

		err = drgn_program_parse_vmcoreinfo(prog, vmcoreinfo,
						strlen(vmcoreinfo) + 1);
		/*
		* As of libkdumpfile 0.4.1, the string returned by
		* kdump_vmcoreinfo_raw() needs to be freed.
		*/
#if KDUMPFILE_VERSION >= KDUMPFILE_MKVER(0, 4, 1)
		free(vmcoreinfo);
#endif
		if (err)
			goto err;
	}

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
	err = drgn_program_finish_set_kernel(prog);
	if (err)
		goto err_platform;
	prog->kdump_ctx = ctx;
	return NULL;

err_platform:
	prog->has_platform = had_platform;
err:
	// Reset anything we parsed from vmcoreinfo
	if (!had_vmcoreinfo) {
		free(prog->vmcoreinfo.raw);
		memset(&prog->vmcoreinfo, 0, sizeof(prog->vmcoreinfo));
	}
	kdump_free(ctx);
	return err;
}

struct drgn_error *drgn_program_cache_kdump_notes(struct drgn_program *prog)
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
		kdump_attr_ref_t prstatus_ref;
		kdump_attr_t prstatus_attr;
		void *prstatus_data;
		size_t prstatus_size;

#define FORMAT "cpu.%" PRIuFAST64 ".PRSTATUS"
		char attr_name[sizeof(FORMAT)
			       - sizeof("%" PRIuFAST64)
			       + max_decimal_length(uint_fast64_t)
			       + 1];
		snprintf(attr_name, sizeof(attr_name), FORMAT, i);
#undef FORMAT
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
		uint32_t _;
		err = drgn_program_cache_prstatus_entry(prog, prstatus_data,
							prstatus_size, &_);
		if (err)
			return err;
	}
	return NULL;
}
