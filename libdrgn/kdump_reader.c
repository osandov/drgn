// Copyright 2019 - Serapheim Dimitropoulos
// SPDX-License-Identifier: GPL-3.0+

#ifdef LIBKDUMPFILE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kdump_reader.h"
#include "program.h"

struct drgn_error *has_kdump_signature(int fd, bool *is_kdump)
{
	char signature[SIG_LEN];

	uint64_t file_offset = 0;
	uint64_t file_count = sizeof (signature);
	while (file_count) {
		ssize_t ret = read(fd, signature + file_offset,
		                   file_count);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			*is_kdump = false;
			return drgn_error_create_os("read", errno, NULL);
		} else if (ret == 0) {
			*is_kdump = false;
			return drgn_error_format(DRGN_ERROR_FAULT,
						 "short read from dump file");
		}

		file_offset += ret;
		file_count -= ret;
	}

	*is_kdump = !(memcmp(signature, KDUMP_SIGNATURE, sizeof (signature)));

	return NULL;
}

struct drgn_error *drgn_kdump_init(kdump_ctx_t **ctx, int fd)
{
	kdump_ctx_t *context = kdump_new();
	if (!ctx) {
		return drgn_error_create(DRGN_ERROR_OTHER,
		                         "kdump_new() failed\n");
	}

	kdump_status ks = kdump_set_number_attr(context,
	                                        KDUMP_ATTR_FILE_FD, fd);
	if (ks != KDUMP_OK) {
		kdump_free(context);
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "setting kdump fd attribute: %s\n",
					 kdump_get_err(context));
	}

	kdump_attr_t attr;
	attr.type = KDUMP_STRING;
	attr.val.string = "linux";
	ks = kdump_set_attr(context, KDUMP_ATTR_OSTYPE, &attr);
	if (ks != KDUMP_OK) {
		kdump_free(context);
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "setting kdump xlat attribute: %s\n",
					 kdump_get_err(context));
	}
	*ctx = context;
}

void drgn_kdump_close(kdump_ctx_t *ctx)
{
	kdump_free(ctx);
}

struct drgn_error *drgn_kdump_get_raw_vmcoreinfo(kdump_ctx_t *ctx,
                                                 const char **ret)
{
	const char *raw = NULL;
	kdump_status ks = kdump_vmcoreinfo_raw(ctx, &raw);
	if (ks != KDUMP_OK) {
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "kdump_vmcoreinfo_raw() failed: %s\n",
					 kdump_get_err(ctx));
	}
	*ret = raw;
	return NULL;

}

static bool drgn_kdump_is_64bits(const char *kdump_arch_attr)
{
	return (!strcmp(kdump_arch_attr, KDUMP_ARCH_X86_64) ||
	        !strcmp(kdump_arch_attr, KDUMP_ARCH_AARCH64) ||
	        !strcmp(kdump_arch_attr, KDUMP_ARCH_ALPHA) ||
	        !strcmp(kdump_arch_attr, KDUMP_ARCH_IA64) ||
	        !strcmp(kdump_arch_attr, KDUMP_ARCH_PPC64) ||
	        !strcmp(kdump_arch_attr, KDUMP_ARCH_S390X));
}

struct drgn_error *drgn_kdump_get_arch(kdump_ctx_t *ctx,
                                       enum drgn_architecture_flags *arch)
{
	/*
	 * We first look in the architecture name and from there we
	 * we determine  whether the architecture is 32 or 64 bits.
	 * We could also attempt to guess the endianess that way but
	 * we once again query the kdump for the rare case of
	 * bi-endian architectures.
	 */
	*arch = 0;

	const char *key = KDUMP_ATTR_ARCH_NAME;
	kdump_attr_ref_t root;
	kdump_status ks = kdump_attr_ref(ctx, key, &root);
	if (ks != KDUMP_OK) {
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "kdump_attr_ref(%s) failed: %s\n",
					 key, kdump_get_err(ctx));
	}

	kdump_attr_t attr;
	ks = kdump_attr_ref_get(ctx, &root, &attr);
	if (ks != KDUMP_OK) {
		kdump_attr_unref(ctx, &root);
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "kdump_attr_ref_get(%s) failed: %s\n",
					 key, kdump_get_err(ctx));
	}

	switch (attr.type) {
	case KDUMP_STRING:
		if (drgn_kdump_is_64bits(attr.val.string))
			*arch |= DRGN_ARCH_IS_64_BIT;
		break;
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "%s - unexpected attr type: %d\n",
					 key, attr.type);
	}
	kdump_attr_unref(ctx, &root);

	key = KDUMP_ATTR_BYTE_ORDER;
	ks = kdump_attr_ref(ctx, key, &root);
	if (ks != KDUMP_OK) {
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "kdump_attr_ref(%s) failed: %s\n",
					 key, kdump_get_err(ctx));
	}

	ks = kdump_attr_ref_get(ctx, &root, &attr);
	if (ks != KDUMP_OK) {
		kdump_attr_unref(ctx, &root);
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "kdump_attr_ref_get(%s) failed: %s\n",
					 key, kdump_get_err(ctx));
	}

	switch (attr.type) {
	case KDUMP_NUMBER:
		if (attr.val.number == KDUMP_LITTLE_ENDIAN)
			*arch |= DRGN_ARCH_IS_LITTLE_ENDIAN;
		break;
	default:
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "%s - unexpected attr type: %d\n",
					 key, attr.type);
	}
	kdump_attr_unref(ctx, &root);

	return NULL;
}

struct drgn_error *drgn_read_kdump(void *buf, uint64_t address, size_t count,
                                   uint64_t offset, void *arg, bool physical)
{
	kdump_ctx_t *ctx = arg;
	size_t nread = count;

	/* zero-out buffer before doing anything */
	memset(buf, 0, count);

	kdump_addrspace_t as = (physical) ? KDUMP_KPHYSADDR : KDUMP_KVADDR;
	kdump_status ks = kdump_read(ctx, as, address, buf, &nread);
	if (ks != KDUMP_OK) {
		return drgn_error_format(DRGN_ERROR_OTHER,
		                         "kdump_read failed: %s",
					 kdump_get_err(ctx));
	}

	if (nread != count) {
		return drgn_error_format(DRGN_ERROR_FAULT,
		                         "short read at kdump_read: %s",
					 kdump_get_err(ctx));
	}
	return NULL;
}
#endif /* LIBKDUMPFILE */
