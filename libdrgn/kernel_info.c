// Copyright (c) 2022 Oracle and/or its affiliates
// SPDX-License-Identifier: GPL-3.0-or-later

#include "drgn.h"
#include "kallsyms.h"
#include "kernel_info.h"
#include "program.h"

struct drgn_error *
drgn_program_load_kernel_info(struct drgn_program *prog)
{
	struct drgn_error *err;
	struct kernel_info *kinfo = calloc(1, sizeof(*kinfo));

	if (!kinfo)
		return &drgn_enomem;

	err = drgn_kallsyms_create(prog, &prog->vmcoreinfo, &kinfo->kallsyms);
	if (err || !kinfo)
		goto out_free_kinfo;

	prog->kinfo = kinfo;
	printf("Loaded symbols from kallsyms\n");
	return NULL;

out_free_kinfo:
	free(kinfo);
	return err;
}
