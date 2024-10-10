// Copyright (c) 2024 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later
#include "util.h"

static _Thread_local int (*qsort_arg_compar)(const void *, const void *, void*);
static _Thread_local void *qsort_arg_arg;

static int qsort_arg_compar_wrapper(const void *a, const void *b)
{
	return qsort_arg_compar(a, b, qsort_arg_arg);
}

void qsort_arg(void *base, size_t nmemb, size_t size,
               int (*compar)(const void *, const void *, void*), void *arg)
{
	qsort_arg_compar = compar;
	qsort_arg_arg = arg;
	qsort(base, nmemb, size, qsort_arg_compar_wrapper);
}
