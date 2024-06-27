// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_OPENMP_H
#define DRGN_OPENMP_H

#ifdef _OPENMP
#include <omp.h> // IWYU pragma: export

extern int drgn_num_threads;
void drgn_init_num_threads(void);
#else
static inline int omp_get_thread_num(void)
{
	return 0;
}

#define drgn_num_threads 1
static inline void drgn_init_num_threads(void)
{
}
#endif

#endif /* DRGN_OPENMP_H */
