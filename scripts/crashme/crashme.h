// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef CRASHME_H
#define CRASHME_H

int *crashme_ptr(void);

struct crashme {
	int *ptr;
};

int crashme(struct crashme *cm);

#endif /* CRASHME_H */
