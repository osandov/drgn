// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * @ref SWITCH_ENUM() definition.
 *
 * This is separate from @ref util.h so that the build system can check whether
 * it works.
 */

#ifndef SWITCH_ENUM
/**
 * Switch statement with an enum controlling expression that must have a case
 * for every enumeration value and a default case.
 *
 * There are a few known limitations:
 *
 * - Before GCC 12.1, GCC can't parse it. This was fixed by GCC commit
 *   1bf976a5de69 ("openmp: Actually ignore pragma_stmt pragmas for which
 *   c_parser_pragma returns false").
 * - Before GCC 12.2, GCC doesn't actually apply the warnings. This was fixed by
 *   GCC commit 98e2676558f6 ("c: Fix location for _Pragma tokens [PR97498]").
 * - Before Clang 18.1, Clang ignores -Wswitch-default. It was implemented in
 *   llvm-project commit c28178298513 ("[clang][Sema] Add -Wswitch-default
 *   warning option (#73077)").
 *
 * If the compiler can't compile this, then the build system defines it as
 * `switch (expr)` instead.
 */
#define SWITCH_ENUM(expr)					\
	_Pragma("GCC diagnostic push")				\
	_Pragma("GCC diagnostic error \"-Wswitch-enum\"")	\
	_Pragma("GCC diagnostic error \"-Wswitch-default\"")	\
	switch (expr)						\
	_Pragma("GCC diagnostic pop")
#endif
