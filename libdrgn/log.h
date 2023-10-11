// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Logging.
 *
 * See @ref LoggingInternals.
 */

#ifndef DRGN_LOG_H
#define DRGN_LOG_H

#include "drgn.h"

/**
 * @ingroup Internals
 *
 * @defgroup LoggingInternals Logging
 *
 * Logging functions.
 *
 * @{
 */

/**
 * Return whether the given log level is enabled.
 *
 * This can be used to avoid expensive computations that are only needed for
 * logging.
 */
bool drgn_log_is_enabled(struct drgn_program *prog, enum drgn_log_level level);

/**
 * @{
 *
 * @name Logging Functions
 */

#ifdef DOXYGEN
/** Log a printf-style message at the given level. */
void drgn_log(enum drgn_log_level level, struct drgn_program *prog,
	      const char *format, ...);
#else
#define drgn_log(level, prog, ...) drgn_error_log(level, prog, NULL, __VA_ARGS__)
#endif
/** Log a critical message. */
#define drgn_log_critical(...) drgn_log(DRGN_LOG_CRITICAL, __VA_ARGS__)
/** Log an error message. */
#define drgn_log_error(...) drgn_log(DRGN_LOG_ERROR, __VA_ARGS__)
/** Log a warning message. */
#define drgn_log_warning(...) drgn_log(DRGN_LOG_WARNING, __VA_ARGS__)
/** Log an informational message. */
#define drgn_log_info(...) drgn_log(DRGN_LOG_INFO, __VA_ARGS__)
/** Log a debug message. */
#define drgn_log_debug(...) drgn_log(DRGN_LOG_DEBUG, __VA_ARGS__)

/**
 * @}
 *
 * @{
 *
 * @name Error Logging Functions
 */

/**
 * Log a printf-style message followed by a @ref drgn_error at the given level.
 */
__attribute__((__format__(__printf__, 4, 5), __nonnull__(2, 4)))
void drgn_error_log(enum drgn_log_level level, struct drgn_program *prog,
		    struct drgn_error *err, const char *format, ...);
/** Log a critical message followed by a @ref drgn_error. */
#define drgn_error_log_critical(...) drgn_error_log(DRGN_LOG_CRITICAL, __VA_ARGS__)
/** Log an error message followed by a @ref drgn_error. */
#define drgn_error_log_error(...) drgn_error_log(DRGN_LOG_ERROR, __VA_ARGS__)
/** Log a warning message followed by a @ref drgn_error. */
#define drgn_error_log_warning(...) drgn_error_log(DRGN_LOG_WARNING, __VA_ARGS__)
/** Log an informational message followed by a @ref drgn_error. */
#define drgn_error_log_info(...) drgn_error_log(DRGN_LOG_INFO, __VA_ARGS__)
/** Log a debug message followed by a @ref drgn_error. */
#define drgn_error_log_debug(...) drgn_error_log(DRGN_LOG_DEBUG, __VA_ARGS__)

/**
 * @}
 * @}
 */

#endif /* DRGN_LOG_H */
