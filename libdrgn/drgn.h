// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * libdrgn public interface.
 */

#ifndef DRGN_H
#define DRGN_H

// IWYU pragma: begin_exports
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
// IWYU pragma: end_exports

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/**
 * @mainpage
 *
 * libdrgn provides the functionality of the
 * [drgn](https://github.com/osandov/drgn) programmable debugger as a library.
 * It implements the main drgn abstractions: @ref Programs, @ref Types, @ref
 * Objects, and @ref StackTraces. See [Topics](topics.html) for detailed
 * documentation.
 *
 * @subsection ThreadSafety Thread Safety
 *
 * Only one thread at a time should access the same @ref drgn_program (including
 * @ref drgn_object, @ref drgn_type, @ref drgn_stack_trace, etc. from that
 * program). It is safe to use different @ref drgn_program%s from concurrent
 * threads.
 */

/** Major version of drgn. */
#define DRGN_VERSION_MAJOR 0
/** Minor version of drgn. */
#define DRGN_VERSION_MINOR 0
/** Patch level of drgn. */
#define DRGN_VERSION_PATCH 32

/**
 * @defgroup ErrorHandling Error handling
 *
 * Error handling in libdrgn.
 *
 * Operations in libdrgn can fail for various reasons. libdrgn returns errors as
 * @ref drgn_error.
 *
 * @{
 */

/** Error code for a @ref drgn_error. */
enum drgn_error_code {
	/** Cannot allocate memory. */
	DRGN_ERROR_NO_MEMORY,
	/** Stop iteration. */
	DRGN_ERROR_STOP,
	/** Miscellaneous error. */
	DRGN_ERROR_OTHER,
	/** Invalid argument. */
	DRGN_ERROR_INVALID_ARGUMENT,
	/** Integer overflow. */
	DRGN_ERROR_OVERFLOW,
	/** Maximum recursion depth exceeded. */
	DRGN_ERROR_RECURSION,
	/** System call error. */
	DRGN_ERROR_OS,
	/** One or more files do not have debug information. */
	DRGN_ERROR_MISSING_DEBUG_INFO,
	/** Syntax error while parsing. */
	DRGN_ERROR_SYNTAX,
	/** Entry not found. */
	DRGN_ERROR_LOOKUP,
	/** Bad memory access. */
	DRGN_ERROR_FAULT,
	/** Type error in expression. */
	DRGN_ERROR_TYPE,
	/** Division by zero. */
	DRGN_ERROR_ZERO_DIVISION,
	/** Array out of bounds */
	DRGN_ERROR_OUT_OF_BOUNDS,
	/** Operation was attempted with absent object. */
	DRGN_ERROR_OBJECT_ABSENT,
	/** Functionality is not implemented. */
	DRGN_ERROR_NOT_IMPLEMENTED,
	/** Number of defined error codes. */
	DRGN_NUM_ERROR_CODES,
} __attribute__((__packed__));

/**
 * libdrgn error.
 *
 * All functions in libdrgn that can return an error return this type.
 */
struct drgn_error {
	/** Error code. */
	enum drgn_error_code code;
	/**
	 * @private
	 *
	 * Whether this error needs to be passed to @ref drgn_error_destroy().
	 *
	 * This is @c true for the error codes returned from @ref
	 * drgn_error_create() and its related functions. Certain errors are
	 * statically allocated and do not need to be passed to @ref
	 * drgn_error_destroy() (but they can be).
	 */
	bool needs_destroy;
	/**
	 * If @c code is @c DRGN_ERROR_OS, then the error number returned from
	 * the system call.
	 */
	int errnum;
	/**
	 * If @c code is @c DRGN_ERROR_OS, then the path of the file which
	 * encountered the error if applicable. Otherwise, @c NULL.
	 */
	char *path;
	/**
	 * If @c code is @c DRGN_ERROR_FAULT, then the address of the read
	 * which encountered the error.
	 */
	uint64_t address;
	/** Human-readable error message. */
	char *message;
};

/**
 * Out of memory @ref drgn_error.
 *
 * This has a code of @ref DRGN_ERROR_NO_MEMORY. It can be returned if a memory
 * allocation fails in order to avoid doing another memory allocation. It does
 * not need to be passed to @ref drgn_error_destroy() (but it can be).
 */
extern struct drgn_error drgn_enomem;

/**
 * Non-fatal lookup @ref drgn_error.
 *
 * This has a code of @ref DRGN_ERROR_LOOKUP. It does not need to be passed to
 * @ref drgn_error_destroy() (but it can be).
 */
extern struct drgn_error drgn_not_found;

/**
 * Create a @ref drgn_error.
 *
 * @param[in] code Error code.
 * @param[in] message Human-readable error message. This string is copied.
 * @return A new error with the given code and message. If there is a failure to
 * allocate memory for the error or the message, @ref drgn_enomem is returned
 * instead.
 */
struct drgn_error *drgn_error_create(enum drgn_error_code code,
				     const char *message)
	__attribute__((__returns_nonnull__));

/**
 * Create a @ref drgn_error from a printf-style format.
 *
 * @param[in] code Error code.
 * @param[in] format printf-style format string.
 * @param[in] ... Arguments for the format string.
 * @return A new error with the given code and formatted message. If there is a
 * failure to allocate memory for the error or the message, @ref drgn_enomem is
 * returned instead.
 */
struct drgn_error *drgn_error_format(enum drgn_error_code code,
				     const char *format, ...)
	__attribute__((__returns_nonnull__, __format__(__printf__, 2, 3)));

/**
 * Create a @ref DRGN_ERROR_OS @ref drgn_error.
 *
 * @sa drgn_error_create().
 *
 * @param[in] errnum Error number (i.e., @c errno).
 * @param[in] path If not @c NULL, the path of the file which encountered the
 * error. This string is copied.
 */
struct drgn_error *drgn_error_create_os(const char *message, int errnum,
					const char *path)
	__attribute__((__returns_nonnull__));

/**
 * Create a @ref DRGN_ERROR_OS @ref drgn_error with a printf-style formatted
 * path.
 *
 * @param[in] errnum Error number (i.e., @c errno).
 * @param[in] path_format printf-style format string for path.
 * @param[in] ... Arguments for the format string.
 */
struct drgn_error *drgn_error_format_os(const char *message, int errnum,
					const char *path_format, ...)
	__attribute__((__returns_nonnull__, __format__(__printf__, 3, 4)));

/**
 * Create a @ref DRGN_ERROR_FAULT @ref drgn_error.
 *
 * @param[in] message Human-readable error message. This string is copied.
 * @param[in] address Address where the fault happened.
 */
struct drgn_error *drgn_error_create_fault(const char *message, uint64_t address)
	__attribute__((__returns_nonnull__));

/**
 *
 * Create a @ref DRGN_ERROR_FAULT @ref drgn_error with a printf-style formatted
 * message.
 *
 * @param[in] address Address where the fault happened.
 * @param[in] format printf-style format string for message.
 * @param[in] ... Arguments for the format string.
 */
struct drgn_error *drgn_error_format_fault(uint64_t address,
					   const char *format, ...)
	__attribute__((__returns_nonnull__, __format__(__printf__, 2, 3)));

/*
 * Create a copy of a @ref drgn_error.
 *
 * The source's error message and path are copied if necessary, so the source
 * error can be destroyed without affecting the new error and vice versa.
 *
 * @param[in] src Error to copy.
 * @return A new error with the same fields. If there is a failure to allocate
 * memory, @ref drgn_enomem is returned instead.
 */
struct drgn_error *drgn_error_copy(struct drgn_error *src)
	__attribute__((__returns_nonnull__));

/**
 * Return a string representation of a @ref drgn_error.
 *
 * @param[in] err Error to write.
 * @return Returned string, or @c NULL if memory could not be allocated. On
 * success, must be freed with @c free().
 */
char *drgn_error_string(struct drgn_error *err);

/**
 * Write a @ref drgn_error followed by a newline to a @c stdio stream.
 *
 * @param[in] file File to write to (usually @c stderr).
 * @param[in] err Error to write.
 * @return Non-negative on success, negative on failure.
 */
int drgn_error_fwrite(FILE *file, struct drgn_error *err);

/**
 * Write a @ref drgn_error followed by a newline to a file descriptor.
 *
 * @param[in] fd File descriptor to write to.
 * @param[in] err Error to write.
 * @return Non-negative on success, negative on failure.
 */
int drgn_error_dwrite(int fd, struct drgn_error *err);

/**
 * Free a @ref drgn_error.
 *
 * This must be called on any error returned from libdrgn unless otherwise
 * noted.
 *
 * @param[in] err Error to destroy. If @c NULL, this is a no-op.
 */
void drgn_error_destroy(struct drgn_error *err);

/** @} */


/**
 * @defgroup Languages Languages
 *
 * Programming languages.
 *
 * @{
 */

struct drgn_language; // IWYU pragma: export

/** C */
extern const struct drgn_language drgn_language_c;
/** C++ */
extern const struct drgn_language drgn_language_cpp;

/** Get the name of a @ref drgn_language. */
const char *drgn_language_name(const struct drgn_language *lang);

/** @} */

/**
 * @ingroup Types
 *
 * Kinds of types.
 *
 * Every type in a program supported by libdrgn falls into one of these
 * categories.
 */
enum drgn_type_kind {
	/** Void type. */
	DRGN_TYPE_VOID = 1,
	/** Integer type. */
	DRGN_TYPE_INT,
	/** Boolean type. */
	DRGN_TYPE_BOOL,
	/** Floating-point type. */
	DRGN_TYPE_FLOAT,
	/** Structure type. */
	DRGN_TYPE_STRUCT,
	/** Union type. */
	DRGN_TYPE_UNION,
	/** Class type. */
	DRGN_TYPE_CLASS,
	/** Enumerated type. */
	DRGN_TYPE_ENUM,
	/** Type definition (a.k.a.\ alias) type. */
	DRGN_TYPE_TYPEDEF,
	/** Pointer type. */
	DRGN_TYPE_POINTER,
	/** Array type. */
	DRGN_TYPE_ARRAY,
	/** Function type. */
	DRGN_TYPE_FUNCTION,
} __attribute__((__packed__));

/**
 * @ingroup Types
 *
 * Type qualifiers.
 *
 * Some languages, like C, have the notion of qualifiers which add properties to
 * a type. Qualifiers are represented as a bitmask; each qualifier is a bit.
 */
enum drgn_qualifiers {
	/** Constant type. */
	DRGN_QUALIFIER_CONST = (1 << 0),
	/** Volatile type. */
	DRGN_QUALIFIER_VOLATILE = (1 << 1),
	/** Restrict type. */
	DRGN_QUALIFIER_RESTRICT = (1 << 2),
	/** Atomic type. */
	DRGN_QUALIFIER_ATOMIC = (1 << 3),
	/** Bitmask of all valid qualifiers. */
	DRGN_ALL_QUALIFIERS = (1 << 4) - 1,
} __attribute__((__packed__));

/**
 * @ingroup Types
 *
 * Qualified type.
 *
 * A type with qualifiers.
 *
 * @sa drgn_qualifiers
 */
struct drgn_qualified_type {
	/** Unqualified type. */
	struct drgn_type *type;
	/** Bitmask of qualifiers on this type. */
	enum drgn_qualifiers qualifiers;
};

#ifndef DRGN_ACCESSOR_LINKAGE
#define DRGN_ACCESSOR_LINKAGE extern
#endif

/**
 * @ingroup Types
 *
 * Get the program that a @ref drgn_type is from.
 */
DRGN_ACCESSOR_LINKAGE
struct drgn_program *drgn_type_program(struct drgn_type *type);

/**
 * @ingroup Types
 *
 * Get the language of a type.
 */
DRGN_ACCESSOR_LINKAGE
const struct drgn_language *drgn_type_language(struct drgn_type *type);

/**
 * @defgroup Platforms Platforms
 *
 * Program platforms (i.e., architecture and ABI).
 *
 * @{
 */

/** An instruction set architecture. */
enum drgn_architecture {
	DRGN_ARCH_UNKNOWN,
	DRGN_ARCH_X86_64,
	DRGN_ARCH_I386,
	DRGN_ARCH_AARCH64,
	DRGN_ARCH_ARM,
	DRGN_ARCH_PPC64,
	DRGN_ARCH_RISCV64,
	DRGN_ARCH_RISCV32,
	DRGN_ARCH_S390X,
	DRGN_ARCH_S390,
};

/** Flags describing a @ref drgn_platform. */
enum drgn_platform_flags {
	/** Platform is 64-bit. */
	DRGN_PLATFORM_IS_64_BIT = (1 << 0),
	/** Platform is little-endian. */
	DRGN_PLATFORM_IS_LITTLE_ENDIAN = (1 << 1),
	/** All valid platform flags. */
	DRGN_ALL_PLATFORM_FLAGS = (1 << 2) - 1,
	/** Use the default flags for the architecture. */
	DRGN_PLATFORM_DEFAULT_FLAGS = UINT_MAX,
};

/**
 * @struct drgn_platform
 *
 * The environment that a program runs on.
 */
struct drgn_platform; // IWYU pragma: export

/**
 * @struct drgn_register
 *
 * A processor register.
 */
struct drgn_register; // IWYU pragma: export

/**
 * Create a @ref drgn_platform.
 *
 * The returned platform should be destroyed with @ref drgn_platform_destroy().
 */
struct drgn_error *drgn_platform_create(enum drgn_architecture arch,
					enum drgn_platform_flags flags,
					struct drgn_platform **ret);

/** Destroy a @ref drgn_platform. */
void drgn_platform_destroy(struct drgn_platform *platform);

/** Get the instruction set architecture of a @ref drgn_platform. */
enum drgn_architecture drgn_platform_arch(const struct drgn_platform *platform);

/** Get the flags of a @ref drgn_platform. */
enum drgn_platform_flags
drgn_platform_flags(const struct drgn_platform *platform);

/** Get the number of @ref drgn_register's on a @ref drgn_platform. */
size_t drgn_platform_num_registers(const struct drgn_platform *platform);

/** Get the @p n-th @ref drgn_register of a @ref drgn_platform. */
const struct drgn_register *
drgn_platform_register(const struct drgn_platform *platform, size_t n);

/** Get a @ref drgn_register in a @ref drgn_platform by its name. */
const struct drgn_register *
drgn_platform_register_by_name(const struct drgn_platform *platform,
			       const char *name);

/** Return whether two platforms are identical. */
bool drgn_platform_eq(struct drgn_platform *a, struct drgn_platform *b);

/** Platform that drgn was compiled for. */
extern const struct drgn_platform drgn_host_platform;

/**
 * Get the names of a @ref drgn_register.
 *
 * @param[out] num_names_ret Returned number of names.
 * @return Array of names.
 */
const char * const *drgn_register_names(const struct drgn_register *reg,
					size_t *num_names_ret);

/** @} */

struct drgn_object;
struct drgn_thread;

/**
 * @defgroup Programs Programs
 *
 * Debugging programs.
 *
 * A program being debugged is represented by a @ref drgn_program.
 *
 * @{
 */

/**
 * @struct drgn_program
 *
 * Program being debugged.
 *
 * A @ref drgn_program represents a crashed or running program. It supports
 * looking up objects (@ref drgn_program_find_object()) and types (@ref
 * drgn_program_find_type()) by name and reading arbitrary memory from the
 * program (@ref drgn_program_read_memory()).
 *
 * A @ref drgn_program is created with @ref drgn_program_from_core_dump(), @ref
 * drgn_program_from_kernel(), or @ref drgn_program_from_pid(). It must be freed
 * with @ref drgn_program_destroy().
 */
struct drgn_program; // IWYU pragma: export

/** Flags which apply to a @ref drgn_program. */
enum drgn_program_flags {
	/** The program is the Linux kernel. */
	DRGN_PROGRAM_IS_LINUX_KERNEL = (1 << 0),
	/** The program is currently running. */
	DRGN_PROGRAM_IS_LIVE = (1 << 1),
	/** The program is running on the local machine. */
	DRGN_PROGRAM_IS_LOCAL = (1 << 2),
};

/**
 * Create a @ref drgn_program.
 *
 * Usually, @ref drgn_program_from_core_dump(), @ref drgn_program_from_kernel(),
 * and @ref drgn_program_from_pid() are more convenient to use. However, this
 * can be used if more flexibility is required.
 *
 * @param[in] platform Platform that this program runs on, or @c NULL if it
 * should be determined automatically. This is copied.
 * @param[out] ret Returned program.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_create(const struct drgn_platform *platform,
				       struct drgn_program **ret);

/**
 * Free a @ref drgn_program.
 *
 * @param[in] prog Program to free.
 */
void drgn_program_destroy(struct drgn_program *prog);

/**
 * Callback implementing a memory read.
 *
 * @param[out] buf Buffer to read into.
 * @param[in] address Address which we are reading from.
 * @param[in] count Number of bytes to read.
 * @param[in] offset Offset in bytes of @p address from the beginning of the
 * segment.
 * @param[in] arg Argument passed to @ref drgn_program_add_memory_segment().
 * @param[in] physical Whether @c address is physical.
 * @return @c NULL on success, non-@c NULL on error.
 */
typedef struct drgn_error *(*drgn_memory_read_fn)(void *buf, uint64_t address,
						  size_t count, uint64_t offset,
						  void *arg, bool physical);

/**
 * Register a segment of memory in a @ref drgn_program.
 *
 * If the segment overlaps a previously registered segment, the new segment
 * takes precedence. If any part of the segment is beyond the maximum address,
 * that part is ignored.
 *
 * @param[in] address Address of the segment.
 * @param[in] size Size of the segment in bytes.
 * @param[in] read_fn Callback to read from segment.
 * @param[in] arg Argument to pass to @p read_fn.
 * @param[in] physical Whether to add a physical memory segment.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_program_add_memory_segment(struct drgn_program *prog, uint64_t address,
				uint64_t size, drgn_memory_read_fn read_fn,
				void *arg, bool physical);

/**
 * Return whether a filename containing a definition (@p haystack) matches a
 * filename being searched for (@p needle).
 *
 * The path is matched from right to left, so a definition in
 * <tt>/usr/include/stdio.h</tt> will match <tt>stdio.h</tt>,
 * <tt>include/stdio.h</tt>, <tt>usr/include/stdio.h</tt>, and
 * <tt>/usr/include/stdio.h</tt>. An empty or @c NULL @p needle matches any @p
 * haystack.
 */
bool drgn_filename_matches(const char *haystack, const char *needle);

enum {
	/** Enable a handler after all enabled handlers. */
	DRGN_HANDLER_REGISTER_ENABLE_LAST = SIZE_MAX,
	/** Don't enable a handler. */
	DRGN_HANDLER_REGISTER_DONT_ENABLE = SIZE_MAX - 1,
};

/** Type finder callback table. */
struct drgn_type_finder_ops {
	/**
	 * Callback to destroy the type finder.
	 *
	 * This may be @c NULL.
	 *
	 * @param[in] arg Argument passed to @ref
	 * drgn_program_register_type_finder().
	 */
	void (*destroy)(void *arg);
	/**
	 * Callback for finding a type.
	 *
	 * @param[in] kinds Kinds of types to find, as a bitmask of bits shifted
	 * by @ref drgn_type_kind. E.g., `(1 << DRGN_TYPE_STRUCT) | (1 <<
	 * DRGN_TYPE_CLASS)` means to find a structure or class type.
	 * @param[in] name Name of type (or tag, for structs, unions, and
	 * enums). This is @em not null-terminated.
	 * @param[in] name_len Length of @p name.
	 * @param[in] filename Filename containing the type definition or @c
	 * NULL. This should be matched with @ref drgn_filename_matches().
	 * @param[in] arg Argument passed to @ref
	 * drgn_program_register_type_finder().
	 * @param[out] ret Returned type.
	 * @return @c NULL on success, non-@c NULL on error. In particular, if
	 * the type is not found, this should return &@ref drgn_not_found; any
	 * other errors are considered fatal.
	 */
	struct drgn_error *(*find)(uint64_t kinds, const char *name,
				   size_t name_len, const char *filename,
				   void *arg, struct drgn_qualified_type *ret);
};

/**
 * Register a type finding callback.
 *
 * @param[in] name Finder name. This is copied.
 * @param[in] ops Callback table. This is copied.
 * @param[in] arg Argument to pass to callbacks.
 * @param[in] enable_index Insert the finder into the list of enabled finders at
 * the given index. If @ref DRGN_HANDLER_REGISTER_ENABLE_LAST or greater than
 * the number of enabled finders, insert it at the end. If @ref
 * DRGN_HANDLER_REGISTER_DONT_ENABLE, don’t enable the finder.
 */
struct drgn_error *
drgn_program_register_type_finder(struct drgn_program *prog, const char *name,
				  const struct drgn_type_finder_ops *ops,
				  void *arg, size_t enable_index);

/**
 * Get the names of all registered type finders.
 *
 * The order of the names is arbitrary.
 *
 * @param[out] names_ret Returned array of names.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *
drgn_program_registered_type_finders(struct drgn_program *prog,
				     const char ***names_ret,
				     size_t *count_ret);

/**
 * Set the list of enabled type finders.
 *
 * Finders are called in the same order as the list until a type is found.
 *
 * @param[in] names Names of finders to enable, in order.
 * @param[in] count Number of names in @p names.
 */
struct drgn_error *
drgn_program_set_enabled_type_finders(struct drgn_program *prog,
				      const char * const *names,
				      size_t count);

/**
 * Get the names of enabled type finders, in order.
 *
 * @param[out] names_ret Returned array of names.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *drgn_program_enabled_type_finders(struct drgn_program *prog,
						     const char ***names_ret,
						     size_t *count_ret);

/** Flags for @ref drgn_program_find_object(). */
enum drgn_find_object_flags {
	/** Find a constant (e.g., enumeration constant or macro). */
	DRGN_FIND_OBJECT_CONSTANT = 1 << 0,
	/** Find a function. */
	DRGN_FIND_OBJECT_FUNCTION = 1 << 1,
	/** Find a variable. */
	DRGN_FIND_OBJECT_VARIABLE = 1 << 2,
	/** Find any kind of object. */
	DRGN_FIND_OBJECT_ANY = (1 << 3) - 1,
};

/** Object finder callback table. */
struct drgn_object_finder_ops {
	/**
	 * Callback to destroy the object finder.
	 *
	 * This may be @c NULL.
	 *
	 * @param[in] arg Argument passed to @ref
	 * drgn_program_register_object_finder().
	 */
	void (*destroy)(void *arg);
	/**
	 * Callback for finding an object.
	 *
	 * @param[in] name Name of object. This is @em not null-terminated.
	 * @param[in] name_len Length of @p name.
	 * @param[in] filename Filename containing the object definition or @c
	 * NULL. This should be matched with @ref drgn_filename_matches().
	 * @param[in] flags Flags indicating what kind of object to look for.
	 * @param[in] arg Argument passed to @ref
	 * drgn_program_register_object_finder().
	 * @param[out] ret Returned object. This must only be modified on
	 * success.
	 * @return @c NULL on success, non-@c NULL on error. In particular, if
	 * the object is not found, this should return &@ref drgn_not_found; any
	 * other errors are considered fatal.
	 */
	struct drgn_error *(*find)(const char *name, size_t name_len,
				   const char *filename,
				   enum drgn_find_object_flags flags,
				   void *arg, struct drgn_object *ret);
};

/**
 * Register an object finding callback.
 *
 * @param[in] name Finder name. This is copied.
 * @param[in] ops Callback table. This is copied.
 * @param[in] arg Argument to pass to callbacks.
 * @param[in] enable_index Insert the finder into the list of enabled finders at
 * the given index. If @ref DRGN_HANDLER_REGISTER_ENABLE_LAST or greater than
 * the number of enabled finders, insert it at the end. If @ref
 * DRGN_HANDLER_REGISTER_DONT_ENABLE, don’t enable the finder.
 */
struct drgn_error *
drgn_program_register_object_finder(struct drgn_program *prog, const char *name,
				    const struct drgn_object_finder_ops *ops,
				    void *arg, size_t enable_index);

/**
 * Get the names of all registered object finders.
 *
 * The order of the names is arbitrary.
 *
 * @param[out] names_ret Returned array of names.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *
drgn_program_registered_object_finders(struct drgn_program *prog,
				       const char ***names_ret,
				       size_t *count_ret);

/**
 * Set the list of enabled object finders.
 *
 * Finders are called in the same order as the list until a object is found.
 *
 * @param[in] names Names of finders to enable, in order.
 * @param[in] count Number of names in @p names.
 */
struct drgn_error *
drgn_program_set_enabled_object_finders(struct drgn_program *prog,
					const char * const *names,
					size_t count);

/**
 * Get the names of enabled object finders, in order.
 *
 * @param[out] names_ret Returned array of names.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *
drgn_program_enabled_object_finders(struct drgn_program *prog,
				    const char ***names_ret, size_t *count_ret);

/**
 * Set a @ref drgn_program to a core dump.
 *
 * @sa drgn_program_from_core_dump()
 *
 * @param[in] path Core dump file path.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_set_core_dump(struct drgn_program *prog,
					      const char *path);

/**
 * Set a @ref drgn_program to a core dump from a file descriptor.
 *
 * @param[in] path Core dump file descriptor.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_set_core_dump_fd(struct drgn_program *prog, int fd);

/**
 * Set a @ref drgn_program to the running operating system kernel.
 *
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_set_kernel(struct drgn_program *prog);

/**
 * Set a @ref drgn_program to a running process.
 *
 * @sa drgn_program_from_pid()
 *
 * @param[in] pid Process ID.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_set_pid(struct drgn_program *prog, pid_t pid);

/**
 * Create a @ref drgn_program from a core dump file.
 *
 * The type of program (e.g., userspace or kernel) is determined automatically.
 *
 * @param[in] path Core dump file path.
 * @param[out] ret Returned program.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_from_core_dump(const char *path,
					       struct drgn_program **ret);

/**
 * Create a @ref drgn_program from a core dump file descriptor.
 *
 * Same as @ref drgn_program_from_core_dump but with an already-opened file
 * descriptor.
 *
 * @param[in] fd Core dump file path descriptor.
 * @param[out] ret Returned program.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_from_core_dump_fd(int fd,
						  struct drgn_program **ret);

/**
 * Create a @ref drgn_program from the running operating system kernel.
 *
 * This requires root privileges.
 *
 * @param[out] ret Returned program.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_from_kernel(struct drgn_program **ret);

/**
 * Create a @ref drgn_program from the a running program.
 *
 * On Linux, this requires @c PTRACE_MODE_ATTACH_FSCREDS permissions (see
 * <tt>ptrace(2)</tt>).
 *
 * @param[in] pid Process ID of the program to debug.
 * @param[out] ret Returned program.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_from_pid(pid_t pid, struct drgn_program **ret);

/** Get the set of @ref drgn_program_flags applying to a @ref drgn_program. */
enum drgn_program_flags drgn_program_flags(struct drgn_program *prog);

/**
 * Get the platform of a @ref drgn_program.
 *
 * This remains valid until the program is destroyed. It should @em not be
 * destroyed with @ref drgn_platform_destroy().
 * @return non-@c NULL on success, @c NULL if the platform is not known yet.
 */
const struct drgn_platform *drgn_program_platform(struct drgn_program *prog);

/**
 * Get the path of the core dump that a @ref drgn_program was created from.
 *
 * @return Path which is valid until the program is destroyed, or @c NULL if the
 * program was not created from a core dump.
 */
const char *drgn_program_core_dump_path(struct drgn_program *prog);

/** Get the default language of a @ref drgn_program. */
const struct drgn_language *drgn_program_language(struct drgn_program *prog);

/** Set the default language of a @ref drgn_program. */
void drgn_program_set_language(struct drgn_program *prog,
			       const struct drgn_language *lang);

/**
 * Read from a program's memory.
 *
 * @param[in] prog Program to read from.
 * @param[out] buf Buffer to read into.
 * @param[in] address Starting address in memory to read.
 * @param[in] count Number of bytes to read.
 * @param[in] physical Whether @c address is physical. A program may support
 * only virtual or physical addresses or both.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_read_memory(struct drgn_program *prog,
					    void *buf, uint64_t address,
					    size_t count, bool physical);

/**
 * Read a C string from a program's memory.
 *
 * This reads up to and including the terminating null byte.
 *
 * @param[in] prog Program to read from.
 * @param[in] address Starting address in memory to read.
 * @param[in] physical Whether @c address is physical. See @ref
 * drgn_program_read_memory().
 * @param[in] max_size Stop after this many bytes are read, not including the
 * null byte. A null byte is appended to @p ret in this case.
 * @param[out] ret Returned string. On success, it must be freed with @c free().
 * On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_read_c_string(struct drgn_program *prog,
					      uint64_t address, bool physical,
					      size_t max_size, char **ret);

struct drgn_error *drgn_program_read_u8(struct drgn_program *prog,
					uint64_t address, bool physical,
					uint8_t *ret);

struct drgn_error *drgn_program_read_u16(struct drgn_program *prog,
					 uint64_t address, bool physical,
					 uint16_t *ret);

struct drgn_error *drgn_program_read_u32(struct drgn_program *prog,
					 uint64_t address, bool physical,
					 uint32_t *ret);

struct drgn_error *drgn_program_read_u64(struct drgn_program *prog,
					 uint64_t address, bool physical,
					 uint64_t *ret);

struct drgn_error *drgn_program_read_word(struct drgn_program *prog,
					  uint64_t address, bool physical,
					  uint64_t *ret);

/**
 * Find a type in a program by name.
 *
 * The returned type is valid for the lifetime of the @ref drgn_program.
 *
 * @param[in] prog Program.
 * @param[in] name Name of the type.
 * @param[in] filename Filename containing the type definition. This is matched
 * with @ref drgn_filename_matches(). If multiple definitions match, one is
 * returned arbitrarily.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_find_type(struct drgn_program *prog,
					  const char *name,
					  const char *filename,
					  struct drgn_qualified_type *ret);

/**
 * Find an object in a program by name.
 *
 * The object can be a variable, constant, or function depending on @p flags.
 *
 * @param[in] prog Program.
 * @param[in] name Name of the object.
 * @param[in] filename Filename containing the object definition. This is
 * matched with @ref drgn_filename_matches(). If multiple definitions match, one
 * is returned arbitrarily.
 * @param[in] flags Flags indicating what kind of object to look for.
 * @param[out] ret Returned object. This must have already been initialized with
 * @ref drgn_object_init().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_find_object(struct drgn_program *prog,
					    const char *name,
					    const char *filename,
					    enum drgn_find_object_flags flags,
					    struct drgn_object *ret);

/**
 * @ingroup Symbols
 *
 * @struct drgn_symbol
 *
 * A @ref drgn_symbol represents an entry in a program's symbol table.
 */
struct drgn_symbol; // IWYU pragma: export

/**
 * Get the symbol containing the given address.
 *
 * @param[out] ret The returned symbol. It should be freed with @ref
 * drgn_symbol_destroy().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_program_find_symbol_by_address(struct drgn_program *prog, uint64_t address,
				    struct drgn_symbol **ret);

/**
 * Get the symbol corresponding to the given name.
 *
 * @param[out] ret The returned symbol. It should be freed with @ref
 * drgn_symbol_destroy().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_find_symbol_by_name(struct drgn_program *prog,
						    const char *name,
						    struct drgn_symbol **ret);

/**
 * Get all global and local symbols, optionally with the given name.
 *
 * @param[in] prog Program.
 * @param[in] name Name to match. If @c NULL, returns all symbols.
 * @param[out] syms_ret Returned array of symbols. On success, this must be
 * freed with @ref drgn_symbols_destroy().
 * @param[out] count_ret Returned number of symbols in @p syms_ret.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_find_symbols_by_name(struct drgn_program *prog,
						     const char *name,
						     struct drgn_symbol ***syms_ret,
						     size_t *count_ret);

/**
 * Get all symbols containing the given address.
 *
 * @param[in] prog Program.
 * @param[in] address Address to search for.
 * @param[out] syms_ret Returned array of symbols. On success, this must be
 * freed with @ref drgn_symbols_destroy().
 * @param[out] count_ret Returned number of symbols in @p syms_ret.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_find_symbols_by_address(struct drgn_program *prog,
							uint64_t address,
							struct drgn_symbol ***syms_ret,
							size_t *count_ret);

/** Flags for @ref drgn_symbol_finder_ops::find() */
enum drgn_find_symbol_flags {
	/** Find symbols whose name matches the name argument */
	DRGN_FIND_SYMBOL_NAME = 1 << 0,
	/** Find symbols whose address matches the addr argument */
	DRGN_FIND_SYMBOL_ADDR = 1 << 1,
	/** Find only one symbol */
	DRGN_FIND_SYMBOL_ONE = 1 << 2,
};

/** Result builder for @ref drgn_symbol_finder_ops::find() */
struct drgn_symbol_result_builder;

/**
 * Add or set the return value for a symbol search
 *
 * Symbol finders should call this with each symbol search result. If the symbol
 * search was @ref DRGN_FIND_SYMBOL_ONE, then only the most recent symbol added
 * to the builder will be returned. Otherwise, all symbols added to the builder
 * are returned. Returns true on success, or false on an allocation failure.
 */
bool
drgn_symbol_result_builder_add(struct drgn_symbol_result_builder *builder,
			       struct drgn_symbol *symbol);

/** Get the current number of results in a symbol search result. */
size_t drgn_symbol_result_builder_count(const struct drgn_symbol_result_builder *builder);

/** Symbol finder callback table. */
struct drgn_symbol_finder_ops {
	/**
	 * Callback to destroy the symbol finder.
	 *
	 * This may be @c NULL.
	 *
	 * @param[in] arg Argument passed to @ref
	 * drgn_program_register_symbol_finder().
	 */
	void (*destroy)(void *arg);
	/**
	 * Callback for finding one or more symbols.
	 *
	 * The callback should perform a symbol lookup based on the flags given
	 * in @p flags. When multiple flags are provided, the effect should be
	 * treated as a logical AND. Symbol results should be added to the
	 * result builder @p builder, via @ref drgn_symbol_result_builder_add().
	 * When @ref DRGN_FIND_SYMBOL_ONE is set, then the finding function
	 * should only return the single best symbol result, and short-circuit
	 * return.
	 *
	 * When no symbol is found, simply do not add any result to the builder.
	 * No error should be returned in this case.
	 *
	 * @param[in] name Name of the symbol to match
	 * @param[in] addr Address of the symbol to match
	 * @param[in] flags Flags indicating the desired behavior of the search
	 * @param[in] arg Argument passed to @ref
	 * drgn_program_register_symbol_finder().
	 * @param[in] builder Used to build the resulting symbol output
	 */
	struct drgn_error *(*find)(const char *name, uint64_t addr,
				   enum drgn_find_symbol_flags flags, void *arg,
				   struct drgn_symbol_result_builder *builder);
};

/**
 * Register a symbol finding callback.
 *
 * @param[in] name Finder name. This is copied.
 * @param[in] ops Callback table. This is copied.
 * @param[in] arg Argument to pass to callbacks.
 * @param[in] enable_index Insert the finder into the list of enabled finders at
 * the given index. If @ref DRGN_HANDLER_REGISTER_ENABLE_LAST or greater than
 * the number of enabled finders, insert it at the end. If @ref
 * DRGN_HANDLER_REGISTER_DONT_ENABLE, don’t enable the finder.
 */
struct drgn_error *
drgn_program_register_symbol_finder(struct drgn_program *prog, const char *name,
				    const struct drgn_symbol_finder_ops *ops,
				    void *arg, size_t enable_index);

/**
 * Get the names of all registered symbol finders.
 *
 * The order of the names is arbitrary.
 *
 * @param[out] names_ret Returned array of names.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *
drgn_program_registered_symbol_finders(struct drgn_program *prog,
				       const char ***names_ret,
				       size_t *count_ret);

/**
 * Set the list of enabled symbol finders.
 *
 * Finders are called in the same order as the list. In case of a search for
 * multiple symbols, then the results of all callbacks are concatenated. If the
 * search is for a single symbol, then the first callback which finds a symbol
 * will short-circuit the search.
 *
 * @param[in] names Names of finders to enable, in order.
 * @param[in] count Number of names in @p names.
 */
struct drgn_error *
drgn_program_set_enabled_symbol_finders(struct drgn_program *prog,
					const char * const *names,
					size_t count);

/**
 * Get the names of enabled symbol finders, in order.
 *
 * @param[out] names_ret Returned array of names.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *
drgn_program_enabled_symbol_finders(struct drgn_program *prog,
				    const char ***names_ret, size_t *count_ret);

/** Element type and size. */
struct drgn_element_info {
	/** Type of the element. */
	struct drgn_qualified_type qualified_type;
	/**
	 * Size in bits of one element.
	 *
	 * Element @c i is at bit offset <tt>i * bit_size</tt>.
	 */
	uint64_t bit_size;
};

/**
 * Get the element type and size of an array or pointer @ref drgn_type.
 *
 * @param[in] prog Program.
 * @param[in] type Array or pointer. After this function is called, this type
 * must remain valid until the program is destroyed.
 * @param[out] ret Returned element information.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_element_info(struct drgn_program *prog,
					     struct drgn_type *type,
					     struct drgn_element_info *ret);

/** @} */

/**
 * @defgroup Modules Modules
 *
 * Modules in a program and debugging information.
 *
 * @{
 */

/**
 * An executable, library, or other binary file used by a program.
 *
 * Modules are uniquely identified by the combination of their kind (@ref
 * drgn_module_kind()), name (@ref drgn_module_name()), and info (@ref
 * drgn_module_info()).
 */
struct drgn_module;

/** Kinds of modules. */
enum drgn_module_kind {
	/**
	 * Main module. For userspace programs, this is the executable. For the
	 * Linux kernel, this is `vmlinux`.
	 */
	DRGN_MODULE_MAIN,
	/** Shared library (a.k.a. dynamic library or dynamic shared object). */
	DRGN_MODULE_SHARED_LIBRARY,
	/** Virtual dynamic shared object (vDSO). */
	DRGN_MODULE_VDSO,
	/** Relocatable object (e.g., Linux kernel loadable module). */
	DRGN_MODULE_RELOCATABLE,
	/** Extra debugging information. */
	DRGN_MODULE_EXTRA,
} __attribute__((__packed__));

/**
 * Find the created @ref drgn_module with the given @p name.
 *
 * If there are multiple modules with the given name, one is returned
 * arbitrarily.
 *
 * @return Module, or @c NULL if not found.
 */
struct drgn_module *drgn_module_find_by_name(struct drgn_program *prog,
					     const char *name);

/**
 * Find the created @ref drgn_module containing the given @p address.
 *
 * @return Module, or @c NULL if not found.
 */
struct drgn_module *drgn_module_find_by_address(struct drgn_program *prog,
						uint64_t address);

/**
 * Find the main module.
 *
 * @param[in] name Module name, or @c NULL to match any name.
 */
struct drgn_module *drgn_module_find_main(struct drgn_program *prog,
					  const char *name);

/**
 * Find the main module, creating it if it doesn't already exist.
 *
 * @param[out] new_ret @c true if the module was newly created, @c false if it
 * was found.
 */
struct drgn_error *drgn_module_find_or_create_main(struct drgn_program *prog,
						   const char *name,
						   struct drgn_module **ret,
						   bool *new_ret);

/** Find a shared library module. */
struct drgn_module *drgn_module_find_shared_library(struct drgn_program *prog,
						    const char *name,
						    uint64_t dynamic_address);

/**
 * Find a shared library module, creating it if it doesn't already exist.
 *
 * @param[out] new_ret @c true if the module was newly created, @c false if it
 * was found.
 */
struct drgn_error *
drgn_module_find_or_create_shared_library(struct drgn_program *prog,
					  const char *name,
					  uint64_t dynamic_address,
					  struct drgn_module **ret,
					  bool *new_ret);

/** Find a vDSO module. */
struct drgn_module *drgn_module_find_vdso(struct drgn_program *prog,
					  const char *name,
					  uint64_t dynamic_address);

/**
 * Find a vDSO module, creating it if it doesn't already exist.
 *
 * @param[out] new_ret @c true if the module was newly created, @c false if it
 * was found.
 */
struct drgn_error *drgn_module_find_or_create_vdso(struct drgn_program *prog,
						   const char *name,
						   uint64_t dynamic_address,
						   struct drgn_module **ret,
						   bool *new_ret);

/** Find a relocatable module. */
struct drgn_module *drgn_module_find_relocatable(struct drgn_program *prog,
						 const char *name,
						 uint64_t address);

/**
 * Find a relocatable module, creating it if it doesn't already exist.
 *
 * @param[out] new_ret @c true if the module was newly created, @c false if it
 * was found.
 */
struct drgn_error *
drgn_module_find_or_create_relocatable(struct drgn_program *prog,
				       const char *name, uint64_t address,
				       struct drgn_module **ret, bool *new_ret);

/**
 * Find a created Linux kernel loadable module from a ``struct module *`` object.
 */
struct drgn_error *
drgn_module_find_linux_kernel_loadable(const struct drgn_object *module_obj,
				       struct drgn_module **ret);

/**
 * Find a Linux kernel loadable module from a ``struct module *`` object, creating
 * it if it doesn't already exist.
 *
 * @param[out] new_ret @c true if the module was newly created, @c false if it
 * was found.
 */
struct drgn_error *
drgn_module_find_or_create_linux_kernel_loadable(const struct drgn_object *module_obj,
						 struct drgn_module **ret,
						 bool *new_ret);

/** Find an extra module. */
struct drgn_module *drgn_module_find_extra(struct drgn_program *prog,
					   const char *name, uint64_t id);

/**
 * Find an extra module, creating it if it doesn't already exist.
 *
 * @param[out] new_ret @c true if the module was newly created, @c false if it
 * was found.
 */
struct drgn_error *drgn_module_find_or_create_extra(struct drgn_program *prog,
						    const char *name,
						    uint64_t id,
						    struct drgn_module **ret,
						    bool *new_ret);

/** Get the program that a module is from. */
struct drgn_program *drgn_module_program(const struct drgn_module *module);

/** Get the kind of a module. */
enum drgn_module_kind drgn_module_kind(const struct drgn_module *module);

/** Get the name of a module. */
const char *drgn_module_name(const struct drgn_module *module);

/**
 * Get the kind-specific info of a module.
 *
 * - For the main module, it is always 0.
 * - For shared library and vDSO modules, it is the address of the dynamic
 *   section.
 * - For relocatable modules, it is an address identifying the module (e.g., for
 *   Linux kernel loadable modules, it is the base address).
 * - For extra modules, it is an arbitrary identification number.
 */
uint64_t drgn_module_info(const struct drgn_module *module);

/**
 * Get the number of address ranges where a module is loaded.
 *
 * @param[out] ret Returned number of address ranges (zero if address ranges are
 * empty or not set).
 * @return @c true on success (including if address ranges are empty), @c false
 * if address ranges are not set.
 */
bool drgn_module_num_address_ranges(const struct drgn_module *module,
				    size_t *ret);

/**
 * Get the @p i-th address range where a module is loaded.
 *
 * @param[out] start_ret Minimum address (inclusive).
 * @param[out] end_ret Maximum address (exclusive).
 * @return @c true on success, @c false if @p i is out of bounds (i.e., if it is
 * greater than @ref drgn_module_num_address_ranges()).
 */
bool drgn_module_address_range(const struct drgn_module *module, size_t i,
			       uint64_t *start_ret, uint64_t *end_ret);

/**
 * Set the address range of a module.
 *
 * This is equivalent to:
 *
 * ```
 * uint64_t range[2] = {start, end};
 * drgn_module_set_address_ranges(module, &range, 1);
 * ```
 */
struct drgn_error *drgn_module_set_address_range(struct drgn_module *module,
						 uint64_t start, uint64_t end);

/**
 * Set the address ranges of a module.
 *
 * @param[in] ranges Ranges to set. The first element of each range is the
 * start. The second is the end. The start must be less than the end. This is
 * copied, so it need not remain valid after this function returns.
 * @param[in] num_ranges Number of ranges in @p ranges.
 */
struct drgn_error *drgn_module_set_address_ranges(struct drgn_module *module,
						  uint64_t ranges[][2],
						  size_t num_ranges);

/** Unset the address ranges for a module. */
void drgn_module_unset_address_ranges(struct drgn_module *module);

/** Return whether a module's address ranges contain @p address. */
bool drgn_module_contains_address(const struct drgn_module *module,
				  uint64_t address);

/**
 * Get the unique byte string (e.g., GNU build ID) identifying files used by
 * a module.
 *
 * @param[out] raw_ret Returned raw build ID. @c NULL if not known. Valid until
 * the build ID is changed.
 * @param[out] raw_len_ret Size of returned build ID, in bytes. 0 if not known.
 * @return Lowercase hexadecimal representation of build ID. @c NULL if not
 * known. Valid until the build ID is changed.
 */
const char *drgn_module_build_id(const struct drgn_module *module,
				 const void **raw_ret, size_t *raw_len_ret);

/**
 * Set the unique byte string (e.g., GNU build ID) identifying files used by a
 * module.
 *
 * @param[in] build_id New build ID.
 * @param[in] build_id_len New size of build ID, in bytes. May be 0 to unset the
 * build ID.
 */
struct drgn_error *drgn_module_set_build_id(struct drgn_module *module,
					    const void *build_id,
					    size_t build_id_len);

/** Get the address of a section with the given name in a relocatable module. */
struct drgn_error *drgn_module_get_section_address(struct drgn_module *module,
						   const char *name,
						   uint64_t *ret);

/**
 * Set the address of a section with the given name in a relocatable module.
 *
 * This is not allowed after a file has been assigned to the module.
 */
struct drgn_error *drgn_module_set_section_address(struct drgn_module *module,
						   const char *name,
						   uint64_t address);

/**
 * Unset the address of a section with the given name in a relocatable module.
 *
 * This is not allowed after a file has been assigned to the module.
 */
struct drgn_error *drgn_module_delete_section_address(struct drgn_module *module,
						      const char *name);

/**
 * Get the number of section addresses currently set in a relocatable module.
 */
struct drgn_error *drgn_module_num_section_addresses(struct drgn_module *module,
						     size_t *ret);

/** Iterator over set section addresses in a relocatable module. */
struct drgn_module_section_address_iterator;

/** Create a @ref drgn_module_section_address_iterator. */
struct drgn_error *
drgn_module_section_address_iterator_create(struct drgn_module *module,
					    struct drgn_module_section_address_iterator **ret);

/** Destroy a @ref drgn_module_section_address_iterator. */
void
drgn_module_section_address_iterator_destroy(struct drgn_module_section_address_iterator *it);

/** Get the module that a @ref drgn_module_section_address_iterator is for. */
struct drgn_module *
drgn_module_section_address_iterator_module(struct drgn_module_section_address_iterator *it);

/**
 * Get the next section name and address from a @ref
 * drgn_module_section_address_iterator.
 *
 * @param[out] name_ret Returned name. Valid until the the next call to @ref
 * drgn_module_section_address_iterator_next() or @ref
 * drgn_module_section_address_iterator_destroy() on @it.
 * @param[out] address_ret Returned address.
 */
struct drgn_error *
drgn_module_section_address_iterator_next(struct drgn_module_section_address_iterator *it,
					  const char **name_ret,
					  uint64_t *address_ret);

/** Status of a file in a @ref drgn_module. */
enum drgn_module_file_status {
	/** File has not been found and should be searched for. */
	DRGN_MODULE_FILE_WANT,
	/** File has already been found and assigned. */
	DRGN_MODULE_FILE_HAVE,
	/** File has not been found, but it should not be searched for. */
	DRGN_MODULE_FILE_DONT_WANT,
	/** File has not been found and is not needed. */
	DRGN_MODULE_FILE_DONT_NEED,
	/**
	 * File has been found, but it requires a supplementary file before it
	 * can be used.
	 */
	DRGN_MODULE_FILE_WANT_SUPPLEMENTARY,
};

/** Kind of supplementary file. */
enum drgn_supplementary_file_kind {
	/** Not known or not needed. */
	DRGN_SUPPLEMENTARY_FILE_NONE,
	/**
	 * GNU-style supplementary debug file referred to by a
	 * ``.gnu_debugaltlink`` section.
	 */
	DRGN_SUPPLEMENTARY_FILE_GNU_DEBUGALTLINK,
};

/** Get the status of a module's loaded file. */
enum drgn_module_file_status
drgn_module_loaded_file_status(const struct drgn_module *module);

/** Set the status of a module's loaded file. */
bool drgn_module_set_loaded_file_status(struct drgn_module *module,
					enum drgn_module_file_status status);

/**
 * Get whether a module wants a loaded file.
 *
 * For future-proofness, debug info finders should prefer this over comparing
 * @ref drgn_module_loaded_file_status() directly.
 */
bool drgn_module_wants_loaded_file(const struct drgn_module *module);

/** Get the absolute path of a module's loaded file, or @c NULL if not known. */
const char *drgn_module_loaded_file_path(const struct drgn_module *module);

/**
 * Get the difference between the load address in the program and addresses in a
 * module's loaded file.
 */
uint64_t drgn_module_loaded_file_bias(const struct drgn_module *module);

enum drgn_module_file_status
drgn_module_debug_file_status(const struct drgn_module *module);

bool drgn_module_set_debug_file_status(struct drgn_module *module,
				       enum drgn_module_file_status status);

/**
 * Get whether a module wants a debug file.
 *
 * For future-proofness, debug info finders should prefer this over comparing
 * @ref drgn_module_debug_file_status() directly.
 */
bool drgn_module_wants_debug_file(const struct drgn_module *module);

/** Get the absolute path of a module's debug file, or @c NULL if not known. */
const char *drgn_module_debug_file_path(const struct drgn_module *module);

/**
 * Get the difference between the load address in the program and addresses in a
 * module's debug file.
 */
uint64_t drgn_module_debug_file_bias(const struct drgn_module *module);

/** Get the kind of a module's supplementary debug file. */
enum drgn_supplementary_file_kind
drgn_module_supplementary_debug_file_kind(const struct drgn_module *module);

/**
 * Get the absolute path of a module's supplementary debug file, or @c NULL if
 * not known or not needed.
 */
const char *
drgn_module_supplementary_debug_file_path(const struct drgn_module *module);

/**
 * Get information about the supplementary debug file that a module currently
 * wants.
 *
 * @param[out] debug_file_path_ret Path of main file that wants the
 * supplementary file.
 * @param[out] supplementary_path_ret Path to supplementary file. This may be
 * absolute or relative to @p debug_file_path_ret.
 * @param[out] checksum_ret Unique identifier of the supplementary file.
 * @param[out] checksum_len_ret Size of unique identifier, in bytes.
 * @return Kind of supplementary file.
 */
enum drgn_supplementary_file_kind
drgn_module_wanted_supplementary_debug_file(struct drgn_module *module,
					    const char **debug_file_path_ret,
					    const char **supplementary_path_ret,
					    const void **checksum_ret,
					    size_t *checksum_len_ret);

/**
 * Return the object associated with this module.
 *
 * For some modules, there may be an object related to it. For example, drgn
 * automatically identifies the Linux kernel `struct module *` associated with
 * loadable modules, and associates it with them. Users may set or replace an
 * associated object with @ref drgn_set_module_object().
 *
 * @param[out] ret Initialized object where the module object is placed
 */
struct drgn_error *
drgn_module_object(const struct drgn_module *module, struct drgn_object *ret);

/**
 * Set the object associated with this module.
 * @param[in] obj A new (or replacement) object for the module
 */
struct drgn_error *
drgn_module_set_object(struct drgn_module *module, const struct drgn_object *obj);

/** Debugging information finder callback table. */
struct drgn_debug_info_finder_ops {
	/**
	 * Callback to destroy the debug info finder.
	 *
	 * This may be @c NULL.
	 *
	 * @param[in] arg Argument passed to @ref
	 * drgn_program_register_debug_info_finder().
	 */
	void (*destroy)(void *arg);
	/**
	 * Callback for finding debug info.
	 *
	 * @param[in] modules Array of modules that want debugging information.
	 * @param[in] num_modules Number of modules in @p modules.
	 * @param[in] arg Argument passed to @ref
	 * drgn_program_register_debug_info_finder().
	 * @return @c NULL on success, non-@c NULL on error. It is not an error
	 * for some debugging information to not be found.
	 */
	struct drgn_error *(*find)(struct drgn_module * const *modules,
				   size_t num_modules, void *arg);
};

/**
 * Register a debugging information finding callback.
 *
 * @param[in] name Finder name. This is copied.
 * @param[in] ops Callback table. This is copied.
 * @param[in] arg Argument to pass to callbacks.
 * @param[in] enable_index Insert the finder into the list of enabled finders at
 * the given index. If @ref DRGN_HANDLER_REGISTER_ENABLE_LAST or greater than
 * the number of enabled finders, insert it at the end. If @ref
 * DRGN_HANDLER_REGISTER_DONT_ENABLE, don’t enable the finder.
 */
struct drgn_error *
drgn_program_register_debug_info_finder(struct drgn_program *prog,
					const char *name,
					const struct drgn_debug_info_finder_ops *ops,
					void *arg, size_t enable_index);

/**
 * Get the names of all registered debugging information finders.
 *
 * The order of the names is arbitrary.
 *
 * @param[out] names_ret Returned array of names.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *
drgn_program_registered_debug_info_finders(struct drgn_program *prog,
					   const char ***names_ret,
					   size_t *count_ret);

/**
 * Set the list of enabled debugging information finders.
 *
 * Finders are called in the same order as the list until all wanted files have
 * been found.
 *
 * @param[in] names Names of finders to enable, in order.
 * @param[in] count Number of names in @p names.
 */
struct drgn_error *
drgn_program_set_enabled_debug_info_finders(struct drgn_program *prog,
					    const char * const *names,
					    size_t count);

/**
 * Get the names of enabled debugging information finders, in order.
 *
 * @param[out] names_ret Returned array of names.
 * @param[out] count_ret Returned number of names in @p names_ret.
 */
struct drgn_error *
drgn_program_enabled_debug_info_finders(struct drgn_program *prog,
					const char ***names_ret,
					size_t *count_ret);

/** Options for debugging information searches. */
struct drgn_debug_info_options;

/** Create a @ref drgn_debug_info_options with the default settings. */
struct drgn_error *
drgn_debug_info_options_create(struct drgn_debug_info_options **ret);

/** Destroy a @ref drgn_debug_info_options. */
void
drgn_debug_info_options_destroy(struct drgn_debug_info_options *options);

/** Set all options in @p dst to the same as @p src. */
struct drgn_error *
drgn_debug_info_options_copy(struct drgn_debug_info_options *dst,
			     const struct drgn_debug_info_options *src);

/**
 * Get the list of directories to search for debugging information files.
 *
 * @return Null-terminated list of directories. Valid until @ref
 * drgn_debug_info_options_set_directories() or @ref
 * drgn_debug_info_options_destroy() is called on @p options.
 */
const char * const *
drgn_debug_info_options_get_directories(const struct drgn_debug_info_options *options);

/**
 * Set the list of directories to search for debugging information files.
 *
 * @param[in] value Null-terminated list of directories. It is copied, so it
 * need not remain valid after this function returns.
 */
struct drgn_error *
drgn_debug_info_options_set_directories(struct drgn_debug_info_options *options,
					const char * const *value)
	__attribute__((__nonnull__(1, 2)));

/** Get whether to try module names that look like filesystem paths. */
bool
drgn_debug_info_options_get_try_module_name(const struct drgn_debug_info_options *options);

/** Set whether to try module names that look like filesystem paths. */
void
drgn_debug_info_options_set_try_module_name(struct drgn_debug_info_options *options,
					    bool value);

/** Get whether to try files by build ID. */
bool
drgn_debug_info_options_get_try_build_id(const struct drgn_debug_info_options *options);

/** Set whether to try files by build ID. */
void
drgn_debug_info_options_set_try_build_id(struct drgn_debug_info_options *options,
					 bool value);

/**
 * Get the list of directories to search for by debug link.
 *
 * @return Null-terminated list of directories. Valid until @ref
 * drgn_debug_info_options_set_debug_link_directories() or @ref
 * drgn_debug_info_options_destroy() is called on @p options.
 */
const char * const *
drgn_debug_info_options_get_debug_link_directories(const struct drgn_debug_info_options *options);

/**
 * Set the list of directories to search for by debug link.
 *
 * @param[in] value Null-terminated list of directories. It is copied, so it
 * need not remain valid after this function returns.
 */
struct drgn_error *
drgn_debug_info_options_set_debug_link_directories(struct drgn_debug_info_options *options,
						   const char * const *value)
	__attribute__((__nonnull__(1, 2)));

/** Get whether to try files by debug link. */
bool
drgn_debug_info_options_get_try_debug_link(const struct drgn_debug_info_options *options);

/** Set whether to try files by debug link. */
void
drgn_debug_info_options_set_try_debug_link(struct drgn_debug_info_options *options,
					   bool value);

/** Get whether to try files via procfs for local processes. */
bool
drgn_debug_info_options_get_try_procfs(const struct drgn_debug_info_options *options);

/** Set whether to try files via procfs for local processes. */
void
drgn_debug_info_options_set_try_procfs(struct drgn_debug_info_options *options,
				       bool value);

/** Get whether to try the vDSO embedded in a process's memory/core dump. */
bool
drgn_debug_info_options_get_try_embedded_vdso(const struct drgn_debug_info_options *options);

/** Set whether to try the vDSO embedded in a process's memory/core dump. */
void
drgn_debug_info_options_set_try_embedded_vdso(struct drgn_debug_info_options *options,
					      bool value);

/**
 * Get whether to reuse a module's loaded file as its debug file or vice versa.
 */
bool
drgn_debug_info_options_get_try_reuse(const struct drgn_debug_info_options *options);

/**
 * Set whether to reuse a module's loaded file as its debug file or vice versa.
 */
void
drgn_debug_info_options_set_try_reuse(struct drgn_debug_info_options *options,
				      bool value);

/** Get whether to try finding supplementary files. */
bool
drgn_debug_info_options_get_try_supplementary(const struct drgn_debug_info_options *options);

/** Set whether to try finding supplementary files. */
void
drgn_debug_info_options_set_try_supplementary(struct drgn_debug_info_options *options,
					      bool value);

/**
 * Get the list of directories to search for kernel debugging information files.
 *
 * @return Null-terminated list of directories. Valid until @ref
 * drgn_debug_info_options_set_kernel_directories() or @ref
 * drgn_debug_info_options_destroy() is called on @p options.
 */
const char * const *
drgn_debug_info_options_get_kernel_directories(const struct drgn_debug_info_options *options);

/**
 * Set the list of directories to search for kernel debugging information files.
 *
 * @param[in] value Null-terminated list of directories. It is copied, so it
 * need not remain valid after this function returns.
 */
struct drgn_error *
drgn_debug_info_options_set_kernel_directories(struct drgn_debug_info_options *options,
					       const char * const *value)
	__attribute__((__nonnull__(1, 2)));

/** Methods of searching for loadable kernel module debugging information. */
enum drgn_kmod_search_method {
	DRGN_KMOD_SEARCH_NONE,
	DRGN_KMOD_SEARCH_DEPMOD,
	DRGN_KMOD_SEARCH_WALK,
	DRGN_KMOD_SEARCH_DEPMOD_OR_WALK,
	DRGN_KMOD_SEARCH_DEPMOD_AND_WALK,
} __attribute__((__packed__));

/** Get how to search for loadable kernel module debugging information. */
enum drgn_kmod_search_method
drgn_debug_info_options_get_try_kmod(const struct drgn_debug_info_options *options);

/** Set how to search for loadable kernel module debugging information. */
void
drgn_debug_info_options_set_try_kmod(struct drgn_debug_info_options *options,
				     enum drgn_kmod_search_method value);

/**
 * Get the default debugging information options for @p prog.
 *
 * @return Program options. May be modified as needed. Must not be passed to
 * @ref drgn_debug_info_options_destroy().
 */
struct drgn_debug_info_options *
drgn_program_debug_info_options(struct drgn_program *prog);

/**
 * Load debugging information for the given modules from the standard locations.
 *
 * @param[in] options Options to use, or @p NULL to use the program's default
 * options.
 */
struct drgn_error *
drgn_find_standard_debug_info(struct drgn_module * const *modules,
			      size_t num_modules,
			      struct drgn_debug_info_options *options);

/**
 * Try to use the given file for a module.
 *
 * @param[in] path Path to file.
 * @param[in] fd If nonnegative, an open file descriptor referring to the file.
 * This always takes ownership of the file descriptor even if the file is not
 * used or on error.
 * @param[in] force If @c true, don't check whether the file matches the module.
 */
struct drgn_error *
drgn_module_try_file(struct drgn_module *module, const char *path, int fd,
		     bool force);

/** Iterator over a set of modules. */
struct drgn_module_iterator;

/** Destroy a @ref drgn_module_iterator. */
void
drgn_module_iterator_destroy(struct drgn_module_iterator *it);

/** Get the program that a module iterator is from. */
struct drgn_program *
drgn_module_iterator_program(const struct drgn_module_iterator *it);

/**
 * Get the next module in a module iterator.
 *
 * @param[out] ret Returned module, or @c NULL if there are no more modules.
 * @param[out] new_ret Whether the module was newly created. May be @c NULL.
 */
struct drgn_error *drgn_module_iterator_next(struct drgn_module_iterator *it,
					     struct drgn_module **ret,
					     bool *new_ret);

/** Create an iterator over created modules. */
struct drgn_error *
drgn_created_module_iterator_create(struct drgn_program *prog,
				    struct drgn_module_iterator **ret);

/**
 * Create an iterator that determines what executables, libraries, etc. are
 * loaded in the program and creates modules to represent them.
 */
struct drgn_error *
drgn_loaded_module_iterator_create(struct drgn_program *prog,
				   struct drgn_module_iterator **ret);

/**
 * Determine what executables, libraries, etc. are loaded in the program and
 * create modules to represent them.
 *
 * This is a shortcut for creating an iterator with @ref
 * drgn_loaded_module_iterator_create() and calling @ref
 * drgn_module_iterator_next() until it is exhausted.
 */
struct drgn_error *
drgn_create_loaded_modules(struct drgn_program *prog);

/**
 * Load debugging information for the given set of files and/or modules.
 *
 * @param[in] load_default Whether to load all debugging information for all
 * loaded modules. This implies @p load_main.
 * @param[in] load_main Whether to load all debugging information for the main
 * module.
 */
struct drgn_error *drgn_program_load_debug_info(struct drgn_program *prog,
						const char **paths, size_t n,
						bool load_default,
						bool load_main);

/**
 * Load debugging information for the given modules using the enabled debugging
 * information finders.
 */
struct drgn_error *drgn_load_module_debug_info(struct drgn_module **modules,
					       size_t *num_modules);

/** @} */

/**
 * @defgroup Logging Logging
 *
 * Logging configuration.
 *
 * drgn can log to a file (@ref drgn_program_set_log_file()) or an arbitrary
 * callback (@ref drgn_program_set_log_callback()). Messages can be filtered
 * based on the log level (@ref drgn_program_set_log_level()).
 *
 * By default, the log file is set to `stderr` and the log level is @ref
 * DRGN_LOG_NONE, so logging is disabled.
 *
 * Additionally, drgn can display a progress bar for some operations, like
 * downloading debugging information. By default, progress bars are displayed on
 * standard error if standard error is a terminal, the log file is set to
 * `stderr`, and the log level is less than or equal to @ref DRGN_LOG_WARNING,
 * but this can be changed (@ref drgn_program_set_progress_file()).
 *
 * @{
 */

/** Log levels. */
enum drgn_log_level {
	DRGN_LOG_DEBUG = 0,
	DRGN_LOG_INFO = 1,
	DRGN_LOG_WARNING = 2,
	DRGN_LOG_ERROR = 3,
	DRGN_LOG_CRITICAL = 4,
};
/** Don't log anything. */
#define DRGN_LOG_NONE (DRGN_LOG_CRITICAL + 1)

/**
 * Set the minimum log level.
 *
 * Messages below this level will not be logged.
 *
 * @param[in] level Minimum @ref drgn_log_level to log, or @ref DRGN_LOG_NONE to
 * disable logging.
 */
void drgn_program_set_log_level(struct drgn_program *prog, int level);

/**
 * Get the minimum log level.
 *
 * @return Minimum @ref drgn_log_level being logged, or @ref DRGN_LOG_NONE if
 * logging is disabled.
 */
int drgn_program_get_log_level(struct drgn_program *prog);

/** Write logs to the given file. */
void drgn_program_set_log_file(struct drgn_program *prog, FILE *file);

/**
 * Log callback.
 *
 * @param[in] prog Program message was logged to.
 * @param[in] arg `callback_arg` passed to @ref drgn_program_set_log_callback().
 * @param[in] level Message level.
 * @param[in] format printf-style format of message.
 * @param[in] ap Arguments for @p format.
 * @param[in] err Error to append after formatted message if non-@c NULL. This
 * can be formatted with @ref drgn_error_string(), @ref drgn_error_fwrite(), or
 * @ref drgn_error_dwrite().
 */
typedef void drgn_log_fn(struct drgn_program *prog, void *arg,
			 enum drgn_log_level level, const char *format,
			 va_list ap, struct drgn_error *err);

/**
 * Set a callback to log to.
 *
 * @param[in] callback Callback to call for each log message. This is only
 * called if the message's level is at least the current log level.
 * @param[in] callback_arg Argument to pass to callback.
 */
void drgn_program_set_log_callback(struct drgn_program *prog,
				   drgn_log_fn *callback, void *callback_arg);

/**
 * Get the current log callback.
 *
 * @param[out] callback_ret Returned callback.
 * @param[out] callback_arg_ret Returned callback argument.
 */
void drgn_program_get_log_callback(struct drgn_program *prog,
				   drgn_log_fn **callback_ret,
				   void **callback_arg_ret);

/**
 * Write progress bars to the given file.
 *
 * @param[in] file File, or @c NULL to disable progress bars.
 */
void drgn_program_set_progress_file(struct drgn_program *prog, FILE *file);

/** @} */

/**
 * @defgroup Objects Objects
 *
 * Objects in a program.
 *
 * A @ref drgn_object represents an object (e.g., variable, constant, or
 * function) in a program.
 *
 * Various operators and helpers are defined on objects; see @ref
 * ObjectOperators and @ref ObjectHelpers.
 *
 * Many operations are language-specific. C is currently the only supported
 * language.
 *
 * In drgn's emulation of C:
 *
 * - Signed and unsigned integer arithmetic is reduced modulo 2^width.
 * - Integer division truncates towards zero.
 * - Modulo has the sign of the dividend.
 * - Division or modulo by 0 returns an error.
 * - Shifts are reduced modulo 2^width. In particular, a shift by a value
 *   greater than the width returns 0.
 * - Shifts by a negative number return an error.
 * - Bitwise operators on signed integers act on the two's complement
 *   representation.
 * - Pointer arithmetic is supported.
 * - Integer literal have the first type of @c int, @c long, <tt>long long</tt>,
 *   and <tt>unsigned long long</tt> which can represent the value.
 * - Boolean literals have type @c int (@b not @c _Bool).
 * - Floating-point literals have type @c double.
 * @{
 */

/** Kinds of objects. */
enum drgn_object_kind {
	/** Constant or temporary computed value. */
	DRGN_OBJECT_VALUE,
	/** In program memory. */
	DRGN_OBJECT_REFERENCE,
	/** Absent (e.g. optimized out). */
	DRGN_OBJECT_ABSENT,
} __attribute__((__packed__));

/**
 * Object encodings.
 *
 * The value of a @ref drgn_object may be encoded in various ways depending on
 * its type. This determines which field of a @ref drgn_value is used.
 *
 * The incomplete encodings are only possible for reference objects; values have
 * a complete type.
 */
enum drgn_object_encoding {
	/**
	 * Memory buffer.
	 *
	 * This is used for objects with a structure, union, class, or array
	 * type.
	 */
	DRGN_OBJECT_ENCODING_BUFFER,
	/**
	 * Signed integer.
	 *
	 * This is used for objects with a signed integer or signed enumerated
	 * type no larger than 64 bits.
	 */
	DRGN_OBJECT_ENCODING_SIGNED,
	/**
	 * Unsigned integer.
	 *
	 * This is used for objects with a unsigned integer, boolean, or pointer
	 * type no larger than 64 bits.
	 */
	DRGN_OBJECT_ENCODING_UNSIGNED,
	/**
	 * Big signed integer.
	 *
	 * This is used for objects with a signed integer or signed enumerated
	 * type larger than 64 bits.
	 */
	DRGN_OBJECT_ENCODING_SIGNED_BIG,
	/**
	 * Big unsigned integer.
	 *
	 * This is used for objects with a unsigned integer, boolean, or pointer
	 * type larger than 64 bits.
	 */
	DRGN_OBJECT_ENCODING_UNSIGNED_BIG,
	/**
	 * Floating-point value.
	 *
	 * This used for objects with a floating-point type.
	 */
	DRGN_OBJECT_ENCODING_FLOAT,
	/**
	 * No value.
	 *
	 * This is used for reference objects with a void or function type.
	 */
	DRGN_OBJECT_ENCODING_NONE = -1,
	/**
	 * Incomplete buffer value.
	 *
	 * This is used for reference objects with an incomplete structure,
	 * union, class, or array type.
	 */
	DRGN_OBJECT_ENCODING_INCOMPLETE_BUFFER = -2,
	/**
	 * Incomplete integer value.
	 *
	 * This is used for reference objects with an incomplete enumerated
	 * types.
	 */
	DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER = -3,
} __attribute__((__packed__));

/**
 * Return whether a type corresponding to an object encoding is complete.
 *
 * @sa drgn_type_is_complete()
 */
static inline bool
drgn_object_encoding_is_complete(enum drgn_object_encoding encoding)
{
	return encoding >= 0;
}

/** Value of a @ref drgn_object. */
union drgn_value {
	/**
	 * Pointer to an external buffer for a @ref DRGN_OBJECT_ENCODING_BUFFER,
	 * @ref DRGN_OBJECT_ENCODING_SIGNED_BIG, or @ref
	 * DRGN_OBJECT_ENCODING_UNSIGNED_BIG value.
	 *
	 * For @ref DRGN_OBJECT_ENCODING_BUFFER, this contains the object's
	 * representation in the memory of the program.
	 *
	 * For @ref DRGN_OBJECT_ENCODING_SIGNED_BIG and @ref
	 * DRGN_OBJECT_ENCODING_UNSIGNED_BIG, the representation of the value is
	 * an implementation detail which may change.
	 */
	char *bufp;
	/**
	 * Inline buffer for a @ref DRGN_OBJECT_ENCODING_BUFFER value.
	 *
	 * Tiny buffers (see @ref drgn_value_is_inline()) are stored inline here
	 * instead of in a separate allocation.
	 */
	char ibuf[8];
	/** @ref DRGN_OBJECT_ENCODING_SIGNED value. */
	int64_t svalue;
	/** @ref DRGN_OBJECT_ENCODING_UNSIGNED value. */
	uint64_t uvalue;
	/** @ref DRGN_OBJECT_ENCODING_FLOAT value. */
	double fvalue;
};

/**
 * Return the number of bytes needed to store the given number of bits.
 *
 * @param[in] bits Number of bits.
 */
static inline uint64_t drgn_value_size(uint64_t bits)
{
	return bits / CHAR_BIT + (bits % CHAR_BIT ? 1 : 0);
}

/**
 * Return whether the given number of bits can be stored in the inline buffer of
 * a @ref drgn_value (@ref drgn_value::ibuf).
 *
 * @param[in] bits Number of bits.
 */
static inline bool drgn_value_is_inline(uint64_t bits)
{
	return bits <= CHAR_BIT * sizeof(((union drgn_value *)0)->ibuf);
}

/** Reason object is absent. */
enum drgn_absence_reason {
	/** Another reason not listed below. */
	DRGN_ABSENCE_REASON_OTHER,
	/** Object was optimized out by the compiler. */
	DRGN_ABSENCE_REASON_OPTIMIZED_OUT,
	/** Encountered unknown debugging information. */
	DRGN_ABSENCE_REASON_NOT_IMPLEMENTED,
};

/**
 * Object in a program.
 *
 * A @ref drgn_object represents a symbol or value in a program. It can be in
 * the memory of the program (a "reference"), a temporary computed value (a
 * "value"), or "absent".
 *
 * A @ref drgn_object must be initialized with @ref drgn_object_init() before it
 * is used. It can then be set and otherwise changed repeatedly. When the object
 * is no longer needed, it must be deinitialized @ref drgn_object_deinit().
 *
 * It is more effecient to initialize an object once and reuse it rather than
 * creating a new one repeatedly (e.g., in a loop).
 *
 * Members of a @ref drgn_object should not be modified except through the
 * provided functions.
 */
struct drgn_object {
	/** Type of this object. */
	struct drgn_type *type;
	/**
	 * Size of this object in bits.
	 *
	 * This is usually the size of @ref drgn_object::type, but it may be
	 * smaller if this is a bit field (@ref drgn_object::is_bit_field).
	 */
	uint64_t bit_size;
	/** Qualifiers on @ref drgn_object::type. */
	enum drgn_qualifiers qualifiers;
	/** How this object is encoded. */
	enum drgn_object_encoding encoding;
	/** Kind of this object. */
	enum drgn_object_kind kind;
	/** Whether this object is a bit field. */
	bool is_bit_field;
	/**
	 * Whether this object is little-endian.
	 *
	 * Valid only for scalars (i.e., @ref DRGN_OBJECT_ENCODING_SIGNED, @ref
	 * DRGN_OBJECT_ENCODING_UNSIGNED, @ref DRGN_OBJECT_ENCODING_SIGNED_BIG,
	 * @ref DRGN_OBJECT_ENCODING_UNSIGNED_BIG, @ref
	 * DRGN_OBJECT_ENCODING_FLOAT, or @ref
	 * DRGN_OBJECT_ENCODING_INCOMPLETE_INTEGER).
	 */
	bool little_endian;
	/**
	 * Offset in bits from @c address.
	 *
	 * Valid only for reference objects.
	 */
	uint8_t bit_offset;
	union {
		/** Value of value object. */
		union drgn_value value;
		/** Address of reference object. */
		uint64_t address;
		/** Reason object is absent. */
		enum drgn_absence_reason absence_reason;
	};
};

/** Return the number of bytes needed to store an object's value. */
static inline uint64_t drgn_object_size(const struct drgn_object *obj)
{
	return drgn_value_size(obj->bit_size);
}

/**
 * Return whether an object's value can be stored in the inline buffer of a @ref
 * drgn_value (@ref drgn_value::ibuf).
 */
static inline bool drgn_object_is_inline(const struct drgn_object *obj)
{
	return drgn_value_is_inline(obj->bit_size);
}

/** Return an object's buffer. */
#define drgn_object_buffer(obj) ({						\
	__auto_type _obj = (obj);						\
	drgn_object_is_inline(_obj) ? _obj->value.ibuf : _obj->value.bufp;	\
})

/** Get the type of a @ref drgn_object. */
static inline struct drgn_qualified_type
drgn_object_qualified_type(const struct drgn_object *obj)
{
	return (struct drgn_qualified_type){
		.type = obj->type,
		.qualifiers = obj->qualifiers,
	};
}

/**
 * Initialize a @ref drgn_object.
 *
 * The object is initialized to an absent object with a void type. This must be
 * paired with a call to @ref drgn_object_deinit().
 *
 * @param[in] obj Object to initialize.
 * @param[in] prog Program containing the object.
 */
void drgn_object_init(struct drgn_object *obj, struct drgn_program *prog);

/**
 * Deinitialize a @ref drgn_object.
 *
 * The object cannot be used after this unless it is reinitialized with @ref
 * drgn_object_init().
 *
 * @param[in] obj Object to deinitialize.
 */
void drgn_object_deinit(struct drgn_object *obj);

/**
 * Define and initialize a @ref drgn_object named @p obj that is automatically
 * deinitialized when it goes out of scope.
 *
 * This is equivalent to
 *
 * ```
 * struct drgn_object obj;
 * drgn_object_init(&obj, prog);
 * ...
 * drgn_object_deinit(&obj);
 * ```
 *
 * @param[in] obj Name of object.
 * @param[in] prog Program containing the object.
 */
#define DRGN_OBJECT(obj, prog)					\
	struct drgn_object obj					\
	__attribute__((__cleanup__(drgn_object_deinit))) =	\
	drgn_object_initializer(prog)
struct drgn_object drgn_object_initializer(struct drgn_program *prog);

/** Get the program that a @ref drgn_object is from. */
static inline struct drgn_program *
drgn_object_program(const struct drgn_object *obj)
{
	return drgn_type_program(obj->type);
}

/** Get the language of a @ref drgn_object from its type. */
static inline const struct drgn_language *
drgn_object_language(const struct drgn_object *obj)
{
	return drgn_type_language(obj->type);
}

/**
 * @defgroup ObjectSetters Setters
 *
 * Object setters.
 *
 * Once a @ref drgn_object is initialized with @ref drgn_object_init(), it may
 * be set any number of times.
 *
 * @{
 */

/**
 * Set a @ref drgn_object to a signed value.
 *
 * @param[out] res Object to set.
 * @param[in] qualified_type Type to set to.
 * @param[in] svalue Value to set to.
 * @param[in] bit_field_size If the object should be a bit field, its size in
 * bits. Otherwise, 0.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_set_signed(struct drgn_object *res,
		       struct drgn_qualified_type qualified_type,
		       int64_t svalue, uint64_t bit_field_size);

/**
 * Set a @ref drgn_object to an unsigned value.
 *
 * @param[out] res Object to set.
 * @param[in] qualified_type Type to set to.
 * @param[in] uvalue Value to set to.
 * @param[in] bit_field_size If the object should be a bit field, its size in
 * bits. Otherwise, 0.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_set_unsigned(struct drgn_object *res,
			 struct drgn_qualified_type qualified_type,
			 uint64_t uvalue, uint64_t bit_field_size);

/**
 * Set a @ref drgn_object to a floating-point value.
 *
 * @param[out] res Object to set.
 * @param[in] qualified_type Type to set to.
 * @param[in] fvalue Value to set to.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_set_float(struct drgn_object *res,
		      struct drgn_qualified_type qualified_type, double fvalue);

/**
 * Set a @ref drgn_object from a buffer.
 *
 * @param[out] res Object to set.
 * @param[in] qualified_type Type to set to.
 * @param[in] buf Buffer to set to. It is copied, so it need not remain valid
 * after this function returns.
 * @param[in] buf_size Size of @p buf, in bytes. `buf_size * 8` must be at least
 * `bit_size + bit_offset`, where @c bit_size is @p bit_field_size if non-zero
 * and the size of @p qualified_type in bits otherwise.
 * @param[in] bit_offset Offset of the value from the beginning of the buffer,
 * in bits. This is usually 0. It must be aligned to a byte unless the type is
 * scalar.
 * @param[in] bit_field_size If the object should be a bit field, its size in
 * bits. Otherwise, 0.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_set_from_buffer(struct drgn_object *res,
			    struct drgn_qualified_type qualified_type,
			    const void *buf, size_t buf_size,
			    uint64_t bit_offset, uint64_t bit_field_size);

/**
 * Set a @ref drgn_object to a reference.
 *
 * @param[out] res Object to set.
 * @param[in] qualified_type Type to set to.
 * @param[in] address Address of the object.
 * @param[in] bit_offset Offset of the value from @p address, in bits. This is
 * usually 0.
 * @param[in] bit_field_size If the object should be a bit field, its size in
 * bits. Otherwise, 0.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_set_reference(struct drgn_object *res,
			  struct drgn_qualified_type qualified_type,
			  uint64_t address, uint64_t bit_offset,
			  uint64_t bit_field_size);

/**
 * Set a @ref drgn_object as absent.
 *
 * @param[out] res Object to set.
 * @param[in] qualified_type Type to set to.
 * @param[in] reason Reason object is absent.
 * @param[in] bit_field_size If the object should be a bit field, its size in
 * bits. Otherwise, 0.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_set_absent(struct drgn_object *res,
		       struct drgn_qualified_type qualified_type,
		       enum drgn_absence_reason reason,
		       uint64_t bit_field_size);

/**
 * Set a @ref drgn_object to a integer literal.
 *
 * This determines the type based on the programming language of the program
 * that the object belongs to.
 *
 * @param[out] res Object to set.
 * @param[in] uvalue Integer value.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_integer_literal(struct drgn_object *res,
					       uint64_t uvalue);

/**
 * Set a @ref drgn_object to a boolean literal.
 *
 * This determines the type based on the programming language of the program
 * that the object belongs to.
 *
 * @param[out] res Object to set.
 * @param[in] bvalue Boolean value.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_bool_literal(struct drgn_object *res,
					    bool bvalue);

/**
 * Set a @ref drgn_object to a floating-point literal.
 *
 * This determines the type based on the programming language of the program
 * that the object belongs to.
 *
 * @param[out] res Object to set.
 * @param[in] fvalue Floating-point value.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_float_literal(struct drgn_object *res,
					     double fvalue);

/** @} */

/**
 * @defgroup ObjectHelpers Helpers
 *
 * Object helpers.
 *
 * Several helpers are provided for working with @ref drgn_object%s.
 *
 * Helpers which return a @ref drgn_object have the same calling convention: the
 * result object is the first argument, which must be initialized and may be the
 * same as the input object argument; the result is only modified if the helper
 * succeeds.
 *
 * @{
 */

/**
 * Set a @ref drgn_object to another object.
 *
 * This copies @c obj to @c res. If @c obj is a value, then @c res is set to a
 * value with the same type and value, and similarly if @c obj was a reference,
 * @c res is set to the same reference.
 *
 * @param[out] res Destination object.
 * @param[in] obj Source object.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_copy(struct drgn_object *res,
				    const struct drgn_object *obj);

/**
 * Get a @ref drgn_object from a "fragment" of an object.
 *
 * This is a low-level interface used to implement @ref drgn_object_subscript(),
 * @ref drgn_object_member(), and @ref drgn_object_reinterpret(). Those
 * functions are usually more convenient.
 *
 * If multiple elements of an array are accessed (e.g., when iterating through
 * it), it can be more efficient to call @ref drgn_program_element_info() once
 * to get the required information and this function with the computed bit
 * offset for each element.
 *
 * If the same member of a type is accessed repeatedly (e.g., in a loop), it can
 * be more efficient to call @ref drgn_type_find_member() once to get the
 * required information and this function to access the member each time.
 *
 * @sa drgn_object_dereference_offset
 *
 * @param[out] res Destination object.
 * @param[in] obj Source object.
 * @param[in] qualified_type Result type.
 * @param[in] bit_offset Offset in bits from the beginning of @p obj.
 * @param[in] bit_field_size If the object should be a bit field, its size in
 * bits. Otherwise, 0.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_fragment(struct drgn_object *res,
					const struct drgn_object *obj,
					struct drgn_qualified_type qualified_type,
					int64_t bit_offset,
					uint64_t bit_field_size);

/**
 * Get a @ref drgn_object from dereferencing a pointer object with an offset.
 *
 * This is a low-level interface used to implement @ref drgn_object_subscript()
 * and @ref drgn_object_member_dereference(). Those functions are usually more
 * convenient, but this function can be more efficient if accessing multiple
 * elements or the same member multiple times.
 *
 * @sa drgn_object_fragment
 *
 * @param[out] res Dereferenced object.
 * @param[in] obj Pointer object.
 * @param[in] qualified_type Result type.
 * @param[in] bit_offset Offset in bits from the address given by the value of
 * @p obj.
 * @param[in] bit_field_size If the object should be a bit field, its size in
 * bits. Otherwise, 0.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_dereference_offset(struct drgn_object *res,
			       const struct drgn_object *obj,
			       struct drgn_qualified_type qualified_type,
			       int64_t bit_offset, uint64_t bit_field_size);

/**
 * Read a @ref drgn_object.
 *
 * If @c obj is already a value, then this is equivalent to @ref
 * drgn_object_copy(). If @c is a reference, then this reads the reference and
 * sets @p res to the value.
 *
 * @param[out] res Object to set.
 * @param[in] obj Object to read.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_read(struct drgn_object *res,
				    const struct drgn_object *obj);

/**
 * Read the value of a @ref drgn_object.
 *
 * If @p obj is a value, that value is returned directly. If @p is a reference,
 * the value is read into the provided temporary buffer.
 *
 * This must be paired with @ref drgn_object_deinit_value().
 *
 * @param[in] obj Object to read.
 * @param[in] value Temporary value to use if necessary.
 * @param[out] ret Pointer to the returned value, which is <tt>&obj->value</tt>
 * if @p obj is a value, or @p value if @p obj is a reference.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_read_value(const struct drgn_object *obj,
					  union drgn_value *value,
					  const union drgn_value **ret);

/**
 * Deinitialize a value which was read with @ref drgn_object_read_value().
 *
 * @param[in] obj Object which was read.
 * @param[in] value Value returned from @ref drgn_object_read_value() in @p ret.
 */
void drgn_object_deinit_value(const struct drgn_object *obj,
			      const union drgn_value *value);

/**
 * Get the binary representation of the value of a @ref drgn_object.
 *
 * @param[out] Buffer to read into. Size must be at least
 * `drgn_object_size(obj)`.
 */
struct drgn_error *drgn_object_read_bytes(const struct drgn_object *obj,
					  void *buf);

/**
 * Get the value of an object encoded with @ref
 * drgn_object_encoding::DRGN_OBJECT_ENCODING_SIGNED.
 *
 * If the object is not a signed integer, an error is returned.
 *
 * @param[in] obj Object to read.
 * @param[out] ret Returned value.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_read_signed(const struct drgn_object *obj,
					   int64_t *ret);

/**
 * Get the value of an object encoded with @ref
 * drgn_object_encoding::DRGN_OBJECT_ENCODING_UNSIGNED.
 *
 * If the object is not an unsigned integer, an error is returned.
 *
 * @param[in] obj Object to read.
 * @param[out] ret Returned value.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_read_unsigned(const struct drgn_object *obj,
					     uint64_t *ret);

/**
 * Get the value of an object encoded with @ref
 * drgn_object_encoding::DRGN_OBJECT_ENCODING_SIGNED or @ref
 * drgn_object_encoding::DRGN_OBJECT_ENCODING_UNSIGNED.
 *
 * If the object is not an integer, an error is returned.
 *
 * @param[in] obj Object to read.
 * @param[out] ret Returned value.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_read_integer(const struct drgn_object *obj,
					    union drgn_value *ret);

/**
 * Get the value of an object encoded with @ref
 * drgn_object_encoding::DRGN_OBJECT_ENCODING_FLOAT.
 *
 * If the object does not have a floating-point type, an error is returned.
 *
 * @param[in] obj Object to read.
 * @param[out] ret Returned value.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_read_float(const struct drgn_object *obj,
					  double *ret);

/**
 * Read the null-terminated string pointed to by a @ref drgn_object.
 *
 * This is only valid for pointers and arrays. The element type is ignored; this
 * operates byte-by-byte.
 *
 * For pointers and flexible arrays, this stops at the first null byte.
 *
 * For complete arrays, this stops at the first null byte or at the end of the
 * array.
 *
 * The returned string is always null-terminated.
 *
 * @param[in] obj Object to read.
 * @param[out] ret Returned string. On success, it must be freed with @c free().
 * On error, it is not modified.
 */
struct drgn_error *drgn_object_read_c_string(const struct drgn_object *obj,
					     char **ret);

/** Flags to control @ref drgn_format_object() output. */
enum drgn_format_object_flags {
	DRGN_FORMAT_OBJECT_DEREFERENCE = 1 << 0,
	DRGN_FORMAT_OBJECT_SYMBOLIZE = 1 << 1,
	DRGN_FORMAT_OBJECT_STRING = 1 << 2,
	DRGN_FORMAT_OBJECT_CHAR = 1 << 3,
	DRGN_FORMAT_OBJECT_TYPE_NAME = 1 << 4,
	DRGN_FORMAT_OBJECT_MEMBER_TYPE_NAMES = 1 << 5,
	DRGN_FORMAT_OBJECT_ELEMENT_TYPE_NAMES = 1 << 6,
	DRGN_FORMAT_OBJECT_MEMBERS_SAME_LINE = 1 << 7,
	DRGN_FORMAT_OBJECT_ELEMENTS_SAME_LINE = 1 << 8,
	DRGN_FORMAT_OBJECT_MEMBER_NAMES = 1 << 9,
	DRGN_FORMAT_OBJECT_ELEMENT_INDICES = 1 << 10,
	DRGN_FORMAT_OBJECT_IMPLICIT_MEMBERS = 1 << 11,
	DRGN_FORMAT_OBJECT_IMPLICIT_ELEMENTS = 1 << 12,
	/** Default "pretty" flags. */
	DRGN_FORMAT_OBJECT_PRETTY = (DRGN_FORMAT_OBJECT_DEREFERENCE |
				     DRGN_FORMAT_OBJECT_SYMBOLIZE |
				     DRGN_FORMAT_OBJECT_STRING |
				     DRGN_FORMAT_OBJECT_TYPE_NAME |
				     DRGN_FORMAT_OBJECT_MEMBER_TYPE_NAMES |
				     DRGN_FORMAT_OBJECT_ELEMENTS_SAME_LINE |
				     DRGN_FORMAT_OBJECT_MEMBER_NAMES |
				     DRGN_FORMAT_OBJECT_IMPLICIT_MEMBERS),
	DRGN_FORMAT_OBJECT_VALID_FLAGS = (1 << 13) - 1,
};

/** Formatting options for @ref drgn_format_object(). */
struct drgn_format_object_options {
	/**
	 * Number of columns to limit output to when the expression can be
	 * reasonably wrapped. The default is @c SIZE_MAX.
	 */
	size_t columns;
	/**
	 * Flags to control formatting. The default is @ref
	 * DRGN_FORMAT_OBJECT_PRETTY.
	 */
	enum drgn_format_object_flags flags;
	/** Base to format integers in (8, 10, or 16). The default is 10. */
	int integer_base;
};

/**
 * Format a @ref drgn_object as a string.
 *
 * This will format the object similarly to an expression in its programming
 * language.
 *
 * @param[in] obj Object to format.
 * @param[in] options Formatting options, or @c NULL to use the default options.
 * @param[out] ret Returned string. On success, it must be freed with @c free().
 * On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_format_object(const struct drgn_object *obj,
		   const struct drgn_format_object_options *options,
		   char **ret);

/** @} */

/**
 * @defgroup ObjectOperators Operators
 *
 * Object operators.
 *
 * Various operators are defined on @ref drgn_object%s. These operators obey the
 * rules of the programming language of the given objects.
 *
 * Operators which return a @ref drgn_object have the same calling convention:
 * the result object is the first argument, which must be initialized and may be
 * the same as one or more of the operands; the result is only modified if the
 * operator succeeds.
 *
 * @{
 */

/**
 * Set a @ref drgn_object to the value of an object explicitly casted to a
 * another type.
 *
 * This uses the programming language's rules for explicit conversions, like the
 * cast operator.
 *
 * @sa drgn_object_implicit_convert(), drgn_object_reinterpret()
 *
 * @param[out] res Object to set. Always set to a value object.
 * @param[in] qualified_type New type.
 * @param[in] obj Object to cast.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_cast(struct drgn_object *res,
				    struct drgn_qualified_type qualified_type,
				    const struct drgn_object *obj);

/**
 * Set a @ref drgn_object to the value of an object implicitly converted to a
 * another type.
 *
 * This uses the programming language's rules for implicit conversions, like
 * when assigning to a variable or passing arguments to a function call.
 *
 * @sa drgn_object_cast(), drgn_object_reinterpret()
 *
 * @param[out] res Object to set. Always set to a value object.
 * @param[in] qualified_type New type.
 * @param[in] obj Object to convert.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_implicit_convert(struct drgn_object *res,
			     struct drgn_qualified_type qualified_type,
			     const struct drgn_object *obj);

/**
 * Set a @ref drgn_object to the representation of an object reinterpreted as
 * another type.
 *
 * This reinterprets the raw memory of the object, so an object can be
 * reinterpreted as any other type.
 *
 * @sa drgn_object_cast(), drgn_object_implicit_convert()
 *
 * @param[out] res Object to set. If @p obj is a value, set to a value. If @p
 * obj is a reference, set to a reference.
 * @param[in] qualified_type New type.
 * @param[in] obj Object to reinterpret.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_object_reinterpret(struct drgn_object *res,
			struct drgn_qualified_type qualified_type,
			const struct drgn_object *obj);

/**
 * @ref drgn_object binary operator.
 *
 * Binary operators apply any language-specific conversions to @p lhs and @p
 * rhs, apply the operator, and store the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p lhs and/or @p rhs.
 * @param[in] lhs Operator left hand side.
 * @param[in] rhs Operator right hand side.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
typedef struct drgn_error *drgn_binary_op(struct drgn_object *res,
					  const struct drgn_object *lhs,
					  const struct drgn_object *rhs);

/**
 * @ref drgn_object unary operator.
 *
 * Unary operators apply any language-specific conversions to @p obj, apply the
 * operator, and store the result in @p res.
 *
 * @param[out] res Operator result. May be the same as @p obj.
 * @param[in] obj Operand.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
typedef struct drgn_error *drgn_unary_op(struct drgn_object *res,
					 const struct drgn_object *obj);

/**
 * Convert a @ref drgn_object to a boolean value.
 *
 * This gets the "truthiness" of an object according to its programming
 * language.
 *
 * @param[in] obj Object.
 * @param[out] ret Returned boolean value.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_bool(const struct drgn_object *obj, bool *ret);

/**
 * Compare the value of two @ref drgn_object%s.
 *
 * This applies any language-specific conversions to @p lhs and @p rhs and
 * compares the resulting values.
 *
 * @param[in] lhs Comparison left hand side.
 * @param[in] rhs Comparison right hand side.
 * @param[out] ret 0 if the operands are equal, < 0 if @p lhs < @p rhs, and > 0
 * if @p lhs > @p rhs.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_cmp(const struct drgn_object *lhs,
				   const struct drgn_object *rhs, int *ret);

/** Add (@c +) two @ref drgn_object%s. */
drgn_binary_op drgn_object_add;
/** Subtract (@c -) a @ref drgn_object from another. */
drgn_binary_op drgn_object_sub;
/** Multiply (@c *) two @ref drgn_object%s. */
drgn_binary_op drgn_object_mul;
/** Divide (@c /) a @ref drgn_object by another. */
drgn_binary_op drgn_object_div;
/** Calculate the modulus (@c %) of two @ref drgn_object%s. */
drgn_binary_op drgn_object_mod;
/** Left shift (@c <<) a @ref drgn_object by another. */
drgn_binary_op drgn_object_lshift;
/** Right shift (@c >>) a @ref drgn_object by another. */
drgn_binary_op drgn_object_rshift;
/** Calculate the bitwise and (@c &) of two @ref drgn_object%s. */
drgn_binary_op drgn_object_and;
/** Calculate the bitwise or (@c |) of two @ref drgn_object%s. */
drgn_binary_op drgn_object_or;
/** Calculate the bitwise exclusive or (@c ^) of two @ref drgn_object%s. */
drgn_binary_op drgn_object_xor;
/** Apply unary plus (@c +) to a @ref drgn_object. */
drgn_unary_op drgn_object_pos;
/** Calculate the arithmetic negation (@c -) of a @ref drgn_object. */
drgn_unary_op drgn_object_neg;
/** Calculate the bitwise negation (@c ~) of a @ref drgn_object. */
drgn_unary_op drgn_object_not;

/**
 * Get the address of (@c &) a @ref drgn_object as an object.
 *
 * This is only possible for reference objects, as value objects don't have an
 * address in the program.
 *
 * @param[out] res Resulting pointer value. May be the same as @p obj.
 * @param[in] obj Reference object.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_object_address_of(struct drgn_object *res,
					  const struct drgn_object *obj);

/**
 * Subscript (@c []) a @ref drgn_object.
 *
 * This is applicable to pointers and arrays.
 *
 * @param[out] res Resulting element. May be the same as @p obj.
 * @param[in] obj Object to subscript.
 * @param[in] index Element index.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_object_subscript(struct drgn_object *res,
					 const struct drgn_object *obj,
					 int64_t index);

/**
 * Deference (@c *) a @ref drgn_object.
 *
 * This is equivalent to @ref drgn_object_subscript with an index of 0.
 *
 * @param[out] res Deferenced object. May be the same as @p obj.
 * @param[in] obj Object to dereference.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
static inline struct drgn_error *
drgn_object_dereference(struct drgn_object *res, const struct drgn_object *obj)
{
	return drgn_object_subscript(res, obj, 0);
}

/**
 * Slice (i.e., get an array from a range of another array) a @ref drgn_object.
 *
 * This is applicable to pointers and arrays.
 *
 * @param[out] res Resulting array. May be the same as @p obj.
 * @param[in] obj Object to slice.
 * @param[in] start Start index (inclusive).
 * @param[in] end End index (exclusive).
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_object_slice(struct drgn_object *res,
				     const struct drgn_object *obj,
				     int64_t start, int64_t end);

/**
 * Get a member of a structure, union, or class @ref drgn_object (@c .).
 *
 * @param[out] res Returned member. May be the same as @p obj.
 * @param[in] obj Object.
 * @param[in] member_name Name of member.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_object_member(struct drgn_object *res,
				      const struct drgn_object *obj,
				      const char *member_name);

/**
 * Get a member of a pointer @ref drgn_object (@c ->).
 *
 * This is applicable to pointers to structures and pointers to unions.
 *
 * @param[out] res Returned member. May be the same as @p obj.
 * @param[in] obj Object.
 * @param[in] member_name Name of member.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_object_member_dereference(struct drgn_object *res,
						  const struct drgn_object *obj,
						  const char *member_name);


/**
 * Get a subobject (member or element) of this object.
 *
 * @param[out] res Returned subobject. May be the same as @p obj.
 * @param[in] obj Object.
 * @param[in] designator One or more member references or array subscripts.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *drgn_object_subobject(struct drgn_object *res,
					 const struct drgn_object *obj,
					 const char *member_designator);


/**
 * Get the containing object of a member @ref drgn_object.
 *
 * This corresponds to the @c container_of() macro commonly used in C.
 *
 * @param[out] res Returned object. May be the same as @p obj.
 * @param[in] obj Pointer to a member.
 * @param[in] qualified_type Type which contains the member.
 * @param[in] member_designator Name of the member in @p qualified_type. This
 * can include one or more member references and zero or more array subscripts.
 * @return @c NULL on success, non-@c NULL on error. @p res is not modified on
 * error.
 */
struct drgn_error *
drgn_object_container_of(struct drgn_object *res, const struct drgn_object *obj,
			 struct drgn_qualified_type qualified_type,
			 const char *member_designator);

/**
 * Get the size of a @ref drgn_object in bytes.
 *
 * @param[in] obj Object.
 * @param[out] ret Returned size.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_object_sizeof(const struct drgn_object *obj,
				      uint64_t *ret);

/** @} */

/** @} */

/**
 * @ingroup LazyObjects
 *
 * Callback to evaluate and/or free a @ref drgn_lazy_object.
 *
 * If @p res is not @c NULL, then this should return the object in @p res and
 * free @p arg if necessary. If this returns an error, it may be called again
 * (so @p arg must remain valid).
 *
 * If @p res is @c NULL, then this should free @p arg if necessary; it must not
 * return an error.
 *
 * @param[out] res Result object (if evaluating) or @c NULL (if freeing). This
 * is already initialized and should not be deinitialized on error.
 * @param[in] arg Callback argument passed to @ref
 * drgn_lazy_object_init_thunk().
 * @return @c NULL on success, non-@c NULL on error.
 */
typedef struct drgn_error *drgn_object_thunk_fn(struct drgn_object *res,
						void *arg);

/**
 * @ingroup LazyObjects
 *
 * Lazily-evaluated object.
 *
 * A lazy object may be in two states: unevaluated, in which case a callback
 * must be called to evaluate the object, or evaluated, in which case the object
 * is cached. To evaluate an object, the callback is called, and the result is
 * cached.
 *
 * This is for internal use only.
 */
union drgn_lazy_object {
	/** Object if it has already been evaluated. */
	struct drgn_object obj;
	/** Thunk if the object has not been evaluated yet. */
	struct {
		/**
		 * Always @c NULL to indicate an unevaluated lazy object.
		 *
		 * This must be at the same offset as @ref drgn_object::type.
		 */
		struct drgn_type *dummy_type;
		/** Program owning this thunk. */
		struct drgn_program *prog;
		/** Callback. */
		drgn_object_thunk_fn *fn;
		/** Argument passed to @ref drgn_lazy_object::thunk::fn. */
		void *arg;
	} thunk;
};

/**
 * @defgroup Types Types
 *
 * Type descriptors.
 *
 * Types in a program are represented by @ref drgn_type.
 *
 * Type descriptors have various fields depending on the kind of type. For each
 * field @c foo, there is a @c drgn_type_kind_has_foo() helper which returns
 * whether the given kind of type has the field @c foo; a @c drgn_type_has_foo()
 * helper which does the same but takes a type; and a @c drgn_type_foo() helper
 * which returns the field. For members, enumerators, parameters, and template
 * parameters, there is also a @c drgn_type_num_foo() helper.
 *
 * @{
 */

/** Primitive types known to drgn. */
enum drgn_primitive_type {
	/* Primitive C types. */
	DRGN_C_TYPE_VOID,
	DRGN_C_TYPE_CHAR,
	DRGN_C_TYPE_SIGNED_CHAR,
	DRGN_C_TYPE_UNSIGNED_CHAR,
	DRGN_C_TYPE_SHORT,
	DRGN_C_TYPE_UNSIGNED_SHORT,
	DRGN_C_TYPE_INT,
	DRGN_C_TYPE_UNSIGNED_INT,
	DRGN_C_TYPE_LONG,
	DRGN_C_TYPE_UNSIGNED_LONG,
	DRGN_C_TYPE_LONG_LONG,
	DRGN_C_TYPE_UNSIGNED_LONG_LONG,
	DRGN_C_TYPE_BOOL,
	DRGN_C_TYPE_FLOAT,
	DRGN_C_TYPE_DOUBLE,
	DRGN_C_TYPE_LONG_DOUBLE,
	DRGN_C_TYPE_SIZE_T,
	DRGN_C_TYPE_PTRDIFF_T,
	DRGN_PRIMITIVE_TYPE_NUM,
	DRGN_NOT_PRIMITIVE_TYPE = DRGN_PRIMITIVE_TYPE_NUM,
	/*
	 * Make sure to update api_reference.rst and type.c when adding anything
	 * here.
	 */
} __attribute__((__packed__));

/** Member of a structure, union, or class type. */
struct drgn_type_member {
	/**
	 * Member as an object.
	 *
	 * Access this with @ref drgn_member_object() or @ref
	 * drgn_member_type().
	 */
	union drgn_lazy_object object;
	/** Member name or @c NULL if it is unnamed. */
	const char *name;
	/**
	 * Offset in bits from the beginning of the type to the beginning of
	 * this member (i.e., for little-endian machines, the least significant
	 * bit, and for big-endian machines, the most significant bit). Members
	 * are usually aligned to at least a byte, so this is usually a multiple
	 * of 8 (but that may not be the case for bit fields).
	 */
	uint64_t bit_offset;
};

/** Value of an enumerated type. */
struct drgn_type_enumerator {
	/** Enumerator name. */
	const char *name;
	union {
		/** Enumerator value if the type is signed. */
		int64_t svalue;
		/** Enumerator value if the type is unsigned. */
		uint64_t uvalue;
	};
};

/** Parameter of a function type. */
struct drgn_type_parameter {
	/**
	 * Parameter type and default argument.
	 *
	 * Access this with @ref drgn_parameter_default_argument() or @ref
	 * drgn_parameter_type().
	 */
	union drgn_lazy_object default_argument;
	/** Parameter name or @c NULL if it is unnamed. */
	const char *name;
};

/** Template parameter of a structure, union, class, or function type. */
struct drgn_type_template_parameter {
	/**
	 * Template parameter type or value.
	 *
	 * Access this with @ref drgn_template_parameter_type() and @ref
	 * drgn_template_parameter_object().
	 */
	union drgn_lazy_object argument;
	/** Template parameter name or @c NULL if it is unnamed. */
	const char *name;
	/** Whether the argument is the default. */
	bool is_default;
};

/**
 * @struct drgn_type
 *
 * Type descriptor.
 *
 * Access it with the getters in @ref Types.
 */
struct drgn_type;

/** Get the kind of a type. */
DRGN_ACCESSOR_LINKAGE
enum drgn_type_kind drgn_type_kind(struct drgn_type *type);

/** Get the primitive type corresponding to a @ref drgn_type. */
DRGN_ACCESSOR_LINKAGE
enum drgn_primitive_type drgn_type_primitive(struct drgn_type *type);

/**
 * Get whether a type is complete (i.e., the type definition is known).
 *
 * This is always @c false for the void type. It may be @c false for structure,
 * union, class, enumerated, and array types, as well as typedef types where the
 * underlying type is one of those. Otherwise, it is always @c true.
 */
DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_complete(struct drgn_type *type);

/**
 * Get whether a kind of type has a name. This is true for integer, boolean,
 * floating-point, and typedef types.
 */
static inline bool drgn_type_kind_has_name(enum drgn_type_kind kind)
{
	return (kind == DRGN_TYPE_INT ||
		kind == DRGN_TYPE_BOOL ||
		kind == DRGN_TYPE_FLOAT ||
		kind == DRGN_TYPE_TYPEDEF);
}
/** Get whether a type has a name. @sa drgn_type_kind_has_name() */
static inline bool drgn_type_has_name(struct drgn_type *type)
{
	return drgn_type_kind_has_name(drgn_type_kind(type));
}
/**
 * Get the name of a type. @ref drgn_type_has_name() must be true for this type.
 */
DRGN_ACCESSOR_LINKAGE
const char *drgn_type_name(struct drgn_type *type);

/**
 * Get whether a kind of type has a size. This is true for integer, boolean,
 * floating-point, structure, union, class, and pointer types.
 */
static inline bool drgn_type_kind_has_size(enum drgn_type_kind kind)
{
	return (kind == DRGN_TYPE_INT ||
		kind == DRGN_TYPE_BOOL ||
		kind == DRGN_TYPE_FLOAT ||
		kind == DRGN_TYPE_STRUCT ||
		kind == DRGN_TYPE_UNION ||
		kind == DRGN_TYPE_CLASS ||
		kind == DRGN_TYPE_POINTER);
}
/** Get whether a type has a size. @sa drgn_type_kind_has_size() */
static inline bool drgn_type_has_size(struct drgn_type *type)
{
	return drgn_type_kind_has_size(drgn_type_kind(type));
}
/**
 * Get the size of a type in bytes. @ref drgn_type_has_size() must be true for
 * this type.
 */
DRGN_ACCESSOR_LINKAGE
uint64_t drgn_type_size(struct drgn_type *type);

/**
 * Get whether a kind of type has a signedness. This is true for integer types.
 */
static inline bool drgn_type_kind_has_is_signed(enum drgn_type_kind kind)
{
	return kind == DRGN_TYPE_INT;
}
/** Get whether a type has a signedness. @sa drgn_type_kind_has_is_signed() */
static inline bool drgn_type_has_is_signed(struct drgn_type *type)
{
	return drgn_type_kind_has_is_signed(drgn_type_kind(type));
}
/**
 * Get the signedness of a type. @ref drgn_type_has_is_signed() must be true for
 * this type.
 */
DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_signed(struct drgn_type *type);

/**
 * Get whether a kind of type has a byte order. This is true for integer,
 * boolean, floating-point, and pointer types.
 */
static inline bool drgn_type_kind_has_little_endian(enum drgn_type_kind kind)
{
	return (kind == DRGN_TYPE_INT ||
		kind == DRGN_TYPE_BOOL ||
		kind == DRGN_TYPE_FLOAT ||
		kind == DRGN_TYPE_POINTER);
}
/**
 * Get whether a type has a byte order. @sa drgn_type_kind_has_little_endian()
 */
static inline bool drgn_type_has_little_endian(struct drgn_type *type)
{
	return drgn_type_kind_has_little_endian(drgn_type_kind(type));
}
/**
 * Get the byte order of a type. @ref drgn_type_has_little_endian() must be true
 * for this type.
 *
 * @return @c true if the type is little-endian, @c false if it is big-endian.
 */
DRGN_ACCESSOR_LINKAGE
bool drgn_type_little_endian(struct drgn_type *type);

/**
 * Get whether a kind of type has a tag. This is true for structure, union,
 * class, and enumerated types.
 */
static inline bool drgn_type_kind_has_tag(enum drgn_type_kind kind)
{
	return (kind == DRGN_TYPE_STRUCT ||
		kind == DRGN_TYPE_UNION ||
		kind == DRGN_TYPE_CLASS ||
		kind == DRGN_TYPE_ENUM);
}
/** Get whether a type has a tag. @sa drgn_type_kind_has_tag() */
static inline bool drgn_type_has_tag(struct drgn_type *type)
{
	return drgn_type_kind_has_tag(drgn_type_kind(type));
}
/**
 * Get the tag of a type. @ref drgn_type_has_tag() must be true for this type.
 */
DRGN_ACCESSOR_LINKAGE
const char *drgn_type_tag(struct drgn_type *type);

/**
 * Get whether a kind of type has members. This is true for structure, union,
 * and class types.
 */
static inline bool drgn_type_kind_has_members(enum drgn_type_kind kind)
{
	return (kind == DRGN_TYPE_STRUCT ||
		kind == DRGN_TYPE_UNION ||
		kind == DRGN_TYPE_CLASS);
}
/** Get whether a type has members. @sa drgn_type_kind_has_members() */
static inline bool drgn_type_has_members(struct drgn_type *type)
{
	return drgn_type_kind_has_members(drgn_type_kind(type));
}
/**
 * Get the members of a type. @ref drgn_type_has_members() must be true for this
 * type.
 */
DRGN_ACCESSOR_LINKAGE
struct drgn_type_member *drgn_type_members(struct drgn_type *type);
/**
 * Get the number of members of a type. @ref drgn_type_has_members() must be
 * true for this type. If the type is incomplete, this is always zero.
 */
DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_members(struct drgn_type *type);

/**
 * Get whether a kind of type has a wrapped type. This is true for enumerated,
 * typedef, pointer, array, and function types.
 */
static inline bool drgn_type_kind_has_type(enum drgn_type_kind kind)
{
	return (kind == DRGN_TYPE_ENUM ||
		kind == DRGN_TYPE_TYPEDEF ||
		kind == DRGN_TYPE_POINTER ||
		kind == DRGN_TYPE_ARRAY ||
		kind == DRGN_TYPE_FUNCTION);
}
/** Get whether a type has a wrapped type. @sa drgn_type_kind_has_type() */
static inline bool drgn_type_has_type(struct drgn_type *type)
{
	return drgn_type_kind_has_type(drgn_type_kind(type));
}
/**
 * Get the type wrapped by this type.
 *
 * For an enumerated type, this is the compatible integer type. It is @c NULL if
 * the enumerated type is incomplete.
 *
 * For a typedef type, this is the aliased type.
 *
 * For a pointer type, this is the referenced type.
 *
 * For an array type, this is the element type.
 *
 * For a function type, this is the return type.
 */
DRGN_ACCESSOR_LINKAGE
struct drgn_qualified_type drgn_type_type(struct drgn_type *type);

/**
 * Get whether a kind of type has enumerators. This is true for enumerated
 * types.
 */
static inline bool drgn_type_kind_has_enumerators(enum drgn_type_kind kind)
{
	return kind == DRGN_TYPE_ENUM;
}
/** Get whether a type has enumerators. @sa drgn_type_kind_has_enumerators() */
static inline bool drgn_type_has_enumerators(struct drgn_type *type)
{
	return drgn_type_kind_has_enumerators(drgn_type_kind(type));
}
/**
 * Get the enumerators of a type. @ref drgn_type_has_enumerators() must be true
 * for this type.
 */
DRGN_ACCESSOR_LINKAGE
struct drgn_type_enumerator *drgn_type_enumerators(struct drgn_type *type);
/**
 * Get the number of enumerators of a type. @ref drgn_type_has_enumerators()
 * must be true for this type. If the type is incomplete, this is always zero.
 */
DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_enumerators(struct drgn_type *type);

/** Get whether a kind of type has a length. This is true for array types. */
static inline bool drgn_type_kind_has_length(enum drgn_type_kind kind)
{
	return kind == DRGN_TYPE_ARRAY;
}
/** Get whether a type has a length. @sa drgn_type_kind_has_length() */
static inline bool drgn_type_has_length(struct drgn_type *type)
{
	return drgn_type_kind_has_length(drgn_type_kind(type));
}
/**
 * Get the length of a type. @ref drgn_type_has_length() must be true for this
 * type. If the type is incomplete, this is always zero.
 */
DRGN_ACCESSOR_LINKAGE
uint64_t drgn_type_length(struct drgn_type *type);

/**
 * Get whether a kind of type has parameters. This is true for function types.
 */
static inline bool drgn_type_kind_has_parameters(enum drgn_type_kind kind)
{
	return kind == DRGN_TYPE_FUNCTION;
}
/** Get whether a type has parameters. @sa drgn_type_kind_has_parameters() */
static inline bool drgn_type_has_parameters(struct drgn_type *type)
{
	return drgn_type_kind_has_parameters(drgn_type_kind(type));
}
/**
 * Get the parameters of a type. @ref drgn_type_has_parameters() must be true
 * for this type.
 */
DRGN_ACCESSOR_LINKAGE
struct drgn_type_parameter *drgn_type_parameters(struct drgn_type *type);
/**
 * Get the number of parameters of a type. @ref drgn_type_has_parameters() must
 * be true for this type.
 */
DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_parameters(struct drgn_type *type);

/**
 * Get whether a kind of type can be variadic. This is true for function types.
 */
static inline bool drgn_type_kind_has_is_variadic(enum drgn_type_kind kind)
{
	return kind == DRGN_TYPE_FUNCTION;
}
/** Get whether a type can be variadic. @sa drgn_type_kind_has_is_variadic() */
static inline bool drgn_type_has_is_variadic(struct drgn_type *type)
{
	return drgn_type_kind_has_is_variadic(drgn_type_kind(type));
}
/**
 * Get whether a type is variadic. @ref drgn_type_has_is_variadic() must be true
 * for this type.
 */
DRGN_ACCESSOR_LINKAGE
bool drgn_type_is_variadic(struct drgn_type *type);

/** Get whether a kind of type can have template parameters. */
static inline bool
drgn_type_kind_has_template_parameters(enum drgn_type_kind kind)
{
	return (kind == DRGN_TYPE_STRUCT ||
		kind == DRGN_TYPE_UNION ||
		kind == DRGN_TYPE_CLASS ||
		kind == DRGN_TYPE_FUNCTION);
}
/** Get whether a type can have template parameters. */
static inline bool drgn_type_has_template_parameters(struct drgn_type *type)
{
	return drgn_type_kind_has_template_parameters(drgn_type_kind(type));
}
/**
 * Get the template parameters of a type. @ref
 * drgn_type_has_template_parameters() must be true for this type.
 */
DRGN_ACCESSOR_LINKAGE
struct drgn_type_template_parameter *
drgn_type_template_parameters(struct drgn_type *type);
/**
 * Get the number of template parameters of a type. @ref
 * drgn_type_has_template_parameters() must be true for this type.
 */
DRGN_ACCESSOR_LINKAGE
size_t drgn_type_num_template_parameters(struct drgn_type *type);

/**
 * Get the object corresponding to a @ref drgn_type_member.
 *
 * @param[in] member Member.
 * @param[out] ret Returned object.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_member_object(struct drgn_type_member *member,
				      const struct drgn_object **ret)
	__attribute__((__nonnull__(1, 2)));

/**
 * Get the type of a @ref drgn_type_member.
 *
 * @param[in] member Member.
 * @param[out] type_ret Returned type.
 * @param[out] bit_field_size_ret If the member is a bit field, returned size of
 * the field in bits. Otherwise, returned as 0. Can be @c NULL if not needed.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_member_type(struct drgn_type_member *member,
				    struct drgn_qualified_type *type_ret,
				    uint64_t *bit_field_size_ret)
	__attribute__((__nonnull__(1, 2)));

/**
 * Get the default argument of a @ref drgn_type_parameter.
 *
 * @param[in] parameter Parameter.
 * @param[out] ret Returned object.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_parameter_default_argument(struct drgn_type_parameter *parameter,
				const struct drgn_object **ret)
	__attribute__((__nonnull__(1, 2)));

/**
 * Get the type of a @ref drgn_type_parameter.
 *
 * @param[in] parameter Parameter.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_parameter_type(struct drgn_type_parameter *parameter,
				       struct drgn_qualified_type *ret)
	__attribute__((__nonnull__(1, 2)));

/**
 * Get the type of a @ref drgn_type_template_parameter.
 *
 * If the template parameter is a non-type template parameter, this is the type
 * of its value.
 *
 * @param[in] parameter Template parameter.
 * @param[out] ret Returned type.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_template_parameter_type(struct drgn_type_template_parameter *parameter,
			     struct drgn_qualified_type *ret)
	__attribute__((__nonnull__(1, 2)));

/**
 * Get the value of a @ref drgn_type_template_parameter.
 *
 * @param[in] parameter Template parameter.
 * @param[out] ret Returned object. If @p parameter is a type template
 * parameter, this is returned as @c NULL.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_template_parameter_object(struct drgn_type_template_parameter *parameter,
			       const struct drgn_object **ret)
	__attribute__((__nonnull__(1, 2)));

/**
 * Get the size of a type in bytes.
 *
 * Unlike @ref drgn_type_size(), this is applicable to any type which has a
 * meaningful size, including typedefs and arrays. Void, function, and
 * incomplete types do not have a size; an error is returned for those types.
 *
 * @param[in] type Type.
 * @param[out] ret Returned size.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_type_sizeof(struct drgn_type *type, uint64_t *ret);

/**
 * Get the alignment requirement of a type.
 *
 * This corresponds to @c _Alignof() in C.
 *
 * @param[in] type Type.
 * @param[out] ret Returned alignment.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_type_alignof(struct drgn_qualified_type qualified_type,
				     uint64_t *ret);

/**
 * Get the offset in bytes of a member from the start of a structure, union, or
 * class type.
 *
 * This corresponds to @c offsetof() in C.
 *
 * @param[in] type Type which contains the member.
 * @param[in] member_designator Name of the member in @p type. This can include
 * one or more member references and zero or more array subscripts.
 */
struct drgn_error *drgn_type_offsetof(struct drgn_type *type,
				      const char *member_designator,
				      uint64_t *ret);

/**
 * Like @ref drgn_type_find_member(), but takes the length of @p member_name.
 */
struct drgn_error *
drgn_type_find_member_len(struct drgn_type *type, const char *member_name,
			  size_t member_name_len,
			  struct drgn_type_member **member_ret,
			  uint64_t *bit_offset_ret);

/**
 * Find a member in a @ref drgn_type by name.
 *
 * If the type has any unnamed members, this also matches members of those
 * unnamed members, recursively.
 *
 * @param[in] type Structure, union, or class type.
 * @param[in] member_name Name of member.
 * @param[out] member_ret Returned member.
 * @param[out] bit_offset_ret Returned offset in bits from the beginning of @p
 * type to the beginning of the member. This can be different from @ref
 * drgn_type_member::bit_offset if the returned member was found in an unnamed
 * member of @p type.
 */
static inline struct drgn_error *
drgn_type_find_member(struct drgn_type *type, const char *member_name,
		      struct drgn_type_member **member_ret,
		      uint64_t *bit_offset_ret)
{
	return drgn_type_find_member_len(type, member_name, strlen(member_name),
					 member_ret, bit_offset_ret);
}

/** Like @ref drgn_type_has_member(), but takes the length of @p member_name. */
struct drgn_error *drgn_type_has_member_len(struct drgn_type *type,
					    const char *member_name,
					    size_t member_name_len, bool *ret);

/**
 * Return whether a @ref drgn_type has a member with the given name.
 *
 * @param[in] type Structure, union, or class type.
 * @param[in] member_name Name of member.
 */
static inline struct drgn_error *drgn_type_has_member(struct drgn_type *type,
						      const char *member_name,
						      bool *ret)
{
	return drgn_type_has_member_len(type, member_name, strlen(member_name),
					ret);
}

/**
 * Format the name of a type as a string.
 *
 * This will format the name of the type as it would be referred to in its
 * programming language.
 *
 * @param[in] qualified_type Type to format.
 * @param[out] ret Returned string. On success, it must be freed with @c free().
 * On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_format_type_name(struct drgn_qualified_type qualified_type, char **ret);

/**
 * Format the definition of a type as a string.
 *
 * This will format the type as it would be defined in its programming language.
 *
 * @param[in] qualified_type Type to format.
 * @param[out] ret Returned string. On success, it must be freed with @c free().
 * On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_format_type(struct drgn_qualified_type qualified_type,
				    char **ret);


/**
 * Format a variable declaration with the given type and name.
 *
 * This will format the variable as it would be declared in its programming
 * language.
 *
 * @param[in] qualified_type Variable type.
 * @param[in] name Variable name.
 * @param[out] ret Returned string. On success, it must be freed with @c free().
 * On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_format_variable_declaration(struct drgn_qualified_type qualified_type,
				 const char *name, char **ret)
	__attribute__((__nonnull__(2, 3)));

/** @} */

/**
 * @defgroup Symbols Symbols
 *
 * Symbol table entries.
 *
 * @sa drgn_program_find_symbol_by_address()
 *
 * @{
 */

/** Symbol linkage behavior and visibility. */
enum drgn_symbol_binding {
	DRGN_SYMBOL_BINDING_UNKNOWN,
	/*
	 * These values match the ELF STB_* definitions (offset by 1). This is
	 * an implementation detail; future values may not correspond 1:1 with
	 * ELF definitions.
	 */
	DRGN_SYMBOL_BINDING_LOCAL,
	DRGN_SYMBOL_BINDING_GLOBAL,
	DRGN_SYMBOL_BINDING_WEAK,
	DRGN_SYMBOL_BINDING_UNIQUE = 11, /* STB_GNU_UNIQUE + 1 */
} __attribute__((__packed__));

/** Kind of entity represented by a symbol. */
enum drgn_symbol_kind {
	/*
	 * Like enum drgn_symbol_binding, these values match the ELF STT_*
	 * definitions, but this will not necessarily be true for future values.
	 */
	DRGN_SYMBOL_KIND_UNKNOWN,
	DRGN_SYMBOL_KIND_OBJECT,
	DRGN_SYMBOL_KIND_FUNC,
	DRGN_SYMBOL_KIND_SECTION,
	DRGN_SYMBOL_KIND_FILE,
	DRGN_SYMBOL_KIND_COMMON,
	DRGN_SYMBOL_KIND_TLS,
	DRGN_SYMBOL_KIND_IFUNC = 10, /* STT_GNU_IFUNC */
} __attribute__((__packed__));

/** Describes the lifetime of an object provided to drgn */
enum drgn_lifetime {
	/**
	 * DRGN_LIFETIME_STATIC: the object is guaranteed to outlive the
	 * drgn_program itself. drgn will not free or copy the object.
	 */
	DRGN_LIFETIME_STATIC,
	/**
	 * DRGN_LIFETIME_EXTERNAL: the object is externally managed. It will
	 * live as long as the object it is associated with, but may be freed
	 * after. drgn will never free the object. If drgn must copy a data
	 * structure, the object will be duplicated, and drgn will own the new
	 * object.
	 */
	DRGN_LIFETIME_EXTERNAL,
	/**
	 * DRGN_LIFETIME_OWNED: the object lifetime is managed by drgn. It
	 * should be freed when the containing object is freed. If the
	 * containing object is copied, it must also be copied.
	 */
	DRGN_LIFETIME_OWNED,
} __attribute__((__packed__));

/**
 * Create a new @ref drgn_symbol with the given values
 *
 * All parameters should be self-explanatory, except for @a name_lifetime.
 * Clients can use this to describe how drgn should treat the string @a name.
 * Strings with lifetime @c STATIC will never be copied or freed. Strings with
 * lifetime @c OWNED will always be copied or and freed with the symbol. Strings
 * with lifetime EXTERNAL will not be freed, but if the Symbol is copied, they
 * will be copied.
 */
struct drgn_error *
drgn_symbol_create(const char *name, uint64_t address, uint64_t size,
		   enum drgn_symbol_binding binding, enum drgn_symbol_kind kind,
		   enum drgn_lifetime name_lifetime, struct drgn_symbol **ret);

/** Destroy a @ref drgn_symbol. */
void drgn_symbol_destroy(struct drgn_symbol *sym);

/**
 * Destroy each @ref drgn_symbol in @syms, and free the array.
 *
 * This will ignore any @c NULL entry in the array, allowing you to take
 * ownership of any symbol from the array prior to freeing the rest. For each
 * symbol you take ownership of, you must free it with @ref
 * drgn_symbol_destroy().
 */
void drgn_symbols_destroy(struct drgn_symbol **syms, size_t count);

/**
 * Get the name of a @ref drgn_symbol.
 *
 * The returned string is valid until @p sym is destroyed. It should not be
 * freed.
 */
const char *drgn_symbol_name(struct drgn_symbol *sym);

/** Get the start address of a @ref drgn_symbol. */
uint64_t drgn_symbol_address(struct drgn_symbol *sym);

/** Get the size in bytes of a @ref drgn_symbol. */
uint64_t drgn_symbol_size(struct drgn_symbol *sym);

/** Get the binding of a @ref drgn_symbol. */
enum drgn_symbol_binding drgn_symbol_binding(struct drgn_symbol *sym);

/** Get the kind of a @ref drgn_symbol. */
enum drgn_symbol_kind drgn_symbol_kind(struct drgn_symbol *sym);

/** Return whether two symbols are identical. */
bool drgn_symbol_eq(struct drgn_symbol *a, struct drgn_symbol *b);

/** @} */

/**
 * @defgroup StackTraces Stack traces
 *
 * Call stacks and stack frames.
 *
 * @{
 */

struct drgn_stack_trace; // IWYU pragma: export

/** Destroy a @ref drgn_stack_trace. */
void drgn_stack_trace_destroy(struct drgn_stack_trace *trace);

/** Get the @ref drgn_program that a @ref drgn_stack_trace came from. */
struct drgn_program *drgn_stack_trace_program(struct drgn_stack_trace *trace);

/** Get the number of stack frames in a stack trace. */
size_t drgn_stack_trace_num_frames(struct drgn_stack_trace *trace);

/**
 * Format a stack trace as a string.
 *
 * @param[out] ret Returned string. On success, it must be freed with @c free().
 * On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_format_stack_trace(struct drgn_stack_trace *trace,
					   char **ret);

/** Return whether a stack frame was interrupted (e.g., by a signal). */
bool drgn_stack_frame_interrupted(struct drgn_stack_trace *trace, size_t frame);

/**
 * Format a stack frame as a string.
 *
 * @param[out] ret Returned string. On success, it must be freed with @c free().
 * On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_format_stack_frame(struct drgn_stack_trace *trace,
					   size_t frame, char **ret);

/**
 * Get the best available name for a stack frame.
 *
 * @param[out] ret Returned name. On success, it must be freed with @c free().
 * On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_stack_frame_name(struct drgn_stack_trace *trace,
					 size_t frame, char **ret);

/**
 * Get the name of the function at a stack frame.
 *
 * @return Function name. This is valid until the stack trace is destroyed; it
 * should not be freed. @c NULL if the name could not be determined.
 */
const char *drgn_stack_frame_function_name(struct drgn_stack_trace *trace,
					   size_t frame);

/** Return whether a stack frame is for an inlined call. */
bool drgn_stack_frame_is_inline(struct drgn_stack_trace *trace, size_t frame);

/**
 * Get the source code location of a stack frame.
 *
 * @param[out] line_ret Returned line number. Returned as 0 if unknown. May be
 * @c NULL if not needed.
 * @param[out] column_ret Returned column number. Returned as 0 if unknown. May
 * be @c NULL if not needed.
 * @return Filename. This is valid until the stack trace is destroyed; it should
 * not be freed. @c NULL if the location could not be determined (in which case
 * `*line_ret` and `*column_ret` are undefined).
 */
const char *drgn_stack_frame_source(struct drgn_stack_trace *trace,
				    size_t frame, int *line_ret,
				    int *column_ret);

/**
 * Get the program counter at a stack frame.
 *
 * @param[out] ret Returned program counter.
 * @return @c true if the program counter is known, @c false if it is not.
 */
bool drgn_stack_frame_pc(struct drgn_stack_trace *trace, size_t frame,
			 uint64_t *ret);

/**
 * Get the stack pointer at a stack frame.
 *
 * @param[out] ret Returned stack pointer.
 * @return @c true if the stack pointer is known, @c false if it is not.
 */
bool drgn_stack_frame_sp(struct drgn_stack_trace *trace, size_t frame,
			 uint64_t *ret);

/**
 * Get the function symbol at a stack frame.
 *
 * @param[out] ret Returned symbol. On success, it should be freed with @ref
 * drgn_symbol_destroy(). On error, its contents are undefined.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_stack_frame_symbol(struct drgn_stack_trace *trace,
					   size_t frame,
					   struct drgn_symbol **ret);

/**
 * Get the names of local objects in the scope of this frame.
 *
 * The array of names must be freed with @ref drgn_stack_frame_locals_destroy().
 *
 * @param[out] names_ret Returned array of names. On success, must be freed with
 * @ref drgn_stack_frame_locals_destroy().
 * @param[out] count_ret Returned number of names in @p names_ret.
 * @return @c NULL on success, non-@c NULL on error
 */
struct drgn_error *
drgn_stack_frame_locals(struct drgn_stack_trace *trace, size_t frame,
			const char ***names_ret, size_t *count_ret);

/**
 * Free an array of names returned by @ref drgn_stack_frame_locals().
 *
 * The individual names from this array are invalid once this function is
 * called. Any string which will be used later should be copied.
 *
 * @param names Array of names returned by @ref drgn_stack_frame_locals().
 * @param count Count returned by @ref drgn_stack_frame_locals().
 */
void drgn_stack_frame_locals_destroy(const char **names, size_t count);

/**
 * Find an object in the scope of a stack frame.
 *
 * @param[in] name Object name.
 * @param[out] ret Returned object. This must have already been initialized with
 * @ref drgn_object_init().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_stack_frame_find_object(struct drgn_stack_trace *trace, size_t frame,
			     const char *name, struct drgn_object *ret);

/**
 * Get the value of a register in a stack frame.
 *
 * @param[in] reg Register to get. Must be from the platform of the program that
 * the trace was taken from.
 * @param[out] ret Returned register value.
 * @return @c true on success, @c false if the value is not known or the
 * register is too large to return in a @c uint64_t.
 */
bool drgn_stack_frame_register(struct drgn_stack_trace *trace, size_t frame,
			       const struct drgn_register *reg, uint64_t *ret);

/**
 * Get a stack trace for the thread with the given thread ID.
 *
 * @param[out] ret Returned stack trace. On success, it should be freed with
 * @ref drgn_stack_trace_destroy(). On error, its contents are undefined.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_stack_trace(struct drgn_program *prog,
					    uint32_t tid,
					    struct drgn_stack_trace **ret);

/**
 * Get a stack trace with the supplied list of program counters.
 *
 * @param[out] ret Returned stack trace. On success, it should be freed with
 * @ref drgn_stack_trace_destroy(). On error, its contents are undefined.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_program_stack_trace_from_pcs(struct drgn_program *prog,
				  const uint64_t *pcs,
				  size_t pcs_size,
				  struct drgn_stack_trace **ret);

/**
 * Get a stack trace for the thread represented by @p obj.
 *
 * @sa drgn_program_stack_trace().
 */
struct drgn_error *drgn_object_stack_trace(const struct drgn_object *obj,
					   struct drgn_stack_trace **ret);

/** @} */

/**
 * @defgroup Threads Threads
 *
 * Threads in a program.
 *
 * @{
 */

/**
 * @struct drgn_thread
 *
 * A thread in a program.
 */
struct drgn_thread;

/**
 * Create a copy of a @ref drgn_thread.
 *
 * @param[in] thread Thread to copy.
 * @param[out] ret Returned copy. On success, must be destroyed with @ref
 * drgn_thread_destroy().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_thread_dup(const struct drgn_thread *thread,
				   struct drgn_thread **ret);

/** Free a @ref drgn_thread. */
void drgn_thread_destroy(struct drgn_thread *thread);

/**
 * @struct drgn_thread_iterator
 *
 * An iterator over all the threads in a program.
 */
struct drgn_thread_iterator;

/**
 * Get an iterator over all of the threads in the program.
 *
 * @param[out] ret Returned iterator, which can be advanced with @ref
 * drgn_thread_iterator_next, and must be destroyed with @ref
 * drgn_thread_iterator_destroy.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *
drgn_thread_iterator_create(struct drgn_program *prog,
			    struct drgn_thread_iterator **ret);

/** Free a @ref drgn_thread_iterator. */
void drgn_thread_iterator_destroy(struct drgn_thread_iterator *it);

/**
 * Get the next thread from a @ref drgn_thread_iterator.
 *
 * @param[out] ret Borrowed thread handle, or @c NULL if there are no more
 * threads. This is valid until until the next call to @ref
 * drgn_thread_iterator_next() with the same @p it, or until @p it is destroyed.
 * It may be copied with @ref drgn_thread_dup() if it is needed for longer. This
 * must NOT be destroyed with @ref drgn_thread_destroy().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_thread_iterator_next(struct drgn_thread_iterator *it,
					     struct drgn_thread **ret);

/**
 * Get the thread with the given thread ID.
 *
 * @param[in] tid Thread ID.
 * @param[out] ret New thread handle, or @c NULL if not found. On success, must
 * be destroyed with @ref drgn_thread_destroy().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_find_thread(struct drgn_program *prog,
					    uint32_t tid,
					    struct drgn_thread **ret);

/**
 * Get the main program thread.
 *
 * @param[out] ret Borrowed thread handle. This is valid for the lifetime of @p
 * prog. This must NOT be destroyed with @ref drgn_thread_destroy().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_main_thread(struct drgn_program *prog,
					    struct drgn_thread **ret);

/**
 * Get the thread that caused the program to crash.
 *
 * @param[out] ret Borrowed thread handle. This is valid for the lifetime of @p
 * prog. This must NOT be destroyed with @ref drgn_thread_destroy().
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_program_crashed_thread(struct drgn_program *prog,
					       struct drgn_thread **ret);

/**
 * Get the object for the given thread. This is currently only defined for the
 * Linux kernel.
 *
 * @param[out] ret Returned object. This must not be modified and is valid for
 * the lifetime of @p thread. It can be copied with @ref drgn_object_copy() if
 * it is needed for longer.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_thread_object(struct drgn_thread *thread,
				      const struct drgn_object **ret);

/**
 * Get a stack trace for the thread represented by @p thread.
 *
 * @sa drgn_program_stack_trace().
 */
struct drgn_error *drgn_thread_stack_trace(struct drgn_thread *thread,
					   struct drgn_stack_trace **ret);

/**
 * Get name for the thread represented by @p thread.
 *
 * @param[out] ret Returned thread name, or @c NULL if not found. On success, it
 * should be freed with free(). On error, it is not modified.
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_thread_name(struct drgn_thread *thread, char **ret);

/** @} */

#endif /* DRGN_H */
