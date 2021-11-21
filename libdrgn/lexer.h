// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file
 *
 * Lexer interface.
 *
 * See @ref Lexer.
 */

#ifndef DRGN_LEXER_H
#define DRGN_LEXER_H

#include <stddef.h>

#include "vector.h"

/**
 * @ingroup Internals
 *
 * @defgroup Lexer Lexer
 *
 * Lexical analysis.
 *
 * This is a convenient interface for lexical analysis. @ref drgn_lexer provides
 * the abstraction of a stack of tokens (@ref drgn_token) on top of a raw @ref
 * drgn_lexer_func.
 *
 * @{
 */

struct drgn_lexer;
struct drgn_token;

/**
 * Lexer function.
 *
 * A lexer function does the work of lexing the next token in a string. It
 * should initialize the passed in token and advance @ref drgn_lexer::p.
 */
typedef struct drgn_error *(*drgn_lexer_func)(struct drgn_lexer *,
					      struct drgn_token *);

/** Lexical token. */
struct drgn_token {
	/** Kind of token as defined by the lexer function. */
	int kind;
	/**
	 * String value of the token (i.e., the lexeme).
	 *
	 * This points to the contents of the original string, so it isn't
	 * null-terminated.
	 */
	const char *value;
	/** Length of the token value. */
	size_t len;
};

DEFINE_VECTOR_TYPE(drgn_token_vector, struct drgn_token)

/**
 * Lexer instance.
 *
 * A lexer comprises a lexer function, a position, and a stack of tokens. Tokens
 * can be pushed and popped onto the stack. When the stack is empty, a pop calls
 * the lexer function instead.
 */
struct drgn_lexer {
	/** Lexer function. */
	drgn_lexer_func func;
	/** Current position in the string. */
	const char *p;
	/** Stack of tokens. */
	struct drgn_token_vector stack;
};

/**
 * Initialize a @ref drgn_lexer from a lexer function and a string.
 *
 * @param[in] lexer Lexer to initialize.
 * @param[in] func Lexer function.
 * @param[in] str String to lex.
 */
void drgn_lexer_init(struct drgn_lexer *lexer, drgn_lexer_func func,
		     const char *str);

/**
 * Free memory allocated by a @ref drgn_lexer.
 *
 * @param[in] lexer Lexer to deinitialize.
 */
void drgn_lexer_deinit(struct drgn_lexer *lexer);

/**
 * Return the next token from a @ref drgn_lexer.
 *
 * If there are tokens on the stack, this pops and returns the top token.
 * Otherwise, this calls the lexer function to get the next token.
 *
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_lexer_pop(struct drgn_lexer *lexer,
				  struct drgn_token *token);

/**
 * Push a token onto the stack of a @ref drgn_lexer.
 *
 * This token must have been returned by @ref drgn_lexer_pop().
 *
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_lexer_push(struct drgn_lexer *lexer,
				   const struct drgn_token *token);

/**
 * Return the next token from a @ref drgn_lexer and leave it on top of the
 * stack.
 *
 * This is equivalent to a call to @ref drgn_lexer_pop() immediately followed by
 * a call to @ref drgn_lexer_push().
 *
 * @return @c NULL on success, non-@c NULL on error.
 */
struct drgn_error *drgn_lexer_peek(struct drgn_lexer *lexer,
				   struct drgn_token *token);

/* Exported only for testing. */
struct drgn_error *drgn_lexer_c(struct drgn_lexer *lexer,
				struct drgn_token *token);

/** @} */

#endif /* DRGN_LEXER_H */
