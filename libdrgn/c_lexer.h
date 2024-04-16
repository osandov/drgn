// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef DRGN_C_LEXER_H
#define DRGN_C_LEXER_H

#include <stdbool.h>

#include "lexer.h"

// These definitions are only exposed for testing purposes.

// This obviously incomplete since we only handle the tokens we care about.
enum {
	C_TOKEN_EOF = -1,
	MIN_KEYWORD_TOKEN,
	MIN_SPECIFIER_TOKEN = MIN_KEYWORD_TOKEN,
	C_TOKEN_VOID = MIN_SPECIFIER_TOKEN,
	C_TOKEN_CHAR,
	C_TOKEN_SHORT,
	C_TOKEN_INT,
	C_TOKEN_LONG,
	C_TOKEN_SIGNED,
	C_TOKEN_UNSIGNED,
	C_TOKEN_BOOL,
	C_TOKEN_FLOAT,
	C_TOKEN_DOUBLE,
	C_TOKEN_COMPLEX,
	MAX_SPECIFIER_TOKEN = C_TOKEN_COMPLEX,
	MIN_QUALIFIER_TOKEN,
	C_TOKEN_CONST = MIN_QUALIFIER_TOKEN,
	C_TOKEN_RESTRICT,
	C_TOKEN_VOLATILE,
	C_TOKEN_ATOMIC,
	MAX_QUALIFIER_TOKEN = C_TOKEN_ATOMIC,
	C_TOKEN_STRUCT,
	C_TOKEN_UNION,
	C_TOKEN_CLASS,
	C_TOKEN_ENUM,
	MAX_KEYWORD_TOKEN = C_TOKEN_ENUM,
	C_TOKEN_LPAREN,
	C_TOKEN_RPAREN,
	C_TOKEN_LBRACKET,
	C_TOKEN_RBRACKET,
	C_TOKEN_ASTERISK,
	C_TOKEN_DOT,
	C_TOKEN_NUMBER,
	C_TOKEN_IDENTIFIER,
	C_TOKEN_TEMPLATE_ARGUMENTS,
	C_TOKEN_COLON,
};

struct drgn_c_family_lexer {
	struct drgn_lexer lexer;
	bool cpp;
};

struct drgn_error *drgn_c_family_lexer_func(struct drgn_lexer *lexer,
					    struct drgn_token *token);

#endif /* DRGN_C_LEXER_H */
