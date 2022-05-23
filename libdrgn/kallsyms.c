// Copyright (c) 2022 Oracle and/or its affiliates
// SPDX-License-Identifier: GPL-3.0-or-later

#include <ctype.h>
#include <stddef.h>

#include "kallsyms.h"
#include "program.h"
#include "drgn.h"

/**
 * This struct contains the tables necessary to reconstruct kallsyms names.
 *
 * vmlinux (core kernel) kallsyms names are compressed using table compression.
 * There is some description of it in the kernel's "scripts/kallsyms.c", but
 * this is a brief overview that should make the code below comprehensible.
 *
 * Table compression uses the remaining 128 characters not defined by ASCII and
 * maps them to common substrings (e.g. the prefix "write_"). Each name is
 * represented as a sequence of bytes which refers to strings in this table.
 * The two arrays below comprise this table:
 *
 *   - token_table: this is one long string with all of the tokens concatenated
 *     together, e.g. "a\0b\0c\0...z\0write_\0read_\0..."
 *   - token_index: this is a 256-entry long array containing the index into
 *     token_table where you'll find that token's string.
 *
 * To decode a string, for each byte you simply index into token_index, then use
 * that to index into token_table, and copy that string into your buffer.
 *
 * The actual kallsyms symbol names are concatenated into a buffer called
 * "names". The first byte in a name is the length (in tokens, not decoded
 * bytes) of the symbol name. The remaining "length" bytes are decoded via the
 * table as described above. The first decoded byte is a character representing
 * what type of symbol this is (e.g. text, data structure, etc).
 */
struct kallsyms_reader {
	uint32_t num_syms;
	uint8_t *names;
	char *token_table;
	uint16_t *token_index;
};

/**
 * Copy the kallsyms names tables from the program into host memory.
 * @param prog Program to read from
 * @param kr kallsyms_reader to populate
 * @param vi vmcoreinfo for the program
 */
static struct drgn_error *
kallsyms_copy_tables(struct drgn_program *prog, struct kallsyms_reader *kr,
		     struct vmcoreinfo *vi)
{
	struct drgn_error *err;
	const size_t token_index_size = (UINT8_MAX + 1) * sizeof(uint16_t);
	uint64_t last_token;
	size_t token_table_size, names_idx;
	char data;
	uint8_t len;
	bool bswap;

	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;

	/* Read num_syms from vmcore */
	err = drgn_program_read_u32(prog,
				    vi->kallsyms_num_syms,
				    false, &kr->num_syms);
	if (err)
		return err;
	if (bswap)
		kr->num_syms = bswap_32(kr->num_syms);

	/* Read the constant-sized token_index table (256 entries) */
	kr->token_index = malloc(token_index_size);
	if (!kr->token_index)
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, kr->token_index,
				       vi->kallsyms_token_index,
				       token_index_size, false);
	if (err)
		return err;
	if (bswap) {
		for (size_t i = 0; i < kr->num_syms; i++) {
			kr->token_index[i] = bswap_16(kr->token_index[i]);
		}
	}

	/*
	 * Find the end of the last token, so we get the overall length of
	 * token_table. Then copy the token_table into host memory.
	 */
	last_token = vi->kallsyms_token_table + kr->token_index[UINT8_MAX];
	do {
		err = drgn_program_read_u8(prog, last_token, false,
					   (uint8_t *)&data);
		if (err)
			return err;

		last_token++;
	} while (data);
	token_table_size = last_token - vi->kallsyms_token_table + 1;
	kr->token_table = malloc(token_table_size);
	if (!kr->token_table)
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, kr->token_table,
				       vi->kallsyms_token_table,
				       token_table_size, false);
	if (err)
		return err;

	/* Now find the end of the names array by skipping through it, then copy
	 * that into host memory. */
	names_idx = 0;
	for (size_t i = 0; i < kr->num_syms; i++) {
		err = drgn_program_read_u8(prog,
					   vi->kallsyms_names + names_idx,
					   false, &len);
		if (err)
			return err;
		names_idx += len + 1;
	}
	kr->names = malloc(names_idx);
	if (!kr->names)
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, kr->names,
				       vi->kallsyms_names,
				       names_idx, false);
	if (err)
		return err;

	return NULL;
}

/**
 * Write the symbol starting at @a offset into @a result.
 * @param kr Registry containing kallsyms data
 * @param offset Starting index within "names" array for this symbol
 * @param result Buffer to write output symbol to
 * @param maxlen Size of output buffer, to avoid overruns
 * @param[out] kind_ret Where to write the symbol kind data
 * @param[out] bytes_ret How many bytes were output (incl. NUL)
 * @returns The offset of the next symbol
 */
static unsigned int
kallsyms_expand_symbol(struct kallsyms_reader *kr, unsigned int offset,
		       char *result, size_t maxlen, char *kind_ret,
		       size_t *bytes_ret)
{
	uint8_t *data = &kr->names[offset];
	unsigned int len = *data;
	bool skipped_first = false;
	size_t bytes = 0;

	offset += len + 1;
	data += 1;
	while (len) {
		char *token_ptr = &kr->token_table[kr->token_index[*data]];
		while (*token_ptr) {
			if (skipped_first) {
				if (maxlen <= 1)
					goto tail;
				*result = *token_ptr;
				result++;
				maxlen--;
				bytes++;
			} else {
				if (kind_ret)
					*kind_ret = *token_ptr;
				skipped_first = true;
			}
			token_ptr++;
		}

		data++;
		len--;
	}

tail:
	*result = '\0';
	bytes++;
	*bytes_ret = bytes;
	return offset;
}

/** Decode all symbol names from @a kr and place them into @a reg */
static struct drgn_error *
kallsyms_create_symbol_array(struct kallsyms_registry *reg, struct kallsyms_reader *kr)
{
	uint8_t token_lengths[UINT8_MAX+1];

	/* Compute the length of each token */
	for (int i = 0; i <= UINT8_MAX; i++) {
		token_lengths[i] = strlen(&kr->token_table[kr->token_index[i]]);
	}

	/* Now compute the length of all symbols together */
	size_t names_idx = 0;
	size_t length = 0;
	for (int i = 0; i < kr->num_syms; i++) {
		uint8_t num_tokens = kr->names[names_idx];
		for (int j = names_idx + 1; j < names_idx + num_tokens + 1; j++)
			length += token_lengths[kr->names[j]];
		length++; /* nul terminator */
		names_idx += num_tokens + 1;
	}

	reg->symbol_buffer = malloc(length);
	reg->symbols = calloc(kr->num_syms, sizeof(*reg->symbols));
	reg->types = malloc(kr->num_syms);
	reg->num_syms = kr->num_syms;
	if (!reg->symbol_buffer || !reg->symbols || !reg->types)
		return &drgn_enomem;

	names_idx = 0;
	size_t symbols_idx = 0;
	for (int i = 0; i < kr->num_syms; i++) {
		size_t bytes = 0;
		names_idx = kallsyms_expand_symbol(kr, names_idx,
						   reg->symbol_buffer + symbols_idx,
						   length - symbols_idx, &reg->types[i],
						   &bytes);
		reg->symbols[i] = &reg->symbol_buffer[symbols_idx];
		symbols_idx += bytes;
	}
	return NULL;
}

/** Copies and decodes symbol names from the program. */
static struct drgn_error *
kallsyms_load_names(struct kallsyms_registry *reg, struct vmcoreinfo *vi)
{
	struct drgn_error *err;
	struct kallsyms_reader reader = {0};

	err = kallsyms_copy_tables(reg->prog, &reader, vi);
	if (err)
		goto out;

	err = kallsyms_create_symbol_array(reg, &reader);
out:
	free(reader.names);
	free(reader.token_index);
	free(reader.token_table);
	return err;
}

/** Lookup @a name in the registry @a kr, and return the index of the symbol */
int drgn_kallsyms_lookup(struct kallsyms_registry *kr, const char *name)
{
	for (int i = 0; i < kr->num_syms; i++)
		if (strcmp(kr->symbols[i], name) == 0)
			return i;
	return -1;
}

/** Return the address of symbol at @a index*/
static uint64_t
kallsyms_address(struct kallsyms_registry *kr, unsigned int index)
{
	return kr->addresses[index];
}

static void drgn_symbol_from_kallsyms(struct kallsyms_registry *kr, int index,
				      struct drgn_symbol *ret)
{
	char kind = kr->types[index];
	char kind_lower = tolower(kind);
	ret->name = kr->symbols[index];
	ret->address = kallsyms_address(kr, index);
	if (index < kr->num_syms)
		ret->size = kallsyms_address(kr, index + 1) - ret->address;
	else
		ret->size = 0;

	ret->binding = DRGN_SYMBOL_BINDING_GLOBAL;
	if (kind == 'u')
		ret->binding = DRGN_SYMBOL_BINDING_UNIQUE;
	else if (kind_lower == 'v' || kind_lower == 'w')
		ret->binding = DRGN_SYMBOL_BINDING_WEAK;
	else if (isupper(kind))
		ret->binding = DRGN_SYMBOL_BINDING_GLOBAL;
	else
		/* If lowercase, the symbol is usually local, but it's
		 * not guaranteed. Use unknown for safety here. */
		ret->binding = DRGN_SYMBOL_BINDING_UNKNOWN;

	switch (kind_lower) {
	case 'b': /* bss */
	case 'c': /* uninitialized data */
	case 'd': /* initialized data */
	case 'g': /* initialized data (small objects) */
	case 'r': /* read-only data */
		ret->kind = DRGN_SYMBOL_KIND_OBJECT;
		break;
	case 't': /* text */
		ret->kind = DRGN_SYMBOL_KIND_FUNC;
		break;
	default:
		ret->kind = DRGN_SYMBOL_KIND_UNKNOWN;
	}
}

DEFINE_VECTOR_FUNCTIONS(symbolp_vector);

static int kallsyms_addr_compar(const void *key_void, const void *memb_void)
{
	const uint64_t *key = key_void;
	const uint64_t *memb = memb_void;

	/* We are guaranteed that: (min <= key <= max), so we can fearlessly
	 * index one beyond memb, so long as we've checked that key > memb.
	 */
	if (*key == *memb)
		return 0;
	else if (*key < *memb)
		return -1;
	else if (*key < memb[1])
		return 0;
	else
		return 1;
}

struct symbol_result_builder {
	struct kallsyms_registry *kr;
	struct symbolp_vector vec;
	struct drgn_error *err;
	enum drgn_find_symbol_flags flags;
	union drgn_find_symbol_result *ret;
};

static inline void
symbol_result_builder_init(struct symbol_result_builder *builder,
			   struct kallsyms_registry *kr,
			   enum drgn_find_symbol_flags flags,
			   union drgn_find_symbol_result *ret)
{
	builder->kr = kr;
	builder->err = NULL;
	builder->flags = flags;
	builder->ret = ret;
	if (flags & DRGN_FIND_SYM_ONE) {
		builder->ret->symbol = NULL;
	} else {
		builder->ret->symbol_arr = NULL;
		builder->ret->count = 0;
		symbolp_vector_init(&builder->vec);
	}
}

static inline bool
symbol_result_builder_add(struct symbol_result_builder *builder, int index)
{
	struct drgn_symbol *symbol = malloc(sizeof(*symbol));
	if (!symbol) {
		builder->err = &drgn_enomem;
		return true;
	}
	drgn_symbol_from_kallsyms(builder->kr, index, symbol);
	if (builder->flags & DRGN_FIND_SYM_ONE) {
		builder->ret->symbol = symbol;
		return true;
	} else if (!symbolp_vector_append(&builder->vec, &symbol)) {
		drgn_symbol_destroy(symbol);
		builder->err = &drgn_enomem;
		return true;
	}
	return false;
}

static inline struct drgn_error *
symbol_result_builder_destroy(struct symbol_result_builder *builder)
{
	if (builder->flags & DRGN_FIND_SYM_ONE) {
		if (!builder->err) {
			return NULL;
		} else {
			drgn_symbol_destroy(builder->ret->symbol);
			builder->ret->symbol = NULL;
			return NULL;
		}
	} else {
		if (!builder->err) {
			symbolp_vector_shrink_to_fit(&builder->vec);
			builder->ret->symbol_arr = builder->vec.data;
			builder->ret->count = builder->vec.size;
			return NULL;
		} else {
			drgn_symbols_destroy(builder->vec.data, builder->vec.size);
			return builder->err;
		}
	}
}

struct drgn_error *
drgn_kallsyms_symbol_finder(const char *name, uint64_t address,
			    enum drgn_find_symbol_flags flags, void *arg,
			    union drgn_find_symbol_result *ret)
{
	struct kallsyms_registry *kr = arg;
	uint64_t begin = kallsyms_address(kr, 0);
	uint64_t end = kallsyms_address(kr, kr->num_syms - 1);
	struct symbol_result_builder builder;

	symbol_result_builder_init(&builder, kr, flags, ret);

	/* We assume the last symbol is "zero length" for simplicity.
	 * Short-circuit the search when we're searching outside the address
	 * range.
	 */
	if (flags & DRGN_FIND_SYM_ADDR) {
		uint64_t *res;
		if (address < begin || address > end)
			goto out;
		res = bsearch(&address, kr->addresses, kr->num_syms, sizeof(address),
			      kallsyms_addr_compar);
		if (!res)
			goto out;
		symbol_result_builder_add(&builder, res - kr->addresses);
	} else {
		bool check_name = flags & DRGN_FIND_SYM_NAME;
		for (int i = 0; i < kr->num_syms; i++)
			if (!check_name || strcmp(kr->symbols[i], name) == 0)
				if (symbol_result_builder_add(&builder, i))
					goto out;
	}

out:
	return symbol_result_builder_destroy(&builder);
}

/** Compute an address via the CONFIG_KALLSYMS_ABSOLUTE_PERCPU method*/
static uint64_t absolute_percpu(uint64_t base, int32_t val)
{
	if (val >= 0)
		return (uint64_t) val;
	else
		return base - 1 - val;
}

/**
 * Load the kallsyms address information from @a prog
 *
 * Just as symbol name loading is complex, so is address loading. Addresses may
 * be stored directly as an array of pointers, but more commonly, they are
 * stored as an array of 32-bit integers which are related to an offset. This
 * function decodes the addresses into a plain array of 64-bit addresses.
 *
 * @param prog The program to read from
 * @param kr The symbol registry to fill
 * @param vi vmcoreinfo containing necessary symbols
 * @returns NULL on success, or error
 */
static struct drgn_error *
kallsyms_load_addresses(struct drgn_program *prog, struct kallsyms_registry *kr, struct vmcoreinfo *vi)
{
	struct drgn_error *err = NULL;
	bool bswap, bits64;
	uint32_t *addr32;

	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;
	err = drgn_program_is_64_bit(prog, &bits64);
	if (err)
		return err;

	kr->addresses = malloc(kr->num_syms * sizeof(uint64_t));
	if (!kr->addresses)
		return &drgn_enomem;

	if (vi->kallsyms_addresses) {
		/*
		 * The kallsyms addresses are stored as plain addresses in an
		 * array of unsigned long! Read the appropriate size array and
		 * do any necessary byte swaps.
		 */
		if (!bits64) {
			addr32 = malloc(kr->num_syms * sizeof(uint32_t));
			if (!addr32)
				return &drgn_enomem;

			err = drgn_program_read_memory(prog, addr32,
						vi->kallsyms_addresses,
						kr->num_syms * sizeof(uint32_t),
						false);
			if (err) {
				free(addr32);
				return err;
			}
			for (int i = 0; i < kr->num_syms; i++) {
				if (bswap)
					kr->addresses[i] = bswap_32(addr32[i]);
				else
					kr->addresses[i] = addr32[i];
			}
			free(addr32);
		} else {
			err = drgn_program_read_memory(prog, kr->addresses,
						vi->kallsyms_addresses,
						kr->num_syms * sizeof(uint32_t),
						false);
			if (err)
				return err;
			if (bswap)
				for (int i = 0; i < kr->num_syms; i++)
					kr->addresses[i] = bswap_64(kr->addresses[i]);
		}
	} else {
		/*
		 * The kallsyms addresses are stored in an array of 4-byte
		 * values, which can be interpreted in two ways:
		 * (1) if CONFIG_KALLSYMS_ABSOLUTE_PERCPU is enabled, then
		 *     positive values are addresses, and negative values are
		 *     offsets from a base address.
		 * (2) otherwise, the 4-byte values are directly used as
		 *     addresses
		 * First, read the values, then figure out which way to
		 * interpret them.
		 */
		uint64_t relative_base;
		if (bits64) {
			err = drgn_program_read_u64(prog, vi->kallsyms_relative_base,
						false, &relative_base);
			if (err)
				return err;
			if (bswap)
				relative_base = bswap_64(relative_base);
		} else {
			uint32_t rel32;
			err = drgn_program_read_u32(prog, vi->kallsyms_relative_base,
						    false, &rel32);
			if (err)
				return err;
			if (bswap)
				rel32 = bswap_32(rel32);
			relative_base = rel32;
		}
		addr32 = malloc(kr->num_syms * sizeof(uint32_t));
		if (!addr32)
			return &drgn_enomem;

		err = drgn_program_read_memory(prog, addr32,
					vi->kallsyms_offsets,
					kr->num_syms * sizeof(uint32_t),
					false);
		if (err) {
			free(addr32);
			return err;
		}
		if (bswap)
			for (int i = 0; i < kr->num_syms; i++)
				addr32[i] = bswap_32(addr32[i]);

		/*
		 * Now that we've read the offsets data, we need to determine
		 * how to interpret them. To do this, use the _stext symbol. We
		 * have the correct value from vmcoreinfo. Compute it both ways
		 * and pick the correct interpretation.
		 */
		int stext_idx = drgn_kallsyms_lookup(kr,"_stext");
		if (stext_idx < 0) {
			free(addr32);
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Could not find _stext symbol in kallsyms");
		}

		uint64_t stext_abs = relative_base + addr32[stext_idx];
		uint64_t stext_pcpu = absolute_percpu(relative_base, (int32_t)addr32[stext_idx]);
		if (stext_abs == vi->_stext) {
			for (int i = 0; i < kr->num_syms; i++)
				kr->addresses[i] = relative_base + addr32[i];
		} else if (stext_pcpu == vi->_stext) {
			for (int i = 0; i < kr->num_syms; i++)
				kr->addresses[i] = absolute_percpu(relative_base, (int32_t)addr32[i]);
		} else {
			err = drgn_error_create(
				DRGN_ERROR_OTHER,
				"Unable to interpret kallsyms address data");
		}
		free(addr32);
	}
	return err;
}

/** Free all data held by @a kr */
void drgn_kallsyms_destroy(struct kallsyms_registry *kr)
{
	if (kr) {
		free(kr->addresses);
		free(kr->symbol_buffer);
		free(kr->symbols);
		free(kr->types);
		free(kr);
	}
}

struct drgn_error *drgn_kallsyms_create(struct drgn_program *prog,
				        struct vmcoreinfo *vi,
					struct kallsyms_registry **kr_out)
{
	struct drgn_error *err;
	struct kallsyms_registry *kr;

	if (!(vi->kallsyms_names && vi->kallsyms_token_table
	      && vi->kallsyms_token_index && vi->kallsyms_num_syms)) {
		return NULL;
	}

	kr = calloc(1, sizeof(*kr));
	if (!kr)
		return &drgn_enomem;

	kr->prog = prog;
	err = kallsyms_load_names(kr, vi);
	if (err)
		goto out;

	err = kallsyms_load_addresses(prog, kr, vi);
	if (err)
		goto out;

	err = drgn_program_add_symbol_finder(prog, drgn_kallsyms_symbol_finder, kr);
	if (err)
		goto out;

	*kr_out = kr;
	return NULL;
out:
	drgn_kallsyms_destroy(kr);
	return err;
}
