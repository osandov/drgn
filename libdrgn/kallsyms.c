// Copyright (c) 2023 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later

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
	bool long_names;
};

/*
 * We determine symbol length by the start of the subsequent symbol.
 * Unfortunately, there can be large gaps in the symbol table, for instance the
 * Linux kernel has percpu symbols near the beginning of the address space, and
 * a large gap before normal kernel symbols. The result of this is that we can
 * create symbols with incredibly large sizes, and then drgn's symbolization
 * will print addresses using that symbol and a very large offset, which is
 * absolutely meaningless.
 *
 * To avoid this, we set a cap on the length of a symbol. Unfortunately, this is
 * a heuristic. It's entirely possible to have very large data symbols. This
 * value is chosen somewhat arbitrarily, but seems to produce decent results.
 */
#define MAX_SYMBOL_LENGTH 0x10000

/*
 * Since 73bbb94466fd3 ("kallsyms: support "big" kernel symbols"), the
 * "kallsyms_names" array may use the most significant bit to indicate that the
 * initial element for each symbol (normally representing the number of tokens
 * in the symbol) requires two bytes.
 *
 * Unfortunately, that means that values 128-255 are now ambiguous: on older
 * kernels, they should be interpreted literally, but on newer kernels, they
 * require treating as a two byte sequence. Since the commit included no changes
 * to the symbol names or vmcoreinfo, there's no way to detect it except via
 * heuristics.
 *
 * The commit in question is a new feature and not likely to be backported to
 * stable, so our heuristic is that it was first included in kernel 6.1.
 * However, we first check the environment variable DRGN_KALLSYMS_LONG: if it
 * exists, then we use its first character to determine our behavior: 1, y, Y
 * all indicate that we should use long names. 0, n, N all indicate that we
 * should not.
 */
static bool guess_long_names(struct drgn_program *prog)
{
	const char *env = getenv("DRGN_KALLSYMS_LONG");
	const char *osrelease;
	int i;
	int major = 0, minor = 0;

	if (env) {
		if (*env == '1' || *env == 'y' || *env == 'Y')
			return true;
		else if (*env == '0' || *env == 'n' || *env == 'N')
			return false;
	}

	osrelease = prog->vmcoreinfo.osrelease;
	for (i = 0; i < sizeof(prog->vmcoreinfo.osrelease) && osrelease[i]; i++) {
		char c = osrelease[i];
		if (c < '0' || c > '9')
			break;
		major *= 10;
		major += osrelease[i] - '0';
	}
	for (i = i + 1; i < sizeof(prog->vmcoreinfo.osrelease) && osrelease[i] && osrelease[i] != '.'; i++) {
		char c = osrelease[i];
		if (c < '0' || c > '9')
			break;
		minor *= 10;
		minor += osrelease[i] - '0';
	}
	return (major == 6 && minor >= 1) || major > 6;
}

/**
 * Copy the kallsyms names tables from the program into host memory.
 * @param prog Program to read from
 * @param kr kallsyms_reader to populate
 * @param vi vmcoreinfo for the program
 */
static struct drgn_error *
kallsyms_copy_tables(struct drgn_program *prog, struct kallsyms_reader *kr,
		     struct kallsyms_locations *loc)
{
	struct drgn_error *err;
	const size_t token_index_size = (UINT8_MAX + 1) * sizeof(uint16_t);
	uint64_t last_token;
	size_t token_table_size, names_idx;
	char data;
	uint8_t len_u8;
	int len;
	bool bswap;

	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;

	/* Read num_syms from vmcore */
	err = drgn_program_read_u32(prog,
				    loc->kallsyms_num_syms,
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
				       loc->kallsyms_token_index,
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
	last_token = loc->kallsyms_token_table + kr->token_index[UINT8_MAX];
	do {
		err = drgn_program_read_u8(prog, last_token, false,
					   (uint8_t *)&data);
		if (err)
			return err;

		last_token++;
	} while (data);
	token_table_size = last_token - loc->kallsyms_token_table + 1;
	kr->token_table = malloc(token_table_size);
	if (!kr->token_table)
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, kr->token_table,
				       loc->kallsyms_token_table,
				       token_table_size, false);
	if (err)
		return err;

	/* Now find the end of the names array by skipping through it, then copy
	 * that into host memory. */
	names_idx = 0;
	kr->long_names = guess_long_names(prog);
	for (size_t i = 0; i < kr->num_syms; i++) {
		err = drgn_program_read_u8(prog,
					   loc->kallsyms_names + names_idx,
					   false, &len_u8);
		if (err)
			return err;
		len = len_u8;
		if ((len & 0x80) && kr->long_names) {
			err = drgn_program_read_u8(prog,
						loc->kallsyms_names + names_idx + 1,
						false, &len_u8);
			if (err)
				return err;
			len = (len & 0x7F) | (len_u8 << 7);
			names_idx++;
		}
		names_idx += len + 1;
	}
	kr->names = malloc(names_idx);
	if (!kr->names)
		return &drgn_enomem;
	err = drgn_program_read_memory(prog, kr->names,
				       loc->kallsyms_names,
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

	if ((len & 0x80) && kr->long_names) {
		data++;
		offset++;
		len = (0x7F & len) | (*data << 7);
	}

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
kallsyms_create_symbol_array(struct kallsyms_finder *reg, struct kallsyms_reader *kr)
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
		unsigned int num_tokens = kr->names[names_idx];
		if ((num_tokens & 0x80) && kr->long_names)
			num_tokens = (num_tokens & 0x7F) | (kr->names[++names_idx] << 7);
		for (int j = names_idx + 1; j < names_idx + num_tokens + 1; j++)
			length += token_lengths[kr->names[j]];
		length++; /* nul terminator */
		names_idx += num_tokens + 1;
	}

	/* We use uint32_t to index into the array of strings. That allows for
	 * 4GiB of names which should be plenty, but still: check for overflow. */
	if (length >= UINT32_MAX)
		return drgn_error_format(DRGN_ERROR_OUT_OF_BOUNDS,
					 "kallsyms string table is too large: %lu",
					 length);

	reg->strings = malloc(length);
	reg->strings_len = length;
	reg->names = calloc(kr->num_syms, sizeof(*reg->names));
	reg->types = malloc(kr->num_syms);
	reg->num_syms = kr->num_syms;
	if (!reg->strings || !reg->names || !reg->types)
		return &drgn_enomem;

	names_idx = 0;
	uint32_t symbols_idx = 0;
	for (int i = 0; i < kr->num_syms; i++) {
		size_t bytes = 0;
		names_idx = kallsyms_expand_symbol(kr, names_idx,
						   reg->strings + symbols_idx,
						   length - symbols_idx, &reg->types[i],
						   &bytes);
		reg->names[i] = symbols_idx;
		symbols_idx += (uint32_t) bytes;
	}
	return NULL;
}

static int kallsyms_name_compar(const void *lhs, const void *rhs, void *arg)
{
	struct kallsyms_finder *kr = arg;
	uint32_t left_ix = *(const uint32_t *)lhs;
	uint32_t right_ix = *(const uint32_t *)rhs;
	return strcmp(&kr->strings[kr->names[left_ix]],
		      &kr->strings[kr->names[right_ix]]);
}

static struct drgn_error *
kallsyms_create_htab(struct kallsyms_finder *kr)
{
	/*
	 * A sorted list of symbol indices. Entries of the hash table will point
	 * into this list for a certain number of elements.
	 */
	kr->sorted = malloc(kr->num_syms * sizeof(kr->sorted[0]));
	for (uint32_t i = 0; i < kr->num_syms; i++)
		kr->sorted[i] = i;

	qsort_r(kr->sorted, kr->num_syms, sizeof(kr->sorted[0]),
		kallsyms_name_compar, kr);

	if (!drgn_kallsyms_names_reserve(&kr->htab, kr->num_syms))
		return &drgn_enomem;

	/* For each unique symbol name, insert the index, and number of
	 * occurrences into the hash table. */
	struct drgn_kallsyms_names_entry entry;
	uint32_t current = 0;
	while (current < kr->num_syms) {
		char *current_str = &kr->strings[kr->names[kr->sorted[current]]];
		uint32_t next = current + 1;
		while (next < kr->num_syms) {
			char *next_str = &kr->strings[kr->names[kr->sorted[next]]];
			if (strcmp(current_str, next_str) != 0)
				break;
			next++;
		}

		entry.key = current_str;
		entry.value.start = current;
		entry.value.end = next;
		drgn_kallsyms_names_insert(&kr->htab, &entry, NULL);
		current = next;
	}
	return NULL;
}

/** Copies and decodes symbol names from the program. */
static struct drgn_error *
kallsyms_load_names(struct kallsyms_finder *reg, struct kallsyms_locations *loc)
{
	struct drgn_error *err;
	struct kallsyms_reader reader = {0};

	err = kallsyms_copy_tables(reg->prog, &reader, loc);
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
static int drgn_kallsyms_lookup(struct kallsyms_finder *kr, const char *name)
{
	struct drgn_kallsyms_names_iterator it =
		drgn_kallsyms_names_search(&kr->htab, (char **)&name);
	if (it.entry) {
		return kr->sorted[it.entry->value.start];
	}
	return -1;
}

/** Return the address of symbol at @a index*/
static uint64_t
kallsyms_address(struct kallsyms_finder *kr, unsigned int index)
{
	return kr->addresses[index];
}

static void drgn_symbol_from_kallsyms(struct kallsyms_finder *kr, int index,
				      struct drgn_symbol *ret)
{
	char kind = kr->types[index];
	char kind_lower = tolower(kind);
	ret->name = &kr->strings[kr->names[index]];
	ret->address = kallsyms_address(kr, index);
	if (index < kr->num_syms) {
		size_t size = kallsyms_address(kr, index + 1) - ret->address;
		if (size < MAX_SYMBOL_LENGTH)
			ret->size = size;
		else
			ret->size = 0;
	} else {
		ret->size = 0;
	}

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
	/* NOTE: The name field is owned by the kallsyms finder.
	 * Once the kallsyms finder is bound to the program, it cannot be
	 * unbound, and so it shares lifetime with the Program.
	 */
	ret->name_lifetime = DRGN_LIFETIME_STATIC;
}

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

static inline struct drgn_error *
add_result(struct kallsyms_finder *kr, struct drgn_symbol_result_builder *builder, int index)
{
	struct drgn_symbol *symbol = malloc(sizeof(*symbol));
	if (!symbol)
		return &drgn_enomem;
	drgn_symbol_from_kallsyms(kr, index, symbol);
	if (drgn_symbol_result_builder_add(builder, symbol)) {
		return NULL;
	} else {
		free(symbol);
		return &drgn_enomem;
	}
}

struct drgn_error *
drgn_kallsyms_symbol_finder(const char *name, uint64_t address,
			    enum drgn_find_symbol_flags flags, void *arg,
			    struct drgn_symbol_result_builder *builder)
{
	struct kallsyms_finder *kr = arg;
	uint64_t begin = kallsyms_address(kr, 0);
	uint64_t end = kallsyms_address(kr, kr->num_syms - 1);
	struct drgn_error *err = NULL;

	/* We assume the last symbol is "zero length" for simplicity.
	 * Short-circuit the search when we're searching outside the address
	 * range.
	 */
	if (flags & DRGN_FIND_SYMBOL_ADDR) {
		uint64_t *res;
		if (address < begin || address > end)
			return NULL;
		res = bsearch(&address, kr->addresses, kr->num_syms, sizeof(address),
			      kallsyms_addr_compar);
		/* If the gap between symbols > MAX_SYMBOL_LENGTH, then we infer that
		 * the symbol doesn't contain the address, so fail. */
		if (!res || res[1] - res[0] > MAX_SYMBOL_LENGTH)
			return NULL;
		return add_result(kr, builder, res - kr->addresses);
	} else if (flags & DRGN_FIND_SYMBOL_NAME) {
		struct drgn_kallsyms_names_iterator it =
			drgn_kallsyms_names_search(&kr->htab, (char **)&name);
		if (!it.entry)
			return NULL;
		for (uint32_t i = it.entry->value.start; i < it.entry->value.end; i++) {
			err = add_result(kr, builder, kr->sorted[i]);
			it = drgn_kallsyms_names_next(it);
			if (err || flags & DRGN_FIND_SYMBOL_ONE)
				break;
		}
		return err;
	} else {
		for (int i = 0; i < kr->num_syms; i++)
			if ((err = add_result(kr, builder, i))
				|| (flags & DRGN_FIND_SYMBOL_ONE))
				return err;
	}
	return NULL;
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
kallsyms_load_addresses(struct drgn_program *prog, struct kallsyms_finder *kr,
			struct kallsyms_locations *loc)
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

	if (loc->kallsyms_addresses) {
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
						loc->kallsyms_addresses,
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
						loc->kallsyms_addresses,
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
			err = drgn_program_read_u64(prog, loc->kallsyms_relative_base,
						false, &relative_base);
			if (err)
				return err;
			if (bswap)
				relative_base = bswap_64(relative_base);
		} else {
			uint32_t rel32;
			err = drgn_program_read_u32(prog, loc->kallsyms_relative_base,
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
					loc->kallsyms_offsets,
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
		if (stext_abs == loc->_stext) {
			for (int i = 0; i < kr->num_syms; i++)
				kr->addresses[i] = relative_base + addr32[i];
		} else if (stext_pcpu == loc->_stext) {
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
void drgn_kallsyms_destroy(struct kallsyms_finder *kr)
{
	if (kr) {
		drgn_kallsyms_names_deinit(&kr->htab);
		free(kr->sorted);
		free(kr->addresses);
		free(kr->strings);
		free(kr->names);
		free(kr->types);
	}
}

/** Load kallsyms data from vmcore + vmcoreinfo data */
static struct drgn_error *
drgn_kallsyms_from_vmcore(struct kallsyms_finder *kr, struct drgn_program *prog,
			  struct kallsyms_locations *loc)
{
	struct drgn_error *err;

	memset(kr, 0, sizeof(*kr));
	kr->prog = prog;
	drgn_kallsyms_names_init(&kr->htab);

	err = kallsyms_load_names(kr, loc);
	if (err)
		goto out;

	err = kallsyms_create_htab(kr);
	if (err)
		goto out;

	err = kallsyms_load_addresses(prog, kr, loc);
	if (err)
		goto out;

	return NULL;

out:
	drgn_kallsyms_destroy(kr);
	return err;
}

struct allocated {
	uint32_t symbols;
	size_t symbol_buffer;
};

/** Append a symbol onto the kallsyms finder, expanding the allocations if needed. */
static struct drgn_error *
kallsyms_append(struct kallsyms_finder *kr, struct allocated *a, const char *name, uint64_t address, char type)
{
	size_t name_len = strlen(name) + 1;
	if (kr->num_syms == a->symbols) {
		a->symbols = a->symbols ? a->symbols * 2 : 1024;
		kr->names = realloc(kr->names, a->symbols * sizeof(kr->names[0]));
		kr->addresses = realloc(kr->addresses, a->symbols * sizeof(kr->addresses[0]));
		kr->types = realloc(kr->types, a->symbols);
		if (!kr->names || !kr->addresses || !kr->types)
			return &drgn_enomem;
	}

	while (kr->strings_len + name_len > a->symbol_buffer) {
		a->symbol_buffer = a->symbol_buffer ? a->symbol_buffer * 2 : 4096;
		kr->strings = realloc(kr->strings, a->symbol_buffer);
		if (!kr->strings)
			return &drgn_enomem;
	}
	memcpy(&kr->strings[kr->strings_len], name, name_len);
	/*
	 * We can't just store the pointer, since symbol_buffer may move during
	 * reallocation. Store the index of the string in the buffer, and when
	 * we finalize everything, we will fix it up.
	 */
	kr->names[kr->num_syms] = kr->strings_len;
	kr->addresses[kr->num_syms] = address;
	kr->types[kr->num_syms] = type;
	kr->num_syms++;
	kr->strings_len += name_len;
	return NULL;
}

/** Reallocate buffers to fit contents, and fixup the symbol array */
static struct drgn_error *
kallsyms_finalize(struct kallsyms_finder *kr)
{
	kr->names = realloc(kr->names, kr->num_syms * sizeof(kr->names[0]));
	kr->addresses = realloc(kr->addresses, kr->num_syms * sizeof(kr->addresses[0]));
	kr->types = realloc(kr->types, kr->num_syms * sizeof(kr->types[0]));
	kr->strings = realloc(kr->strings, kr->strings_len);
	if (!kr->names || !kr->addresses || !kr->types || !kr->strings)
		return &drgn_enomem;
	return NULL;
}

/** Load kallsyms directly from the /proc/kallsyms file */
static struct drgn_error *drgn_kallsyms_from_proc(struct kallsyms_finder *kr,
						  struct drgn_program *prog)
{
	char *line = NULL;
	size_t line_size = 0;
	ssize_t res;
	size_t line_number = 1;
	struct allocated allocated = {0};
	struct drgn_error *err = NULL;
	FILE *fp = fopen("/proc/kallsyms", "r");
	if (!fp)
		return drgn_error_create_os("Error opening kallsyms", errno, "/proc/kallsyms");

	memset(kr, 0, sizeof(*kr));
	kr->prog = prog;
	drgn_kallsyms_names_init(&kr->htab);

	while ((res = getline(&line, &line_size, fp)) != -1) {
		char *save = NULL;
		char *name, *addr_str, *type_str, *mod, *addr_rem;
		char type;
		uint64_t addr;

		addr_str = strtok_r(line, " \t\r\n", &save);
		type_str = strtok_r(NULL,"  \t\r\n", &save);
		name = strtok_r(NULL,"  \t\r\n", &save);
		mod = strtok_r(NULL,"  \t\r\n", &save);

		if (!addr_str || !type_str || !name) {
			err = drgn_error_format(DRGN_ERROR_SYNTAX, "Error parsing kallsyms line %zu", line_number);
			break;
		}
		if (mod)
			break;
		type = *type_str;
		addr = strtoull(addr_str, &addr_rem, 16);
		if (*addr_rem) {
			/* addr_rem should be set to the first un-parsed character, and
			 * since the entire string should be a valid base 16 integer,
			 * we expect it to be \0 */
			 err = drgn_error_format(DRGN_ERROR_SYNTAX,
						 "Invalid address \"%s\" in kallsyms line %zu",
						 addr_str, line_number);
			 break;
		}
		err = kallsyms_append(kr, &allocated, name, addr, type);
		if (err)
			break;
		line_number++;
	}

	if (!err && ferror(fp))
		err = drgn_error_create_os("Error reading kallsyms", errno, "/proc/kallsyms");
	else
		err = kallsyms_finalize(kr);
	if (!err)
		err = kallsyms_create_htab(kr);
	fclose(fp);
	free(line);
	if (err)
		drgn_kallsyms_destroy(kr);
	return err;
}

struct drgn_error *drgn_kallsyms_init(struct kallsyms_finder *kr,
				      struct drgn_program *prog,
				      struct kallsyms_locations *loc)
{
	/*
	 * There are two ways to parse kallsyms data: by using /proc/kallsyms,
	 * or by finding the necessary symbols in the vmcoreinfo and using them
	 * to read out the kallsyms data from the vmcore.
	 *
	 * Reading /proc/kallsyms is more straightforward, performant, and it
	 * has broader kernel version support: it should be preferred for live
	 * systems.
	 *
	 * Parsing kallsyms from a core dump is more involved, and it requires
	 * that the kernel publish some symbol addresses in the VMCOREINFO note.
	 * The following kernel commits are required, and were introduced in
	 * 6.0:
	 *
	 * - 5fd8fea935a10 ("vmcoreinfo: include kallsyms symbols")
	 * - f09bddbd86619 ("vmcoreinfo: add kallsyms_num_syms symbol")
	 */
	if (prog->flags & DRGN_PROGRAM_IS_LIVE)
		return drgn_kallsyms_from_proc(kr, prog);
	else if (loc->kallsyms_names && loc->kallsyms_token_table
		 && loc->kallsyms_token_index && loc->kallsyms_num_syms)
		return drgn_kallsyms_from_vmcore(kr, prog, loc);
	else
		return drgn_error_create(
			DRGN_ERROR_MISSING_DEBUG_INFO,
			"The symbols: kallsyms_names, kallsyms_token_table, "
			"kallsyms_token_index, and kallsyms_num_syms were not "
			"found in VMCOREINFO, and the program is not live, "
			"so /proc/kallsyms cannot be used. There is not enough "
			"information to use the kallsyms symbol finder."
		);
}
