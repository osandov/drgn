// Copyright (c) 2024 Oracle and/or its affiliates
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <ctype.h>
#include <stddef.h>

#include "kallsyms.h"
#include "program.h"
#include "drgn.h"
#include "string_builder.h"
#include "symbol.h"

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
 * Kallsyms doesn't include symbol length.  We determine symbol length by the
 * start of the subsequent symbol.  Unfortunately, there can be large gaps in
 * the symbol table, for instance on x86_64 the Linux kernel has percpu symbols
 * near the beginning of the address space, and a large gap before normal kernel
 * symbols.  The result of this is that we can create symbols with incredibly
 * large sizes, and then drgn's symbolization will print addresses using that
 * symbol and a very large offset, which is absolutely meaningless.
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
 * Extract the symbol name and type
 * @param kr Registry containing kallsyms data
 * @param offset Starting index within names array for this symbol
 * @param sb Buffer to write output symbol to
 * @param[out] kind_ret Where to write the symbol kind data
 * @returns The offset of the next symbol in the names array
 */
static unsigned int
kallsyms_expand_symbol(struct kallsyms_reader *kr, unsigned int offset,
		       struct string_builder *sb, char *kind_ret)
{
	uint8_t *data = &kr->names[offset];
	unsigned int len = *data;
	bool skipped_first = false;

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
				if (!string_builder_appendc(sb, *token_ptr)) {
					string_builder_null_terminate(sb);
					return offset;
				}
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

	string_builder_null_terminate(sb);
	return offset;
}

/**
 * Used to find _stext in the kallsyms before we've moved everything into
 * the drgn_symbol_index. Finds the index matching the given name, or -1.
 */
static ssize_t search_for_string(struct kallsyms_reader *kr, const char *name)
{
	STRING_BUILDER(sb);
	size_t len = strlen(name);
	uint32_t names_idx = 0;
	for (ssize_t i = 0; i < kr->num_syms; i++) {
		char kind;
		sb.len = 0;
		names_idx = kallsyms_expand_symbol(kr, names_idx, &sb, &kind);
		if (sb.len == len && strcmp(name, sb.str) == 0)
			return i;
	}
	return -1;
}

static void symbol_from_kallsyms(uint64_t address, char *name, char kind,
				      uint64_t size, struct drgn_symbol *ret)
{
	char kind_lower = tolower(kind);
	ret->name = name;
	ret->address = address;
	ret->size = size;
	ret->binding = DRGN_SYMBOL_BINDING_GLOBAL;

	// See nm(1) for information on decoding this "kind" character
	if (kind == 'u')
		ret->binding = DRGN_SYMBOL_BINDING_UNIQUE;
	else if (kind_lower == 'v' || kind_lower == 'w')
		ret->binding = DRGN_SYMBOL_BINDING_WEAK;
	else if (isupper(kind))
		ret->binding = DRGN_SYMBOL_BINDING_GLOBAL;
	else
		// If lowercase, the symbol is usually local, but it's
		// not guaranteed. Use unknown for safety here.
		ret->binding = DRGN_SYMBOL_BINDING_UNKNOWN;

	switch (kind_lower) {
	case 'b': // bss
	case 'c': // uninitialized data
	case 'd': // initialized data
	case 'g': // initialized data (small objects)
	case 'r': // read-only data
	case 'v': // weak object (guaranteed by elf_info() in kernel/module.c)
		ret->kind = DRGN_SYMBOL_KIND_OBJECT;
		break;
	case 't': // text
		ret->kind = DRGN_SYMBOL_KIND_FUNC;
		break;
	default:
		ret->kind = DRGN_SYMBOL_KIND_UNKNOWN;
	}
	ret->name_lifetime = DRGN_LIFETIME_STATIC;
	ret->lifetime = DRGN_LIFETIME_STATIC; // avoid copying
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
kallsyms_load_addresses(struct drgn_program *prog, struct kallsyms_reader *kr,
			struct kallsyms_locations *loc, uint64_t **ret)
{
	struct drgn_error *err = NULL;
	bool bswap, bits64;
	_cleanup_free_ uint32_t *addr32 = NULL;

	err = drgn_program_bswap(prog, &bswap);
	if (err)
		return err;
	err = drgn_program_is_64_bit(prog, &bits64);
	if (err)
		return err;

	_cleanup_free_ uint64_t *addresses =
		malloc_array(kr->num_syms, sizeof(addresses[0]));
	if (!addresses)
		return &drgn_enomem;

	if (loc->kallsyms_addresses) {
		/*
		 * The kallsyms addresses are stored as plain addresses in an
		 * array of unsigned long! Read the appropriate size array and
		 * do any necessary byte swaps.
		 */
		if (!bits64) {
			addr32 = malloc_array(kr->num_syms, sizeof(addr32[0]));
			if (!addr32)
				return &drgn_enomem;

			err = drgn_program_read_memory(prog, addr32,
						loc->kallsyms_addresses,
						kr->num_syms * sizeof(uint32_t),
						false);
			if (err)
				return err;
			for (int i = 0; i < kr->num_syms; i++) {
				if (bswap)
					addresses[i] = bswap_32(addr32[i]);
				else
					addresses[i] = addr32[i];
			}
		} else {
			err = drgn_program_read_memory(prog, addresses,
						loc->kallsyms_addresses,
						kr->num_syms * sizeof(uint32_t),
						false);
			if (err)
				return err;
			if (bswap)
				for (int i = 0; i < kr->num_syms; i++)
					addresses[i] = bswap_64(addresses[i]);
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
		if (err)
			return err;
		if (bswap)
			for (int i = 0; i < kr->num_syms; i++)
				addr32[i] = bswap_32(addr32[i]);

		/*
		 * Now that we've read the offsets data, we need to determine
		 * how to interpret them. To do this, use the _stext symbol. We
		 * have the correct value from vmcoreinfo. Compute it both ways
		 * and pick the correct interpretation.
		 */
		ssize_t stext_idx = search_for_string(kr, "_stext");
		if (stext_idx < 0)
			return drgn_error_create(
				DRGN_ERROR_OTHER,
				"Could not find _stext symbol in kallsyms");

		uint64_t stext_abs = relative_base + addr32[stext_idx];
		uint64_t stext_pcpu = absolute_percpu(relative_base, (int32_t)addr32[stext_idx]);
		if (stext_abs == loc->_stext) {
			for (int i = 0; i < kr->num_syms; i++)
				addresses[i] = relative_base + addr32[i];
		} else if (stext_pcpu == loc->_stext) {
			for (int i = 0; i < kr->num_syms; i++)
				addresses[i] = absolute_percpu(relative_base, (int32_t)addr32[i]);
		} else {
			err = drgn_error_create(
				DRGN_ERROR_OTHER,
				"Unable to interpret kallsyms address data");
			if (err)
				return err;
		}
	}
	*ret = no_cleanup_ptr(addresses);
	return NULL;
}

static void kallsyms_reader_cleanup(struct kallsyms_reader *kr)
{
	free(kr->names);
	free(kr->token_index);
	free(kr->token_table);
}

struct drgn_error *
drgn_load_builtin_kallsyms(struct drgn_program *prog,
			  struct kallsyms_locations *loc,
			  struct drgn_symbol_index *ret)
{
	if (!(loc->kallsyms_names && loc->kallsyms_token_table
	      && loc->kallsyms_token_index && loc->kallsyms_num_syms))
		return drgn_error_create(
			DRGN_ERROR_MISSING_DEBUG_INFO,
			"The symbols: kallsyms_names, kallsyms_token_table, "
			"kallsyms_token_index, and kallsyms_num_syms were not "
			"found in VMCOREINFO. There is not enough "
			"information to load the kallsyms table."
		);

	_cleanup_(kallsyms_reader_cleanup) struct kallsyms_reader kr = {0};

	struct drgn_error *err = kallsyms_copy_tables(prog, &kr, loc);
	if (err)
		return err;

	_cleanup_free_ uint64_t *addresses = NULL;
	err = kallsyms_load_addresses(prog, &kr, loc, &addresses);
	if (err)
		return err;

	struct drgn_symbol_index_builder builder;
	drgn_symbol_index_builder_init(&builder);
	STRING_BUILDER(sb);

	uint32_t names_idx = 0;
	for (int i = 0; i < kr.num_syms; i++) {
		struct drgn_symbol symbol;
		char kind;
		uint64_t size = 0;
		sb.len = 0;
		names_idx = kallsyms_expand_symbol(&kr, names_idx, &sb, &kind);
		if (i + 1 < kr.num_syms &&
		    addresses[i + 1] - addresses[i] < MAX_SYMBOL_LENGTH)
			size = addresses[i + 1] - addresses[i];
		symbol_from_kallsyms(addresses[i], sb.str, kind, size, &symbol);
		if (!drgn_symbol_index_builder_add(&builder, &symbol)) {
			drgn_symbol_index_builder_deinit(&builder);
			return &drgn_enomem;
		}
	}

	return drgn_symbol_index_init_from_builder(ret, &builder);
}

/** Load kallsyms directly from the /proc/kallsyms file */
struct drgn_error *drgn_load_proc_kallsyms(const char *filename, bool modules,
					   struct drgn_symbol_index *ret)
{
	FILE *fp = fopen(filename, "r");
	if (!fp)
		return drgn_error_create_os("Error opening kallsyms", errno, filename);

	struct drgn_error *err = NULL;
	struct drgn_symbol sym = {0};
	struct drgn_symbol_index_builder builder;
	drgn_symbol_index_builder_init(&builder);
	char *line = NULL, *current_module = NULL;
	size_t line_size = 0, line_number = 1;
	ssize_t res;
	while ((res = getline(&line, &line_size, fp)) != -1) {
		char *save = NULL;
		char *name, *type_str, *mod, *addr_rem, *addr_str;
		char type;
		uint64_t addr;
		bool new_module = false;

		addr_str = strtok_r(line, " \t\r\n", &save);
		type_str = strtok_r(NULL,"  \t\r\n", &save);
		name = strtok_r(NULL,"  \t\r\n", &save);
		mod = strtok_r(NULL,"  \t\r\n", &save);

		if (!addr_str || !type_str || !name) {
			err = drgn_error_format(DRGN_ERROR_SYNTAX,
						"Error parsing kallsyms line %zu",
						line_number);
			break;
		}
		if (mod && !modules) {
			break;
		} else if (mod && (!current_module || strcmp(mod, current_module) != 0)) {
			free(current_module);
			current_module = strdup(mod);
			new_module = true;
			if (!current_module) {
				err = &drgn_enomem;
				break;
			}
		}

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

		// Append the previous symbol now that we have the next symbol's
		// address to compute the size, only if we didn't get a symbol
		// size before.
		uint64_t size = addr - sym.address;
		if (!new_module && size < MAX_SYMBOL_LENGTH)
			sym.size = size;
		if (sym.name && !drgn_symbol_index_builder_add(&builder, &sym)) {
			err = &drgn_enomem;
			sym.name = NULL;  // don't try to append again
			break;
		}
		free((char *)sym.name);

		symbol_from_kallsyms(addr, name, type, 0, &sym);

		// Copy the name so we don't clobber it in the next iteration
		sym.name = strdup(name);
		if (!sym.name) {
			err = &drgn_enomem;
			break;
		}

		line_number++;
	}

	// Append the final symbol
	if (sym.name && !drgn_symbol_index_builder_add(&builder, &sym))
		err = &drgn_enomem;
	free((char *)sym.name);
	free(current_module);

	if (!err && ferror(fp))
		err = drgn_error_create_os("Error reading kallsyms", errno, "/proc/kallsyms");
	else
		err = drgn_symbol_index_init_from_builder(ret, &builder);
	return err;
}
