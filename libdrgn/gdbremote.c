// Copyright (c) Daniel Thompson <daniel@redfelineninja.org.uk>
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <endian.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "gdbremote.h"
#include "program.h"
#include "util.h"

#define VERBOSE_PROTOCOL 0

// We don't expect anyone outside this module to need to check for this error
// by address so, until that changes, we'll keep it static.
static struct drgn_error drgn_error_end_of_packet = {
	.code = DRGN_ERROR_OTHER,
	.message = "cannot read past end of gdbremote packet",
};

struct gdb_packet {
	unsigned char buffer[1024];
	unsigned int buflen;
};

struct gdb_7bit_iterator {
	unsigned char *bufp;
	unsigned int remaining;
	unsigned char repeat_char;
	unsigned char run_length;
};

static char hexchar(uint8_t nibble)
{
	assert(nibble < 16);

	if (nibble < 10)
		return '0' + nibble;

	return 'a' + nibble - 10;
}

static unsigned char lookup_hexchar(unsigned char c)
{
	if (c < 'A')
		return 0 + (c - '0');

	return 10 + ((c | 0x20) - 'a');
}

static struct gdb_7bit_iterator gdb_7bit_iterator_init(struct gdb_packet *pkt)
{
	struct gdb_7bit_iterator it = {
		.bufp = &pkt->buffer[1],
		.remaining = pkt->buflen - 4,
		.repeat_char = pkt->buffer[0],
		.run_length = 0,
	};

	return it;
}

/*
 * Extract a single character from the packet currently being processed.
 *
 * Handles run length encoding and escapes.
 *
 * The packet *must* be checked using gdb_packet_verify_framing() before
 * processing because we rely on the trailing # to mark the end of the
 * packet.
 *
 * TODO: Provide this with it's own statically allocated error type
 *       (to clearly indicate end-of-packet)
 */
static struct drgn_error *
gdb_7bit_iterator_get_char(struct gdb_7bit_iterator *it, uint8_t *ret)
{
	if (it->run_length) {
		it->run_length--;
		*ret = it->repeat_char;
		return NULL;
	}

	if (it->bufp[0] == '*') {
		if (it->bufp[1] == '#')
			return &drgn_error_end_of_packet;

		it->run_length = it->bufp[1] - 30;
		it->bufp += 2;

		*ret = it->repeat_char;
		return NULL;
	}

	if (it->bufp[0] == '#')
		return &drgn_error_end_of_packet;

	if (it->bufp[0] == 0x7d) {
		if (it->bufp[1] == '#')
			return &drgn_error_end_of_packet;

		it->repeat_char = it->bufp[1] ^ 0x20;
		it->bufp += 2;
	} else {
		it->repeat_char = *it->bufp++;
	}

	*ret = it->repeat_char;
	return NULL;
}

static struct drgn_error *
gdb_7bit_iterator_get_integer(struct gdb_7bit_iterator *it, unsigned int nchars,
			      uint64_t *ret)
{
	uint64_t accumulator = 0;
	bool valid = true;
	struct drgn_error *err = NULL;

	for (int i=0; i<nchars; i++) {
		uint8_t c;
		err = gdb_7bit_iterator_get_char(it, &c);
		if (err)
			break;

		if (isxdigit(c)) {
			accumulator = (accumulator << 4) | lookup_hexchar(c);
		} else {
			valid = false;
		}
	}

	if (err)
		return err;

	if (!valid)
		return &drgn_not_found;

	*ret = accumulator;
	return NULL;
}

static struct drgn_error *gdb_7bit_iterator_get_u8(struct gdb_7bit_iterator *it,
						   uint8_t *ret)
{
	uint64_t v;
	struct drgn_error *err = gdb_7bit_iterator_get_integer(it, 2, &v);
	if (err)
		return err;

	*ret = v;
	return NULL;
}

static uint8_t gdb_packet_get_checksum(struct gdb_packet *pkt)
{
	int i;
	uint8_t checksum = pkt->buffer[1];

	for (i=2; i<pkt->buflen && pkt->buffer[i] != '#'; i++)
		checksum += pkt->buffer[i];

	return checksum;
}

static struct drgn_error *gdb_packet_verify_framing(struct gdb_packet *pkt)
{
	if (pkt->buffer[0] != '$')
		return drgn_error_format(
		    DRGN_ERROR_OTHER,
		    "Packet is badly framed (no leading '$')");

	if (pkt->buffer[pkt->buflen - 3] != '#')
		return drgn_error_format(
		    DRGN_ERROR_OTHER,
		    "Packet is badly framed (no trailing '#')");

	uint8_t checksum = gdb_packet_get_checksum(pkt);
	if (pkt->buffer[pkt->buflen - 2] != hexchar(checksum >> 4) ||
	    pkt->buffer[pkt->buflen - 1] != hexchar(checksum & 0x0f))
		return drgn_error_format(
		    DRGN_ERROR_OTHER,
		    "Packet has bad checksum (should be %02x, got %c%c)",
		    checksum, pkt->buffer[pkt->buflen - 2],
		    pkt->buffer[pkt->buflen - 1]);

	return NULL;
}

static void gdb_packet_fixup_checksum(struct gdb_packet *pkt)
{
	assert(pkt->buflen >= 3);
	assert(pkt->buflen <= sizeof(pkt->buffer) - 2);

	uint8_t checksum = gdb_packet_get_checksum(pkt);

	pkt->buffer[pkt->buflen] = hexchar(checksum >> 4);
	pkt->buffer[pkt->buflen+1] = hexchar(checksum & 0x0f);
	pkt->buflen += 2;

	pkt->buffer[pkt->buflen] = '\0';

	assert(NULL == gdb_packet_verify_framing(pkt));
}

static void gdb_packet_init(struct gdb_packet *pkt, const char *cmd)
{
	int len = strlen(cmd);
	assert(sizeof(pkt->buffer) > len + 5);

	pkt->buffer[0] = '$';
	memcpy(&pkt->buffer[1], cmd, len);
	pkt->buffer[len+1] = '#';
	pkt->buflen = len+2;
	gdb_packet_fixup_checksum(pkt);

	// make the buffer printable (the assert above checks there is space for
	// this)
	pkt->buffer[pkt->buflen] = '\0';
}

static struct drgn_error *gdb_send_command(int fd, struct gdb_packet *pkt)
{
	unsigned char *bufp = pkt->buffer;

	if (VERBOSE_PROTOCOL)
		fprintf(stderr, "=> %s\n", bufp);

	// this is an old school write-all loop...
	while (pkt->buflen > 0) {
		ssize_t res = write(fd, bufp, pkt->buflen);
		if (res < 0)
			return drgn_error_create_os(
			    "failed to send gdbserver command", errno, NULL);
		bufp += res;;
		pkt->buflen -= res;
	}

	return 0;
}

static struct drgn_error *gdb_await_ack(int fd, struct gdb_packet *pkt)
{
	int res;

	do {
		res = read(fd, pkt->buffer, 1);
	} while (res == 0);

	if (res < 0)
		return drgn_error_create_os("failed to wait for gdbserver ack",
					    errno, NULL);

	if (VERBOSE_PROTOCOL > 1)
		fprintf(stderr, "<- %c\n", pkt->buffer[0]);

	if (pkt->buffer[0] != '+')
		return drgn_error_format(
		    DRGN_ERROR_OTHER,
		    "no ack from gdbserver (expected '+', got '%c')",
		    pkt->buffer[0]);

	return 0;
}

static struct drgn_error *gdb_await_reply(int fd, struct gdb_packet *pkt)
{
	int res;
	struct drgn_error *err;

	pkt->buflen = 0;

	// keep reading until we have an end-of-packet marker
	while(pkt->buflen < 4 || pkt->buffer[pkt->buflen - 3] != '#') {
		// The - 1 is important here: it's not needed to correctly
		// implement the protocol but it does allow us to terminate
		// the buffer (which allows debug code to treat it like a
		// C-string
		int nbytes = sizeof(pkt->buffer) - pkt->buflen - 1;
		if (nbytes <= 0)
			return drgn_error_format(
			    DRGN_ERROR_OTHER,
			    "overflow waiting for gdbserver reply");

		res = read(fd, pkt->buffer + pkt->buflen, nbytes);
		if (res < 0)
			return drgn_error_create_os(
			    "failed to wait for gdbserver reply", errno, NULL);

		pkt->buflen += res;
	}

	// we reserved space for this in the read loop
	pkt->buffer[pkt->buflen] = '\0';
	if (VERBOSE_PROTOCOL)
		fprintf(stderr, "<= %s\n", (char *) pkt->buffer);

	err = gdb_packet_verify_framing(pkt);
	if (err)
		return err;

	return 0;
}

static struct drgn_error *gdb_send_and_receive(int fd, struct gdb_packet *pkt)
{
	struct drgn_error *err;

	err = gdb_send_command(fd, pkt);
	if (err)
		return err;

	err = gdb_await_ack(fd, pkt);
	if (err)
		return err;

	err = gdb_await_reply(fd, pkt);
	if (err)
		return err;

	int res = write(fd, "+", 1);
	if (res != 1)
		return drgn_error_create_os(
			"failed to send gdbserver ack", errno, NULL);

	if (VERBOSE_PROTOCOL > 1)
		fprintf(stderr, "-> +\n");

	return NULL;
}

static struct drgn_error *gdb_query(int fd, struct gdb_packet *pkt)
{
	struct drgn_error *err;

	gdb_packet_init(pkt, "?");
	err = gdb_send_and_receive(fd, pkt);
	if (err)
		return err;

	return NULL;
}

static struct drgn_error *gdb_get_registers(int fd, struct gdb_packet *pkt)
{
	struct drgn_error *err;

	gdb_packet_init(pkt, "g");
	err = gdb_send_and_receive(fd, pkt);
	if (err)
		return err;

	return 0;
}

struct drgn_error *drgn_gdbremote_connect(const char *conn, int *ret)
{
	struct drgn_error *err;
	int res;

	// Currently we only support the hostname:port format
	_cleanup_free_ char *host = strdup(conn);
	if (!host)
		return &drgn_enomem;
	char *port = strrchr(host, ':');
	if (port)
		*port++ = '\0';

	struct addrinfo  hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
        struct addrinfo *result, *rp;
	res = getaddrinfo(host, port, &hints, &result);
	if (res < 0)
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "could not connect to '%s'", conn);

	int conn_fd = -1;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		conn_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (conn_fd < 0)
			continue;

		res = connect(conn_fd, rp->ai_addr, rp->ai_addrlen);
		if (res >= 0)
			break;

		close(conn_fd);
		conn_fd = -1;
	}

	if (conn_fd < 0)
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "failed to connect to '%s'", conn);

	// Verify that the remote stub responds to the query packet
	struct gdb_packet pkt;
	err = gdb_query(conn_fd, &pkt);
	if (err)
		return err;

	*ret = conn_fd;
	return NULL;
}

struct drgn_error *drgn_gdbremote_read_memory(void *buf, uint64_t address,
					      size_t count, uint64_t offset,
					      void *arg, bool physical)
{
	struct drgn_program *prog = arg;
	struct drgn_error *err;
	char cmd[32];
	struct gdb_packet pkt;

	if (physical)
		return drgn_error_format(DRGN_ERROR_FAULT,
		    "Cannot read from physical memory at %"PRIx64, address);

	// Make sure we don't read more than we can fit in the statically
	// sized packet buffer
	const size_t chunksz = (sizeof(pkt.buffer) / 2) - 8;

	for (size_t i=0; i < count; i += chunksz) {
		size_t remaining = min(count - i, chunksz);
		sprintf(cmd, "m%"PRIx64",%zu", address + i, remaining);
		gdb_packet_init(&pkt, cmd);
		err = gdb_send_and_receive(prog->conn_fd, &pkt);
		if (err)
			return err;

		struct gdb_7bit_iterator it = gdb_7bit_iterator_init(&pkt);
		for (int j = 0; j < remaining; j++) {
			err = gdb_7bit_iterator_get_u8(&it,
					((uint8_t *)buf) + i + j);
			if (err)
				return err;
		}
	}

	return NULL;
}

struct drgn_error *drgn_gdbremote_get_registers(int conn_fd, uint32_t tid,
						void **regs_ret,
						size_t *reglen_ret)
{
	struct drgn_error *err;
	struct gdb_packet pkt;
	struct gdb_7bit_iterator it;
	int len;

	err = gdb_get_registers(conn_fd, &pkt);
	if (err)
		return err;

	// figure out how large the register set is
	it = gdb_7bit_iterator_init(&pkt);
	for (len=0; ; len++) {
		uint8_t byte;
		err = gdb_7bit_iterator_get_u8(&it, &byte);
		if (err == &drgn_error_end_of_packet)
			break;
	}

	uint8_t *regs = calloc(len, 1);
	if (regs == NULL)
		return &drgn_enomem;

	it = gdb_7bit_iterator_init(&pkt);
	for (int i=0; i<len; i++) {
		// decode errors can happen (they indicate xx in the packet)
		// but we can just ignore them and rely on the calloc() to
		// pass zeroed registers to the rest of the register handling
		// logic
		(void) gdb_7bit_iterator_get_u8(&it, &regs[i]);
	}

	*regs_ret = regs;
	*reglen_ret = len;
	return NULL;
}
