// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "cleanup.h"
#include "drgn_internal.h"
#include "hexlify.h"
#include "io.h"
#include "minmax.h"
#include "platform.h"
#include "plugins.h"
#include "program.h"
#include "util.h"

#define _cleanup_json_object_ _cleanup_(json_object_putp)
static inline void json_object_putp(struct json_object **objp)
{
	json_object_put(*objp);
}

void drgn_qmp_conn_deinit(struct drgn_qmp_conn *conn)
{
	if (conn->json_tok)
		json_tokener_free(conn->json_tok);
	string_builder_deinit(&conn->write_buf);
	string_builder_deinit(&conn->read_buf);
	if (conn->fd >= 0)
		close(conn->fd);
}

static struct drgn_error *qmp_recv_msg(struct drgn_qmp_conn *conn,
					struct json_object **ret)
{
	struct string_builder *buf = &conn->read_buf;
	for (;;) {
		// Check if we already have a complete line in the buffer.
		char *newline = memchr(buf->str, '\n', buf->len);
		if (newline) {
			struct json_object *obj =
				json_tokener_parse_ex(conn->json_tok, buf->str,
						      newline - buf->str);
			if (!obj) {
				enum json_tokener_error jerr =
					json_tokener_get_error(conn->json_tok);
				json_tokener_reset(conn->json_tok);
				return drgn_error_format(DRGN_ERROR_OTHER,
							 "could not parse QMP message: %s",
							 json_tokener_error_desc(jerr));
			}

			size_t line_len = newline - buf->str + 1;
			buf->len -= line_len;
			memmove(buf->str, newline + 1, buf->len);

			// Skip asynchronous events.
			if (json_object_object_get_ex(obj, "event", NULL)) {
				json_object_put(obj);
				continue;
			}
			*ret = obj;
			return NULL;
		}

		// Need more data.
		if (!string_builder_reserve_for_append(buf, 4096))
			return &drgn_enomem;
		ssize_t r = read(conn->fd, buf->str + buf->len, 4096);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return drgn_error_create_os("read", errno, NULL);
		}
		if (r == 0) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "QMP connection closed unexpectedly");
		}
		buf->len += r;
	}
}

static struct drgn_error *drgn_error_qmp(struct json_object *obj)
{
	struct json_object *value;
	const char *error_class = NULL, *error_desc = NULL;
	if (json_object_object_get_ex(obj, "class", &value)
	    && json_object_is_type(value, json_type_string))
		error_class = json_object_get_string(value);
	if (json_object_object_get_ex(obj, "desc", &value)
	    && json_object_is_type(value, json_type_string))
		error_desc = json_object_get_string(value);

	if (error_class && error_desc) {
		return drgn_error_format(DRGN_ERROR_OTHER, "QMP error: %s: %s",
					 error_class, error_desc);
	} else if (error_class || error_desc) {
		return drgn_error_format(DRGN_ERROR_OTHER, "QMP error: %s",
					 error_class ?: error_desc);
	} else {
		return drgn_error_create(DRGN_ERROR_OTHER, "unknown QMP error");
	}
}

static struct drgn_error *qmp_execute_str(struct drgn_qmp_conn *conn,
					  const char *cmd, size_t cmd_len,
					  struct json_object **ret)
{
	struct drgn_error *err;

	if (write_all(conn->fd, cmd, cmd_len))
		return drgn_error_create_os("write", errno, NULL);

	_cleanup_json_object_ struct json_object *response = NULL;
	err = qmp_recv_msg(conn, &response);
	if (err)
		return err;

	struct json_object *error;
	if (json_object_object_get_ex(response, "error", &error))
		return drgn_error_qmp(error);

	if (ret) {
		struct json_object *return_val;
		if (!json_object_object_get_ex(response, "return",
					       &return_val)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "QMP response missing \"return\"");
		}
		*ret = json_object_get(return_val);
	}
	return NULL;
}

#define QMP_CMD_NO_ARGS(cmd) "{\"execute\":\"" cmd "\"}\r\n"
#define QMP_EXECUTE_NO_ARGS(conn, cmd, ret) \
	qmp_execute_str(conn, QMP_CMD_NO_ARGS(cmd), sizeof(QMP_CMD_NO_ARGS(cmd)) - 1, ret)

static struct drgn_error *qmp_negotiate(struct drgn_qmp_conn *conn)
{
	struct drgn_error *err;

	// Read the greeting.
	_cleanup_json_object_ struct json_object *greeting = NULL;
	err = qmp_recv_msg(conn, &greeting);
	if (err)
		return err;
	if (!json_object_object_get_ex(greeting, "QMP", NULL)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "did not receive QMP greeting");
	}

	// Send qmp_capabilities to enter command mode.
	return QMP_EXECUTE_NO_ARGS(conn, "qmp_capabilities", NULL);
}

static struct drgn_error *qmp_detect_platform(struct drgn_qmp_conn *conn,
					      struct drgn_platform *ret)
{
	struct drgn_error *err;

	_cleanup_json_object_ struct json_object *result = NULL;
	err = QMP_EXECUTE_NO_ARGS(conn, "query-target", &result);
	if (err)
		return err;

	struct json_object *arch_obj;
	if (!json_object_object_get_ex(result, "arch", &arch_obj)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "QMP query-target response missing \"arch\"");
	}
	if (!json_object_is_type(arch_obj, json_type_string)) {
		return drgn_error_create(DRGN_ERROR_OTHER,
					 "QMP query-target \"arch\" is not string");
	}

	const char *arch = json_object_get_string(arch_obj);
	const struct drgn_architecture_info *arch_info;
	if (strcmp(arch, "x86_64") == 0)
		arch_info = &arch_info_x86_64;
	else if (strcmp(arch, "i386") == 0)
		arch_info = &arch_info_i386;
	else if (strcmp(arch, "aarch64") == 0)
		arch_info = &arch_info_aarch64;
	else if (strcmp(arch, "arm") == 0)
		arch_info = &arch_info_arm;
	else if (strcmp(arch, "ppc64") == 0)
		arch_info = &arch_info_ppc64;
	else if (strcmp(arch, "riscv64") == 0)
		arch_info = &arch_info_riscv64;
	else if (strcmp(arch, "riscv32") == 0)
		arch_info = &arch_info_riscv32;
	else if (strcmp(arch, "s390x") == 0)
		arch_info = &arch_info_s390x;
	else
		arch_info = &arch_info_unknown;

	ret->arch = arch_info;
	ret->flags = arch_info->default_flags;
	return NULL;
}

static struct drgn_error *parse_qemu_xp(const char *str, void *buf,
					size_t count)
{
	uint8_t *p = buf, *end = p + count;
	const char *s = str;

	while (p < end) {
		const char *address_str = s;
		// Skip "address:" prefix.
		const char *colon = strchr(s, ':');
		if (!colon) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						 "could not parse QEMU monitor xp response");
		}
		s = colon + 1;

		// Parse hex byte values.
		while (p < end && *s != '\0') {
			// Skip whitespace.
			while (*s == ' ' || *s == '\t')
				s++;
			if (*s == '\r' || *s == '\n' || *s == '\0')
				break;

			uint8_t lo, hi;
			if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X')
			    || !hex_digit_to_nibble(s[2], &hi)
			    || !hex_digit_to_nibble(s[3], &lo)) {
				// We always return a fault error in this case
				// just in case the error message from QEMU
				// changes, but we indicate this in our own
				// error message.
				const char *error_msg =
					strstartswith(s, "Cannot access memory")
					? "QEMU could not access memory"
					: "could not parse QEMU monitor xp response";
				unsigned long long address =
					strtoull(address_str, NULL, 16);
				return drgn_error_create_fault(error_msg,
							       address);
			}
			*p++ = (hi << 4) | lo;
			s += 4;
		}

		// Skip to next line.
		while (*s == '\r' || *s == '\n')
			s++;
	}
	return NULL;
}

static struct drgn_error *drgn_qmp_read_memory(void *buf, uint64_t address,
					       size_t count, uint64_t offset,
					       void *arg, bool physical)
{
	// Maximum number of bytes we'll read at once.
	static const size_t xp_max_bytes = 1024;
	struct drgn_error *err;
	struct drgn_program *prog = arg;
	struct drgn_qmp_conn *conn = &prog->qmp_conn;
	uint8_t *p = buf;

	drgn_blocking_guard(blocking_guard);

	while (count > 0) {
		size_t n = min(count, xp_max_bytes);

		conn->write_buf.len = 0;
		if (!string_builder_appendf(&conn->write_buf,
					    "{\"execute\":\"human-monitor-command\","
					    "\"arguments\":{\"command-line\":"
					    "\"xp /%zuxb 0x%" PRIx64 "\"}}\r\n",
					    n, address))
			return &drgn_enomem;

		_cleanup_json_object_ struct json_object *result = NULL;
		err = qmp_execute_str(conn, conn->write_buf.str,
				      conn->write_buf.len, &result);
		if (err)
			return err;

		if (!json_object_is_type(result, json_type_string)) {
			return drgn_error_create(DRGN_ERROR_OTHER,
						"QMP human-monitor-command xp return value is not string");
		}

		err = parse_qemu_xp(json_object_get_string(result), p, n);
		if (err)
			return err;

		p += n;
		address += n;
		count -= n;
	}
	return NULL;
}

static struct drgn_error *qmp_connect_unix(const char *address, int *ret)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	size_t path_len = strlen(address);
	if (path_len >= sizeof(sa.sun_path)) {
		return drgn_error_format(DRGN_ERROR_INVALID_ARGUMENT,
					"QMP Unix socket path is too long");
	}
	memcpy(sa.sun_path, address, path_len + 1);

	_cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return drgn_error_create_os("socket", errno, NULL);

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return drgn_error_create_os("connect", errno, address);

	*ret = fd;
	fd = -1;
	return NULL;
}

static struct drgn_error *qmp_connect_tcp(const char *address,
					  const char *colon, int *ret)
{
	_cleanup_free_ char *host = NULL;
	if (colon > address) {
		host = strndup(address, colon - address);
		if (!host)
			return &drgn_enomem;
	}
	const char *port = colon + 1;

	struct addrinfo hints = {
		.ai_flags = AI_ADDRCONFIG,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *res;
	int gai_err = getaddrinfo(host, port, &hints, &res);
	if (gai_err == EAI_SYSTEM) {
		return drgn_error_create_os("getaddrinfo", errno, address);
	} else if (gai_err) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "getaddrinfo: %s: %s", address,
					 gai_strerror(gai_err));
	}

	int saved_errno = 0;
	_cleanup_close_ int fd = -1;
	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			saved_errno = errno;
			continue;
		}
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		saved_errno = errno;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);

	if (fd < 0)
		return drgn_error_create_os("connect", saved_errno, address);

	*ret = fd;
	fd = -1;
	return NULL;
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_qemu_qmp(struct drgn_program *prog, const char *address)
{
	struct drgn_error *err;
	int fd;

	const char *colon;
	char *end;
	unsigned long port;
	if (address[0] == '/' || address[0] == '.'
	    || !(colon = strrchr(address, ':'))
	    || colon[1] < '0' || colon[1] > '9'
	    || (port = strtoul(colon + 1, &end, 10), *end != '\0')
	    || port < 1 || port > 65535)
		err = qmp_connect_unix(address, &fd);
	else
		err = qmp_connect_tcp(address, colon, &fd);
	if (err)
		return err;

	return drgn_program_set_qemu_qmp_fd(prog, fd);
}

LIBDRGN_PUBLIC struct drgn_error *
drgn_program_set_qemu_qmp_fd(struct drgn_program *prog, int fd)
{
	struct drgn_error *err;
	enum drgn_program_flags old_flags = prog->flags;
	bool had_platform = prog->has_platform;

	prog->qmp_conn.fd = fd;
	prog->qmp_conn.json_tok = json_tokener_new();
	if (!prog->qmp_conn.json_tok) {
		err = &drgn_enomem;
		goto err;
	}

	err = drgn_program_check_initialized(prog);
	if (err)
		goto err;

	err = qmp_negotiate(&prog->qmp_conn);
	if (err)
		goto err;

	if (!had_platform) {
		struct drgn_platform platform;
		err = qmp_detect_platform(&prog->qmp_conn, &platform);
		if (err)
			goto err;
		drgn_program_set_platform(prog, &platform);
	}

	err = drgn_program_add_memory_segment(prog, 0, UINT64_MAX,
					      drgn_qmp_read_memory, prog, true);
	if (err)
		goto err;

	prog->flags |= DRGN_PROGRAM_IS_LIVE;

	drgn_call_plugins_prog("drgn_prog_set", prog);
	return NULL;

err:
	drgn_memory_reader_clear(&prog->reader);
	drgn_qmp_conn_deinit(&prog->qmp_conn);
	drgn_qmp_conn_init(&prog->qmp_conn);
	prog->has_platform = had_platform;
	prog->flags = old_flags;
	return err;
}
