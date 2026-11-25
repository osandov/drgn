// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * bpfwalk.c - session, cursor, and the walker registry (see bpfwalk.h).
 *
 * Walkers are data-driven: each is one row in WALKERS[] naming its compiled BPF
 * object, the program to drive, and the ring-buffer map it emits into. Adding a
 * walker is therefore one new bpf/walk_<x>.bpf.c plus one row here -- no new C
 * types or per-walker code. Objects are loaded generically via libbpf
 * (bpf_object__open_file + find_{program,map}_by_name), so no skeletons are
 * generated and the registry stays uniform across walkers.
 *
 * The .bpf.o files live beside libbpfwalk.so; the library finds that directory
 * via dladdr() at runtime (override with BPFWALK_OBJDIR).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE		/* dladdr(); the Makefile also defines this */
#endif
#include <dlfcn.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpfwalk.h"
#include "bpfwalk_abi.h"

/* How the kernel is asked to run a walker. Only the seq iterator for now; a
 * BPF_PROG_RUN variant (with a resume cursor in args) slots in here later. */
enum bw_drive {
	BW_DRIVE_ITER,		/* seq iterator: link + bpf_iter_create + read() */
};

struct bw_walker_def {
	const char *name;	/* selector, e.g. "task" */
	const char *obj_file;	/* compiled BPF object beside libbpfwalk.so */
	const char *prog_name;	/* program to drive within that object */
	const char *map_name;	/* ring buffer the walker emits bw_ref into */
	enum bw_drive drive;
};

/* The registry. One row per walker. */
static const struct bw_walker_def WALKERS[] = {
	{ "task", "walk_task.bpf.o", "walk_task", "refs", BW_DRIVE_ITER },
};
#define N_WALKERS (sizeof(WALKERS) / sizeof(WALKERS[0]))

struct bw_loaded {
	const struct bw_walker_def *def;
	struct bpf_object *obj;
	int prog_fd;
	int map_fd;
	int failed;		/* load attempted and failed; don't retry */
};

struct bpfwalk {
	char objdir[PATH_MAX];
	struct bw_loaded loaded[N_WALKERS];
};

struct bpfwalk_cursor {
	struct bpfwalk *bw;
	struct bw_loaded *w;
	struct ring_buffer *rb;

	/* Materialized results, streamed out in batches. */
	__u64 *items;
	size_t n, cap, pos;
	int driven;
	int err;
};

/* Keep libbpf's probe/load chatter off stderr for library use. */
static int quiet(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	(void)level; (void)fmt; (void)ap;
	return 0;
}

static void resolve_objdir(char *out, size_t n)
{
	const char *env = getenv("BPFWALK_OBJDIR");
	Dl_info info;

	if (env && *env) {
		snprintf(out, n, "%s", env);
		return;
	}
	if (dladdr((void *)bpfwalk_open, &info) && info.dli_fname) {
		char tmp[PATH_MAX];

		snprintf(tmp, sizeof(tmp), "%s", info.dli_fname);
		snprintf(out, n, "%s", dirname(tmp));
		return;
	}
	snprintf(out, n, ".");
}

struct bpfwalk *bpfwalk_open(void)
{
	struct bpfwalk *bw = calloc(1, sizeof(*bw));
	size_t i;

	if (!bw)
		return NULL;
	libbpf_set_print(quiet);
	resolve_objdir(bw->objdir, sizeof(bw->objdir));
	for (i = 0; i < N_WALKERS; i++)
		bw->loaded[i].def = &WALKERS[i];
	return bw;
}

void bpfwalk_close(struct bpfwalk *bw)
{
	size_t i;

	if (!bw)
		return;
	for (i = 0; i < N_WALKERS; i++)
		if (bw->loaded[i].obj)
			bpf_object__close(bw->loaded[i].obj);
	free(bw);
}

static struct bw_loaded *find(struct bpfwalk *bw, const char *name)
{
	size_t i;

	for (i = 0; i < N_WALKERS; i++)
		if (strcmp(bw->loaded[i].def->name, name) == 0)
			return &bw->loaded[i];
	return NULL;
}

/* Load a walker's object exactly once. Returns the entry, or NULL on failure. */
static struct bw_loaded *ensure(struct bpfwalk *bw, const char *name)
{
	struct bw_loaded *w = find(bw, name);
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_object *obj;
	char path[PATH_MAX * 2];	/* objdir + '/' + obj_file, no truncation */

	if (!w || w->failed)
		return NULL;
	if (w->obj)
		return w;

	snprintf(path, sizeof(path), "%s/%s", bw->objdir, w->def->obj_file);
	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		w->failed = 1;
		return NULL;
	}
	if (bpf_object__load(obj)) {		/* CO-RE relocation + verifier */
		bpf_object__close(obj);
		w->failed = 1;
		return NULL;
	}
	prog = bpf_object__find_program_by_name(obj, w->def->prog_name);
	map = bpf_object__find_map_by_name(obj, w->def->map_name);
	if (!prog || !map) {
		bpf_object__close(obj);
		w->failed = 1;
		return NULL;
	}
	w->obj = obj;
	w->prog_fd = bpf_program__fd(prog);
	w->map_fd = bpf_map__fd(map);
	return w;
}

int bpfwalk_has(struct bpfwalk *bw, const char *walker)
{
	if (!bw || !walker)
		return 0;
	return ensure(bw, walker) != NULL;
}

static int cursor_append(void *ctx, void *data, size_t len)
{
	struct bpfwalk_cursor *c = ctx;
	const struct bw_ref *ref = data;

	if (len < sizeof(*ref))
		return 0;
	if (c->n == c->cap) {
		size_t ncap = c->cap ? c->cap * 2 : 4096;
		__u64 *ni = realloc(c->items, ncap * sizeof(*ni));

		if (!ni) {
			c->err = -ENOMEM;
			return 0;
		}
		c->items = ni;
		c->cap = ncap;
	}
	c->items[c->n++] = ref->addr;
	return 0;
}

struct bpfwalk_cursor *bpfwalk_walk_open(struct bpfwalk *bw, const char *walker,
					 const void *args, size_t args_len)
{
	struct bpfwalk_cursor *c;
	struct bw_loaded *w;

	(void)args; (void)args_len;		/* "task" takes no arguments */

	if (!bw)
		return NULL;
	w = ensure(bw, walker);
	if (!w)
		return NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;
	c->bw = bw;
	c->w = w;
	c->rb = ring_buffer__new(w->map_fd, cursor_append, c, NULL);
	if (!c->rb) {
		free(c);
		return NULL;
	}
	return c;
}

/*
 * Drive the seq iterator to completion, draining the ring buffer into c->items.
 * The program writes only to the ring buffer (nothing to the seq_file), so a
 * single read() runs it across every element; we still loop + consume to be
 * robust to chunked reads.
 */
static int drive_iter(struct bpfwalk_cursor *c)
{
	char sink[8192];
	int link_fd, iter_fd;
	ssize_t n;

	link_fd = bpf_link_create(c->w->prog_fd, 0, BPF_TRACE_ITER, NULL);
	if (link_fd < 0)
		return -errno;
	iter_fd = bpf_iter_create(link_fd);
	if (iter_fd < 0) {
		int e = -errno;

		close(link_fd);
		return e;
	}
	do {
		n = read(iter_fd, sink, sizeof(sink));
		ring_buffer__consume(c->rb);
	} while (n > 0);
	close(iter_fd);
	close(link_fd);
	if (n < 0)
		return -errno;
	return c->err;
}

int bpfwalk_walk_next(struct bpfwalk_cursor *c, void *buf, size_t rec_size,
		      size_t max)
{
	__u64 *out = buf;
	size_t avail, take, i;

	if (!c || !buf || rec_size < sizeof(__u64) || max == 0)
		return -EINVAL;

	if (!c->driven) {
		int rc;

		switch (c->w->def->drive) {
		case BW_DRIVE_ITER:
			rc = drive_iter(c);
			break;
		default:
			rc = -ENOTSUP;
			break;
		}
		c->driven = 1;
		if (rc)
			return rc;
	}

	avail = c->n - c->pos;
	if (avail == 0)
		return 0;
	take = avail < max ? avail : max;
	for (i = 0; i < take; i++)
		out[i] = c->items[c->pos + i];
	c->pos += take;
	return (int)take;
}

void bpfwalk_walk_close(struct bpfwalk_cursor *c)
{
	if (!c)
		return;
	ring_buffer__free(c->rb);
	free(c->items);
	free(c);
}
