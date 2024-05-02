// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <getopt.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../drgn.h"
#include "../util.h"

extern char **environ;

static struct drgn_error *run_command(const char *which, const char *command,
				      struct drgn_program *prog)
{
	if (!command)
		return NULL;

	char pid_arg[max_decimal_length(long)];
	sprintf(pid_arg, "%ld", (long)getpid());
	char prog_arg[2 * sizeof(prog) + 3];
	sprintf(prog_arg, "%p", prog);
	const char * const argv[] = {
		"sh", "-c", command, "sh", pid_arg, prog_arg, NULL
	};

	pid_t pid;
	int errnum =
		posix_spawnp(&pid, "sh", NULL, NULL, (char **)argv, environ);
	if (errnum)
		return drgn_error_create_os("posix_spawnp", errnum, "sh");

	int wstatus;
	if (waitpid(pid, &wstatus, 0) < 0)
		return drgn_error_create_os("waitpid", errno, NULL);

	if (!WIFEXITED(wstatus)) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s-exec command exited abnormally: %d",
					 which, wstatus);
	}
	if (WEXITSTATUS(wstatus) != 0) {
		return drgn_error_format(DRGN_ERROR_OTHER,
					 "%s-exec command exited with status %d",
					 which, WEXITSTATUS(wstatus));
	}
	return NULL;
}

static inline struct timespec timespec_sub(struct timespec a, struct timespec b)
{
	if (a.tv_nsec < b.tv_nsec) {
		return (struct timespec){
			.tv_sec = a.tv_sec - 1 - b.tv_sec,
			.tv_nsec = a.tv_nsec + 1000000000L - b.tv_nsec,
		};
	} else {
		return (struct timespec){
			.tv_sec = a.tv_sec - b.tv_sec,
			.tv_nsec = a.tv_nsec - b.tv_nsec,
		};
	}
}

noreturn static void usage(bool error)
{
	fprintf(error ? stderr : stdout,
		"usage: load_debug_info [OPTION...] [-k|-c CORE|-p PID] [PATH...]\n"
		"\n"
		"Example libdrgn program that loads default debug information\n"
		"\n"
		"Options:\n"
		"  -k, --kernel            debug the running kernel\n"
		"  -c PATH, --core PATH    debug the given core dump\n"
		"  -p PID, --pid PID       debug the running process with the given PID\n"
		"  -T, --time              print how long loading debug info took in seconds\n"
		"  --pre-exec CMD          before loading debug info, execute the given shell\n"
		"                          command with the PID of this process and the address\n"
		"                          of the struct drgn_program in hexadecimal as arguments\n"
		"  --post-exec CMD         after loading debug info, execute the given shell\n"
		"                          command with the same arguments as --pre-exec\n"
		"  -h, --help              display this help message and exit\n");
	exit(error ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	struct option long_options[] = {
		{"kernel", no_argument, NULL, 'k'},
		{"core", required_argument, NULL, 'c'},
		{"pid", required_argument, NULL, 'p'},
		{"time", no_argument, NULL, 'T'},
		{"pre-exec", required_argument, NULL, 'x'},
		{"post-exec", required_argument, NULL, 'X'},
		{"help", no_argument, NULL, 'h'},
		{},
	};
	bool kernel = false;
	const char *core = NULL;
	const char *pid = NULL;
	bool print_time = false;
	const char *pre_exec = NULL;
	const char *post_exec = NULL;
	for (;;) {
		int c = getopt_long(argc, argv, "kc:p:Th", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'k':
			kernel = true;
			break;
		case 'c':
			core = optarg;
			break;
		case 'p':
			pid = optarg;
			break;
		case 'T':
			print_time = true;
			break;
		case 'x':
			pre_exec = optarg;
			break;
		case 'X':
			post_exec = optarg;
			break;
		case 'h':
			usage(false);
		default:
			usage(true);
		}
	}
	if (kernel + !!core + !!pid > 1)
		usage(true);

	struct drgn_program *prog;
	struct drgn_error *err = drgn_program_create(NULL, &prog);
	if (err) {
		prog = NULL;
		goto out;
	}

	if (core)
		err = drgn_program_set_core_dump(prog, core);
	else if (pid)
		err = drgn_program_set_pid(prog, atoi(pid) ?: getpid());
	else if (kernel)
		err = drgn_program_set_kernel(prog);
	if (err)
		goto out;

	err = run_command("pre", pre_exec, prog);
	if (err)
		goto out;

	struct timespec start, end;
	if (print_time && clock_gettime(CLOCK_MONOTONIC, &start))
		abort();
	err = drgn_program_load_debug_info(prog, (const char **)&argv[optind],
					   argc - optind, kernel || core || pid,
					   false);
	if ((!err || err->code == DRGN_ERROR_MISSING_DEBUG_INFO)
	    && print_time && clock_gettime(CLOCK_MONOTONIC, &end))
		abort();
	if (err && err->code == DRGN_ERROR_MISSING_DEBUG_INFO) {
		drgn_error_fwrite(stderr, err);
		drgn_error_destroy(err);
	} else if (err) {
		goto out;
	}

	err = run_command("post", post_exec, prog);
	if (err)
		goto out;

	if (print_time) {
		struct timespec diff = timespec_sub(end, start);
		printf("%lld.%09ld\n", (long long)diff.tv_sec, diff.tv_nsec);
	}

out:;
	int status = err ? EXIT_FAILURE : EXIT_SUCCESS;
	if (err) {
		drgn_error_fwrite(stderr, err);
		drgn_error_destroy(err);
	}
	drgn_program_destroy(prog);
	return status;
}
