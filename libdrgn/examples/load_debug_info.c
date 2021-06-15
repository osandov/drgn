#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "drgn.h"

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

static void usage(bool error)
{
	fprintf(error ? stderr : stdout,
		"usage: load_debug_info [-k|-c CORE|-p PID] [PATH...]\n"
		"\n"
		"Example libdrgn program that loads default debug information\n"
		"\n"
		"Options:\n"
		"  -k, --kernel            debug the running kernel\n"
		"  -c PATH, --core PATH    debug the given core dump\n"
		"  -p PID, --pid PID       debug the running process with the given PID\n"
		"  -T, --time              print how long loading debug info took in seconds\n"
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
		{"help", no_argument, NULL, 'h'},
		{},
	};
	bool kernel = false;
	const char *core = NULL;
	const char *pid = NULL;
	bool print_time = false;
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

	struct timespec start, end;
	if (print_time && clock_gettime(CLOCK_MONOTONIC, &start))
		abort();
	err = drgn_program_load_debug_info(prog, (const char **)&argv[optind],
					   argc - optind, kernel || core || pid,
					   false);
	if ((!err || err->code == DRGN_ERROR_MISSING_DEBUG_INFO) && print_time) {
		if (clock_gettime(CLOCK_MONOTONIC, &end))
			abort();
		struct timespec diff = timespec_sub(end, start);
		printf("%lld.%09ld\n", (long long)diff.tv_sec, diff.tv_nsec);
	}

out:;
	int status;
	if (err) {
		if (err->code == DRGN_ERROR_MISSING_DEBUG_INFO)
			status = EXIT_SUCCESS;
		else
			status = EXIT_FAILURE;
		drgn_error_fwrite(stderr, err);
		drgn_error_destroy(err);
	} else {
		status = EXIT_SUCCESS;
	}
	drgn_program_destroy(prog);
	return status;
}
