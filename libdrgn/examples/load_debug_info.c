#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "drgn.h"

static void usage(bool error)
{
	fprintf(error ? stderr : stdout,
		"usage: load_debug_info [-k|-c CORE|-p PID]\n"
		"\n"
		"Example libdrgn program that loads default debug information\n"
		"\n"
		"Options:\n"
		"  -k, --kernel            debug the running kernel (default)\n"
		"  -c PATH, --core PATH    debug the given core dump\n"
		"  -p PID, --pid PID       debug the running process with the given PID\n"
		"  -h, --help              display this help message and exit\n");
	exit(error ? EXIT_FAILURE : EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	struct option long_options[] = {
		{"kernel", no_argument, NULL, 'k'},
		{"core", required_argument, NULL, 'c'},
		{"pid", required_argument, NULL, 'p'},
		{"help", no_argument, NULL, 'h'},
		{},
	};
	bool kernel = false;
	const char *core = NULL;
	const char *pid = NULL;
	for (;;) {
		int c = getopt_long(argc, argv, "kc:p:h", long_options, NULL);
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
		case 'h':
			usage(false);
		default:
			usage(true);
		}
	}
	if (optind != argc || kernel + !!core + !!pid > 1)
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
	else
		err = drgn_program_set_kernel(prog);
	if (err)
		goto out;

	err = drgn_program_load_debug_info(prog, NULL, 0, true, true);

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
