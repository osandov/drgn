// Copyright 2020 - Omar Sandoval
// SPDX-License-Identifier: GPL-3.0+

#include <assert.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#define HOSTNAME "vmtest"
#define VPORT_NAME "com.osandov.vmtest.0"

__attribute__((format(printf, 1, 2)))
static void poweroff(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (reboot(RB_POWER_OFF))
		perror("reboot");
	_exit(EXIT_FAILURE);
}

#define CHECK(func, ...) ({			\
	__auto_type _ret = func(__VA_ARGS__);	\
	if (_ret == -1)				\
		poweroff(#func ": %m\n");	\
	_ret;					\
})

#define CHECK1(func, arg1, ...) ({			\
	__auto_type _arg1 = (arg1);			\
	__auto_type _ret = func(arg1, ##__VA_ARGS__);	\
	if (_ret == -1)					\
		poweroff(#func ": %s: %m\n", _arg1);	\
	_ret;						\
})

#define CHECK2(func, arg1, arg2, ...) ({			\
	__auto_type _arg2 = (arg2);				\
	__auto_type _ret = func((arg1), _arg2, ##__VA_ARGS__);	\
	if (_ret == -1)						\
		poweroff(#func ": %s: %m\n", _arg2);		\
	_ret;							\
})

#define CHECKP(func, ...) ({			\
	__auto_type _ret = func(__VA_ARGS__);	\
	if (_ret == (void *)0)			\
		poweroff(#func ": %m\n");	\
	_ret;					\
})

#define CHECKP1(func, arg1, ...) ({			\
	__auto_type _arg1 = (arg1);			\
	__auto_type _ret = func(arg1, ##__VA_ARGS__);	\
	if (_ret == (void *)0)				\
		poweroff(#func ": %s: %m\n", _arg1);	\
	_ret;						\
})

static void write_text_file(const char *pathname, const char *contents)
{
	const char *p = contents, *end = p + strlen(contents);
	int fd;

	fd = CHECK1(creat, pathname, 0644);
	while (p < end) {
		ssize_t ret;

		ret = write(fd, p, end - p);
		if (ret == -1)
			poweroff("write: %s\n", pathname);
		p += ret;
	}
	close(fd);
}

static void setup_vmlinux(void)
{
	const char *vmlinux = getenv("VMLINUX");
	struct utsname uts;
#define BOOT_VMLINUX_FORMAT "/mnt/upper/boot/vmlinux-%s"
	/* - 3 for %s\0 */
	char path[sizeof(BOOT_VMLINUX_FORMAT) - 3 + sizeof(uts.release)];

	if (!vmlinux)
		return;

	CHECK(uname, &uts);
	snprintf(path, sizeof(path), BOOT_VMLINUX_FORMAT, uts.release);
	CHECK1(mkdir, "/mnt/upper/boot", 0755);
	CHECK2(symlink, vmlinux, path);
}

static void setup_fs(void)
{

	CHECK2(mount, "tmpfs", "/mnt", "tmpfs", 0, "");
	CHECK1(mkdir, "/mnt/upper", 0755);
	CHECK1(mkdir, "/mnt/work", 0755);
	CHECK1(mkdir, "/mnt/merged", 0755);

	CHECK1(mkdir, "/mnt/upper/dev", 0755);
	CHECK1(mkdir, "/mnt/upper/proc", 0555);
	CHECK1(mkdir, "/mnt/upper/sys", 0555);
	CHECK1(mkdir, "/mnt/upper/tmp", 01777);

	CHECK1(mkdir, "/mnt/upper/etc", 0755);
	write_text_file("/mnt/upper/etc/hosts",
			"127.0.0.1 localhost\n"
			"::1 localhost\n"
			"127.0.1.1 " HOSTNAME ".localdomain " HOSTNAME "\n");
	write_text_file("/mnt/upper/etc/resolv.conf", "");

	setup_vmlinux();

	CHECK2(mount, "overlay", "/mnt/merged", "overlay", 0,
	       "lowerdir=/,upperdir=/mnt/upper,workdir=/mnt/work");

	CHECK2(syscall, SYS_pivot_root, "/mnt/merged", "/mnt/merged/mnt");
	CHECK1(chdir, "/");
	CHECK1(umount2, "/mnt", MNT_DETACH);

	CHECK2(mount, "dev", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "");
	CHECK2(mount, "proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC,
	       "");
	CHECK2(mount, "sys", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
	       "");
	/*
	 * Ideally we'd just be able to create an opaque directory for /tmp on
	 * the upper layer. However, before Linux kernel commit 51f7e52dc943
	 * ("ovl: share inode for hard link") (in v4.8), overlayfs doesn't
	 * handle hard links correctly, which breaks some tests.
	 */
	CHECK2(mount, "tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "");
}

static void setup_net(void)
{
	struct ifreq ifr = { .ifr_name = "lo" };
	int fd;

	CHECK(sethostname, HOSTNAME, strlen(HOSTNAME));

	fd = CHECK(socket, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_IP);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
		poweroff("ioctl: SIOCGIFFLAGS: %m\n");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
		poweroff("ioctl: SIOCSIFFLAGS: %m\n");
	close(fd);
}

static int open_vport(void)
{
	DIR *dir;
	char buf[1024];

	dir = CHECKP1(opendir, "/sys/class/virtio-ports");
	for (;;) {
		struct dirent *ent;
		FILE *file;
		bool got_line;

		errno = 0;
		ent = readdir(dir);
		if (!ent) {
			if (errno) {
				poweroff("readdir: /sys/class/virtio-ports: %m\n");
			} else {
				poweroff("could not find virtio-port \"%s\"\n",
					 VPORT_NAME);
			}
		}
		if (ent->d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "/sys/class/virtio-ports/%s/name",
			 ent->d_name);
		file = fopen(buf, "re");
		if (!file) {
			if (errno == ENOENT)
				continue;
			else
				poweroff("fopen: %s: %m\n", buf);
		}
		got_line = fgets(buf, sizeof(buf), file);
		fclose(file);
		if (!got_line || strcmp(buf, VPORT_NAME "\n") != 0)
			continue;

		snprintf(buf, sizeof(buf), "/dev/%s", ent->d_name);
		closedir(dir);
		return CHECK1(open, buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	}
}

struct vec {
	char **vec;
	size_t capacity;
	uint32_t count;
	uint32_t pos;
};

enum {
	SIGNALFD,
	VPORTFD,
};

struct state {
	enum {
		STATE_ARGC,
		STATE_ARG,
		STATE_ARG_NUL,
		STATE_ENV_COUNT,
		STATE_ENV,
		STATE_ENV_NUL,
		STATE_EXECUTABLE,
		STATE_EXECUTABLE_NUL,
		STATE_CWD,
		STATE_CWD_NUL,
		STATE_EXEC,
		STATE_WAIT,
		STATE_STATUS_LO,
		STATE_STATUS_HI,
	} state;

	pid_t child;
	uint16_t wstatus;

	struct pollfd fds[2];

	char *buf;
	size_t capacity;
	size_t len;
	size_t pos;

	struct vec args;
	struct vec env;
	char *executable;
	char *cwd;
};

static void handle_signalfd_read(struct state *state)
{
	struct signalfd_siginfo siginfo;
	ssize_t ret;

	ret = read(state->fds[SIGNALFD].fd, &siginfo, sizeof(siginfo));
	if (ret == -1) {
		if (errno == EAGAIN)
			return;
		else
			poweroff("read: signalfd\n");
	}
	if (ret < sizeof(siginfo))
		return;
	if (siginfo.ssi_signo == SIGCHLD) {
		pid_t pid;
		int wstatus;

		while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
			if (state->state == STATE_WAIT && pid == state->child) {
				if (WIFEXITED(wstatus)) {
					printf("Exited with status %d\n",
					       WEXITSTATUS(wstatus));
				} else {
					printf("Terminated by signal %d\n",
					       WTERMSIG(wstatus));
				}
				state->wstatus = htole16(wstatus);
				state->fds[VPORTFD].events |= POLLOUT;
				state->state = STATE_STATUS_LO;
			}
		}
		if (pid == -1 && errno != ECHILD)
			poweroff("waitpid");
	}
}

static void handle_vport_read(struct state *state)
{
	for (;;) {
		ssize_t ret;

		if (state->len >= state->capacity) {
			char *tmp;
			uint32_t i;

			if (state->capacity)
				state->capacity *= 2;
			else
				state->capacity = 4096;
			tmp = CHECKP(malloc, state->capacity);
			memcpy(tmp, state->buf, state->len);
			for (i = 0; i < state->args.pos; i++)
				state->args.vec[i] =
					tmp + (state->args.vec[i] - state->buf);
			for (i = 0; i < state->env.pos; i++)
				state->env.vec[i] =
					tmp + (state->env.vec[i] - state->buf);
			if (state->executable)
				state->executable =
					tmp + (state->executable - state->buf);
			if (state->cwd)
				state->cwd = tmp + (state->cwd - state->buf);
			free(state->buf);
			state->buf = tmp;
		}

		ret = read(state->fds[VPORTFD].fd, state->buf + state->len,
			   state->capacity - state->len);
		if (ret == 0 || (ret == -1 && errno == EAGAIN))
			break;
		else if (ret == -1)
			poweroff("read: vport: %m\n");
		state->len += ret;
	}

	while (state->pos < state->len && state->state < STATE_EXEC) {
		switch (state->state) {
		case STATE_ARGC:
		case STATE_ENV_COUNT: {
			struct vec *vec;
			uint32_t count;

			if (state->len - state->pos < sizeof(count))
				return;
			if (state->state == STATE_ARGC)
				vec = &state->args;
			else
				vec = &state->env;
			memcpy(&count, &state->buf[state->pos], sizeof(count));
			state->pos += sizeof(count);
			vec->count = le32toh(count);
			if (vec->count >= vec->capacity) {
				size_t size;

				/* One extra element for NULL pointer. */
				if (__builtin_mul_overflow(sizeof(*vec->vec),
							   vec->count, &size) ||
				    __builtin_add_overflow(size,
							   sizeof(*vec->vec),
							   &size))
					poweroff("count is too large\n");
				vec->vec = CHECKP(realloc, vec->vec, size);
				vec->capacity = vec->count;
			}
			vec->vec[vec->count] = NULL;
			state->state += vec->count ? 1 : 3;
			break;
		}
		case STATE_ARG:
		case STATE_ENV:
		case STATE_EXECUTABLE:
		case STATE_CWD: {
			char **str;

			if (state->state == STATE_ARG)
				str = &state->args.vec[state->args.pos++];
			else if (state->state == STATE_ENV)
				str = &state->env.vec[state->env.pos++];
			else if (state->state == STATE_EXECUTABLE)
				str = &state->executable;
			else /* (state->state == STATE_CWD) */
				str = &state->cwd;
			*str = &state->buf[state->pos];
			state->state++;
			/* fallthrough */
		}
		case STATE_ARG_NUL:
		case STATE_ENV_NUL:
		case STATE_EXECUTABLE_NUL:
		case STATE_CWD_NUL: {
			struct vec *vec;
			char *nul;

			if (state->state == STATE_ARG_NUL)
				vec = &state->args;
			else if (state->state == STATE_ENV_NUL)
				vec = &state->env;
			else
				vec = NULL;
			nul = memchr(&state->buf[state->pos], 0,
				     state->len - state->pos);
			if (nul) {
				state->pos = nul + 1 - state->buf;
				if (!vec || vec->pos == vec->count)
					state->state++;
				else
					state->state--;
			} else {
				state->pos = state->len;
			}
			break;
		default:
			assert(false);
			break;
		}
		}
	}

	if (state->state == STATE_EXEC) {
		uint32_t i;
		pid_t pid;

		printf("Executing");
		for (i = 0; i < state->args.count; i++)
			printf(" %s", state->args.vec[i]);
		printf("\n");
		pid = CHECK(fork);
		if (pid == 0) {
			int status;

			if (state->cwd[0] && chdir(state->cwd) == -1) {
				fprintf(stderr, "chdir: %s: %m\n", state->cwd);
				_exit(EXIT_FAILURE);
			}
			execvpe(state->executable, state->args.vec,
				state->env.vec);
			/* Mimic bash exit status. */
			status = errno == ENOENT ? 127 : 126;
			perror("execvpe");
			_exit(status);
		}
		state->child = pid;
		state->fds[VPORTFD].revents &= ~POLLIN;
		state->len -= state->pos;
		memmove(state->buf, &state->buf[state->pos], state->len);
		state->pos = 0;
		state->args.pos = 0;
		state->env.pos = 0;
		state->executable = NULL;
		state->cwd = NULL;
		state->state = STATE_WAIT;
	}
}

static void handle_vport_write(struct state *state)
{
	ssize_t ret;

	assert(state->state == STATE_STATUS_LO ||
	       state->state == STATE_STATUS_HI);
	ret = write(state->fds[VPORTFD].fd,
		    (char *)&state->wstatus + (state->state - STATE_STATUS_LO),
		    STATE_STATUS_HI - STATE_STATUS_LO + 1);
	if (ret == -1) {
		if (errno == EAGAIN)
			return;
		else
			poweroff("write: vport: %m\n");
	}
	state->state += ret;
	if (state->state > STATE_STATUS_HI) {
		state->fds[VPORTFD].events &= ~POLLOUT;
		state->state = STATE_ARGC;
	}
}

int main(void)
{
	sigset_t sigs;
	struct state state = { .state = STATE_ARGC };

	CHECK(sigemptyset, &sigs);
	CHECK(sigaddset, &sigs, SIGCHLD);
	CHECK(sigprocmask, SIG_BLOCK, &sigs, NULL);

	state.fds[SIGNALFD].fd = CHECK(signalfd, -1, &sigs,
				       SFD_NONBLOCK | SFD_CLOEXEC);
	state.fds[SIGNALFD].events = POLLIN;

	setup_fs();
	setup_net();

	state.fds[VPORTFD].fd = open_vport();
	state.fds[VPORTFD].events = POLLIN;

	for (;;) {
		CHECK(poll, state.fds, sizeof(state.fds) / sizeof(state.fds[0]),
		      -1);

		if (state.fds[SIGNALFD].revents & POLLIN)
			handle_signalfd_read(&state);

		if (state.fds[VPORTFD].revents & POLLIN)
			handle_vport_read(&state);
		if (state.fds[VPORTFD].revents & POLLOUT)
			handle_vport_write(&state);
		if (state.fds[VPORTFD].revents & POLLHUP)
			poweroff("Host disconnected\n");
	}
}
