// The tracepoint requires kernel CONFIG_FTRACE_SYSCALLS to be set.

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "connect_kern.skel.h"

#define MAX_LENGTH 16

struct bpf_msg {
        char comm[MAX_LENGTH];
	struct sockaddr uservaddr;
};

static struct connect_kern *skel;
static struct ring_buffer *rb;
static bool stop;

static void sigint_handler(int sig) {
	stop = true;
}

static int print_bpf_output(void *ctx, void *data, size_t size) {
	struct bpf_msg *val = data;
	struct sockaddr_in *dest = (struct sockaddr_in *)&val->uservaddr;

	fprintf(stdout, ">> [%s]: connect '%s:%d'\n",
			val->comm,
			inet_ntoa(dest->sin_addr),
			dest->sin_port);
	return 0;
}

/* Prevent:
 *   libbpf: load bpf program failed: Operation not permitted
 *   libbpf: permission error while running as root; try raising 'ulimit -l'?
 *   current value: 64.0 KiB
 *   libbpf: failed to load program 'tracepoint/syscalls/sys_enter_openat'
 */
void setlimit(void) {
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);
}

int main(int argc, char *argv[]) {
	struct ring_buffer_opts rb_opts = {};
	int retval = 0;
	int map_fd;

	setlimit();

	skel = connect_kern__open_and_load();
	if (!skel)
		goto cleanup;

	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ringbuf");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed!\n");
		goto cleanup;
	}

	retval = connect_kern__attach(skel);
	if (retval)
		goto cleanup;

	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		goto cleanup;
	}

	rb = ring_buffer__new(map_fd, print_bpf_output, NULL, NULL);
	if (rb == NULL) {
		fprintf(stderr, "ERROR: failed to setup bpf ring_buffer!\n");
		goto cleanup;
	}

	while (true) {
		ring_buffer__poll(rb, 1000);
		if (stop)
			break;
	}

	connect_kern__detach(skel);
	ring_buffer__free(rb);
	bpf_link__destroy(skel->links.hello);
cleanup:
	connect_kern__destroy(skel);
	return 0;
}
