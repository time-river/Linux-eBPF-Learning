// The tracepoint requires kernel CONFIG_FTRACE_SYSCALLS to be set.

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>

#include "map3_kern.skel.h"

#define MAX_LENGTH 64

struct msg {
	int id;
	int pid;
	int flags;
	char comm[MAX_LENGTH];
	char file[MAX_LENGTH];
};

static struct map3_kern *skel;
static struct ring_buffer *rb;

/* TODO: There are something errors during exiting by sigint signal. */
static void sigint_handler(int sig) {
	if (rb != NULL) {
		ring_buffer__consume(rb);
		ring_buffer__free(rb);
	}

	if (skel->links.hello != NULL)
		bpf_link__destroy(skel->links.hello);
}

static int print_bpf_output(void *ctx, void *data, size_t size) {
	struct msg *val = data;

	fprintf(stdout, "id=%d pid=%d comm=%s flags=0x%x file=%s\n",
	       val->id, val->pid, val->comm, val->flags, val->file);

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

	skel = map3_kern__open_and_load();
	if (!skel)
		goto cleanup;

	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ringbuf");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed!\n");
		goto cleanup;
	}

	retval = map3_kern__attach(skel);
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
	}
cleanup:
	map3_kern__destroy(skel);
	return 0;
}
