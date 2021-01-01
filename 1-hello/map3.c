#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "map3_kern.skel.h"

#define MAX_LENGTH 64

struct msg {
	int id;
	unsigned int pid;
	int flags;
	char comm[MAX_LENGTH];
	char file[MAX_LENGTH];
};

static struct map3_kern *skel;
static struct perf_buffer *pb;

static void sigint_handler(int sig) {
	if (skel->links.hello != NULL)
		bpf_link__destroy(skel->links.hello);

	if (pb != NULL)
		perf_buffer__free(pb);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size) {
	struct msg *val = data;

	fprintf(stdout, "id=%d pid=%d comm=%s flags=%x file=%s\n",
	       val->id, val->pid, val->comm, val->flags, val->file);
}

int main(int argc, char *argv[]) {
	struct perf_buffer_opts pb_opts = {
		.sample_cb = print_bpf_output
	};
	int retval = 0;
	int map_fd;

	skel = map3_kern__open_and_load();
	if (!skel)
		goto cleanup;

	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "perf_map");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed!\n");
		goto cleanup;
	}

	retval = map3_kern__attach(skel);
	if (retval)
		goto cleanup;

	if (signal(SIGINT, sigint_handler) != sigint_handler) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		goto cleanup;
	}

	pb = perf_buffer__new(map_fd, 8, &pb_opts);
	if (libbpf_get_error(pb)) {
		fprintf(stderr, "ERROR: failed to setup perf_buffer: %d\n", retval);
		goto cleanup;
	}

	while (true) {
		perf_buffer__poll(pb, 1000);
	}
cleanup:
	map3_kern__destroy(skel);
	return 0;
}
