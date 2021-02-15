#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

struct msg {
	char buf[32];
	size_t count;
	loff_t pos;
};

static bool stop;

static void sigint_handler(int sig) {
	stop = true;
}

static float time_get_ns(void)
{
	struct timespec ts;
	float second;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	second = ts.tv_sec + (float)ts.tv_nsec / 1000000000ull;

	return second;
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size) {
	struct msg *msg = data;

	fprintf(stdout, "%.4f: @buf=%s count=%zu %ld\n",
		time_get_ns(), msg->buf, msg->count, msg->pos);
}

int main(int argc, char *argv[]) {
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	struct bpf_link *link = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_object *obj = NULL;
	int map_fd;

	if (argc != 2) {
		fprintf(stdout, "Usage: %s <eBPF program>\n", argv[0]);
		return 0;
	}

	if (access(argv[1], R_OK) != 0) {
		fprintf(stderr, "ERROR: access('%s'): %s\n",
			argv[0], strerror(errno));
		return 1;
	}

	obj = bpf_object__open_file(argv[1], NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening eBPF object '%s' failed\n",
			argv[1]);
		goto out;
	}

	/* load eBPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading eBPF object file failed!\n");
		goto close;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "map");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed!\n");
		goto unload;
	};

	prog = bpf_object__find_program_by_name(obj, "hello");
	if (libbpf_get_error(prog)) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed!\n");
		goto unload;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto unload;
	}

	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		fprintf(stderr, "ERROR: %s\n", strerror(errno));
		goto deattach;
	}

	pb_opts.sample_cb = print_bpf_output;
	pb = perf_buffer__new(map_fd, 8, &pb_opts);
	if (libbpf_get_error(pb)) {
		fprintf(stderr, "failed to setup perf_buffer!\n");
		goto deattach;
	}

	while (true) {
		perf_buffer__poll(pb, 1000);
		if (stop)
			break;
	}

deattach:
	bpf_link__destroy(link);
unload:
	bpf_object__unload(obj);
close:
	bpf_object__close(obj);
out:
	return 0;
}
