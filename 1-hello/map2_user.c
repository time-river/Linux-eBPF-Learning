#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_FILENAME_LEN 256

#define MAX_LENGTH	16
#define MAX_ENTRIES	16

struct msg {
	unsigned int tgid;
	unsigned int pid;
	char comm[MAX_LENGTH];
	char msg[MAX_LENGTH];
};

int main(int argc, char *argv[]) {
	struct msg msg = {0};
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
		goto cleanup;
	}

	/* load eBPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading eBPF object file failed!\n");
		goto cleanup;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "map");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed!\n");
		goto cleanup;
	};

	bpf_object__for_each_program(prog, obj) {
		link = bpf_program__attach(prog);
		if (libbpf_get_error(link)) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
		}
	}

	for (int key = 0; ; key = (key+1)%MAX_ENTRIES) {
		if (!bpf_map_lookup_elem(map_fd, &key, &msg)) {
			fprintf(stdout, "@tgid='%u' @gid='%u' @comm='%s' @msg='%s'\n",
				msg.tgid, msg.pid, msg.comm, msg.msg);
			memset(&msg, 0, sizeof(msg));
			bpf_map_delete_elem(map_fd, &key);
		}
	}

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
