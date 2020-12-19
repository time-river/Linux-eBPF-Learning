#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "bpf_load.h"

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

	if (argc != 2) {
		fprintf(stdout, "Usage: %s <eBPF program>\n", argv[0]);
		return 0;
	}

	if (access(argv[1], R_OK) != 0) {
		fprintf(stderr, "ERROR: access('%s'): %s\n",
			argv[0], strerror(errno));
		return 1;
	}

	if (load_bpf_file(argv[1])) {
		fprintf(stdout, "%s", bpf_log_buf);
		return 1;
	}

	for (int key = 0; ; key = (key+1)%MAX_ENTRIES) {
		if (!bpf_map_lookup_elem(map_fd[0], &key, &msg)) {
			fprintf(stdout, "@tgid='%u' @gid='%u' @comm='%s' @msg='%s'\n",
				msg.tgid, msg.pid, msg.comm, msg.msg);
			memset(&msg, 0, sizeof(msg));
			bpf_map_delete_elem(map_fd[0], &key);
		}
	}

	return 0;
}
