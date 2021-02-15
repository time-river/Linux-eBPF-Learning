#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "bpf_load.h"

#define MAX_LENGTH	16
#define MAX_ENTRIES	16

struct msg {
	__s32 seq;
	__u64 cts;
	__u8 comm[MAX_LENGTH];
};

int main(int argc, char *argv[]) {
	struct msg msg = {0};
	int nr_cpus;

	nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	nr_cpus = nr_cpus > MAX_ENTRIES ? MAX_ENTRIES : nr_cpus;

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

	for (int key = 0; ; key = (key+1)%nr_cpus) {
		if (!bpf_map_lookup_elem(map_fd[0], &key, &msg)) {
			fprintf(stdout, "%.4f: @seq=%d @comm='%s'\n",
				(float)msg.cts/1000000000ul, msg.seq, msg.comm);
			msg.seq -= 1;
			if (msg.seq <= 0)
				bpf_map_delete_elem(map_fd[0], &key);
			else
				bpf_map_update_elem(map_fd[0], &key, &msg, BPF_EXIST);
			memset(&msg, 0, sizeof(msg));
		}
	}

	return 0;
}
