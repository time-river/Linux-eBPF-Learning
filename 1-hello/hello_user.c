#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "bpf_load.h"

#define MAX_FILENAME_LEN 256

void read_msg(void);

int main(int argc, char *argv[]) {
	int ch;

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

	fprintf(stdout, ">>> begin to read trace_pipe...\n");
	read_msg();

	return 0;
}

void read_msg(void) {
	FILE *fp;
	char filename[MAX_FILENAME_LEN];
	char *line = NULL;
	size_t len = 0;

	snprintf(filename, sizeof(filename), DEBUGFS "trace_pipe");

	fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "ERROR: fopen('%s'): %s\n",
			filename, strerror(errno));
		return;
	}

	while (getline(&line, &len, fp) != -1) {
		fprintf(stdout, "%s", line);
		continue;
	}

	return;
}
